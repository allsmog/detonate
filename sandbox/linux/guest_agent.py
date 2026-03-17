#!/usr/bin/env python3
"""Guest agent that runs inside the sandbox container.

Executes the sample under strace, captures syscall events,
diffs the filesystem for dropped files, and writes structured
JSON results to /opt/agent/results.json.

Events are also streamed line-by-line to /tmp/events.jsonl in
real time so the host can tail them while the analysis is running.
"""

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

WATCH_DIRS = ["/tmp", "/var/tmp", "/home"]
RESULTS_PATH = "/opt/agent/results.json"
STRACE_LOG = "/tmp/strace.log"
PCAP_PATH = "/tmp/capture.pcap"
EVENTS_PATH = "/tmp/events.jsonl"
YARA_RULES_INDEX = "/opt/yara/rules/index.yar"
SCREENSHOTS_DIR = "/tmp/screenshots"
VIDEO_PATH = "/tmp/recording.mp4"
XVFB_DISPLAY = ":99"


def snapshot_fs(dirs: list[str]) -> dict[str, float]:
    """Return {path: mtime} for all files under the watched directories."""
    snap: dict[str, float] = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    snap[fp] = os.path.getmtime(fp)
                except OSError:
                    pass
    return snap


def diff_fs(
    before: dict[str, float], after: dict[str, float]
) -> tuple[list[dict], list[dict], list[dict]]:
    created, modified, deleted = [], [], []
    for path, mtime in after.items():
        if path in (STRACE_LOG, RESULTS_PATH, PCAP_PATH, EVENTS_PATH):
            continue
        if path not in before:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            created.append({"path": path, "size": size})
        elif mtime != before[path]:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            modified.append({"path": path, "size": size})
    for path in before:
        if path not in after:
            deleted.append({"path": path})
    return created, modified, deleted


def parse_strace(log_path: str) -> tuple[list[dict], list[dict]]:
    """Parse strace log for process and network events, including ppid via clone."""
    processes: list[dict] = []
    network: list[dict] = []
    seen_pids: set[str] = set()
    pid_to_ppid: dict[int, int] = {}

    if not os.path.exists(log_path):
        return processes, network

    execve_re = re.compile(
        r"^(\d+)\s+execve\(\"([^\"]+)\",\s*\[([^\]]*)\]"
    )
    clone_re = re.compile(
        r"^(\d+)\s+clone\d*\(.*\)\s*=\s*(\d+)"
    )
    connect_re = re.compile(
        r"^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET6?,\s*"
        r"sin6?_port=htons\((\d+)\),\s*sin6?_addr="
        r"(?:inet_pton\([^,]+,\s*)?\"([^\"]+)\""
    )
    connect_simple_re = re.compile(
        r"^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET,\s*"
        r"sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\(\"([^\"]+)\"\)"
    )

    # First pass: collect clone relationships for ppid mapping
    with open(log_path) as f:
        for line in f:
            m = clone_re.match(line)
            if m:
                ppid = int(m.group(1))
                child_pid = int(m.group(2))
                if child_pid > 0:
                    pid_to_ppid[child_pid] = ppid

    # Second pass: collect processes and network events
    with open(log_path) as f:
        for line in f:
            m = execve_re.match(line)
            if m:
                pid = m.group(1)
                cmd = m.group(2)
                raw_args = m.group(3)
                args = [a.strip().strip('"') for a in raw_args.split(",") if a.strip()]
                if pid not in seen_pids:
                    proc = {
                        "pid": int(pid),
                        "ppid": pid_to_ppid.get(int(pid)),
                        "command": cmd,
                        "args": args,
                    }
                    processes.append(proc)
                    seen_pids.add(pid)
                continue

            for rx in (connect_re, connect_simple_re):
                m = rx.match(line)
                if m:
                    port = int(m.group(2))
                    addr = m.group(3)
                    if addr not in ("127.0.0.1", "::1", "0.0.0.0"):
                        network.append({"protocol": "tcp", "address": addr, "port": port})
                    break

    return processes, network


def start_tcpdump() -> subprocess.Popen | None:
    """Start tcpdump to capture all network traffic to a pcap file."""
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-w", PCAP_PATH, "-U"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Give tcpdump a moment to initialize
        time.sleep(0.5)
        return proc
    except Exception:
        return None


def stop_tcpdump(proc: subprocess.Popen | None) -> None:
    """Stop tcpdump gracefully."""
    if proc is None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass


def parse_pcap() -> dict:
    """Parse the captured pcap file using tcpdump text output.

    Returns a dict with dns_queries, connections, http_hosts,
    total_packets, total_bytes, and pcap_size.
    """
    result: dict = {
        "dns_queries": [],
        "connections": [],
        "http_hosts": [],
        "total_packets": 0,
        "total_bytes": 0,
        "pcap_size": 0,
    }

    if not os.path.exists(PCAP_PATH):
        return result

    try:
        result["pcap_size"] = os.path.getsize(PCAP_PATH)
    except OSError:
        pass

    # Pre-compile regexes used across parsing passes
    # Regex for DNS queries: e.g. "A? example.com." or "AAAA? example.com."
    dns_query_re = re.compile(r"\s(A{1,4})\?\s+(\S+?)\.?\s")
    # Regex for DNS answers: e.g. "A 1.2.3.4" after the query
    dns_answer_re = re.compile(r"\s+A\s+(\d+\.\d+\.\d+\.\d+)")
    # Regex for TCP SYN: src.port > dst.port: Flags [S]
    tcp_syn_re = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+"
        r"(\d+\.\d+\.\d+\.\d+)\.(\d+):.*Flags \[S\]"
    )
    # Regex for UDP traffic (non-DNS)
    udp_re = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+"
        r"(\d+\.\d+\.\d+\.\d+)\.(\d+):.*UDP"
    )
    # Regex for length in packets
    length_re = re.compile(r"length\s+(\d+)")

    # Parse verbose tcpdump output for connection details
    try:
        out = subprocess.run(
            ["tcpdump", "-r", PCAP_PATH, "-nn", "-v"],
            capture_output=True, text=True, timeout=15,
        )
        lines = out.stdout.strip().splitlines()
        result["total_packets"] = len(lines)

        seen_dns: set[str] = set()
        seen_conns: set[str] = set()
        seen_hosts: set[str] = set()

        for line in lines:
            # Count bytes from length fields
            lm = length_re.search(line)
            if lm:
                result["total_bytes"] += int(lm.group(1))

            # DNS queries
            dm = dns_query_re.search(line)
            if dm:
                qtype = dm.group(1)
                qname = dm.group(2).rstrip(".")
                if qname not in seen_dns:
                    # Look for the answer in the same line
                    ans = dns_answer_re.search(line)
                    response = ans.group(1) if ans else ""
                    result["dns_queries"].append({
                        "query": qname,
                        "type": qtype,
                        "response": response,
                    })
                    seen_dns.add(qname)

            # TCP SYN connections
            sm = tcp_syn_re.search(line)
            if sm:
                src = f"{sm.group(1)}:{sm.group(2)}"
                dst = f"{sm.group(3)}:{sm.group(4)}"
                conn_key = f"{src}->{dst}"
                if conn_key not in seen_conns:
                    result["connections"].append({
                        "src": src,
                        "dst": dst,
                        "protocol": "tcp",
                        "bytes": 0,
                    })
                    seen_conns.add(conn_key)

            # UDP connections (non-DNS, port != 53)
            um = udp_re.search(line)
            if um:
                src = f"{um.group(1)}:{um.group(2)}"
                dst = f"{um.group(3)}:{um.group(4)}"
                if um.group(4) != "53" and um.group(2) != "53":
                    conn_key = f"{src}->{dst}"
                    if conn_key not in seen_conns:
                        result["connections"].append({
                            "src": src,
                            "dst": dst,
                            "protocol": "udp",
                            "bytes": 0,
                        })
                        seen_conns.add(conn_key)

            # HTTP Host headers (look in packet payload)
            if "Host:" in line:
                host_match = re.search(r"Host:\s*(\S+)", line)
                if host_match:
                    host = host_match.group(1)
                    if host not in seen_hosts:
                        result["http_hosts"].append(host)
                        seen_hosts.add(host)
    except Exception:
        pass

    # Second pass: try to extract HTTP hosts from ASCII dump
    if not result["http_hosts"]:
        try:
            out = subprocess.run(
                ["tcpdump", "-r", PCAP_PATH, "-nn", "-A"],
                capture_output=True, text=True, timeout=15,
            )
            seen_hosts_set: set[str] = set()
            for line in out.stdout.splitlines():
                if line.strip().startswith("Host:"):
                    host_match = re.search(r"Host:\s*(\S+)", line)
                    if host_match:
                        host = host_match.group(1)
                        if host not in seen_hosts_set:
                            result["http_hosts"].append(host)
                            seen_hosts_set.add(host)
        except Exception:
            pass

    # Update connection byte counts by parsing per-connection stats
    # This is approximate - sum length fields per connection pair
    try:
        out = subprocess.run(
            ["tcpdump", "-r", PCAP_PATH, "-nn", "-q"],
            capture_output=True, text=True, timeout=15,
        )
        conn_bytes: dict[str, int] = {}
        conn_q_re = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+"
            r"(\d+\.\d+\.\d+\.\d+)\.(\d+):"
        )
        for line in out.stdout.splitlines():
            cm = conn_q_re.search(line)
            if cm:
                src = f"{cm.group(1)}:{cm.group(2)}"
                dst = f"{cm.group(3)}:{cm.group(4)}"
                lm = length_re.search(line)
                nbytes = int(lm.group(1)) if lm else 0
                # Normalize direction
                fwd = f"{src}->{dst}"
                rev = f"{dst}->{src}"
                if fwd in conn_bytes:
                    conn_bytes[fwd] += nbytes
                elif rev in conn_bytes:
                    conn_bytes[rev] += nbytes
                else:
                    conn_bytes[fwd] = nbytes

        for conn in result["connections"]:
            key = f"{conn['src']}->{conn['dst']}"
            rev_key = f"{conn['dst']}->{conn['src']}"
            conn["bytes"] = conn_bytes.get(key, 0) + conn_bytes.get(rev_key, 0)
    except Exception:
        pass

    return result


def _emit_event(events_file, event: dict) -> None:
    """Write one JSON event line to the events file and flush."""
    try:
        events_file.write(json.dumps(event) + "\n")
        events_file.flush()
    except OSError:
        pass


def _tail_strace(
    strace_path: str,
    events_file,
    start_time: float,
    stop_event: threading.Event,
) -> None:
    """Tail the strace log file and emit parsed events in real time.

    Runs in a separate thread while the sample is executing.
    """
    execve_re = re.compile(
        r"^(\d+)\s+execve\(\"([^\"]+)\",\s*\[([^\]]*)\]"
    )
    clone_re = re.compile(
        r"^(\d+)\s+clone\d*\(.*\)\s*=\s*(\d+)"
    )
    connect_re = re.compile(
        r"^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET6?,\s*"
        r"sin6?_port=htons\((\d+)\),\s*sin6?_addr="
        r"(?:inet_pton\([^,]+,\s*)?\"([^\"]+)\""
    )
    connect_simple_re = re.compile(
        r"^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET,\s*"
        r"sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\(\"([^\"]+)\"\)"
    )
    openat_re = re.compile(
        r"^(\d+)\s+openat?\([^,]*,\s*\"([^\"]+)\".*O_CREAT"
    )

    seen_pids: set[str] = set()
    pid_to_ppid: dict[int, int] = {}

    # Wait for strace log to appear
    for _ in range(50):
        if os.path.exists(strace_path) or stop_event.is_set():
            break
        time.sleep(0.1)

    if not os.path.exists(strace_path):
        return

    with open(strace_path) as f:
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                # No new data yet, poll briefly
                time.sleep(0.05)
                continue

            ts = round(time.time() - start_time, 3)

            # Track clone events for ppid mapping
            m = clone_re.match(line)
            if m:
                ppid = int(m.group(1))
                child_pid = int(m.group(2))
                if child_pid > 0:
                    pid_to_ppid[child_pid] = ppid
                continue

            # Process spawn
            m = execve_re.match(line)
            if m:
                pid = m.group(1)
                cmd = m.group(2)
                raw_args = m.group(3)
                args = [a.strip().strip('"') for a in raw_args.split(",") if a.strip()]
                if pid not in seen_pids:
                    seen_pids.add(pid)
                    _emit_event(events_file, {
                        "type": "process",
                        "timestamp": ts,
                        "pid": int(pid),
                        "ppid": pid_to_ppid.get(int(pid)),
                        "command": cmd,
                        "args": args,
                    })
                continue

            # Network connection
            for rx in (connect_re, connect_simple_re):
                m = rx.match(line)
                if m:
                    port = int(m.group(2))
                    addr = m.group(3)
                    if addr not in ("127.0.0.1", "::1", "0.0.0.0"):
                        pid_str = line.split()[0] if line.split() else "0"
                        _emit_event(events_file, {
                            "type": "network",
                            "timestamp": ts,
                            "pid": int(pid_str),
                            "protocol": "tcp",
                            "address": addr,
                            "port": port,
                        })
                    break

            # File creation via openat/open with O_CREAT
            m = openat_re.match(line)
            if m:
                pid = m.group(1)
                path = m.group(2)
                if path not in (STRACE_LOG, RESULTS_PATH, EVENTS_PATH, PCAP_PATH):
                    _emit_event(events_file, {
                        "type": "file",
                        "timestamp": ts,
                        "pid": int(pid),
                        "operation": "create",
                        "path": path,
                    })

        # Drain any remaining lines after stop
        while True:
            line = f.readline()
            if not line:
                break


def yara_scan_file(file_path: str) -> list[dict]:
    """Run YARA scan on a single file using the yara CLI.

    Returns a list of match dicts with rule, tags, meta, and strings.
    """
    if not os.path.exists(YARA_RULES_INDEX):
        return []
    if not os.path.exists(file_path):
        return []

    matches: list[dict] = []
    try:
        proc_result = subprocess.run(
            ["yara", "-s", "-m", YARA_RULES_INDEX, file_path],
            capture_output=True, text=True, timeout=30,
        )
        if proc_result.returncode != 0:
            return []

        current_match: dict | None = None
        for line in proc_result.stdout.splitlines():
            if not line:
                continue

            if not line.startswith("0x"):
                if current_match is not None:
                    matches.append(current_match)

                parts = line.strip()
                rule_name = ""
                tags: list[str] = []
                meta: dict[str, str] = {}

                tokens = parts.split(" ", 1)
                rule_name = tokens[0]

                if len(tokens) > 1:
                    remainder = tokens[1]
                    if remainder.startswith("["):
                        bracket_end = remainder.find("]")
                        if bracket_end > 0:
                            tag_str = remainder[1:bracket_end]
                            tags = [t.strip() for t in tag_str.split(",") if t.strip()]
                            remainder = remainder[bracket_end + 1:].strip()
                    if remainder.startswith("["):
                        bracket_end = remainder.find("]")
                        if bracket_end > 0:
                            meta_str = remainder[1:bracket_end]
                            for pair in meta_str.split(","):
                                if "=" in pair:
                                    k, v = pair.split("=", 1)
                                    meta[k.strip()] = v.strip()

                current_match = {
                    "rule": rule_name,
                    "tags": tags,
                    "meta": meta,
                    "strings": [],
                }
            elif current_match is not None:
                string_info = line.strip()
                sparts = string_info.split(":", 2)
                if len(sparts) >= 2:
                    offset = sparts[0].strip()
                    identifier = sparts[1].strip()
                    current_match["strings"].append(f"{identifier} at {offset}")

        if current_match is not None:
            matches.append(current_match)

    except (subprocess.TimeoutExpired, OSError):
        pass

    return matches


def count_yara_rules() -> int:
    """Count the total number of YARA rules loaded."""
    if not os.path.exists(YARA_RULES_INDEX):
        return 0
    try:
        count = 0
        rules_dir = os.path.dirname(YARA_RULES_INDEX)
        for fname in os.listdir(rules_dir):
            if fname.endswith(".yar") and fname != "index.yar":
                fpath = os.path.join(rules_dir, fname)
                with open(fpath) as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith("rule ") and not stripped.startswith("rule:"):
                            count += 1
        return count
    except OSError:
        return 0


def run_yara_scanning(
    sample_path: str,
    files_created: list[dict],
    files_modified: list[dict],
) -> dict:
    """Run YARA scanning on the sample and all dropped/modified files."""
    yara_result: dict = {
        "sample_matches": [],
        "dropped_file_matches": [],
        "total_matches": 0,
        "rules_loaded": count_yara_rules(),
    }

    sample_matches = yara_scan_file(sample_path)
    yara_result["sample_matches"] = sample_matches
    total = len(sample_matches)

    dropped_files = [f["path"] for f in files_created] + [f["path"] for f in files_modified]
    for fpath in dropped_files:
        file_matches = yara_scan_file(fpath)
        if file_matches:
            yara_result["dropped_file_matches"].append({
                "file": fpath,
                "matches": file_matches,
            })
            total += len(file_matches)

    yara_result["total_matches"] = total
    return yara_result


def start_xvfb() -> subprocess.Popen | None:
    """Start Xvfb virtual framebuffer for headless display."""
    try:
        proc = subprocess.Popen(
            ["Xvfb", XVFB_DISPLAY, "-screen", "0", "1280x720x24"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.environ["DISPLAY"] = XVFB_DISPLAY
        time.sleep(0.5)
        return proc
    except FileNotFoundError:
        return None


def start_x11vnc() -> subprocess.Popen | None:
    """Start x11vnc to expose the Xvfb display for interactive VNC sessions."""
    try:
        proc = subprocess.Popen(
            ["x11vnc", "-display", XVFB_DISPLAY, "-forever", "-nopw",
             "-rfbport", "5900", "-shared", "-quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.3)
        return proc
    except FileNotFoundError:
        return None


def capture_screenshots(
    stop_event: threading.Event,
    interval: float = 1.0,
) -> None:
    """Capture periodic screenshots from Xvfb display using scrot."""
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    frame = 0
    while not stop_event.is_set():
        try:
            output_path = os.path.join(SCREENSHOTS_DIR, f"frame_{frame:06d}.png")
            subprocess.run(
                ["scrot", output_path],
                env={**os.environ, "DISPLAY": XVFB_DISPLAY},
                capture_output=True,
                timeout=5,
            )
            frame += 1
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        stop_event.wait(interval)


def assemble_video() -> bool:
    """Assemble screenshots into an MP4 video using ffmpeg."""
    pattern = os.path.join(SCREENSHOTS_DIR, "frame_%06d.png")
    # Check if any frames exist
    if not os.path.isdir(SCREENSHOTS_DIR):
        return False
    frames = [f for f in os.listdir(SCREENSHOTS_DIR) if f.endswith(".png")]
    if not frames:
        return False

    try:
        subprocess.run(
            [
                "ffmpeg", "-y", "-framerate", "1",
                "-i", pattern,
                "-c:v", "libx264", "-pix_fmt", "yuv420p",
                "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2",
                VIDEO_PATH,
            ],
            capture_output=True,
            timeout=60,
        )
        return os.path.exists(VIDEO_PATH)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def collect_screenshot_data() -> list[tuple[str, bytes]]:
    """Collect all screenshot frames as (filename, bytes) tuples."""
    result = []
    if not os.path.isdir(SCREENSHOTS_DIR):
        return result
    for fname in sorted(os.listdir(SCREENSHOTS_DIR)):
        if fname.endswith(".png"):
            fpath = os.path.join(SCREENSHOTS_DIR, fname)
            try:
                with open(fpath, "rb") as f:
                    result.append((fname, f.read()))
            except OSError:
                pass
    return result


def run(sample_path: str, timeout: int, enable_pcap: bool = False) -> dict:
    os.chmod(sample_path, 0o755)

    enable_screenshots = os.environ.get("DETONATE_SCREENSHOTS", "0") == "1"
    enable_vnc = os.environ.get("DETONATE_VNC", "0") == "1"
    screenshot_interval = float(os.environ.get("DETONATE_SCREENSHOT_INTERVAL", "1.0"))

    before = snapshot_fs(WATCH_DIRS)

    # Start Xvfb if screenshots or VNC requested
    xvfb_proc = None
    vnc_proc = None
    screenshot_stop = threading.Event()
    screenshot_thread = None

    if enable_screenshots or enable_vnc:
        xvfb_proc = start_xvfb()

    if enable_vnc and xvfb_proc:
        vnc_proc = start_x11vnc()

    if enable_screenshots and xvfb_proc:
        screenshot_thread = threading.Thread(
            target=capture_screenshots,
            args=(screenshot_stop, screenshot_interval),
            daemon=True,
        )
        screenshot_thread.start()

    # Start tcpdump before sample execution if pcap capture is enabled
    tcpdump_proc = None
    if enable_pcap:
        tcpdump_proc = start_tcpdump()

    strace_cmd = [
        "strace", "-f", "-q",
        "-e", "trace=process,network,open,openat,unlink,write,clone,clone3",
        "-o", STRACE_LOG,
        sample_path,
    ]

    start = time.time()
    timed_out = False
    stdout_data = ""
    stderr_data = ""
    exit_code = -1

    # Open the events JSONL file for real-time streaming
    os.makedirs(os.path.dirname(EVENTS_PATH) or "/tmp", exist_ok=True)
    events_file = open(EVENTS_PATH, "w")
    stop_event = threading.Event()
    tail_thread = None

    try:
        proc = subprocess.Popen(
            strace_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/tmp",
        )

        # Start tailing strace output in a background thread
        tail_thread = threading.Thread(
            target=_tail_strace,
            args=(STRACE_LOG, events_file, start, stop_event),
            daemon=True,
        )
        tail_thread.start()

        try:
            out, err = proc.communicate(timeout=timeout)
            stdout_data = out.decode(errors="replace")[:4096]
            stderr_data = err.decode(errors="replace")[:4096]
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            stdout_data = out.decode(errors="replace")[:4096]
            stderr_data = err.decode(errors="replace")[:4096]
            timed_out = True
            exit_code = -9
    except Exception as e:
        stderr_data = str(e)

    # Stop tcpdump after sample execution completes
    stop_tcpdump(tcpdump_proc)

    duration = time.time() - start

    # Stop screenshots and assemble video
    if screenshot_thread is not None:
        screenshot_stop.set()
        screenshot_thread.join(timeout=3)

    # Stop the tail thread and let it drain remaining lines
    stop_event.set()
    if tail_thread is not None:
        tail_thread.join(timeout=3)

    # Emit the final status event
    _emit_event(events_file, {
        "type": "status",
        "timestamp": round(duration, 3),
        "message": "execution_complete",
        "exit_code": exit_code,
    })
    events_file.close()

    # Stop VNC and Xvfb
    if vnc_proc:
        try:
            vnc_proc.terminate()
            vnc_proc.wait(timeout=3)
        except Exception:
            pass
    if xvfb_proc:
        try:
            xvfb_proc.terminate()
            xvfb_proc.wait(timeout=3)
        except Exception:
            pass

    after = snapshot_fs(WATCH_DIRS)
    created, modified, deleted = diff_fs(before, after)
    processes, network = parse_strace(STRACE_LOG)

    result = {
        "execution": {
            "exit_code": exit_code,
            "duration_seconds": round(duration, 2),
            "timed_out": timed_out,
        },
        "processes": processes,
        "network": network,
        "files_created": created,
        "files_modified": modified,
        "files_deleted": deleted,
        "stdout": stdout_data,
        "stderr": stderr_data,
    }

    # Parse pcap data if capture was enabled
    if enable_pcap:
        result["pcap"] = parse_pcap()

    # Run YARA scanning on sample and dropped files
    result["yara"] = run_yara_scanning(sample_path, created, modified)

    # Collect screenshots and assemble video if screenshots were enabled
    if enable_screenshots:
        screenshot_data = collect_screenshot_data()
        if screenshot_data:
            import base64 as _b64
            result["_screenshot_data"] = [
                (name, _b64.b64encode(data).decode())
                for name, data in screenshot_data
            ]
            result["screenshot_count"] = len(screenshot_data)

        has_video = assemble_video()
        if has_video:
            try:
                with open(VIDEO_PATH, "rb") as vf:
                    result["_video_data"] = _b64.b64encode(vf.read()).decode()
            except OSError:
                pass

    return result


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: guest_agent.py <sample_path> [timeout_seconds]", file=sys.stderr)
        sys.exit(1)

    sample_path = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    enable_pcap = os.environ.get("DETONATE_PCAP", "0") == "1"

    results = run(sample_path, timeout, enable_pcap=enable_pcap)

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
