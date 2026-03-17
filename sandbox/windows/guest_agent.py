#!/usr/bin/env python3
"""Windows guest agent for Detonate sandbox.

Runs as an HTTP server inside the Windows VM. Receives malware samples
via HTTP POST, executes them with Sysmon monitoring, and returns
structured analysis results.

The agent is designed to run as a Windows service (via NSSM or
sc.exe) so it starts automatically on boot. It listens on port 8080
and exposes the following endpoints:

  GET  /health  - Readiness probe (returns {"status": "ready"})
  POST /submit  - Accept a sample for execution (multipart/form-data)
  GET  /status  - Current execution status
  GET  /results - Full analysis results (available after completion)

Requirements:
  - Python 3.11+ (standard library only -- no third-party packages)
  - Sysmon installed and configured (see sysmon_config.xml)
  - PowerShell available for wevtutil / Sysmon log access
"""

import cgi
import http.server
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT = 8080
SAMPLE_DIR = r"C:\Users\sandbox\samples"
RESULTS_DIR = r"C:\Users\sandbox\results"
SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

# Directories to monitor for file-system changes
WATCH_DIRS = [
    r"C:\Users\sandbox\Desktop",
    r"C:\Users\sandbox\Documents",
    r"C:\Users\sandbox\AppData",
    r"C:\Windows\Temp",
    r"C:\Temp",
    r"C:\ProgramData",
]

# Paths to ignore during file-system diff (agent artifacts, logs, etc.)
IGNORE_PATHS = {
    SAMPLE_DIR.lower(),
    RESULTS_DIR.lower(),
}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("guest_agent")

# ---------------------------------------------------------------------------
# Global execution state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_execution_status: str = "idle"  # idle | running | completed | failed
_execution_error: str = ""
_execution_start: float = 0.0
_results: dict = {}


def _set_status(status: str, error: str = "") -> None:
    global _execution_status, _execution_error
    with _lock:
        _execution_status = status
        _execution_error = error


def _get_status() -> dict:
    with _lock:
        resp: dict = {"status": _execution_status}
        if _execution_error:
            resp["error"] = _execution_error
        if _execution_start > 0:
            resp["elapsed"] = round(time.monotonic() - _execution_start, 1)
        return resp


# ---------------------------------------------------------------------------
# File-system snapshot / diff
# ---------------------------------------------------------------------------

def snapshot_fs(dirs: list[str]) -> dict[str, float]:
    """Return {lowercase_path: mtime} for all files under watched dirs."""
    snap: dict[str, float] = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _dirnames, filenames in os.walk(d):
            for fname in filenames:
                fp = os.path.join(root, fname)
                try:
                    snap[fp.lower()] = os.path.getmtime(fp)
                except OSError:
                    pass
    return snap


def diff_fs(
    before: dict[str, float],
    after: dict[str, float],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Compare two filesystem snapshots and return created/modified/deleted."""
    created: list[dict] = []
    modified: list[dict] = []
    deleted: list[dict] = []

    for path, mtime in after.items():
        # Skip our own artifacts
        skip = False
        for ignore in IGNORE_PATHS:
            if path.startswith(ignore):
                skip = True
                break
        if skip:
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


# ---------------------------------------------------------------------------
# Sysmon event parser
# ---------------------------------------------------------------------------

class SysmonParser:
    """Parse Windows Event Log for Sysmon events.

    Uses wevtutil.exe to export events as XML, then parses them to
    extract process creation, network connections, file operations,
    registry changes, and DNS queries.

    Sysmon Event IDs of interest:
        1  - Process Create (ppid, cmdline, hashes, image)
        3  - Network Connection (protocol, src/dst addr+port)
        5  - Process Terminated
        11 - File Create (target filename)
        13 - Registry Value Set (key, value, details)
        22 - DNS Query (query name, result)
    """

    # XML namespace used by Windows Event Log
    NS = {
        "e": "http://schemas.microsoft.com/win/2004/08/events/event",
    }

    def __init__(self, after_time: datetime | None = None):
        """Initialize parser.

        Args:
            after_time: Only include events after this time. If None,
                        all events in the log are included.
        """
        self.after_time = after_time
        self.processes: list[dict] = []
        self.network: list[dict] = []
        self.files_created_sysmon: list[dict] = []
        self.registry_changes: list[dict] = []
        self.dns_queries: list[dict] = []
        self._seen_pids: set[int] = set()
        self._seen_connections: set[str] = set()
        self._seen_dns: set[str] = set()

    def parse_events(self) -> dict:
        """Export Sysmon events via wevtutil and parse them.

        Returns a dict with parsed event categories:
            processes, network, files_created_sysmon,
            registry_changes, dns_queries
        """
        xml_data = self._export_events()
        if not xml_data:
            logger.warning("No Sysmon events exported")
            return self._build_result()

        self._parse_xml(xml_data)
        return self._build_result()

    def _export_events(self) -> str:
        """Export Sysmon Operational log as XML using wevtutil."""
        # Build an XPath query to filter by time if needed
        cmd = ["wevtutil", "qe", SYSMON_LOG_NAME, "/f:xml"]

        if self.after_time is not None:
            # Format for XPath time filter:
            # *[System[TimeCreated[@SystemTime>='2024-01-01T00:00:00.000Z']]]
            ts = self.after_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            xpath = (
                f"*[System[TimeCreated[@SystemTime>='{ts}'] "
                f"and Provider[@Name='{SYSMON_PROVIDER}']]]"
            )
            cmd.extend(["/q:" + xpath])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if result.returncode != 0:
                logger.warning("wevtutil failed (rc=%d): %s", result.returncode, result.stderr[:500])
                return ""
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error("wevtutil timed out")
            return ""
        except FileNotFoundError:
            logger.error("wevtutil not found -- is this running on Windows?")
            return ""
        except Exception as exc:
            logger.error("wevtutil error: %s", exc)
            return ""

    def _parse_xml(self, xml_data: str) -> None:
        """Parse the concatenated XML events from wevtutil output.

        wevtutil outputs one <Event> element per line without a root
        wrapper, so we wrap them to form valid XML.
        """
        # Wrap in a root element for valid XML
        wrapped = f"<Events>{xml_data}</Events>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            # Try parsing line-by-line if the concatenated form fails
            self._parse_xml_line_by_line(xml_data)
            return

        for event_el in root:
            self._handle_event(event_el)

    def _parse_xml_line_by_line(self, xml_data: str) -> None:
        """Fallback parser: handle each <Event>...</Event> independently."""
        # Find all <Event ...>...</Event> blocks
        event_pattern = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL)
        for match in event_pattern.finditer(xml_data):
            try:
                event_el = ET.fromstring(match.group(0))
                self._handle_event(event_el)
            except ET.ParseError:
                continue

    def _handle_event(self, event_el: ET.Element) -> None:
        """Dispatch a single <Event> element to the correct handler."""
        # Extract EventID from System/EventID
        event_id = self._get_event_id(event_el)
        if event_id is None:
            return

        # Build a flat dict of EventData Name->Value pairs
        data = self._get_event_data(event_el)

        if event_id == 1:
            self._handle_process_create(data)
        elif event_id == 3:
            self._handle_network_connection(data)
        elif event_id == 5:
            self._handle_process_terminate(data)
        elif event_id == 11:
            self._handle_file_create(data)
        elif event_id == 13:
            self._handle_registry_set(data)
        elif event_id == 22:
            self._handle_dns_query(data)

    def _get_event_id(self, event_el: ET.Element) -> int | None:
        """Extract the integer EventID from an <Event> element."""
        # Try with namespace
        for prefix in ["e:", ""]:
            eid_el = event_el.find(f".//{prefix}System/{prefix}EventID", self.NS)
            if eid_el is not None and eid_el.text:
                try:
                    return int(eid_el.text)
                except ValueError:
                    pass
        # Try without namespace
        eid_el = event_el.find(".//EventID")
        if eid_el is not None and eid_el.text:
            try:
                return int(eid_el.text)
            except ValueError:
                pass
        return None

    def _get_event_data(self, event_el: ET.Element) -> dict[str, str]:
        """Extract all EventData Name/Value pairs as a flat dict."""
        data: dict[str, str] = {}
        # Try with namespace
        for prefix in ["e:", ""]:
            for data_el in event_el.findall(f".//{prefix}EventData/{prefix}Data", self.NS):
                name = data_el.get("Name", "")
                value = data_el.text or ""
                if name:
                    data[name] = value
        # Also try without namespace prefix
        for data_el in event_el.findall(".//EventData/Data"):
            name = data_el.get("Name", "")
            value = data_el.text or ""
            if name:
                data[name] = value
        return data

    # -- Event handlers ----------------------------------------------------

    def _handle_process_create(self, data: dict[str, str]) -> None:
        """Handle Sysmon Event ID 1: Process Create."""
        try:
            pid = int(data.get("ProcessId", "0"))
        except ValueError:
            pid = 0

        if pid in self._seen_pids:
            return
        self._seen_pids.add(pid)

        try:
            ppid = int(data.get("ParentProcessId", "0"))
        except ValueError:
            ppid = 0

        image = data.get("Image", "")
        command_line = data.get("CommandLine", "")
        hashes = data.get("Hashes", "")

        # Parse command line into command + args
        command = image
        args = self._parse_command_line(command_line)

        proc_entry: dict = {
            "pid": pid,
            "ppid": ppid,
            "command": command,
            "args": args,
        }

        # Include extra Windows-specific fields
        if hashes:
            proc_entry["hashes"] = self._parse_hashes(hashes)
        user = data.get("User", "")
        if user:
            proc_entry["user"] = user
        integrity = data.get("IntegrityLevel", "")
        if integrity:
            proc_entry["integrity_level"] = integrity

        self.processes.append(proc_entry)

    def _handle_network_connection(self, data: dict[str, str]) -> None:
        """Handle Sysmon Event ID 3: Network Connection."""
        protocol = data.get("Protocol", "tcp").lower()
        dst_ip = data.get("DestinationIp", "")
        src_ip = data.get("SourceIp", "")

        # Skip localhost connections
        if dst_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return
        # Skip connections to our own agent port
        dst_port_str = data.get("DestinationPort", "0")
        try:
            dst_port = int(dst_port_str)
        except ValueError:
            dst_port = 0
        if dst_port == PORT:
            return

        conn_key = f"{protocol}:{dst_ip}:{dst_port}"
        if conn_key in self._seen_connections:
            return
        self._seen_connections.add(conn_key)

        entry: dict = {
            "protocol": protocol,
            "address": dst_ip,
            "port": dst_port,
        }
        if src_ip:
            entry["source_address"] = src_ip
        src_port_str = data.get("SourcePort", "")
        if src_port_str:
            try:
                entry["source_port"] = int(src_port_str)
            except ValueError:
                pass
        image = data.get("Image", "")
        if image:
            entry["process"] = image

        self.network.append(entry)

    def _handle_process_terminate(self, data: dict[str, str]) -> None:
        """Handle Sysmon Event ID 5: Process Terminated.

        We don't add new data here, but we could enrich existing process
        records with termination info if needed.
        """
        pass

    def _handle_file_create(self, data: dict[str, str]) -> None:
        """Handle Sysmon Event ID 11: File Create."""
        target = data.get("TargetFilename", "")
        if not target:
            return
        # Skip our own artifacts
        target_lower = target.lower()
        for ignore in IGNORE_PATHS:
            if target_lower.startswith(ignore):
                return

        creation_time = data.get("CreationUtcTime", "")
        image = data.get("Image", "")

        entry: dict = {"path": target, "size": 0}
        if image:
            entry["created_by"] = image
        if creation_time:
            entry["creation_time"] = creation_time

        # Try to get actual file size
        try:
            if os.path.exists(target):
                entry["size"] = os.path.getsize(target)
        except OSError:
            pass

        self.files_created_sysmon.append(entry)

    def _handle_registry_set(self, data: dict[str, str]) -> None:
        """Handle Sysmon Event ID 13: Registry Value Set."""
        key = data.get("TargetObject", "")
        details = data.get("Details", "")
        event_type = data.get("EventType", "")
        image = data.get("Image", "")

        if not key:
            return

        entry: dict = {
            "key": key,
            "value": details,
            "event_type": event_type,
        }
        if image:
            entry["process"] = image

        self.registry_changes.append(entry)

    def _handle_dns_query(self, data: dict[str, str]) -> None:
        """Handle Sysmon Event ID 22: DNS Query."""
        query_name = data.get("QueryName", "")
        query_results = data.get("QueryResults", "")
        query_status = data.get("QueryStatus", "")
        image = data.get("Image", "")

        if not query_name:
            return
        if query_name in self._seen_dns:
            return
        self._seen_dns.add(query_name)

        entry: dict = {
            "query": query_name,
            "response": query_results,
        }
        if query_status:
            entry["status"] = query_status
        if image:
            entry["process"] = image

        self.dns_queries.append(entry)

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _parse_command_line(cmd_line: str) -> list[str]:
        """Split a Windows command line into a list of arguments.

        Handles quoted strings and basic escaping.
        """
        if not cmd_line:
            return []
        args: list[str] = []
        current = ""
        in_quotes = False
        for char in cmd_line:
            if char == '"':
                in_quotes = not in_quotes
            elif char == " " and not in_quotes:
                if current:
                    args.append(current)
                    current = ""
            else:
                current += char
        if current:
            args.append(current)
        return args

    @staticmethod
    def _parse_hashes(hashes_str: str) -> dict[str, str]:
        """Parse Sysmon hash string like 'SHA256=abc,MD5=def' into a dict."""
        result: dict[str, str] = {}
        for pair in hashes_str.split(","):
            pair = pair.strip()
            if "=" in pair:
                algo, value = pair.split("=", 1)
                result[algo.strip()] = value.strip()
        return result

    def _build_result(self) -> dict:
        return {
            "processes": self.processes,
            "network": self.network,
            "files_created_sysmon": self.files_created_sysmon,
            "registry_changes": self.registry_changes,
            "dns_queries": self.dns_queries,
        }

    @staticmethod
    def clear_log() -> bool:
        """Clear the Sysmon operational log before analysis.

        Returns True on success, False on failure.
        """
        try:
            result = subprocess.run(
                ["wevtutil", "cl", SYSMON_LOG_NAME],
                capture_output=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            return result.returncode == 0
        except Exception as exc:
            logger.warning("Failed to clear Sysmon log: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Sample execution
# ---------------------------------------------------------------------------

def execute_sample(sample_path: str, timeout: int) -> None:
    """Execute a sample and monitor it with Sysmon.

    Runs in a background thread. Updates global state with results.

    Steps:
        1. Clear the Sysmon event log
        2. Snapshot the file system
        3. Start the sample process
        4. Wait up to timeout seconds
        5. Terminate the sample and any child processes
        6. Parse Sysmon events
        7. Diff the file system
        8. Build and store the results dict
    """
    global _results, _execution_start

    _execution_start = time.monotonic()
    _set_status("running")

    try:
        # Step 1: Clear Sysmon log so we only see events from this execution
        logger.info("Clearing Sysmon log")
        SysmonParser.clear_log()

        # Record the start time for Sysmon event filtering
        analysis_start_time = datetime.now(timezone.utc)

        # Step 2: Snapshot file system
        logger.info("Taking filesystem snapshot")
        fs_before = snapshot_fs(WATCH_DIRS)

        # Step 3: Execute the sample
        logger.info("Executing sample: %s (timeout=%ds)", sample_path, timeout)
        start_time = time.monotonic()
        timed_out = False
        exit_code = -1
        stdout_data = ""
        stderr_data = ""

        try:
            # Determine how to execute based on extension
            ext = os.path.splitext(sample_path)[1].lower()

            if ext in (".ps1",):
                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", sample_path]
            elif ext in (".bat", ".cmd"):
                cmd = ["cmd.exe", "/c", sample_path]
            elif ext in (".vbs", ".vbe", ".wsf"):
                cmd = ["cscript.exe", "//NoLogo", sample_path]
            elif ext in (".js", ".jse"):
                cmd = ["wscript.exe", "//NoLogo", sample_path]
            elif ext in (".msi",):
                cmd = ["msiexec.exe", "/i", sample_path, "/quiet", "/norestart"]
            elif ext in (".dll",):
                cmd = ["rundll32.exe", sample_path + ",DllMain"]
            else:
                # Default: execute directly (.exe and anything else)
                cmd = [sample_path]

            creation_flags = 0
            if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                creation_flags |= subprocess.CREATE_NEW_PROCESS_GROUP

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=SAMPLE_DIR,
                creationflags=creation_flags,
            )

            try:
                out, err = proc.communicate(timeout=timeout)
                stdout_data = out.decode(errors="replace")[:8192]
                stderr_data = err.decode(errors="replace")[:8192]
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                logger.info("Sample execution timed out after %ds", timeout)
                _kill_process_tree(proc.pid)
                try:
                    out, err = proc.communicate(timeout=5)
                    stdout_data = out.decode(errors="replace")[:8192]
                    stderr_data = err.decode(errors="replace")[:8192]
                except Exception:
                    pass
                timed_out = True
                exit_code = -9

        except Exception as exc:
            logger.error("Failed to execute sample: %s", exc)
            stderr_data = str(exc)

        duration = time.monotonic() - start_time

        # Step 4: Wait a moment for Sysmon to flush events
        time.sleep(2)

        # Step 5: Parse Sysmon events
        logger.info("Parsing Sysmon events")
        parser = SysmonParser(after_time=analysis_start_time)
        sysmon_data = parser.parse_events()

        # Step 6: Diff file system
        logger.info("Diffing filesystem")
        fs_after = snapshot_fs(WATCH_DIRS)
        created, modified, deleted = diff_fs(fs_before, fs_after)

        # Merge Sysmon file creates with fs diff (Sysmon may catch files
        # in directories we don't watch)
        created_paths = {f["path"].lower() for f in created}
        for sysmon_file in sysmon_data.get("files_created_sysmon", []):
            if sysmon_file["path"].lower() not in created_paths:
                created.append(sysmon_file)

        # Step 7: Build results
        _results = {
            "execution": {
                "exit_code": exit_code,
                "duration_seconds": round(duration, 2),
                "timed_out": timed_out,
            },
            "processes": sysmon_data.get("processes", []),
            "network": sysmon_data.get("network", []),
            "files_created": created,
            "files_modified": modified,
            "files_deleted": deleted,
            "registry_changes": sysmon_data.get("registry_changes", []),
            "dns_queries": sysmon_data.get("dns_queries", []),
            "stdout": stdout_data,
            "stderr": stderr_data,
        }

        logger.info(
            "Analysis complete: exit=%d timed_out=%s processes=%d network=%d "
            "files_created=%d registry=%d dns=%d",
            exit_code,
            timed_out,
            len(_results["processes"]),
            len(_results["network"]),
            len(_results["files_created"]),
            len(_results["registry_changes"]),
            len(_results["dns_queries"]),
        )

        _set_status("completed")

    except Exception as exc:
        logger.error("Execution thread failed: %s\n%s", exc, traceback.format_exc())
        _results = {
            "execution": {
                "exit_code": -1,
                "duration_seconds": 0,
                "timed_out": False,
            },
            "error": str(exc),
            "processes": [],
            "network": [],
            "files_created": [],
            "files_modified": [],
            "files_deleted": [],
            "registry_changes": [],
            "dns_queries": [],
            "stdout": "",
            "stderr": "",
        }
        _set_status("failed", str(exc))


def _kill_process_tree(pid: int) -> None:
    """Kill a process and all its children on Windows using taskkill."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except Exception as exc:
        logger.warning("Failed to kill process tree (pid=%d): %s", pid, exc)


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class SandboxHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for sandbox operations.

    Implements the guest agent protocol that the QEMU machinery
    communicates with to submit samples and retrieve results.
    """

    # Suppress default stderr logging
    def log_message(self, format, *args):
        logger.info("HTTP %s %s", self.command, self.path)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/status":
            self._handle_status()
        elif self.path == "/results":
            self._handle_results()
        else:
            self._send_error(404, "Not found")

    def do_POST(self) -> None:
        if self.path == "/submit":
            self._handle_submit()
        else:
            self._send_error(404, "Not found")

    # -- Endpoint handlers -------------------------------------------------

    def _handle_health(self) -> None:
        """Report agent readiness."""
        self._send_json(200, {
            "status": "ready",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
        })

    def _handle_status(self) -> None:
        """Report current execution status."""
        self._send_json(200, _get_status())

    def _handle_results(self) -> None:
        """Return full analysis results. Only available after completion."""
        status = _get_status()
        if status["status"] not in ("completed", "failed"):
            self._send_error(409, "Analysis not yet complete")
            return
        self._send_json(200, _results)

    def _handle_submit(self) -> None:
        """Receive a sample file and start execution.

        Expects multipart/form-data with:
          - file: The sample binary
          - timeout: Execution timeout in seconds (optional, default 120)
        """
        global _results

        # Reject if already running
        current = _get_status()
        if current["status"] == "running":
            self._send_error(409, "Analysis already in progress")
            return

        # Parse multipart form data
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_error(400, "Expected multipart/form-data")
            return

        try:
            # Read the request body
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self._send_error(400, "Empty request body")
                return
            if content_length > 256 * 1024 * 1024:  # 256 MB limit
                self._send_error(413, "File too large")
                return

            body = self.rfile.read(content_length)

            # Parse multipart form
            environ = {
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": content_type,
                "CONTENT_LENGTH": str(content_length),
            }
            fs = cgi.FieldStorage(
                fp=io.BytesIO(body),
                environ=environ,
                keep_blank_values=True,
            )

            # Extract the file
            file_item = fs["file"]
            if not hasattr(file_item, "filename") or not file_item.filename:
                self._send_error(400, "No file uploaded")
                return

            filename = os.path.basename(file_item.filename)
            file_data = file_item.file.read()

            # Extract timeout
            timeout = 120
            if "timeout" in fs:
                try:
                    timeout = int(fs["timeout"].value)
                    timeout = max(10, min(timeout, 600))  # Clamp 10-600s
                except (ValueError, AttributeError):
                    pass

        except KeyError:
            self._send_error(400, "Missing 'file' field in form data")
            return
        except Exception as exc:
            self._send_error(400, f"Failed to parse form data: {exc}")
            return

        # Save the sample to disk
        os.makedirs(SAMPLE_DIR, exist_ok=True)
        sample_path = os.path.join(SAMPLE_DIR, filename)
        with open(sample_path, "wb") as f:
            f.write(file_data)

        logger.info("Received sample: %s (%d bytes, timeout=%ds)", filename, len(file_data), timeout)

        # Reset state and start execution in background thread
        _results = {}
        _set_status("running")

        thread = threading.Thread(
            target=execute_sample,
            args=(sample_path, timeout),
            daemon=True,
        )
        thread.start()

        self._send_json(200, {
            "accepted": True,
            "filename": filename,
            "size": len(file_data),
            "timeout": timeout,
        })

    # -- Response helpers --------------------------------------------------

    def _send_json(self, status_code: int, data: dict) -> None:
        """Send a JSON response."""
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status_code: int, message: str) -> None:
        """Send a JSON error response."""
        self._send_json(status_code, {"error": message})


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the guest agent HTTP server."""
    # Ensure required directories exist
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Bind to all interfaces
    server = http.server.HTTPServer(("0.0.0.0", PORT), SandboxHandler)
    logger.info("Guest agent listening on 0.0.0.0:%d", PORT)
    logger.info("Sample directory: %s", SAMPLE_DIR)
    logger.info("Sysmon log: %s", SYSMON_LOG_NAME)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down guest agent")
        server.shutdown()


if __name__ == "__main__":
    main()
