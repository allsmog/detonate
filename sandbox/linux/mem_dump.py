"""Post-execution memory artifact extraction for the Linux sandbox.

Strategy: while the sample process is alive, walk ``/proc/<pid>/maps``,
pull memory ranges that are readable+writable+anonymous (typical for
unpacked code) up to ``MAX_TOTAL_BYTES``, and emit:

- a printable-string list (>= 6 chars), and
- carved blobs that look like PE (``MZ``) or ELF (``\x7fELF``) headers.

Writing a full Volatility-style profile is out of scope; this script
gives you the *outputs* analysts care about: in-memory strings, a
list of unpacked-blob candidates, and SHA-256s for downstream YARA.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

MAX_TOTAL_BYTES = 64 * 1024 * 1024  # cap memory we slurp per process
MIN_STRING_LEN = 6


def _readable_anon(line: str) -> tuple[int, int] | None:
    # Format: "7f1234500000-7f1234508000 rw-p 00000000 00:00 0      [heap]"
    parts = line.split()
    if len(parts) < 5:
        return None
    addr_range, perms = parts[0], parts[1]
    if "r" not in perms or "x" in perms and "w" not in perms:
        return None
    if "w" not in perms:
        return None
    if "-" not in addr_range:
        return None
    start_s, end_s = addr_range.split("-", 1)
    try:
        start = int(start_s, 16)
        end = int(end_s, 16)
    except ValueError:
        return None
    if end <= start:
        return None
    return start, end


def collect_pid(pid: int) -> dict:
    out: dict = {
        "pid": pid,
        "regions_read": 0,
        "bytes_read": 0,
        "carved": [],
        "strings_count": 0,
        "errors": [],
    }
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    if not os.path.exists(maps_path):
        out["errors"].append("maps not found")
        return out

    strings: set[str] = set()
    string_re = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
    total = 0
    fd = None
    try:
        fd = open(mem_path, "rb", buffering=0)
        with open(maps_path) as mf:
            for line in mf:
                rng = _readable_anon(line)
                if not rng:
                    continue
                start, end = rng
                size = min(end - start, MAX_TOTAL_BYTES - total)
                if size <= 0:
                    break
                try:
                    fd.seek(start)
                    chunk = fd.read(size)
                except (OSError, OverflowError):
                    continue
                if not chunk:
                    continue
                total += len(chunk)
                out["regions_read"] += 1

                # Strings
                for m in string_re.finditer(chunk):
                    try:
                        strings.add(m.group(0).decode("ascii"))
                    except UnicodeDecodeError:
                        pass

                # Carve PE
                idx = 0
                while True:
                    i = chunk.find(b"MZ", idx)
                    if i < 0:
                        break
                    # Check for "PE\0\0" within e_lfanew range
                    if i + 0x40 < len(chunk):
                        try:
                            e_lfanew = int.from_bytes(chunk[i + 0x3C : i + 0x40], "little")
                            if 0 < e_lfanew < 0x1000 and i + e_lfanew + 4 < len(chunk):
                                if chunk[i + e_lfanew : i + e_lfanew + 4] == b"PE\x00\x00":
                                    blob = chunk[i : i + min(0x80000, len(chunk) - i)]
                                    out["carved"].append({
                                        "kind": "pe",
                                        "offset": start + i,
                                        "size": len(blob),
                                        "sha256": hashlib.sha256(blob).hexdigest(),
                                    })
                        except Exception:
                            pass
                    idx = i + 2

                # Carve ELF
                idx = 0
                while True:
                    i = chunk.find(b"\x7fELF", idx)
                    if i < 0:
                        break
                    blob = chunk[i : i + min(0x80000, len(chunk) - i)]
                    out["carved"].append({
                        "kind": "elf",
                        "offset": start + i,
                        "size": len(blob),
                        "sha256": hashlib.sha256(blob).hexdigest(),
                    })
                    idx = i + 4

                if total >= MAX_TOTAL_BYTES:
                    break
    except Exception as exc:
        out["errors"].append(repr(exc))
    finally:
        if fd:
            try:
                fd.close()
            except OSError:
                pass

    out["bytes_read"] = total
    out["strings_count"] = len(strings)
    out["strings"] = sorted(strings)[:2000]  # cap
    return out


def collect_all(pids: list[int], output_path: Path) -> dict:
    summary = {"pids": []}
    for pid in pids:
        try:
            summary["pids"].append(collect_pid(pid))
        except Exception as exc:
            summary["pids"].append({"pid": pid, "errors": [repr(exc)]})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: mem_dump.py <pid>[,<pid>...]", file=sys.stderr)
        sys.exit(1)
    pids = [int(p) for p in sys.argv[1].split(",")]
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/memory_artifacts.json")
    summary = collect_all(pids, out_path)
    print(json.dumps({"regions": sum(p.get("regions_read", 0) for p in summary["pids"])}))
