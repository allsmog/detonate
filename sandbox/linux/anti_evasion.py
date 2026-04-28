"""Anti-evasion preparation steps run inside the sandbox container
*before* the sample executes.

Pure stdlib so it works in the slim Ubuntu image without extra
packages. Each helper is best-effort: if it fails (e.g. permissions),
it logs and continues. The goal is to defeat the cheapest sandbox
fingerprints — empty home directories, recent-files emptiness,
hostname like "sandbox", no browser history — that account for the
majority of "boring sandbox" detection logic in commodity malware.

Activated when the host sets DETONATE_ANTI_EVASION=1.
"""

from __future__ import annotations

import os
import random
import socket
import subprocess
import time
from pathlib import Path


_FAKE_DOCS = [
    ("Documents/Resume_2024.docx", b"PK\x03\x04resume placeholder"),
    ("Documents/TaxReturn_2023.pdf", b"%PDF-1.4 placeholder"),
    ("Documents/MeetingNotes.txt", b"Q1 review notes\nfollow-ups\n"),
    ("Documents/budget.xlsx", b"PK\x03\x04budget placeholder"),
    ("Pictures/IMG_2412.jpg", b"\xff\xd8\xff\xe0fakejpeg"),
    ("Pictures/screenshot.png", b"\x89PNG\r\n\x1a\nfake"),
    ("Downloads/setup.exe", b"MZ fake installer"),
    ("Downloads/song.mp3", b"ID3 fake"),
    ("Desktop/notes.txt", b"reminder: pay rent\n"),
    (".bash_history", b"ls\ncd ~\nfirefox\nsudo apt update\n"),
    (".lesshst", b".\n"),
]


def _set_hostname(name: str) -> None:
    try:
        # Best-effort — works only when running with CAP_SYS_ADMIN
        with open("/proc/sys/kernel/hostname", "w") as f:
            f.write(name)
    except Exception:
        pass
    try:
        socket.sethostname(name)
    except Exception:
        pass
    try:
        Path("/etc/hostname").write_text(name + "\n")
    except Exception:
        pass


def _populate_home(user_home: Path) -> None:
    user_home.mkdir(parents=True, exist_ok=True)
    for rel, content in _FAKE_DOCS:
        target = user_home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(content)
            # Backdate mtime by a random amount up to 1 year so the
            # filesystem doesn't look like it was provisioned 30s ago.
            past = time.time() - random.randint(86_400, 365 * 86_400)
            os.utime(target, (past, past))
        except OSError:
            pass


def _seed_browser_history(user_home: Path) -> None:
    """Drop a fake recently-used.xbel and Firefox-style profile dir."""
    recent = user_home / ".local/share/recently-used.xbel"
    recent.parent.mkdir(parents=True, exist_ok=True)
    xbel = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<xbel version="1.0">\n'
        '  <bookmark href="file:///root/Documents/Resume_2024.docx">\n'
        '    <title>Resume_2024.docx</title>\n'
        '  </bookmark>\n'
        '  <bookmark href="https://example.com/login">\n'
        '    <title>Sign in - Example</title>\n'
        '  </bookmark>\n'
        "</xbel>\n"
    )
    try:
        recent.write_text(xbel)
    except OSError:
        pass

    ff_profile = user_home / ".mozilla/firefox/abc123.default-release"
    ff_profile.mkdir(parents=True, exist_ok=True)
    try:
        (ff_profile / "places.sqlite").write_bytes(b"SQLite format 3\x00fake")
        (ff_profile / "cookies.sqlite").write_bytes(b"SQLite format 3\x00fake")
    except OSError:
        pass


def _idle_jitter(seconds: float = 1.5) -> None:
    """Burn a small amount of CPU + sleep so anti-sandbox idle-detection
    that monitors initial CPU load sees activity."""
    end = time.time() + seconds
    n = 0
    while time.time() < end:
        n = (n * 31 + 7) & 0xFFFFFFFF
        if n % 1000 == 0:
            time.sleep(0.001)


def _generate_uptime_artifact() -> None:
    """Some samples check ``/proc/uptime``; we can't fake the kernel
    file but we can drop a high-uptime hint into ``/var/log/wtmp``-style
    files — best-effort and harmless if missing."""
    try:
        Path("/var/log/lastlog").write_bytes(b"\x00" * 4096)
    except OSError:
        pass


def prepare_sandbox(hostname: str = "DESKTOP-UF3R7K9") -> dict[str, object]:
    """Run all anti-evasion steps and return a summary dict for logging."""
    summary: dict[str, object] = {"steps": []}

    _set_hostname(hostname)
    summary["steps"].append({"hostname": hostname})

    user_home = Path(os.environ.get("HOME", "/root"))
    _populate_home(user_home)
    summary["steps"].append({"populated_home": str(user_home)})

    _seed_browser_history(user_home)
    summary["steps"].append({"seeded_browser_history": True})

    _generate_uptime_artifact()
    _idle_jitter(0.4)

    # Spawn a couple of innocent background processes so the process
    # tree isn't suspiciously empty. Detached daemons that the kernel
    # will reap automatically.
    for cmd in (["sleep", "120"], ["sleep", "180"]):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
    summary["steps"].append({"spawned_decoy_procs": 2})

    return summary


if __name__ == "__main__":
    import json
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "DESKTOP-UF3R7K9"
    print(json.dumps(prepare_sandbox(host), indent=2))
