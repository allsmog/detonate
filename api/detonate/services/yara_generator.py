"""Generate a YARA rule from a sample's most distinctive strings.

Strategy: take ASCII + wide strings extracted by ``static_analysis``,
prefer long, low-noise tokens (filter generic English words, library
strings, URL fragments seen across many samples), keep up to N, emit a
valid YARA rule that matches when ``--threshold`` of them are present.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Tokens we don't want as signature material (library/runtime noise)
_NOISE_PATTERNS = [
    re.compile(r"^[A-Za-z]{1,3}$"),  # very short
    re.compile(r"^[0-9.]+$"),
    re.compile(r"^https?://w3\.org"),
    re.compile(r"^https?://schemas\."),
    re.compile(r"^application/", re.IGNORECASE),
    re.compile(r"^image/", re.IGNORECASE),
    re.compile(r"^text/", re.IGNORECASE),
    re.compile(r"^font/", re.IGNORECASE),
    re.compile(r"GCC: \(.*\)"),
    re.compile(r"\.dynstr|\.dynsym|\.rela|\.gnu|\.note"),
    re.compile(r"libc\.so|ld-linux"),
    re.compile(r"^\\.+$"),
]

_GENERIC_WORDS = {
    "Microsoft", "Windows", "Corporation", "Reserved", "Copyright",
    "Library", "Module", "Version", "Application", "kernel32", "ntdll",
    "USER32", "ADVAPI32", "Microsoft Corporation", "All rights reserved",
}


def _is_noise(s: str) -> bool:
    if len(s) < 6 or len(s) > 80:
        return True
    if s in _GENERIC_WORDS:
        return True
    for rx in _NOISE_PATTERNS:
        if rx.search(s):
            return True
    # Mostly punctuation or non-printable
    printable = sum(1 for c in s if c.isalnum())
    if printable < len(s) // 3:
        return True
    return False


def _escape_yara_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def select_strings(static_result: dict[str, Any], max_strings: int = 12) -> list[str]:
    s = static_result.get("strings", {}) or {}
    candidates: list[str] = []
    candidates.extend(s.get("ascii_strings", []) or [])
    candidates.extend(s.get("wide_strings", []) or [])
    seen: set[str] = set()
    selected: list[str] = []
    for c in candidates:
        c = c.strip()
        if c in seen or _is_noise(c):
            continue
        seen.add(c)
        selected.append(c)
        if len(selected) >= max_strings:
            break
    return selected


def generate_yara_rule(
    static_result: dict[str, Any],
    rule_name: str | None = None,
    threshold: int = 3,
    family_tag: str | None = None,
) -> dict[str, Any]:
    """Build a YARA rule dict + serialized text from a static-analysis result."""
    sha256 = static_result.get("sha256") or static_result.get("filename", "sample")
    name = rule_name or f"detonate_auto_{hashlib.sha1(sha256.encode()).hexdigest()[:12]}"
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not name[:1].isalpha():
        name = "rule_" + name

    strings = select_strings(static_result, max_strings=12)
    if not strings:
        return {
            "rule_name": name,
            "yara": "",
            "strings": [],
            "warning": "Insufficient distinctive strings to generate a rule",
        }

    threshold = min(max(1, threshold), len(strings))
    family = family_tag or "auto_generated"

    lines = [f"rule {name}", "{", "    meta:"]
    lines.append(f'        author = "detonate-auto"')
    lines.append(f'        description = "Auto-generated from sample {sha256[:32]}"')
    lines.append(f'        family = "{family}"')
    lines.append(f'        sample_sha256 = "{sha256}"')
    lines.append("    strings:")
    for i, s in enumerate(strings):
        lines.append(f'        $s{i} = "{_escape_yara_string(s)}" ascii wide')
    lines.append("    condition:")
    lines.append(f"        {threshold} of ($s*)")
    lines.append("}")

    return {
        "rule_name": name,
        "yara": "\n".join(lines) + "\n",
        "strings": strings,
        "threshold": threshold,
    }
