#!/usr/bin/env python3
"""triage.py — Module 1.4 first-look triage, in ~60 lines of pure Python.

Computes the same signals Detonate's submission pipeline computes, so you can
see there's no magic: hashes, size, type guess, and Shannon entropy (with a
packed/encrypted heuristic). No third-party dependencies.

Usage:  python3 triage.py <file>
"""
from __future__ import annotations

import hashlib
import math
import sys


def shannon_entropy(data: bytes) -> float:
    """Bits-per-byte entropy (0..8). ~7.9+ suggests compression/encryption."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def magic_guess(data: bytes) -> str:
    """Tiny file-type guesser from magic bytes — the loader's first question."""
    if data[:2] == b"MZ":
        return "PE (Windows executable)"
    if data[:4] == b"\x7fELF":
        return "ELF (Unix executable)"
    if data[:4] in (b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1"):
        return "JPEG image"
    if data[:4] == b"%PDF":
        return "PDF document"
    if data[:2] == b"PK":
        return "ZIP/Office/JAR archive"
    return "unknown"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], "rb") as f:
        data = f.read()

    ent = shannon_entropy(data)
    print(f"file        : {sys.argv[1]}")
    print(f"size        : {len(data)} bytes")
    print(f"md5         : {hashlib.md5(data).hexdigest()}")
    print(f"sha1        : {hashlib.sha1(data).hexdigest()}")
    print(f"sha256      : {hashlib.sha256(data).hexdigest()}")
    print(f"type (magic): {magic_guess(data)}")
    print(f"entropy     : {ent:.4f} bits/byte")
    if ent > 7.2:
        print("  -> HIGH entropy: likely packed/encrypted/compressed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
