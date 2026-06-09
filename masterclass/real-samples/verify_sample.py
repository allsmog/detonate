#!/usr/bin/env python3
"""verify_sample.py — confirm you're analyzing the EXACT documented sample, then
triage it. Use this when a real-sample lab gives you a SHA-256 to fetch.

Why: writeups describe a specific binary. A "Formbook sample" is meaningless —
the solution only matches if your bytes match. This tool refuses to proceed on a
hash mismatch, so you never waste an hour on the wrong sample (or a tampered
download).

Usage:
  python3 verify_sample.py <file> --sha256 <expected>
  python3 verify_sample.py <file>            # triage only, no verification

Safety: this does NOT execute the sample. Keep real samples zipped (password
'infected') until they're inside your isolated lab — see ../SAFETY.md.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import sys


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def magic(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE (Windows executable)"
    if data[:4] == b"\x7fELF":
        return "ELF (Unix executable)"
    if data[:2] == b"PK":
        return "ZIP/Office/JAR (is it still in the 'infected' zip?)"
    if data[:4] == b"%PDF":
        return "PDF"
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify + triage a malware sample.")
    ap.add_argument("file")
    ap.add_argument("--sha256", help="expected SHA-256 from the lab/writeup")
    args = ap.parse_args()

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    actual = hashlib.sha256(data).hexdigest()

    print(f"file        : {args.file}")
    print(f"size        : {len(data)} bytes")
    print(f"sha256      : {actual}")
    print(f"md5         : {hashlib.md5(data).hexdigest()}")
    print(f"type (magic): {magic(data)}")
    print(f"entropy     : {entropy(data):.4f} bits/byte"
          + ("   (HIGH — packed/encrypted?)" if entropy(data) > 7.2 else ""))

    if args.sha256:
        if actual.lower() == args.sha256.lower().strip():
            print("verify      : ✓ MATCH — this is the documented sample.")
            return 0
        print("verify      : ✗ MISMATCH — this is NOT the documented sample!")
        print("              Do not trust the writeup against this file. Re-fetch.")
        return 1
    print("verify      : (no --sha256 given; triage only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
