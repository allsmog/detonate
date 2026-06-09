#!/usr/bin/env python3
"""deobf.py — Module 4.4: automate what you did by hand in 4.3.

Two real techniques, no sample-specific magic numbers:

  1. brute_xor1(blob)   : try all 256 single-byte XOR keys, return the key(s)
                          that yield printable text. This is how you recover an
                          unknown-key XOR string without reading the decryptor.

  2. identify_api(hash) : reverse djb2 API hashing by hashing a wordlist and
                          matching — turning an opaque hash back into a name.

Usage:
  python3 deobf.py xor 0x39,0x68,0x74,0x3f,0x22,0x3b,0x37,0x2a,0x36,0x3f,0x74,0x39,0x35,0x37
  python3 deobf.py api 0xff8760ae
"""
from __future__ import annotations

import string
import sys

PRINTABLE = set(bytes(string.printable, "ascii"))


def brute_xor1(blob: bytes):
    """Return [(key, plaintext), ...] for keys giving mostly-printable output."""
    hits = []
    for key in range(256):
        dec = bytes(b ^ key for b in blob)
        if all(c in PRINTABLE for c in dec):
            hits.append((key, dec.decode("ascii")))
    return hits


def djb2(s: str) -> int:
    h = 5381
    for c in s.encode():
        h = ((h * 33) + c) & 0xFFFFFFFF
    return h


def identify_api(target: int, wordlist=None) -> str | None:
    words = wordlist or [
        "open", "read", "write", "getenv", "system", "connect", "socket",
        "fork", "execve", "ptrace", "mmap", "dlopen", "dlsym", "send", "recv",
    ]
    for w in words:
        if djb2(w) == (target & 0xFFFFFFFF):
            return w
    return None


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    if mode == "xor":
        blob = bytes(int(x, 0) for x in sys.argv[2].split(","))
        hits = brute_xor1(blob)
        for key, txt in hits:
            print(f"key=0x{key:02x} -> {txt!r}")
        if not hits:
            print("no single-byte XOR key produced printable text")
    elif mode == "api":
        target = int(sys.argv[2], 0)
        name = identify_api(target)
        print(f"0x{target:08x} -> {name or '(not in wordlist)'}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
