#!/usr/bin/env python3
"""extract_config.py — Module 6.2: an automated config extractor for the
`configbot` family.

A config extractor turns a one-off manual decryption into a repeatable tool:
locate the blob by signature, decrypt it, parse the fields, emit structured
output. This is the model real frameworks (CAPE, MWCP) follow.

Pipeline for the configbot family:
  1. find the "CFG0" magic in the file
  2. read the uint16 length that follows
  3. RC4-decrypt the next <length> bytes with the known key
  4. parse the "k=v;k=v" config into a dict (with C2 list split out)

Usage:  python3 extract_config.py ./configbot
Output: JSON config to stdout.
"""
from __future__ import annotations

import json
import sys

MAGIC = b"CFG0"
RC4_KEY = b"s3cr3tk3y"


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def extract(path: str) -> dict:
    raw = open(path, "rb").read()
    off = raw.find(MAGIC)
    if off < 0:
        raise ValueError("CFG0 magic not found — not a configbot sample?")
    length = int.from_bytes(raw[off + 4 : off + 6], "little")
    enc = raw[off + 6 : off + 6 + length]
    plain = rc4(RC4_KEY, enc).decode("utf-8", errors="replace")

    cfg: dict = {"raw": plain, "c2": []}
    for field in plain.split(";"):
        if "=" not in field:
            continue
        k, v = field.split("=", 1)
        if k == "c2":
            for endpoint in v.split(","):
                host, _, port = endpoint.partition(":")
                cfg["c2"].append({"host": host, "port": int(port) if port else None})
        else:
            cfg[k] = v
    return cfg


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    print(json.dumps(extract(sys.argv[1]), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
