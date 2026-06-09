#!/usr/bin/env python3
"""xorpack.py — Module 4.2 helper: the "packer" side AND the static unpacker.

A real packer compresses/encrypts a payload and ships a stub that restores it at
runtime. This minimal version XOR-encrypts a payload with a repeating key and
emits a C array you can paste into a stub (see crypt_stub.c, which is already
generated). The SAME function decrypts — which is the analyst's job once you've
recovered the key.

Usage:
  python3 xorpack.py encode "secret text" K3yz     # -> C array
  python3 xorpack.py decode 41,12,...   K3yz        # -> plaintext
"""
import sys


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    mode, payload, key = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    if mode == "encode":
        enc = xor(payload.encode(), key)
        arr = ", ".join(f"0x{b:02x}" for b in enc)
        print(f"/* key=\"{key.decode()}\" len={len(enc)} */")
        print(f"static unsigned char enc[] = {{ {arr} }};")
    elif mode == "decode":
        enc = bytes(int(x, 0) for x in payload.replace(" ", "").split(","))
        print(xor(enc, key).decode(errors="replace"))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
