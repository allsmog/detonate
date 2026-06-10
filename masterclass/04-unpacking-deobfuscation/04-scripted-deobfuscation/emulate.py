#!/usr/bin/env python3
"""emulate.py — Module 4.4: run a malware decryptor with Unicorn instead of
reimplementing it.

Sometimes you don't want to port a gnarly decryption routine to Python — you
want to *run the original code* on the encrypted blob and read the plaintext
out. CPU emulation (Unicorn) lets you execute an isolated function with no OS,
no risk, and full control of memory/registers.

Here we emulate a REAL compiled x86-64 XOR-decrypt routine (the machine code
bytes below were produced by gcc from:  void dec(uint8_t*buf, size_t n, uint8_t
key){ for(i)buf[i]^=key; }). We map memory, place the encrypted blob, set the
SysV args (rdi=buf, rsi=n, dl=key), run until RET, and read the decrypted bytes
back.

Requires: pip install unicorn
Usage:    python3 emulate.py
"""
from __future__ import annotations

from unicorn import (
    UC_ARCH_X86, UC_MODE_64, Uc,
    UC_HOOK_CODE,
)
from unicorn.x86_const import (
    UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RSP,
)

# Real gcc output for the leaf routine `dec(buf, n, key)` (ends in 0xc3 RET).
DEC_CODE = bytes([
    0x48, 0x85, 0xf6, 0x74, 0x29, 0x48, 0x8d, 0x04, 0x37, 0x83, 0xe6, 0x01,
    0x74, 0x12, 0x30, 0x17, 0x48, 0x83, 0xc7, 0x01, 0x48, 0x39, 0xc7, 0x74,
    0x16, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x30, 0x17, 0x30, 0x57,
    0x01, 0x48, 0x83, 0xc7, 0x02, 0x48, 0x39, 0xc7, 0x75, 0xf2, 0xc3, 0xc3,
])

CODE_BASE = 0x1000
DATA_BASE = 0x200000
STACK_BASE = 0x300000
RET_MAGIC = 0xDEAD0000          # fake return address; we stop when RIP hits it


def emulate_decrypt(blob: bytes, key: int) -> bytes:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, 0x1000)
    mu.mem_map(DATA_BASE, 0x1000)
    mu.mem_map(STACK_BASE, 0x1000)

    mu.mem_write(CODE_BASE, DEC_CODE)
    mu.mem_write(DATA_BASE, blob)

    # SysV x86-64 args: rdi=buf, rsi=n, rdx(=dl)=key
    mu.reg_write(UC_X86_REG_RDI, DATA_BASE)
    mu.reg_write(UC_X86_REG_RSI, len(blob))
    mu.reg_write(UC_X86_REG_RDX, key)

    # Stack with a sentinel return address so RET lands on RET_MAGIC and stops.
    mu.reg_write(UC_X86_REG_RSP, STACK_BASE + 0x800)
    mu.mem_write(STACK_BASE + 0x800, RET_MAGIC.to_bytes(8, "little"))

    # Stop emulation when we return to the sentinel.
    def hook(uc, address, size, _):
        if address == RET_MAGIC:
            uc.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook)
    mu.emu_start(CODE_BASE, RET_MAGIC, count=10000)
    return mu.mem_read(DATA_BASE, len(blob))


if __name__ == "__main__":
    # XOR(0x5A) of "c2.example.com" — same blob as Module 4.3.
    enc = bytes([0x39, 0x68, 0x74, 0x3f, 0x22, 0x3b, 0x37, 0x2a,
                 0x36, 0x3f, 0x74, 0x39, 0x35, 0x37])
    out = emulate_decrypt(enc, 0x5A)
    print("emulated decrypt ->", out.decode(errors="replace"))
