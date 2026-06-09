# Module 4.2 — Custom Packers & Unpacking Stubs

> When `upx -d` won't save you — a custom or tampered packer — you unpack by
> hand: let the stub decrypt the payload, catch it at the Original Entry Point,
> and dump the plaintext from memory. This module teaches that universal
> workflow on a self-contained stub.

- **Level:** 4 — Unpacking & Deobfuscation
- **Time:** ~75 minutes
- **Difficulty:** Intermediate→Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Recognize an unpacking stub and its decrypt loop in disassembly.
- [ ] Recover the key/algorithm statically.
- [ ] Find the "OEP moment" — where plaintext exists in memory.
- [ ] **Dump** the decrypted payload from a running process with a debugger.
- [ ] Cross-check static and dynamic recovery.

## Prerequisites

- [Module 4.1](../01-upx-and-packers/), [Module 1.2](../../01-foundations/02-assembly-survival-kit/)
  (reading loops in asm), [Module 1.3](../../01-foundations/03-re-toolchain/)
  (gdb). `gcc`, `gdb`, `objdump`, `python3`.

---

## Theory

Every packer, no matter how custom, follows the same shape:

```
[ encrypted/compressed payload blob ]   <- the real code, unreadable on disk
[ stub ]                                <- small loader that, at runtime:
   1. decrypts/decompresses the blob into memory
   2. fixes up imports (real packers)
   3. JMPs to the Original Entry Point (OEP) — the real start of the payload
```

So the **universal manual unpack** is:

1. Identify the **decrypt loop** in the stub (a tight loop doing XOR/sub/rol over
   a buffer — recognizable from [Module 1.2](../../01-foundations/02-assembly-survival-kit/)).
2. Recover the **key/algorithm** (often an immediate or a small key buffer).
3. Either **decrypt statically** (port the algorithm), or **run to the OEP** and
   **dump** the now-plaintext memory. Dumping is king when the algorithm is
   complex or multi-stage.

The **OEP** is the hinge: right after the stub finishes decrypting and before it
hands control to the payload, the real bytes are sitting in memory. Catch it
there.

---

## Lab

**Sample:** [`crypt_stub.c`](crypt_stub.c) — models a packer: an encrypted blob
`enc[]` plus an `unpack()` stub with an XOR **decrypt loop**. No readable payload
exists in the binary. Helper: [`xorpack.py`](xorpack.py) (packs and statically
unpacks).

### Task 0 — Build and confirm it's "packed"

```bash
gcc -O0 -fno-stack-protector -no-pie crypt_stub.c -o crypt_stub
./crypt_stub                         # payload: FLAG{unpacked_at_runtime}
strings crypt_stub | grep FLAG       # (nothing — payload is encrypted)
```

### Task 1 — Find the decrypt loop and key (static)

```bash
objdump -d -M intel crypt_stub | sed -n '/<unpack>:/,/ret/p'
```

You'll find a loop XORing `enc[i]` with a repeating key. The key bytes are the
ASCII of `K3yz` (`0x4b 0x33 0x79 0x7a`), visible in the binary / referenced by
the loop. Recover it.

### Task 2 — Decrypt statically

Pull the `enc[]` bytes and apply the key offline — exactly what a real analyst
does after recovering the algorithm:

```bash
python3 xorpack.py decode \
  0x0d,0x7f,0x38,0x3d,0x30,0x46,0x17,0x0a,0x2a,0x50,0x12,0x1f,0x2f,0x6c,0x18,0x0e,0x14,0x41,0x0c,0x14,0x3f,0x5a,0x14,0x1f,0x36 \
  K3yz
# -> FLAG{unpacked_at_runtime}
```

### Task 3 — Dump at the OEP (dynamic)

The realistic case: malware is **stripped**, so you don't have symbols or source.
Catch the plaintext in memory instead. `unpack(out, n)` receives the output
buffer in `rdi` (System V), so:

```bash
gdb -q -batch \
  -ex 'break unpack' -ex 'run' \
  -ex 'set $buf = $rdi' \
  -ex 'finish' \
  -ex 'x/s $buf' \
  crypt_stub
```

Real result:

```
0x7fffffffded0:  "FLAG{unpacked_at_runtime}"
```

You let the stub do the decryption, then **read the unpacked bytes straight out
of memory** at the OEP moment (`finish` returns from `unpack`, after the loop
ran). Static and dynamic agree — that's your confidence check.

---

## Guided questions

1. In the disassembly, how do you distinguish the **decrypt loop** from any
   other loop?
2. You recovered the key as `K3yz`. If the stub used a *generated* key (derived
   from the host, or decrypted in an earlier stage) instead of a constant, which
   of your two methods still works, and why?
3. What exactly is the "OEP moment," and why is `finish` after `break unpack` a
   reliable way to reach it *here*?
4. The sample is stripped in the real world. Why did dumping via `$rdi` still
   work without any symbols for the payload?
5. When is **dumping** strictly better than porting the algorithm to Python?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. A decrypt loop **reads a buffer, applies a reversible op (XOR/sub/add/rol)
   with a key, writes it back**, and iterates over a length. The XOR against a
   cycling key (`enc[i] ^ KEY[i % klen]`) plus the buffer in/out pattern is the
   tell — versus, say, a checksum loop (reads, accumulates, never writes back).
2. **Dumping (dynamic)** still works — you let the stub generate/derive the key
   and decrypt, then read memory; you never needed to know the key. **Static
   porting fails** if you can't reproduce the key without running the earlier
   stage. This is *why* dumping is the analyst's default for nontrivial packers.
3. The OEP moment is **immediately after decryption completes, before the
   payload runs**. Here, `break unpack` + `finish` returns control right after
   the decrypt loop wrote the full plaintext into `out` (whose address we saved
   from `rdi`), so the buffer is fully decrypted and not yet overwritten. (In a
   real packer you'd break on the tail-jump to OEP instead.)
4. We didn't need payload symbols — only the **calling convention**: the output
   buffer pointer is the first argument, in `rdi`. Saving `$rdi` at the stub's
   entry and reading that address after `finish` is symbol-free. Conventions,
   not symbols, get you the data.
5. When the algorithm is **complex, chained, or environment-dependent** (multi-
   stage, key derived from runtime state, compression you don't want to
   reimplement). Let the original code do the work and just **steal the result
   from memory**. Porting is better only when you need to decrypt *many* blobs
   offline at scale ([Module 4.4](../04-scripted-deobfuscation/)).

</details>

---

## Going further

- Strip the binary (`strip crypt_stub`) and redo Task 3 — confirm the `$rdi`
  dump still works with zero symbols.
- Change the key in `crypt_stub.c`, rebuild, and re-recover it both ways.
- Next: [Module 4.3 — String & API obfuscation](../03-string-api-obfuscation/).
