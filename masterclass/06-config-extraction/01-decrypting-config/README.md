# Module 6.1 — Decrypting Embedded Config

> Commodity malware carries its marching orders — C2 servers, campaign ID, keys
> — as an encrypted **config blob**. Recovering it is the single highest-value
> output of reverse engineering: it hands defenders the infrastructure to block.
> This module teaches you to find and decrypt one.

- **Level:** 6 — Configuration & IOC Extraction
- **Time:** ~75 minutes
- **Difficulty:** Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Locate an embedded config blob in a binary.
- [ ] Identify the decryption scheme and recover the key.
- [ ] Decrypt the config by hand and parse its fields.
- [ ] Produce a clean, defanged IOC list from it.

## Prerequisites

- [Level 4](../../04-unpacking-deobfuscation/) (deobfuscation, RC4/XOR),
  [Module 3.3](../../03-dynamic-analysis/03-network-and-c2/) (C2). `gcc`,
  `python3`, `strings`.

---

## Theory

Why config blobs exist: one malware build is reused across campaigns; the
**config** is what varies (C2 list, campaign/botnet ID, encryption keys, kill
dates, target filters). It's stored encrypted so it doesn't show in `strings`
and so each campaign's infrastructure isn't trivially extracted.

Finding and decrypting it:

1. **Locate** — config often sits in a high-entropy region of `.data`/`.rdata`,
   sometimes behind a **magic marker** or at a fixed offset, sometimes in a
   resource. High-entropy island + referenced by a decrypt routine = candidate.
2. **Identify the scheme** — trace where the blob is read; the routine right
   there is the decryptor. Common: XOR, **RC4**, AES, or base64 layered on top.
   RC4's key-scheduling loop (a 256-byte `S` array, two swaps) is very
   recognizable.
3. **Recover the key** — an immediate, a nearby buffer, or derived. Then decrypt
   and **parse** the structure.

---

## Lab

**Sample:** [`configbot.c`](configbot.c) — carries an **RC4-encrypted** config
behind a `CFG0` magic. Key: `s3cr3tk3y`.

### Task 1 — Confirm the config is hidden, find the anchor

```bash
gcc -O0 -no-pie configbot.c -o configbot
./configbot                              # prints the decrypted config at runtime
strings configbot | grep -iE "example|TRAIN-2026"   # nothing — it's encrypted
strings configbot | grep CFG0            # but the magic marker IS visible
```

Verified: the C2 hosts never appear in `strings`, but `CFG0` does — that's your
anchor to the blob.

### Task 2 — Read the decryptor and recover the scheme/key

```bash
objdump -d -M intel configbot | sed -n '/<rc4>:/,/ret/p' | head -30
```

Recognize the RC4 key-schedule (256-entry `S`, swaps) and find the key
(`s3cr3tk3y`) passed to it. The blob layout is `CFG0 | uint16 len | RC4(config)`.

### Task 3 — Decrypt by hand

Pull the blob bytes after the magic+length and RC4-decrypt with the key (a
10-line Python RC4 — see [Module 6.2](../02-building-extractor/) for a complete
one). You'll recover:

```
v=1;id=TRAIN-2026;c2=c2a.example.com:443,c2b.example.net:8443;mutex=Global\Train_8f3a
```

### Task 4 — Produce the IOC list (defanged)

| IOC (defanged) | Type | Note |
|----------------|------|------|
| `c2a[.]example[.]com:443` | C2 | primary |
| `c2b[.]example[.]net:8443` | C2 | fallback |
| `TRAIN-2026` | campaign id | clusters samples |
| `Global\Train_8f3a` | mutex | host-based detection / single-instance |

---

## Guided questions

1. The config is encrypted but the `CFG0` magic is plaintext. Why would malware
   authors leave a marker, and how does it help *you*?
2. You found RC4 by its key-schedule shape. What specifically in the disassembly
   gives RC4 away versus a simple XOR loop?
3. The key here is a hardcoded string. What are two ways a sample could make key
   recovery harder, and which of your methods still works for each?
4. Why is the **campaign ID** valuable even though it's not directly blockable
   like a C2 domain?
5. You recovered two C2 endpoints on ports 443 and 8443. Why list both, and what
   does the fallback tell you operationally?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. A marker lets the **malware itself** find its config quickly (and lets a
   builder insert it at pack time). It helps you because it's a reliable
   **anchor**: search the file for `CFG0`, and the length + blob follow at a
   known layout — no guessing offsets. (Markers are also great YARA anchors.)
2. RC4 has a distinctive **key-scheduling algorithm**: initialize a 256-byte
   array `S` to `0..255`, then a 256-iteration loop doing `j = (j + S[i] +
   key[i % klen]) & 0xff` with a **swap** of `S[i]`/`S[j]`; then a second
   keystream loop with two more swaps and an XOR. A plain XOR loop has none of
   that state — just `buf[i] ^= key`. The 256-entry table + swaps is the tell.
3. (a) **Derive the key at runtime** (from host data / an earlier stage) — then
   **dynamic** recovery (run it, dump the decrypted config from memory, like
   [Module 4.2](../../04-unpacking-deobfuscation/02-custom-packers/)) still
   works while static key-reading fails. (b) **Layer encodings** (e.g. AES then
   base64) — static still works but you must peel each layer; dumping the final
   plaintext from memory short-circuits it.
4. The **campaign/botnet ID clusters samples and activity**: it links otherwise
   different binaries to the same operator/campaign, supports attribution and
   tracking over time, and helps you tell "new campaign" from "same campaign,
   new build." It's intelligence, not a block-list entry.
5. Malware lists a **fallback C2** for resilience — if the primary is taken down
   or sinkholed, it rotates to the secondary. Operationally it tells you (a)
   block **both**, (b) the actor plans for takedowns, and (c) monitoring the
   fallback can reveal continued activity after the primary dies.

</details>

---

## Going further

- Change the RC4 key in `configbot.c`, rebuild, and re-recover it from the
  disassembly.
- Make the key runtime-derived (XOR the stored key with a constant first) and
  switch to **dynamic** recovery — dump the decrypted config from memory.
- Next: [Module 6.2 — Building a config extractor](../02-building-extractor/).
