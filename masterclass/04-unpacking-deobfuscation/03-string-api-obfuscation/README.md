# Module 4.3 — String & API Obfuscation

> Even unpacked malware hides its intent at the code level: encrypted strings,
> strings built on the stack, and APIs resolved by *hash* so no name ever
> appears. This module teaches you to recognize and defeat all three.

- **Level:** 4 — Unpacking & Deobfuscation
- **Time:** ~75 minutes
- **Difficulty:** Intermediate→Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Recognize and decrypt XOR-obfuscated strings.
- [ ] Recognize stack-string construction.
- [ ] Explain and reverse **API hashing**.
- [ ] Locate the decode routine that turns ciphertext into intent.

## Prerequisites

- [Module 4.2](../02-custom-packers/), [Module 2.1](../../02-static-analysis/01-strings-and-iocs/),
  [Module 2.2](../../02-static-analysis/02-imports-as-behavior/). `gcc`, `strings`, `python3`.

---

## Theory

Three obfuscations you'll meet constantly:

1. **Encrypted strings.** The C2 domain, mutex, etc. are stored XOR/RC4-encrypted
   and decrypted just before use. `strings` shows noise. You find the **decode
   routine** (a loop near where the string is used) and recover the key.
2. **Stack strings.** The string is never stored contiguously — it's assembled
   one byte at a time into a stack buffer (`mov [rbp-x], 'h'; mov [rbp-x+1],
   '4'; ...`). `strings` misses it entirely; you read the immediates (you did
   this in [Module 1.3](../../01-foundations/03-re-toolchain/)).
3. **API hashing.** Instead of importing `connect` (which shows in the import
   table and as a string), malware stores a **hash** of the name and, at
   runtime, walks the export table hashing each name until it matches — then
   calls it. Neither the import nor the readable name exists. You reverse it by
   identifying the hash algorithm and **hashing a wordlist** to map hash → name.

---

## Lab

**Sample:** [`obf_strings.c`](obf_strings.c) — one binary, all three techniques:
a single-byte-XOR C2 string, a stack string, and a `djb2`-hash-resolved API.

### Task 0 — Build and confirm strings are hidden

```bash
gcc -O0 -fno-stack-protector -no-pie obf_strings.c -o obf_strings -ldl
./obf_strings
#   c2  = c2.example.com
#   path= /tmp/.sysd
#   api : resolved getenv by hash; HOME=/root
strings obf_strings | grep -E "example.com|sysd"   # -> nothing; all hidden
```

The program *uses* `c2.example.com` and `/tmp/.sysd`, yet neither appears in
`strings`. That gap is the obfuscation working.

### Task 1 — Defeat the XOR string

Find `enc_c2[]` and the decode loop in the disassembly. The op is `xor ..., 0x5a`.
Recover offline:

```bash
python3 -c "print(bytes(b^0x5a for b in [0x39,0x68,0x74,0x3f,0x22,0x3b,0x37,0x2a,0x36,0x3f,0x74,0x39,0x35,0x37]).decode())"
# -> c2.example.com
```

(If you *didn't* know the key, you'd brute-force it — see
[Module 4.4](../04-scripted-deobfuscation/).)

### Task 2 — Read the stack string

```bash
objdump -d -M intel obf_strings | grep -E "mov.*BYTE PTR.*0x2f|0x74|0x6d|0x70"
```

You'll see the bytes of `/tmp/.sysd` stored one at a time. Decode the immediates
in order — same skill as the Module 1.3 crackme.

### Task 3 — Reverse the API hash

The binary calls `resolve_by_hash(0xff8760ae)`. It uses **djb2**. Hash a wordlist
to find which API that is:

```bash
python3 -c "
def djb2(s):
    h=5381
    for c in s.encode(): h=((h*33)+c)&0xffffffff
    return h
for w in ['open','read','write','getenv','system','connect','socket']:
    print(hex(djb2(w)), w)" | grep ff8760ae
# -> 0xff8760ae getenv
```

So the "mystery API" is **`getenv`**. (Automated in
[Module 4.4](../04-scripted-deobfuscation/)'s `deobf.py api`.)

---

## Guided questions

1. The program clearly uses `c2.example.com`, but `strings` can't find it. Where
   *is* it in the binary, and what makes it invisible to `strings`?
2. Why is a **stack string** invisible even to a tool that extracts UTF-16 and
   short strings?
3. API hashing removes both the import and the name string. What does the
   malware store instead, and what's the one thing you need to reverse it?
4. You recovered `0xff8760ae → getenv`. Why was a *wordlist* necessary — why
   can't you just invert the hash directly?
5. Why do malware authors resolve `getenv`/`connect` by hash instead of just
   importing them normally?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. It's stored as **`enc_c2[]`, the XOR-encrypted bytes**, and only decrypted
   into a stack buffer at runtime. `strings` scans for runs of printable
   characters; the encrypted bytes aren't printable, so it finds nothing. The
   plaintext exists only transiently in memory while the program runs.
2. A stack string is **never a contiguous sequence of bytes anywhere** — it's a
   series of `mov [stack+offset], imm` instructions interleaved with other code.
   There's no printable run to find at any width; the "string" only exists once
   the instructions have executed.
3. It stores a **numeric hash of the API name** (here djb2). To reverse it you
   need the **hash algorithm** — then you hash candidate names and match. (Real
   samples often hash module+function or use ROR13/CRC variants; identifying the
   algorithm is the work.)
4. djb2 is a **non-invertible** many-to-one hash — you can't compute the input
   from the output. But it's cheap to compute *forward*, and the input space
   (API names) is tiny and known, so you **hash a wordlist** and look for the
   matching output. Reversal-by-enumeration, not by inversion.
5. To **hide capability from static analysis**: no `connect` in the import table
   ([Module 2.2](../../02-static-analysis/02-imports-as-behavior/)), no `getenv`
   string, nothing for signatures or a quick triage to flag. The behavior is
   identical at runtime but invisible until you either reverse the hashing or
   observe it dynamically ([Level 3](../../03-dynamic-analysis/)).

</details>

---

## Going further

- Add a second encrypted string with a *different* key and recover it.
- Reimplement the API-hash resolver for a ROR13 hash (the classic shellcode
  algorithm) and reverse it with a wordlist.
- Next: [Module 4.4 — Scripted deobfuscation](../04-scripted-deobfuscation/).
