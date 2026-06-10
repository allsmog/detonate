# Module 4.4 — Scripted Deobfuscation

> Doing it once by hand teaches you the mechanism. Doing it across a whole
> family — dozens of strings, many samples — demands automation. This module
> turns your manual skills into reusable scripts, including **CPU emulation** to
> *run* a malware decryptor without reimplementing it.

- **Level:** 4 — Unpacking & Deobfuscation
- **Time:** ~90 minutes
- **Difficulty:** Advanced

---

## Objectives

By the end of this module you will be able to:

- [ ] Brute-force an unknown single-byte XOR key from a blob.
- [ ] Reverse API hashing programmatically with a wordlist.
- [ ] Use **Unicorn** to emulate a real decryptor and read the plaintext out of
      emulated memory.
- [ ] Choose between *porting* an algorithm and *emulating* it.

## Prerequisites

- [Module 4.3](../03-string-api-obfuscation/). `python3`,
  `pip install unicorn`. (Capstone optional.)

---

## Theory

Two automation strategies:

- **Port the algorithm.** Reimplement the decryptor in Python. Best when it's
  simple (XOR, RC4) and you must run it over **many** blobs/samples offline.
- **Emulate the original code.** Use a CPU emulator (**Unicorn**) to *execute*
  the actual decrypt routine from the binary — no reimplementation, no OS, no
  risk. Best when the algorithm is **complex, custom, or you don't fully
  understand it** but you can isolate the function. You set up registers/memory
  (the calling convention), run to the `ret`, and read the result.

A recurring real-world wrinkle: brute-forcing single-byte XOR on a **short**
blob yields **many** printable candidates. You disambiguate with a **scoring
heuristic** (English/letter frequency, known markers like `http`, `.com`) or a
**known-plaintext** crib.

---

## Lab

Files: [`deobf.py`](deobf.py) (brute XOR + API-hash reversal) and
[`emulate.py`](emulate.py) (Unicorn runs a real compiled decryptor). Both target
the artifacts from [Module 4.3](../03-string-api-obfuscation/).

### Task 1 — Brute-force the XOR key

```bash
python3 deobf.py xor 0x39,0x68,0x74,0x3f,0x22,0x3b,0x37,0x2a,0x36,0x3f,0x74,0x39,0x35,0x37
```

It prints every key that yields printable text. On this short blob you get
**many** candidates — but only one is meaningful:

```
key=0x5a -> 'c2.example.com'
```

**Lesson:** automation finds *candidates*; you still apply judgment (or a
scoring function). Note how `0x5a` stands out as a real domain among noise.

### Task 2 — Reverse the API hash

```bash
python3 deobf.py api 0xff8760ae
# -> 0xff8760ae -> getenv
```

`deobf.py` hashes a built-in wordlist with djb2 and matches — instant name
recovery, scalable to every hash in a sample.

### Task 3 — Emulate the real decryptor (Unicorn)

`emulate.py` embeds the **actual gcc-compiled machine code** of an XOR-decrypt
routine, maps memory, sets the System V arguments (`rdi`=buffer, `rsi`=length,
`dl`=key), runs to `ret`, and reads the decrypted bytes from emulated memory:

```bash
python3 emulate.py
# -> emulated decrypt -> c2.example.com
```

You never reimplemented the algorithm — you **ran the malware's own code** in a
sandboxed CPU and stole the output. This scales to gnarly custom decryptors where
porting would be painful or error-prone.

### Task 4 — Tie it together

A production deobfuscator for a family typically: (1) locates each encrypted blob
by structure/signature, (2) recovers or emulates the decryptor, (3) emits the
plaintext IOCs. That pipeline feeds straight into **config extraction**
([Level 6](../../06-config-extraction/)) and Detonate's IOC export.

---

## Guided questions

1. Brute-forcing the short XOR blob returned dozens of printable strings. Why,
   and how do you pick the right one programmatically?
2. When would you **emulate** a decryptor instead of **porting** it to Python?
   Give a concrete property of the algorithm that forces emulation.
3. In `emulate.py`, why must you set `rdi`/`rsi`/`dl` specifically, and what
   breaks if you get the calling convention wrong?
4. The emulator stops when execution returns to a fake address (`RET_MAGIC`).
   Why is a sentinel return address necessary?
5. Why is emulating a decryptor **safe** even though the bytes come from malware?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. A **14-byte** blob has few constraints, so for many of the 256 keys the
   output happens to be all-printable by chance. You disambiguate with a
   **scoring heuristic** — letter/bigram frequency, or matching known markers
   (`http`, `.com`, `\\`, `/tmp/`) — or a **known-plaintext crib**. Pick the
   candidate that scores like real text/IOCs; here `0x5a → c2.example.com` is the
   only one that reads as a domain.
2. Emulate when the algorithm is **complex, custom, multi-stage, or
   state-dependent** — e.g. a key **derived at runtime** from earlier code, a
   bespoke cipher you'd spend an hour porting and still risk getting subtly
   wrong, or compression you don't want to reimplement. If you can isolate the
   function and set up its inputs, emulation runs the *exact* original logic.
3. The routine follows **System V x86-64**: first arg in `rdi` (buffer pointer),
   second in `rsi` (length), third in `rdx`/`dl` (key). Set them wrong and the
   function reads/writes the wrong memory or length — you get garbage or a fault.
   Knowing the convention *is* the setup.
4. The function ends in `ret`, which pops a return address and jumps there. In a
   real process that's the caller; in the emulator there's no caller, so we push
   a **sentinel** (`RET_MAGIC`) and stop when `rip` reaches it. Without it,
   execution would run off into unmapped memory after the `ret`.
5. Emulation **executes the bytes on a virtual CPU with no real OS, no syscalls,
   and isolated mapped memory**. The decrypt routine just shuffles bytes in a
   buffer you control — it can't touch your filesystem, network, or host. (For
   code that *does* make syscalls, you stub or hook them — but you never give it
   real ones.) That's exactly why emulation is a safe deobfuscation primitive.

</details>

---

## Going further

- Add a frequency-scoring function to `deobf.py` so it auto-ranks the best XOR
  candidate instead of printing all of them.
- Extend `emulate.py` to hook memory writes and log the decrypt loop byte-by-byte
  (great for understanding an unknown cipher).
- Next: **[Level 5 — Anti-Analysis](../../05-anti-analysis/)**.
