# Module 2.2 — Imports as Behavior

> A program's import table is a confession. Before you read a single
> instruction, the APIs it links against tell you what it's *capable* of —
> networking, crypto, injection, persistence. This module teaches you to read
> capability from imports, and to spot when a program is hiding them.

- **Level:** 2 — Static Analysis
- **Time:** ~60 minutes
- **Difficulty:** Beginner→Intermediate

---

## Objectives

By the end of this module you will be able to:

- [ ] List a binary's imported functions (ELF and PE).
- [ ] Map API families to capabilities (network/crypto/process/persistence).
- [ ] Form a behavioral hypothesis from imports alone.
- [ ] Recognize **dynamic import resolution** and explain why it's a red flag.

## Prerequisites

- [Module 1.1](../../01-foundations/01-pe-anatomy/) (import table location),
  [Module 2.1](../01-strings-and-iocs/). `nm`, `objdump`/`readelf`.

---

## Theory

### APIs → capabilities

| Capability | Windows APIs (examples) | Linux/libc (examples) |
|------------|-------------------------|------------------------|
| Network | `socket`, `WSAStartup`, `InternetOpen`, `HttpSendRequest`, `connect` | `socket`, `connect`, `getaddrinfo`, `send` |
| Crypto | `CryptEncrypt`, `BCryptEncrypt` | `EVP_*` (OpenSSL), custom |
| Process injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | `ptrace`, `process_vm_writev` |
| Persistence | `RegSetValueEx`, service APIs | `crontab`, writing to `~/.config/autostart` |
| Dynamic resolution | `LoadLibrary` + `GetProcAddress` | `dlopen` + `dlsym` |

You won't always be right from imports alone — but you'll have a **hypothesis**
to confirm dynamically, which is far faster than reading cold.

### The hiding tell

Here's the catch attackers exploit: if a program calls `connect` directly, it
shows up as an import. So malware instead imports only **`LoadLibrary` +
`GetProcAddress`** (Windows) or **`dlopen` + `dlsym`** (Linux) and resolves the
*real* functions by name **at runtime**. Result: the static import table is
nearly empty and the interesting capability is invisible. **A binary whose only
imports are the resolution primitives is more suspicious than one with fifty
honest imports.** Even sneakier is **API hashing** (resolve by a hash of the
name, so even the name strings are gone) — covered in
[Module 4.3](../../04-unpacking-deobfuscation/03-string-api-obfuscation/).

---

## Lab

Three benign binaries, three import profiles.

```bash
gcc -O2 -no-pie net_tool.c  -o net_tool
gcc -O2 -no-pie calc_tool.c -o calc_tool
gcc -O2 -no-pie dynres.c    -o dynres -ldl
```

### Task 1 — Read imports and form a hypothesis

```bash
nm -D net_tool   | grep ' U '   # undefined = imported
nm -D calc_tool  | grep ' U '
nm -D dynres     | grep ' U '
```

(On PE samples you'd use `objdump -x` / `pefile` to read `DIRECTORY_ENTRY_IMPORT`
— what Detonate parses.)

Real results:

| Binary | Imports (network-relevant) | Hypothesis |
|--------|----------------------------|------------|
| `net_tool` | `getaddrinfo`, `socket`, `connect` | **Talks to the network / DNS.** |
| `calc_tool` | just `__printf_chk` | Pure computation, no capability of interest. |
| `dynres` | **only** `dlopen`, `dlsym` | **Hiding** its real API — resolves at runtime. |

### Task 2 — Prove the hiding

`dynres` actually calls `cos` from libm, but:

```bash
nm -D dynres | grep -i cos     # nothing — cos is NOT in the import table
./dynres                        # yet it computes cos(0)=1.000000 at runtime
```

The capability is real but invisible statically. That gap is the whole point.

### Task 3 — Through Detonate

Submit each binary; read the imports Detonate reports in the static view. Note
that `dynres` looks "boring" statically — which is exactly when you escalate to
**dynamic analysis** ([Level 3](../../03-dynamic-analysis/)) to see what it
resolves and calls at runtime.

---

## Guided questions

1. From imports alone, which of the three binaries would you prioritize for
   dynamic analysis, and why isn't it the one with the most imports?
2. `dynres` calls `cos` but `cos` isn't imported. Where did the address come
   from, and what are the Windows-equivalent APIs?
3. Why is "only two imports" sometimes *more* alarming than "fifty imports"?
4. You see `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` together
   in a PE. What single behavior does that trio strongly imply?
5. What's the next evasion step beyond `dlopen`/`GetProcAddress`, and why does it
   defeat even string-based detection?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. **`dynres`** — counterintuitively, the one with the *fewest* imports. Its
   `dlopen`/`dlsym`-only table signals deliberate hiding, so static analysis
   can't tell you what it does; dynamic analysis can. `net_tool`'s imports
   already confess its capability, so it's less *mysterious* (though you'd still
   confirm the destination).
2. `dlsym(handle, "cos")` returned the runtime address of `cos` after
   `dlopen("libm.so.6")` loaded the library — **runtime resolution**, leaving no
   static import. The Windows analogues are **`LoadLibrary` + `GetProcAddress`**.
3. Two imports being the *resolution primitives* means the program is choosing
   to resolve everything else at runtime — a deliberate evasion. Fifty honest
   imports just describe a normal, readable program. Sparse + resolution APIs =
   "what are you hiding?"
4. **Process injection** — allocate memory in a remote process, write a payload
   into it, then start a thread there. Classic code-injection / hollowing
   primitive.
5. **API hashing**: resolve functions by a numeric **hash of the name** instead
   of the name string, so neither the import nor the readable name appears. You
   defeat it by reversing the hash algorithm or resolving hashes dynamically —
   [Module 4.3](../../04-unpacking-deobfuscation/03-string-api-obfuscation/).

</details>

---

## Going further

- Run `capa` against `net_tool` and a real (lab-sourced) sample — capa maps
  imports+code to capabilities and ATT&CK automatically; compare to your manual
  read.
- Next: [Module 2.3 — Entropy & packing detection](../03-entropy-and-packing/).
