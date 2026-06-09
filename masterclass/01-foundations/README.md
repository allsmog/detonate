# Level 1 — Foundations

*Goal: read a binary's structure and speak the language of the machine. After
this level, nothing about an executable is a black box to you.*

Start here if you're new to reverse engineering. If you already know PE/ELF
internals and assembly, skim and move to [Level 2](../02-static-analysis/).

## Modules

| # | Module | Status |
|---|--------|--------|
| 1.1 | [PE & ELF anatomy](01-pe-anatomy/) | ✅ Fully built (flagship) |
| 1.2 | x86/x64 assembly survival kit | 📝 Outlined below |
| 1.3 | The RE toolchain | 📝 Outlined below |
| 1.4 | File triage & hashing | 📝 Outlined below |

---

### 1.2 — x86/x64 assembly survival kit
**Objective:** read disassembly well enough to follow malware logic — not write
a compiler. **Theory:** registers (general-purpose, RIP, RSP/RBP, flags), the
stack and calling conventions (System V vs Windows x64), the ~30 instructions
that cover 95% of what you'll see (`mov`, `lea`, `call`, `cmp`/`test`,
conditional jumps, `push`/`pop`, `xor reg,reg`), and recognizing common patterns
(loops, string ops, function prologue/epilogue). **Lab:** compile a small C
program at `-O0` and `-O2`, disassemble both in Ghidra/objdump, and map source
lines to instructions; identify how the optimizer changed the shape. **Solution:**
annotated side-by-side. **Sample:** your own code (no malware needed).

### 1.3 — The RE toolchain
**Objective:** know which tool to reach for and how the sandbox complements
local tools. **Theory:** disassemblers/decompilers (Ghidra as the free default,
IDA, radare2/Cutter), debuggers (gdb+pwndbg on Linux, x64dbg on Windows), hex
editors, and triage utilities (`file`, `capa`, Detect It Easy). When to go
static vs dynamic vs sandbox. **Lab:** load the Module 1.2 binary in Ghidra,
navigate to `main`, rename a variable, add a comment, and use the decompiler;
then set a breakpoint in gdb and inspect a register. **Solution:** a guided
tour. **Sample:** your own code.

### 1.4 — File triage & hashing
**Objective:** do the 60-second first-look that decides how you'll spend the
next hour. **Theory:** cryptographic hashes (MD5/SHA-1/SHA-256) for identity,
**fuzzy hashing** (ssdeep) for similarity, MIME/type detection, and quick
heuristics (entropy, packer signatures, suspicious imports). How Detonate's
submission pipeline computes all of this automatically. **Lab:** submit several
files to Detonate, read the hashes/type/entropy it reports, and use a hash to
look the sample up on MalwareBazaar/VirusTotal via Detonate's threat-intel
enrichment. **Solution:** interpreting each triage signal. **Maps to:**
`api/detonate/services/static_analysis.py` and the threat-intel services.

---

**Next:** [Level 2 — Static Analysis](../02-static-analysis/).
