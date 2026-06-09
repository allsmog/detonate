# Module 1.1 — PE & ELF Anatomy

> Before you can reverse a program, you have to read its skeleton. This module
> teaches you the structure of executables — and shows you that Detonate's
> static analyzer is doing exactly what you'll learn to do by hand.

- **Level:** 1 — Foundations
- **Time:** ~90 minutes
- **Difficulty:** Beginner

---

## Objectives

By the end of this module you will be able to:

- [ ] Identify a file as PE (Windows) or ELF (Linux/Unix) from its magic bytes.
- [ ] Name the major structures of a PE — DOS header, NT headers, section
      table, import/export tables — and say what each is for.
- [ ] Read the same structures out of an ELF (header, program/section headers).
- [ ] Explain why the **entry point**, **sections**, and **imports** are the
      first three things an analyst looks at.
- [ ] Map every field you learn to the JSON Detonate's static analyzer returns.

## Prerequisites

- Comfort with hex and bytes (a hex editor or `xxd`).
- Detonate running, or just the static-analysis tooling. See
  [SETUP.md](../../SETUP.md).
- No execution happens in this module — but still treat files as live
  ([SAFETY.md](../../SAFETY.md)).

---

## Theory

### Why structure matters

An executable isn't a blob — it's a contract with the operating system loader.
The loader reads a well-defined set of headers to learn: where to put the code
in memory, where execution starts, and which external functions to wire up.
Every one of those answers is intelligence for you. Malware *has* to declare a
lot about itself to run at all, and that declaration is your first foothold.

### PE (Portable Executable) — Windows

The layout, top to bottom:

```
+-------------------------------+  offset 0
|  DOS Header (MZ)              |   "MZ" magic (0x4D 0x5A); e_lfanew -> NT headers
|  DOS Stub ("This program...")|
+-------------------------------+
|  NT Headers                  |   "PE\0\0" signature (0x50450000)
|   - File Header (COFF)       |     machine, #sections, characteristics
|   - Optional Header          |     AddressOfEntryPoint, ImageBase, subsystem,
|                              |     data directories (imports, exports, ...)
+-------------------------------+
|  Section Table               |   one entry per section: name, VA, raw size...
+-------------------------------+
|  Sections                    |
|   .text   (code, executable) |
|   .data   (initialized data) |
|   .rdata  (read-only: imports,|
|            strings, consts)  |
|   .rsrc   (resources)        |
|   ...                        |
+-------------------------------+
```

The fields you'll use constantly:

| Field | Where | Why you care |
|-------|-------|--------------|
| `e_magic` = `MZ` | DOS header | Confirms PE family. |
| `Machine` | File header | x86 (`0x14c`) vs x64 (`0x8664`). |
| `AddressOfEntryPoint` | Optional header | The RVA where execution begins — where you start reading code. |
| `ImageBase` | Optional header | Preferred load address; RVA + ImageBase = virtual address. |
| Data Directory: Import | Optional header | Points to the Import Address Table — the external APIs the binary calls. |
| Section table | After headers | Names, sizes, and **characteristics** (is it executable? writable?). |

**Red flags you can already spot** just from headers:
- A section that is both **writable and executable** (`.text` shouldn't be
  writable) → often a sign of self-modifying or unpacking code.
- **Raw size 0 but large virtual size** → space allocated at runtime, classic
  packer behavior (the real code is unpacked into it).
- Section names like `UPX0`/`UPX1`, `.aspack`, or random gibberish → packer.
- A tiny import table (one or two functions like `LoadLibrary`/`GetProcAddress`)
  → the program resolves its real imports at runtime to hide them.

### ELF (Executable and Linkable Format) — Linux

Same job, different shape:

```
+-------------------------------+
|  ELF Header                  |   magic 0x7F 'E' 'L' 'F'; class (32/64),
|                              |   type (EXEC/DYN), machine, e_entry (entry pt)
+-------------------------------+
|  Program Headers (segments)  |   loader's view: what to map, with what perms
+-------------------------------+
|  Sections (.text/.data/...)  |   linker's view: code, data, symbols, relocs
+-------------------------------+
|  Section Headers             |
+-------------------------------+
```

Key fields: `e_ident` (magic + class + endianness), `e_type`
(`ET_EXEC` static vs `ET_DYN` PIE/shared object), `e_machine` (x86-64 = 62),
and `e_entry` (entry-point virtual address). The `.dynamic` section and the
symbol tables tell you which shared libraries and functions it imports —
the ELF analogue of the PE import table.

### The analyst's first three questions

Whatever the format, you open with the same three:

1. **Where does it start?** (entry point) — your reading anchor.
2. **What sections exist and what are their permissions/sizes?** — packing and
   structure clues.
3. **What does it import?** — a behavioral preview before you read a single
   instruction (we go deep on this in [Module 2.2](../../02-static-analysis/)).

---

## Lab

You'll parse a known binary three ways — by eye, with Python, and through
Detonate — and confirm all three agree. Seeing the platform reproduce your
manual findings is the point: it demystifies the tool *and* the format.

**Sample:** any small, known-benign executable you trust. Good choices:
- Linux: `/bin/ls` or a `hello-world` you compile (`gcc hello.c -o hello`).
- Windows: a copy of `notepad.exe` from a VM, or a small program you build.

No malware needed for this module — we're learning the container, not the
contents.

### Task 1 — Identify the format by hand

```bash
xxd /bin/ls | head -2
file /bin/ls
```

Find the magic bytes. Confirm `file`'s verdict matches what the magic tells you.

### Task 2 — Parse the structure with Python

Detonate's static analyzer uses `pefile` and `lief` — the same libraries you'll
use here.

```python
# ELF
import lief
b = lief.parse("/bin/ls")
print(b.header.entrypoint, b.header.machine_type)
for s in b.sections:
    print(f"{s.name:15} vaddr={hex(s.virtual_address)} size={s.size} entropy={s.entropy:.2f}")
print("Imports:", [f.name for lib in b.imports for f in lib.entries][:20])
```

```python
# PE (run against a PE you copied into your lab)
import pefile
pe = pefile.PE("sample.exe")
print(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), hex(pe.OPTIONAL_HEADER.ImageBase))
for s in pe.sections:
    print(s.Name.decode(errors="replace").strip("\x00"),
          hex(s.VirtualAddress), s.SizeOfRawData, f"{s.get_entropy():.2f}")
for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    print(entry.dll.decode())
```

Write down: entry point, the section list with sizes, and the first few imports.

### Task 3 — Reproduce it through Detonate

1. Start the platform (`make services && make dev`, plus the worker — see SETUP).
2. Submit the same file via the UI (http://localhost:3000) or the API:
   ```bash
   curl -F "file=@/bin/ls" http://localhost:8000/api/v1/submit
   ```
3. Fetch the static analysis:
   ```bash
   curl http://localhost:8000/api/v1/submissions/<id>/static | jq
   ```
4. Compare the platform's reported entry point, sections, entropy, and imports
   against your hand-parsed values. They should match — Detonate is running the
   same libraries you just did, in `api/detonate/services/static_analysis.py`.

---

## Guided questions

Answer before opening the solution:

1. Your sample's first two bytes are `7F 45`. PE or ELF? How do you know, and
   what would the *other* format's magic look like?
2. One section reports `SizeOfRawData = 0` but a large virtual size, and is
   marked executable. What does that strongly suggest, and why?
3. You see exactly two imports: `LoadLibraryA` and `GetProcAddress`. Why is that
   *more* suspicious than a binary importing fifty functions?
4. The entry point RVA is `0x1500` and `ImageBase` is `0x400000`. At what
   virtual address does execution begin once loaded?
5. Open `api/detonate/services/static_analysis.py`. Which library does Detonate
   use for PE vs ELF, and which header field does it read for the entry point?

---

## Solution

<details>
<summary>Spoiler — open after attempting the questions.</summary>

1. **ELF.** `7F 45 4C 46` = `\x7F E L F`, the ELF magic. PE begins with `4D 5A`
   (`MZ`); you'd then follow `e_lfanew` to a `50 45 00 00` (`PE\0\0`) signature.

2. **A packer.** Raw size 0 means nothing is stored on disk for that section,
   but virtual size reserves runtime memory. The packer's stub *unpacks* the
   real code into this executable region at runtime. (You'll exploit this in
   [Level 4](../../04-unpacking-deobfuscation/).)

3. **Hidden imports.** `LoadLibraryA` + `GetProcAddress` is the minimal toolkit
   for **dynamic API resolution**: the program loads libraries and looks up
   functions *by name at runtime*, so the interesting APIs (network, crypto,
   injection) never appear in the static import table. Fifty honest imports
   tell you what the program does; two imports tell you it's hiding what it
   does.

4. **`0x401500`.** Virtual address = `ImageBase + RVA` = `0x400000 + 0x1500`.

5. Detonate uses **`pefile`** for PE and **`lief`** for ELF. It reads
   `OPTIONAL_HEADER.AddressOfEntryPoint` for PE and the ELF header entrypoint —
   exactly the fields in Task 2. The platform isn't magic; it's the libraries
   you just drove, wrapped in an API.

</details>

---

## Going further

- Corrupt one byte of the `MZ`/`ELF` magic in a *copy* and watch `file` and the
  loader refuse it — internalize how fragile and how load-bearing those bytes are.
- Read [`api/detonate/services/static_analysis.py`](../../../api/detonate/services/static_analysis.py)
  end to end. You now understand most of what it does.
- References: Microsoft's [PE format spec](https://learn.microsoft.com/windows/win32/debug/pe-format),
  the ELF spec (`man 5 elf`), and *Practical Malware Analysis* ch. 1.
- Next: [Module 1.2 — x86/x64 assembly survival kit](../) (assembly), then
  [Level 2 — Static Analysis](../../02-static-analysis/).
