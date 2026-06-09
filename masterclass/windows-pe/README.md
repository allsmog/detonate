# Windows PE Supplement

> Real-world malware reverse engineering is overwhelmingly **Windows / PE**. The
> core Levels 1–7 use Linux/ELF training binaries because they're reproducible
> in any sandbox, but the *skills* transfer directly. This supplement applies
> them to actual PE binaries so you're not surprised by the format that matters
> most in practice.

- **Type:** Cross-cutting supplement (apply after Levels 1–6)
- **Time:** ~90 minutes
- **Difficulty:** Intermediate

---

## Why a supplement (and an honest caveat)

PE binaries **run on Windows**, not Linux. So:
- The **static** parts of these labs are fully reproducible anywhere — you
  cross-compile real PEs on Linux with mingw-w64 and analyze them with `pefile`,
  `objdump`, Ghidra. No Windows needed.
- The **dynamic** parts (actually executing) need a **Windows VM** or
  **Detonate's Windows (QEMU) sandbox**. Those steps are marked clearly; do them
  in your own isolated Windows lab.

This is the same static-first discipline the rest of the course teaches — most
of your intelligence comes before you ever run the sample.

## Objectives

By the end you will be able to:

- [ ] Read PE structure and imports from a real `.exe` (not just theory).
- [ ] Infer capability from a Windows import table (file / persistence / network).
- [ ] Recognize Windows anti-debug (`IsDebuggerPresent` + direct PEB reads).
- [ ] Map PE/Windows analysis onto the Linux skills from Levels 1–6.

## Prerequisites

- [Module 1.1 — PE/ELF anatomy](../01-foundations/01-pe-anatomy/),
  [Module 2.2 — imports as behavior](../02-static-analysis/02-imports-as-behavior/),
  [Module 5.2 — anti-debug](../05-anti-analysis/02-debugger-detection/).
- `mingw-w64` (`sudo apt-get install gcc-mingw-w64-x86-64`), `pefile`
  (`pip install pefile`), `objdump`.

---

## Build

```bash
cd masterclass/windows-pe
bash build.sh        # produces win_imports.exe, win_antidbg.exe (gitignored)
```

---

## Lab 1 — Capability from a Windows import table

**Sample:** [`win_imports.c`](win_imports.c) → `win_imports.exe`. It imports from
three capability families on purpose.

```bash
python3 -c "import pefile; pe=pefile.PE('win_imports.exe'); \
print({d.dll.decode(): [i.name.decode() for i in d.imports if i.name][:6] \
for d in pe.DIRECTORY_ENTRY_IMPORT})"
```

Real output maps cleanly to capability:

| DLL | Imports | Capability |
|-----|---------|------------|
| `kernel32.dll` | `CreateFileA`, `WriteFile` | **File** I/O |
| `advapi32.dll` | `RegOpenKeyExA` | **Persistence** (it touches the Run key) |
| `wininet.dll` | `InternetOpenA`, `InternetOpenUrlA` | **Network / C2** |

From imports alone — before reading code — you can say "this writes files, reads
an autostart registry key, and makes HTTP requests." That's the Module 2.2 skill,
on a real PE.

> Windows malware hides imports the same way Linux samples do: by resolving APIs
> at runtime with `LoadLibrary` + `GetProcAddress` (the `dlopen`/`dlsym` analogue
> from Module 2.2), or via **API hashing** (Module 4.3). A nearly-empty PE import
> table with just those two is the same red flag.

## Lab 2 — Windows anti-debug

**Sample:** [`win_antidbg.c`](win_antidbg.c) → `win_antidbg.exe`.

```bash
python3 -c "import pefile; pe=pefile.PE('win_antidbg.exe'); \
print([i.name.decode() for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name and b'Debug' in i.name])"
# -> ['IsDebuggerPresent']
```

Two checks, one visible and one stealthy:
1. **`IsDebuggerPresent`** — shows up as a kernel32 import (easy to spot).
2. **Direct PEB read** — reads `PEB->BeingDebugged` (`gs:[0x60]`, offset 2)
   *without* any API call, so **no import betrays it**. In the disassembly you'd
   see a `gs:`-segment memory read; there's nothing in the import table.

This is the same idea as Module 5.2's `ptrace` self-check: a boolean the malware
reads and branches on. **Dynamic bypass (in your Windows lab):** patch
`IsDebuggerPresent` to return 0 and/or zero the PEB byte — exactly analogous to
forcing `ptrace` to return 0 in gdb.

## Lab 3 — Dynamic, in Detonate's Windows sandbox

(Requires the QEMU/Windows backend — see the root README.) Submit a real
(lab-sourced) Windows sample and observe via Sysmon-based telemetry: process
creation, registry writes, network. The behavioral pillars from Level 3 are the
same; only the collection mechanism differs (Sysmon/ETW instead of strace).

---

## Guided questions

1. From `win_imports.exe`'s import table alone, what three sentences can you
   write about its capability — and which import is the strongest malice signal?
2. `win_antidbg.exe` performs two anti-debug checks but only one appears in the
   imports. Which one is invisible statically, and why?
3. How is forcing `IsDebuggerPresent` to return 0 the same operation as the
   Module 5.2 `ptrace` bypass?
4. A PE imports only `LoadLibraryA` and `GetProcAddress`. What is it doing, and
   which Linux technique from Module 2.2 is this the analogue of?
5. Why can you do the *static* half of these labs on Linux, but not the dynamic
   half?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. "It **writes files** (`CreateFileA`/`WriteFile`), **reads an autostart
   registry key** (`RegOpenKeyExA` on `...\CurrentVersion\Run`), and **makes
   HTTP requests** (`InternetOpenA`/`InternetOpenUrlA`)." The **Run-key access**
   is the strongest malice signal — legitimate programs rarely poke autostart
   keys, and combined with file-write + network it describes a
   download-persist-beacon shape.
2. The **direct PEB read** is invisible: it reads `gs:[0x60]` → `+2`
   (`BeingDebugged`) with a raw memory access and **no API call**, so nothing
   appears in the import table. Only `IsDebuggerPresent` (an actual kernel32
   import) shows. Lesson: imports reveal *some* anti-analysis, not all — you must
   also read the code for segment-register/PEB tricks.
3. Both **force the "not being analyzed" answer** at the point the malware reads
   it. `IsDebuggerPresent` returns the PEB `BeingDebugged` flag; patching it to
   return 0 is identical in spirit to making `ptrace(PTRACE_TRACEME)` return 0 —
   you neutralize the check's result so the payload branch executes.
4. It's resolving its **real APIs at runtime** to keep them out of the static
   import table (dynamic API resolution). This is the exact analogue of Linux
   **`dlopen` + `dlsym`** from Module 2.2 — and the next step up is API hashing
   (Module 4.3).
5. The **static** analysis reads bytes (headers, imports, disassembly) — format,
   not execution — so any OS with `pefile`/`objdump`/Ghidra can do it. The
   **dynamic** half requires actually *running* PE code, which needs Windows (a
   VM or Detonate's QEMU sandbox). Same static-first principle as the whole
   course: most intelligence comes before you run anything.

</details>

---

## Going further

- Build `win_imports.exe`, open it in Ghidra, and confirm the decompiler shows
  the same three capability calls you found in the import table.
- Add a `LoadLibrary`+`GetProcAddress` resolver to `win_imports.c`, rebuild, and
  watch the network imports *disappear* from the static table.
- Compare a UPX-packed `win_imports.exe` (`upx win_imports.exe`) to the original
  — PE packing tells (Module 2.3) on a real PE: section names like `UPX0`/`UPX1`
  (PE keeps named sections, unlike the stripped ELF case).
