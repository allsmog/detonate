# Module 3.1 — Your First Detonation

> Static analysis tells you what a program *can* do. Dynamic analysis tells you
> what it *actually does*. In this module you detonate a sample in Detonate and
> learn to read the three pillars of behavioral telemetry: **processes**,
> **network**, and **files**.

- **Level:** 3 — Dynamic Analysis
- **Time:** ~60 minutes
- **Difficulty:** Beginner (the on-ramp to all dynamic modules)
- **Doubles as the lab smoke test** from [SETUP.md](../../SETUP.md).

---

## Objectives

By the end of this module you will be able to:

- [ ] Submit a sample for dynamic analysis through Detonate and retrieve results.
- [ ] Read a **process tree** and explain parent/child relationships.
- [ ] Identify **network behavior** (DNS lookups, TCP connections) from telemetry.
- [ ] Identify **filesystem activity** (dropped/modified files).
- [ ] Connect each observation back to the syscall that produced it.
- [ ] Explain, at a high level, how Detonate captures this (strace + tcpdump in
      a disposable sandbox).

## Prerequisites

- [Module 1.1 — PE & ELF anatomy](../../01-foundations/01-pe-anatomy/) (helpful, not required).
- Detonate fully running **including a Celery worker** and the sandbox image
  built. See [SETUP.md](../../SETUP.md).
- A C compiler in your lab (`gcc`).
- **Read [SAFETY.md](../../SAFETY.md).** This module *executes* code. We use a
  benign training binary, but build the habit now: detonate in the sandbox,
  never on your host, with networking isolated.

---

## Theory

### What "dynamic analysis" actually is

You run the sample in an instrumented, disposable environment and record what it
does. The instrumentation is the whole game. Detonate's Linux sandbox uses two
classic tools:

- **`strace`** — intercepts every *system call* the program makes. Processes,
  files, and network all bottom out in syscalls (`clone`, `open`, `connect`,
  `write`...), so tracing syscalls captures behavior at its source. Detonate
  runs `strace -f` (follow children) with a filter for
  `process,network,open,openat,unlink,write,clone,clone3` — see
  [`sandbox/linux/guest_agent.py`](../../../sandbox/linux/guest_agent.py).
- **`tcpdump`** — captures all network packets to a PCAP for later parsing
  (DNS, TCP/UDP, HTTP hosts).

The sandbox is **disposable**: it's torn down after the run, so whatever the
sample does to it doesn't matter. That's why you can safely observe malicious
behavior — the blast radius is a throwaway container.

### The three pillars

Almost everything an analyst cares about in a first pass falls into three
buckets, each tied to syscalls:

| Pillar | Syscalls | What it reveals |
|--------|----------|-----------------|
| **Process** | `clone`/`clone3`, `execve`, `fork` | Child processes, injected/spawned tools, the execution structure. |
| **Network** | `connect`, `sendto`, DNS resolution | C2 contact, downloads, exfiltration, beaconing. |
| **Filesystem** | `open`/`openat`, `write`, `unlink` | Dropped payloads, config files, self-deletion, persistence artifacts. |

The **process tree** is the backbone — you read it first because it gives you
the structure everything else hangs off of. Detonate reconstructs parent/child
links from the PIDs in `clone`/`clone3` calls (see `parse_strace` in the guest
agent).

---

## Lab

### The sample

We use [`sample_beacon.c`](sample_beacon.c) — a **benign** training binary in
this folder. Read its source: it deliberately exhibits all three pillars
(spawns a child, drops a file, attempts a network beacon) and nothing harmful.
You compile it yourself so nothing executable is committed to the repo
([SAFETY §4](../../SAFETY.md)).

### Task 0 — Build it (in your lab)

```bash
cd masterclass/03-dynamic-analysis/01-detonate-first-detonation
gcc -O0 sample_beacon.c -o sample_beacon
file sample_beacon          # confirm: ELF 64-bit executable
```

### Task 1 — Predict (do this before detonating)

From reading the source alone, write down what you expect in each pillar:
- Process: how many processes? what's the parent/child shape?
- Network: what host/port, what protocol(s)?
- Files: what path gets written?

Predicting first is the habit that separates analysts from button-pushers.

### Task 2 — Detonate

UI path: submit `sample_beacon` at http://localhost:3000, then click
**Analyze** to start dynamic analysis and watch the live telemetry stream.

API path:

```bash
# Submit
SID=$(curl -s -F "file=@sample_beacon" http://localhost:8000/api/v1/submit | jq -r .id)

# Start dynamic analysis (isolated network recommended)
AID=$(curl -s -X POST http://localhost:8000/api/v1/submissions/$SID/analyze \
  -H 'Content-Type: application/json' \
  -d '{"timeout": 30, "network": "none"}' | jq -r .id)

# Poll until completed, then read results
curl -s http://localhost:8000/api/v1/submissions/$SID/analyses/$AID | jq
```

### Task 3 — Read the three pillars

In the submission detail view (or the JSON `result`):

1. **Process tree panel** — find the parent process and its child. Confirm the
   parent/child shape matches your prediction. Which syscall created the child?
2. **Network panel** — find the DNS lookup for the beacon host and the TCP
   connection attempt. With `network: none`, the *attempt* still shows even
   though it fails. What host and port?
3. **Files panel** — find the dropped marker file. What path? Which syscall
   wrote it?

### Task 4 — Confirm the source of truth

The UI is a view over syscall data. To see the raw signal, note which
observations in each panel correspond to which syscall (`clone`/`clone3` →
process, `connect` + DNS → network, `openat`/`write` → file). This mapping is
what you'll rely on when a *real* sample does something the UI doesn't pre-label.

---

## Guided questions

Answer before opening the solution:

1. You set `network: "none"` and the beacon "failed." Why does the telemetry
   still show network behavior, and why is a *failed* connect attempt still
   valuable intelligence?
2. The process tree shows two processes from one binary. What in the **source**
   caused that, and what **syscall** does Detonate use to detect it?
3. The dropped file is `/tmp/.beacon_marker`. Why do real samples favor dotfiles
   and `/tmp`? What syscalls would you grep for to find all file drops?
4. If this were *real* malware, which single pillar would you prioritize for
   producing IOCs to share with other defenders, and why?
5. Why is running this in Detonate's disposable sandbox safe even if the binary
   were malicious — what's the blast radius?

---

## Solution

<details>
<summary>Spoiler — open after attempting the questions.</summary>

1. The behavior is captured at the **syscall** layer, before the network result
   is known. `getaddrinfo` (DNS) and `connect()` are *issued* regardless of
   whether they succeed — `strace` records the attempt. A failed connect is
   still intel: it reveals the **intended** C2 host/port even when the sandbox
   is offline. Analysts routinely extract C2 from samples that never reach the
   internet.

2. The `fork()` call in `main()` creates the child. On Linux, glibc's `fork()`
   is implemented via the **`clone`/`clone3`** syscall, which is exactly what
   Detonate filters for and uses (`parse_strace`) to reconstruct parent/child
   PIDs into the process tree.

3. `/tmp` is world-writable and survives without privileges; a leading dot hides
   the file from default `ls`. To find drops, look at **`open`/`openat`** (with
   write/create flags) followed by **`write`**, and **`unlink`** for
   self-deletion. Detonate already filters for these.

4. **Network**, usually. C2 domains/IPs and URLs are the highest-value, most
   shareable IOCs — they let other defenders block/hunt immediately, and they
   pivot in threat-intel platforms. (Hashes are valuable too but are trivially
   changed by the attacker; network infrastructure is costlier for them to
   rotate.) Detonate's IOC export ([Level 6](../../06-config-extraction/))
   pulls exactly these.

5. The sample runs inside a **disposable Docker sandbox** that is destroyed
   after the run, on an isolated network. Anything it writes, spawns, or
   connects to is confined to a container that ceases to exist. Your host and
   network are never the execution target — you only receive the *telemetry*.

</details>

---

## Going further

- Re-run with `network` set to a simulated/controlled mode (if configured) and
  compare: does the connect now succeed, and what extra network telemetry
  appears?
- Modify `sample_beacon.c` to also `unlink` its own dropped file, rebuild, and
  confirm the self-deletion shows up in telemetry. You just simulated a common
  anti-forensics behavior.
- Read [`sandbox/linux/guest_agent.py`](../../../sandbox/linux/guest_agent.py)'s
  `parse_strace` and `start_tcpdump` — you now understand the engine.
- Next: process-tree deep dive, then network/C2 analysis, then
  [MITRE ATT&CK mapping](../) — translating these raw behaviors into techniques.
