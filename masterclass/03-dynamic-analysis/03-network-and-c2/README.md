# Module 3.3 — Network Behavior & C2

> Network behavior is the highest-value intelligence malware produces: the C2
> infrastructure other defenders can block today. This module teaches you to
> extract it from telemetry and PCAP — even when the sandbox is offline.

- **Level:** 3 — Dynamic Analysis
- **Time:** ~75 minutes
- **Difficulty:** Intermediate

---

## Objectives

By the end of this module you will be able to:

- [ ] Capture and read a sample's network traffic (DNS + TCP) from a PCAP.
- [ ] Extract C2 indicators: domain, IP, port, URL path, User-Agent.
- [ ] Explain why a *failed/offline* connection still yields C2 intel.
- [ ] Defang IOCs for safe reporting.
- [ ] Relate this to Detonate's network analysis + Suricata alerts.

## Prerequisites

- [Module 3.1](../01-detonate-first-detonation/),
  [Module 3.2](../02-process-trees/). `gcc`, `tcpdump`, `python3`.
  **[SAFETY.md](../../SAFETY.md)** — keep detonations isolated.

---

## Theory

Most commodity malware "phones home." The shape of that contact is intel:

- **DNS** — the domain it resolves (often the most durable, blockable IOC).
- **Connection** — destination IP + port + protocol. Non-standard ports hint at
  C2/exfil.
- **Payload** — for cleartext HTTP, the **request line** (`GET /gate.php?id=...`),
  **Host** header, and **User-Agent** are gold: paths and UAs are frequently
  family-specific signatures.
- **Beaconing** — periodic check-ins with jitter; visible as repeated
  connections at rough intervals.

**Offline still works.** The DNS query and the `connect()` are *issued* before
any reply; tracing/capturing records the attempt. So you recover the *intended*
C2 even with the sandbox network disabled. (TLS hides the payload, but you still
get SNI/domain, IP, and port.)

---

## Lab — fully offline, self-contained

**Sample:** [`beacon_http.c`](beacon_http.c) sends a recognizable HTTP beacon.
[`sinkhole.py`](sinkhole.py) is a local listener that stands in for a controlled
C2, so the whole exercise runs on loopback with no internet.

### Task 1 — Build, run the sinkhole, capture

```bash
gcc -O2 -no-pie beacon_http.c -o beacon_http

# Terminal A — the controlled "C2":
python3 sinkhole.py 8888

# Terminal B — capture loopback, then beacon:
sudo tcpdump -i lo -w beacon.pcap port 8888 -U &
./beacon_http 127.0.0.1 8888
# stop tcpdump:  kill %1
```

### Task 2 — Extract the C2 indicators from the PCAP

```bash
tcpdump -r beacon.pcap -nn -A | grep -E "GET|Host:|User-Agent:"
```

Real output:

```
GET /gate.php?id=TRAINING-BOT-01 HTTP/1.1
Host: c2.example.com
User-Agent: TrainingBeacon/1.0
```

Your IOC table (note: **defang** for any writeup):

| IOC | Value (defanged) | Type |
|-----|------------------|------|
| C2 host (Host header) | `c2[.]example[.]com` | domain |
| Destination | `127[.]0[.]0[.]1:8888` (lab) | ip:port |
| URL path | `/gate.php?id=TRAINING-BOT-01` | url path |
| User-Agent | `TrainingBeacon/1.0` | signature |

### Task 3 — Prove offline still yields intel

```bash
./beacon_http 198.51.100.7 80     # a doc IP that won't answer
# -> "connect ... failed — attempt still visible in telemetry"
strace -e trace=network ./beacon_http 198.51.100.7 80 2>&1 | grep -E "connect|getaddrinfo"
```

The `connect()` to the intended host is right there in the syscall trace even
though it failed. **Failed ≠ useless.**

### Task 4 — Through Detonate

Submit `beacon_http` for dynamic analysis. Read the **network** panel (DNS +
connections + extracted HTTP hosts) and any **Suricata** alerts on the captured
PCAP (`SURICATA_ENABLED=true`). Detonate's network-analysis service performs the
same DNS/host/connection extraction you just did by hand, and the IOC export
([Level 6](../../06-config-extraction/)) emits these as structured indicators.

---

## Guided questions

1. You point the beacon at an unreachable IP and the connection fails. Name two
   pieces of C2 intel you can *still* recover, and from where.
2. Of {domain, IP, URL path, User-Agent}, which is usually the most durable IOC
   to block, and which is most useful as a *detection signature*? Why might they
   differ?
3. The traffic is plain HTTP here. If it were HTTPS, what would you still see in
   the PCAP and what would be hidden?
4. Why must you **defang** `c2.example.com` and the URL before putting them in a
   report or ticket?
5. How would you recognize **beaconing** specifically (vs a one-shot download) in
   the telemetry?

---

## Solution

<details>
<summary>Spoiler — open after attempting.</summary>

1. The **intended destination IP+port** (from the `connect()` syscall / capture)
   and, if a DNS lookup preceded it, the **domain** (from the `getaddrinfo`/DNS
   query). Both are emitted before any server reply, so they survive a failed or
   offline connection.
2. **Domain/IP are the most blockable** (push to firewalls/DNS sinkholes); the
   **URL path + User-Agent make the best detection signatures** because they're
   often hard-coded per family and survive infrastructure rotation. They differ
   because attackers rotate domains/IPs cheaply but change code (paths/UAs) less
   often — the "pyramid of pain."
3. With HTTPS you'd still see the **destination IP and port**, the **TLS SNI**
   (often the domain), and timing/size patterns; the **request path, headers,
   and body are encrypted** and hidden without TLS interception.
4. So the IOC can't be **accidentally clicked, fetched, or auto-extracted** by a
   scanner/mail filter from your report — and to avoid re-triggering tooling on
   the live indicator. `hxxp://`, `c2[.]example[.]com` neutralize that
   ([SAFETY §5](../../SAFETY.md)).
5. **Repetition at intervals**: the same destination contacted multiple times
   with roughly periodic spacing (often with jitter), small request sizes, and a
   consistent UA/path. A one-shot download is a single connection, usually
   pulling a larger response. Detonate's timeline + repeated-connection view
   makes the cadence visible.

</details>

---

## Going further

- Run the beacon several times in a loop and capture; eyeball the inter-arrival
  timing — you've simulated beaconing.
- Write a Suricata rule that alerts on `User-Agent: TrainingBeacon` and test it
  against `beacon.pcap` with `suricata -r beacon.pcap`.
- Next: [Module 3.4 — MITRE ATT&CK mapping](../04-mitre-attack/).
