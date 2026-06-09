# SAFETY — Handling Malware Without Hurting Yourself or Others

Read this completely before any lab that uses a real sample. The skills in this
masterclass are dual-use. Treating live malware casually is how analysts infect
their own networks, leak victim data, or break the law. None of that is
hypothetical.

If you only remember three things:

1. **Real malware runs only in an isolated lab you can throw away.**
2. **Never execute a sample on a machine you care about, on your home/work
   network, or anywhere it can reach the internet unfiltered.**
3. **Samples are shared password-protected and IOCs are defanged. Keep them
   that way until you're deliberately inside the lab.**

---

## 1. Lab isolation

The labs assume one of these isolation models. Pick one and stick to it.

**Option A — Detonate sandbox (default for most labs).**
The platform is *designed* to detonate samples in a disposable Docker/QEMU
sandbox with controlled networking. For the dynamic-analysis labs, you submit
the sample to Detonate and read telemetry — you do **not** run it on your host.
Configure the sandbox network mode to `none` or `inetsim`-style simulation
unless a lab explicitly calls for controlled internet.

**Option B — A dedicated analysis VM (for hands-on debugging labs).**
When a lab has you load a sample in a debugger/disassembler:
- Use a VM (VMware/VirtualBox/KVM) with a **host-only or internal network**, no
  bridged/NAT internet unless required and simulated.
- Take a **clean snapshot** before each detonation; revert after.
- No shared folders / clipboard with the host while a sample is live.
- Never store the only copy of anything important inside the analysis VM.

**What is *not* acceptable:** running real samples directly on your OS, on a
machine with corporate/VPN access, or on a network with other people's devices.

> Static analysis (reading bytes, disassembly without execution) is far lower
> risk, but still treat the files as live — a "static" PDF/Office sample can
> compromise a careless viewer. Don't double-click anything.

---

## 2. Legal & ethical boundaries

- **Authorization:** Only analyze samples you are authorized to handle —
  curated training samples, samples from your own incidents, or samples from
  reputable sharing communities under their terms. Don't pull malware off
  random victims' machines without authority.
- **Don't redistribute live malware** outside controlled, clearly-labeled,
  password-protected channels. This repo does **not** check live binaries into
  git (see §4).
- **Don't weaponize.** This curriculum teaches you to *understand and defend
  against* malware. Using these skills to build or deploy malware, attack
  systems you don't own, or evade detection for malicious ends is outside its
  purpose and, in most jurisdictions, a crime.
- **Respect victim data.** Real samples and PCAPs can contain victim IPs,
  credentials, or stolen data. Don't publish it. Defang before sharing.
- **Jurisdiction matters.** Possessing/handling malware is regulated
  differently around the world. Know your local law and your
  employer/school's acceptable-use policy.

---

## 3. Sourcing samples responsibly

This repo does **not** ship live malicious binaries. Labs use one of:

- **Purpose-built benign "malware-like" binaries** — programs we wrote that
  *exhibit* a behavior (e.g., make a beacon-shaped request to a sinkhole,
  pack themselves with UPX) without being harmful. Early modules use these so
  you can learn mechanics safely. They live alongside their module with source.
- **References to vetted repositories** — for real-sample labs, we point you to
  community sources and tell you the exact hash to fetch:
  - [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) — free, hash-addressable.
  - [vx-underground](https://vx-underground.org/) — research archive.
  - [theZoo](https://github.com/ytisf/theZoo) — curated educational repo.
  - [MalShare](https://malshare.com/), [VirusShare](https://virusshare.com/) — registration required.

  You download these yourself, into your lab, under those sources' terms. We
  give you the SHA-256 so you analyze the *exact* sample the solution describes.

**The `infected` convention:** real samples are distributed as ZIPs encrypted
with the password `infected`. That's an industry standard — it stops automated
scanners and accidental execution. Keep samples zipped until they're inside
your isolated lab.

---

## 4. What this repository will and won't contain

| Will contain | Will NOT contain |
|--------------|------------------|
| Source for purpose-built benign training binaries | Live malicious binaries committed to git |
| SHA-256 hashes + sourcing instructions for real samples | Unencrypted real samples in the repo |
| **Defanged** IOCs in writeups (`hxxp://`, `1.2.3[.]4`) | Live clickable C2 URLs / un-defanged IOCs |
| Annotated disassembly and extracted (defanged) configs | Victim PII, stolen data, or credentials |

`.gitignore` excludes common sample extensions and a `samples/` working
directory so you don't commit live malware by accident. If you ever find a live
sample committed here, open a security issue per [../SECURITY.md](../SECURITY.md).

---

## 5. Defanging reference

When you write up findings, defang IOCs so they can't be accidentally clicked,
fetched, or auto-extracted by a scanner:

| Live | Defanged |
|------|----------|
| `http://evil.com/x` | `hxxp://evil[.]com/x` |
| `8.8.8.8` | `8.8.8[.]8` |
| `bad@evil.com` | `bad@evil[.]com` |
| `evil.com` | `evil[.]com` |

Detonate's IOC export and reporting already store IOCs as structured data;
defang when you copy them into human-readable docs.

---

## 6. If something goes wrong

- **You think your host got infected:** disconnect from the network, stop, and
  treat it as a real incident — revert the VM / reimage the host, rotate
  credentials that touched it.
- **You leaked a sample or victim data:** follow your org's incident process;
  for this repo, see [../SECURITY.md](../SECURITY.md).
- **You're unsure whether a lab step is safe:** default to the Detonate
  sandbox with networking disabled, and ask in an issue before improvising.

When in doubt, isolate harder. Nobody was ever fired for being too careful with
live malware.
