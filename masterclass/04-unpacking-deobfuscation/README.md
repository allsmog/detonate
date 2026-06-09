# Level 4 — Unpacking & Deobfuscation

*Goal: get past the armor to the real code. Most interesting malware is packed,
encrypted, or obfuscated. This level is where reverse engineering gets real.*

**Prerequisites:** [Level 1](../01-foundations/) (assembly + PE/ELF),
[Level 2.3](../02-static-analysis/) (entropy/packing detection), comfort with a
debugger. **Read [SAFETY.md](../SAFETY.md).**

## Modules

| # | Module | Status |
|---|--------|--------|
| 4.1 | [UPX & common packers](01-upx-and-packers/) | ✅ Built |
| 4.2 | [Custom packers & unpacking stubs](02-custom-packers/) | ✅ Built |
| 4.3 | [String & API obfuscation](03-string-api-obfuscation/) | ✅ Built |
| 4.4 | [Scripted deobfuscation](04-scripted-deobfuscation/) | ✅ Built |

---

### 4.1 — UPX & common packers
**Objective:** recognize and unpack standard packers. **Theory:** what a packer
does (compress/encrypt the real image, prepend a stub that restores it at
runtime), the UPX format, and the difference between automated unpacking
(`upx -d`) and the manual approach you'll need when the header is tampered.
**Lab:** UPX-pack a benign binary, confirm via entropy/section names in Detonate
that it's packed, then unpack it both ways. **Solution:** both methods, with the
tells that revealed the packer.

### 4.2 — Custom packers & unpacking stubs
**Objective:** manually unpack when no tool exists. **Theory:** the universal
manual-unpacking workflow — let the stub run, find the **Original Entry Point**
(OEP) where it jumps to the unpacked code (tail jumps, `pushad`/`popad`
bookends, the moment a section becomes executable), dump the process image, and
**rebuild the Import Address Table**. **Lab:** unpack a custom-packed training
sample in a debugger: break at OEP, dump, fix imports, confirm the dumped binary
disassembles cleanly. **Solution:** step-by-step with screenshots of OEP
identification. **Connects to:** Detonate's dynamic analysis can confirm the
unpacked behavior even before you finish a clean dump.

### 4.3 — String & API obfuscation
**Objective:** defeat the most common code-level obfuscation. **Theory:** stack
strings (built byte-by-byte to evade `strings`), XOR/RC4/custom string
encryption, and **API hashing** (resolving functions by a hash of their name so
no readable import or string exists). How to recognize each and where the
decryption routine lives. **Lab:** find and reverse a simple XOR string
decryptor in a training sample; identify the key and decrypt the strings.
**Solution:** locating the routine, recovering the key, recovering plaintext.

### 4.4 — Scripted deobfuscation
**Objective:** automate decryption instead of doing it by hand. **Theory:**
porting a decryption routine to Python; **emulation** with Unicorn to run an
isolated decryption function without the whole binary; using Capstone for
disassembly-driven extraction. **Lab:** write a Python script that decrypts all
strings from the Module 4.3 sample, then emulate the decryptor with Unicorn to
verify. **Solution:** a reusable deobfuscation script. **Leads into:**
[Level 6 — config extraction](../06-config-extraction/) uses the same skills.

---

**Next:** [Level 5 — Anti-Analysis](../05-anti-analysis/).
