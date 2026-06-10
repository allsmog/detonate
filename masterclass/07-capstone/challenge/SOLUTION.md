# Capstone Solution — `crackmalware` (sealed answer key)

> **Instructors / self-graders only.** Do not read until your report is written.
> This is the model solution + grading key for the self-contained challenge
> built from `challenge_src.c`. All IOCs are inert (example.com/.net).

The challenge binary combines: **UPX packing**, **ptrace anti-debug**,
**XOR-obfuscated** User-Agent, **RC4** config behind a `CFG0` marker, and a
**beacon**. Full kill chain below, with verified outputs.

## 1. Triage / static — recognize packing

```
file crackmalware        -> ELF 64-bit, x86-64
strings crackmalware | grep UPX!   -> "UPX!"        (UPX packed)
readelf -S crackmalware | grep -c '\]'  -> 0        (no section headers)
```

**Conclusion:** UPX-packed, stripped. Static reading is futile until unpacked.

## 2. Unpack (Level 4.1)

```
cp crackmalware cm && upx -d cm
readelf -S cm | grep -c '\]'   -> 30     (sections restored)
strings cm | grep CFG0          -> CFG0    (config marker now visible)
```

## 3. Anti-debug (Level 5.2)

The unpacked binary calls `ptrace(PTRACE_TRACEME)`; under a debugger it prints
`system check failed` and exits. **Bypass** by forcing the return to 0:

```
gdb -q -batch -ex 'break ptrace' -ex 'run' -ex 'finish' -ex 'set $rax=0' \
  -ex 'continue' ./cm
```

Result (the real path runs):

```
[ok] config=id=CAPSTONE-01;c2=evil-c2.example.com:8443,backup.example.net:443;mutex=Global\Caps_1337
[ok] ua=Mozilla/5.0 (CapstoneBot)
```

## 4. Config extraction (Level 6) — static, no execution needed

RC4 key `unpackme!`; blob is `CFG0 | uint16 len | RC4(config)`:

```python
def rc4(key,data):
    S=list(range(256)); j=0
    for i in range(256): j=(j+S[i]+key[i%len(key)])&0xff; S[i],S[j]=S[j],S[i]
    i=j=0; out=bytearray()
    for b in data:
        i=(i+1)&0xff; j=(j+S[i])&0xff; S[i],S[j]=S[j],S[i]
        out.append(b^S[(S[i]+S[j])&0xff])
    return bytes(out)
raw=open("cm","rb").read(); off=raw.find(b"CFG0")
ln=int.from_bytes(raw[off+4:off+6],"little")
print(rc4(b"unpackme!", raw[off+6:off+6+ln]).decode())
# -> id=CAPSTONE-01;c2=evil-c2.example.com:8443,backup.example.net:443;mutex=Global\Caps_1337
```

User-Agent (Level 4.3): `enc_ua` is single-byte **XOR key 0x6b** →
`Mozilla/5.0 (CapstoneBot)` (recoverable by brute-force since it starts with
"Mozilla").

## 5. Dynamic / network (Level 3)

The sample beacons to the primary C2 over TCP/8443 with request line
`GET /panel/gate.php?bot=CAPSTONE-01` and the decoded User-Agent. (In Detonate,
the connection attempt + DNS appear in the network panel even offline.)

## 6. IOCs (defanged)

| IOC | Type |
|-----|------|
| `evil-c2[.]example[.]com:8443` | C2 (primary) |
| `backup[.]example[.]net:443` | C2 (fallback) |
| `/panel/gate[.]php?bot=CAPSTONE-01` | URL path / signature |
| `Mozilla/5.0 (CapstoneBot)` | User-Agent signature |
| `Global\Caps_1337` | mutex |
| `CAPSTONE-01` | campaign/bot id |

## 7. MITRE ATT&CK

| Technique | Tactic | Evidence |
|-----------|--------|----------|
| T1027 Obfuscated Files/Info | Defense Evasion | UPX packing + RC4 config + XOR string |
| T1497 Virtualization/Sandbox Evasion | Defense Evasion | ptrace anti-debug |
| T1071.001 Web Protocols | Command and Control | HTTP beacon to C2 |
| T1071 / T1041 | C2 / Exfil | C2 over 8443/443 |

## 8. Detection (YARA)

Anchor on the `CFG0` marker + UPX characteristics + the RC4 key-schedule
constant. Network: alert on the User-Agent `CapstoneBot` and the C2 domains.

## Grading key (maps to the rubric in ../README.md)

| Area | Must demonstrate |
|------|------------------|
| Triage & static (15) | Correctly IDs UPX packing + stripped + anti-debug presence. |
| Unpacking (20) | `upx -d` (or manual dump); reaches the real code. |
| Dynamic (20) | Identifies beacon to C2:8443, request path, UA; ties to evidence. |
| IOC & config (15) | Recovers full config + UA; IOCs complete and **defanged**. |
| MITRE (10) | T1027/T1497/T1071 justified, not guessed. |
| Detection (10) | Working YARA on CFG0/UA; low FP. |
| Report (10) | Clear, evidence-backed, honest; no over-attribution. |

Pass = 70. A top report is decisive on the recoverable facts (config, C2, UA)
and explicitly notes what *isn't* knowable from a single sample (the operator).
