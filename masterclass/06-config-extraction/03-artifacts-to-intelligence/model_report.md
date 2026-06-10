# Malware Analysis Report — "configbot" (training sample)

> Model report for Module 6.3. Demonstrates structure, evidence-first claims, and
> **defanged** IOCs. All indicators are inert (example.com/.net).

**Analyst:** masterclass · **Date:** 2026-06-09 · **Classification:** TLP:CLEAR (training)

## 1. Executive summary

`configbot` is a benign training sample modeling a commodity bot. It carries an
**RC4-encrypted configuration** (behind a `CFG0` marker) containing two C2
endpoints, a campaign ID, and a mutex. On execution it decrypts and would beacon
to its C2. **Verdict: malicious (simulated) · score 80/100** — based on encrypted
C2 config and beaconing behavior. *(For a real sample, attribute to a family
only with supporting evidence.)*

## 2. Triage

| Field | Value |
|-------|-------|
| SHA-256 | *(compute with `sha256sum configbot`)* |
| Type | ELF 64-bit executable |
| Notable | `CFG0` config marker present; C2 absent from `strings` (encrypted) |

## 3. Static analysis

- No C2/campaign strings in plaintext → config is encrypted.
- `CFG0` magic anchors an embedded blob: layout `CFG0 | uint16 len | RC4(config)`.
- Decryptor identified as **RC4** (256-byte S-box key schedule + swaps); key
  `s3cr3tk3y` recovered from the binary.

## 4. Configuration extraction

Decrypted config:

```
v=1;id=TRAIN-2026;c2=c2a.example.com:443,c2b.example.net:8443;mutex=Global\Train_8f3a
```

Structured (via `extract_config.py`): campaign `TRAIN-2026`, primary C2
`c2a.example.com:443`, fallback `c2b.example.net:8443`, mutex `Global\Train_8f3a`.

## 5. Dynamic analysis

On execution the sample decrypts its config and (would) beacon to the primary
C2 over TCP/443, falling back to the secondary on TCP/8443. *(Detonate would
capture the connection attempts and DNS lookups — see Level 3.)*

## 6. Indicators of Compromise (defanged)

| IOC | Type | Context |
|-----|------|---------|
| `c2a[.]example[.]com:443` | C2 | primary |
| `c2b[.]example[.]net:8443` | C2 | fallback |
| `TRAIN-2026` | campaign id | clustering / tracking |
| `Global\Train_8f3a` | mutex | single-instance / host detection |

Machine-readable STIX 2.1 bundle: see `make_stix.py` output.

## 7. MITRE ATT&CK

| Technique | Tactic | Evidence |
|-----------|--------|----------|
| T1071.001 Web Protocols | Command and Control | C2 over 443/8443 |
| T1027 Obfuscated Files or Information | Defense Evasion | RC4-encrypted config |
| T1041 Exfiltration Over C2 Channel | Exfiltration | (if data sent over C2) |

## 8. Detection

YARA: anchor on the `CFG0` marker + the RC4 key schedule constant pattern; see
Module 2.4 for rule-writing. Network: alert on the C2 domains/mutex.

## 9. Recommendations

Block both C2 endpoints; hunt for the mutex and campaign ID across the estate;
deploy the YARA rule to catch additional samples of the family.
