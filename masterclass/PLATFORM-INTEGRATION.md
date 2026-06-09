# Platform Integration — Detonate as the Lab Bench

The masterclass isn't a separate course bolted onto a product; the platform *is*
the lab. This doc covers the two-way integration and how it was verified against
a running instance.

## 1. CTF challenges (auto-graded labs)

The platform ships a **Challenges** feature (`/challenges` in the UI,
`/api/v1/challenges` in the API) that turns the curriculum into an auto-graded
CTF. Each challenge maps to a real lab; the **flag is the value you recover** by
doing it:

| Challenge | Maps to | Flag (the recovered value) |
|-----------|---------|----------------------------|
| Read a Debugger | [Module 1.3](01-foundations/03-re-toolchain/) | the crackme flag |
| Dump at the OEP | [Module 4.2](04-unpacking-deobfuscation/02-custom-packers/) | the unpacked payload string |
| Defeat the Obfuscation | [Module 4.3](04-unpacking-deobfuscation/03-string-api-obfuscation/) | the deobfuscated C2 host |
| Pull the Campaign ID | [Module 6.1](06-config-extraction/01-decrypting-config/) | the decrypted campaign id |
| Capstone: Identify the Bot | [Level 7](07-capstone/) | the bot id from the full kill chain |

Flags are stored only as SHA-256 hashes. Solves are tracked per user (or per
anonymous handle when `AUTH_ENABLED=false`, the default masterclass setup), with
a points leaderboard. Backend: `api/detonate/{models,services,api/routes}/
challenge*`. Frontend: `frontend/src/app/challenges/`. Tests:
`api/tests/test_challenges.py` (8 tests).

## 2. Labs reference the real engine

Throughout the curriculum, labs point at the actual platform code rather than a
parallel reimplementation:
- Static analysis (`api/detonate/services/static_analysis.py`) — Modules 1.1,
  1.4, 2.1–2.3.
- Guest agent / strace (`sandbox/linux/guest_agent.py`) — Modules 3.1–3.3.
- MITRE rules (`api/detonate/services/mitre/rules.py`) — Module 3.4.
- IOC export / STIX (`api/detonate/services/ioc_export.py`) — Module 6.3.

## 3. Live verification

This integration was verified against a locally-run stack (Postgres 16 + Redis
7, plus the FastAPI app), not just unit mocks:

**a. Migrations + tests.** Alembic migrations applied cleanly (including the new
`challenges`/`challenge_solves` tables); `tests/test_challenges.py` passes 8/8,
idempotently across repeated runs against the real database.

**b. CTF end-to-end against the running app + real Postgres.** Listing
challenges, rejecting a wrong flag, accepting the real lab answer
(`TRAIN-2026` → "Correct! +250 points", first_solve=True), and a leaderboard
reflecting persisted solves across players — all exercised through the actual
FastAPI request/response cycle with DB commits.

**c. Platform engine on masterclass samples.** The real
`run_static_analysis()` was run on the Module 2.1 `stringy` training binary and
extracted exactly the IOCs the module documents:

```
strings.interesting:
  urls:        ['http://example.com/gate.php?id=']
  ips:         ['192.0.2.123']
  emails:      ['operator@example.com']
  file_paths:  ['C:\\Users\\Public\\svchost32.exe']
```

and parsed the Windows PE (`win_imports.exe`) entry point as `0x1410` — matching
the value the Windows supplement teaches. The curriculum, the training binaries,
and the platform agree.

## 4. Honest scope note

Full **dynamic detonation** (submitting a sample and running it in the
Docker/QEMU sandbox) requires Docker, which wasn't available in the environment
where this was verified. The dynamic *labs* were instead verified independently
at the syscall level (`strace`) in
[`tools/build_and_test.sh`](tools/build_and_test.sh), and the dynamic modules
reference the exact guest-agent code that performs the same capture. Standing up
the sandbox image (`make sandbox-build`) on a Docker-capable host enables the
end-to-end detonation path described in Level 3.
