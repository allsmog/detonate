# Contributing to Detonate

Thanks for your interest. Detonate is two things in one repo — an open-source
malware analysis sandbox **and** the [Detonate Masterclass](masterclass/), a
hands-on reverse-engineering curriculum. You can contribute to either.

Please read this whole file before opening a PR, and read
[masterclass/SAFETY.md](masterclass/SAFETY.md) if your contribution touches
samples or malware-handling.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Never commit live malware.** No malicious binaries, no un-defanged IOCs, no
  victim data. This is a hard rule (see below and SAFETY.md).
- Discuss large changes in an issue first so effort isn't wasted.

## Contributing to the platform (code)

### Setup

See [README.md](README.md) and [masterclass/SETUP.md](masterclass/SETUP.md).
Roughly: `make services && make setup`, then `make dev`.

### Before you open a PR

```bash
make lint      # Ruff (Python) + ESLint (frontend)
make format    # Ruff format + Prettier
make test-api  # pytest
```

- Keep changes focused; one logical change per PR.
- Match the existing style — async SQLAlchemy 2.0 patterns in the API, the
  established component/hook structure in the frontend.
- Add or update tests for behavior changes.
- Update docs (README/API) when you change endpoints or behavior.

## Contributing to the masterclass (curriculum)

This is where help is especially welcome — the curriculum spine exists and many
modules are outlined and waiting to be built out.

### Building a module

1. Copy [`masterclass/_template/`](masterclass/_template/) into the right level
   folder with the correct number (e.g. `02-static-analysis/02-imports-as-behavior/`).
2. Follow the **seven-part shape**: Objectives, Prerequisites, Theory, Lab,
   Guided questions, Solution, Going further.
3. A module is **not done** until it has a *working lab* and a *complete
   solution*. Theory alone is not a module.
4. Prefer tying labs to **Detonate** — use the platform as the lab bench.
   Reference real files/endpoints so learners see the connection.

### Sample rules for modules (non-negotiable)

- **Early/teaching labs:** use a **purpose-built benign training binary**.
  Commit the **source** (e.g. `.c`/`.py`), never the compiled binary. It must
  be genuinely harmless — it may *mimic the shape* of malicious behavior
  (spawn a child, drop a file, attempt a beacon) but must do no harm.
- **Real-sample labs:** do **not** commit the sample. Instead provide:
  - the **SHA-256**,
  - where to fetch it (MalwareBazaar/vx-underground/theZoo per SAFETY §3),
  - and a note to handle it password-protected, in an isolated lab.
- **All IOCs in writeups must be defanged** (`hxxp://`, `evil[.]com`,
  `1.2.3[.]4`). No exceptions.
- Solutions may include annotated disassembly and **defanged** extracted configs.

### Quality bar

World-class means: objectives are testable, theory has no padding, the lab works
end-to-end on a clean setup, guided questions force understanding (not recall),
and the solution actually explains the reasoning — not just the answer.

## Pull request process

1. Branch from `main` (or the active development branch).
2. Make your change; run lint/format/tests (for code) or self-review against the
   seven-part shape and sample rules (for curriculum).
3. Open a PR using the template; describe what and why, link any issue.
4. CI must pass. A maintainer reviews; address feedback.

## License

By contributing, you agree your contributions are licensed under the repository's
[MIT License](LICENSE).
