# Security Policy

Detonate is a malware analysis platform and an educational masterclass. Security
matters here in two distinct ways: vulnerabilities in the software, and the safe
handling of malicious samples.

## Reporting a vulnerability

If you find a security vulnerability in Detonate (the API, sandbox escape,
authentication bypass, etc.), please report it responsibly:

- **Do not** open a public issue with exploit details.
- Use GitHub's **private vulnerability reporting** (Security → Report a
  vulnerability) on this repository, or contact the maintainers directly.
- Include: affected component, version/commit, reproduction steps, and impact.
- Please allow a reasonable window for a fix before public disclosure.

We'll acknowledge receipt, keep you updated, and credit you (if you wish) when a
fix ships.

## Sandbox escapes — highest priority

This project executes untrusted, often malicious code in a sandbox. A **sandbox
escape** (sample breaking out of the Docker/QEMU isolation onto the host or
network) is the most serious class of bug here. Report these privately and
treat them as critical.

If you operate Detonate, follow the deployment hardening guidance and run the
sandbox on isolated, disposable infrastructure — never on a host with access to
anything you care about.

## Handling malicious samples (masterclass)

This repository's educational content involves handling live malware. Sample
safety is covered in depth in [masterclass/SAFETY.md](masterclass/SAFETY.md).
In short:

- **No live malicious binaries are committed to this repository.** The repo
  ships purpose-built *benign* training binaries (source included) and
  *references* (SHA-256 + sourcing instructions) to real samples you fetch
  yourself from vetted communities.
- IOCs in documentation are **defanged** (`hxxp://`, `1.2.3[.]4`).
- `.gitignore` excludes sample binaries and `samples/` working directories.

### Found a live sample committed to the repo?

If you discover an un-defanged live malicious binary committed to the
repository (it shouldn't happen), **report it privately** as a security issue so
it can be purged from history. Do not download or execute it outside an isolated
lab.

## Supported versions

This is an actively developed project; security fixes target the `main` branch.
There is no long-term-support guarantee for older commits.
