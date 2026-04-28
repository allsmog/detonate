"""Email file (.eml / .msg) analyzer.

Parses headers, extracts attachments and URLs, surfaces SPF/DKIM/DMARC
hints, and computes a phishing-style risk score from sender domain
mismatches and presence of executable attachments. Native Python for
.eml; uses ``extract-msg`` for Outlook .msg when installed.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import logging
import re
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger("detonate.services.email_analyzer")


_EXECUTABLE_EXTS = (
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".ps1", ".lnk", ".hta", ".wsf", ".jar", ".msi",
    ".docm", ".xlsm", ".pptm", ".doc", ".xls",  # macro-capable
    ".iso", ".img",
)


def is_email_file(filename: str | None, mime: str | None, data: bytes | None = None) -> bool:
    if mime and mime in {"message/rfc822", "application/vnd.ms-outlook"}:
        return True
    if filename:
        lower = filename.lower()
        if lower.endswith((".eml", ".msg")):
            return True
    if data:
        head = data[:1024].lower()
        if b"received:" in head and b"from " in head:
            return True
    return False


def _extract_iocs(text: str) -> dict[str, list[str]]:
    url_re = re.compile(r"https?://[^\s\"'<>)\\\]]+", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return {
        "urls": list(dict.fromkeys(url_re.findall(text)))[:100],
        "ips": list(dict.fromkeys(ip_re.findall(text)))[:100],
    }


def _domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.split("@", 1)[1].strip(">").lower()
    return ""


def _walk_eml(msg: EmailMessage) -> tuple[list[dict[str, Any]], str]:
    attachments: list[dict[str, Any]] = []
    body_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        if filename or "attachment" in disp:
            sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
            attachments.append({
                "filename": filename or "(unnamed)",
                "content_type": ctype,
                "size": len(payload),
                "sha256": sha256,
                "is_executable": bool(filename and any(filename.lower().endswith(e) for e in _EXECUTABLE_EXTS)),
            })
        elif ctype.startswith("text/"):
            try:
                body_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
            except Exception:
                pass
    return attachments, "\n".join(body_parts)


def analyze_email_eml(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "format": "eml",
        "headers": {},
        "from": "",
        "reply_to": "",
        "to": [],
        "subject": "",
        "date": "",
        "received_chain": [],
        "auth_results": {"spf": "", "dkim": "", "dmarc": ""},
        "attachments": [],
        "body_preview": "",
        "iocs": {"urls": [], "ips": []},
        "warnings": [],
    }

    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as exc:
        out["warnings"].append(f"Parse failed: {exc}")
        return out

    headers_keep = ("From", "To", "Cc", "Subject", "Date", "Reply-To",
                    "Return-Path", "Message-ID", "X-Originating-IP",
                    "X-Mailer", "User-Agent")
    out["headers"] = {h: str(msg.get(h, "")) for h in headers_keep if msg.get(h)}
    out["from"] = str(msg.get("From", ""))
    out["reply_to"] = str(msg.get("Reply-To", ""))
    out["to"] = [t.strip() for t in str(msg.get("To", "")).split(",") if t.strip()]
    out["subject"] = str(msg.get("Subject", ""))
    out["date"] = str(msg.get("Date", ""))
    out["received_chain"] = [str(r) for r in msg.get_all("Received", [])][:10]

    # Authentication-Results parsing
    ar = " ".join(msg.get_all("Authentication-Results", []) or [])
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{key}=([a-z]+)", ar, re.IGNORECASE)
        if m:
            out["auth_results"][key] = m.group(1).lower()

    attachments, body = _walk_eml(msg)
    out["attachments"] = attachments
    out["body_preview"] = body[:4000]
    out["iocs"] = _extract_iocs(body)

    # Phishing risk heuristics
    risk = 0
    if any(att["is_executable"] for att in attachments):
        risk += 35
    if out["auth_results"].get("spf") == "fail":
        risk += 20
    if out["auth_results"].get("dkim") == "fail":
        risk += 15
    if out["auth_results"].get("dmarc") == "fail":
        risk += 15
    from_dom = _domain_of(out["from"])
    reply_dom = _domain_of(out["reply_to"])
    if from_dom and reply_dom and from_dom != reply_dom:
        risk += 15
        out["warnings"].append(f"From/Reply-To domain mismatch: {from_dom} vs {reply_dom}")
    if len(out["iocs"].get("urls", [])) > 5:
        risk += 5
    out["risk_score"] = min(100, risk)
    return out


def analyze_email_msg(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"format": "msg", "warnings": []}
    try:
        import extract_msg  # type: ignore
        import io as _io

        msg = extract_msg.openMsg(_io.BytesIO(data))
    except Exception as exc:
        out["warnings"].append(f"extract-msg unavailable or parse failed: {exc}")
        return out

    try:
        out["from"] = msg.sender or ""
        out["to"] = (msg.to or "").split(";")
        out["subject"] = msg.subject or ""
        out["date"] = str(msg.date or "")
        body = msg.body or ""
        out["body_preview"] = body[:4000]
        atts = []
        for att in msg.attachments or []:
            try:
                payload = att.data or b""
            except Exception:
                payload = b""
            fname = att.longFilename or att.shortFilename or "(unnamed)"
            atts.append({
                "filename": fname,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                "is_executable": bool(fname and any(fname.lower().endswith(e) for e in _EXECUTABLE_EXTS)),
            })
        out["attachments"] = atts
        out["iocs"] = _extract_iocs(body)
        risk = 0
        if any(a["is_executable"] for a in atts):
            risk += 35
        out["risk_score"] = min(100, risk)
    finally:
        try:
            msg.close()
        except Exception:
            pass

    return out


def analyze_email(data: bytes, filename: str = "message.eml") -> dict[str, Any]:
    if filename.lower().endswith(".msg") or data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return analyze_email_msg(data)
    return analyze_email_eml(data)
