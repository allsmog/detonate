"""Script (PowerShell, JS, VBS, batch) static analyzer.

Decodes common obfuscation chains (base64, hex, char-code), extracts
IOCs, and flags high-risk APIs. The goal is "fast triage": no
sandboxing, just structural analysis you can run in milliseconds.
"""

from __future__ import annotations

import base64
import re
from typing import Any

_SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1",
    ".js", ".jse",
    ".vbs", ".vbe",
    ".bat", ".cmd",
    ".sh",
    ".hta", ".wsf",
}

_SCRIPT_MIMES = {
    "text/x-shellscript",
    "application/x-powershell",
    "application/x-msdos-program",
    "application/javascript",
    "text/javascript",
    "application/x-vbscript",
}


def is_script_file(filename: str | None, mime: str | None) -> bool:
    if mime and mime in _SCRIPT_MIMES:
        return True
    if filename:
        lower = filename.lower()
        for ext in _SCRIPT_EXTENSIONS:
            if lower.endswith(ext):
                return True
    return False


def detect_language(filename: str | None, content: str) -> str:
    if filename:
        lower = filename.lower()
        if lower.endswith((".ps1", ".psm1", ".psd1")):
            return "powershell"
        if lower.endswith((".js", ".jse")):
            return "javascript"
        if lower.endswith((".vbs", ".vbe")):
            return "vbscript"
        if lower.endswith((".bat", ".cmd")):
            return "batch"
        if lower.endswith(".sh"):
            return "shell"
        if lower.endswith((".hta", ".wsf")):
            return "windows-script"
    head = content[:512].lower()
    if "powershell" in head or "$env:" in head or "invoke-" in head:
        return "powershell"
    if "function" in head and "var " in head:
        return "javascript"
    if "createobject" in head or "wscript" in head:
        return "vbscript"
    return "unknown"


_HIGH_RISK_TOKENS = {
    "powershell": (
        "IEX", "Invoke-Expression", "Invoke-Command", "Invoke-WebRequest",
        "DownloadString", "DownloadFile", "Net.WebClient", "FromBase64String",
        "EncodedCommand", "-enc", "-EncodedCommand", "-nop", "-NonInteractive",
        "Start-Process", "Add-Type", "Reflection.Assembly", "GetType",
        "VirtualAlloc", "WriteProcessMemory", "CreateThread",
        "BypassPolicy", "Bypass",
    ),
    "javascript": (
        "eval(", "Function(", "WScript.Shell", "ActiveXObject",
        "ADODB.Stream", "MSXML2.XMLHTTP", "XMLHttpRequest",
        "atob(", "fromCharCode", "unescape(", "document.write(",
    ),
    "vbscript": (
        "CreateObject", "Wscript.Shell", "WScript.Shell", "ADODB.Stream",
        "MSXML2.XMLHTTP", "XMLHTTP", "Run", "Shell", "Chr(", "Asc(",
        "Eval(", "Execute(",
    ),
    "batch": (
        "powershell", "rundll32", "regsvr32", "mshta", "wmic",
        "schtasks", "bitsadmin", "certutil", "/c ", "/k ",
    ),
    "shell": (
        "curl ", "wget ", "/bin/sh", "bash -c", "nc ", "ncat ",
        "/dev/tcp/", "base64 -d", "eval ",
    ),
    "windows-script": (
        "ActiveXObject", "WScript.Shell", "MSXML2", "ADODB.Stream",
    ),
}


_OBFUSCATION_PATTERNS = (
    (r"FromBase64String", "powershell-base64"),
    (r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{30,}", "powershell-encoded-command"),
    (r"\bChr\s*\(\s*\d+\s*\)\s*&", "vbs-chr-concat"),
    (r"String\.fromCharCode\s*\(", "js-fromcharcode"),
    (r"\\x[0-9a-fA-F]{2}", "hex-escape"),
    (r"\\u[0-9a-fA-F]{4}", "unicode-escape"),
    (r"\^", "batch-caret-escape"),
    (r"`[a-z]", "powershell-backtick-escape"),
    (r"\$\{[a-z]\}\$\{[a-z]\}", "powershell-variable-split"),
    (r"\[char\]\s*0x", "powershell-char-cast"),
)


_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")


def _try_decode_base64(s: str) -> tuple[str, bytes] | None:
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if not raw:
        return None
    # Heuristic: PowerShell uses UTF-16LE for -EncodedCommand
    try:
        utf16 = raw.decode("utf-16-le")
        printable = sum(1 for c in utf16 if 32 <= ord(c) < 127 or c in "\r\n\t")
        if printable > 0.8 * len(utf16) and len(utf16) > 4:
            return ("utf-16-le", raw)
    except Exception:
        pass
    try:
        ascii_dec = raw.decode("utf-8")
        printable = sum(1 for c in ascii_dec if 32 <= ord(c) < 127 or c in "\r\n\t")
        if printable > 0.8 * len(ascii_dec) and len(ascii_dec) > 4:
            return ("utf-8", raw)
    except Exception:
        pass
    return ("binary", raw)


def _extract_iocs(text: str) -> dict[str, list[str]]:
    url_re = re.compile(r"https?://[^\s\"'<>)\\\]]+", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_re = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
    urls = list(dict.fromkeys(url_re.findall(text)))
    ips = list(dict.fromkeys(ip_re.findall(text)))
    domains = list(dict.fromkeys(d for d in domain_re.findall(text) if not ip_re.fullmatch(d)))
    return {"urls": urls[:100], "ips": ips[:100], "domains": domains[:100]}


def analyze_script(data: bytes, filename: str = "script") -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16-le")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")

    lang = detect_language(filename, text)

    high_risk: list[str] = []
    for token in _HIGH_RISK_TOKENS.get(lang, ()):
        if token.lower() in text.lower():
            high_risk.append(token)

    obfuscation: list[str] = []
    for pattern, label in _OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            obfuscation.append(label)

    # Decode chains: find base64 blobs, decode, recursively re-scan
    decoded_layers: list[dict[str, Any]] = []
    seen: set[str] = set()
    blobs = _BASE64_RE.findall(text)
    for blob in blobs:
        if blob in seen:
            continue
        seen.add(blob)
        result = _try_decode_base64(blob)
        if result is None:
            continue
        encoding, raw = result
        try:
            decoded_text = raw.decode(encoding, errors="replace") if encoding != "binary" else raw.hex()[:512]
        except Exception:
            decoded_text = raw.hex()[:512]
        decoded_layers.append({
            "encoding": encoding,
            "input_length": len(blob),
            "output_preview": decoded_text[:1024],
        })
        # Pull tokens from decoded text too
        for token in _HIGH_RISK_TOKENS.get(lang, ()):
            if token.lower() in decoded_text.lower() and token not in high_risk:
                high_risk.append(token)
        if len(decoded_layers) >= 10:
            break

    # IOCs from raw + decoded
    blob = text + "\n" + "\n".join(layer.get("output_preview", "") for layer in decoded_layers)
    iocs = _extract_iocs(blob)

    risk = 0
    risk += min(40, 6 * len(high_risk))
    risk += min(30, 8 * len(obfuscation))
    risk += min(15, 3 * len(decoded_layers))
    risk += min(15, 3 * len(iocs.get("urls", [])))

    return {
        "filename": filename,
        "language": lang,
        "size": len(data),
        "high_risk_tokens": sorted(set(high_risk)),
        "obfuscation_techniques": sorted(set(obfuscation)),
        "decoded_layers": decoded_layers,
        "iocs": iocs,
        "risk_score": min(100, risk),
    }
