"""Office document (Word/Excel/PowerPoint) static analyzer.

Extracts VBA macros, evaluates suspicious-keyword density, surfaces
auto-exec triggers, and lists embedded objects. Uses ``oletools`` when
available; degrades to a structural-only result when not.
"""

from __future__ import annotations

import io
import logging
import re
from typing import Any

logger = logging.getLogger("detonate.services.office_analyzer")


_OFFICE_MIMES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-office",
}

_OFFICE_EXTENSIONS = {
    ".doc", ".docm", ".docx", ".dot", ".dotm", ".dotx",
    ".xls", ".xlsm", ".xlsx", ".xlsb", ".xlt", ".xltm", ".xltx",
    ".ppt", ".pptm", ".pptx", ".ppsm", ".pptm",
    ".rtf",
}


def is_office_file(filename: str | None, mime: str | None, data: bytes | None = None) -> bool:
    if mime and mime in _OFFICE_MIMES:
        return True
    if filename:
        lower = filename.lower()
        for ext in _OFFICE_EXTENSIONS:
            if lower.endswith(ext):
                return True
    if data:
        # OLE2 compound (older formats) and ZIP (OOXML) magic
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return True
        if data.startswith(b"PK\x03\x04") and (b"word/" in data[:8192] or b"xl/" in data[:8192] or b"ppt/" in data[:8192]):
            return True
    return False


_AUTO_EXEC_KEYWORDS = (
    "AutoOpen", "AutoExec", "AutoClose", "Auto_Open", "Auto_Close",
    "Workbook_Open", "Document_Open", "Document_Close", "Workbook_Activate",
)
_SUSPICIOUS_VBA_TOKENS = (
    "Shell", "WScript.Shell", "Wscript.Shell", "CreateObject", "GetObject",
    "URLDownloadToFile", "MSXML2.XMLHTTP", "XMLHTTP", "WinHttp.WinHttpRequest",
    "ADODB.Stream", "Environ", "Chr", "ChrW", "Asc", "StrReverse",
    "Run", "Open", "Write", "Close", "Kill", "Schtasks", "Powershell",
    "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta",
    "Base64", "FromBase64String", "GetSpecialFolder", "RegRead", "RegWrite",
)


def _suspicious_indicators(macro_source: str) -> list[str]:
    found: list[str] = []
    for token in _SUSPICIOUS_VBA_TOKENS:
        if token in macro_source:
            found.append(token)
    return sorted(set(found))


def _auto_exec_triggers(macro_source: str) -> list[str]:
    found: list[str] = []
    for kw in _AUTO_EXEC_KEYWORDS:
        if kw.lower() in macro_source.lower():
            found.append(kw)
    return sorted(set(found))


def _extract_iocs(text: str) -> dict[str, list[str]]:
    url_re = re.compile(r"https?://[^\s\"'<>)\\\]]+", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_re = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
    urls = list(dict.fromkeys(url_re.findall(text)))
    ips = list(dict.fromkeys(ip_re.findall(text)))
    domains = list(dict.fromkeys(d for d in domain_re.findall(text) if not ip_re.fullmatch(d)))
    return {"urls": urls[:100], "ips": ips[:100], "domains": domains[:100]}


def analyze_office(data: bytes, filename: str = "document") -> dict[str, Any]:
    """Run Office-document analysis. Always returns a dict; ``available``
    indicates whether the heavy oletools backend ran."""
    out: dict[str, Any] = {
        "filename": filename,
        "format": "ole2" if data.startswith(b"\xd0\xcf\x11\xe0") else "ooxml" if data.startswith(b"PK\x03\x04") else "rtf" if data.lstrip().startswith(b"{\\rtf") else "unknown",
        "available": False,
        "macros": [],
        "macro_count": 0,
        "auto_exec_triggers": [],
        "suspicious_indicators": [],
        "iocs": {"urls": [], "ips": [], "domains": []},
        "embedded_objects": [],
        "warnings": [],
    }

    try:
        from oletools.olevba import VBA_Parser
    except Exception as exc:
        logger.info("oletools not available: %s", exc)
        out["warnings"].append("oletools not installed; install with `pip install oletools`")
        return out

    try:
        vba = VBA_Parser(filename, data=data)
    except Exception as exc:
        out["warnings"].append(f"VBA_Parser failed: {exc}")
        return out

    out["available"] = True
    macros: list[dict[str, Any]] = []
    full_source: list[str] = []
    try:
        if vba.detect_vba_macros():
            for (filepath, stream_path, vba_filename, vba_code) in vba.extract_macros():
                source = (vba_code or "").strip()
                if not source:
                    continue
                full_source.append(source)
                macros.append({
                    "stream": stream_path,
                    "filename": vba_filename,
                    "size": len(source),
                    "source_preview": source[:2000],
                })
    except Exception as exc:
        out["warnings"].append(f"Macro extraction failed: {exc}")
    finally:
        try:
            vba.close()
        except Exception:
            pass

    out["macros"] = macros
    out["macro_count"] = len(macros)
    joined = "\n".join(full_source)
    out["auto_exec_triggers"] = _auto_exec_triggers(joined)
    out["suspicious_indicators"] = _suspicious_indicators(joined)
    out["iocs"] = _extract_iocs(joined)

    # Embedded objects (OLE2 only): look for known directory names
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        try:
            import olefile  # type: ignore

            ole = olefile.OleFileIO(io.BytesIO(data))
            try:
                streams = ole.listdir(streams=True)
                emb: list[dict[str, Any]] = []
                for parts in streams:
                    name = "/".join(parts)
                    if any(k in name for k in ("Ole10Native", "Package", "Embedded", "ObjectPool")):
                        try:
                            size = ole.get_size(parts)
                        except Exception:
                            size = 0
                        emb.append({"path": name, "size": size})
                out["embedded_objects"] = emb[:50]
            finally:
                ole.close()
        except Exception as exc:
            logger.debug("Embedded-object extraction failed: %s", exc)

    # Heuristic risk score: 0..100
    risk = 0
    risk += min(40, 10 * len(out["auto_exec_triggers"]))
    risk += min(40, 4 * len(out["suspicious_indicators"]))
    risk += min(20, 5 * len(out["iocs"].get("urls", [])))
    out["risk_score"] = min(100, risk)

    return out
