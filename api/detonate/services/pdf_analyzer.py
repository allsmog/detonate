"""PDF static analyzer.

Counts suspicious PDF object types (JavaScript, OpenAction, EmbeddedFile,
Launch, AA, RichMedia), extracts JS streams, and pulls URLs/IPs from
decoded streams. Implementation is dependency-light: walks raw PDF
bytes with regex, then uses ``pikepdf`` if available for richer
embedded-file enumeration.
"""

from __future__ import annotations

import logging
import re
import zlib
from typing import Any

logger = logging.getLogger("detonate.services.pdf_analyzer")


PDF_INDICATORS = [
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/AcroForm",
    "/JBIG2Decode",
    "/RichMedia",
    "/Launch",
    "/EmbeddedFile",
    "/XFA",
    "/URI",
    "/SubmitForm",
    "/GoTo",
    "/GoToR",
    "/GoToE",
    "/ObjStm",
    "/Encrypt",
]


def is_pdf(filename: str | None, mime: str | None, data: bytes | None = None) -> bool:
    if mime and mime in {"application/pdf"}:
        return True
    if filename and filename.lower().endswith(".pdf"):
        return True
    if data and data.lstrip().startswith(b"%PDF-"):
        return True
    return False


_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj(.*?)endobj", re.DOTALL)
_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_FILTER_RE = re.compile(rb"/Filter\s*(?:\[\s*)?/([A-Za-z0-9]+)")


def _read_pdf_string(buf: bytes, start: int) -> tuple[bytes, int] | None:
    """Read a PDF literal string starting at ``buf[start] == '('`` and
    track nested unescaped parens. Returns (content, end_index_after_close)
    or None if unterminated.
    """
    if start >= len(buf) or buf[start:start + 1] != b"(":
        return None
    i = start + 1
    depth = 1
    out = bytearray()
    while i < len(buf):
        ch = buf[i:i + 1]
        if ch == b"\\" and i + 1 < len(buf):
            out.extend(buf[i:i + 2])
            i += 2
            continue
        if ch == b"(":
            depth += 1
            out.extend(ch)
        elif ch == b")":
            depth -= 1
            if depth == 0:
                return bytes(out), i + 1
            out.extend(ch)
        else:
            out.extend(ch)
        i += 1
    return None


def _decode_stream(blob: bytes, filt: bytes) -> bytes:
    if filt in (b"FlateDecode", b"Fl"):
        try:
            return zlib.decompress(blob)
        except Exception:
            return blob
    return blob


def _extract_iocs(text: str) -> dict[str, list[str]]:
    url_re = re.compile(r"https?://[^\s\"'<>)\\\]]+", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return {
        "urls": list(dict.fromkeys(url_re.findall(text)))[:100],
        "ips": list(dict.fromkeys(ip_re.findall(text)))[:100],
    }


def analyze_pdf(data: bytes, filename: str = "document.pdf") -> dict[str, Any]:
    out: dict[str, Any] = {
        "filename": filename,
        "version": "",
        "indicator_counts": {k: 0 for k in PDF_INDICATORS},
        "object_count": 0,
        "javascript": [],
        "embedded_files": [],
        "uris": [],
        "iocs": {"urls": [], "ips": []},
        "warnings": [],
    }

    if not data.lstrip().startswith(b"%PDF-"):
        out["warnings"].append("Does not start with %PDF- header")

    # PDF version
    m = re.match(rb"%PDF-(\d\.\d)", data.lstrip()[:16])
    if m:
        out["version"] = m.group(1).decode("ascii", errors="replace")

    # Indicator counts (case-sensitive token search across raw bytes)
    for ind in PDF_INDICATORS:
        out["indicator_counts"][ind] = data.count(ind.encode("ascii"))

    # Walk objects, decode streams when filter is FlateDecode
    js_chunks: list[str] = []
    uri_set: set[str] = set()
    objects = list(_OBJ_RE.finditer(data))
    out["object_count"] = len(objects)

    for obj_match in objects:
        body = obj_match.group(3)
        is_js_obj = b"/JavaScript" in body or b"/JS" in body
        # URIs in dictionary (uses balanced-paren reader to tolerate nested parens)
        for um in re.finditer(rb"/URI\s*\(", body):
            parsed = _read_pdf_string(body, um.end() - 1)
            if parsed:
                try:
                    uri_set.add(parsed[0].decode("utf-8", errors="replace"))
                except Exception:
                    pass
        # Inline JS strings: ( ... ) after /JS
        for jm in re.finditer(rb"/JS\s*\(", body):
            parsed = _read_pdf_string(body, jm.end() - 1)
            if parsed:
                try:
                    js_chunks.append(parsed[0].decode("utf-8", errors="replace"))
                except Exception:
                    pass
        # Stream content
        sm = _STREAM_RE.search(body)
        if sm:
            stream_bytes = sm.group(1)
            fm = _FILTER_RE.search(body)
            filt = fm.group(1) if fm else b""
            decoded = _decode_stream(stream_bytes, filt)
            if is_js_obj:
                js_chunks.append(decoded.decode("utf-8", errors="replace"))

    out["javascript"] = [j for j in (s.strip() for s in js_chunks) if j][:20]
    out["uris"] = sorted(uri_set)[:100]

    # IOCs from concatenated JS + URIs
    blob = "\n".join(out["javascript"]) + "\n" + "\n".join(out["uris"])
    out["iocs"] = _extract_iocs(blob)

    # Embedded files via pikepdf when available
    try:
        import pikepdf  # type: ignore
        import io as _io

        with pikepdf.open(_io.BytesIO(data)) as pdf:
            attachments = getattr(pdf, "attachments", {}) or {}
            embedded: list[dict[str, Any]] = []
            for name in list(attachments.keys()):
                try:
                    spec = attachments[name]
                    size = len(bytes(spec.get_file()))
                except Exception:
                    size = 0
                embedded.append({"name": str(name), "size": size})
            out["embedded_files"] = embedded
    except Exception:
        # Best-effort: pikepdf optional
        pass

    # Risk score
    risk = 0
    risk += min(40, 8 * out["indicator_counts"]["/JavaScript"])
    risk += min(20, 10 * out["indicator_counts"]["/Launch"])
    risk += min(20, 6 * out["indicator_counts"]["/OpenAction"])
    risk += min(10, 5 * out["indicator_counts"]["/EmbeddedFile"])
    risk += min(10, 2 * len(out["javascript"]))
    out["risk_score"] = min(100, risk)

    return out
