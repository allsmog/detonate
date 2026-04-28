"""Archive analyzer: recurse into ZIP/TAR/7z/RAR, optionally with passwords.

Returns a flat list of contained entries (path, size, sha256, type) and
re-runs static analysis on individual entries when small enough.
Recursion depth and password list are bounded by config.
"""

from __future__ import annotations

import hashlib
import io
import logging
import tarfile
import zipfile
from typing import Any, Iterable

logger = logging.getLogger("detonate.services.archive_analyzer")


_ARCHIVE_EXTS = (".zip", ".jar", ".apk", ".tar", ".tar.gz", ".tgz", ".tar.bz2",
                 ".tbz2", ".7z", ".rar")
_ARCHIVE_MIMES = {
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-tar",
    "application/gzip",
    "application/x-bzip2",
    "application/java-archive",
}


def is_archive(filename: str | None, mime: str | None, data: bytes | None = None) -> bool:
    if mime and mime in _ARCHIVE_MIMES:
        return True
    if filename:
        lower = filename.lower()
        if any(lower.endswith(ext) for ext in _ARCHIVE_EXTS):
            return True
    if data:
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            return True
        if data.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):  # 7z
            return True
        if data.startswith(b"Rar!\x1a\x07"):
            return True
        if len(data) > 262 and data[257:262] == b"ustar":
            return True
        if data[:2] == b"\x1f\x8b":  # gzip
            return True
    return False


def _entry_record(path: str, payload: bytes) -> dict[str, Any]:
    rec = {
        "path": path,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
        "magic": payload[:8].hex(),
    }
    if payload.startswith(b"MZ"):
        rec["type"] = "pe"
    elif payload.startswith(b"\x7fELF"):
        rec["type"] = "elf"
    elif payload.startswith(b"%PDF-"):
        rec["type"] = "pdf"
    elif payload.startswith(b"PK\x03\x04"):
        rec["type"] = "zip-or-ooxml"
    elif payload.startswith(b"\xd0\xcf\x11\xe0"):
        rec["type"] = "ole2"
    else:
        rec["type"] = "data"
    return rec


def _try_passwords(zf: zipfile.ZipFile, name: str, passwords: Iterable[str]) -> bytes | None:
    for pw in passwords:
        try:
            return zf.read(name, pwd=pw.encode("utf-8") if pw else None)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
            continue
        except Exception:
            continue
    return None


def _walk_zip(data: bytes, passwords: list[str], max_entries: int) -> tuple[list[dict[str, Any]], bool]:
    entries: list[dict[str, Any]] = []
    encrypted_any = False
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        return [{"error": f"zip open failed: {exc}"}], False

    try:
        for info in zf.infolist():
            if len(entries) >= max_entries:
                break
            if info.is_dir():
                continue
            payload: bytes | None = None
            if info.flag_bits & 0x1:
                encrypted_any = True
                payload = _try_passwords(zf, info.filename, passwords)
            else:
                try:
                    payload = zf.read(info.filename)
                except Exception:
                    payload = None
            rec = _entry_record(info.filename, payload or b"")
            rec["compressed_size"] = info.compress_size
            rec["encrypted"] = bool(info.flag_bits & 0x1)
            rec["recovered"] = payload is not None
            entries.append(rec)
    finally:
        zf.close()
    return entries, encrypted_any


def _walk_tar(data: bytes, max_entries: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception as exc:
        return [{"error": f"tar open failed: {exc}"}]
    try:
        for member in tf.getmembers():
            if len(entries) >= max_entries:
                break
            if not member.isfile():
                continue
            try:
                f = tf.extractfile(member)
                payload = f.read() if f else b""
            except Exception:
                payload = b""
            rec = _entry_record(member.name, payload)
            rec["recovered"] = bool(payload)
            entries.append(rec)
    finally:
        tf.close()
    return entries


def _walk_7z(data: bytes, passwords: list[str], max_entries: int) -> tuple[list[dict[str, Any]], bool]:
    try:
        import py7zr  # type: ignore
    except Exception:
        return [{"error": "py7zr not installed"}], False
    encrypted_any = False
    for pw in [None, *passwords]:
        try:
            zf = py7zr.SevenZipFile(io.BytesIO(data), password=pw)
            break
        except py7zr.exceptions.PasswordRequired:
            encrypted_any = True
            continue
        except Exception:
            continue
    else:
        return [{"error": "7z open failed (password required?)"}], True

    entries: list[dict[str, Any]] = []
    try:
        for name, payload in (zf.readall() or {}).items():
            if len(entries) >= max_entries:
                break
            buf = payload.read() if hasattr(payload, "read") else b""
            entries.append(_entry_record(name, buf))
    finally:
        try:
            zf.close()
        except Exception:
            pass
    return entries, encrypted_any


def analyze_archive(
    data: bytes,
    filename: str = "archive",
    passwords: list[str] | None = None,
    max_entries: int = 500,
) -> dict[str, Any]:
    pwlist = list(passwords or [])
    out: dict[str, Any] = {
        "filename": filename,
        "format": "unknown",
        "entries": [],
        "entry_count": 0,
        "encrypted": False,
        "passwords_tried": pwlist,
        "warnings": [],
    }

    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        out["format"] = "zip"
        entries, enc = _walk_zip(data, pwlist, max_entries)
        out["entries"] = entries
        out["encrypted"] = enc
    elif data[:6] == b"\x37\x7a\xbc\xaf\x27\x1c":
        out["format"] = "7z"
        entries, enc = _walk_7z(data, pwlist, max_entries)
        out["entries"] = entries
        out["encrypted"] = enc
    elif data.startswith(b"Rar!\x1a\x07"):
        out["format"] = "rar"
        try:
            import rarfile  # type: ignore
            rf = rarfile.RarFile(io.BytesIO(data))
            for info in rf.infolist()[:max_entries]:
                payload = b""
                try:
                    payload = rf.read(info.filename)
                except Exception:
                    pass
                out["entries"].append(_entry_record(info.filename, payload))
            out["encrypted"] = any(getattr(i, "needs_password", False) for i in rf.infolist())
        except Exception as exc:
            out["warnings"].append(f"rar open failed: {exc}")
    elif data[:2] == b"\x1f\x8b" or (len(data) > 262 and data[257:262] == b"ustar"):
        out["format"] = "tar"
        out["entries"] = _walk_tar(data, max_entries)
    else:
        out["warnings"].append("Unrecognized archive header")

    out["entry_count"] = len(out["entries"])

    # Quick risk hint: any executables inside?
    exec_count = sum(1 for e in out["entries"] if e.get("type") in ("pe", "elf"))
    macro_capable = sum(
        1 for e in out["entries"]
        if e.get("path", "").lower().endswith((".docm", ".xlsm", ".pptm", ".doc", ".xls"))
    )
    risk = 0
    risk += min(40, 10 * exec_count)
    risk += min(20, 10 * macro_capable)
    if out["encrypted"]:
        risk += 20
    out["risk_score"] = min(100, risk)
    return out
