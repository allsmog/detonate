"""Similarity hashing and clustering helpers.

Computes the standard family-clustering hashes used in malware triage:

- **imphash**: PE import-table hash (via pefile when available)
- **rich_pe_hash**: SHA-256 of the cleaned PE Rich header bytes
- **ssdeep**: context-triggered piecewise hash (CTPH)
- **tlsh**: Trend Micro locality-sensitive hash (>50 byte input)
- **vhash**-style behavior hash from a static-analysis result

All hashing back-ends are best-effort: missing native libraries return
``None`` rather than raising, so the API stays usable in slim deploys.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger("detonate.services.similarity")


def imphash(data: bytes) -> str | None:
    try:
        import pefile  # type: ignore
    except Exception:
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ])
        h = pe.get_imphash()
        pe.close()
        return h or None
    except Exception:
        return None


def rich_pe_hash(data: bytes) -> str | None:
    try:
        import pefile  # type: ignore
    except Exception:
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        rich = getattr(pe, "RICH_HEADER", None)
        pe.close()
        if not rich:
            return None
        clear_data = getattr(rich, "clear_data", b"") or b""
        if not clear_data:
            return None
        return hashlib.sha256(clear_data).hexdigest()
    except Exception:
        return None


def ssdeep_hash(data: bytes) -> str | None:
    try:
        import ssdeep  # type: ignore
    except Exception:
        return None
    try:
        return ssdeep.hash(data)
    except Exception:
        return None


def tlsh_hash(data: bytes) -> str | None:
    """Returns ``None`` when input is < 50 bytes (TLSH lower bound)."""
    if len(data) < 50:
        return None
    try:
        import tlsh  # type: ignore
    except Exception:
        return None
    try:
        h = tlsh.hash(data)
        return h if h and h != "TNULL" else None
    except Exception:
        return None


def behavior_vhash(static_result: dict[str, Any]) -> str:
    """Deterministic behavior hash from a static analysis dict.

    Combines: PE imports (DLL list), section names+sizes, YARA rule
    names, and (if present) script/macro high-risk tokens. Designed to
    cluster *variants of the same family* even when the binary changes.
    """
    h = hashlib.sha256()
    pe = static_result.get("pe") or {}
    for dll in sorted((pe.get("imports") or {}).keys()):
        h.update(b"|dll|" + dll.lower().encode("utf-8", errors="replace"))
    for sect in pe.get("sections") or []:
        h.update(b"|sect|" + str(sect.get("name", "")).encode("utf-8") + b"/" + str(sect.get("raw_size", 0)).encode("ascii"))
    for rule in sorted(static_result.get("yara_matches", []) or []):
        h.update(b"|yara|" + str(rule).encode("utf-8"))
    for tok in sorted((static_result.get("script") or {}).get("high_risk_tokens") or []):
        h.update(b"|tok|" + tok.encode("utf-8"))
    for tok in sorted((static_result.get("office") or {}).get("auto_exec_triggers") or []):
        h.update(b"|auto|" + tok.encode("utf-8"))
    return h.hexdigest()


def compute_similarity_hashes(data: bytes, static_result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute all available similarity hashes for one sample."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "imphash": imphash(data),
        "rich_pe_hash": rich_pe_hash(data),
        "ssdeep": ssdeep_hash(data),
        "tlsh": tlsh_hash(data),
        "behavior_vhash": behavior_vhash(static_result or {}) if static_result else None,
    }


def ssdeep_compare(a: str, b: str) -> int | None:
    try:
        import ssdeep  # type: ignore
        return int(ssdeep.compare(a, b))
    except Exception:
        return None


def tlsh_distance(a: str, b: str) -> int | None:
    try:
        import tlsh  # type: ignore
        return int(tlsh.diff(a, b))
    except Exception:
        return None
