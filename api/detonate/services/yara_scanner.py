"""YARA scanning service for static analysis of submitted samples."""

import logging
import os
from pathlib import Path
from typing import Any

import yara
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_storage
from detonate.config import settings

logger = logging.getLogger("detonate.services.yara_scanner")

_compiled_rules: yara.Rules | None = None


def _get_rules_path() -> str:
    """Resolve the YARA rules directory path."""
    rules_path = settings.yara_rules_path
    if os.path.isabs(rules_path):
        return rules_path
    # Relative paths are resolved from the project root (two levels up from this file)
    base = Path(__file__).resolve().parent.parent.parent.parent
    return str(base / rules_path)


def _compile_rules() -> yara.Rules:
    """Compile YARA rules from the index file."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    rules_dir = _get_rules_path()
    index_path = os.path.join(rules_dir, "index.yar")

    if not os.path.exists(index_path):
        raise FileNotFoundError(f"YARA index file not found: {index_path}")

    logger.info("Compiling YARA rules from %s", index_path)
    _compiled_rules = yara.compile(filepath=index_path)
    return _compiled_rules


def reload_rules() -> None:
    """Force recompilation of YARA rules."""
    global _compiled_rules
    _compiled_rules = None
    _compile_rules()


class YaraScanner:
    """Scans files against compiled YARA rules."""

    def __init__(self, rules_path: str | None = None) -> None:
        """Load compiled YARA rules.

        Args:
            rules_path: Optional override for the YARA rules directory.
                        If None, uses settings.yara_rules_path.
        """
        if rules_path is not None:
            index_path = os.path.join(rules_path, "index.yar")
            if not os.path.exists(index_path):
                raise FileNotFoundError(f"YARA index file not found: {index_path}")
            self._rules = yara.compile(filepath=index_path)
        else:
            self._rules = _compile_rules()

    def _format_match(self, match: yara.Match) -> dict[str, Any]:
        """Convert a yara.Match to a serializable dict."""
        strings_list: list[str] = []
        for string_match in match.strings:
            for instance in string_match.instances:
                offset = instance.offset
                identifier = string_match.identifier
                strings_list.append(f"{identifier} at 0x{offset:x}")

        return {
            "rule": match.rule,
            "tags": list(match.tags) if match.tags else [],
            "meta": dict(match.meta) if match.meta else {},
            "strings": strings_list,
        }

    async def scan_bytes(self, data: bytes, filename: str = "") -> list[dict[str, Any]]:
        """Scan raw bytes with YARA rules.

        Args:
            data: File content as bytes.
            filename: Optional filename for context.

        Returns:
            List of match dicts with rule, tags, meta, and strings.
        """
        if not settings.yara_enabled:
            return []

        try:
            matches = self._rules.match(data=data)
            return [self._format_match(m) for m in matches]
        except yara.Error as exc:
            logger.error("YARA scan error for %s: %s", filename or "<bytes>", exc)
            return []

    async def scan_submission(self, db: AsyncSession, submission: Any) -> dict[str, Any]:
        """Download sample from MinIO and scan with YARA.

        Args:
            db: Database session (unused but kept for consistency).
            submission: Submission model instance.

        Returns:
            Dict with matches list and metadata.
        """
        if not settings.yara_enabled:
            return {"matches": [], "enabled": False}

        try:
            storage = get_storage()
            sample_data = storage.get_file(submission.storage_path)
        except Exception as exc:
            logger.error("Failed to download sample for YARA scan: %s", exc)
            return {"matches": [], "error": str(exc)}

        matches = await self.scan_bytes(
            sample_data, submission.filename or "sample"
        )

        return {
            "matches": matches,
            "total_matches": len(matches),
            "filename": submission.filename,
            "file_hash": submission.file_hash_sha256,
        }
