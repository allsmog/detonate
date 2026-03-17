"""Routes for managing YARA rule files: CRUD, validation, and metadata."""

import logging
import os
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException

from detonate.config import settings
from detonate.schemas.yara_management import (
    YaraRuleContent,
    YaraRuleFile,
    YaraRuleUploadRequest,
    YaraValidateRequest,
    YaraValidateResponse,
)

logger = logging.getLogger("detonate.api.routes.yara_management")

router = APIRouter(tags=["yara-management"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9_\-]+\.yar$")


def _rules_dir() -> Path:
    """Resolve the YARA rules directory to an absolute path."""
    rules_path = settings.yara_rules_path
    if os.path.isabs(rules_path):
        return Path(rules_path)
    # Relative paths are resolved from the repo root (parent of api/)
    base = Path(__file__).resolve().parent.parent.parent.parent.parent
    return base / rules_path


def _validate_filename(filename: str) -> None:
    """Raise 400 if *filename* is unsafe."""
    if not _SAFE_FILENAME.match(filename):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename. Must match [a-zA-Z0-9_-]+.yar",
        )


def _count_rules(content: str) -> int:
    """Rough count of ``rule <name>`` declarations in *content*."""
    return len(re.findall(r"(?m)^\s*rule\s+\w+", content))


def _compile_yara(source: str) -> str | None:
    """Try to compile *source* and return the error string, or None on success."""
    try:
        import yara  # type: ignore[import-untyped]

        yara.compile(source=source)
        return None
    except Exception as exc:
        return str(exc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/yara/rules", response_model=list[YaraRuleFile])
async def list_yara_rules() -> list[YaraRuleFile]:
    """List all YARA rule files with metadata."""
    if not settings.yara_enabled:
        raise HTTPException(status_code=503, detail="YARA is disabled")

    rules_dir = _rules_dir()
    if not rules_dir.is_dir():
        return []

    files: list[YaraRuleFile] = []
    for entry in sorted(rules_dir.iterdir()):
        if entry.suffix != ".yar" or not entry.is_file():
            continue
        content = entry.read_text(encoding="utf-8", errors="replace")
        stat = entry.stat()
        files.append(
            YaraRuleFile(
                filename=entry.name,
                rule_count=_count_rules(content),
                last_modified=stat.st_mtime,
                size_bytes=stat.st_size,
            )
        )
    return files


@router.get("/yara/rules/{filename}", response_model=YaraRuleContent)
async def get_yara_rule(filename: str) -> YaraRuleContent:
    """Return the full content of a single YARA rule file."""
    if not settings.yara_enabled:
        raise HTTPException(status_code=503, detail="YARA is disabled")

    _validate_filename(filename)
    rule_path = _rules_dir() / filename
    if not rule_path.is_file():
        raise HTTPException(status_code=404, detail="Rule file not found")

    content = rule_path.read_text(encoding="utf-8", errors="replace")
    return YaraRuleContent(filename=filename, content=content)


@router.post("/yara/rules", response_model=YaraRuleFile, status_code=201)
async def upload_yara_rule(body: YaraRuleUploadRequest) -> YaraRuleFile:
    """Upload a new YARA rule file after validating its syntax."""
    if not settings.yara_enabled:
        raise HTTPException(status_code=503, detail="YARA is disabled")

    _validate_filename(body.filename)
    rules_dir = _rules_dir()
    rule_path = rules_dir / body.filename

    if rule_path.exists():
        raise HTTPException(
            status_code=409,
            detail="Rule file already exists. Use PUT to update.",
        )

    # Validate syntax before writing
    error = _compile_yara(body.content)
    if error:
        raise HTTPException(
            status_code=422,
            detail=f"YARA syntax error: {error}",
        )

    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(body.content, encoding="utf-8")

    # Reload cached compiled rules
    _reload_rules_cache()

    stat = rule_path.stat()
    return YaraRuleFile(
        filename=body.filename,
        rule_count=_count_rules(body.content),
        last_modified=stat.st_mtime,
        size_bytes=stat.st_size,
    )


@router.put("/yara/rules/{filename}", response_model=YaraRuleFile)
async def update_yara_rule(
    filename: str,
    body: YaraRuleUploadRequest,
) -> YaraRuleFile:
    """Update an existing YARA rule file after validating syntax."""
    if not settings.yara_enabled:
        raise HTTPException(status_code=503, detail="YARA is disabled")

    _validate_filename(filename)

    # The filename in the path takes precedence
    if body.filename != filename:
        raise HTTPException(
            status_code=400,
            detail="Filename in body must match path parameter",
        )

    rule_path = _rules_dir() / filename
    if not rule_path.is_file():
        raise HTTPException(status_code=404, detail="Rule file not found")

    error = _compile_yara(body.content)
    if error:
        raise HTTPException(
            status_code=422,
            detail=f"YARA syntax error: {error}",
        )

    rule_path.write_text(body.content, encoding="utf-8")
    _reload_rules_cache()

    stat = rule_path.stat()
    return YaraRuleFile(
        filename=filename,
        rule_count=_count_rules(body.content),
        last_modified=stat.st_mtime,
        size_bytes=stat.st_size,
    )


@router.delete("/yara/rules/{filename}", status_code=204)
async def delete_yara_rule(filename: str) -> None:
    """Delete a YARA rule file."""
    if not settings.yara_enabled:
        raise HTTPException(status_code=503, detail="YARA is disabled")

    _validate_filename(filename)

    # Protect the index file from deletion
    if filename == "index.yar":
        raise HTTPException(
            status_code=400,
            detail="Cannot delete the index file",
        )

    rule_path = _rules_dir() / filename
    if not rule_path.is_file():
        raise HTTPException(status_code=404, detail="Rule file not found")

    rule_path.unlink()
    _reload_rules_cache()


@router.post("/yara/rules/validate", response_model=YaraValidateResponse)
async def validate_yara_rule(body: YaraValidateRequest) -> YaraValidateResponse:
    """Validate YARA rule syntax without saving to disk."""
    error = _compile_yara(body.content)
    return YaraValidateResponse(valid=error is None, error=error)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _reload_rules_cache() -> None:
    """Force-reload the cached compiled YARA rules used by YaraScanner."""
    try:
        from detonate.services.yara_scanner import reload_rules

        reload_rules()
    except Exception:
        logger.debug("Failed to reload YARA rules cache", exc_info=True)
