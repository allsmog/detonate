"""Pydantic schemas for the YARA rule management endpoints."""

from pydantic import BaseModel, Field


class YaraRuleFile(BaseModel):
    """Metadata about a single YARA rule file on disk."""

    filename: str
    rule_count: int = 0
    last_modified: float = 0.0
    size_bytes: int = 0


class YaraRuleContent(BaseModel):
    """Full content of a YARA rule file."""

    filename: str
    content: str


class YaraRuleUploadRequest(BaseModel):
    """Request body for creating or updating a YARA rule file."""

    filename: str = Field(..., pattern=r"^[a-zA-Z0-9_\-]+\.yar$")
    content: str


class YaraValidateRequest(BaseModel):
    """Request body for validating YARA rule syntax."""

    content: str


class YaraValidateResponse(BaseModel):
    """Result of YARA syntax validation."""

    valid: bool
    error: str | None = None
