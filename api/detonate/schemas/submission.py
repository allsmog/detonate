from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class SubmissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    filename: str | None = None
    url: str | None = None
    file_hash_sha256: str
    file_hash_md5: str | None = None
    file_hash_sha1: str | None = None
    file_size: int | None = None
    file_type: str | None = None
    mime_type: str | None = None
    storage_path: str
    submitted_at: datetime | None = None
    tags: list[str] | None = None
    verdict: str = "unknown"
    score: int = 0
    ai_summary: str | None = None
    ai_verdict: str | None = None
    ai_score: int | None = None
    ai_analyzed_at: datetime | None = None


class SubmissionListResponse(BaseModel):
    items: list[SubmissionResponse]
    total: int
    limit: int
    offset: int
