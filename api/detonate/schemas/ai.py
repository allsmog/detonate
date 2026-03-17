from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AITaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    submission_id: UUID
    task_type: str
    status: str
    celery_task_id: str | None = None
    input_data: dict[str, Any] | None = None
    output_data: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    model_used: str | None = None
    tokens_used: dict[str, Any] | None = None
    created_at: datetime | None = None


class AISummaryResponse(BaseModel):
    submission_id: UUID
    summary: str | None = None
    generated: bool = False


class AIStatusResponse(BaseModel):
    enabled: bool
    configured: bool = False
    provider: str | None = None
    model: str | None = None
