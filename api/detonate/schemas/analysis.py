from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AnalysisConfigRequest(BaseModel):
    timeout: int = 60
    network: bool = False
    platform: str = "linux"
    screenshots: bool = False
    screenshots_interval: float = 1.0
    vnc: bool = False


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    submission_id: UUID
    type: str
    status: str
    machine_id: UUID | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: int | None = None
    config: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    celery_task_id: str | None = None


class AnalysisListResponse(BaseModel):
    items: list[AnalysisResponse]
    total: int
