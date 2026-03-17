from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class MachineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    machinery: str
    platform: str
    status: str
    ip_address: str | None = None
    snapshot: str | None = None
    config: dict[str, Any] | None = None
    container_id: str | None = None
    last_health_check: datetime | None = None
    locked_at: datetime | None = None


class MachineListResponse(BaseModel):
    items: list[MachineResponse]
    total: int


class PoolScaleRequest(BaseModel):
    size: int = Field(..., ge=0, le=50, description="Target pool size (0-50)")


class PoolStatusResponse(BaseModel):
    total: int
    available: int
    busy: int
    error: int = 0
    platform: str
    pool_enabled: bool
