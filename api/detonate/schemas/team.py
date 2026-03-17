from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class TeamCreateRequest(BaseModel):
    name: str
    description: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Team name cannot be empty")
        if len(v) > 255:
            raise ValueError("Team name cannot exceed 255 characters")
        return v


class TeamUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None


class TeamMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    email: str
    display_name: str | None = None
    role: str
    joined_at: str | None = None

    @field_validator("id", "user_id", mode="before")
    @classmethod
    def convert_uuid_to_str(cls, v: UUID | str) -> str:
        return str(v)

    @field_validator("joined_at", mode="before")
    @classmethod
    def convert_datetime_to_str(cls, v: datetime | str | None) -> str | None:
        if v is None:
            return None
        if isinstance(v, datetime):
            return v.isoformat()
        return str(v)


class TeamResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None = None
    is_active: bool
    created_at: str | None = None
    member_count: int = 0

    @field_validator("id", mode="before")
    @classmethod
    def convert_uuid_to_str(cls, v: UUID | str) -> str:
        return str(v)

    @field_validator("created_at", mode="before")
    @classmethod
    def convert_datetime_to_str(cls, v: datetime | str | None) -> str | None:
        if v is None:
            return None
        if isinstance(v, datetime):
            return v.isoformat()
        return str(v)


class TeamDetailResponse(TeamResponse):
    members: list[TeamMemberResponse] = []


class AddMemberRequest(BaseModel):
    user_email: str
    role: str = "member"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        allowed = {"owner", "admin", "member"}
        if v not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(sorted(allowed))}")
        return v


class TeamListResponse(BaseModel):
    items: list[TeamResponse]
    total: int
