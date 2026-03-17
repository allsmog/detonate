from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class CommentCreateRequest(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Comment content cannot be empty")
        if len(v) > 10000:
            raise ValueError("Comment content cannot exceed 10000 characters")
        return v


class CommentUpdateRequest(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Comment content cannot be empty")
        if len(v) > 10000:
            raise ValueError("Comment content cannot exceed 10000 characters")
        return v


class CommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    submission_id: str
    user_id: str
    user_email: str
    user_display_name: str | None = None
    content: str
    created_at: str | None = None
    updated_at: str | None = None

    @field_validator("id", "submission_id", "user_id", mode="before")
    @classmethod
    def convert_uuid_to_str(cls, v: UUID | str) -> str:
        return str(v)

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def convert_datetime_to_str(cls, v: datetime | str | None) -> str | None:
        if v is None:
            return None
        if isinstance(v, datetime):
            return v.isoformat()
        return str(v)


class CommentListResponse(BaseModel):
    items: list[CommentResponse]
    total: int
