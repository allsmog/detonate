from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class RegisterRequest(BaseModel):
    email: str
    password: str
    display_name: str | None = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address")
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str | None = None
    role: str
    is_active: bool
    created_at: str | None = None

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


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class APIKeyCreateRequest(BaseModel):
    name: str | None = None


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    key_prefix: str
    name: str | None = None
    is_active: bool
    created_at: str | None = None

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


class APIKeyCreateResponse(BaseModel):
    key: str
    api_key: APIKeyResponse
