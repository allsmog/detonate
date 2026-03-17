from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

VALID_EVENTS = [
    "submission.created",
    "analysis.completed",
    "analysis.failed",
    "webhook.test",
]


class WebhookCreateRequest(BaseModel):
    url: str = Field(..., description="Webhook endpoint URL (must be HTTPS in production)")
    events: list[str] = Field(
        ...,
        min_length=1,
        description=f"Events to subscribe to. Valid: {', '.join(VALID_EVENTS)}",
    )
    secret: str | None = Field(
        default=None,
        max_length=255,
        description="Optional HMAC secret for request signing",
    )


class WebhookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    url: str
    events: list[str]
    is_active: bool
    created_at: datetime | None = None
    last_triggered_at: datetime | None = None
    failure_count: int = 0


class WebhookTestResponse(BaseModel):
    success: bool
    status_code: int | None = None
    error: str | None = None
