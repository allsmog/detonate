import uuid

from sqlalchemy import String, Text, text
from sqlalchemy.dialects.postgresql import INET, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from detonate.models.base import Base


class Machine(Base):
    __tablename__ = "machines"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    machinery: Mapped[str] = mapped_column(String(20), nullable=False)
    platform: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        server_default=text("'available'"),
        default="available",
    )
    ip_address: Mapped[str | None] = mapped_column(INET)
    snapshot: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict | None] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))

    # Pool management columns
    container_id: Mapped[str | None] = mapped_column(Text)
    last_health_check: Mapped[str | None] = mapped_column(TIMESTAMP(timezone=True))
    locked_at: Mapped[str | None] = mapped_column(TIMESTAMP(timezone=True))
