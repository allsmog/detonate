import uuid

from sqlalchemy import ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from detonate.models.base import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    submission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("submissions.id"),
        nullable=False,
    )
    type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        server_default=text("'queued'"),
        default="queued",
    )
    machine_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("machines.id"),
    )
    started_at: Mapped[str | None] = mapped_column(TIMESTAMP(timezone=True))
    completed_at: Mapped[str | None] = mapped_column(TIMESTAMP(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    config: Mapped[dict | None] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    result: Mapped[dict | None] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    report_es_id: Mapped[str | None] = mapped_column(Text)
    celery_task_id: Mapped[str | None] = mapped_column(String(255))
    mitre_techniques: Mapped[list | None] = mapped_column(
        JSONB, server_default=text("'[]'::jsonb")
    )

    submission = relationship("Submission", back_populates="analyses")
