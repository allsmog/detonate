import uuid

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from detonate.models.base import Base


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    filename: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_hash_md5: Mapped[str | None] = mapped_column(String(32))
    file_hash_sha1: Mapped[str | None] = mapped_column(String(40))
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    file_type: Mapped[str | None] = mapped_column(Text)
    mime_type: Mapped[str | None] = mapped_column(Text)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    submitted_at: Mapped[str | None] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=text("now()"),
    )
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    verdict: Mapped[str] = mapped_column(
        String(20),
        server_default=text("'unknown'"),
        default="unknown",
    )
    score: Mapped[int] = mapped_column(Integer, server_default=text("0"), default=0)

    # Cached AI columns
    ai_summary: Mapped[str | None] = mapped_column(Text)
    ai_verdict: Mapped[str | None] = mapped_column(String(20))
    ai_score: Mapped[int | None] = mapped_column(Integer)
    ai_analyzed_at: Mapped[str | None] = mapped_column(TIMESTAMP(timezone=True))

    threat_intel: Mapped[dict | None] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb")
    )

    analyses = relationship("Analysis", back_populates="submission")
    user = relationship("User", foreign_keys=[user_id])
