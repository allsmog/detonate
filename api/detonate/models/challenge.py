import uuid

from sqlalchemy import ForeignKey, Integer, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from detonate.models.base import Base


class Challenge(Base):
    """A CTF-style challenge that ties a masterclass lab to a submittable flag.

    The correct flag is never stored in plaintext — only its SHA-256 hash. This
    lets the platform double as an auto-graded training ground: a learner does
    the lab (e.g. unpacks a sample, extracts a config) and submits the value
    they recovered as the flag.
    """

    __tablename__ = "challenges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False, default="misc")
    difficulty: Mapped[str] = mapped_column(Text, nullable=False, default="beginner")
    points: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # SHA-256 hex of the correct (normalized) flag. Never store the plaintext.
    flag_hash: Mapped[str] = mapped_column(Text, nullable=False)
    hints: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    module_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[str | None] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=text("now()"),
    )

    solves = relationship("ChallengeSolve", back_populates="challenge")


class ChallengeSolve(Base):
    """A successful flag submission. Tied to a user when auth is enabled, or to
    an anonymous ``player`` handle otherwise (so the leaderboard still works in
    the default AUTH_ENABLED=false masterclass setup)."""

    __tablename__ = "challenge_solves"
    __table_args__ = (
        UniqueConstraint("challenge_id", "player", name="uq_challenge_solves_challenge_id_player"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    # Anonymous handle used when auth is disabled (defaults to "anonymous").
    player: Mapped[str] = mapped_column(Text, nullable=False, default="anonymous")
    solved_at: Mapped[str | None] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=text("now()"),
    )

    challenge = relationship("Challenge", back_populates="solves")
