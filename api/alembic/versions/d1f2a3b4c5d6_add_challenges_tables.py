"""add challenges and challenge_solves tables

Revision ID: d1f2a3b4c5d6
Revises: c7b4b0983128
Create Date: 2026-06-09

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d1f2a3b4c5d6"
down_revision: str | None = "c7b4b0983128"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "challenges",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("difficulty", sa.Text(), nullable=False),
        sa.Column("points", sa.Integer(), nullable=False),
        sa.Column("flag_hash", sa.Text(), nullable=False),
        sa.Column(
            "hints",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("module_ref", sa.Text(), nullable=True),
        sa.Column("order_index", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenges")),
        sa.UniqueConstraint("slug", name=op.f("uq_challenges_slug")),
    )
    op.create_index(op.f("ix_challenges_slug"), "challenges", ["slug"], unique=True)

    op.create_table(
        "challenge_solves",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("challenge_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("player", sa.Text(), nullable=False),
        sa.Column(
            "solved_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["challenge_id"],
            ["challenges.id"],
            name=op.f("fk_challenge_solves_challenge_id_challenges"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_challenge_solves_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_challenge_solves")),
        sa.UniqueConstraint(
            "challenge_id", "player", name="uq_challenge_solves_challenge_id_player"
        ),
    )
    op.create_index(
        op.f("ix_challenge_solves_challenge_id"),
        "challenge_solves",
        ["challenge_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_challenge_solves_challenge_id"), table_name="challenge_solves")
    op.drop_table("challenge_solves")
    op.drop_index(op.f("ix_challenges_slug"), table_name="challenges")
    op.drop_table("challenges")
