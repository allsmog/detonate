"""add celery_task_id to analyses

Revision ID: b8e3f2a71c04
Revises: 01acff0981bf
Create Date: 2026-03-16 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b8e3f2a71c04'
down_revision: Union[str, None] = '01acff0981bf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('analyses', sa.Column('celery_task_id', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('analyses', 'celery_task_id')
