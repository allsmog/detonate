"""add machine pool columns

Revision ID: b8c3a1d42e9f
Revises: 01acff0981bf
Create Date: 2026-03-16 20:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b8c3a1d42e9f'
down_revision: Union[str, None] = 'b8e3f2a71c04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add pool management columns to machines table
    op.add_column('machines', sa.Column('container_id', sa.Text(), nullable=True))
    op.add_column('machines', sa.Column(
        'last_health_check',
        postgresql.TIMESTAMP(timezone=True),
        nullable=True,
    ))
    op.add_column('machines', sa.Column(
        'locked_at',
        postgresql.TIMESTAMP(timezone=True),
        nullable=True,
    ))

    # Add an index on (machinery, platform, status) for efficient pool queries
    op.create_index(
        'ix_machines_pool_lookup',
        'machines',
        ['machinery', 'platform', 'status'],
    )


def downgrade() -> None:
    op.drop_index('ix_machines_pool_lookup', table_name='machines')
    op.drop_column('machines', 'locked_at')
    op.drop_column('machines', 'last_health_check')
    op.drop_column('machines', 'container_id')
