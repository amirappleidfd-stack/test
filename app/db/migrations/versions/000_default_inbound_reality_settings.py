"""Add reality_settings column to system table for the Default Inbound.

Stores the generated Reality keypair + short id so they persist across
restarts / rebuilds (see app/default_inbound.py).

Revision ID: 000_default_inbound_reality_settings
Revises: 2b231de97dc3
Create Date: 2026-07-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "000_default_inbound_reality_settings"
down_revision = "2b231de97dc3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # JSON column is portable across SQLite / PostgreSQL / MySQL with SQLAlchemy.
    op.add_column(
        "system",
        sa.Column("reality_settings", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("system", "reality_settings")
