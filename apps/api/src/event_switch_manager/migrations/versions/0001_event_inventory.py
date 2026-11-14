"""Add event and planned switch inventory."""

import sqlalchemy as sa
from alembic import op

revision = "0001_event_inventory"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("management_vlan", sa.Integer(), nullable=False),
    )
    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("events.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("hostname", sa.String(63, collation="NOCASE"), nullable=False),
        sa.Column("family", sa.String(14), nullable=False),
        sa.Column("role", sa.String(21), nullable=False),
        sa.Column("model", sa.String(80)),
        sa.Column("serial_number", sa.String(64, collation="NOCASE")),
        sa.Column("software_version", sa.String(80)),
        sa.Column("management_ip", sa.String(15)),
        sa.Column("location", sa.String(120)),
        sa.UniqueConstraint("event_id", "hostname", name="uq_device_event_hostname"),
        sa.UniqueConstraint("event_id", "management_ip", name="uq_device_event_management_ip"),
        sa.UniqueConstraint("event_id", "serial_number", name="uq_device_event_serial_number"),
    )


def downgrade() -> None:
    op.drop_table("devices")
    op.drop_table("events")
