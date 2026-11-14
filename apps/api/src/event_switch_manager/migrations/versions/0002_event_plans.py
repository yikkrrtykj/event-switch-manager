"""Add append-only event plan revisions and stable identities."""

import sqlalchemy as sa
from alembic import op

revision = "0002_event_plans"
down_revision = "0001_event_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "physical_assets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("vendor", sa.String(24), nullable=False),
        sa.Column("verified_serial", sa.String(64, collation="NOCASE"), nullable=False),
        sa.UniqueConstraint("vendor", "verified_serial", name="uq_asset_identity"),
    )
    op.create_table(
        "assignment_identities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("events.id", ondelete="RESTRICT"), nullable=False
        ),
    )
    op.create_index("ix_assignment_identities_event_id", "assignment_identities", ["event_id"])
    op.execute("INSERT INTO assignment_identities (id, event_id) SELECT id, event_id FROM devices")
    op.create_table(
        "event_plan_revisions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "event_id", sa.Uuid(), sa.ForeignKey("events.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("canonical_json", sa.Text(), nullable=False),
        sa.UniqueConstraint("event_id", "number", name="uq_plan_revision_number"),
        sa.UniqueConstraint("event_id", "content_hash", name="uq_plan_revision_hash"),
        sa.CheckConstraint("number > 0", name="ck_plan_revision_number"),
    )
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"CREATE TRIGGER event_plan_revisions_no_{operation.lower()} "
            f"BEFORE {operation} ON event_plan_revisions "
            "BEGIN SELECT RAISE(ABORT, 'Plan revisions are immutable'); END"
        )


def downgrade() -> None:
    op.drop_table("event_plan_revisions")
    op.drop_index("ix_assignment_identities_event_id", table_name="assignment_identities")
    op.drop_table("assignment_identities")
    op.drop_table("physical_assets")
