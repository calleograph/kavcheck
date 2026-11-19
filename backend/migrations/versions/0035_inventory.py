"""Инвентаризация (учёт ИТ-активов): местоположения, справочники, сотрудники учёта, дополнительные свойства, учётные единицы и их история, документы и строки документов,
лицензии и назначения, вложения, сохранённые фильтры.

Revision ID: 0035_inventory
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0035_inventory"
down_revision = "0034_ad_audit"
branch_labels = None
depends_on = None

TABLES = ("inv_views", "inv_files", "inv_lic_assign", "inv_licenses", "inv_doc_items", "inv_docs", "inv_history", "inv_assets", "inv_props", "inv_people", "inv_refs", "inv_locations")


def upgrade() -> None:
    json_t = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    big_pk = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
    op.create_table(
        "inv_locations",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('parent_id', sa.BigInteger(), sa.ForeignKey("inv_locations.id", ondelete="RESTRICT")),
        sa.Column('kind', sa.String(12), nullable=False, server_default="room"),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('code', sa.String(60), nullable=False, server_default=""),
        sa.Column('note', sa.String(1000), nullable=False, server_default=""),
        sa.Column('path', sa.String(1500), nullable=False, server_default=""),
        sa.Column('ids_path', sa.String(400), nullable=False, server_default=""),
        sa.Column('data', json_t, nullable=False, server_default="{}"),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('sort', sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_inv_locations_ids", "inv_locations", ['ids_path'])
    op.create_index("ix_inv_locations_parent", "inv_locations", ['parent_id'])
    op.create_table(
        "inv_refs",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('code', sa.String(60), nullable=False, server_default=""),
        sa.Column('parent_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('data', json_t, nullable=False, server_default="{}"),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('sort', sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_inv_refs_kind", "inv_refs", ['kind', 'name'])
    op.create_table(
        "inv_people",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('login', sa.String(256), nullable=False, server_default=""),
        sa.Column('email', sa.String(320), nullable=False, server_default=""),
        sa.Column('dept', sa.String(300), nullable=False, server_default=""),
        sa.Column('title', sa.String(300), nullable=False, server_default=""),
        sa.Column('phone', sa.String(60), nullable=False, server_default=""),
        sa.Column('source', sa.String(8), nullable=False, server_default="manual"),
        sa.Column('ext_key', sa.String(400), nullable=False, server_default=""),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('note', sa.String(1000), nullable=False, server_default=""),
        sa.Column('search', sa.String(1300), nullable=False, server_default=""),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_inv_people_ext", "inv_people", ['ext_key'])
    op.create_index("ix_inv_people_email", "inv_people", ['email'])
    op.create_table(
        "inv_props",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('code', sa.String(40), unique=True, nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('descr', sa.String(500), nullable=False, server_default=""),
        sa.Column('type', sa.String(12), nullable=False, server_default="text"),
        sa.Column('options', json_t, nullable=False, server_default="[]"),
        sa.Column('default', json_t, nullable=False, server_default="{}"),
        sa.Column('required', sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column('type_ids', json_t, nullable=False, server_default="[]"),
        sa.Column('in_list', sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column('sort', sa.Integer(), nullable=False, server_default="0"),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.create_table(
        "inv_assets",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('uid', sa.Uuid(), unique=True, nullable=False),
        sa.Column('inv_no', sa.String(60), unique=True, nullable=False),
        sa.Column('acc_no', sa.String(60), nullable=False, server_default=""),
        sa.Column('serial', sa.String(120), nullable=False, server_default=""),
        sa.Column('name', sa.String(300), nullable=False, server_default=""),
        sa.Column('hostname', sa.String(255), nullable=False, server_default=""),
        sa.Column('type_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('cls', sa.String(12), nullable=False, server_default="other"),
        sa.Column('model_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('manufacturer_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('status_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('st_cls', sa.String(10), nullable=False, server_default="stock"),
        sa.Column('location_id', sa.BigInteger(), sa.ForeignKey("inv_locations.id", ondelete="RESTRICT")),
        sa.Column('loc_detail', sa.String(300), nullable=False, server_default=""),
        sa.Column('parent_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="SET NULL")),
        sa.Column('rel', sa.String(10), nullable=False, server_default=""),
        sa.Column('user_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('owner_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('resp_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('mol_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('it_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('dept_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('branch_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('purchase_date', sa.Date()),
        sa.Column('received_date', sa.Date()),
        sa.Column('commissioned_date', sa.Date()),
        sa.Column('warranty_until', sa.Date()),
        sa.Column('cost', sa.BigInteger()),
        sa.Column('supplier_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('purchase_doc', sa.String(300), nullable=False, server_default=""),
        sa.Column('props', json_t, nullable=False, server_default="{}"),
        sa.Column('note', sa.Text(), nullable=False, server_default=""),
        sa.Column('ksc_source_id', sa.Uuid()),
        sa.Column('ksc_host_id', sa.BigInteger()),
        sa.Column('ksc_link', sa.String(10), nullable=False, server_default=""),
        sa.Column('ksc_name', sa.String(300), nullable=False, server_default=""),
        sa.Column('linked_at', sa.DateTime(timezone=True)),
        sa.Column('ext_ids', json_t, nullable=False, server_default="{}"),
        sa.Column('transit_doc_id', sa.BigInteger()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('version', sa.Integer(), nullable=False, server_default="1"),
        sa.Column('search', sa.String(3000), nullable=False, server_default=""),
    )
    op.create_index("ux_inv_assets_ksc", "inv_assets", ['ksc_source_id', 'ksc_host_id'], unique=True)
    op.create_index("ix_inv_assets_status", "inv_assets", ['st_cls', 'cls'])
    op.create_index("ix_inv_assets_user", "inv_assets", ['user_id'])
    op.create_index("ix_inv_assets_warranty", "inv_assets", ['warranty_until'])
    op.create_index("ix_inv_assets_host", "inv_assets", ['hostname'])
    op.create_index("ix_inv_assets_loc", "inv_assets", ['location_id'])
    op.create_index("ix_inv_assets_resp", "inv_assets", ['resp_id'])
    op.create_index("ix_inv_assets_serial", "inv_assets", ['serial'])
    op.create_index("ix_inv_assets_owner", "inv_assets", ['owner_id'])
    op.create_index("ix_inv_assets_parent", "inv_assets", ['parent_id'])
    op.create_table(
        "inv_history",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('asset_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('by', sa.String(160), nullable=False, server_default=""),
        sa.Column('kind', sa.String(12), nullable=False),
        sa.Column('title', sa.String(300), nullable=False, server_default=""),
        sa.Column('changes', json_t, nullable=False, server_default="[]"),
        sa.Column('state', json_t, nullable=False, server_default="{}"),
        sa.Column('comment', sa.String(2000), nullable=False, server_default=""),
        sa.Column('basis', sa.String(500), nullable=False, server_default=""),
        sa.Column('doc_id', sa.BigInteger()),
        sa.Column('people', sa.String(300), nullable=False, server_default=""),
    )
    op.create_index("ix_inv_history_at", "inv_history", ['at'])
    op.create_index("ix_inv_history_asset", "inv_history", ['asset_id', 'at'])
    op.create_table(
        "inv_docs",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('no', sa.String(40), unique=True, nullable=False),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('status', sa.String(10), nullable=False, server_default="draft"),
        sa.Column('doc_date', sa.Date(), nullable=False),
        sa.Column('from_location_id', sa.BigInteger(), sa.ForeignKey("inv_locations.id", ondelete="RESTRICT")),
        sa.Column('to_location_id', sa.BigInteger(), sa.ForeignKey("inv_locations.id", ondelete="RESTRICT")),
        sa.Column('from_person_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('to_person_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('resp_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('basis', sa.String(500), nullable=False, server_default=""),
        sa.Column('comment', sa.Text(), nullable=False, server_default=""),
        sa.Column('data', json_t, nullable=False, server_default="{}"),
        sa.Column('history', json_t, nullable=False, server_default="[]"),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(160), nullable=False, server_default=""),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('done_at', sa.DateTime(timezone=True)),
    )
    op.create_index("ix_inv_docs_kind", "inv_docs", ['kind', 'status', 'doc_date'])
    op.create_table(
        "inv_doc_items",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('doc_id', sa.BigInteger(), sa.ForeignKey("inv_docs.id", ondelete="CASCADE"), nullable=False),
        sa.Column('asset_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="RESTRICT"), nullable=False),
        sa.Column('snap', json_t, nullable=False, server_default="{}"),
        sa.Column('condition', sa.String(200), nullable=False, server_default=""),
        sa.Column('note', sa.String(500), nullable=False, server_default=""),
    )
    op.create_index("ix_inv_doc_items_asset", "inv_doc_items", ['asset_id'])
    op.create_index("ux_inv_doc_items", "inv_doc_items", ['doc_id', 'asset_id'], unique=True)
    op.create_table(
        "inv_licenses",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('vendor', sa.String(200), nullable=False, server_default=""),
        sa.Column('version', sa.String(100), nullable=False, server_default=""),
        sa.Column('edition', sa.String(100), nullable=False, server_default=""),
        sa.Column('type_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('category_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('metric', sa.String(10), nullable=False, server_default="device"),
        sa.Column('qty', sa.Integer()),
        sa.Column('match', json_t, nullable=False, server_default="[]"),
        sa.Column('purchase_date', sa.Date()),
        sa.Column('valid_until', sa.Date()),
        sa.Column('supplier_id', sa.BigInteger(), sa.ForeignKey("inv_refs.id", ondelete="RESTRICT")),
        sa.Column('cost', sa.BigInteger()),
        sa.Column('purchase_doc', sa.String(300), nullable=False, server_default=""),
        sa.Column('resp_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="RESTRICT")),
        sa.Column('note', sa.Text(), nullable=False, server_default=""),
        sa.Column('key_enc', sa.Text(), nullable=False, server_default=""),
        sa.Column('usage', json_t, nullable=False, server_default="{}"),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_by', sa.String(160), nullable=False, server_default=""),
    )
    op.create_table(
        "inv_lic_assign",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('license_id', sa.BigInteger(), sa.ForeignKey("inv_licenses.id", ondelete="CASCADE"), nullable=False),
        sa.Column('asset_id', sa.BigInteger(), sa.ForeignKey("inv_assets.id", ondelete="CASCADE")),
        sa.Column('person_id', sa.BigInteger(), sa.ForeignKey("inv_people.id", ondelete="CASCADE")),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('by', sa.String(160), nullable=False, server_default=""),
        sa.Column('note', sa.String(500), nullable=False, server_default=""),
    )
    op.create_index("ix_inv_lic_assign", "inv_lic_assign", ['license_id'])
    op.create_index("ix_inv_lic_assign_asset", "inv_lic_assign", ['asset_id'])
    op.create_table(
        "inv_files",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('owner', sa.String(8), nullable=False),
        sa.Column('owner_id', sa.BigInteger(), nullable=False),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('mime', sa.String(120), nullable=False, server_default="application/octet-stream"),
        sa.Column('size', sa.Integer(), nullable=False, server_default="0"),
        sa.Column('sha256', sa.String(64), nullable=False, server_default=""),
        sa.Column('data', sa.LargeBinary(), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('by', sa.String(160), nullable=False, server_default=""),
    )
    op.create_index("ix_inv_files_owner", "inv_files", ['owner', 'owner_id'])
    op.create_table(
        "inv_views",
        sa.Column('id', big_pk, primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('page', sa.String(20), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('params', json_t, nullable=False, server_default="{}"),
        sa.Column('shared', sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_inv_views_user", "inv_views", ['user_id', 'page'])


def downgrade() -> None:
    for t in TABLES:
        op.drop_table(t)
