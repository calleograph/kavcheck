"""BI-выгрузки: источники (Excel через SMB), история импортов, нормализованные записи, сотрудники, устройства, история принадлежности и сопоставление с KSC.

Revision ID: 0021_bi
Revises: 0020_hunt
Create Date: 2026-10-29
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0021_bi"
down_revision = "0020_hunt"
branch_labels = None
depends_on = None

TABLES = ("bi_matches", "bi_records", "bi_owners", "bi_devices", "bi_persons", "bi_imports", "bi_sources")


def upgrade() -> None:
    js = sa.JSON().with_variant(JSONB(), "postgresql")
    dt = sa.DateTime(timezone=True)
    big = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
    op.create_table('bi_sources',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('smb_host', sa.String(length=253), nullable=False),
    sa.Column('smb_port', sa.Integer(), nullable=False),
    sa.Column('smb_share', sa.String(length=120), nullable=False),
    sa.Column('smb_path', sa.String(length=500), nullable=False),
    sa.Column('username', sa.String(length=256), nullable=False),
    sa.Column('password_enc', sa.Text(), nullable=True),
    sa.Column('smb_encrypt', sa.Boolean(), nullable=False),
    sa.Column('file_mode', sa.String(length=8), nullable=False),
    sa.Column('file_name', sa.String(length=255), nullable=False),
    sa.Column('schedule_time', sa.String(length=5), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=False),
    sa.Column('profile', js, nullable=False),
    sa.Column('options', js, nullable=False),
    sa.Column('created_at', dt, nullable=False),
    sa.Column('next_run_at', dt, nullable=True),
    sa.Column('request', js, nullable=True),
    sa.Column('last_try_at', dt, nullable=True),
    sa.Column('last_ok_at', dt, nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('last_import_id', sa.Uuid(), nullable=True),
    sa.Column('fail_n', sa.Integer(), nullable=False),
    sa.Column('match_stamp', sa.String(length=600), nullable=False),
    sa.Column('matched_at', dt, nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('bi_devices',
    sa.Column('id', big, autoincrement=True, nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('dkey', sa.String(length=700), nullable=False),
    sa.Column('name', sa.String(length=300), nullable=False),
    sa.Column('short', sa.String(length=300), nullable=False),
    sa.Column('names', js, nullable=False),
    sa.Column('generic', sa.Boolean(), nullable=False),
    sa.Column('os', sa.String(length=200), nullable=False),
    sa.Column('os_family', sa.String(length=8), nullable=False),
    sa.Column('personal', sa.Boolean(), nullable=True),
    sa.Column('av', js, nullable=False),
    sa.Column('owners_now', sa.Integer(), nullable=False),
    sa.Column('first_seen_at', dt, nullable=False),
    sa.Column('last_seen_at', dt, nullable=False),
    sa.Column('last_import_id', sa.Uuid(), nullable=True),
    sa.Column('present', sa.Boolean(), nullable=False),
    sa.Column('search', sa.String(length=1500), nullable=False),
    sa.ForeignKeyConstraint(['source_id'], ['bi_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_bi_devices_short', 'bi_devices', ['source_id', 'short'], unique=False)
    op.create_index('ux_bi_devices_key', 'bi_devices', ['source_id', 'dkey'], unique=True)
    op.create_table('bi_imports',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('started_at', dt, nullable=False),
    sa.Column('finished_at', dt, nullable=True),
    sa.Column('trigger', sa.String(length=10), nullable=False),
    sa.Column('by', sa.String(length=300), nullable=False),
    sa.Column('file_name', sa.String(length=255), nullable=False),
    sa.Column('file_size', sa.BigInteger(), nullable=True),
    sa.Column('file_mtime', dt, nullable=True),
    sa.Column('snapshot_at', dt, nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('rows_read', sa.Integer(), nullable=False),
    sa.Column('rows_valid', sa.Integer(), nullable=False),
    sa.Column('rows_new', sa.Integer(), nullable=False),
    sa.Column('rows_changed', sa.Integer(), nullable=False),
    sa.Column('rows_same', sa.Integer(), nullable=False),
    sa.Column('rows_rejected', sa.Integer(), nullable=False),
    sa.Column('rows_gone', sa.Integer(), nullable=False),
    sa.Column('rows_empty', sa.Integer(), nullable=False),
    sa.Column('devices_n', sa.Integer(), nullable=False),
    sa.Column('persons_n', sa.Integer(), nullable=False),
    sa.Column('headers', js, nullable=False),
    sa.Column('errors', js, nullable=False),
    sa.Column('warnings', js, nullable=False),
    sa.Column('ms', sa.Integer(), nullable=True),
    sa.Column('stored', sa.String(length=300), nullable=False),
    sa.ForeignKeyConstraint(['source_id'], ['bi_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_bi_imports_src', 'bi_imports', ['source_id', 'started_at'], unique=False)
    op.create_table('bi_persons',
    sa.Column('id', big, autoincrement=True, nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('pkey', sa.String(length=330), nullable=False),
    sa.Column('full_name', sa.String(length=300), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('department', sa.String(length=300), nullable=False),
    sa.Column('account_created', dt, nullable=True),
    sa.Column('first_seen_at', dt, nullable=False),
    sa.Column('last_seen_at', dt, nullable=False),
    sa.Column('last_import_id', sa.Uuid(), nullable=True),
    sa.Column('present', sa.Boolean(), nullable=False),
    sa.Column('search', sa.String(length=1000), nullable=False),
    sa.ForeignKeyConstraint(['source_id'], ['bi_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ux_bi_persons_key', 'bi_persons', ['source_id', 'pkey'], unique=True)
    op.create_table('bi_records',
    sa.Column('id', big, autoincrement=True, nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('rkey', sa.String(length=40), nullable=False),
    sa.Column('rhash', sa.String(length=40), nullable=False),
    sa.Column('device_id', sa.BigInteger(), nullable=False),
    sa.Column('person_id', sa.BigInteger(), nullable=True),
    sa.Column('first_import_id', sa.Uuid(), nullable=False),
    sa.Column('last_import_id', sa.Uuid(), nullable=False),
    sa.Column('first_seen_at', dt, nullable=False),
    sa.Column('last_seen_at', dt, nullable=False),
    sa.Column('row_n', sa.Integer(), nullable=False),
    sa.Column('attrs', js, nullable=False),
    sa.Column('flags', js, nullable=False),
    sa.ForeignKeyConstraint(['source_id'], ['bi_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_bi_records_dev', 'bi_records', ['device_id'], unique=False)
    op.create_index('ix_bi_records_key', 'bi_records', ['source_id', 'rkey', 'last_import_id'], unique=False)
    op.create_table('bi_matches',
    sa.Column('id', big, autoincrement=True, nullable=False),
    sa.Column('device_id', sa.BigInteger(), nullable=False),
    sa.Column('bi_source_id', sa.Uuid(), nullable=False),
    sa.Column('ksc_source_id', sa.Uuid(), nullable=False),
    sa.Column('host_id', sa.BigInteger(), nullable=False),
    sa.Column('host_name', sa.String(length=300), nullable=False),
    sa.Column('level', sa.String(length=10), nullable=False),
    sa.Column('signals', js, nullable=False),
    sa.Column('issues', js, nullable=False),
    sa.Column('decided_by', sa.String(length=300), nullable=False),
    sa.Column('decided_at', dt, nullable=True),
    sa.Column('note', sa.String(length=500), nullable=False),
    sa.Column('updated_at', dt, nullable=False),
    sa.ForeignKeyConstraint(['bi_source_id'], ['bi_sources.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['device_id'], ['bi_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['ksc_source_id'], ['ksc_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_bi_matches_host', 'bi_matches', ['ksc_source_id', 'host_id'], unique=False)
    op.create_index('ix_bi_matches_src', 'bi_matches', ['bi_source_id', 'level'], unique=False)
    op.create_index('ux_bi_matches_pair', 'bi_matches', ['device_id', 'ksc_source_id', 'host_id'], unique=True)
    op.create_table('bi_owners',
    sa.Column('id', big, autoincrement=True, nullable=False),
    sa.Column('source_id', sa.Uuid(), nullable=False),
    sa.Column('device_id', sa.BigInteger(), nullable=False),
    sa.Column('person_id', sa.BigInteger(), nullable=False),
    sa.Column('first_seen_at', dt, nullable=False),
    sa.Column('last_seen_at', dt, nullable=False),
    sa.Column('first_import_id', sa.Uuid(), nullable=True),
    sa.Column('last_import_id', sa.Uuid(), nullable=True),
    sa.Column('present', sa.Boolean(), nullable=False),
    sa.Column('seen_n', sa.Integer(), nullable=False),
    sa.Column('src_seen_at', dt, nullable=True),
    sa.Column('owned_from', dt, nullable=True),
    sa.Column('owned_to', dt, nullable=True),
    sa.Column('confidence', sa.String(length=8), nullable=False),
    sa.Column('basis', sa.String(length=200), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['bi_devices.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['person_id'], ['bi_persons.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['source_id'], ['bi_sources.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_bi_owners_person', 'bi_owners', ['person_id'], unique=False)
    op.create_index('ix_bi_owners_src', 'bi_owners', ['source_id', 'present'], unique=False)
    op.create_index('ux_bi_owners_pair', 'bi_owners', ['device_id', 'person_id'], unique=True)

    if op.get_bind().dialect.name == "postgresql" and op.get_bind().execute(sa.text("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'")).scalar():
        op.execute("CREATE INDEX IF NOT EXISTS ix_bi_persons_search_trgm ON bi_persons USING gin (search gin_trgm_ops)")      # поиск по ФИО, почте и подразделению
        op.execute("CREATE INDEX IF NOT EXISTS ix_bi_devices_search_trgm ON bi_devices USING gin (search gin_trgm_ops)")      # поиск по текущему и прежним именам


def downgrade() -> None:
    for t in TABLES:
        op.drop_table(t)
