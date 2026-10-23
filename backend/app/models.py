"""ORM-модели внутренней базы KAV Checker. Схема меняется ТОЛЬКО через Alembic (backend/migrations). Базы KSC здесь не описываются."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

JSONType = JSON().with_variant(JSONB(), "postgresql")
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")

ROLES = ("admin", "analyst", "viewer")


class UTCDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime запрещён: используйте timezone-aware UTC")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)       # логин в нижнем регистре
    display_name: Mapped[str] = mapped_column(String(300), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    auth_source: Mapped[str] = mapped_column(String(8), default="local", server_default="local", nullable=False)   # local | ldap
    ldap_guid: Mapped[str | None] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str | None] = mapped_column(Text)                                 # только local
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default="viewer", server_default="viewer", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    all_sources: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)   # доступ ко всем источникам KSC
    source_ids: Mapped[list | None] = mapped_column(JSONType)                               # явный список источников, если all_sources = false
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class Session(Base):
    """Серверные сессии: в cookie — только случайный идентификатор, в базе — его sha256."""
    __tablename__ = "sessions"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    csrf: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    current_source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)   # выбранный источник KSC


class LoginFailure(Base):
    """Счётчик неудачных входов по логину (защита от перебора; ключ — sha256 логина)."""
    __tablename__ = "login_failures"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AppSetting(Base):
    """Группы настроек приложения (JSON); секреты внутри зашифрованы SecretBox."""
    __tablename__ = "app_settings"
    group: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(300))


class KscSource(Base):
    """Подключение к базе одного Сервера администрирования KSC (только чтение)."""
    __tablename__ = "ksc_sources"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=1433, nullable=False)
    database: Mapped[str] = mapped_column(String(128), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(16), default="sql", server_default="sql", nullable=False)   # sql | windows (DOMAIN\user через NTLM)
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    password_enc: Mapped[str | None] = mapped_column(Text)
    tls_mode: Mapped[str] = mapped_column(String(16), default="require", server_default="require", nullable=False)  # require | request | off
    trust_server_cert: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    connect_timeout_s: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    query_timeout_s: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_check_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_check_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_check: Mapped[dict | None] = mapped_column(JSONType)       # результат диагностики: версия SQL Server, версия KSC, доступные объекты
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class GroupingRule(Base):
    """Правило логической группировки программ по продукту и версии (встроенное PHP + пользовательские)."""
    __tablename__ = "grouping_rules"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)      # php, …
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    name_like: Mapped[str] = mapped_column(String(200), nullable=False)             # SQL LIKE для первичного отбора: %php%
    name_regex: Mapped[str] = mapped_column(Text, nullable=False)                   # точный отбор пакетов продукта (регистр не важен)
    branch_regex: Mapped[str | None] = mapped_column(Text)                          # ветка из имени пакета (группа 1 — major.minor; группы 2,3 — major, minor)
    branch_parts: Mapped[int] = mapped_column(Integer, default=2, nullable=False)   # сколько частей версии образуют ветку (2 → 7.4)
    exclude_regex: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class AuditCheck(Base):
    """Сохранённый сценарий аудита: пользовательский критерий «эти версии потенциально уязвимы»."""
    __tablename__ = "audit_checks"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    selection: Mapped[dict] = mapped_column(JSONType, nullable=False)     # {"product_ids":[…]} | {"rule":"php","branches":[…]} | {"name_like":…,"min_version":…}
    cve: Mapped[str | None] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16), default="medium", server_default="medium", nullable=False)   # low | medium | high | critical
    description: Mapped[str | None] = mapped_column(Text)
    comment: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class ReportTemplate(Base):
    __tablename__ = "report_templates"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    params: Mapped[dict] = mapped_column(JSONType, nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    shared: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class ReportJob(Base):
    """Фоновое формирование отчёта. Результат — файлы в DATA_DIR/reports/<id>/ (rows.jsonl, report.xlsx, report.csv)."""
    __tablename__ = "report_jobs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    params: Mapped[dict] = mapped_column(JSONType, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="queued", server_default="queued", nullable=False, index=True)  # queued|running|done|failed|cancelled
    progress: Mapped[str | None] = mapped_column(String(300))
    created_by: Mapped[str | None] = mapped_column(String(300))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    data_fetched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    rows: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[dict | None] = mapped_column(JSONType)
    error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    worker: Mapped[str | None] = mapped_column(String(120))


class AuditLog(Base):
    """Журнал действий пользователей (не технический лог)."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor: Mapped[str] = mapped_column(String(300), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_id: Mapped[str] = mapped_column(String(200), nullable=False)
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    details: Mapped[dict | None] = mapped_column(JSONType)
    result: Mapped[str] = mapped_column(String(16), default="success", server_default="success", nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    request_id: Mapped[str | None] = mapped_column(String(64))


class EventLog(Base):
    """Журнал событий: ошибки, подключения к SQL Server, формирование отчётов, входы."""
    __tablename__ = "event_log"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(8), nullable=False, index=True)        # debug|info|warn|error
    category: Mapped[str] = mapped_column(String(24), nullable=False, index=True)    # auth|ksc|report|admin|system
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    user: Mapped[str | None] = mapped_column(String(256))
    source: Mapped[str | None] = mapped_column(String(120))
    message: Mapped[str | None] = mapped_column(String(600))
    data: Mapped[dict | None] = mapped_column(JSONType)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    ip: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))


class KscCache(Base):
    """Кэш справочников по источнику (группы, сводка главной страницы): срок актуальности — cache_ttl_seconds."""
    __tablename__ = "ksc_cache"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONType, nullable=False)


Index("ix_event_log_user", EventLog.user)
