"""ORM-модели внутренней базы KAV Checker. Схема меняется ТОЛЬКО через Alembic (backend/migrations). Базы KSC здесь не описываются."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid, text
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
    current_source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)   # последний выбранный источник KSC (свой у каждого пользователя)
    ldap_connection_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # подключение каталога, через которое вошёл доменный пользователь
    ldap_groups: Mapped[list | None] = mapped_column(JSONType)          # группы каталога при последнем входе (для правил доступа и политики 2FA)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)            # секрет TOTP, зашифрован APP_MASTER_KEY (AAD — пользователь)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)       # последний принятый шаг: повтор перехваченного кода отклоняется
    totp_enabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


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
    must_totp: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)   # политика требует 2FA, а она не настроена
    second_factor: Mapped[str | None] = mapped_column(String(16))       # totp | backup_code — чем подтверждён вход


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
    """Сохранённая проверка версий: программы, условия версий, целевые версии и источники — запускается повторно одним действием.
    kind = version_audit (0.2.0+, params — параметры проверки, source_ids — источники); legacy — сценарий 0.1.0 (selection на одном источнике)."""
    __tablename__ = "audit_checks"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="version_audit", server_default="legacy", nullable=False)
    params: Mapped[dict | None] = mapped_column(JSONType)
    source_ids: Mapped[list | None] = mapped_column(JSONType)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    shared: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_job_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    selection: Mapped[dict | None] = mapped_column(JSONType)     # legacy: {"product_ids":[…]} | {"rule":"php","branches":[…]} | {"name_like":…,"min_version":…}
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
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="SET NULL"), index=True)   # первый источник (совместимость)
    source_ids: Mapped[list | None] = mapped_column(JSONType)          # все источники отчёта (version_audit — несколько)
    source_name: Mapped[str] = mapped_column(String(600), nullable=False)
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


class CatalogProduct(Base):
    """Каталог продуктов источника: записи реестра KSC, объединённые в продукты и ветки (строится фоновой задачей, см. ksc/catalog_build.py)."""
    __tablename__ = "catalog_products"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    publisher: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    publisher_key: Mapped[str] = mapped_column(String(160), nullable=False, default="", index=True)
    origin: Mapped[str] = mapped_column(String(10), nullable=False, default="auto")        # builtin | auto | manual
    component: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    family_key: Mapped[str] = mapped_column(String(160), nullable=False, default="", server_default="")   # основной продукт семейства; свой ключ — сам основной
    family_size: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")    # у основного — число продуктов семейства вместе с ним
    platforms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    note: Mapped[str | None] = mapped_column(Text)
    names: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    versions: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    branches: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    versions_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latest_version: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    scheme: Mapped[str] = mapped_column(String(10), nullable=False, default="numeric")
    transform: Mapped[str | None] = mapped_column(String(20))
    hosts_all: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_active: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    installs_all: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    installs_active: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    search: Mapped[str] = mapped_column(Text, nullable=False, default="")
    built_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class CatalogState(Base):
    """Состояние каталога источника: когда построен, по какому порогу активности, отпечаток данных KSC, запрос на перестроение, ошибка."""
    __tablename__ = "catalog_state"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="empty")       # empty | building | ready | failed
    built_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    signature: Mapped[str | None] = mapped_column(String(200))
    activity_days: Mapped[int | None] = mapped_column(Integer)
    overrides_rev: Mapped[str | None] = mapped_column(String(64))
    progress: Mapped[str | None] = mapped_column(String(300))
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSONType)
    duration_ms: Mapped[int | None] = mapped_column(Integer)


class CatalogOverride(Base):
    """Ручная корректировка каталога (общая для всех источников, сохраняется при обновлении приложения).
    merge — продукт from_key входит в to_key; split — записи с названием match_name выделяются в продукт to_key/to_name; rename — название и производитель продукта to_key."""
    __tablename__ = "catalog_overrides"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    from_key: Mapped[str | None] = mapped_column(String(160))
    match_name: Mapped[str | None] = mapped_column(String(300))
    to_key: Mapped[str] = mapped_column(String(160), nullable=False)
    to_name: Mapped[str | None] = mapped_column(String(300))
    to_publisher: Mapped[str | None] = mapped_column(String(300))
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class UserBackupCode(Base):
    """Резервные коды второго фактора: только HMAC-хэш, каждый действует один раз."""
    __tablename__ = "user_backup_codes"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuthChallenge(Base):
    """Короткоживущие подтверждения: «пароль принят, нужен код 2FA» (kind=totp) и ожидающий подтверждения секрет при включении 2FA (kind=totp_setup)."""
    __tablename__ = "auth_challenges"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)        # sha256 токена или «setup:<user_id>»
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    data: Mapped[dict | None] = mapped_column(JSONType)                   # секреты внутри зашифрованы
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class LdapConnection(Base):
    """Подключение к каталогу (LDAPS/STARTTLS). Несколько подключений — несколько доменов; основное проверяется первым. Пароль сервисной записи зашифрован."""
    __tablename__ = "ldap_connections"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="ldaps", nullable=False)        # ldaps | starttls
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=636, nullable=False)
    ldap_version: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    timeout_s: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    base_dn: Mapped[str] = mapped_column(String(500), nullable=False)
    domain_dns: Mapped[str] = mapped_column(String(253), default="", nullable=False)        # суффикс UPN: user@example.local
    netbios: Mapped[str] = mapped_column(String(64), default="", nullable=False)             # EXAMPLE\user
    bind_dn: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    bind_password_enc: Mapped[str | None] = mapped_column(Text)
    login_attribute: Mapped[str] = mapped_column(String(64), default="sAMAccountName", nullable=False)
    display_name_attribute: Mapped[str] = mapped_column(String(64), default="displayName", nullable=False)
    email_attribute: Mapped[str] = mapped_column(String(64), default="mail", nullable=False)
    user_filter: Mapped[str] = mapped_column(String(1000), default="(&(objectCategory=person)(objectClass=user))", nullable=False)
    nested_groups: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_check_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_check_ok: Mapped[bool | None] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class CaCertificate(Base):
    """Доверенный сертификат удостоверяющего центра (корневой или промежуточный) для проверки LDAPS. Закрытые ключи не принимаются."""
    __tablename__ = "ca_certificates"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    subject: Mapped[str] = mapped_column(String(1000), nullable=False)
    issuer: Mapped[str] = mapped_column(String(1000), nullable=False)
    serial: Mapped[str] = mapped_column(String(100), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    not_before: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    not_after: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    is_ca: Mapped[bool] = mapped_column(Boolean, nullable=False)
    self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    pem: Mapped[str] = mapped_column(Text, nullable=False)
    added_by: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class AccessRule(Base):
    """Правило доступа по группе каталога: участникам группы (с учётом вложенности) — роль и источники KSC. Берётся старшая роль и объединение источников."""
    __tablename__ = "access_rules"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("ldap_connections.id", ondelete="CASCADE"))   # None — любое подключение
    group_dn: Mapped[str] = mapped_column(String(1000), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    all_sources: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    source_ids: Mapped[list | None] = mapped_column(JSONType)
    note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class ServiceHeartbeat(Base):
    """Пульс фоновых служб (worker): для раздела «Состояние системы»."""
    __tablename__ = "service_heartbeats"
    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    data: Mapped[dict | None] = mapped_column(JSONType)


Index("ix_event_log_user", EventLog.user)
Index("ix_catalog_products_hosts", CatalogProduct.source_id, CatalogProduct.hosts_active)


# ------------------------------------------------------------------------------------------------ база уязвимостей (внешние источники)
class VdbSource(Base):
    """Внешний источник сведений об уязвимостях (nvd | kev | osv | bdu): настройки, расписание и состояние последней загрузки.
    Источники с полной выгрузкой (kev, bdu) пишутся в новое «поколение» и подменяют активное только после проверки; предыдущее поколение хранится для отката."""
    __tablename__ = "vdb_sources"
    key: Mapped[str] = mapped_column(String(16), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    settings: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    secret_enc: Mapped[str | None] = mapped_column(Text)
    active_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    prev_generation: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="never")      # never | running | ok | error
    progress: Mapped[str | None] = mapped_column(String(300))
    requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                    # ручной запуск: подхватывает воркер
    last_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_ok_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_duration_ms: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(Text)
    records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cursor: Mapped[dict | None] = mapped_column(JSONType)                                 # NVD: до какой даты изменений загружено; OSV: обработанные идентификаторы
    channel: Mapped[str] = mapped_column(String(24), nullable=False, default="", server_default="")   # канал, которым получены действующие данные
    diag: Mapped[list | None] = mapped_column(JSONType)                                   # попытки последней загрузки: [{channel, ok, error, ms, bytes}]


class VdbRun(Base):
    """История загрузок источников (последние записи хранятся ограниченное время)."""
    __tablename__ = "vdb_runs"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    trigger: Mapped[str] = mapped_column(String(10), nullable=False, default="schedule")  # schedule | manual | file
    mode: Mapped[str] = mapped_column(String(12), nullable=False, default="")             # full | incremental
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="running")
    fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    channel: Mapped[str] = mapped_column(String(24), nullable=False, default="", server_default="")
    attempts: Mapped[list | None] = mapped_column(JSONType)


class VdbRecord(Base):
    """Сведения одного источника об одной уязвимости. Данные источников хранятся раздельно и объединяются только при показе (по vuln_key)."""
    __tablename__ = "vdb_records"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    ext_id: Mapped[str] = mapped_column(String(80), nullable=False)                       # идентификатор в источнике: CVE-…, BDU:…, GHSA-…
    vuln_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)         # общий ключ: CVE, а если его нет — идентификатор источника
    aliases: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="")         # critical | high | medium | low | ""
    score: Mapped[float | None] = mapped_column(Float)
    vector: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    scores: Mapped[list] = mapped_column(JSONType, nullable=False, default=list, server_default="[]")   # все оценки CVSS записи: версия, балл, вектор, уровень, источник, дата (vdb/normalize.make_score)
    scores_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                       # когда оценки получены разбором с их списком; пусто — запись из прежней версии, оценки дозагружаются
    published: Mapped[datetime | None] = mapped_column(UTCDateTime)
    modified: Mapped[datetime | None] = mapped_column(UTCDateTime)
    exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)       # подтверждённая эксплуатация (CISA KEV)
    fix_available: Mapped[bool | None] = mapped_column(Boolean)
    fix_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    refs: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    extra: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ux_vdb_records_ext", "source", "generation", "ext_id", unique=True), Index("ix_vdb_records_mod", "source", "generation", "modified"))


class VdbAffected(Base):
    """Затронутый продукт из записи источника: производитель и продукт (CPE) или пакет (PURL), границы версий, исправление."""
    __tablename__ = "vdb_affected"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    ext_id: Mapped[str] = mapped_column(String(80), nullable=False)
    vuln_key: Mapped[str] = mapped_column(String(80), nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    vendor_key: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    product_key: Mapped[str] = mapped_column(String(300), nullable=False, default="", index=True)
    cpe: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    purl: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    ecosystem: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    pkg_name: Mapped[str] = mapped_column(String(300), nullable=False, default="", index=True)
    platform: Mapped[str] = mapped_column(String(80), nullable=False, default="")         # windows | linux | macos | … либо целевая среда (плагин другого продукта)
    exact: Mapped[str] = mapped_column(String(120), nullable=False, default="")           # конкретная версия
    v_start: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    v_start_incl: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    v_end: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    v_end_incl: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fixed: Mapped[str] = mapped_column(String(120), nullable=False, default="")           # версия, в которой исправлено (OSV)
    versions_all: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)   # затронуты все версии / границы не заданы
    version_text: Mapped[str] = mapped_column(String(300), nullable=False, default="")   # исходный текст версии (БДУ), если разобрать не удалось
    conditional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)   # уязвимость зависит от среды выполнения (конфигурация «И»)
    __table_args__ = (Index("ix_vdb_aff_rec", "source", "generation", "ext_id"), Index("ix_vdb_aff_key", "vuln_key"))


class VdbVuln(Base):
    """Сводка по уязвимости: объединяет записи всех источников для быстрого поиска и списков (пересчитывается при загрузке)."""
    __tablename__ = "vdb_vulns"
    vuln_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    sev_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)  # 4 critical … 1 low, 0 — нет оценки
    score: Mapped[float | None] = mapped_column(Float, index=True)                        # основная оценка CVSS 0.0–10.0; пусто — достоверной оценки нет
    score_version: Mapped[str] = mapped_column(String(4), nullable=False, default="", server_default="")   # методика основной оценки: 4.0 | 3.1 | 3.0 | 2.0
    score_source: Mapped[str] = mapped_column(String(16), nullable=False, default="", server_default="")   # источник основной оценки: nvd | bdu | osv
    exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    has_fix: Mapped[bool | None] = mapped_column(Boolean)
    published: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    modified: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    sources: Mapped[str] = mapped_column(String(80), nullable=False, default="")          # через запятую: nvd,kev
    ids_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    products_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    __table_args__ = (Index("ix_vdb_vulns_priority", text("exploited DESC"), text("sev_rank DESC"), text("published DESC")),)


class VdbMapping(Base):
    """Решение администратора о соответствии продукта из базы уязвимостей (производитель+продукт CPE или пакет) продукту каталога.
    map — считать продуктом каталога; exclude — не считать (ложное совпадение). Сохраняется при обновлении базы и приложения."""
    __tablename__ = "vdb_mappings"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vendor_key: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    product_key: Mapped[str] = mapped_column(String(300), nullable=False)
    catalog_key: Mapped[str] = mapped_column(String(160), nullable=False)
    action: Mapped[str] = mapped_column(String(8), nullable=False, default="map")
    note: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_vdb_mappings_key", "vendor_key", "product_key"),)


class VdbFinding(Base):
    """Уязвимость из внешней базы, потенциально затрагивающая установленное ПО источника KSC (оценка по каталогу, без обращения к KSC).
    Пересчитывается после загрузки новых и изменённых записей; «новые» — ещё не просмотренные специалистом."""
    __tablename__ = "vdb_findings"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    vuln_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    status: Mapped[str] = mapped_column(String(14), nullable=False, default="")           # лучший статус сопоставления
    sev_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    products: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)        # [{key, name, versions, installs}]
    installs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_max: Mapped[int] = mapped_column(Integer, nullable=False, default=0)            # верхняя оценка числа компьютеров (сумма по версиям каталога)
    seen_by: Mapped[str | None] = mapped_column(String(300))
    seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


# ------------------------------------------------------------------------------------------------ зоны ответственности, рассылки, обработка уязвимостей
class Zone(Base):
    """Зона ответственности: произвольная группа компьютеров (сети, группы KSC, имена), закреплённая за ответственными. Департамент, филиал, площадка — решает администратор."""
    __tablename__ = "zones"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)          # устойчивый идентификатор: по нему CSV обновляет зону, а не по названию
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    purpose: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)                # меньше — главнее; при равных приоритетах пересечение остаётся видимым спором
    activity_days: Mapped[int | None] = mapped_column(Integer)                                 # свой период активности; пусто — общий (30 суток)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(300))


class ZoneRule(Base):
    """Признак принадлежности: net — сеть/диапазон/адрес, exclude — исключение, group — группа администрирования KSC (маска), name — имя компьютера (маска)."""
    __tablename__ = "zone_rules"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    zone_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("zones.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    value: Mapped[str] = mapped_column(String(300), nullable=False)
    note: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ZoneContact(Base):
    """Ответственный или получатель отчётов зоны. Учётная запись KAV Checker не нужна — достаточно контактных данных."""
    __tablename__ = "zone_contacts"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    zone_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("zones.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    position: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    role: Mapped[str] = mapped_column(String(12), nullable=False, default="responsible")      # responsible | cc | group
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)               # рассылка конкретному получателю можно отключить
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class ZonePin(Base):
    """Явное решение по спорному компьютеру: он относится к указанной зоне, даже если подходит под несколько."""
    __tablename__ = "zone_pins"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False)
    host_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    host_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    zone_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("zones.id", ondelete="CASCADE"), nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ux_zone_pins_host", "source_id", "host_id", unique=True),)


class ReportSchedule(Base):
    """Правило автоматической рассылки: какие зоны, какие разделы, как часто. Расписание хранится в базе и переживает перезапуски и обновления."""
    __tablename__ = "report_schedules"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    zone_ids: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)             # пусто — все зоны
    include_unassigned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sections: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)             # ksc_vulns, critical_only, ext_vulns, no_av, rtp_off, bases_old, infected, inactive, …
    filters: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)              # severity, online_only, active_days, include_inactive, source_ids
    level: Mapped[str] = mapped_column(String(12), nullable=False, default="management")       # management | technical
    frequency: Mapped[str] = mapped_column(String(8), nullable=False, default="weekly")        # daily | weekly | monthly
    weekday: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                   # 0 — понедельник
    monthday: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    at_time: Mapped[str] = mapped_column(String(5), nullable=False, default="08:00")
    tz: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    attach_html: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    attach_xlsx: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    skip_empty: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)           # не отправлять зоне без проблем
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_period: Mapped[str | None] = mapped_column(String(32))
    created_by: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class MailOutbox(Base):
    """Устойчивая очередь и журнал отправки. Одно письмо = одна зона × одно правило × один период (UNIQUE): после перезапуска воркера повторной отправки нет.
    «accepted» — сервер SMTP принял письмо; это не доставка и не прочтение."""
    __tablename__ = "mail_outbox"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("report_schedules.id", ondelete="SET NULL"), index=True)
    zone_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("zones.id", ondelete="SET NULL"))
    zone_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    period_key: Mapped[str] = mapped_column(String(40), nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False, default="schedule")          # schedule | manual | test
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="queued")          # queued | sending | accepted | failed | skipped
    subject: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    to_addrs: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    cc_addrs: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    body_path: Mapped[str | None] = mapped_column(String(400))                                  # письмо и вложения, подготовленные заранее (не пересобираются при повторе)
    stats: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    refused: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)               # адреса, отклонённые сервером SMTP
    message_id: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    __table_args__ = (Index("ux_mail_outbox_period", "schedule_id", "zone_id", "period_key", unique=True),)


class VulnTriage(Base):
    """Решение специалиста по обнаруженной уязвимости. Область действия — всегда явная: по умолчанию «эта уязвимость на этом компьютере»; шире (программа, зона) — только по осознанному выбору.
    Исходные сведения об уязвимости не удаляются: решение лишь определяет, показывать ли её среди актуальных проблем."""
    __tablename__ = "vuln_triage"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(8), nullable=False, default="host")              # host | product | zone
    host_id: Mapped[int | None] = mapped_column(BigInteger)
    host_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    zone_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("zones.id", ondelete="CASCADE"))
    vuln_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)              # CVE-… / BDU:… / KLA…
    origin: Mapped[str] = mapped_column(String(4), nullable=False, default="ksc")              # ksc | ext
    product: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(120), nullable=False, default="")              # установленная версия на момент решения (основание)
    status: Mapped[str] = mapped_column(String(16), nullable=False)                             # review | confirmed | false_positive | obsolete | risk_accepted
    reason: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    review_until: Mapped[datetime | None] = mapped_column(UTCDateTime)                          # принятый риск: срок пересмотра
    recheck: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)              # основание изменилось — вернуть на проверку
    recheck_reason: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_vuln_triage_host", "source_id", "host_id", "vuln_key"),)


class VulnTriageEvent(Base):
    """История обработки: кто, когда и что изменил."""
    __tablename__ = "vuln_triage_events"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    triage_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("vuln_triage.id", ondelete="CASCADE"), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    actor: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(16), nullable=False)                             # create | status | comment | recheck | expire | delete
    from_status: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    to_status: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")


# ------------------------------------------------------------------------------------------------ подготовленные данные зон (ночной расчёт)
class ZcSource(Base):
    """Состояние подготовленных данных зон по источнику KSC: текущее поколение, время и срез данных, ход расчёта. Читатели видят только поколение `gen`: новое записывается рядом и подменяется одной транзакцией."""
    __tablename__ = "zc_sources"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    gen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                       # 0 — данных ещё нет
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="empty")           # empty | building | ready | failed
    built_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                              # срез данных KSC (начало последнего успешного чтения)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    progress: Mapped[str | None] = mapped_column(String(300))
    error: Mapped[str | None] = mapped_column(Text)
    hosts_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detections_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    agg_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    stamp: Mapped[str] = mapped_column(String(200), nullable=False, default="")                 # отпечаток данных KSC в момент расчёта
    probe_stamp: Mapped[str] = mapped_column(String(200), nullable=False, default="")           # отпечаток по последней лёгкой проверке KSC
    probe_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    vdb_rev: Mapped[str] = mapped_column(String(64), nullable=False, default="")                # состояние баз уязвимостей и каталога при расчёте (хэш)
    vdb_rev_now: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class ZcHost(Base):
    """Компьютер источника в подготовленных данных: колонки для фильтров, сортировки и итогов (без чтения KSC), data — остальные сведения для карточки и отчётов."""
    __tablename__ = "zc_hosts"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    host_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    gen: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    search: Mapped[str] = mapped_column(String(800), nullable=False, default="")                # имя, FQDN и адрес в нижнем регистре
    ip_num: Mapped[int | None] = mapped_column(BigInteger)
    os: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    last_connected: Mapped[datetime | None] = mapped_column(UTCDateTime)
    days_since: Mapped[float | None] = mapped_column(Float)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    online: Mapped[bool | None] = mapped_column(Boolean)
    has_av: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    bases_age: Mapped[float | None] = mapped_column(Float)                                      # возраст антивирусных баз в сутках на момент среза
    scan_age: Mapped[float | None] = mapped_column(Float)
    p_no_av: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    p_rtp: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    p_inf: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    p_lic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    p_reb: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    k_crit: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    k_high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    k_warn: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    k_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    k_acc: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    k_exc: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    k_rev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_crit: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_warn: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_kev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_conf: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_acc: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    e_exc: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conflict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    data: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    __table_args__ = (Index("ix_zc_hosts_gen", "source_id", "gen"),)


class ZcHostZone(Base):
    """Принадлежность компьютера зоне (zone_id — идентификатор зоны или «none»): пересчитывается при изменении зон без обращения к KSC."""
    __tablename__ = "zc_hostzones"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    host_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    gen: Mapped[int] = mapped_column(Integer, primary_key=True)
    zone_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    __table_args__ = (Index("ix_zc_hostzones_zone", "zone_id", "source_id", "gen"),)


class ZcDetection(Base):
    """Обнаружение (подтверждённое KSC или потенциальное по внешним базам) на компьютере: строки для карточки, таблиц и отчётов, с решением специалиста (bucket, triage)."""
    __tablename__ = "zc_detections"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    gen: Mapped[int] = mapped_column(Integer, nullable=False)
    host_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    origin: Mapped[str] = mapped_column(String(4), nullable=False)                              # ksc | ext
    vuln_key: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    keys: Mapped[str] = mapped_column(String(600), nullable=False, default="")                  # все идентификаторы строки в верхнем регистре (поиск и привязка решений)
    prod: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                   # 0 нет, 1 предупреждение, 2 высокая, 3 критическая
    bucket: Mapped[str] = mapped_column(String(8), nullable=False, default="current")           # current | accepted | excluded
    tstatus: Mapped[str] = mapped_column(String(16), nullable=False, default="")                # эффективное решение: review | confirmed | … | "" (решения нет)
    flags: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                      # 1 — в каталоге CISA KEV, 2 — подтверждено источником (внешние базы)
    row: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    __table_args__ = (Index("ix_zc_det_host", "source_id", "gen", "host_id"), Index("ix_zc_det_vuln", "source_id", "gen", "vuln_key"))


class ZcDashboard(Base):
    """Готовая сводка зоны (показатели, данные диаграмм, обзорная строка): читается при открытии страницы. Заменяется целиком после успешного расчёта; при ошибке остаётся прежняя."""
    __tablename__ = "zc_dashboards"
    zone_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    kind: Mapped[str] = mapped_column(String(12), primary_key=True, default="default")
    payload: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    built_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)       # когда рассчитана сводка
    data_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                                # срез данных KSC, по которому она построена (самый старый из источников)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default="ok")
    error: Mapped[str | None] = mapped_column(Text)
    failed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class ZcJob(Base):
    """Задание фонового расчёта: ночной пересчёт всех зон, обновление одной зоны или пересчёт состава зон. Один активный экземпляр каждого вида (dedupe_key), состояние переживает перезапуск worker."""
    __tablename__ = "zc_jobs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)                                # all | zone | members
    zone_id: Mapped[str | None] = mapped_column(String(40))
    dedupe_key: Mapped[str] = mapped_column(String(60), nullable=False)
    trigger: Mapped[str] = mapped_column(String(10), nullable=False, default="manual")          # nightly | manual | initial | auto
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="queued")           # queued | running | done | failed
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    progress: Mapped[str | None] = mapped_column(String(300))
    pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (Index("ux_zc_jobs_active", "dedupe_key", unique=True, postgresql_where=text("status IN ('queued','running')"), sqlite_where=text("status IN ('queued','running')")),)
