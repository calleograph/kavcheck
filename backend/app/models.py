"""ORM-модели внутренней базы KAV Checker. Схема меняется ТОЛЬКО через Alembic (backend/migrations). Базы KSC здесь не описываются."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid, text
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
    theme: Mapped[str | None] = mapped_column(String(16))               # выбранная тема оформления; None — тема по умолчанию системы (выбор не перезаписывается обновлениями)


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


class JobLease(Base):
    """Аренда фонового задания: пока исполнитель жив, он продлевает `lease_until` (heartbeat). Нет продления — аренда истекает, задание считается прерванным и любой worker вправе его перехватить.
    Одна строка на (вид, область): два исполнителя одной задачи невозможны. `run_id` — идентификатор выполнения: запись результата проверяет, что аренда всё ещё принадлежит этому выполнению."""
    __tablename__ = "job_leases"
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)            # catalog | eol | vdb_sync | vdb_analyze | zonecache | report | devices …
    scope: Mapped[str] = mapped_column(String(80), primary_key=True, default="")   # источник KSC, ключ источника базы уязвимостей, задание и т. п.; пусто — задача без области
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    owner: Mapped[str] = mapped_column(String(160), nullable=False)             # хост/процесс/экземпляр исполнителя
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    lease_until: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    stage: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    progress: Mapped[str | None] = mapped_column(String(300))
    app_version: Mapped[str] = mapped_column(String(40), nullable=False, default="")


class JobRun(Base):
    """История выполнений фоновых заданий (последние по каждой области): результат, этап, причина ошибки, версия приложения. Прежние ошибки остаются здесь и не выдаются за текущую причину отказа."""
    __tablename__ = "job_runs"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    scope: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    owner: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    app_version: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(14), nullable=False)             # success | error | interrupted | deferred | lost
    stage: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (Index("ix_job_runs_scope", "kind", "scope", "finished_at"),)


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


class VdbFindingProduct(Base):
    """Находка × продукт каталога (одна строка на пару «уязвимость, продукт»): основа плана устранения — что обновить, какие версии затронуты, сколько уязвимостей у продукта. Строится вместе с `vdb_findings`;
    единицы подсчёта разделены: уникальные уязвимости — COUNT(vuln_key), продукты — число различных product_key, компьютеры — по версиям каталога (верхняя оценка до проверки)."""
    __tablename__ = "vdb_finding_products"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    vuln_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    product_key: Mapped[str] = mapped_column(String(160), primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(12), nullable=False, default="unclassified")      # os | system | application | unclassified
    status: Mapped[str] = mapped_column(String(14), nullable=False, default="")                   # лучший статус сопоставления для продукта
    sev_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    installs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                        # сумма по затронутым версиям (верхняя оценка)
    versions: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)                # затронутые версии каталога (не более 40)
    __table_args__ = (Index("ix_vdb_fp_product", "source_id", "product_key"), Index("ix_vdb_fp_category", "source_id", "category"))


class ProductClass(Base):
    """Решение администратора: категория продукта каталога для аналитики уязвимостей (PostgreSQL — серверное или системное ПО, решает роль на вашей установке)."""
    __tablename__ = "product_classes"
    catalog_key: Mapped[str] = mapped_column(String(160), primary_key=True)
    category: Mapped[str] = mapped_column(String(12), nullable=False)
    note: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


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
    p_hwc: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)                 # Linux-сервер: мало ядер CPU
    p_hwr: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)                 # Linux-сервер: мало ОЗУ
    hw_crit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)               # среди проблем ресурсов есть критическая
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
    kk: Mapped[str] = mapped_column(Text, nullable=False, default="")                            # идентификаторы и программы текущих обнаружений через «|» (строчные): поиск по CVE/KLA и программе без обхода обнаружений
    ke: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pk: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pe: Mapped[str] = mapped_column(Text, nullable=False, default="")
    __table_args__ = (Index("ix_zc_hosts_gen", "source_id", "gen"), Index("ix_zc_hosts_ip", "source_id", "gen", "ip_num"))


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
    __table_args__ = (Index("ix_zc_det_host", "source_id", "gen", "host_id"), Index("ix_zc_det_vuln", "source_id", "gen", "vuln_key"),
                      Index("ix_zc_det_crit", "source_id", "gen", "host_id", postgresql_include=["vuln_key"],          # «Критические уязвимости» главной: по индексу, без чтения всех обнаружений
                            postgresql_where=text("origin = 'ksc' AND severity = 3 AND bucket = 'current'")))


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


# ------------------------------------------------------------------------------------------------ жизненный цикл ПО (endoflife.date)
class EolProduct(Base):
    """Продукт из базы endoflife.date (локальная копия): названия, идентификаторы (purl, cpe, repology), подписи этапов поддержки у производителя."""
    __tablename__ = "eol_products"
    name: Mapped[str] = mapped_column(String(120), primary_key=True)                          # слаг endoflife.date
    label: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    category: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    tags: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    aliases: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    identifiers: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)       # [{type: purl|cpe|repology, id}]
    labels: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)            # как производитель называет этапы: eoas, eol, eoes, discontinued
    links: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)             # html, releasePolicy, icon
    search: Mapped[str] = mapped_column(Text, nullable=False, default="")                   # название, подпись, алиасы, идентификаторы — строчными, для поиска
    releases_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    digest: Mapped[str] = mapped_column(String(32), nullable=False, default="")             # хэш содержимого: неизменившиеся продукты при обновлении не переписываются
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class EolRelease(Base):
    """Ветка (цикл) продукта: даты этапов поддержки как их отдаёт API; признаки «закончилось» пересчитываются по датам на момент проверки, а не берутся из сохранённого."""
    __tablename__ = "eol_releases"
    product: Mapped[str] = mapped_column(String(120), ForeignKey("eol_products.name", ondelete="CASCADE"), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), primary_key=True)                          # название ветки: «7.4», «2019», «22.04»
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)               # порядок в ответе API (новые первыми)
    label: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    codename: Mapped[str | None] = mapped_column(String(80))
    release_date: Mapped[date | None] = mapped_column(Date)
    is_lts: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lts_from: Mapped[date | None] = mapped_column(Date)
    eoas_from: Mapped[date | None] = mapped_column(Date)                                    # конец активной поддержки (исправления ошибок и новые возможности)
    eol_from: Mapped[date | None] = mapped_column(Date)                                     # конец поддержки исправлений безопасности (стандартной)
    eoes_from: Mapped[date | None] = mapped_column(Date)                                    # конец расширенной поддержки (платной, по подписке или договору)
    eol_flag: Mapped[bool | None] = mapped_column(Boolean)                                  # признак isEol из API (если даты нет)
    eoes_flag: Mapped[bool | None] = mapped_column(Boolean)
    discontinued_from: Mapped[date | None] = mapped_column(Date)
    latest_name: Mapped[str | None] = mapped_column(String(80))
    latest_date: Mapped[date | None] = mapped_column(Date)
    latest_link: Mapped[str | None] = mapped_column(String(400))
    custom: Mapped[dict | None] = mapped_column(JSONType)


class EolMapping(Base):
    """Решение администратора: какому продукту endoflife.date соответствует программа каталога (или что соответствия нет). Сохраняется при обновлении базы и каталога."""
    __tablename__ = "eol_mappings"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    catalog_key: Mapped[str] = mapped_column(String(160), nullable=False)       # ключ продукта каталога (одинаков во всех источниках)
    eol_product: Mapped[str | None] = mapped_column(String(120))                            # слаг endoflife.date; пусто при action=exclude
    action: Mapped[str] = mapped_column(String(8), nullable=False, default="map")           # map | exclude
    note: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ux_eol_mappings_key", "catalog_key", unique=True),)


class EolFinding(Base):
    """Итог сопоставления программы или ОС источника KSC с жизненным циклом: считается в фоне после загрузки базы EOL, пересборки каталога или решения администратора; страницы читают готовое."""
    __tablename__ = "eol_findings"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(3), primary_key=True)                          # app | os
    subject: Mapped[str] = mapped_column(String(200), primary_key=True)                     # app: ключ продукта каталога; os: название ОС (как в KSC)
    version: Mapped[str] = mapped_column(String(120), primary_key=True)                     # app: версия каталога; os: «мажор.минор.сборка»
    title: Mapped[str] = mapped_column(String(300), nullable=False, default="")             # название продукта или ОС
    publisher: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    eol_product: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    eol_release: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="unknown")      # eol | extended | upcoming | supported | unknown | undetermined (ОС: выпуск или срок не определены)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="")           # critical | high | warning | ""
    confidence: Mapped[str] = mapped_column(String(8), nullable=False, default="")          # mapped | high | name — насколько надёжно сопоставлен продукт
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)          # False: поддержка зависит от подписки/договора или продукт сопоставлен только по названию
    eol_from: Mapped[date | None] = mapped_column(Date)
    eoas_from: Mapped[date | None] = mapped_column(Date)
    eoes_from: Mapped[date | None] = mapped_column(Date)
    condition: Mapped[str] = mapped_column(String(600), nullable=False, default="")
    link: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    os_key: Mapped[dict | None] = mapped_column(JSONType)                                   # для ОС: поля отбора устройств в KSC (название, версия, сборка)
    product_ids: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)       # для программ: записи реестра ПО (для списка устройств)
    hosts_all: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_active: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    installs_active: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    computed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_eol_findings_status", "source_id", "status"), Index("ix_eol_findings_product", "eol_product"))


class EolHostStat(Base):
    """Итоги EOL по устройству (сколько программ и ОС с проблемой поддержки, наихудшее состояние): считаются при расчёте, чтобы таблица устройств и дашборды зон не агрегировали миллионы связей при каждом открытии."""
    __tablename__ = "eol_host_stat"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    host_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)          # проблемных программ и ОС
    n_os: Mapped[int] = mapped_column(Integer, nullable=False, default=0)       # из них операционных систем
    n_crit: Mapped[int] = mapped_column(Integer, nullable=False, default=0)     # из них критических (стандартная поддержка закончилась, соответствие подтверждено)
    w: Mapped[int] = mapped_column(Integer, nullable=False, default=0)          # наихудшее состояние: 3 — EOL, 2 — только расширенная поддержка, 1 — скоро
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class DevicesState(Base):
    """Состояние опроса пользователей устройств по источнику KSC (опрос выполняет worker; страницы читают накопленное)."""
    __tablename__ = "dev_state"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    polled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                        # начало последнего успешного опроса
    first_poll_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                     # с этого времени KAV Checker ведёт наблюдения (раньше истории нет)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    rows_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)             # строк в списках KSC при последнем опросе
    users_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                     # опрос по требованию


class EolState(Base):
    """Состояние расчёта сопоставления по источнику: отпечаток данных, от которых зависит результат (база EOL, каталог, решения), и время."""
    __tablename__ = "eol_state"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    rev: Mapped[str] = mapped_column(String(64), nullable=False, default="")               # отпечаток результата (для «изменилось ли»)
    inputs: Mapped[str] = mapped_column(String(64), nullable=False, default="")            # отпечаток исходных данных последнего расчёта: база EOL, каталог источника, решения
    computed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    items: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    progress: Mapped[str | None] = mapped_column(String(200))
    app_version: Mapped[str | None] = mapped_column(String(40))                           # версия приложения, в которой сделана последняя попытка: ошибка прежней версии не считается текущей причиной отказа
    attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                       # начало последней попытки расчёта (успешной или нет): отличает свежую ошибку от оставшейся с прошлых попыток
    error_detail: Mapped[str | None] = mapped_column(Text)                                  # техническая причина последней ошибки (этап, операция, ключ) — только для администратора
    diag: Mapped[dict | None] = mapped_column(JSONType)                                      # сведения последнего расчёта: объединённые дубли, конфликты при записи, число попыток
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                       # расчёт идёт сейчас (очищается по завершении; после падения worker сбрасывается при запуске)


class EolHost(Base):
    """Устройство, на котором найдена программа или ОС из `eol_findings` (по записи реестра ПО либо по ОС компьютера). Строится вместе с находками; страницы EOL и дашборды зон читают готовое."""
    __tablename__ = "eol_hosts"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(3), primary_key=True)
    subject: Mapped[str] = mapped_column(String(200), primary_key=True)
    version: Mapped[str] = mapped_column(String(120), primary_key=True)
    host_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)            # связь с KSC за период активности (на момент расчёта): счётчики по зонам без обращения к данным зон
    __table_args__ = (Index("ix_eol_hosts_host", "source_id", "host_id"),)


# ------------------------------------------------------------------------------------------------ пользователи устройств
class DeviceUser(Base):
    """Наблюдения за пользователями устройств: KSC хранит список вошедших сейчас и список «входивших ранее» без дат, поэтому история семи суток строится по наблюдениям KAV Checker
    (время — когда пользователь замечен в списках KSC, а не время входа в систему)."""
    __tablename__ = "dev_users"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    host_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_key: Mapped[str] = mapped_column(String(80), primary_key=True)                     # логин (sAMAccountName) либо хэш учётной записи, если логин в KSC неизвестен
    login: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    domain: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="user")            # user | service | system
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)           # логин определён (иначе — только хэш из KSC)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)       # первое наблюдение KAV Checker
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)        # последнее наблюдение в любом списке KSC
    last_session_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                              # последнее наблюдение в списке вошедших сейчас (bActual=1)
    session_now: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    seen_n: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    initial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)           # замечен при первом опросе источника: дата входа неизвестна, в «за 7 суток» не входит, пока не появился в списке вошедших
    __table_args__ = (Index("ix_dev_users_login", "login"), Index("ix_dev_users_host", "source_id", "host_id", "last_seen_at"))


# ------------------------------------------------------------------------------------------------ главная: лицензии и ежедневные срезы
class LicenseState(Base):
    """Состояние чтения лицензий по источнику KSC (читает worker): когда, чем закончилось, какие таблицы и столбцы найдены (для диагностики администратором)."""
    __tablename__ = "lic_state"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    polled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                         # последнее успешное чтение
    error: Mapped[str | None] = mapped_column(Text)
    error_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    records_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    diag: Mapped[dict | None] = mapped_column(JSONType)                                       # найденные таблицы, сопоставление столбцов, пояснение, если лицензии не прочитаны


class LicenseRecord(Base):
    """Лицензия источника: из KSC (origin=ksc, заменяется при каждом чтении) либо внесена администратором (origin=manual). Полные ключи не хранятся: fp — HMAC-отпечаток серийного номера."""
    __tablename__ = "lic_records"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    lic_key: Mapped[str] = mapped_column(String(40), primary_key=True)                        # отпечаток либо хэш (продукт, срок, лимит); для ручных — случайный
    origin: Mapped[str] = mapped_column(String(6), nullable=False, default="ksc")             # ksc | manual
    product: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    limit_n: Mapped[int | None] = mapped_column(Integer)
    used_n: Mapped[int | None] = mapped_column(Integer)                                       # пусто — KSC не сообщает использование
    state: Mapped[str] = mapped_column(String(10), nullable=False, default="unknown")         # active | expiring | expired | unknown
    fp: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    note: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class LicenseOverride(Base):
    """Решение администратора: лицензия источника входит в общий пул (запись KSC не меняется). Лицензии с одним пулом считаются один раз: лимит — общий, использование — суммой."""
    __tablename__ = "lic_overrides"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    lic_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    pool: Mapped[str] = mapped_column(String(120), nullable=False)
    set_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    set_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class OverviewDaily(Base):
    """Ежедневный срез показателей главной по источнику (для графика динамики): одна строка в сутки, хранится ограниченное время."""
    __tablename__ = "ov_daily"
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    data: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    taken_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


# ------------------------------------------------------------------------------------------------ Pentest: сетевое сканирование
class PtJob(Base):
    """Задание сетевого сканирования. Не зависит от KSC: цели задаёт оператор. Выполняет отдельный сканер (`python -m app.pentest.worker`) под арендой; состояние переживает перезапуск."""
    __tablename__ = "pt_jobs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="queued")       # queued | running | done | partial | failed | cancelled
    stage: Mapped[str] = mapped_column(String(24), nullable=False, default="")             # targets | discovery | ports | services | versions | normalize | match | assess | results | report
    stage_ru: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    profile: Mapped[str] = mapped_column(String(40), nullable=False, default="standard")
    options: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)          # порты, обнаружение, интенсивность версий, безопасные скрипты, подтверждение крупного охвата
    targets_input: Mapped[str] = mapped_column(Text, nullable=False, default="")           # что ввёл оператор (для «создать на основе»)
    targets_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejected: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)         # отклонённые при проверке цели с причинами
    hosts_up: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ports_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    services_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_confirmed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    incomplete_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)          # порты без версии сервиса и другие неполные проверки
    max_sev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)               # наивысшая опасность находок: 4 критическая … 1 низкая
    sev: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)              # распределение находок по опасности
    nmap_version: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    vdb_rev: Mapped[str] = mapped_column(String(80), nullable=False, default="")           # состояние баз уязвимостей при анализе
    engines: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)          # версии и режимы движков задания: nuclei, шаблоны, набор проверок, число запросов
    base_job_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)                              # задание, на основе которого создано
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    stages: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)           # состояние каждого этапа: {этап: {state, at, ms, note}}
    diag: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)             # итог контроля полноты: причины неполного выполнения и сведения о пропущенном
    __table_args__ = (Index("ix_pt_jobs_status", "status", "created_at"),)


class PtHost(Base):
    """Адрес задания и итог по нему: состояние, ошибка этапа, число портов. Основа восстановления: после перезапуска сканера незавершённые адреса выполняются заново, готовые не повторяются."""
    __tablename__ = "pt_hosts"
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pt_jobs.id", ondelete="CASCADE"), primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    names: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)             # имена, под которыми адрес указан, и обратная запись DNS
    state: Mapped[str] = mapped_column(String(10), nullable=False, default="pending")       # pending | up | down | done | error
    error_stage: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    error: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    ports_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_sev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scan_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notes: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)             # неполные проверки хоста: Nuclei не уложился во время, проверка недоступна и т. п. (видны в отчёте)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    __table_args__ = (Index("ix_pt_hosts_ip", "ip", "job_id"), Index("ix_pt_hosts_state", "job_id", "state"))


class PtPort(Base):
    """Открытый порт и определённый сервис (структурированный результат Nmap)."""
    __tablename__ = "pt_ports"
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pt_jobs.id", ondelete="CASCADE"), primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    proto: Mapped[str] = mapped_column(String(4), primary_key=True, default="tcp")
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    service: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    extrainfo: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    ostype: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    tunnel: Mapped[str] = mapped_column(String(10), nullable=False, default="")
    cpe: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="")             # table (по номеру порта) | probed (по ответу сервиса)
    conf: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                    # уверенность Nmap 0–10
    banner: Mapped[str] = mapped_column(Text, nullable=False, default="")                    # исходный ответ сервиса (обрезан по настройке)
    scripts: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)           # результаты безопасных скриптов: [{id, output}]
    skipped: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)           # уязвимости, исключённые как неприменимые к сервису: [{key, reason, kind}] (роль компонента, платформа, исправление дистрибутива)
    __table_args__ = (Index("ix_pt_ports_service", "job_id", "service"),)


class PtFinding(Base):
    """Потенциальная или подтверждённая уязвимость сервиса: основание, правило, уровень уверенности и доказательства."""
    __tablename__ = "pt_findings"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pt_jobs.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    proto: Mapped[str] = mapped_column(String(4), nullable=False, default="tcp")
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    vuln_key: Mapped[str] = mapped_column(String(80), nullable=False)                        # CVE или идентификатор источника (как в базе уязвимостей)
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    sev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                      # 4 критическая … 1 низкая, 0 — нет оценки
    score: Mapped[float | None] = mapped_column(Float)
    score_version: Mapped[str] = mapped_column(String(4), nullable=False, default="")
    exploited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)         # в каталоге CISA KEV
    confidence: Mapped[str] = mapped_column(String(14), nullable=False)                      # confirmed | probable | needs_check | not_confirmed
    basis: Mapped[str] = mapped_column(String(10), nullable=False, default="version")       # version | banner | nse | oval | name
    rule: Mapped[str] = mapped_column(String(60), nullable=False, default="")                # идентификатор применённого правила сопоставления
    product: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    evidence: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)          # объяснение: источники, диапазоны, отклонённые условия, проверки (OVAL, скрипты)
    category: Mapped[str] = mapped_column(String(12), nullable=False, default="cve", server_default="cve")          # cve | config | web | exposure | tls | service
    engines: Mapped[str] = mapped_column(String(40), nullable=False, default="nmap", server_default="nmap")       # движки доказательств через запятую: nmap, nse, nuclei, oval
    __table_args__ = (Index("ix_pt_findings_job", "job_id", "sev"), Index("ix_pt_findings_host", "job_id", "ip", "port"), Index("ix_pt_findings_key", "vuln_key"))


class PtEvent(Base):
    """Ошибки и предупреждения хода задания: этап, адрес, причина (не более нескольких сотен на задание)."""
    __tablename__ = "pt_events"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pt_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    level: Mapped[str] = mapped_column(String(5), nullable=False, default="warn")
    stage: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    message: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    # структурированные поля диагностики (миграция 0019): живой журнал, скачивание, сводка причин неполного выполнения
    engine: Mapped[str] = mapped_column(String(10), nullable=False, default="")             # nmap | nse | nuclei | oval | match | scanner
    kind: Mapped[str] = mapped_column(String(10), nullable=False, default="")               # step (ход) | skip (не применимо, не ошибка) | problem (неисполненная проверка) | info
    port: Mapped[int | None] = mapped_column(Integer)
    check_id: Mapped[str] = mapped_column(String(160), nullable=False, default="")          # скрипт NSE, шаблон Nuclei, запуск
    rc: Mapped[int | None] = mapped_column(Integer)                                          # код завершения процесса
    ms: Mapped[int | None] = mapped_column(Integer)                                          # длительность, мс
    retry: Mapped[str] = mapped_column(String(8), nullable=False, default="")               # safe (повтор безопасен) | no | done (повтор уже выполнен)
    attempt: Mapped[int | None] = mapped_column(Integer)                                     # номер запуска задания (после перезапуска сканера — следующий)
    incomplete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)        # событие объясняет неисполненную обязательную часть
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")                   # технические подробности: вывод ошибки (усечён, секреты скрыты)


class HuntHit(Base):
    """Результат целевого поиска (CVE Hunt): компьютер × критерий. Статусы: confirmed | probable | needs_check | failed (не удалось проверить). «Не обнаружено» не хранится — охват задания виден по хостам задания."""
    __tablename__ = "hunt_hits"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pt_jobs.id", ondelete="CASCADE"), nullable=False)
    crit_key: Mapped[str] = mapped_column(String(80), nullable=False)                         # критерий задания: CVE-… либо ключ продукта
    vuln_key: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    ip: Mapped[str] = mapped_column(String(45), nullable=False, default="")
    port: Mapped[int | None] = mapped_column(Integer)
    source_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)                                  # устройство KSC (не склеивается с другим источником по имени или адресу)
    host_id: Mapped[int | None] = mapped_column(BigInteger)
    host_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    os: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    user_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")           # последний замеченный пользователь (не владелец и не интерактивный сеанс)
    user_kind: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    zone: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    group_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    product: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(14), nullable=False)
    basis: Mapped[str] = mapped_column(String(8), nullable=False, default="network")          # ksc | network | both
    evidence: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)           # [{kind, text, at}]: «как определено»
    data_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                              # возраст использованных данных
    last_connected: Mapped[datetime | None] = mapped_column(UTCDateTime)
    ambiguous: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)           # адрес совпал с несколькими устройствами KSC
    diff: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)               # версия в KSC и по сети различаются
    __table_args__ = (Index("ix_hunt_hits_job", "job_id", "status"), Index("ix_hunt_hits_ip", "job_id", "ip"))


class CompCheck(Base):
    """Последняя известная версия компонента по данным официального источника (проверяется в фоне, кэшируется; страница внешних сервисов не опрашивает)."""
    __tablename__ = "comp_checks"
    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    latest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    url: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    error: Mapped[str] = mapped_column(String(300), nullable=False, default="")


class PtHit(Base):
    """Необработанный результат проверки Nuclei: хранится до анализа и показывается в техническом приложении отчёта. Секреты в ответах скрыты ещё до записи."""
    __tablename__ = "pt_hits"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pt_jobs.id", ondelete="CASCADE"), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engine: Mapped[str] = mapped_column(String(8), nullable=False, default="nuclei")
    check_id: Mapped[str] = mapped_column(String(160), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    sev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cves: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    tags: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    matched_at: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    vhost: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    extracted: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    info: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)               # описание, рекомендация, ссылки из шаблона
    __table_args__ = (Index("ix_pt_hits_host", "job_id", "ip", "port"),)


class PtCheck(Base):
    """Каталог проверок Pentest (скрипты Nmap NSE и шаблоны Nuclei): назначение, воздействие, политика и решение администратора. Выполняются только разрешённые (`state = allowed`)."""
    __tablename__ = "pt_checks"
    engine: Mapped[str] = mapped_column(String(8), primary_key=True)                         # nse | nuclei
    check_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    category: Mapped[str] = mapped_column(String(24), nullable=False, default="")           # web | cve | config | exposure | tls | ssh | smb | dns | db | mail | ftp | rdp | cache | tech
    name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="info")
    protocols: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    impact: Mapped[str] = mapped_column(String(12), nullable=False, default="low")          # passive | low | moderate | intrusive
    policy: Mapped[str] = mapped_column(String(10), nullable=False, default="review")       # safe — входит в проверенный набор; review — только по утверждению администратора; forbidden — не выполняется никогда
    policy_reason: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    state: Mapped[str] = mapped_column(String(8), nullable=False, default="blocked")        # allowed | blocked
    decided_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")        # кто изменил решение вручную (пусто — действует политика)
    tags: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    cves: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    path: Mapped[str] = mapped_column(String(400), nullable=False, default="")             # файл шаблона относительно каталога шаблонов
    requests: Mapped[int] = mapped_column(Integer, nullable=False, default=1)              # оценка числа запросов на цель (бюджет задания)
    meta: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)             # рекомендация, ссылки, порты TCP-шаблона, продукт, CVSS — из шаблона
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    templates_ver: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_pt_checks_sel", "engine", "state", "category"),)


class PtEngine(Base):
    """Состояние внешнего движка (Nuclei): версия, шаблоны (версия, контрольная сумма, источник), запрос администратора на обновление или импорт."""
    __tablename__ = "pt_engine"
    key: Mapped[str] = mapped_column(String(16), primary_key=True)
    version: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    templates_ver: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    templates_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    templates_source: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    templates_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    templates_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="idle")          # idle | working | error
    message: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    request: Mapped[dict | None] = mapped_column(JSONType)                                    # {action: update | import, by, at}: исполняет сканер


class PtLink(Base):
    """Явное решение оператора: адрес — это устройство источника KSC. Единственный надёжный способ связать результаты сканирования с устройством (совпадение имени или адреса само по себе не объединяет)."""
    __tablename__ = "pt_links"
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), primary_key=True)
    host_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    set_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    set_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)


class OvalDef(Base):
    """Определение OVAL (уязвимость или исправление): идентификатор, версия, CVE и условия в сжатом виде. Хранится отдельно от записей баз уязвимостей; проверки выполняются только для поддерживаемых типов условий."""
    __tablename__ = "oval_defs"
    feed: Mapped[str] = mapped_column(String(60), primary_key=True)
    def_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    klass: Mapped[str] = mapped_column(String(14), nullable=False, default="vulnerability")
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="")
    cves: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    platforms: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    criteria: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)          # дерево условий: {op, negate, items: [... | {test: id}]}
    tests: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)             # id теста → {kind, name, op, evr, arch}; неподдерживаемые — {kind, unsupported: причина}
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ix_oval_defs_feed", "feed"),)


class OvalCve(Base):
    """Индекс «CVE → определения OVAL» для быстрого сопоставления с находками."""
    __tablename__ = "oval_cves"
    cve: Mapped[str] = mapped_column(String(40), primary_key=True)
    feed: Mapped[str] = mapped_column(String(60), primary_key=True)
    def_id: Mapped[str] = mapped_column(String(120), primary_key=True)


# ------------------------------------------------------------------------------------------------ BI-выгрузки: владельцы устройств и история принадлежности
class BiSource(Base):
    """BI-система: регулярная Excel-выгрузка «сотрудник × устройство» на SMB (только чтение). Данные разных подключений не смешиваются: каждая запись ниже принадлежит одному источнику."""
    __tablename__ = "bi_sources"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="excel_smb")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    smb_host: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    smb_port: Mapped[int] = mapped_column(Integer, nullable=False, default=445)
    smb_share: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    smb_path: Mapped[str] = mapped_column(String(500), nullable=False, default="")             # папка внутри общего ресурса
    username: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    password_enc: Mapped[str | None] = mapped_column(Text)
    smb_encrypt: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)            # требовать шифрование SMB 3.x
    file_mode: Mapped[str] = mapped_column(String(8), nullable=False, default="fixed")          # fixed — одно имя; auto — новейший подходящий по маске
    file_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")             # имя файла или маска
    schedule_time: Mapped[str] = mapped_column(String(5), nullable=False, default="06:00")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")             # часовой пояс расписания и дат без пояса в выгрузке
    profile: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)               # сопоставление столбцов: sheet, columns {поле: заголовок}, origin [заголовки], generic_names
    options: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)               # проверки, частичный импорт, хранение исходных файлов, повторы
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    request: Mapped[dict | None] = mapped_column(JSONType)                                     # запуск по требованию: {at, by, force, upload, match}
    last_try_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_ok_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                           # последнее успешное получение (в том числе «изменений нет»)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)                              # последний опубликованный снимок: его данные видят страницы
    fail_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    match_stamp: Mapped[str] = mapped_column(String(600), nullable=False, default="")           # снимок и поколения данных KSC, по которым выполнено сопоставление
    matched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class BiImport(Base):
    """Получение файла: что прочитано, сколько записей новых, изменённых, без изменений и отклонённых, чем закончилось."""
    __tablename__ = "bi_imports"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bi_sources.id", ondelete="CASCADE"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    trigger: Mapped[str] = mapped_column(String(10), nullable=False, default="schedule")       # schedule | manual | upload
    by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    file_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    file_mtime: Mapped[datetime | None] = mapped_column(UTCDateTime)
    snapshot_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                          # дата снимка (изменение файла): дата наблюдения для истории
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")          # содержание без оформления и порядка строк
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="running")        # running | ok | partial | unchanged | rejected | failed
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rows_read: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_valid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_new: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_same: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_gone: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_empty: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    persons_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    headers: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    errors: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)               # отклонённые строки: [{row, field, reason}] (ограниченно)
    warnings: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)             # [{code, text, n}]
    ms: Mapped[int | None] = mapped_column(Integer)
    stored: Mapped[str] = mapped_column(String(300), nullable=False, default="")                # копия исходного файла (пусто — удалена по сроку хранения)
    __table_args__ = (Index("ix_bi_imports_src", "source_id", "started_at"),)


class BiPerson(Base):
    """Сотрудник по данным одного BI-источника: ключ — рабочая почта, без неё — ФИО."""
    __tablename__ = "bi_persons"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bi_sources.id", ondelete="CASCADE"), nullable=False)
    pkey: Mapped[str] = mapped_column(String(330), nullable=False)
    full_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    department: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    account_created: Mapped[datetime | None] = mapped_column(UTCDateTime)                      # дата создания учётной записи (не дата начала владения устройством)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)               # есть в последнем опубликованном снимке
    search: Mapped[str] = mapped_column(String(1000), nullable=False, default="")              # ФИО, почта, подразделение (строчные)
    __table_args__ = (Index("ux_bi_persons_key", "source_id", "pkey", unique=True),)


class BiDevice(Base):
    """Устройство по данным BI. Ключ — устойчивый идентификатор, если источник его передаёт; иначе — короткое имя. Условные имена («Личный ПК») — отдельное устройство на сотрудника."""
    __tablename__ = "bi_devices"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bi_sources.id", ondelete="CASCADE"), nullable=False)
    dkey: Mapped[str] = mapped_column(String(700), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    short: Mapped[str] = mapped_column(String(300), nullable=False, default="")                # короткое имя в нижнем регистре (сопоставление с KSC)
    names: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)                # прежние имена: [{name, first, last}]
    generic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)              # условное имя: с KSC по имени не сопоставляется
    os: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    os_family: Mapped[str] = mapped_column(String(8), nullable=False, default="")              # windows | linux | mac | ""
    personal: Mapped[bool | None] = mapped_column(Boolean)
    av: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)                   # сведения BI об антивирусе: {uses, other, origin, raw}
    owners_now: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                # сотрудников за устройством в последнем снимке
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    search: Mapped[str] = mapped_column(String(1500), nullable=False, default="")              # текущее и прежние имена (строчные)
    __table_args__ = (Index("ux_bi_devices_key", "source_id", "dkey", unique=True), Index("ix_bi_devices_short", "source_id", "short"))


class BiOwner(Base):
    """Соответствие «устройство × сотрудник» по снимкам BI. first/last_seen — даты выгрузок, в которых связь наблюдалась (не даты передачи устройства);
    owned_from/owned_to — только если источник сам передаёт период владения."""
    __tablename__ = "bi_owners"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bi_sources.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("bi_devices.id", ondelete="CASCADE"), nullable=False)
    person_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("bi_persons.id", ondelete="CASCADE"), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    first_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    last_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    seen_n: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    src_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)                          # последняя достоверная дата наблюдения из самой выгрузки (даты из будущего не берутся)
    owned_from: Mapped[datetime | None] = mapped_column(UTCDateTime)
    owned_to: Mapped[datetime | None] = mapped_column(UTCDateTime)
    confidence: Mapped[str] = mapped_column(String(8), nullable=False, default="medium")      # high | medium | low
    basis: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    __table_args__ = (Index("ux_bi_owners_pair", "device_id", "person_id", unique=True), Index("ix_bi_owners_person", "person_id"), Index("ix_bi_owners_src", "source_id", "present"))


class BiRecord(Base):
    """Нормализованная запись выгрузки. Без изменений запись не копируется: продлевается last_import_id; изменилась — новая версия (прежняя остаётся в истории)."""
    __tablename__ = "bi_records"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bi_sources.id", ondelete="CASCADE"), nullable=False)
    rkey: Mapped[str] = mapped_column(String(40), nullable=False)                               # устройство × сотрудник
    rhash: Mapped[str] = mapped_column(String(40), nullable=False)
    device_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    person_id: Mapped[int | None] = mapped_column(BigInteger)
    first_import_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    last_import_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    row_n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)                      # номер строки в файле, где версия появилась
    attrs: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    flags: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    __table_args__ = (Index("ix_bi_records_key", "source_id", "rkey", "last_import_id"), Index("ix_bi_records_dev", "device_id"))


class BiMatch(Base):
    """Сопоставление устройства BI с компьютером KSC: auto — предполагаемое (имя и подтверждающие признаки), confirmed/rejected — решение администратора;
    candidate/ambiguous/conflict — не сопоставлено (только имя, несколько компьютеров, противоречие)."""
    __tablename__ = "bi_matches"
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("bi_devices.id", ondelete="CASCADE"), nullable=False)
    bi_source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bi_sources.id", ondelete="CASCADE"), nullable=False)
    ksc_source_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("ksc_sources.id", ondelete="CASCADE"), nullable=False)
    host_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    host_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    level: Mapped[str] = mapped_column(String(10), nullable=False)
    signals: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)              # основание: какие признаки совпали или противоречат
    issues: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)               # расхождения BI и KSC: [{code, text}]
    decided_by: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    __table_args__ = (Index("ux_bi_matches_pair", "device_id", "ksc_source_id", "host_id", unique=True), Index("ix_bi_matches_host", "ksc_source_id", "host_id"), Index("ix_bi_matches_src", "bi_source_id", "level"))
