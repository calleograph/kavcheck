"""Конфигурация backend. Источник — только переменные окружения (compose/.env). Ничего специфичного для организации в коде нет."""
from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    app_version: str = "0.0.0"
    app_git_commit: str = "unknown"
    app_built_at: str = "unknown"
    app_public_url: str = "http://localhost:8080"
    log_level: str = "INFO"
    log_format: str = "json"           # json | console
    docs_enabled: bool = False
    data_dir: str = "/data"
    trusted_proxy_hops: int = Field(default=1, ge=1, le=10)
    allowed_origins: str = ""          # дополнительные адреса вида https://host[:port] через запятую

    # --- внутренняя база PostgreSQL (database_url имеет приоритет — для тестов)
    database_url: str | None = None
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "kavcheck"
    postgres_user: str = "kavcheck"
    postgres_password: str = ""

    # --- сессии и защита входа
    cookie_secure: bool = True
    cookie_name: str = "kavcheck_session"
    session_idle_timeout_seconds: int = Field(default=28800, ge=60)
    session_absolute_timeout_seconds: int = Field(default=86400, ge=60)
    login_max_failures: int = Field(default=10, ge=1)
    login_lockout_seconds: int = Field(default=300, ge=10)

    # --- секреты приложения: ключ шифрования паролей источников и LDAP (base64 от 32 байт), в Git не хранится
    app_master_key: str = ""

    # --- ограничения работы с SQL Server
    ksc_max_rows: int = Field(default=100000, ge=1000, le=5_000_000)   # предел строк одного отчёта
    ksc_page_max: int = Field(default=500, ge=10, le=5000)             # предел строк одной страницы API
    ksc_concurrency: int = Field(default=3, ge=1, le=32)               # одновременных запросов к одному источнику
    report_concurrency: int = Field(default=2, ge=1, le=16)            # одновременных тяжёлых отчётов у воркера
    cache_ttl_seconds: int = Field(default=600, ge=30, le=86400)       # срок актуальности кэша справочников

    @property
    def sqlalchemy_url(self) -> str | URL:
        if self.database_url:
            return self.database_url
        return URL.create("postgresql+asyncpg", username=self.postgres_user, password=self.postgres_password, host=self.postgres_host,
                          port=self.postgres_port, database=self.postgres_db)

    @property
    def reports_dir(self) -> str:
        return f"{self.data_dir.rstrip('/')}/reports"

    @property
    def allowed_origin_set(self) -> frozenset[str]:
        extra = [o.strip() for o in self.allowed_origins.split(",") if o.strip()]
        return frozenset(n for n in (normalize_origin(o) for o in [self.app_public_url, *extra]) if n)


def normalize_origin(url: str) -> str:
    """`схема://хост[:порт]` в виде, в котором Origin присылает браузер; пустая строка — адрес непригоден."""
    parts = urlsplit(url.strip())
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host or parts.username or parts.password:
        return ""
    try:
        port = parts.port
    except ValueError:
        return ""
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != (443 if scheme == "https" else 80):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def origin_allowed(origin: str, settings: Settings) -> bool:
    parts = urlsplit(origin.strip())
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return False
    normalized = normalize_origin(origin)
    return bool(normalized) and normalized in settings.allowed_origin_set


@lru_cache
def get_settings() -> Settings:
    return Settings()
