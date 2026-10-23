from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    login: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=512)


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    role: str
    is_admin: bool
    local: bool


class MeOut(BaseModel):
    user: UserOut
    csrf_token: str
    must_change_password: bool
    current_source_id: str | None
    site_name: str


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9._-]+$")
    port: int = Field(default=1433, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=128, pattern=r"^[\w.$-]+$")
    auth_type: str = Field(default="sql", pattern=r"^(sql|windows)$")
    username: str = Field(min_length=1, max_length=256)
    password: str | None = None            # None — не менять; "" — очистить
    tls_mode: str = Field(default="require", pattern=r"^(require|request|off)$")
    trust_server_cert: bool = True
    connect_timeout_s: int = Field(default=10, ge=1, le=120)
    query_timeout_s: int = Field(default=60, ge=5, le=3600)
    is_active: bool = True


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(default="", max_length=300)
    email: str | None = Field(default=None, max_length=320)
    role: str = Field(default="viewer", pattern=r"^(admin|analyst|viewer)$")
    password: str | None = None
    is_active: bool = True
    all_sources: bool = True
    source_ids: list[str] = []
    must_change_password: bool = True


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=300)
    email: str | None = Field(default=None, max_length=320)
    role: str | None = Field(default=None, pattern=r"^(admin|analyst|viewer)$")
    password: str | None = None
    is_active: bool | None = None
    all_sources: bool | None = None
    source_ids: list[str] | None = None
    must_change_password: bool | None = None


class RuleIn(BaseModel):
    key: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=120)
    name_like: str = Field(min_length=1, max_length=200)
    name_regex: str = Field(min_length=1, max_length=2000)
    branch_regex: str | None = Field(default=None, max_length=2000)
    branch_parts: int = Field(default=2, ge=1, le=4)
    exclude_regex: str | None = Field(default=None, max_length=2000)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool = True


class ReportParams(BaseModel):
    """Параметры отчёта: выбор программ (идентификаторы, правило + ветки, шаблон названия), диапазон версий, активность, платформа, группа."""
    product_ids: list[int] = []
    rule: str | None = Field(default=None, max_length=64)
    branches: list[str] = []
    name_like: str | None = Field(default=None, max_length=200)
    name_regex: str | None = Field(default=None, max_length=2000)
    min_version: str | None = Field(default=None, max_length=100)
    max_version: str | None = Field(default=None, max_length=100)
    below_version: str | None = Field(default=None, max_length=100)
    platform: str | None = Field(default=None, pattern=r"^(windows|linux)?$")
    group_contains: str | None = Field(default=None, max_length=200)
    active_days: int | None = Field(default=None, ge=1, le=3650)
    include_inactive: bool = False
    inactive_only: bool = False
    q: str | None = Field(default=None, max_length=200)
    os_contains: str | None = Field(default=None, max_length=200)


class ReportIn(BaseModel):
    kind: str = Field(pattern=r"^(software_hosts|hosts)$")
    title: str = Field(default="", max_length=300)
    params: ReportParams


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern=r"^(software_hosts|hosts)$")
    params: ReportParams
    shared: bool = True


class CheckIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    selection: ReportParams
    cve: str | None = Field(default=None, max_length=300)
    severity: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    description: str | None = Field(default=None, max_length=4000)
    comment: str | None = Field(default=None, max_length=4000)
