from __future__ import annotations

import re
import uuid
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class LoginIn(BaseModel):
    login: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=512)
    domain: str = Field(default="", max_length=64)        # подключение LDAPS, выбранное на странице входа; пусто — определить по имени


class TotpLoginIn(BaseModel):
    challenge: str = Field(min_length=10, max_length=200)
    code: str = Field(min_length=6, max_length=32)


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
    activity_days: int = 30
    must_enroll_totp: bool = False
    totp_enabled: bool = False
    second_factor: str | None = None
    secure_cookie: bool = False


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


class AuditItem(BaseModel):
    """Пункт проверки версий: программа (ключ каталога) или, в дополнительных настройках, шаблон названия / правило группировки."""
    kind: Literal["product", "pattern", "rule"] = "product"
    product_key: str | None = Field(default=None, max_length=160)
    product_keys: list[str] = Field(default_factory=list, max_length=100)    # несколько продуктов каталога (семейство, компоненты) с одним условием
    product_name: str | None = Field(default=None, max_length=300)
    op: Literal["lt", "le", "eq", "ge", "gt", "range", "any"] = "lt"
    value: str | None = Field(default=None, max_length=100)
    min: str | None = Field(default=None, max_length=100)
    max: str | None = Field(default=None, max_length=100)
    exclude: list[str] = Field(default_factory=list, max_length=50)
    branches: list[str] = Field(default_factory=list, max_length=100)
    target_version: str | None = Field(default=None, max_length=100)
    platform: Literal["windows", "linux", ""] | None = None
    name_like: str | None = Field(default=None, max_length=200)
    name_regex: str | None = Field(default=None, max_length=2000)
    publisher_like: str | None = Field(default=None, max_length=200)
    rule: str | None = Field(default=None, max_length=64)

    @field_validator("exclude", "branches")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        out = [x.strip()[:100] for x in v if isinstance(x, str)]
        return [x for x in out if x] if v is not None else []

    @model_validator(mode="after")
    def _check(self):
        for f in ("value", "min", "max", "target_version"):
            v = getattr(self, f)
            if v is not None:
                setattr(self, f, v.strip() or None)
        if self.kind == "product" and not self.product_key:
            raise ValueError("Выберите программу из каталога")
        if self.kind == "pattern" and not (self.name_like or self.name_regex):
            raise ValueError("Укажите шаблон названия (SQL LIKE) или регулярное выражение")
        if self.kind == "rule" and not self.rule:
            raise ValueError("Укажите правило группировки")
        if self.op == "range" and not (self.min or self.max):
            raise ValueError("Для диапазона укажите хотя бы одну границу")
        if self.op not in ("range", "any") and not self.value:
            raise ValueError("Укажите версию для сравнения")
        if self.name_regex:
            try:
                re.compile(self.name_regex, re.I)
            except re.error as exc:
                raise ValueError(f"Регулярное выражение некорректно: {exc}") from None
        return self


class AuditParams(BaseModel):
    """Параметры проверки версий (вид отчёта version_audit)."""
    items: list[AuditItem] = Field(min_length=1, max_length=50)
    active_days: int | None = Field(default=None, ge=1, le=3650)
    include_inactive: bool = False
    group_contains: str | None = Field(default=None, max_length=200)


class ReportIn(BaseModel):
    kind: str = Field(pattern=r"^(software_hosts|hosts|version_audit)$")
    title: str = Field(default="", max_length=300)
    params: dict
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class PreviewIn(BaseModel):
    params: AuditParams
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    limit: int = Field(default=300, ge=1, le=20_000)     # интерфейс запрашивает все строки (в пределах max_rows) и показывает их непрерывным списком


class SavedCheckIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    params: AuditParams
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    shared: bool = True


class OverrideIn(BaseModel):
    kind: Literal["merge", "split", "rename"]
    from_key: str | None = Field(default=None, max_length=160)
    match_names: list[str] = Field(default_factory=list, max_length=200)
    to_key: str | None = Field(default=None, max_length=160)
    to_name: str | None = Field(default=None, max_length=300)
    to_publisher: str | None = Field(default=None, max_length=300)
    note: str | None = Field(default=None, max_length=1000)


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern=r"^(software_hosts|hosts|version_audit)$")
    params: dict
    shared: bool = True


class CheckIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    selection: ReportParams
    cve: str | None = Field(default=None, max_length=300)
    severity: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    description: str | None = Field(default=None, max_length=4000)
    comment: str | None = Field(default=None, max_length=4000)
