"""Настройки приложения из административной панели (таблица app_settings). Группы типизированы pydantic-моделями;
секретные поля хранятся зашифрованными (SecretBox) и наружу не отдаются — только флаг «задано». Пустая строка в PUT очищает секрет, отсутствие поля — не меняет."""
from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.ldap import LdapConfig
from ..models import AppSetting, utcnow
from ..security.secretbox import SecretBox, SecretBoxError


class SettingsError(Exception):
    pass


class _Group(BaseModel):
    SECRETS: ClassVar[tuple[str, ...]] = ()
    model_config = {"extra": "forbid"}


class GeneralSettings(_Group):
    """Общие параметры: порог активности устройств, часовой пояс, название установки."""
    site_name: str = Field(default="KAV Checker", max_length=80)
    activity_days: int = Field(default=7, ge=1, le=3650)             # устройство считается актуальным, если подключалось к KSC за N суток
    timezone: str = Field(default="UTC", max_length=64)
    report_keep_days: int = Field(default=90, ge=1, le=3650)         # сколько хранить сформированные отчёты
    journal_keep_days: int = Field(default=90, ge=1, le=3650)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("timezone: неизвестный часовой пояс (пример: Europe/Moscow)") from None
        return v


class LdapSettings(_Group):
    SECRETS: ClassVar[tuple[str, ...]] = ("bind_password",)
    enabled: bool = False
    host: str = Field(default="", max_length=253)
    port: int = Field(default=636, ge=1, le=65535)
    protocol: Literal["ldaps", "starttls", "ldap"] = "ldaps"
    base_dn: str = Field(default="", max_length=1000)
    bind_dn: str = Field(default="", max_length=1000)
    bind_password: str = ""
    user_filter: str = Field(default="(&(objectClass=user)(sAMAccountName={login}))", max_length=1000)
    group_filter: str = Field(default="(objectClass=group)", max_length=1000)
    login_attribute: str = Field(default="sAMAccountName", max_length=64)
    display_name_attribute: str = Field(default="displayName", max_length=64)
    email_attribute: str = Field(default="mail", max_length=64)
    guid_attribute: str = Field(default="objectGUID", max_length=64)
    admin_group_dn: str = Field(default="", max_length=1000)
    analyst_group_dn: str = Field(default="", max_length=1000)
    viewer_group_dn: str = Field(default="", max_length=1000)
    verify_cert: bool = True
    ca_pem: str = Field(default="", max_length=200_000)
    timeout_s: int = Field(default=5, ge=1, le=60)
    nested_groups: bool = True

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if v and not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", v):
            raise ValueError("host: имя сервера или IP без схемы и слэшей")
        return v

    @field_validator("user_filter")
    @classmethod
    def _flt(cls, v: str) -> str:
        if "{login}" not in v:
            raise ValueError("user_filter должен содержать {login}")
        return v

    def to_config(self, password: str) -> LdapConfig:
        return LdapConfig(enabled=self.enabled, host=self.host, port=self.port, protocol=self.protocol, base_dn=self.base_dn, bind_dn=self.bind_dn,
                          bind_password=password, user_filter=self.user_filter, group_filter=self.group_filter, login_attribute=self.login_attribute,
                          display_name_attribute=self.display_name_attribute, email_attribute=self.email_attribute, guid_attribute=self.guid_attribute,
                          admin_group_dn=self.admin_group_dn, analyst_group_dn=self.analyst_group_dn, viewer_group_dn=self.viewer_group_dn,
                          verify_cert=self.verify_cert, ca_pem=self.ca_pem, timeout_s=self.timeout_s, nested_groups=self.nested_groups)


class ReportsSettings(_Group):
    """Ограничения отчётов и запросов к SQL Server."""
    max_rows: int = Field(default=100_000, ge=1000, le=5_000_000)
    include_inactive_default: bool = False
    exclude_slave_servers: bool = True          # bIsSlaveServer = 1 — кластеры и подчинённые серверы, не компьютеры


GROUPS: dict[str, type[_Group]] = {"general": GeneralSettings, "ldap": LdapSettings, "reports": ReportsSettings}


class SettingsService:
    def __init__(self, box: SecretBox | None):
        self.box = box

    async def _row(self, db: AsyncSession, group: str) -> AppSetting | None:
        return await db.get(AppSetting, group)

    async def raw(self, db: AsyncSession, group: str) -> dict:
        row = await self._row(db, group)
        return dict(row.value or {}) if row else {}

    async def get(self, db: AsyncSession, group: str) -> _Group:
        """Модель группы: секреты расшифрованы (для использования внутри приложения)."""
        model = GROUPS[group]
        data = await self.raw(db, group)
        for s in model.SECRETS:
            enc = data.pop(f"{s}_enc", None)
            data[s] = self.decrypt(enc, f"{group}.{s}") if enc else ""
        try:
            return model(**{k: v for k, v in data.items() if k in model.model_fields})
        except ValidationError:
            return model()

    async def public(self, db: AsyncSession, group: str) -> dict:
        """Для интерфейса: вместо секрета — флаг <имя>_set."""
        model = GROUPS[group]
        cfg = await self.get(db, group)
        out = cfg.model_dump()
        for s in model.SECRETS:
            out[f"{s}_set"] = bool(out.pop(s))
        return out

    async def update(self, db: AsyncSession, group: str, patch: dict[str, Any], *, actor: str) -> list[str]:
        model = GROUPS[group]
        cur = await self.raw(db, group)
        merged = {k: v for k, v in cur.items() if not k.endswith("_enc")}
        changed = []
        for k, v in patch.items():
            if k in model.SECRETS:
                continue
            if k not in model.model_fields:
                raise SettingsError(f"Неизвестное поле: {k}")
            if merged.get(k) != v:
                changed.append(k)
            merged[k] = v
        try:
            validated = model(**{**{s: "" for s in model.SECRETS}, **merged})
        except ValidationError as exc:
            raise SettingsError("; ".join(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors())) from None
        data = validated.model_dump()
        for s in model.SECRETS:
            data.pop(s, None)
            if s in patch and patch[s] is not None:
                if patch[s] == "":
                    data.pop(f"{s}_enc", None)
                else:
                    data[f"{s}_enc"] = self.encrypt(str(patch[s]), f"{group}.{s}")
                changed.append(s)
            elif cur.get(f"{s}_enc"):
                data[f"{s}_enc"] = cur[f"{s}_enc"]
        row = await self._row(db, group)
        if row is None:
            row = AppSetting(group=group, value=data)
            db.add(row)
        else:
            row.value = data
        row.updated_at, row.updated_by = utcnow(), actor
        await db.flush()
        return changed

    def encrypt(self, value: str, aad: str) -> str:
        if self.box is None:
            raise SettingsError("APP_MASTER_KEY не задан: секреты сохранить нельзя")
        return self.box.encrypt(value, aad=aad.encode())

    def decrypt(self, token: str | None, aad: str) -> str:
        if not token or self.box is None:
            return ""
        try:
            return self.box.decrypt(token, aad=aad.encode())
        except SecretBoxError:
            return ""

    async def ldap_config(self, db: AsyncSession) -> LdapConfig:
        cfg: LdapSettings = await self.get(db, "ldap")  # type: ignore[assignment]
        return cfg.to_config(cfg.bind_password)
