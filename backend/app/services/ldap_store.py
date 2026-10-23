"""Подключения к каталогу, доверенные сертификаты и правила доступа по группам (внутренняя база). Пароль сервисной записи зашифрован (AAD — подключение)
и наружу не отдаётся: только признак «задан». Перенос настройки LDAP из 0.1.0 (одно подключение в app_settings) выполняется при запуске."""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.ldap import Directory, LdapConfig, LdapIdentity
from ..models import AccessRule, AppSetting, CaCertificate, KscSource, LdapConnection, utcnow
from ..security import certs
from .settings import SettingsError, SettingsService

log = logging.getLogger("app.ldap")
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ATTR = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_NETBIOS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
URL_RX = re.compile(r"^(ldaps?)://([^/:]+)(?::(\d+))?/?$", re.I)


def aad(cid) -> bytes:
    return f"ldap_connection.{cid}".encode()


def clean(data: dict) -> dict:
    """Проверка формы подключения. LDAPS URL (ldaps://dc1.example.local:636) заполняет протокол, адрес и порт."""
    out: dict = {}
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 120:
        raise SettingsError("Отображаемое название: от 1 до 120 символов")
    out["name"] = name
    url = str(data.get("url") or "").strip()
    host, port, proto = str(data.get("host") or "").strip(), data.get("port"), str(data.get("protocol") or "ldaps")
    if url:
        m = URL_RX.match(url)
        if not m:
            raise SettingsError("LDAPS URL: ldaps://сервер:636 (или ldap://сервер:389 для STARTTLS)")
        proto = "ldaps" if m.group(1).lower() == "ldaps" else "starttls"
        host = m.group(2)
        port = int(m.group(3)) if m.group(3) else (636 if proto == "ldaps" else 389)
    if proto not in ("ldaps", "starttls"):
        raise SettingsError("Протокол: LDAPS (порт 636) или STARTTLS (порт 389). Нешифрованный LDAP не поддерживается")
    if not _HOST.match(host):
        raise SettingsError("Адрес контроллера домена: имя или IP без схемы и слэшей, например dc1.example.local")
    try:
        port = int(port or (636 if proto == "ldaps" else 389))
    except (TypeError, ValueError):
        raise SettingsError("Порт: число от 1 до 65535") from None
    if not 1 <= port <= 65535:
        raise SettingsError("Порт: число от 1 до 65535")
    out.update(protocol=proto, host=host, port=port)
    v = int(data.get("ldap_version") or 3)
    if v not in (2, 3):
        raise SettingsError("Версия LDAP: 3 (рекомендуется) или 2")
    t = int(data.get("timeout_s") or 5)
    if not 1 <= t <= 60:
        raise SettingsError("Сетевой тайм-аут: от 1 до 60 секунд")
    out.update(ldap_version=v, timeout_s=t)
    base = str(data.get("base_dn") or "").strip()
    if not base or "=" not in base or len(base) > 500:
        raise SettingsError("Base DN: например, DC=example,DC=local")
    out["base_dn"] = base
    dom = str(data.get("domain_dns") or "").strip().lower()
    if dom and not _DOMAIN.match(dom):
        raise SettingsError("DNS-имя домена: например, example.local")
    nb = str(data.get("netbios") or "").strip().upper()
    if nb and not _NETBIOS.match(nb):
        raise SettingsError("NetBIOS-имя домена: до 15 символов, например EXAMPLE")
    out.update(domain_dns=dom, netbios=nb)
    bind = str(data.get("bind_dn") or "").strip()
    if not bind or len(bind) > 500:
        raise SettingsError("Сервисная учётная запись: DN (CN=svc-kavcheck,OU=…) или user@домен")
    out["bind_dn"] = bind
    for k, d in (("login_attribute", "sAMAccountName"), ("display_name_attribute", "displayName"), ("email_attribute", "mail")):
        val = str(data.get(k) or d).strip()
        if not _ATTR.match(val):
            raise SettingsError("Имя атрибута LDAP: латиница и цифры, например sAMAccountName")
        out[k] = val
    flt = str(data.get("user_filter") or "(&(objectCategory=person)(objectClass=user))").strip()
    if not (flt.startswith("(") and flt.endswith(")")) or flt.count("(") != flt.count(")") or len(flt) > 1000:
        raise SettingsError("Фильтр пользователей: LDAP-фильтр в скобках, например (&(objectCategory=person)(objectClass=user))")
    out["user_filter"] = flt
    out["nested_groups"] = bool(data.get("nested_groups", True))
    out["enabled"] = bool(data.get("enabled", True))
    out["is_primary"] = bool(data.get("is_primary", False))
    return out


def conn_out(c: LdapConnection) -> dict:
    return {"id": str(c.id), "name": c.name, "enabled": c.enabled, "is_primary": c.is_primary, "protocol": c.protocol, "host": c.host, "port": c.port,
            "url": f"{'ldaps' if c.protocol == 'ldaps' else 'ldap'}://{c.host}:{c.port}", "ldap_version": c.ldap_version, "timeout_s": c.timeout_s, "base_dn": c.base_dn,
            "domain_dns": c.domain_dns, "netbios": c.netbios, "bind_dn": c.bind_dn, "bind_password_set": bool(c.bind_password_enc), "login_attribute": c.login_attribute,
            "display_name_attribute": c.display_name_attribute, "email_attribute": c.email_attribute, "user_filter": c.user_filter, "nested_groups": c.nested_groups,
            "position": c.position, "last_check_at": c.last_check_at, "last_check_ok": c.last_check_ok, "created_at": c.created_at, "updated_at": c.updated_at}


def cert_out(c: CaCertificate) -> dict:
    now = datetime.now(timezone.utc)
    return {"id": str(c.id), "label": c.label, "subject": c.subject, "issuer": c.issuer, "serial": c.serial, "sha256": c.sha256, "not_before": c.not_before,
            "not_after": c.not_after, "is_ca": c.is_ca, "self_signed": c.self_signed, "type": certs.kind_label(c.is_ca, c.self_signed), "expired": c.not_after < now,
            "expires_soon": now <= c.not_after and (c.not_after - now).days < 30, "added_by": c.added_by, "created_at": c.created_at}


def rule_out(r: AccessRule, names: dict[str, str]) -> dict:
    return {"id": str(r.id), "connection_id": str(r.connection_id) if r.connection_id else None, "connection": names.get(str(r.connection_id), "любое") if r.connection_id else "любое",
            "group_dn": r.group_dn, "role": r.role, "all_sources": r.all_sources, "source_ids": [str(x) for x in (r.source_ids or [])], "note": r.note, "created_at": r.created_at}


class LdapStore:
    def __init__(self, svc: SettingsService):
        self.svc = svc

    def encrypt(self, cid, secret: str) -> str:
        if self.svc.box is None:
            raise SettingsError("APP_MASTER_KEY не задан — пароль сохранить нельзя")
        return self.svc.box.encrypt(secret, aad=aad(cid))

    def decrypt(self, c: LdapConnection) -> str:
        if not c.bind_password_enc or self.svc.box is None:
            return ""
        try:
            return self.svc.box.decrypt(c.bind_password_enc, aad=aad(c.id))
        except Exception:  # noqa: BLE001
            return ""

    async def ca_bundle(self, db: AsyncSession) -> str:
        rows = (await db.execute(select(CaCertificate).order_by(CaCertificate.created_at))).scalars().all()
        now = datetime.now(timezone.utc)
        return "".join(r.pem if r.pem.endswith("\n") else r.pem + "\n" for r in rows if r.not_after >= now)

    def config(self, c: LdapConnection, bundle: str) -> LdapConfig:
        return LdapConfig(id=str(c.id), name=c.name, enabled=c.enabled, protocol=c.protocol, host=c.host, port=c.port, ldap_version=c.ldap_version, timeout_s=c.timeout_s,
                          base_dn=c.base_dn, domain_dns=c.domain_dns, netbios=c.netbios, bind_dn=c.bind_dn, bind_password=self.decrypt(c),
                          login_attribute=c.login_attribute, display_name_attribute=c.display_name_attribute, email_attribute=c.email_attribute,
                          user_filter=c.user_filter, nested_groups=c.nested_groups, ca_pem=bundle)

    async def connections(self, db: AsyncSession) -> list[LdapConnection]:
        return list((await db.execute(select(LdapConnection).order_by(LdapConnection.is_primary.desc(), LdapConnection.position, LdapConnection.name))).scalars().all())

    async def directory(self, db: AsyncSession) -> Directory:
        bundle = await self.ca_bundle(db)
        return Directory([self.config(c, bundle) for c in await self.connections(db) if c.enabled])

    async def rules(self, db: AsyncSession) -> list[AccessRule]:
        return list((await db.execute(select(AccessRule).order_by(AccessRule.created_at))).scalars().all())

    async def save(self, db: AsyncSession, data: dict, secret: str | None, cid: uuid.UUID | None = None) -> LdapConnection:
        clean_ = clean(data)
        other = (await db.execute(select(LdapConnection).where(LdapConnection.name == clean_["name"]))).scalar_one_or_none()
        if other is not None and other.id != cid:
            raise SettingsError("Подключение с таким названием уже есть")
        if cid is None:
            c = LdapConnection(id=uuid.uuid4(), position=int((await db.execute(select(func.coalesce(func.max(LdapConnection.position), 0)))).scalar_one()) + 1, **clean_)
            db.add(c)
        else:
            c = await db.get(LdapConnection, cid)
            if c is None:
                raise SettingsError("Подключение не найдено")
            for k, v in clean_.items():
                setattr(c, k, v)
            c.updated_at = utcnow()
        if secret is not None:
            c.bind_password_enc = self.encrypt(c.id, secret) if secret else None
        if c.is_primary:                     # основное подключение — одно
            for o in await self.connections(db):
                if o.id != c.id and o.is_primary:
                    o.is_primary = False
        if not c.bind_password_enc:
            raise SettingsError("Укажите пароль сервисной учётной записи")
        await db.flush()
        return c

    async def add_certs(self, db: AsyncSession, data: bytes, label: str, actor: str, *, confirm_non_ca: bool = False, preview: bool = False) -> tuple[list[certs.CertInfo], list[certs.CertInfo]]:
        infos = certs.parse(data)
        now = datetime.now(timezone.utc)
        if not preview:
            non_ca = [i for i in infos if not i.is_ca]
            if non_ca and not confirm_non_ca:
                raise certs.CertError("Это не сертификат удостоверяющего центра (CA). Для проверки цепочки нужен корневой или промежуточный CA. Если вы уверены, подтвердите добавление.")
            if all(i.not_after < now for i in infos):
                raise certs.CertError("Срок действия сертификата истёк — добавлять его нет смысла.")
        have = set((await db.execute(select(CaCertificate.sha256))).scalars().all())
        added, existing = [], []
        for i in infos:
            if i.sha256 in have:
                existing.append(i)
                continue
            added.append(i)
            if not preview:
                db.add(CaCertificate(label=(label or "").strip()[:200] or i.subject[:200], subject=i.subject[:1000], issuer=i.issuer[:1000], serial=i.serial[:100], sha256=i.sha256,
                                     not_before=i.not_before, not_after=i.not_after, is_ca=i.is_ca, self_signed=i.self_signed, pem=i.pem, added_by=actor))
        await db.flush()
        return added, existing

    @staticmethod
    def decide(rules: list[AccessRule], ident: LdapIdentity) -> "Decision":
        matched = [r for r in rules if (r.connection_id is None or str(r.connection_id) == ident.connection_id) and r.group_dn.strip().lower() in ident.groups]
        if not matched:
            return Decision(None, False, frozenset(), [])
        role = max((r.role for r in matched), key=lambda x: ROLE_RANK.get(x, 0))
        all_src = any(r.all_sources for r in matched)
        ids = frozenset(str(s) for r in matched for s in (r.source_ids or []))
        return Decision(role, all_src, ids, matched)

    async def migrate_legacy(self, db: AsyncSession) -> bool:
        """Перенос единственного подключения 0.1.0 (app_settings «ldap»): подключение, CA, группы администраторов, аналитиков и просмотра → правила доступа."""
        if (await db.execute(select(func.count()).select_from(LdapConnection))).scalar_one():
            return False
        row = await db.get(AppSetting, "ldap")
        v = dict(row.value or {}) if row else {}
        if not v.get("host") or v.get("migrated"):
            return False
        old_pw = self.svc.decrypt(v.get("bind_password_enc"), "ldap.bind_password")
        proto = "starttls" if v.get("protocol") == "starttls" else "ldaps"
        cid = uuid.uuid4()
        c = LdapConnection(id=cid, name="Основной домен", enabled=bool(v.get("enabled")), is_primary=True, protocol=proto, host=str(v["host"]), port=int(v.get("port") or 636),
                           ldap_version=3, timeout_s=int(v.get("timeout_s") or 5), base_dn=str(v.get("base_dn") or ""), domain_dns="", netbios="",
                           bind_dn=str(v.get("bind_dn") or ""), bind_password_enc=self.encrypt(cid, old_pw) if old_pw and self.svc.box else None,
                           login_attribute=str(v.get("login_attribute") or "sAMAccountName"), display_name_attribute=str(v.get("display_name_attribute") or "displayName"),
                           email_attribute=str(v.get("email_attribute") or "mail"), user_filter="(&(objectCategory=person)(objectClass=user))",
                           nested_groups=bool(v.get("nested_groups", True)), position=1)
        db.add(c)
        if v.get("ca_pem"):
            try:
                await self.add_certs(db, str(v["ca_pem"]).encode(), "Перенесено из настроек 0.1.0", "миграция", confirm_non_ca=True)
            except certs.CertError:
                log.warning("CA из прежних настроек LDAP не перенесён")
        for key, role in (("admin_group_dn", "admin"), ("analyst_group_dn", "analyst"), ("viewer_group_dn", "viewer")):
            if v.get(key):
                db.add(AccessRule(group_dn=str(v[key]), role=role, all_sources=True, note="Перенесено из настроек 0.1.0"))
        row.value = {**v, "migrated": True}
        await db.commit()
        log.info("Настройки LDAP 0.1.0 перенесены в подключение «Основной домен»")
        return True

    async def source_names(self, db: AsyncSession) -> dict[str, str]:
        return {str(s.id): s.name for s in (await db.execute(select(KscSource))).scalars().all()}


@dataclass(frozen=True)
class Decision:
    role: str | None
    all_sources: bool
    source_ids: frozenset[str]
    rules: list
