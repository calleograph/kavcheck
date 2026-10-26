"""Клиенты источников KSC: по одному SourceClient на источник (семафор параллельных запросов), пересоздаются при изменении настроек."""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..ksc.driver import ConnParams, SourceClient
from ..models import KscSource
from .settings import SettingsService


class SourceRegistry:
    def __init__(self, settings: Settings, svc: SettingsService):
        self._s, self._svc = settings, svc
        self._clients: dict[uuid.UUID, tuple[str, SourceClient]] = {}

    def params(self, src: KscSource, password: str | None = None) -> ConnParams:
        pw = password if password is not None else self._svc.decrypt(src.password_enc, f"source.{src.id}")
        return ConnParams(host=src.host, port=src.port, database=src.database, username=src.username, password=pw, tls_mode=src.tls_mode,
                          trust_server_cert=src.trust_server_cert, connect_timeout_s=src.connect_timeout_s, query_timeout_s=src.query_timeout_s)

    def client(self, src: KscSource) -> SourceClient:
        fp = f"{src.host}:{src.port}/{src.database}/{src.username}/{src.password_enc}/{src.tls_mode}/{src.query_timeout_s}/{src.connect_timeout_s}"
        got = self._clients.get(src.id)
        if got is None or got[0] != fp:
            got = (fp, SourceClient(self.params(src), concurrency=self._s.ksc_concurrency, name=src.name))
            self._clients[src.id] = got
        return got[1]

    def forget(self, source_id: uuid.UUID) -> None:
        self._clients.pop(source_id, None)


def _norm_host(h: str) -> str:
    return (h or "").strip().lower().rstrip(".")


def find_overlaps(sources: list[KscSource]) -> dict[str, list[dict]]:
    """Подключения, которые, возможно, ведут к одному и тому же KSC (дубли в общей статистике): id источника → [{other, level, reason}].
    exact — совпадают сервер, порт и база; likely — по последней проверке совпадают имя сервера SQL, база, версия KSC и число устройств, хотя адреса разные (имя и IP, разные имена одного сервера).
    Только предупреждение: данные не объединяются и не удаляются; администратор решает сам. Независимые KSC с одинаковыми именами компьютеров дублями не считаются."""
    out: dict[str, list[dict]] = {}
    for i, a in enumerate(sources):
        for b in sources[i + 1:]:
            hit = None
            if (_norm_host(a.host), a.port, (a.database or "").lower()) == (_norm_host(b.host), b.port, (b.database or "").lower()):
                hit = ("exact", "совпадают сервер, порт и база данных")
            else:
                ia, ib = (a.last_check or {}).get("server_identity"), (b.last_check or {}).get("server_identity")
                ha, hb = (a.last_check or {}).get("hosts"), (b.last_check or {}).get("hosts")
                if ia and ib and ia == ib and ia.get("server") and ha and ha == hb and (a.last_check or {}).get("ksc_version") == (b.last_check or {}).get("ksc_version"):
                    hit = ("likely", f"по последней проверке совпадают сервер SQL «{ia['server']}», база, версия KSC и число устройств ({ha})")
            if hit:
                out.setdefault(str(a.id), []).append({"other": b.name, "other_id": str(b.id), "level": hit[0], "reason": hit[1]})
                out.setdefault(str(b.id), []).append({"other": a.name, "other_id": str(a.id), "level": hit[0], "reason": hit[1]})
    return out


def source_out(src: KscSource, *, full: bool = False) -> dict:
    out = {"id": str(src.id), "name": src.name, "host": src.host, "port": src.port, "database": src.database, "is_active": src.is_active,
           "last_check_at": src.last_check_at, "last_check_ok": src.last_check_ok, "ksc_version": (src.last_check or {}).get("ksc_version"),
           "features": {k: v.get("ok") for k, v in ((src.last_check or {}).get("features") or {}).items()}}
    if full:
        out.update({"auth_type": src.auth_type, "username": src.username, "password_set": bool(src.password_enc), "tls_mode": src.tls_mode,
                    "trust_server_cert": src.trust_server_cert, "connect_timeout_s": src.connect_timeout_s, "query_timeout_s": src.query_timeout_s,
                    "position": src.position, "last_check": src.last_check, "created_at": src.created_at})
    return out


async def visible_sources(db: AsyncSession, su) -> list[KscSource]:
    from sqlalchemy import select  # noqa: PLC0415

    rows = (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position, KscSource.name))).scalars().all()
    return [s for s in rows if su.can_use_source(s.id)]
