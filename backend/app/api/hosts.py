from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import SessionUser, current_source, get_db, require_user
from ..ksc import hosts as H
from ..ksc import protection as P
from ..ksc import queries as q
from ..ksc.driver import KscError
from ..models import KscSource
from .vulns import unsupported

router = APIRouter(prefix="/hosts", tags=["hosts"])



def _ksc(exc: KscError) -> HTTPException:
    return HTTPException(status_code=502 if exc.code in ("connect", "auth", "query") else 422, detail={"code": exc.code, "message": exc.message})


@router.get("")
async def hosts(request: Request, q_: str = Query("", alias="q", max_length=200), group: str = Query("", max_length=200), os: str = Query("", max_length=200),
                activity: str = Query("active", pattern=r"^(all|active|inactive)$"), days: int | None = Query(None, ge=1, le=3650), sort: str = "name", desc: bool = False, zone: str = Query("", max_length=40),
                offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Компьютеры источника: имя, IP, ОС, группа, последнее подключение к KSC и статус активности.
    По умолчанию (activity=active) — только подключавшиеся к KSC за порог глобального фильтра; hidden — сколько при этом скрыто."""
    client = request.app.state.sources.client(src)
    general = await request.app.state.settings_svc.get(db, "general")
    rcfg = await request.app.state.settings_svc.get(db, "reports")
    active_days = days or general.activity_days
    users_ok = unsupported(src, "users") is None and "users" in ((src.last_check or {}).get("features") or {})          # логин ищем, только если проверка источника подтвердила таблицы пользователей
    where, params = H.hosts_where(qtext=q_, group_contains=group, os_contains=os, active_days=active_days if activity != "all" else None, inactive_only=activity == "inactive",
                                  exclude_slaves=rcfg.exclude_slave_servers, search_users=users_ok)
    zsql = ""
    if zone:        # фильтр «Зона ответственности»: компьютеры зоны по сетям, группам и закреплениям
        from .zones import zone_host_ids  # noqa: PLC0415

        zids = sorted(await zone_host_ids(request, db, src, zone))
        if len(zids) > 30_000:
            raise HTTPException(status_code=422, detail="В зоне больше 30 000 компьютеров: сузьте зону или используйте отчёт")
        zsql = f" AND h.nId IN ({q.ids_list(zids)})" if zids else " AND 1 = 0"
    try:
        rows = await client.run(q.HOSTS_PAGE.format(where=where + zsql, order=H.hosts_order(sort, desc)), {**params, "offset": offset, "limit": limit}, max_rows=limit)
        total = int((await client.run(q.HOSTS_COUNT.format(where=where + zsql), params, max_rows=1))[0]["n"])
        hidden = 0
        if activity == "active":
            w_all, p_all = H.hosts_where(qtext=q_, group_contains=group, os_contains=os, exclude_slaves=rcfg.exclude_slave_servers, search_users=users_ok)
            w_all += zsql
            hidden = int((await client.run(q.HOSTS_COUNT.format(where=w_all), p_all, max_rows=1))[0]["n"]) - total
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    items = [H.host_row(h, None, now) for h in rows]
    from .zones import zone_labels  # noqa: PLC0415

    await zone_labels(db, src, items)
    return {"items": items, "total": total, "hidden": hidden, "offset": offset, "limit": limit, "activity_days": active_days, "fetched_at": now}


@router.get("/{host_id}")
async def host(host_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    client = request.app.state.sources.client(src)
    feats = (src.last_check or {}).get("features") or {}
    try:
        rows = await client.run(q.HOST_ONE, {"id": host_id}, max_rows=1)
        if not rows:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        groups = await H.groups_map(client)
        software = await client.run(q.SOFTWARE_ON_HOST, {"id": host_id}, max_rows=20_000)
        kaspersky = await client.run(q.KASPERSKY_ON_HOST, {"id": host_id}, max_rows=100) if feats.get("protection", {}).get("ok", True) else []
        status = await client.run(q.HOST_STATUS, {"id": host_id}, max_rows=1) if feats.get("protection", {}).get("ok", True) else []
    except KscError as exc:
        raise _ksc(exc) from None
    now = datetime.now(timezone.utc)
    h = H.host_row(rows[0], groups, now)
    h["rtp_state_label"] = P.RTP.get(h.get("rtp_state"), "")
    st = status[0] if status else None
    h["ksc_status"] = {"status": P.KSC_STATUS.get(st["status"], str(st["status"])), "reasons": [t for b, t in P.STATUS_MASK.items() if int(st["mask"] or 0) & b]} if st else None
    h["protection"] = P.host_protection(rows[0], kaspersky, st, now) if feats.get("protection", {}).get("ok", True) else None
    general = await request.app.state.settings_svc.get(db, "general")
    return {"host": h, "activity_days": general.activity_days, "fetched_at": now,
            "software": [{"install_id": int(s["install_id"]), "product_id": int(s["product_id"]), "name": s.get("name") or "", "version": s.get("version") or "", "publisher": s.get("publisher") or "",
                          "install_date": s.get("install_date"), "is_msi": bool(s.get("is_msi"))} for s in software],
            "kaspersky": [{"product_code": k.get("product_code"), "product": k.get("product") or k.get("product_code"), "build": k.get("build"), "state": P.PRODUCT_STATE.get(k.get("state"), str(k.get("state"))),
                           "av_bases_date": k.get("av_bases_date"), "is_av": bool(k.get("is_av")), "has_rtp": bool(k.get("has_rtp"))} for k in kaspersky]}


async def _host_vuln_rows(request: Request, db: AsyncSession, src: KscSource, host_id: int, external: bool) -> tuple[list[dict], list[str]]:
    """Объединённый список уязвимостей компьютера (KSC + внешние базы) и замечания. Кэшируется на короткое время: раскрытие продуктов и страницы не повторяют обращение к KSC."""
    from ..ksc import vulns as V  # noqa: PLC0415
    from ..services import hostvulns as HV  # noqa: PLC0415
    from .vdb import host_ext_items  # noqa: PLC0415
    from .vulns import unsupported  # noqa: PLC0415

    async def build() -> tuple[list[dict], list[str]]:
        client = request.app.state.sources.client(src)
        notes: list[str] = []
        ksc_items: list[dict] = []
        if unsupported(src):
            notes.append("В базе источника нет объектов уязвимостей KSC: показаны только результаты проверки по внешним базам.")
        else:
            try:
                ksc_items = await V.on_host(client, host_id)
            except KscError as exc:
                notes.append(f"Данные об уязвимостях KSC получить не удалось ({exc.message}): показаны только результаты проверки по внешним базам.")
        ext_items, catalog = [], True
        if external:
            try:       # сопоставление с внешними базами — самая долгая часть: результат кэшируется (ключ — состояние баз уязвимостей и каталога), страница сначала просит только данные KSC (`external=false`)
                from ..vdb import store as vdb_store  # noqa: PLC0415

                rev = await vdb_store.revision(db, src.id)
                (ext_items, catalog), _at = await request.app.state.cache.get((str(src.id), "host_ext", host_id, rev), request.app.state.settings.cache_ttl_seconds,
                                                                              lambda: host_ext_items(db, client, src.id, host_id))
            except KscError as exc:
                notes.append(f"Проверка по внешним базам не выполнена ({exc.message}): показаны только данные KSC.")
        if external and not catalog:
            notes.append("Каталог программ источника ещё не построен: проверка по внешним базам не выполнялась.")
        return HV.merge(ksc_items, ext_items), notes

    from ..vdb import store as vdb_store  # noqa: PLC0415

    rev = await vdb_store.revision(db, src.id) if external else ""
    (rows, notes), _at = await request.app.state.cache.get((str(src.id), "host_vulns", host_id, external, rev), min(60, request.app.state.settings.cache_ttl_seconds), build)
    return rows, list(notes)


@router.get("/{host_id}/vulnerabilities")
async def host_vulnerabilities(host_id: int, request: Request, external: bool = True, group: str = Query("", pattern="^(|product)$"), offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                               su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Уязвимости компьютера: подтверждённые KSC и найденные по внешним базам (NVD, CISA KEV, OSV, БДУ), без дублей; у каждой строки — источники обнаружения и достоверность.
    `group=product` — компактно: одна строка на установленный продукт и версию (критичность, число уникальных CVE, KEV, EOL, первые три идентификатора), страницами; полный список группы — `/vulnerabilities/items`.
    Недоступность одного источника сведений не скрывает другой: причина — в `notes`."""
    from ..services import hostvulns as HV  # noqa: PLC0415

    rows, notes = await _host_vuln_rows(request, db, src, host_id, external)
    base = {"counts": HV.counts(rows), "notes": notes, "external_checked": external, "fetched_at": datetime.now(timezone.utc)}
    if group == "product":
        eol: list[dict] = []
        try:
            from ..eol import read as EOLR  # noqa: PLC0415

            eol = await EOLR.host_items(db, src.id, host_id)
        except Exception:  # noqa: BLE001 — EOL ещё не рассчитан: колонка остаётся пустой
            eol = []
        gs = HV.groups(rows, eol)
        return {**base, "groups": gs[offset:offset + limit], "groups_total": len(gs)}
    return {**base, "items": rows[:1000]}


@router.get("/{host_id}/vulnerabilities/items")
async def host_vulnerability_items(host_id: int, request: Request, product: str = Query("", max_length=300), version: str = Query("", max_length=200), external: bool = True,
                                   offset: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=200), su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source),
                                   db: AsyncSession = Depends(get_db)):
    """Полный список уязвимостей одного продукта и версии на компьютере (по раскрытию строки), серверная пагинация."""
    from ..services import hostvulns as HV  # noqa: PLC0415

    rows, _notes = await _host_vuln_rows(request, db, src, host_id, external)
    sel = HV.group_rows(rows, "" if product == "—" else product, version)
    return {"items": sel[offset:offset + limit], "total": len(sel), "offset": offset}


@router.get("/{host_id}/hardware")
async def host_hardware(host_id: int, request: Request, su: SessionUser = Depends(require_user), src: KscSource = Depends(current_source), db: AsyncSession = Depends(get_db)):
    """Аппаратная часть компьютера по инвентаризации Агента (из KSC): процессоры, ОЗУ, накопители (физические отдельно от логических), сеть, плата. Для Linux-серверов — оценка достаточности ресурсов.
    Нет данных — «Нет данных», ложных предупреждений нет."""
    from ..ksc import hardware as HW  # noqa: PLC0415
    from .vulns import unsupported  # noqa: PLC0415

    cfg = await request.app.state.settings_svc.get(db, "hardware")
    if unsupported(src, "hardware"):
        return {"supported": False, "hw": {"known": False, "line": "Нет данных"}, "problems": [], "linux": False, "thresholds": cfg.model_dump()}
    client = request.app.state.sources.client(src)
    try:
        rows = await client.run(q.HW_HOST, {"id": host_id}, max_rows=2000)
        host = await client.run(q.HOST_ONE, {"id": host_id}, max_rows=1)
    except KscError as exc:
        raise _ksc(exc) from None
    if not host:
        raise HTTPException(status_code=404, detail="Устройство не найдено")
    hw = HW.finish(HW.summarize(rows))
    linux = host[0].get("platform_type") == 6
    problems = HW.evaluate(hw, cfg, host[0].get("name") or "") if linux and hw["known"] else []
    return {"supported": True, "hw": hw, "linux": linux, "problems": problems, "thresholds": cfg.model_dump(), "fetched_at": datetime.now(timezone.utc)}
