"""Сетевое обнаружение для инвентаризации: задание сканера Pentest (профиль `netscan`) по подсетям и классификация найденных узлов.

Сканирует только сканер Pentest (своей очереди и запуска nmap здесь нет); область — `PentestSettings.allowed_networks`. Результат готового задания
переносится в источник инфраструктуры вида `netscan` (сопоставление и сверка — общие, `infra/sync.py`). Тип узла — эвристика по открытым портам и ответам
служб; ОС без привилегий NET_RAW nmap не определяет — берётся из ответов служб (SSH, SMB, HTTP), иначе «не определена».
"""
from __future__ import annotations

import asyncio
import re
import socket
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InfraSource, PtHost, PtJob, PtPort, utcnow
from ..pentest import service as S
from ..pentest import targets as T
from . import connectors as K
from . import sync as IS

PROFILE = "netscan"
PORTS = "22,23,25,53,80,88,135,139,389,443,445,515,631,902,1433,3306,3389,5432,5900,5985,8006,8080,8443,9100"
KIND_RU = {"server": "Сервер", "workstation": "Компьютер", "printer": "Принтер или МФУ", "network": "Сетевое устройство", "host": "Узел (тип не определён)"}
FINISHED = ("done", "partial")
_NET = re.compile(r"cisco|mikrotik|routeros|juniper|huawei|vrp|eltex|d-link|tp-link|zyxel|ubiquiti|edgeos|fortinet|fortigate|aruba|procurve|hp switch|keenetic|snmp", re.I)
_PRN = re.compile(r"printer|jetdirect|cups|ipp|laserjet|kyocera|xerox|ricoh|canon|brother|epson|lexmark|konica|pantum", re.I)
_WIN = re.compile(r"windows|microsoft", re.I)
_LIN = re.compile(r"linux|ubuntu|debian|red ?hat|centos|astra|alt ?linux|redos|fedora|suse|almalinux|rocky|samba", re.I)
_SRV = re.compile(r"nginx|apache|\bIIS\b|tomcat|lighttpd|postgres|mysql|mariadb|sql server|exchange|\bbind\b|openldap|postfix|exim", re.I)
SERVER_PORTS = {25, 53, 88, 389, 902, 1433, 3306, 5432, 8006}


class NetscanError(ValueError):
    """Ошибка запуска с понятным оператору текстом."""


def classify(ports: list[dict]) -> dict:
    """Тип узла и ОС по открытым портам: [{port, service, product, version, extrainfo, ostype}] → {kind, os, why}. Чистая функция."""
    nums = {int(p["port"]) for p in ports}
    text = " ".join(f"{p.get('service', '')} {p.get('product', '')} {p.get('version', '')} {p.get('extrainfo', '')} {p.get('ostype', '')}" for p in ports)
    ostypes = " ".join(p.get("ostype", "") for p in ports)
    os_ = "Windows" if _WIN.search(ostypes) or nums & {135, 139, 445, 3389, 5985} and not _LIN.search(text) else "Linux" if _LIN.search(text) else ""
    if nums & {9100, 515, 631} or _PRN.search(text):
        return {"kind": "printer", "os": "", "why": "порты печати (9100, 515, 631) или ответ службы принтера"}
    if _NET.search(text) or (nums & {23} and not nums & {135, 445, 3389}):
        return {"kind": "network", "os": "", "why": "ответ службы сетевого оборудования или Telnet без служб Windows"}
    if nums & {8006, 902}:
        return {"kind": "server", "os": os_, "why": "служба управления виртуализацией (8006, 902)"}
    if os_ == "Windows":
        srv = nums & SERVER_PORTS or _SRV.search(text)
        return {"kind": "server" if srv else "workstation", "os": os_, "why": "службы Windows" + (" и серверные службы" if srv else ", серверных служб нет")}
    if os_ == "Linux" or nums & ({22} | SERVER_PORTS) or _SRV.search(text):
        return {"kind": "server", "os": os_ or "", "why": "SSH или серверные службы"}
    return {"kind": "host", "os": os_, "why": "открытых портов, по которым можно определить тип, нет" if not nums else "по открытым портам тип не определяется"}


async def start(db: AsyncSession, *, subnets: str, title: str, settings, user_name: str, user_id, confirm_scope: bool, confirm_large: bool) -> PtJob:
    """Создать задание обнаружения в очереди сканера Pentest. Область и подтверждения — по правилам Pentest."""
    policy = T.Policy.from_settings(settings)
    try:
        plan = await asyncio.to_thread(T.build, subnets, policy, T.resolve_name, [])
    except T.TargetError as exc:
        raise NetscanError(str(exc)) from None
    try:
        opts = S.check_options(settings, "custom", PORTS, "on", 2, False, plan, confirm_scope, confirm_large, scan=None, engine_ready=False)
    except S.JobError as exc:
        raise NetscanError(str(exc)) from None
    opts["scan"] = {"preset": PROFILE, "nse": False, "nse_groups": [], "nuclei": False, "cats": [], "active": False}
    opts["netscan"] = {"ingested": False}
    job = await S.create_job(db, title=title.strip() or f"Обнаружение: {' '.join(subnets.split())[:80]}", text=subnets, plan=plan, profile="custom", options=opts,
                             user_name=user_name, user_id=user_id)
    job.profile = PROFILE
    await db.flush()
    return job


async def _rdns(ips: list[str]) -> dict[str, str]:
    sem = asyncio.Semaphore(16)

    async def one(ip: str) -> tuple[str, str]:
        async with sem:
            try:
                return ip, (await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), 3))[0]
            except (OSError, TimeoutError):
                return ip, ""

    return dict(await asyncio.gather(*(one(i) for i in ips)))


async def hosts(db: AsyncSession, job_id: uuid.UUID) -> list[dict]:
    """Найденные узлы задания с классификацией: только ответившие (есть открытые порты или ответ на обнаружение)."""
    rows = [h for h in (await db.execute(select(PtHost).where(PtHost.job_id == job_id, PtHost.state.in_(("done", "up", "svc", "chk"))))).scalars()]
    ports: dict[str, list[dict]] = {}
    for p in (await db.execute(select(PtPort).where(PtPort.job_id == job_id))).scalars():
        ports.setdefault(p.ip, []).append({"port": p.port, "service": p.service, "product": p.product, "version": p.version, "extrainfo": p.extrainfo, "ostype": p.ostype})
    out = []
    for h in rows:
        ps = sorted(ports.get(h.ip, []), key=lambda x: x["port"])
        out.append({"ip": h.ip, "names": list(h.names or []), "ports": ps, **classify(ps)})
    return sorted(out, key=lambda x: tuple(int(o) for o in x["ip"].split(".")) if "." in x["ip"] else (999, x["ip"]))


async def source(db: AsyncSession) -> InfraSource:
    """Единственный источник «Сетевое обнаружение» (создаётся при первом переносе; без расписания и секрета)."""
    src = (await db.execute(select(InfraSource).where(InfraSource.kind == PROFILE).limit(1))).scalar_one_or_none()
    if src is None:
        src = InfraSource(name="Сетевое обнаружение", kind=PROFILE, enabled=True, url="", every_min=1440)
        db.add(src)
        await db.flush()
    return src


async def ingest(db: AsyncSession, job: PtJob) -> dict:
    """Перенести узлы готового задания в источник `netscan`: объекты по IP, сопоставление с учётом. Узлы вне охвата задания не помечаются исчезнувшими."""
    found = await hosts(db, job.id)
    names = await _rdns([h["ip"] for h in found if not h["names"]])
    objs = []
    for h in found:
        name = (h["names"] or [names.get(h["ip"], "")])[0] or h["ip"]
        fqdn = name if "." in name and not name.replace(".", "").isdigit() else ""
        objs.append(K.obj(f"ip:{h['ip']}", h["kind"], name, fqdn=fqdn, ips=[h["ip"]], os=h["os"], available="да",
                          ports=", ".join(str(p["port"]) for p in h["ports"])[:300], detected=h["why"], job=str(job.id)))
    src = await source(db)
    st = await IS.store(db, src, objs, partial=True)
    st.update(await IS.match(db, src))
    src.last_ok_at = src.last_try_at = utcnow()
    src.last_stats, src.last_error = st, ""
    job.options = {**(job.options or {}), "netscan": {**(job.options or {}).get("netscan", {}), "ingested": True, "stats": st}}
    await db.flush()
    return st


async def pending(db: AsyncSession) -> list[PtJob]:
    """Готовые задания обнаружения, ещё не перенесённые в инфраструктуру."""
    jobs = (await db.execute(select(PtJob).where(PtJob.profile == PROFILE, PtJob.status.in_(FINISHED)).order_by(PtJob.finished_at.desc()).limit(20))).scalars()
    return [j for j in jobs if not ((j.options or {}).get("netscan") or {}).get("ingested")]
