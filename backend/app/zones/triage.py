"""Обработка обнаруженных уязвимостей специалистом: подтверждение, ложное срабатывание, неактуальность, принятый риск.

Принципы:
* исходные сведения об уязвимости не удаляются — решение только определяет, показывать ли запись среди проблем, требующих внимания;
* область действия всегда явная: «эта уязвимость на этом компьютере» (по умолчанию); шире — программа (и версия) во всём источнике или зона — только осознанно;
* при совпадении побеждает самая узкая область: компьютер → программа → зона;
* решение привязано к основанию (установленная версия, идентификатор устройства): если основание изменилось, запись возвращается на повторную проверку;
* принятый риск имеет срок пересмотра; по его истечении запись снова требует внимания;
* история (кто, когда, что) хранится в БД KAV Checker и переживает обновление баз уязвимостей, повторную синхронизацию KSC и обновление приложения."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import VulnTriage, VulnTriageEvent

STATUSES = ("review", "confirmed", "false_positive", "obsolete", "risk_accepted")
STATUS_RU = {"review": "Требует проверки", "confirmed": "Подтверждена", "false_positive": "Ложное срабатывание", "obsolete": "Неактуальна", "risk_accepted": "Риск принят"}
EXCLUDED = ("false_positive", "obsolete")            # не входят в актуальные проблемы и основные показатели
SCOPES = ("host", "product", "zone")
SCOPE_RU = {"host": "эта уязвимость на этом компьютере", "product": "эта уязвимость для программы во всём источнике", "zone": "эта уязвимость во всей зоне"}
REASONS = {"fp_version": "Версия не затронута (исправление перенесено или версия вне диапазона)", "fp_product": "Сопоставление с другой программой (совпадение по названию)",
           "fp_component": "Уязвимый компонент не установлен или отключён", "fp_env": "Условие эксплуатации не выполняется в этой среде", "fixed": "Устранено (обновление, удаление программы)",
           "compensating": "Компенсирующие меры (сегментация, запрет доступа, WAF и т. п.)", "business": "Бизнес-необходимость, исправление невозможно сейчас", "other": "Другое (см. комментарий)"}
MAX_COMMENT = 4000
DEFAULT_REVIEW_DAYS = 90


class TriageError(ValueError):
    pass


@dataclass
class Decision:
    id: str
    scope: str
    status: str                 # эффективный: «review», если основание изменилось или срок истёк
    stored_status: str
    reason: str = ""
    comment: str = ""
    by: str = ""
    at: datetime | None = None
    review_until: datetime | None = None
    recheck: bool = False
    recheck_reason: str = ""
    expired: bool = False
    version: str = ""
    product: str = ""

    def public(self) -> dict:
        return {"id": self.id, "scope": self.scope, "scope_ru": SCOPE_RU[self.scope], "status": self.status, "status_ru": STATUS_RU[self.status], "stored_status": self.stored_status,
                "stored_status_ru": STATUS_RU[self.stored_status], "reason": self.reason, "reason_ru": REASONS.get(self.reason, self.reason), "comment": self.comment, "by": self.by,
                "at": self.at, "review_until": self.review_until, "recheck": self.recheck, "recheck_reason": self.recheck_reason, "expired": self.expired, "version": self.version, "product": self.product}


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


class TriageIndex:
    def __init__(self, records: list[VulnTriage], now: datetime | None = None):
        self.now = now or datetime.now(timezone.utc)
        self.by_host: dict[tuple[int, str], list[VulnTriage]] = {}
        self.by_host_name: dict[tuple[str, str], list[VulnTriage]] = {}
        self.by_product: dict[str, list[VulnTriage]] = {}
        self.by_zone: dict[tuple[str, str], list[VulnTriage]] = {}
        for r in records:
            k = r.vuln_key.upper()
            if r.scope == "host" and r.host_id is not None:
                self.by_host.setdefault((int(r.host_id), k), []).append(r)
                self.by_host_name.setdefault((_norm(r.host_name), k), []).append(r)
            elif r.scope == "product":
                self.by_product.setdefault(k, []).append(r)
            elif r.scope == "zone" and r.zone_id:
                self.by_zone.setdefault((str(r.zone_id), k), []).append(r)
        self.stale: list[tuple[VulnTriage, str]] = []        # записи, у которых основание изменилось: кого пометить в БД

    def _decision(self, r: VulnTriage, recheck_reason: str = "") -> Decision:
        until = _aware(r.review_until)
        expired = r.status == "risk_accepted" and until is not None and until < self.now
        rc = bool(r.recheck) or bool(recheck_reason)
        reason = recheck_reason or r.recheck_reason or ("срок пересмотра принятого риска истёк" if expired else "")
        eff = "review" if (rc or expired) else r.status
        return Decision(str(r.id), r.scope, eff, r.status, r.reason, r.comment, r.created_by, _aware(r.updated_at), until, rc, reason, expired, r.version, r.product)

    def lookup(self, *, host_id: int, host_name: str, keys: list[str], product: str, version: str, zone_ids: list[str]) -> Decision | None:
        """Решение для обнаружения: ключи — все идентификаторы уязвимости строки (KLA, CVE, БДУ). Самая узкая область побеждает."""
        ks = [k.upper() for k in keys if k]
        for k in ks:                                                     # компьютер
            for r in self.by_host.get((int(host_id), k), []):
                reason = ""
                if r.version and version and _norm(r.version) != _norm(version):
                    reason = f"установленная версия изменилась: {r.version} → {version}"
                    self.stale.append((r, reason))
                return self._decision(r, reason)
        for k in ks:                                                     # тот же компьютер под новым идентификатором (переустановлен Агент, перенесён в KSC)
            for r in self.by_host_name.get((_norm(host_name), k), []):
                if r.host_id is not None and int(r.host_id) != int(host_id):
                    reason = f"устройство получило новый идентификатор в KSC ({r.host_id} → {host_id})"
                    self.stale.append((r, reason))
                    return self._decision(r, reason)
        for k in ks:                                                     # программа
            for r in self.by_product.get(k, []):
                if _norm(r.product) == _norm(product) and (not r.version or _norm(r.version) == _norm(version)):
                    return self._decision(r)
        for k in ks:                                                     # зона
            for z in zone_ids:
                for r in self.by_zone.get((z, k), []):
                    return self._decision(r)
        return None


async def load(db: AsyncSession, source_id: uuid.UUID, now: datetime | None = None) -> TriageIndex:
    rows = (await db.execute(select(VulnTriage).where(VulnTriage.source_id == source_id))).scalars().all()
    return TriageIndex(list(rows), now)


def split(rows: list[dict], index: TriageIndex, *, key_fields=("kla_id", "cve_list", "vuln_key", "ids_list")) -> dict[str, list[dict]]:
    """Размечает строки обнаружений решением (row['triage']) и делит на: current (внимание: нет решения, «требует проверки», «подтверждена»), accepted (риск принят), excluded (ложные и неактуальные)."""
    out: dict[str, list[dict]] = {"current": [], "accepted": [], "excluded": []}
    for r in rows:
        keys: list[str] = []
        for f in key_fields:
            v = r.get(f)
            keys += v if isinstance(v, list) else ([v] if v else [])
        d = index.lookup(host_id=r["host_id"], host_name=r.get("name") or "", keys=keys, product=r.get("product") or r.get("program") or "", version=r.get("installed_version") or "",
                         zone_ids=r.get("zones") or [])
        r = {**r, "triage": d.public() if d else None}
        bucket = "excluded" if d and d.status in EXCLUDED else "accepted" if d and d.status == "risk_accepted" else "current"
        out[bucket].append(r)
    return out


# ------------------------------------------------------------------------------------------------ запись решений
def _event(db: AsyncSession, t: VulnTriage, actor: str, action: str, frm: str, to: str, comment: str = "") -> None:
    db.add(VulnTriageEvent(triage_id=t.id, actor=actor, action=action, from_status=frm, to_status=to, comment=comment[:MAX_COMMENT]))


def validate(status: str, scope: str, reason: str, comment: str, review_until: datetime | None) -> None:
    if status not in STATUSES:
        raise TriageError("Неизвестный статус обработки")
    if scope not in SCOPES:
        raise TriageError("Неизвестная область действия")
    if len(comment) > MAX_COMMENT:
        raise TriageError(f"Комментарий длиннее {MAX_COMMENT} символов")
    if status in ("false_positive", "obsolete", "risk_accepted") and not (comment.strip() or reason):
        raise TriageError("Укажите причину или комментарий: решение должно быть обосновано")
    if status == "risk_accepted":
        if review_until is None:
            raise TriageError("Для принятого риска нужен срок пересмотра")
        if _aware(review_until) <= datetime.now(timezone.utc):
            raise TriageError("Срок пересмотра должен быть в будущем")
    if reason and reason not in REASONS:
        raise TriageError("Неизвестная причина")


async def set_decision(db: AsyncSession, *, source_id: uuid.UUID, actor: str, scope: str, vuln_key: str, status: str, origin: str = "ksc", host_id: int | None = None, host_name: str = "",
                       zone_id: uuid.UUID | None = None, product: str = "", version: str = "", reason: str = "", comment: str = "", review_until: datetime | None = None) -> VulnTriage:
    validate(status, scope, reason, comment, review_until)
    vuln_key = vuln_key.strip().upper()
    if not vuln_key:
        raise TriageError("Не указана уязвимость")
    if scope == "host" and host_id is None:
        raise TriageError("Для области «компьютер» нужен компьютер")
    if scope == "zone" and zone_id is None:
        raise TriageError("Для области «зона» нужна зона")
    if scope == "product" and not product.strip():
        raise TriageError("Для области «программа» нужно название программы")
    q = select(VulnTriage).where(VulnTriage.source_id == source_id, VulnTriage.scope == scope, VulnTriage.vuln_key == vuln_key)
    if scope == "host":
        q = q.where(VulnTriage.host_id == host_id)
    elif scope == "zone":
        q = q.where(VulnTriage.zone_id == zone_id)
    else:
        q = q.where(VulnTriage.product == product.strip(), VulnTriage.version == version.strip())
    cur = (await db.execute(q)).scalars().first()
    now = datetime.now(timezone.utc)
    if cur is None:
        t = VulnTriage(id=uuid.uuid4(), source_id=source_id, scope=scope, host_id=host_id if scope == "host" else None, host_name=host_name if scope == "host" else "", zone_id=zone_id if scope == "zone" else None,
                       vuln_key=vuln_key, origin=origin, product=product.strip(), version=version.strip(), status=status, reason=reason, comment=comment.strip(),
                       review_until=review_until if status == "risk_accepted" else None, created_by=actor, created_at=now, updated_at=now)
        db.add(t)
        await db.flush()
        _event(db, t, actor, "create", "", status, comment)
        return t
    frm = cur.status
    cur.status, cur.reason, cur.comment = status, reason, comment.strip()
    cur.review_until = review_until if status == "risk_accepted" else None
    cur.product, cur.version = (product.strip() or cur.product), (version.strip() if scope != "product" else cur.version)
    if host_name and scope == "host":
        cur.host_name = host_name
    if host_id is not None and scope == "host":
        cur.host_id = host_id
    cur.recheck, cur.recheck_reason = False, ""                       # решение подтверждено заново на текущем основании
    cur.created_by, cur.updated_at = actor, now
    _event(db, cur, actor, "status" if frm != status else "comment", frm, status, comment)
    return cur


async def mark_stale(db: AsyncSession, index: TriageIndex) -> int:
    """Фиксирует в БД, что основание решения изменилось (версия, идентификатор устройства): запись остаётся в истории и возвращается на проверку. Идемпотентно."""
    n = 0
    seen: set[uuid.UUID] = set()
    for r, why in index.stale:
        if r.id in seen or (r.recheck and r.recheck_reason == why):
            continue
        seen.add(r.id)
        r.recheck, r.recheck_reason, r.updated_at = True, why[:200], datetime.now(timezone.utc)
        _event(db, r, "система", "recheck", r.status, "review", why)
        n += 1
    index.stale.clear()
    return n


async def sweep_expired(db: AsyncSession, source_id: uuid.UUID | None = None) -> int:
    """Принятые риски с истёкшим сроком: фиксирует событие «срок истёк» один раз (повторно не пишет)."""
    now = datetime.now(timezone.utc)
    q = select(VulnTriage).where(VulnTriage.status == "risk_accepted", VulnTriage.review_until < now, VulnTriage.recheck.is_(False))
    if source_id:
        q = q.where(VulnTriage.source_id == source_id)
    n = 0
    for r in (await db.execute(q)).scalars():
        r.recheck, r.recheck_reason, r.updated_at = True, "срок пересмотра принятого риска истёк", now
        _event(db, r, "система", "expire", "risk_accepted", "review", f"срок {r.review_until:%d.%m.%Y} истёк")
        n += 1
    return n


async def history(db: AsyncSession, triage_id: uuid.UUID) -> list[dict]:
    ev = (await db.execute(select(VulnTriageEvent).where(VulnTriageEvent.triage_id == triage_id).order_by(VulnTriageEvent.id))).scalars().all()
    return [{"at": e.at, "actor": e.actor, "action": e.action, "from": STATUS_RU.get(e.from_status, ""), "to": STATUS_RU.get(e.to_status, ""), "comment": e.comment} for e in ev]


def default_review_until(days: int = DEFAULT_REVIEW_DAYS) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)
