"""Разбор выгрузки событий смены (4723) и сброса (4724) пароля, подготовленной скриптом `scripts/windows/Export-KavPasswordEvents.ps1`.

LDAP истории операций не хранит: события читаются из журналов Security контроллеров домена учётной записью из группы «Event Log Readers»
(без прав администратора домена) и загружаются в раздел файлом. Кроме событий выгрузка содержит охват журнала каждого контроллера
(первое и последнее событие журнала) — без него отсутствие события нельзя отличить от отсутствия данных."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

FORMAT = "kavcheck-pwd-events/1"
MAX_BYTES = 200 * 1024 * 1024
MAX_EVENTS = 2_000_000
_SID = re.compile(r"^S-1-\d+(-\d+){1,14}$")


class EventsError(Exception):
    """Файл не принят (понятное сообщение для интерфейса)."""


def _dt(v) -> datetime | None:
    if not v:
        return None
    s = str(v).strip()
    m = re.fullmatch(r"/Date\((\d+)\)/", s)                  # ConvertTo-Json в Windows PowerShell 5.1
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, timezone.utc)
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _s(v, n: int = 256) -> str:
    return "".join(ch for ch in str(v or "") if ch.isprintable())[:n].strip()


def parse(raw: bytes) -> dict:
    """{generated_at, dcs: [{name, log_from, log_to, error}], events: [{dc, record_id, kind, success, at, target_sid, target, target_domain, by, by_domain, by_sid}]}."""
    if len(raw) > MAX_BYTES:
        raise EventsError(f"Файл больше {MAX_BYTES // 1024 // 1024} МБ: выгрузите период короче")
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise EventsError("Файл не является выгрузкой событий в формате JSON (UTF-8): используйте скрипт Export-KavPasswordEvents.ps1") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise EventsError(f"Неизвестный формат файла: ожидается «{FORMAT}» (скрипт Export-KavPasswordEvents.ps1)")
    dcs = []
    for d in doc.get("dcs") or []:
        if not isinstance(d, dict) or not _s(d.get("name")):
            continue
        dcs.append({"name": _s(d.get("name"), 255).lower(), "log_from": _dt(d.get("log_from")), "log_to": _dt(d.get("log_to")), "error": _s(d.get("error"), 500)})
    evs = doc.get("events") or []
    if not isinstance(evs, list) or len(evs) > MAX_EVENTS:
        raise EventsError(f"Событий больше {MAX_EVENTS}: выгрузите период короче")
    out, bad = [], 0
    for e in evs:
        if not isinstance(e, dict):
            bad += 1
            continue
        eid, at = int(e.get("id") or 0), _dt(e.get("time_utc"))
        sid = _s(e.get("target_sid"), 190)
        if eid not in (4723, 4724) or at is None or not (sid and _SID.match(sid) or _s(e.get("target_user"))):
            bad += 1
            continue
        out.append({"dc": _s(e.get("dc"), 255).lower(), "record_id": int(e.get("record_id") or 0), "kind": "change" if eid == 4723 else "reset", "success": bool(e.get("success")), "at": at,
                    "target_sid": sid if _SID.match(sid or "") else "", "target": _s(e.get("target_user"), 256), "target_domain": _s(e.get("target_domain"), 256),
                    "by": _s(e.get("subject_user"), 256), "by_domain": _s(e.get("subject_domain"), 256), "by_sid": _s(e.get("subject_sid"), 190)})
    if not dcs and not out:
        raise EventsError("В файле нет ни контроллеров, ни событий")
    return {"generated_at": _dt(doc.get("generated_at")), "dcs": dcs, "events": out, "skipped": bad}
