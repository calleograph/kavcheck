"""Обновление из веб-интерфейса: обмен с «исполнителем» на хосте (scripts/updater.sh) через каталог DATA_DIR/updater.

Контейнер backend НЕ имеет доступа к Docker и git хоста. Поэтому:
    backend  →  request.txt   запрос: check | update | rollback | backup (простые строки key=value, без исполняемого содержимого)
    updater  →  status.json   пульс исполнителя и состояние текущего действия (этап, код завершения)
    updater  →  remote.json   что опубликовано в GitHub (последний релиз, список изменений)
    updater  →  update.log    построчный вывод scripts/update.sh
    updater  →  history.ndjson история попыток; backups.json — список резервных копий
Исполнитель выполняет только фиксированный набор действий; произвольные команды передать нельзя."""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

HEARTBEAT_MAX_AGE = 40
UPDATER_API = 2                 # версия обмена с помощником (scripts/updater.sh); у более старого помощника нет восстановления и контроля зависаний
STALL_WARN_S = 300              # столько секунд без вывода в журнале — показываем предупреждение «нет прогресса»
URL_CRED = re.compile(r"(https?://)[^/@\s:]+(?::[^/@\s]*)?@")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LOG_CHUNK = 64 * 1024
ACTIONS = ("check", "update", "rollback", "backup", "ping", "preflight", "restore")
BUSY_STATES = ("updating", "rolling_back", "backing_up", "restoring", "recovering")
BACKUP_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}\.dump$")
_SAFE = re.compile(r"[^A-Za-z0-9._-]")
VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+$")


class Channel:
    def __init__(self, directory: str):
        self.dir = Path(directory)

    def _json(self, name: str) -> dict | None:
        try:
            data = json.loads((self.dir / name).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    def status(self) -> dict:
        st = self._json("status.json") or {}
        ts = float(st.get("ts") or 0)
        age = time.time() - ts if ts else None
        available = age is not None and age <= HEARTBEAT_MAX_AGE
        state = st.get("state")
        # помощник остановлен, а в статусе осталось «Выполняется»: это прерванное действие, а не работающее
        interrupted = not available and state in BUSY_STATES
        if interrupted:
            st = {**st, "state": "interrupted", "result": "failed"}
        out_at = float(st.get("last_output_at") or 0)
        stalled = available and state in BUSY_STATES and out_at and time.time() - out_at > STALL_WARN_S
        return {**st, "available": available, "heartbeat_age_s": None if age is None else int(age), "request_pending": (self.dir / "request.txt").exists(),
                "interrupted": interrupted, "stalled_s": int(time.time() - out_at) if stalled else None, "api_outdated": available and int(st.get("updater_api") or 1) < UPDATER_API}

    def remote(self) -> dict | None:
        r = self._json("remote.json")
        if r and r.get("checked_at"):
            r["age_s"] = int(time.time() - float(r["checked_at"]))
        return r

    def preflight(self) -> dict | None:
        r = self._json("preflight.json")
        if r and r.get("checked_at"):
            r["age_s"] = int(time.time() - float(r["checked_at"]))
        return r

    def report(self) -> dict | None:
        return self._json("report.json")

    def backups(self) -> list[dict]:
        r = self._json("backups.json") or {}
        items = r.get("items")
        return items if isinstance(items, list) else []

    def history(self, limit: int = 20) -> list[dict]:
        out: list[dict] = []
        try:
            lines = (self.dir / "history.ndjson").read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return out
        for ln in reversed(lines):
            try:
                d = json.loads(ln)
            except ValueError:
                continue
            if isinstance(d, dict):
                out.append(d)
            if len(out) >= limit:
                break
        return out

    def read_log(self, offset: int) -> dict:
        path = self.dir / "update.log"
        try:
            size = path.stat().st_size
        except OSError:
            return {"offset": 0, "size": 0, "text": "", "reset": False}
        reset = offset > size or offset < 0
        if reset:
            offset = 0
        with path.open("rb") as fh:
            fh.seek(offset)
            raw = fh.read(LOG_CHUNK)
        if len(raw) == LOG_CHUNK and b"\n" in raw:
            raw = raw[: raw.rindex(b"\n") + 1]
        return {"offset": offset + len(raw), "size": size, "text": ANSI.sub("", raw.decode("utf-8", errors="replace")), "reset": reset}

    def download_text(self, which: str = "last") -> str:
        """Журнал последнего (или предыдущего) обновления для диагностики: сведения о системе и итоге, затем полный журнал. Секреты и пароли маскируются."""
        from ..logging_setup import scrub  # noqa: PLC0415

        path = self.dir / ("update.prev.log" if which == "prev" else "update.log")
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = "(журнал отсутствует: обновление ещё не выполнялось)\n"
        st, rep, pf = self.status(), self.report() or {}, self.preflight() or {}
        head = ["# Журнал обновления KAV Checker (для диагностики)", f"# Сформирован: {time.strftime('%Y-%m-%d %H:%M:%S %z')}", f"# Помощник: {'работает' if st['available'] else 'не отвечает'}, состояние: {st.get('state')}, API {st.get('updater_api')}",
                f"# Действие: {st.get('action')} · способ: {rep.get('mode') or st.get('mode') or '?'} · этап {st.get('step_no')}/{st.get('step_total')}: {st.get('step_name')}"]
        if rep:
            head += [f"# Итог: {rep.get('result')} · {rep.get('from_version')} → {rep.get('to_version')} · этап: {rep.get('stage')} · причина: {rep.get('reason_code') or '-'}", f"# Совет: {rep.get('advice')}"]
            head += [f"# Действие помощника: {a}" for a in (rep.get("actions") or [])]
        if pf:
            head += [f"# Проверка перед обновлением ({'пройдена' if pf.get('ok') else 'есть препятствия'}):"] + [f"#   [{i.get('status')}] {i.get('message')}" for i in pf.get("items") or []]
        text = "\n".join(head) + "\n" + "=" * 78 + "\n" + ANSI.sub("", body)
        text = URL_CRED.sub(r"\1***@", text)          # адрес зеркала с логином и паролем
        return "\n".join(str(scrub(line)) for line in text.splitlines()) + "\n"

    def request(self, action: str, *, by: str, target: str = "", mode: str = "") -> str:
        if action not in ACTIONS or mode not in ("", "pull", "build"):
            raise ValueError("action")
        if target and not (BACKUP_RE.match(target) if action == "restore" else VERSION_RE.match(target)):
            raise ValueError("target")
        rid = uuid.uuid4().hex[:16]
        body = "\n".join([f"id={rid}", f"action={action}", f"target={target}", f"mode={mode}", f"by={_SAFE.sub('_', by)[:60]}", f"at={int(time.time())}"]) + "\n"
        tmp = self.dir / f".request.{rid}.tmp"
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(self.dir / "request.txt")
        return rid
