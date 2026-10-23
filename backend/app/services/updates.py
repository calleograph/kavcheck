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
LOG_CHUNK = 64 * 1024
ACTIONS = ("check", "update", "rollback", "backup", "ping")
BUSY_STATES = ("updating", "rolling_back", "backing_up")
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
        return {**st, "available": age is not None and age <= HEARTBEAT_MAX_AGE, "heartbeat_age_s": None if age is None else int(age), "request_pending": (self.dir / "request.txt").exists()}

    def remote(self) -> dict | None:
        r = self._json("remote.json")
        if r and r.get("checked_at"):
            r["age_s"] = int(time.time() - float(r["checked_at"]))
        return r

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
        return {"offset": offset + len(raw), "size": size, "text": raw.decode("utf-8", errors="replace"), "reset": reset}

    def request(self, action: str, *, by: str, target: str = "") -> str:
        if action not in ACTIONS:
            raise ValueError("action")
        if target and not VERSION_RE.match(target):
            raise ValueError("target")
        rid = uuid.uuid4().hex[:16]
        body = "\n".join([f"id={rid}", f"action={action}", f"target={target}", f"by={_SAFE.sub('_', by)[:60]}", f"at={int(time.time())}"]) + "\n"
        tmp = self.dir / f".request.{rid}.tmp"
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(self.dir / "request.txt")
        return rid
