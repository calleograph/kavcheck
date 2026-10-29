"""Доступ к SMB-папке выгрузок — только чтение: список файлов, сведения о файле и копирование в собственное хранилище. Ничего не изменяется, не удаляется и не переименовывается.

Функции синхронные (smbprotocol), вызываются из worker через asyncio.to_thread. Сеанс — на одну операцию (собственный кэш соединений), пароль в журналы не попадает."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SKIP = re.compile(r"^(~\$|~|\.)|\.(tmp|part|partial|crdownload|download|swp)$|~$", re.I)       # временные и блокировочные файлы: ещё пишутся или служебные
AMBIGUOUS_S = 60
CHUNK = 1024 * 1024
DIALECTS = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}


class SmbError(Exception):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage, self.message = stage, message


@dataclass
class Conn:
    host: str
    share: str
    path: str = ""
    username: str = ""
    password: str = ""
    port: int = 445
    encrypt: bool = True
    timeout: int = 15


@dataclass
class FileInfo:
    name: str
    size: int
    mtime: datetime


def host_allowed(host: str, allowed: list[str]) -> str | None:
    """Причина отказа или None. Петлевой и link-local адреса запрещены всегда; непустой список разрешённых — имя (маска) или сеть CIDR."""
    h = host.strip().lower()
    if not h or any(c in h for c in "\\/ @"):
        return "Укажите имя или адрес SMB-сервера без пути и учётных данных"
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return "Петлевые, link-local и служебные адреса не допускаются"
    except ValueError:
        ip = None
        if h == "localhost":
            return "Петлевые, link-local и служебные адреса не допускаются"
    if not allowed:
        return None
    for a in allowed:
        a = a.strip().lower()
        if "/" in a and ip is not None:
            try:
                if ip in ipaddress.ip_network(a, strict=False):
                    return None
            except ValueError:
                continue
        elif fnmatch.fnmatchcase(h, a):
            return None
    return "Сервер не входит в список разрешённых источников (Администрирование → Источники данных → BI: «Разрешённые SMB-серверы»)"


def _unc(c: Conn, name: str = "") -> str:
    parts = [p for p in re.split(r"[\\/]+", c.path) if p]
    if any(p in (".", "..") for p in parts) or (name and (name in (".", "..") or re.search(r"[\\/]", name))):
        raise SmbError("path", "Путь не должен содержать «.», «..» и разделителей в имени файла")
    return "\\\\" + "\\".join([c.host, c.share.strip("\\/"), *parts, *([name] if name else [])])


class Smb:
    """Сеанс SMB на время одной операции."""

    def __init__(self, c: Conn):
        self.c = c
        self.cache: dict = {}
        self.dialect = ""
        self.encrypted = False

    def __enter__(self):
        import smbclient  # noqa: PLC0415
        from smbprotocol.exceptions import SMBException  # noqa: PLC0415

        try:
            smbclient.register_session(self.c.host, username=self.c.username or None, password=self.c.password or None, port=self.c.port, encrypt=self.c.encrypt,
                                       connection_timeout=self.c.timeout, connection_cache=self.cache)
        except (SMBException, ValueError, OSError) as exc:
            raise SmbError("auth", _msg(exc)) from None
        for conn in self.cache.values():
            self.dialect = DIALECTS.get(int(getattr(conn, "dialect", 0) or 0), "")
            self.encrypted = any(getattr(s, "encrypt_data", False) for s in (getattr(conn, "session_table", {}) or {}).values())
        return self

    def __exit__(self, *_exc):
        import smbclient  # noqa: PLC0415

        try:
            smbclient.reset_connection_cache(fail_on_error=False, connection_cache=self.cache)
        except Exception:  # noqa: BLE001
            pass

    def _call(self, stage: str, fn, *a, **kw):
        from smbprotocol.exceptions import SMBException  # noqa: PLC0415

        try:
            return fn(*a, connection_cache=self.cache, **kw)
        except (SMBException, OSError, ValueError) as exc:
            raise SmbError(stage, _msg(exc)) from None

    def listing(self) -> list[FileInfo]:
        import smbclient  # noqa: PLC0415

        out = []
        for e in self._call("list", lambda **kw: list(smbclient.scandir(_unc(self.c), **kw))):
            if e.is_file():
                st = e.stat()
                out.append(FileInfo(e.name, int(st.st_size), datetime.fromtimestamp(st.st_mtime, timezone.utc)))
        return out

    def stat(self, name: str) -> FileInfo:
        import smbclient  # noqa: PLC0415

        st = self._call("stat", smbclient.stat, _unc(self.c, name))
        return FileInfo(name, int(st.st_size), datetime.fromtimestamp(st.st_mtime, timezone.utc))

    def copy(self, name: str, dst: Path, max_bytes: int) -> int:
        """Копирование только на чтение (совместный доступ на чтение, запись и удаление — не мешаем BI-системе заменить файл). Больше max_bytes — отказ."""
        import smbclient  # noqa: PLC0415

        n = 0
        with self._call("read", smbclient.open_file, _unc(self.c, name), mode="rb", share_access="rwd") as f, dst.open("wb") as out:
            while chunk := f.read(CHUNK):
                n += len(chunk)
                if n > max_bytes:
                    raise SmbError("size", f"Файл больше допустимого размера {max_bytes // (1024 * 1024)} МБ")
                out.write(chunk)
        return n

    def probe(self, name: str) -> None:
        import smbclient  # noqa: PLC0415

        with self._call("read", smbclient.open_file, _unc(self.c, name), mode="rb", share_access="rwd") as f:
            f.read(4)


def _msg(exc: Exception) -> str:
    s = str(exc) or type(exc).__name__
    s = re.sub(r"(?i)(password|пароль)\S*\s*[=:]\s*\S+", r"\1=***", s)
    return f"{type(exc).__name__}: {s[:300]}"


def choose(files: list[FileInfo], mode: str, rule: str) -> tuple[FileInfo | None, list[FileInfo], str]:
    """(файл, кандидаты, причина отказа). fixed — точное имя (без учёта регистра); auto — новейший файл по маске, временные файлы пропускаются.
    Если два новейших файла изменены почти одновременно, актуальный не определить — импорт не выполняется."""
    if mode == "fixed":
        hit = next((f for f in files if f.name.lower() == rule.strip().lower()), None)
        return hit, [hit] if hit else [], "" if hit else f"Файл «{rule}» не найден в папке"
    mask = (rule or "*.xlsx").strip().lower()
    cand = sorted((f for f in files if fnmatch.fnmatchcase(f.name.lower(), mask) and not SKIP.search(f.name)), key=lambda f: f.mtime, reverse=True)
    if not cand:
        return None, [], f"В папке нет файлов по маске «{mask}»"
    if len(cand) > 1 and abs((cand[0].mtime - cand[1].mtime).total_seconds()) <= AMBIGUOUS_S:
        return None, cand, (f"Несколько одинаково новых файлов («{cand[0].name}», «{cand[1].name}»): актуальный определить нельзя. Оставьте в папке один файл или уточните маску")
    return cand[0], cand, ""


def tcp_check(host: str, port: int, timeout: int) -> None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except socket.gaierror as exc:
        raise SmbError("tcp", f"Имя сервера {host} не найдено в DNS: {exc.strerror or exc}") from None
    except OSError as exc:
        raise SmbError("tcp", f"Порт {port} сервера {host} недоступен: {exc.strerror or exc}") from None


def fetch_stable(s: Smb, name: str, dst: Path, max_bytes: int, stable_s: float) -> FileInfo:
    """Копирование только «устоявшегося» файла: размер и время изменения не меняются за stable_s и во время копирования; иначе SmbError("busy")."""
    a = s.stat(name)
    if stable_s:
        time.sleep(stable_s)
    b = s.stat(name)
    if (a.size, a.mtime) != (b.size, b.mtime):
        raise SmbError("busy", "Файл ещё изменяется (BI-система записывает выгрузку): получение отложено")
    n = s.copy(name, dst, max_bytes)
    c = s.stat(name)
    if (c.size, c.mtime) != (b.size, b.mtime) or n != b.size:
        dst.unlink(missing_ok=True)
        raise SmbError("busy", "Файл изменился во время копирования: получение отложено")
    return b


def diagnose(c: Conn, mode: str, rule: str, allowed: list[str]) -> dict:
    """«Проверить подключение»: разрешён ли сервер, TCP, вход и диалект, чтение папки, выбор файла и право чтения. Каждый этап — отдельной строкой."""
    stages: list[dict] = []

    def stage(key: str, ok: bool, message: str, t0: float) -> None:
        stages.append({"stage": key, "ok": ok, "message": message, "ms": int((time.monotonic() - t0) * 1000)})

    t = time.monotonic()
    why = host_allowed(c.host, allowed)
    stage("allowed", why is None, why or "Сервер разрешён", t)
    if why:
        return {"ok": False, "stages": stages}
    try:
        t = time.monotonic()
        tcp_check(c.host, c.port, c.timeout)
        stage("tcp", True, f"Порт {c.port} доступен", t)
        t = time.monotonic()
        with Smb(c) as s:
            stage("auth", True, f"Вход выполнен{', ' + s.dialect if s.dialect else ''}{', шифрование включено' if s.encrypted or c.encrypt else ', без шифрования'}", t)
            t = time.monotonic()
            files = s.listing()
            stage("list", True, f"Папка доступна для чтения: файлов {len(files)}", t)
            t = time.monotonic()
            hit, cand, why = choose(files, mode, rule)
            if hit is None:
                stage("choose", False, why, t)
                return {"ok": False, "stages": stages, "files": [f.__dict__ for f in cand[:20]]}
            stage("choose", True, f"Выбран «{hit.name}», {hit.size // 1024} КБ, изменён {hit.mtime:%d.%m.%Y %H:%M} UTC" + (f"; подходящих файлов: {len(cand)}" if len(cand) > 1 else ""), t)
            t = time.monotonic()
            s.probe(hit.name)
            stage("read", True, "Файл открывается на чтение", t)
            return {"ok": True, "stages": stages, "files": [f.__dict__ for f in cand[:20]], "file": hit.__dict__}
    except SmbError as exc:
        stage(exc.stage, False, exc.message, t)
        return {"ok": False, "stages": stages}
