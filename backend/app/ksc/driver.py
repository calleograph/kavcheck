"""Подключение к SQL Server базы KSC: только чтение, параметризованные запросы, тайм-ауты, предел строк, ограничение параллельных обращений на источник.
Драйвер — pymssql (FreeTDS). Пароль расшифровывается перед подключением и нигде не журналируется."""
from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

from . import guard

log = logging.getLogger("app.ksc")


class KscError(Exception):
    """Безопасное для показа сообщение (без пароля и строки подключения)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


@dataclass(frozen=True)
class ConnParams:
    host: str
    port: int
    database: str
    username: str
    password: str
    tls_mode: str = "require"          # require | request | off
    trust_server_cert: bool = True
    connect_timeout_s: int = 10
    query_timeout_s: int = 60


def _sanitize(exc: BaseException) -> str:
    """Текст ошибки драйвера без пароля: pymssql в сообщениях пароль не печатает, но на всякий случай режем длину и управляющие символы."""
    text = " ".join(str(exc).split())
    if isinstance(exc, (tuple, list)):
        text = " ".join(str(x) for x in exc)
    return text[:300]


# ошибки FreeTDS → понятная причина и следующее действие; исходный текст остаётся в скобках для администратора
_CAUSES = (
    (("timed out", "20003"), "сервер {where} не ответил за {t} с: проверьте, что SQL Server запущен, порт открыт и сетевой экран пропускает подключение"),
    (("Name or service not known", "Unknown host", "nodename nor servname"), "имя сервера {host} не найдено в DNS: проверьте адрес в настройках источника"),
    (("Connection refused",), "сервер {where} отклонил подключение: SQL Server не слушает этот порт"),
    (("4060", "Cannot open database"), "база «{db}» недоступна этой учётной записи: проверьте имя базы и права на чтение"),
    (("SSL", "TLS", "certificate"), "не удалось согласовать шифрование TLS с {where}: проверьте режим шифрования в настройках источника"),
    (("Unable to connect", "20009", "unavailable or does not exist"), "не удалось установить соединение с {where}: сервер не найден или порт закрыт"),
)


def explain(msg: str, p: ConnParams) -> str:
    raw = " ".join(re.sub(r"\\n|\(\d+, b'|'\)|b'", " ", msg).split())[:200]       # «(20002, b'DB-Lib …\\n…')» → читаемый текст
    for keys, text in _CAUSES:
        if any(k in msg for k in keys):
            return text.format(where=f"{p.host}:{p.port}", host=p.host, db=p.database, t=p.connect_timeout_s) + f" (техническая причина: {raw})"
    return msg


def connect(p: ConnParams):
    import pymssql  # noqa: PLC0415

    kw: dict[str, Any] = dict(server=p.host, port=str(p.port), user=p.username, password=p.password, database=p.database, login_timeout=p.connect_timeout_s,
                              timeout=p.query_timeout_s, charset="UTF-8", tds_version="7.4", autocommit=True, as_dict=True, read_only=True)
    if p.tls_mode != "off":
        kw["encryption"] = p.tls_mode
    try:
        try:
            conn = pymssql.connect(**kw)
        except TypeError:   # старый pymssql без параметров encryption/read_only
            kw.pop("encryption", None)
            kw.pop("read_only", None)
            conn = pymssql.connect(**kw)
    except pymssql.OperationalError as exc:
        msg = _sanitize(exc)
        code = "auth" if "Login failed" in msg or "18456" in msg else "connect"
        raise KscError(code, "Вход на SQL Server отклонён: проверьте имя пользователя и пароль" if code == "auth" else f"SQL Server недоступен: {explain(msg, p)}") from None
    except Exception as exc:  # noqa: BLE001
        raise KscError("connect", f"Не удалось подключиться: {type(exc).__name__}: {_sanitize(exc)}") from None
    cur = conn.cursor()
    # Чтение без блокировок производственной базы KSC и без ожидания чужих блокировок
    cur.execute("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
    cur.execute("SET LOCK_TIMEOUT 5000")
    cur.close()
    return conn


def query(conn, sql: str, params: dict | tuple | None = None, *, max_rows: int) -> list[dict]:
    """Один запрос только для чтения. Возвращает до max_rows строк (max_rows + 1 строка — признак обрезки, см. query_capped)."""
    guard.check(sql)
    cur = conn.cursor()
    try:
        cur.execute(sql, params or ())
        rows = cur.fetchmany(max_rows + 1) if max_rows else cur.fetchall()
    finally:
        cur.close()
    return rows


def _close(conn) -> None:
    try:
        conn.close()
    except Exception:  # noqa: BLE001 — закрытие не должно скрывать исходную ошибку
        pass


IDLE_TTL_S = 30          # соединение, простоявшее дольше, не используется (сервер или сетевой экран мог его закрыть)


class SourceClient:
    """Клиент одного источника: семафор на число одновременных запросов, небольшой пул простаивающих соединений (подключение к SQL Server стоит ~0,25 с — вдвое больше самого запроса),
    журнал подключений. Запросы только на чтение, поэтому при разрыве взятого из пула соединения запрос безопасно повторяется на новом."""

    def __init__(self, params: ConnParams, *, concurrency: int = 3, name: str = ""):
        self.params = params
        self.name = name
        self._concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)
        self._tsem = threading.Semaphore(concurrency)
        self._idle: list[tuple[Any, float]] = []
        self._lock = threading.Lock()

    def _take(self):
        now = time.monotonic()
        with self._lock:
            while self._idle:
                conn, at = self._idle.pop()
                if now - at <= IDLE_TTL_S:
                    return conn
                _close(conn)
        return None

    def _give(self, conn) -> None:
        with self._lock:
            if len(self._idle) < self._concurrency:
                self._idle.append((conn, time.monotonic()))
                return
        _close(conn)

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for conn, _at in idle:
            _close(conn)

    def run_sync(self, sql: str, params: dict | tuple | None = None, *, max_rows: int = 100_000) -> list[dict]:
        guard.check(sql)                       # до подключения: запрещённый запрос не доходит до сервера
        with self._tsem:
            started = time.perf_counter()
            for attempt in (0, 1):
                conn = self._take() if attempt == 0 else None
                reused = conn is not None
                conn = conn or connect(self.params)
                try:
                    rows = query(conn, sql, params, max_rows=max_rows)
                except (KscError, guard.UnsafeQuery):
                    _close(conn)
                    raise
                except Exception as exc:  # noqa: BLE001
                    _close(conn)
                    if reused:                 # соединение из пула могло быть разорвано сервером: один повтор на новом (запрос только читает)
                        continue
                    msg = _sanitize(exc)
                    log.warning("Ошибка запроса к KSC", extra={"source": self.name, "error": type(exc).__name__, "ms": int((time.perf_counter() - started) * 1000)})
                    raise KscError("query", f"Ошибка запроса к базе KSC: {type(exc).__name__}: {msg}") from None
                if len(rows) > max_rows:       # не дочитанный результат: соединение в пул не возвращается
                    _close(conn)
                    raise KscError("too_many_rows", f"Результат превышает предел {max_rows} строк: сузьте фильтр или используйте фоновый отчёт")
                self._give(conn)
                return rows
        raise AssertionError("unreachable")

    async def run(self, sql: str, params: dict | tuple | None = None, *, max_rows: int = 100_000) -> list[dict]:
        from ..services.jobs import touch_current  # noqa: PLC0415

        async with self._sem:
            rows = await asyncio.to_thread(self.run_sync, sql, params, max_rows=max_rows)
        touch_current()                      # запрос к KSC выполнен — ход выполнения фонового задания (сторож зависаний не сочтёт его стоящим)
        return rows

    def run_many_sync(self, items: list[tuple[str, dict | tuple | None]], *, max_rows: int = 100_000) -> list[list[dict]]:
        """Несколько запросов на одном соединении (отчёты)."""
        for sql, _ in items:
            guard.check(sql)
        with self._tsem:
            conn = connect(self.params)
            try:
                return [query(conn, sql, params, max_rows=max_rows) for sql, params in items]
            except KscError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise KscError("query", f"Ошибка запроса к базе KSC: {type(exc).__name__}: {_sanitize(exc)}") from None
            finally:
                conn.close()


class Session:
    """Одно открытое соединение для серии запросов (фоновый отчёт): создаётся в рабочем потоке, закрывается по выходу."""

    def __init__(self, params: ConnParams):
        self._p = params
        self._conn = None

    def __enter__(self):
        self._conn = connect(self._p)
        return self

    def __exit__(self, *exc):
        if self._conn is not None:
            self._conn.close()

    def query(self, sql: str, params: dict | tuple | None = None, *, max_rows: int = 100_000) -> list[dict]:
        guard.check(sql)
        try:
            rows = query(self._conn, sql, params, max_rows=max_rows)
        except (KscError, guard.UnsafeQuery):
            raise
        except Exception as exc:  # noqa: BLE001
            raise KscError("query", f"Ошибка запроса к базе KSC: {type(exc).__name__}: {_sanitize(exc)}") from None
        if len(rows) > max_rows:
            raise KscError("too_many_rows", f"Результат превышает предел {max_rows} строк")
        return rows
