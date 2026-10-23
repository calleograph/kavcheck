"""Проверка SQL перед отправкой в базу KSC: только одна инструкция SELECT/WITH, никаких изменяющих и опасных слов.
Все запросы приложения — заранее подготовленные шаблоны (queries.py); произвольный SQL от пользователя не принимается.
Проверка — дополнительная защита на случай ошибки в шаблоне."""
from __future__ import annotations

import re

FORBIDDEN = {
    "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "ALTER", "DROP", "CREATE", "RENAME", "GRANT", "REVOKE", "DENY", "DBCC", "EXEC", "EXECUTE",
    "BACKUP", "RESTORE", "INTO", "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "SHUTDOWN", "KILL", "RECONFIGURE", "WAITFOR", "USE", "SET", "DECLARE",
    "BEGIN", "COMMIT", "ROLLBACK", "SAVE", "CHECKPOINT", "BULK", "UPDATETEXT", "WRITETEXT", "SEND", "RECEIVE", "ENABLE", "DISABLE", "GO",
}
_TOKENS = re.compile(r"/\*.*?\*/|--[^\n]*|N?'(?:[^']|'')*'|\[(?:[^\]]|\]\])*\]|\"(?:[^\"]|\"\")*\"", re.S)


class UnsafeQuery(ValueError):
    pass


def _normalize(sql: str) -> str:
    def repl(m):
        t = m.group(0)
        if t.startswith(("/*", "--")):
            return " "
        return " 'str' " if t.startswith(("'", "N'")) else "ident"
    text = _TOKENS.sub(repl, sql)
    if "/*" in text or "*/" in text or text.count("'") != text.count("'str'") * 2:
        raise UnsafeQuery("незакрытая строка или комментарий")
    return text.strip().lstrip(";").rstrip(";").strip()


def check(sql: str) -> None:
    text = _normalize(sql)
    if ";" in text:
        raise UnsafeQuery("разрешена только одна инструкция")
    words = re.findall(r"[A-Za-z_@#][\w@#$]*", text.upper())
    if not words or words[0] not in ("SELECT", "WITH"):
        raise UnsafeQuery("запрос должен начинаться с SELECT или WITH")
    bad = sorted(set(words) & FORBIDDEN)
    if bad:
        raise UnsafeQuery(f"запрещённые слова: {', '.join(bad)}")
