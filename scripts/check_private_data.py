#!/usr/bin/env python3
"""Проверка репозитория на утечку сведений о конкретной организации: внутренние домены, имена хостов, адреса e-mail, IP-адреса, секреты.

Проверка «по списку разрешённого» (scripts/private-data.allow): любой домен или адрес не из списка считается возможной частной настройкой.
Дополнительно: запрещённые шаблоны своей организации — вне репозитория, PRIVATE_DENY_FILE=/путь (регулярное выражение в строке).
Запуск: python3 scripts/check_private_data.py [--history] [--all]. Код 1 — найдено."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW_FILE = ROOT / "scripts" / "private-data.allow"
SKIP_SUFFIX = {".png", ".jpg", ".ico", ".svg", ".woff", ".woff2", ".lock", ".dump"}
SKIP_NAMES = {"package-lock.json", "private-data.allow"}
SELF = "scripts/check_private_data.py"
TLDS = "com|org|net|ru|su|io|ai|dev|app|cloud|local|lan|corp|internal|intranet|home|test|invalid|example"
DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:%s))(?![\w-]|\.[a-z])" % TLDS, re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
IPV4 = re.compile(r"(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3})(?![\w.-])")
SECRET = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['\"]?(?!CHANGE_ME|\$|\{|%|<|\"\"|'')([A-Za-z0-9+/=_-]{12,})")
CODE_LIKE = re.compile(r"^(?:me|su|ws|self|this|app|window|document|os|sys|req|res|settings|config|cfg|state|ctx|request|response|result|data|obj|item|row|e|p|h|i|g|s|a|n|d|o|v|c|r|t|x|u|m|b|f|j|k|y|cur|next|prev|out|err|exc|src|job|rule|list|map|set|dict|re|json|time|math|api|db|svc|st|ch|u|p|h|g|q|pv|vp|ev|dc|git|npm|pip|docker)\.", re.I)


def load_allow() -> tuple[list[str], list[re.Pattern[str]]]:
    domains, ips = [], []
    for raw in ALLOW_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("ip:"):
            ips.append(re.compile(line[3:].strip()))
        else:
            domains.append(line.lower().lstrip("*."))
    return domains, ips


def domain_ok(d: str, allowed: list[str]) -> bool:
    d = d.lower()
    return any(d == a or d.endswith("." + a) for a in allowed)


def tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8", "replace")
        return [f for f in out.split("\0") if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and not any(x in p.parts for x in (".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache"))]


def scan_text(name: str, text: str, allowed, ips, deny) -> list[str]:
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        if "private-data: ignore" in line:          # явно помеченная строка (тестовые данные)
            continue
        for rx in deny:
            m = rx.search(line)
            if m:
                found.append(f"{name}:{n}: запрещённый шаблон «{m.group(0)}»")
        for m in DOMAIN.finditer(line):
            d = m.group(1)
            if CODE_LIKE.match(d) or domain_ok(d, allowed):
                continue
            found.append(f"{name}:{n}: домен «{d}» не из списка разрешённых")
        for m in EMAIL.finditer(line):
            if not domain_ok(m.group(1), allowed):
                found.append(f"{name}:{n}: адрес e-mail на домене «{m.group(1)}» не из списка разрешённых")
        for m in IPV4.finditer(line):
            ip = m.group(1)
            if any(int(p) > 255 for p in ip.split(".")):
                continue
            if not any(rx.fullmatch(ip) for rx in ips):
                found.append(f"{name}:{n}: IP-адрес {ip} не из списка разрешённых")
        m = SECRET.search(line)
        if m and not name.endswith((".md",)) and "example" not in line.lower() and "private-data: ignore" not in line and re.search(r"\d", m.group(2)) and not line[m.end():].lstrip().startswith("("):
            found.append(f"{name}:{n}: похоже на секрет в коде ({m.group(1)}=…)")
    return found


def main() -> int:
    allowed, ips = load_allow()
    deny = []
    extra = os.environ.get("PRIVATE_DENY_FILE")
    if extra and Path(extra).is_file():
        deny = [re.compile(ln.strip(), re.I) for ln in Path(extra).read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    problems: list[str] = []
    for f in tracked_files():
        p = ROOT / f
        if f == SELF or p.name in SKIP_NAMES or p.suffix.lower() in SKIP_SUFFIX or not p.is_file():
            continue
        try:
            problems += scan_text(f, p.read_text(encoding="utf-8"), allowed, ips, deny)
        except (UnicodeDecodeError, OSError):
            continue
    if "--history" in sys.argv:
        log = subprocess.run(["git", "log", "--all", "-p", "--no-color", "--format=commit %h", "-U0"], cwd=ROOT, capture_output=True).stdout.decode("utf-8", "replace")
        commit, cur, seen = "?", "", set()
        for line in log.splitlines():
            if line.startswith("commit "):
                commit = line[7:]
            elif line.startswith("+++ "):
                cur = line[6:] if line.startswith("+++ b/") else line[4:]
            elif line.startswith("+") and not line.startswith("+++") and cur and not cur.endswith(tuple(SKIP_SUFFIX)) and cur.split("/")[-1] not in SKIP_NAMES and cur != SELF:
                for item in scan_text(f"{commit}:{cur}", line[1:], allowed, ips, deny):
                    key = item.split(": ", 1)[-1]
                    if key not in seen:
                        seen.add(key)
                        problems.append(item)
    if problems:
        print("Найдены возможные частные данные (замените на универсальные значения вроде example.local либо внесите безобидное в scripts/private-data.allow):")
        limit = None if "--all" in sys.argv else 200
        for item in problems[:limit]:
            print("  " + item)
        if limit and len(problems) > limit:
            print(f"  … и ещё {len(problems) - limit} (все: --all)")
        return 1
    print("Частных данных не найдено.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
