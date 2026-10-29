"""Диагностический отчёт «Технического состояния» (JSON, TXT, HTML) для передачи разработчику.

Строится из той же сводки, что и страница (app/tech/collect.py): новых обращений к KSC, SMB или Docker нет. Секреты не попадают никогда: значения ключей
с «паролем», «токеном», «ключом» и т. п. заменяются, строки подключения и параметры URL с учётными данными маскируются. В режиме «для внешней передачи»
дополнительно заменяются IP-адреса, имена компьютеров и доменов, почта, идентификаторы, пути SMB и названия источников — одинаковое значение получает
одинаковую замену, чтобы связи в отчёте читались. Содержимое Excel и персональные данные в сводку не входят.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Any

SECRET_KEY = re.compile(r"(pass(word)?|secret|token|authorization|cookie|api[_-]?key|master[_-]?key|credential|private|session)", re.I)
_URL_CRED = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.I)
_ASSIGN = re.compile(r"(?i)\b([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|MASTER_KEY|CREDENTIAL)[A-Z0-9_]*)(\s*[=:]\s*)([^\s,;&\"']+)")
_QUERY = re.compile(r"(?i)((?:access_token|token|key|secret|password|pwd)=)[^&\s\"']+")
_IP4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_IP6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_HEXID = re.compile(r"\b[0-9a-f]{12}\b")                                       # имя хоста контейнера Docker
_FQDN = re.compile(r"\b(?=[a-z0-9-]*[a-z])[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+\.(?:local|lan|corp|internal|intra|home|ru|com|net|org|su|рф|io|info|biz|by|kz|ua|de|eu|uk)\b", re.I)
_SMB = re.compile(r"\\\\[^\\\s]+\\[^\s\"']*")
KEEP_HOSTS = {"github.com", "api.github.com", "ghcr.io", "nvd.nist.gov", "endoflife.date", "osv.dev", "cisa.gov", "www.cisa.gov", "bdu.fstec.ru", "example.local"}


class Masker:
    def __init__(self, external: bool, names: list[str] | None = None) -> None:
        self.external = external
        self.map: dict[str, str] = {}
        self.names = sorted({n for n in (names or []) if n and len(n) >= 3}, key=len, reverse=True)

    def _sub(self, kind: str, value: str) -> str:
        k = f"{kind}:{value.lower()}"
        if k not in self.map:
            self.map[k] = f"{kind}-{sum(1 for x in self.map if x.startswith(kind + ':')) + 1}"
        return self.map[k]

    def text(self, v: str) -> str:
        v = _URL_CRED.sub(lambda m: f"{m.group(1)}***:***@", v)
        v = _ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}***", v)
        v = _QUERY.sub(lambda m: m.group(1) + "***", v)
        if not self.external:
            return v
        for n in self.names:                                                       # названия источников KSC/BI могут содержать имя организации
            if n in v:
                v = v.replace(n, self._sub("источник", n))
        v = _SMB.sub(lambda m: "\\\\" + self._sub("smb", m.group(0)), v)
        v = _EMAIL.sub(lambda m: self._sub("почта", m.group(0)) + "@example.local", v)
        v = _UUID.sub(lambda m: self._sub("id", m.group(0)), v)
        v = _IP4.sub(lambda m: self._sub("ip", m.group(0)), v)
        v = _IP6.sub(lambda m: self._sub("ip", m.group(0)), v)
        v = _FQDN.sub(lambda m: m.group(0) if m.group(0).lower() in KEEP_HOSTS else self._sub("хост", m.group(0)), v)
        return _HEXID.sub(lambda m: self._sub("контейнер", m.group(0)), v)

    def __call__(self, v: Any) -> Any:
        if isinstance(v, dict):
            return {k: ("***" if isinstance(k, str) and SECRET_KEY.search(k) and not isinstance(x, (bool, int, float, type(None))) else self(x)) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [self(x) for x in v]
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, datetime):
            return v.isoformat()
        return v


def build(state: dict, *, external: bool) -> dict:
    """Содержимое отчёта: без длинной истории замеров (последние 20 точек), с обезличенными текстами SQL."""
    names = [x["name"] for x in state["sources"]["ksc"]] + [x["name"] for x in state["sources"]["bi"]]
    m = Masker(external, names)
    services = []
    for sv in state["services"]:
        r = dict(sv["res"])
        r["hist"] = r.get("hist", [])[-20:]
        services.append({**sv, "res": r})
    rep = {"kind": "Диагностический отчёт KAV Checker", "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "для внешней передачи (адреса, имена и идентификаторы заменены)" if external else "внутренний",
           "version": state["version"], "commit": state["commit"], "built_at": state["built_at"], "level": state["level"], "problems": state["problems"], "thresholds": state["thresholds"],
           "host": {**(state["host"] or {}), "hist": (state["host"] or {}).get("hist", [])[-20:]} if state["host"] else None, "disk": state["disk"], "dirs": state["dirs"], "helper": state["helper"],
           "services": services, "jobs": state["jobs"], "postgres": {k: v for k, v in state["pg"].items() if k != "tables"} | {"tables": state["pg"].get("tables", {}).get("items", [])[:30],
                                                                                                                          "indexes": state["pg"].get("tables", {}).get("indexes", [])},
           "sources": state["sources"], "journal": state["journal"],
           "components": [{k: c.get(k) for k in ("title", "group", "installed", "verified", "latest", "status_ru", "why", "checked_at")} for c in state["components"]["items"]]}
    return json.loads(json.dumps(m(rep), default=str))


def to_text(rep: dict) -> str:
    out = [f"{rep['kind']} · {rep['generated_at']} · режим: {rep['mode']}", f"Версия {rep['version']} ({rep['commit']}), сборка {rep['built_at']}", f"Общее состояние: {LEVEL_RU.get(rep['level'], rep['level'])}", ""]
    out.append("== Проблемы ==")
    out += [f"[{LEVEL_RU.get(p['level'], p['level'])}] {p['area']}: {p['text']}" for p in rep["problems"]] or ["нет"]
    h = rep.get("host") or {}
    out += ["", "== Сервер ==", f"CPU: {h.get('cpu_pct')} % ({h.get('cpus')} ядер), load {h.get('load')}", f"ОЗУ: доступно {_gb(h.get('mem_available'))} из {_gb(h.get('mem_total'))}, swap свободно {_gb(h.get('swap_free'))} из {_gb(h.get('swap_total'))}",
            f"Диск данных: свободно {_gb((rep.get('disk') or {}).get('free'))} из {_gb((rep.get('disk') or {}).get('total'))}", "", "== Службы =="]
    for s in rep["services"]:
        r = s["res"]
        out.append(f"{s['title']}: {s['text']}; функции: {s['func']['text'] or '—'}; CPU {r.get('cpu_pct')} % ядра; память {_mb(r.get('mem'))} / {_mb(r.get('mem_limit'))}; пульс {str(s['heartbeat_age_s']) + ' с назад' if s.get('heartbeat_age_s') is not None else '—'}"
                   + (f"; Docker: {s['container'].get('state')}/{s['container'].get('health') or '—'}, перезапусков {s['container'].get('restarts')}" if s.get("container") else ""))
    j = rep["jobs"]
    out += ["", "== Фоновые задания ==", f"всего {j['counts']['total']}, ожидают {j['counts']['waiting']}, выполняются {j['counts']['running']}, без хода выполнения {j['counts']['stalled']}, "
            f"завершено за сутки {j['counts']['done_24h']}, с ошибкой {j['counts']['failed_24h']}"]
    for i in j["items"]:
        out.append(f"- {i['kind_ru']} · {i.get('scope') or '—'}: {i['state_ru']}; этап «{i.get('stage') or '—'}»; ожидание {i.get('wait_s')} с; ход {i.get('progress_age_s')} с назад; пульс {i.get('heartbeat_age_s')} с назад"
                   + (f"; {i['reason']}" if i.get("reason") else ""))
    out += ["", "== История за сутки (по видам) =="] + [f"- {k['kind_ru']}: {k['n']} (ошибок {k['failed']}), среднее {k['avg_s']} с, максимум {k['max_s']} с, ожидание среднее {k['wait_avg_s']} с" for k in j["by_kind"]]
    p = rep["postgres"]
    out += ["", "== PostgreSQL ==", f"{'доступен' if p.get('ok') else 'НЕДОСТУПЕН ' + str(p.get('error'))}; версия {p.get('version')}; ответ {p.get('ping_ms')} мс; соединений {p.get('connections')} из {p.get('max_connections')}; "
            f"активных {p.get('active')}, ожидающих {p.get('waiting')}"]
    out += [f"- долгий запрос {q['query_s']} с ({q['app']}): {q['sql'][:300]}" for q in p.get("long", [])]
    out += [f"- блокировка: ждёт {lk['waiting']['app']} ({lk['waiting']['kind']}), держит {lk['holder']['app']} ({lk['holder'].get('state')})" for lk in p.get("locks", [])]
    out += [f"- таблица {t['table']}: {_mb(t['total'])}, строк ≈{t['rows_est']}, мёртвых {t['dead_pct']} %" for t in p.get("tables", [])[:15]]
    src = rep["sources"]
    out += ["", "== Источники =="]
    out += [f"KSC {k['name']}: проверка {'успешна' if k['check_ok'] else 'ОШИБКА' if k['check_ok'] is False else '—'} ({k['check_at']}); данные {k['sync']['at']} ({k['sync']['status']}); каталог {k['catalog']['at']}" for k in src["ksc"]]
    out += [f"BI {b['name']}: последний успех {b['last_ok_at']}, попытка {b['last_try_at']}, ошибка: {b['last_error'] or '—'}" for b in src["bi"]]
    pt = src["pentest"]
    out += [f"Pentest: {'отвечает' if pt['alive'] else 'не отвечает'}; Nmap {pt['nmap']}; NSE {pt['nse_scripts']}; Nuclei {pt['nuclei']['version']} (шаблоны {pt['nuclei']['templates']}); очередь {pt['queued']}, выполняется {pt['running']}"]
    out += ["", "== Журнал ==", f"ошибок за сутки {rep['journal']['errors_24h']}, предупреждений {rep['journal']['warn_24h']}"]
    out += [f"- {e['at']} [{e['level']}] {e['category']}: {e['message']}" for e in rep["journal"]["recent"]]
    out += ["", "== Компоненты =="] + [f"- {c['title']}: установлено {c['installed']}, проверено {c['verified']}, доступно {c['latest']} — {c['status_ru']}" for c in rep["components"]]
    return "\n".join(str(x) for x in out) + "\n"


def to_html(rep: dict) -> str:
    esc = html.escape
    body = esc(to_text(rep))
    return ("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Диагностический отчёт KAV Checker</title>"
            "<style>body{font:14px/1.5 system-ui,sans-serif;margin:24px;color:#1b2430;background:#fff}h1{font-size:20px;margin:0 0 4px}p{color:#5b6675;margin:0 0 16px}"
            "pre{white-space:pre-wrap;word-break:break-word;font:12.5px/1.55 ui-monospace,Consolas,monospace;background:#f5f7fa;border:1px solid #dde3ea;border-radius:8px;padding:16px}"
            "details{margin-top:16px}summary{cursor:pointer;color:#2457c5}</style></head><body>"
            f"<h1>Диагностический отчёт KAV Checker {esc(str(rep['version']))}</h1><p>{esc(rep['generated_at'])} · режим: {esc(rep['mode'])} · состояние: {esc(LEVEL_RU.get(rep['level'], rep['level']))}</p>"
            f"<pre>{body}</pre><details><summary>Полные данные (JSON)</summary><pre>{esc(json.dumps(rep, ensure_ascii=False, indent=1))}</pre></details></body></html>")


LEVEL_RU = {"ok": "исправно", "warn": "предупреждение", "bad": "неисправность", "unknown": "неизвестно"}


def _gb(v) -> str:
    return f"{v / 1024**3:.1f} ГБ" if isinstance(v, (int, float)) else "—"


def _mb(v) -> str:
    return f"{v / 1024**2:.0f} МБ" if isinstance(v, (int, float)) else "—"
