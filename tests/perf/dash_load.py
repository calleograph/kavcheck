#!/usr/bin/env python3
"""Нагрузочная проверка страниц зон на работающей установке: время открытия каждой зоны (сводка и первая страница таблицы), типовые фильтры, параллельное открытие одной зоны.
    python3 tests/perf/dash_load.py http://127.0.0.1:18080 admin 'пароль' [параллельно=10]
Пишет в stdout таблицу времени (мс) и размер ответа; код возврата 1, если любая страница отвечает дольше 2 секунд."""
import concurrent.futures as cf
import json
import statistics
import sys
import time
import urllib.parse
import urllib.request
import http.cookiejar

base, user, pw = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
par = int(sys.argv[4]) if len(sys.argv) > 4 else 10
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
H = {"Origin": base, "Content-Type": "application/json"}


def call(method, path, body=None, timeout=60):
    req = urllib.request.Request(base + "/api/v1" + path, method=method, headers=H, data=json.dumps(body).encode() if body is not None else None)
    t = time.perf_counter()
    with op.open(req, timeout=timeout) as r:
        raw = r.read()
    return (time.perf_counter() - t) * 1000, len(raw), json.loads(raw or b"null")


_, _, lg = call("POST", "/auth/login", {"login": user, "password": pw})
H["X-CSRF-Token"] = lg["csrf_token"]
ms, size, ov = call("GET", "/zones")
rows = [("обзор зон", ms, size)]
zones = sorted(ov["items"], key=lambda z: -z["stats"]["total"])
for z in zones[:8]:
    m, s, d = call("GET", f"/zones/{z['id']}?limit=50")
    rows.append((f"зона «{z['name'][:30]}» ({z['stats']['total']} комп.)", m, s))
big = zones[0]["id"]
for label, q in (("фильтр: критические", "state=critical"), ("фильтр: CVE", "cve=CVE-2024*"), ("фильтр: программа", "product=*Chrome*"), ("поиск по имени", "q=*-1*"), ("сортировка по IP", "sort=ip"), ("все, включая неактивные", "activity=all")):
    m, s, d = call("GET", f"/zones/{big}?limit=50&{q}")
    rows.append((f"{label} (найдено {d['total']})", m, s))
d0 = call("GET", f"/zones/{big}?limit=1")[2]
if d0["items"]:
    h = d0["items"][0]
    m, s, _ = call("GET", f"/zones/{big}/hosts/{h['source_id']}/{h['host_id']}")
    rows.append(("карточка компьютера", m, s))
with cf.ThreadPoolExecutor(par) as ex:
    t = time.perf_counter()
    res = list(ex.map(lambda _: call("GET", f"/zones/{big}?limit=50")[0], range(par * 3)))
    wall = (time.perf_counter() - t) * 1000
rows.append((f"{par * 3} открытий зоны, {par} параллельно: медиана / максимум / всего", statistics.median(res), max(res)))
width = max(len(r[0]) for r in rows)
bad = 0
for name, m, s in rows:
    print(f"{name:<{width}}  {m:8.0f} мс  {s:>9}")
    bad += m > 2000
print(f"всего на параллельную серию: {wall:.0f} мс")
sys.exit(1 if bad else 0)
