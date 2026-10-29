"""Изоляция источников KSC: данные, кэши и состояния каждого источника независимы; повторные подключения к одному KSC обнаруживаются; разные топологии SQL Server (несколько баз на одном
экземпляре, независимые экземпляры, недоступный сервер). Живые сценарии — при KSC_TEST_HOST (и KSC_TEST_HOST2 для второго независимого экземпляра)."""
import asyncio
import os
import uuid

import pytest
from sqlalchemy import select

from app.eol import compute as C
from app.models import Base, CatalogProduct, CatalogState, EolFinding, EolHost, EolHostStat, EolState, KscSource, utcnow
from app.services.sources import find_overlaps
from tests.conftest import login
from tests.test_eol_compute import TODAY, FakeKsc, hosts
from tests.test_eol_multisource import run, seed_many
from tests.test_hostvulns import ksc


def test_every_table_with_per_host_data_is_scoped_by_source():
    """Одинаковые идентификаторы компьютеров и записей реестра в разных KSC не должны сталкиваться: любая таблица с данными по компьютерам хранит источник."""
    external = {"ksc_sources", "ldap_connections"}                          # «host» здесь — адрес сервера, а не компьютер
    for t in Base.metadata.sorted_tables:
        cols = {c.name for c in t.columns}
        if t.name in external or not ({"host_id", "product_id", "install_id", "host"} & cols):
            continue
        src = "source_id" if "source_id" in cols else "ksc_source_id"           # bi_matches: компьютер KSC рядом с источником BI — столбец назван явно
        assert src in cols, f"{t.name}: данные по компьютерам без источника"
        pk = {c.name for c in t.primary_key.columns}
        uniques = {frozenset(c.name for c in i.columns) for i in t.indexes if i.unique}
        assert src in pk or any(src in u for u in uniques) or "id" in pk, f"{t.name}: ключ не содержит источник"


async def test_same_host_ids_names_and_products_in_two_sources_stay_separate(app):
    a, b = await seed_many(app, 2)
    await run(app, a, FakeKsc({11: [(1, 1), (2, 1)], 12: [(5, 1)], 13: []}, hosts()))                 # у обоих источников компьютеры 1, 2, 5 и одинаковые ОС и программы
    await run(app, b, FakeKsc({11: [(1, 1)], 12: [], 13: []}, hosts()))
    async with app.state.session_maker() as db:
        by_src = {sid: {(h.kind, h.subject, h.version, h.host_id) for h in (await db.execute(select(EolHost).where(EolHost.source_id == sid))).scalars()} for sid in (a, b)}
        stat = {sid: {s.host_id: s.n for s in (await db.execute(select(EolHostStat).where(EolHostStat.source_id == sid))).scalars()} for sid in (a, b)}
    assert by_src[a] != by_src[b] and by_src[b] < by_src[a]                                                # у второго только часть связей первого
    assert stat[a].get(5) and not stat[b].get(5)                                                          # компьютер 5 с устаревшей программой есть только у первого источника, хотя номер один и тот же


async def test_page_caches_are_keyed_by_source(client, app, monkeypatch):
    from app.ksc import vulns as V
    import app.api.vdb as vdb_api

    await login(client, "admin", "Admin-Passw0rd-123")
    s1 = (await client.post("/api/v1/admin/sources", json={"name": "KSC-1", "host": "a.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    s2 = (await client.post("/api/v1/admin/sources", json={"name": "KSC-2", "host": "b.example.local", "database": "KAV", "username": "u", "password": "p"})).json()
    monkeypatch.setattr(app.state.sources, "client", lambda src: type("C", (), {"tag": src.name})())

    async def on_host(c, hid):
        return [ksc([f"CVE-2024-{1 if c.tag == 'KSC-1' else 2}"])]

    async def ext(*_a):
        return [], True

    monkeypatch.setattr(V, "on_host", on_host)
    monkeypatch.setattr(vdb_api, "host_ext_items", ext)
    seen = {}
    for sid in (s1["id"], s2["id"]):
        seen[sid] = (await client.get("/api/v1/hosts/7/vulnerabilities", headers={"X-Source-Id": sid})).json()["items"][0]["keys"]      # компьютер 7 есть в обоих
    assert seen[s1["id"]] == ["CVE-2024-1"] and seen[s2["id"]] == ["CVE-2024-2"]


def _src(name, host, db="KAV", port=1433, check=None):
    return KscSource(id=uuid.uuid4(), name=name, host=host, port=port, database=db, username="u", password_enc="x", is_active=True, last_check=check)


def test_duplicate_connections_are_reported_but_independent_servers_are_not():
    same = find_overlaps([_src("A", "Ksc-01.Example.Local."), _src("B", "ksc-01.example.local")])
    assert [o["level"] for o in same.values().__iter__().__next__()] == ["exact"]                         # тот же сервер, порт и база
    ident = {"server": "SQL1", "db": "KAV"}
    likely = find_overlaps([_src("A", "192.0.2.5", check={"server_identity": ident, "hosts": 1200, "ksc_version": "15.1"}), _src("B", "sql1.example.local", check={"server_identity": ident, "hosts": 1200, "ksc_version": "15.1"})])
    assert sum(len(v) for v in likely.values()) == 2 and all(o["level"] == "likely" for v in likely.values() for o in v)
    other = find_overlaps([_src("A", "sql1", check={"server_identity": {"server": "SQL1", "db": "KAV"}, "hosts": 1200, "ksc_version": "15.1"}),
                           _src("B", "sql2", check={"server_identity": {"server": "SQL2", "db": "KAV"}, "hosts": 1200, "ksc_version": "15.1"})])
    assert other == {}                                                                                     # независимые KSC с одинаковыми базами и числом устройств дублем не считаются
    assert find_overlaps([_src("A", "sql1", db="KAV1"), _src("B", "sql1", db="KAV2")]) == {}               # две базы на одном экземпляре — разные KSC


async def test_admin_sources_list_warns_about_a_repeated_connection(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    for n in ("A", "B"):
        await client.post("/api/v1/admin/sources", json={"name": n, "host": "ksc.example.local", "database": "KAV", "username": "u", "password": "p"})
    items = (await client.get("/api/v1/admin/sources")).json()["items"]
    assert all(i["overlaps"] and i["overlaps"][0]["level"] == "exact" for i in items) and len(items) == 2


# ---- живые топологии SQL Server
HOST1, HOST2 = os.environ.get("KSC_TEST_HOST"), os.environ.get("KSC_TEST_HOST2")


async def _add(client, name, host, port, db):
    r = await client.post("/api/v1/admin/sources", json={"name": name, "host": host, "port": port, "database": db, "username": os.environ.get("KSC_TEST_USER", "kavcheck_ro"),
                                                         "password": os.environ.get("KSC_TEST_PASSWORD", "KavCheck-Test-Pass-1"), "tls_mode": "request", "trust_server_cert": True, "connect_timeout_s": 4})
    return uuid.UUID(r.json()["id"])


@pytest.mark.skipif(not HOST1, reason="нужен SQL Server (KSC_TEST_HOST)")
async def test_live_two_databases_one_instance_and_an_unreachable_server_in_parallel(client, app):
    from app.services import catalog as CS

    await login(client, "admin", "Admin-Passw0rd-123")
    p1 = int(os.environ.get("KSC_TEST_PORT", "11433"))
    small, big = await _add(client, "small", HOST1, p1, "KAVTEST"), await _add(client, "big", HOST1, p1, "KAVBIG")
    dead = await _add(client, "dead", "127.0.0.1", 9, "KAV")                                               # порт, где никого нет
    s = CS.CatalogScheduler(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    await asyncio.gather(*(s.build(i, "тест") for i in (small, big, dead)))                                 # параллельно, у каждого свой исход
    async with app.state.session_maker() as db:
        st = {i: await db.get(CatalogState, i) for i in (small, big, dead)}
        n = {i: len((await db.execute(select(CatalogProduct.key).where(CatalogProduct.source_id == i))).scalars().all()) for i in (small, big, dead)}
    assert st[small].status == "ready" and st[big].status == "ready" and st[dead].status == "failed" and st[dead].built_at is None and st[dead].error
    assert n[small] > 0 and n[big] > 0 and n[dead] == 0 and n[small] != n[big]                             # данные двух баз не смешаны
    from app.eol.service import EolService
    from app.eol.sync import apply_products
    from tests.test_eol_compute import DOC

    await apply_products(app.state.session_maker, DOC["result"])
    svc = EolService(app.state.session_maker, app.state.settings_svc, app.state.sources, app.state.journal)
    await svc.tick()
    await asyncio.gather(*list(svc._tasks))
    async with app.state.session_maker() as db:
        eol = {i: await db.get(EolState, i) for i in (small, big, dead)}
    assert eol[small].computed_at and eol[big].computed_at and eol[small].error is None and eol[big].error is None
    assert dead not in await svc.due(TODAY) or eol.get(dead) is None or eol[dead].computed_at is None      # недоступный источник без каталога не считается и не мешает остальным


@pytest.mark.skipif(not (HOST1 and HOST2), reason="нужны два независимых SQL Server (KSC_TEST_HOST, KSC_TEST_HOST2)")
async def test_live_two_independent_instances_with_identical_data_do_not_mix(client, app):
    from app.services import catalog as CS

    await login(client, "admin", "Admin-Passw0rd-123")
    a = await _add(client, "inst1", HOST1, int(os.environ.get("KSC_TEST_PORT", "11433")), "KAVTEST")
    b = await _add(client, "inst2", HOST2, int(os.environ.get("KSC_TEST_PORT2", "11434")), "KAVTEST")     # та же схема и те же имена компьютеров на другом сервере
    s = CS.CatalogScheduler(app.state.session_maker, app.state.settings, app.state.settings_svc, app.state.journal)
    await asyncio.gather(s.build(a, "тест"), s.build(b, "тест"))
    async with app.state.session_maker() as db:
        pa = {r.key: r.hosts_all for r in (await db.execute(select(CatalogProduct).where(CatalogProduct.source_id == a))).scalars()}
        pb = {r.key: r.hosts_all for r in (await db.execute(select(CatalogProduct).where(CatalogProduct.source_id == b))).scalars()}
    async with app.state.session_maker() as db:
        assert (await db.get(CatalogState, b)).status == "ready", (await db.get(CatalogState, b)).error
    assert pa and pa == pb                                                                                  # одинаковое содержимое — одинаковые, но раздельные каталоги
    ov = (await client.get("/api/v1/admin/sources")).json()["items"]
    assert all(not i["overlaps"] for i in ov)                                                               # разные серверы дублями не считаются (до проверки идентичности — по адресам)
