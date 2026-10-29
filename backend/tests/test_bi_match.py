"""Сопоставление BI ↔ KSC (без ложных объединений), SMB: выбор файла, разрешённые серверы, защита от недокопированного файла; служба worker: расписание, повторы, хранение копий."""
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.bi import match as M
from app.bi import read as R
from app.bi import service as SV
from app.bi import smb as S
from app.models import BiImport, BiMatch, BiSource, DeviceUser, KscSource, ZcHost, ZcSource, utcnow
from tests.test_bi_import import BASE, T0, row, run, source, xlsx

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)


async def ksc(app, name, hosts, users=()):
    """Источник KSC с подготовленными данными зон: hosts — (host_id, имя, ОС, has_av, p_rtp, fqdn)."""
    async with app.state.session_maker() as db:
        k = KscSource(name=name, host="sql.example.local", database="KAV", username="ro")
        db.add(k)
        await db.flush()
        db.add(ZcSource(source_id=k.id, gen=1, status="ready"))
        for hid, n, os, has_av, rtp, fqdn in hosts:
            db.add(ZcHost(source_id=k.id, host_id=hid, gen=1, name=n, os=os, has_av=has_av, p_rtp=rtp, p_no_av=not has_av, active=True, data={"fqdn": fqdn, "ip": "192.0.2.10"}))
        for hid, login in users:
            db.add(DeviceUser(source_id=k.id, host_id=hid, user_key=login, login=login, domain="example", kind="user", resolved=True, first_seen_at=NOW, last_seen_at=NOW, last_session_at=NOW))
        await db.commit()
        return k.id


async def levels(app, sid) -> dict:
    async with app.state.session_maker() as db:
        q = select(BiMatch.host_name, BiMatch.level, BiMatch.issues).where(BiMatch.bi_source_id == sid)
        return {(n, lv): iss for n, lv, iss in (await db.execute(q)).all()}


async def count(app, sid, name) -> int:
    async with app.state.session_maker() as db:
        return len((await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid, BiMatch.host_name == name))).scalars().all())


async def test_matching_levels_never_merge_on_name_alone(app, tmp_path):
    k1 = await ksc(app, "KSC A", [(1, "WS-001", "Windows 10 Pro", True, False, "ws-001.example.local"), (2, "WS-002", "Windows 10", True, False, ""), (3, "srv-app01", "Microsoft Windows Server 2019", True, False, ""),
                                  (4, "MAC-007", "", False, False, ""), (5, "Личный ПК", "Windows 11", True, False, "")], users=[(2, "a.petrova")])
    k2 = await ksc(app, "KSC B", [(10, "WS-002", "Windows 10", True, False, "")])
    sid = await source(app)
    rows = [*BASE, row("Без ОС", "n.os@example.local", "Отдел", "WS-777", os="")]
    await ksc(app, "KSC C", [(20, "ws-777", "Windows 10", True, False, "")])
    await run(app, sid, xlsx(tmp_path / "f.xlsx", rows))
    await M.run(app.state.session_maker, sid)
    lv = await levels(app, sid)
    assert ("WS-001", "auto") in lv                                      # имя единственное + ОС совпадает
    assert ("WS-002", "ambiguous") in lv and await count(app, sid, "WS-002") == 2                # одно имя в двух KSC — не объединять, даже при совпавшей учётной записи
    assert ("srv-app01", "conflict") in lv                               # BI: Linux, KSC: Windows — противоречие
    assert ("MAC-007", "candidate") in lv                                # у KSC нет ОС: только имя — требует подтверждения
    assert ("ws-777", "candidate") in lv                                 # у BI нет ОС
    assert not any(k[0] == "Личный ПК" for k in lv)                      # условные имена по имени не сопоставляются
    async with app.state.session_maker() as db:
        blk = await R.host_block(db, k1, 4, pd=True)
        assert blk["devices"] == [] and blk["candidates"][0]["level"] == "candidate" and "не подтверждено" in blk["note"]
        blk = await R.host_block(db, k1, 1, pd=False)
        assert blk["devices"][0]["owner"]["person"]["name"] == "Иванов Иван Иванович" and blk["devices"][0]["owner"]["person"]["email"] == ""     # почта скрыта без прав
        assert (await R.owners_for(db, k1, [1, 2, 4], pd=True)).keys() == {1}
    _ = k2


async def test_user_corroboration_and_av_discrepancies(app, tmp_path):
    k = await ksc(app, "KSC", [(1, "WS-001", "", False, False, ""), (2, "WS-002", "Windows 10", True, True, "")], users=[(1, "i.ivanov"), (2, "someone")])
    sid = await source(app)
    await run(app, sid, xlsx(tmp_path / "f.xlsx", [*BASE[:2]]))
    await M.run(app.state.session_maker, sid)
    lv = await levels(app, sid)
    iss1 = lv[("WS-001", "auto")]                                         # ОС у KSC нет, но учётная запись KSC совпадает с почтой сотрудника
    assert any(i["code"] == "av_missing" for i in iss1)                   # BI «использует антивирус», KSC — продукта нет: показываем расхождение, показатели не меняем
    iss2 = lv[("WS-002", "auto")]
    assert {i["code"] for i in iss2} >= {"av_broken", "user"}
    async with app.state.session_maker() as db:
        out = await R.devices(db, flt="issues", pd=True)
        assert {x["name"] for x in out["items"]} == {"WS-001", "WS-002"}
    _ = k


async def test_admin_decisions_survive_rematch(app, tmp_path):
    k = await ksc(app, "KSC", [(4, "MAC-007", "", False, False, ""), (5, "WS-002", "Windows 10", True, False, ""), (6, "WS-002", "Windows 10", True, False, "")])
    sid = await source(app)
    await run(app, sid, xlsx(tmp_path / "f.xlsx", BASE))
    await M.run(app.state.session_maker, sid)
    async with app.state.session_maker() as db:
        dev = {m.host_id: m.device_id for m in (await db.execute(select(BiMatch).where(BiMatch.bi_source_id == sid))).scalars()}
        await db.execute(BiMatch.__table__.delete().where(BiMatch.host_id.in_((4, 5))))
        db.add(BiMatch(device_id=dev[4], bi_source_id=sid, ksc_source_id=k, host_id=4, host_name="MAC-007", level="confirmed", decided_by="admin", decided_at=utcnow()))
        db.add(BiMatch(device_id=dev[5], bi_source_id=sid, ksc_source_id=k, host_id=5, host_name="WS-002", level="rejected", decided_by="admin", decided_at=utcnow()))
        await db.commit()
    await M.run(app.state.session_maker, sid, force=True)
    lv = await levels(app, sid)
    assert ("MAC-007", "confirmed") in lv and ("MAC-007", "candidate") not in lv
    assert ("WS-002", "rejected") in lv and [k_ for k_ in lv if k_[0] == "WS-002" and k_[1] != "rejected"] == [("WS-002", "ambiguous")]   # отклонённая пара не предлагается, а второй одноимённый компьютер не становится «предполагаемым»
    assert await M.run(app.state.session_maker, sid) is None                # без изменений снимка и данных KSC — пропуск


# ------------------------------------------------------------------------------------------------ SMB
def fi(name, s, m=0):
    return S.FileInfo(name, 100, datetime(2026, 10, 29, 6, 0, tzinfo=timezone.utc) + timedelta(seconds=s))


def test_choose_fixed_auto_temp_and_ambiguous():
    files = [fi("computers.xlsx", 0), fi("export_20261028.xlsx", -86400), fi("~$export.xlsx", 100), fi("export.xlsx.tmp", 200), fi("notes.txt", 300)]
    assert S.choose(files, "fixed", "COMPUTERS.xlsx")[0].name == "computers.xlsx"
    assert S.choose(files, "fixed", "missing.xlsx")[0] is None
    assert S.choose(files, "auto", "export*.xlsx")[0].name == "export_20261028.xlsx"           # временные и блокировочные файлы пропущены
    assert S.choose(files, "auto", "*.xlsx")[0].name == "computers.xlsx"
    hit, cand, why = S.choose([fi("a.xlsx", 0), fi("b.xlsx", 30)], "auto", "*.xlsx")
    assert hit is None and len(cand) == 2 and "Несколько одинаково новых" in why               # случайный импорт не выполняется
    assert S.choose([], "auto", "*.xlsx")[2].startswith("В папке нет")


def test_host_allowlist_and_unsafe_paths():
    assert S.host_allowed("files.example.local", []) is None
    assert S.host_allowed("127.0.0.1", []) and S.host_allowed("localhost", []) and S.host_allowed("169.254.1.1", [])
    assert S.host_allowed("files.example.local", ["*.example.local"]) is None and S.host_allowed("evil.example.org", ["*.example.local"])
    assert S.host_allowed("192.0.2.15", ["192.0.2.0/24"]) is None and S.host_allowed("198.51.100.1", ["192.0.2.0/24"])
    with pytest.raises(S.SmbError):
        S._unc(S.Conn(host="h", share="s", path="a/../b"))
    assert S._unc(S.Conn(host="h", share="bi", path="exports/daily"), "x.xlsx") == "\\\\h\\bi\\exports\\daily\\x.xlsx"


class FakeSmb:
    """Папка SMB в памяти: stat меняется на заданных вызовах (BI-система ещё пишет файл)."""

    def __init__(self, src: Path, changes=()):
        self.src, self.n, self.changes = src, 0, set(changes)

    def stat(self, name):
        self.n += 1
        return S.FileInfo(name, self.src.stat().st_size + (self.n if self.n in self.changes else 0), datetime(2026, 10, 29, tzinfo=timezone.utc))

    def copy(self, name, dst, max_bytes):
        data = self.src.read_bytes()
        if len(data) > max_bytes:
            raise S.SmbError("size", "big")
        dst.write_bytes(data)
        return len(data)


def test_fetch_stable_rejects_file_being_written(tmp_path):
    f = xlsx(tmp_path / "c.xlsx", BASE)
    assert S.fetch_stable(FakeSmb(f), "c.xlsx", tmp_path / "ok.xlsx", 10**7, 0).size == f.stat().st_size
    with pytest.raises(S.SmbError, match="ещё изменяется"):
        S.fetch_stable(FakeSmb(f, changes={2}), "c.xlsx", tmp_path / "x.xlsx", 10**7, 0)
    with pytest.raises(S.SmbError, match="во время копирования"):
        S.fetch_stable(FakeSmb(f, changes={3}), "c.xlsx", tmp_path / "y.xlsx", 10**7, 0)
    assert not (tmp_path / "y.xlsx").exists()
    with pytest.raises(S.SmbError, match="big"):
        S.fetch_stable(FakeSmb(f), "c.xlsx", tmp_path / "z.xlsx", 10, 0)


# ------------------------------------------------------------------------------------------------ служба worker
def test_schedule_next_run_in_source_timezone():
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("Europe/Moscow")
    assert SV.next_run("06:00", tz, datetime(2026, 10, 29, 2, 0, tzinfo=timezone.utc)) == datetime(2026, 10, 29, 3, 0, tzinfo=timezone.utc)
    assert SV.next_run("06:00", tz, datetime(2026, 10, 29, 3, 0, tzinfo=timezone.utc)) == datetime(2026, 10, 30, 3, 0, tzinfo=timezone.utc)


async def test_service_fixed_and_variable_names_unavailable_smb_and_retention(app, tmp_path, monkeypatch):
    share = tmp_path / "share"
    share.mkdir()
    state = {"down": False, "t": T0}

    def fake_fetch(conn, mode, rule, allowed, dst, max_bytes, stable_s, on_fetch=None):
        if state["down"]:
            raise S.SmbError("tcp", "Порт 445 сервера files.example.local недоступен: Connection refused")
        files = [S.FileInfo(p.name, p.stat().st_size, datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)) for p in share.iterdir()]
        hit, _c, why = S.choose(files, mode, rule)
        if hit is None:
            raise S.SmbError("choose", why)
        dst.write_bytes((share / hit.name).read_bytes())
        return S.FileInfo(hit.name, hit.size, state["t"])

    monkeypatch.setattr(SV.BiService, "_fetch", staticmethod(fake_fetch))
    svc = SV.BiService(app.state.session_maker, app.state.settings, app.state.settings_svc)
    sid = await source(app, keep_files=1)
    xlsx(share / "computers.xlsx", BASE)
    imp = await svc.run_source(sid)
    assert imp.status == "ok" and imp.trigger == "schedule" and imp.stored
    xlsx(share / "computers.xlsx", BASE[:5])                               # BI перезаписала файл с прежним именем
    state["t"] = T0 + timedelta(days=1)
    imp2 = await svc.run_source(sid)
    assert imp2.status == "ok" and imp2.rows_gone == 1
    async with app.state.session_maker() as db:
        stored = [i for i in (await db.execute(select(BiImport).where(BiImport.source_id == sid))).scalars() if i.stored]
        assert [i.id for i in stored] == [imp2.id]                         # хранится одна копия исходного файла, история импортов — полная
        assert (Path(app.state.settings.data_dir) / "bi" / stored[0].stored).exists()
        s = await db.get(BiSource, sid)
        s.file_mode, s.file_name = "auto", "export_*.xlsx"
        await db.commit()
    (share / "computers.xlsx").unlink()
    xlsx(share / "export_20261030_0600.xlsx", BASE)
    state["t"] = T0 + timedelta(days=2)
    assert (await svc.run_source(sid)).status == "ok"                      # имя файла меняется: выбирается новейший по маске
    state["down"] = True
    failed = await svc.run_source(sid)
    assert failed.status == "failed" and "недоступен" in failed.message
    async with app.state.session_maker() as db:
        s = await db.get(BiSource, sid)
        assert s.fail_n == 1 and s.last_error and s.last_import_id is not None      # прежний снимок остаётся опубликованным
        s.last_try_at = utcnow() - timedelta(hours=2)
        assert SV.due(s, utcnow())                                         # повтор через retry_minutes
        s.fail_n = 9
        assert not SV.due(s, utcnow()) or s.next_run_at <= utcnow()
    _ = uuid
