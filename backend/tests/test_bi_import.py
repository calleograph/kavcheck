"""BI-выгрузки: разбор и проверка Excel, повторные импорты, история владельцев, отклонение некорректных снимков без порчи накопленной истории."""
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import openpyxl
import pytest
from sqlalchemy import select

from app.bi import importer as IM
from app.bi import profile as PR
from app.models import BiDevice, BiImport, BiOwner, BiPerson, BiRecord, BiSource

HDR = ["ФИО сотрудника", "Рабочая почта", "Департамент", "Дата создания УЗ", "Личная техника", "Версия ОС", "Процессор", "Имя рабочей станции", "Использует антивирус",
       "Сторонний антивирус", "Дата установления связи с хостом", "Из базы касперского", "Дата ручного исправления", "Из ручного справочника"]
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def row(fio, email, dept, host, os="Windows 10 Pro", personal="Нет", av="Да", other="", seen="15.09.2026", kav="Да", manual="", hand="Нет", cpu="Intel Core i5", created="01.02.2020"):
    return [fio, email, dept, created, personal, os, cpu, host, av, other, seen, kav, manual, hand]


BASE = [row("Иванов Иван Иванович", "i.ivanov@example.local", "Департамент ИТ", "WS-001"),
        row("Петрова Анна Сергеевна", "a.petrova@example.local", "Бухгалтерия", "WS-002"),
        row("Сидоров Пётр", "p.sidorov@example.local", "Департамент ИТ", "srv-app01", os="Astra Linux 1.7"),
        row("Кузнецова Мария", "m.kuz@example.local", "Маркетинг", "MAC-007", os="macOS 14"),
        row("Иванов Иван Иванович", "i.ivanov@example.local", "Департамент ИТ", "Личный ПК", personal="Да", os="Windows 11"),
        row("Петрова Анна Сергеевна", "a.petrova@example.local", "Бухгалтерия", "Личный ПК", personal="Да", os="macOS", seen="01.01.2037")]


def xlsx(path: Path, rows, headers=HDR, sheet="Table 1", bold=False):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet
    ws.append(headers)
    if bold:
        for c in ws[1]:
            c.font = openpyxl.styles.Font(bold=True)
    for r in rows:
        ws.append(r)
    wb.save(path)
    return path


async def source(app, **opt) -> uuid.UUID:
    async with app.state.session_maker() as db:
        s = BiSource(name=f"BI {uuid.uuid4().hex[:6]}", smb_host="files.example.local", smb_share="bi", file_mode="fixed", file_name="computers.xlsx", timezone="Europe/Moscow",
                     profile=PR.validate_profile(PR.suggest(HDR)), options={"stable_s": 0, **opt})
        db.add(s)
        await db.commit()
        return s.id


async def run(app, sid, path, at=T0, **kw) -> BiImport:
    return await IM.import_file(app.state.session_maker, sid, path, file_name=path.name, file_size=path.stat().st_size, file_mtime=at, trigger="manual", by="test", **kw)


async def owners(app, sid) -> dict:
    """{(имя устройства, почта): (present связи, present устройства)}"""
    async with app.state.session_maker() as db:
        q = select(BiDevice.name, BiPerson.email, BiOwner.present, BiDevice.present, BiOwner.first_seen_at, BiOwner.last_seen_at, BiOwner.seen_n).join(BiDevice, BiDevice.id == BiOwner.device_id) \
            .join(BiPerson, BiPerson.id == BiOwner.person_id).where(BiOwner.source_id == sid)
        return {(n, e): (op, dp, f, l, s) for n, e, op, dp, f, l, s in (await db.execute(q)).all()}


def test_profile_suggest_maps_sample_columns():
    p = PR.validate_profile(PR.suggest(HDR))
    assert p["columns"]["device_name"] == "Имя рабочей станции" and p["columns"]["person_name"] == "ФИО сотрудника" and p["columns"]["email"] == "Рабочая почта"
    assert p["columns"]["av_uses"] == "Использует антивирус" and p["columns"]["av_other"] == "Сторонний антивирус" and p["columns"]["observed_at"].startswith("Дата установления")
    assert p["columns"]["account_created"] == "Дата создания УЗ" and "Процессор" not in p["columns"].values()
    assert p["origin"] == ["Из базы касперского", "Из ручного справочника"]
    with pytest.raises(PR.ProfileError):
        PR.validate_profile({"columns": {"person_name": "ФИО"}})


def test_row_normalization_dates_generic_and_families():
    p = PR.validate_profile(PR.suggest(HDR))
    tz = IM.ZoneInfo("Europe/Moscow")
    r, why, warns = PR.parse_row(dict(zip(HDR, BASE[5])), p, tz, T0)
    assert r["generic"] and r["dkey"].startswith("g:e:a.petrova@example.local:") and r["personal"] is True
    assert "future:observed_at" in r["flags"] and PR.trusted(r, "observed_at") is None and r["observed_at"].startswith("2036-12-31T21")    # дата сохранена как есть (в UTC), не подменена
    assert any(w["code"] == "future_date" for w in warns)
    r2, *_ = PR.parse_row(dict(zip(HDR, BASE[0])), p, tz, T0)
    assert r2["dkey"] == "n:ws-001" and r2["origin"] == ["Из базы касперского"] and r2["extra"] == {"Процессор": "Intel Core i5"} and PR.trusted(r2, "observed_at") is not None
    assert PR.os_family("Astra Linux 1.7") == "linux" and PR.os_family("macOS 14") == "mac" and PR.os_family("Windows 10 Pro") == "windows"
    assert PR.parse_row(dict(zip(HDR, ["Без компьютера", "x@example.local", "", "", "", "", "", "", "", "", "", "", "", ""])), p, tz, T0)[1].startswith("нет имени")
    assert PR.parse_row(dict(zip(HDR, ["", "", "", "", "", "", "", "Личный ПК", "", "", "", "", "", ""])), p, tz, T0)[1].startswith("условное имя")
    assert PR.parse_row(dict.fromkeys(HDR), p, tz, T0) == (None, "", [])
    assert PR.short_name("WS-001.example.local") == "ws-001" and PR.short_name("EXAMPLE\\WS-9") == "ws-9" and PR.short_name("192.0.2.7") == "192.0.2.7"


async def test_import_sample_and_repeat(app, tmp_path):
    sid = await source(app)
    f = xlsx(tmp_path / "computers.xlsx", BASE)
    imp = await run(app, sid, f)
    assert imp.status == "ok", imp.message
    assert (imp.rows_read, imp.rows_valid, imp.rows_new, imp.rows_rejected, imp.persons_n) == (6, 6, 6, 0, 4)
    assert any(w["code"] == "future_date" for w in imp.warnings) and any(w["code"] == "generic" for w in imp.warnings)
    async with app.state.session_maker() as db:
        devs = {d.name: d for d in (await db.execute(select(BiDevice).where(BiDevice.source_id == sid))).scalars()}
        assert {d.os_family for d in devs.values()} == {"windows", "linux", "mac"}
        n_generic = (await db.execute(select(BiDevice).where(BiDevice.source_id == sid, BiDevice.generic.is_(True)))).scalars().all()
        assert len(n_generic) == 2                                       # «Личный ПК» двух сотрудников — разные устройства
        fut = (await db.execute(select(BiOwner).join(BiDevice, BiDevice.id == BiOwner.device_id).where(BiDevice.generic.is_(True), BiOwner.src_seen_at.is_(None)))).scalars().all()
        assert len(fut) == 1                                             # дата 2037 года не стала датой наблюдения
        p = (await db.execute(select(BiPerson).where(BiPerson.email == "i.ivanov@example.local"))).scalar_one()
        assert p.account_created is not None                             # хранится как атрибут сотрудника, не как начало владения
    async with app.state.session_maker() as db:
        (await db.get(BiSource, sid)).last_error = "прежняя ошибка"
        await db.commit()
    again = await run(app, sid, f, at=T0 + timedelta(days=1))
    assert again.status == "unchanged" and "совпадает с уже импортированным" in again.message
    async with app.state.session_maker() as db:
        assert (await db.get(BiSource, sid)).last_error is None                 # получение успешно — прежняя ошибка снята
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(BiRecord).where(BiRecord.source_id == sid))).scalars().all()) == 6


async def test_same_content_other_order_and_formatting_extends_observation(app, tmp_path):
    sid = await source(app)
    await run(app, sid, xlsx(tmp_path / "a.xlsx", BASE))
    imp = await run(app, sid, xlsx(tmp_path / "b.xlsx", list(reversed(BASE)), bold=True), at=T0 + timedelta(days=1))
    assert imp.status == "unchanged" and "оформление или порядок" in imp.message
    o = await owners(app, sid)
    assert o[("WS-001", "i.ivanov@example.local")][3] == T0 + timedelta(days=1)          # даты наблюдения продлены
    async with app.state.session_maker() as db:
        assert len((await db.execute(select(BiRecord).where(BiRecord.source_id == sid))).scalars().all()) == 6


async def test_owner_change_disappearance_and_return_keep_history(app, tmp_path):
    sid = await source(app)
    await run(app, sid, xlsx(tmp_path / "1.xlsx", BASE))
    changed = [row("Смирнов Олег", "o.smirnov@example.local", "Департамент ИТ", "WS-001"), *BASE[1:]]
    imp = await run(app, sid, xlsx(tmp_path / "2.xlsx", changed), at=T0 + timedelta(days=14))
    assert imp.status == "ok" and (imp.rows_new, imp.rows_same, imp.rows_gone) == (1, 5, 1)
    o = await owners(app, sid)
    assert o[("WS-001", "i.ivanov@example.local")][:2] == (False, True)        # прежний владелец сохранён
    assert o[("WS-001", "o.smirnov@example.local")][:2] == (True, True)
    assert o[("WS-001", "i.ivanov@example.local")][3] == T0 and o[("WS-001", "o.smirnov@example.local")][2] == T0 + timedelta(days=14)   # смена — между снимками, точная дата не выдумывается
    gone = [r for r in changed if r[7] != "WS-002"]
    await run(app, sid, xlsx(tmp_path / "3.xlsx", gone), at=T0 + timedelta(days=20))
    o = await owners(app, sid)
    assert o[("WS-002", "a.petrova@example.local")][:2] == (True, False)         # устройство исчезло: связь остаётся, текущий статус неизвестен
    await run(app, sid, xlsx(tmp_path / "4.xlsx", changed), at=T0 + timedelta(days=30))
    o = await owners(app, sid)
    back = o[("WS-002", "a.petrova@example.local")]
    assert back[:2] == (True, True) and back[2] == T0 and back[4] == 3           # вернулось с тем же сотрудником: история не прервана


async def test_rejected_snapshots_keep_published_data(app, tmp_path):
    sid = await source(app, drift_pct=40)
    await run(app, sid, xlsx(tmp_path / "ok.xlsx", BASE * 5 + [row(f"Сотрудник {i}", f"u{i}@example.local", "Отдел", f"WS-{100 + i}") for i in range(20)]))
    before = await owners(app, sid)
    no_col = xlsx(tmp_path / "nocol.xlsx", [r[:7] + r[8:] for r in BASE], headers=HDR[:7] + HDR[8:])
    r1 = await run(app, sid, no_col, at=T0 + timedelta(days=1))
    assert r1.status == "rejected" and "Нет обязательных столбцов" in r1.message and "Имя рабочей станции" in r1.message
    broken = tmp_path / "broken.xlsx"
    broken.write_bytes(xlsx(tmp_path / "full.xlsx", BASE).read_bytes()[:900])        # недокопированный файл
    r2 = await run(app, sid, broken, at=T0 + timedelta(days=1))
    assert r2.status == "rejected" and "XLSX" in r2.message
    r3 = await run(app, sid, xlsx(tmp_path / "small.xlsx", BASE[:3]), at=T0 + timedelta(days=1))
    assert r3.status == "rejected" and "изменилось слишком сильно" in r3.message
    old = await run(app, sid, xlsx(tmp_path / "old.xlsx", BASE * 5 + [row(f"Сотрудник {i}", f"u{i}@example.local", "Отдел", f"WS-{100 + i}") for i in range(21)]), at=T0 - timedelta(days=3))
    assert old.status == "rejected" and "старше" in old.message
    assert await owners(app, sid) == before                                   # отказы не тронули историю
    forced = await run(app, sid, xlsx(tmp_path / "small2.xlsx", BASE[:3]), at=T0 + timedelta(days=2), force=True)
    assert forced.status == "ok"


async def test_partial_import_reports_rows_and_does_not_mark_absence(app, tmp_path):
    sid = await source(app, max_reject_pct=50)
    await run(app, sid, xlsx(tmp_path / "1.xlsx", BASE))
    bad = [*BASE[:3], row("Без имени ПК", "x@example.local", "Отдел", ""), row("", "", "", "Личный ПК")]
    imp = await run(app, sid, xlsx(tmp_path / "2.xlsx", bad), at=T0 + timedelta(days=1))
    assert imp.status == "partial" and imp.rows_rejected == 2 and [e["row"] for e in imp.errors] == [5, 6]
    o = await owners(app, sid)
    assert o[("MAC-007", "m.kuz@example.local")][:2] == (True, True)          # неполный снимок не «удаляет» устройства
    strict = await source(app, partial=False)
    r = await run(app, strict, xlsx(tmp_path / "3.xlsx", bad))
    assert r.status == "rejected" and "частичный импорт выключен" in r.message


async def test_duplicates_and_multiple_owners_are_reported(app, tmp_path):
    sid = await source(app)
    rows = [*BASE, BASE[0], row("Орлов Илья", "i.orlov@example.local", "Отдел", "WS-001")]
    imp = await run(app, sid, xlsx(tmp_path / "d.xlsx", rows))
    codes = {w["code"]: w["n"] for w in imp.warnings}
    assert codes["dup"] == 1 and codes["multi_owner"] == 1
    async with app.state.session_maker() as db:
        d = (await db.execute(select(BiDevice).where(BiDevice.source_id == sid, BiDevice.name == "WS-001"))).scalar_one()
        assert d.owners_now == 2


async def test_device_uid_tracks_rename(app, tmp_path):
    hdr = [*HDR, "Серийный номер"]
    sid = await source(app)
    async with app.state.session_maker() as db:
        s = await db.get(BiSource, sid)
        s.profile = PR.validate_profile(PR.suggest(hdr))
        await db.commit()
    await run(app, sid, xlsx(tmp_path / "1.xlsx", [[*BASE[0], "SN-42"]], headers=hdr))
    await run(app, sid, xlsx(tmp_path / "2.xlsx", [[*row("Иванов Иван Иванович", "i.ivanov@example.local", "Департамент ИТ", "WS-NEW-01"), "SN-42"]], headers=hdr), at=T0 + timedelta(days=1), force=True)
    async with app.state.session_maker() as db:
        d = (await db.execute(select(BiDevice).where(BiDevice.source_id == sid))).scalar_one()
        assert d.name == "WS-NEW-01" and d.names[0]["name"] == "WS-001" and "ws-001" in d.search
