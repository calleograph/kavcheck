"""Проверка настоящей выгрузки BI на всём конвейере импорта, без вывода персональных данных (только счётчики и тексты предупреждений).
Файл в репозиторий не кладётся. Запуск вручную:
    BI_REAL_FILE=/путь/выгрузка.xlsx pytest -s tests/test_bi_real_file.py --basetemp=<каталог вне /tmp, удалить после проверки>"""
import os
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import openpyxl
import pytest
from sqlalchemy import func, select

from app.bi import profile as PR
from app.bi import xlsx as X
from app.models import BiDevice, BiOwner, BiPerson, BiRecord
from tests.test_bi_import import run, source

REAL = os.environ.get("BI_REAL_FILE", "")
pytestmark = pytest.mark.skipif(not REAL, reason="нужен файл настоящей выгрузки (BI_REAL_FILE)")


async def test_real_export(app, tmp_path):
    path = Path(REAL)
    wb = X.open_book(path)
    try:
        hn, hdr = X.headers(X.pick_sheet(wb, ""), 0)
        rows = [vals for _n, vals in X.rows(X.pick_sheet(wb, ""), hn, hdr)]
    finally:
        wb.close()
    prof = PR.validate_profile(PR.suggest(hdr))
    unmapped = [h for h in hdr if h not in prof["columns"].values() and h not in prof["origin"]]
    print(f"\nстолбцов {len(hdr)}, сопоставлено {len(prof['columns'])}, признаков происхождения {len(prof['origin'])}, без сопоставления: {unmapped}")
    sid = await source(app)
    async with app.state.session_maker() as db:
        from app.models import BiSource  # noqa: PLC0415
        (await db.get(BiSource, sid)).profile = prof
        await db.commit()
    at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)            # как при получении с SMB: дата снимка — время изменения файла
    imp = await run(app, sid, path, at=at)
    print(f"импорт: {imp.status} — {imp.message}; строк {imp.rows_read}, записей {imp.rows_valid}, пустых {imp.rows_empty}, отклонено {imp.rows_rejected}, "
          f"устройств {imp.devices_n}, сотрудников {imp.persons_n}")
    for w in imp.warnings:
        print("  •", w["text"])
    print("  причины отказа строк:", dict(Counter(e["reason"] for e in imp.errors)))
    assert imp.status in ("ok", "partial"), imp.message
    async with app.state.session_maker() as db:
        n = lambda m, *w: db.scalar(select(func.count()).select_from(m).where(m.source_id == sid, *w))  # noqa: E731
        devs, gen, recs, own = await n(BiDevice), await n(BiDevice, BiDevice.generic.is_(True)), await n(BiRecord), await n(BiOwner)
        null_dev = await n(BiDevice, func.lower(BiDevice.name).in_(PR.NULLS))
        dup_dev = (await db.execute(select(BiDevice.short).where(BiDevice.source_id == sid, BiDevice.generic.is_(False)).group_by(BiDevice.short).having(func.count() > 1))).all()
        dup_mail = (await db.execute(select(BiPerson.email).where(BiPerson.source_id == sid, BiPerson.email != "").group_by(BiPerson.email).having(func.count() > 1))).all()
        multi = await n(BiDevice, BiDevice.owners_now > 1)
    print(f"в базе: устройств {devs} (условных {gen}, с несколькими владельцами {multi}), версий записей {recs}, связей {own}")
    assert null_dev == 0 and not dup_dev and not dup_mail                    # «Нет» — не устройство; одно имя — одно устройство; одна почта — один сотрудник
    random.Random(1).shuffle(rows)                                            # тот же снимок в другом порядке строк — без новых версий
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(hdr)
    for r in rows:
        ws.append([r.get(h) for h in hdr])
    copy = tmp_path / "shuffled.xlsx"
    wb.save(copy)
    again = await run(app, sid, copy, at=at + timedelta(days=1))
    print(f"повтор в другом порядке: {again.status} — {again.message}")
    assert again.status == "unchanged"
    async with app.state.session_maker() as db:
        assert await n(BiRecord) == recs
    copy.unlink()


def _write(path: Path, hdr: list[str], rows: list[dict]) -> Path:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(hdr)
    for r in rows:
        ws.append([r.get(h) for h in hdr])
    wb.save(path)
    return path


async def test_real_export_garbled_variants(app, tmp_path):
    """Кривые варианты настоящей выгрузки отклоняются без записи в историю, обычные изменения (несколько процентов) проходят."""
    path = Path(REAL)
    wb = X.open_book(path)
    try:
        hn, hdr = X.headers(X.pick_sheet(wb, ""), 0)
        rows = [vals for _n, vals in X.rows(X.pick_sheet(wb, ""), hn, hdr)]
    finally:
        wb.close()
    prof = PR.validate_profile(PR.suggest(hdr))
    c = prof["columns"]
    sid = await source(app)
    async with app.state.session_maker() as db:
        from app.models import BiSource  # noqa: PLC0415
        (await db.get(BiSource, sid)).profile = prof
        await db.commit()
    at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    assert (await run(app, sid, path, at=at)).status == "ok"
    async with app.state.session_maker() as db:
        before = (await db.execute(select(BiOwner.device_id, BiOwner.person_id, BiOwner.present).where(BiOwner.source_id == sid))).all()
    dn, fio, mail = c["device_name"], c["person_name"], c["email"]
    devs = [r[dn] for r in rows]
    rnd = random.Random(7)
    some = set(rnd.sample(range(len(rows)), len(rows) * 3 // 100))
    variants = {
        "ФИО и почта поменялись местами": ([{**r, fio: r[mail], mail: r[fio]} for r in rows], "rejected"),
        "столбец компьютеров сдвинут на строку": ([{**r, dn: devs[i - 1]} for i, r in enumerate(rows)], "rejected"),
        "выгрузка оборвалась: 70 % строк": (rows[: len(rows) * 7 // 10], "rejected"),
        "ФИО в столбце компьютеров": ([{**r, dn: r[fio]} for r in rows], "rejected"),
        "3 % компьютеров у других сотрудников": ([{**r, dn: devs[(i + 1) % len(rows)]} if i in some else r for i, r in enumerate(rows)], "ok"),
    }
    for k, (name, (data, want)) in enumerate(variants.items(), 1):
        imp = await run(app, sid, _write(tmp_path / f"v{k}.xlsx", hdr, data), at=at + timedelta(hours=k))
        print(f"\n{name}: {imp.status} — {imp.message[:160]}")
        assert imp.status == want, imp.message
        if want == "rejected":
            async with app.state.session_maker() as db:
                assert (await db.execute(select(BiOwner.device_id, BiOwner.person_id, BiOwner.present).where(BiOwner.source_id == sid))).all() == before
        (tmp_path / f"v{k}.xlsx").unlink()
