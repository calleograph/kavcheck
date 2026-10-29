"""Память и время импорта большой выгрузки (п. 25 ТЗ): 50 тыс. строк, первый импорт и повторный с 10 % изменений. Запуск вручную: BI_PERF=1 [TEST_PG_URL=…] pytest tests/test_bi_perf.py -s."""
import os
import time
import tracemalloc
from datetime import timedelta

import pytest

from tests.test_bi_import import T0, row, run, source, xlsx

pytestmark = pytest.mark.skipif(not os.environ.get("BI_PERF"), reason="замер выполняется вручную (BI_PERF=1)")
N = 50_000


def rows(shift: int = 0):
    out = []
    for i in range(N):
        who = i + shift if i % 10 == 0 else i                         # каждая десятая связь — другой сотрудник
        out.append(row(f"Сотрудник {who:06d}", f"u{who:06d}@example.local", f"Отдел {i % 40}", f"WS-{i:06d}", os=("Windows 10 Pro", "Astra Linux 1.7", "macOS 14")[i % 3]))
    return out


async def test_large_import_memory_and_time(app, tmp_path):
    sid = await source(app, drift_pct=1000, max_rows=N + 10)
    f1, f2 = xlsx(tmp_path / "a.xlsx", rows()), xlsx(tmp_path / "b.xlsx", rows(shift=1))
    out = {}
    for name, f, at in (("первый", f1, T0), ("повторный, 10 % изменений", f2, T0 + timedelta(days=1))):
        tracemalloc.start()
        t = time.monotonic()
        imp = await run(app, sid, f, at=at)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        out[name] = (imp.status, imp.rows_valid, imp.rows_new, imp.rows_changed, round(time.monotonic() - t, 1), round(peak / 2**20))
        assert imp.status == "ok", imp.message
        assert peak < 600 * 2**20                                       # предел для worker — 1,5 ГБ; импорт должен оставаться далеко ниже
    for k, v in out.items():
        print(f"\n{k}: статус {v[0]}, записей {v[1]}, новых {v[2]}, изменено {v[3]}, {v[4]} с, пик памяти Python {v[5]} МБ (файл {f1.stat().st_size // 1024} КБ)")
