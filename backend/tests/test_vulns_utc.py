"""Даты обнаружений KSC (UTC без пояса от pymssql) отдаются с поясом UTC: браузер не сдвигает время, сортировка не смешивает «наивные» и «осознанные» даты."""
from datetime import datetime, timezone

from app.ksc import queries as q
from app.ksc import vulns as V


class Fake:
    async def run(self, sql, params=None, *, max_rows=0):
        if sql == q.VULN_DESCR_AGG.format(where=q.VULNS_WHERE + " AND h.bIsSlaveServer = 0"):
            return [{"descr_id": 1, "hosts": 2, "total": 3, "last_detected": datetime(2026, 1, 2, 3, 4, 5)}]
        return []


async def test_descr_list_dates_are_utc():
    items = await V.descr_list(Fake(), active_days=None, exclude_slaves=True)
    assert items[0]["last_detected"] == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    sorted(items + [{"last_detected": None}], key=lambda i: i["last_detected"] or datetime.min.replace(tzinfo=timezone.utc))     # как сортирует api/vulns.py
