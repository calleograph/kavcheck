"""Замер потребления памяти и времени тяжёлых фоновых операций на данных текущей установки (инструмент разработчика и нагрузочных испытаний).
    python -m app.tools.perf <analyze|analyze-keys|catalog|scores|zones|extindex> [--source ИМЯ]
Пиковая память процесса (RSS) измеряется отдельным потоком по /proc/self/status. Изменения в базе не фиксируются (транзакции откатываются), KSC — только чтение."""
from __future__ import annotations

import argparse
import asyncio
import threading
import time

from sqlalchemy import select

from ..config import get_settings
from ..db import create_engine, create_session_maker
from ..models import KscSource


def rss_mb() -> float:
    try:
        for ln in open("/proc/self/status"):
            if ln.startswith("VmRSS:"):
                return int(ln.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


class Peak:
    def __init__(self) -> None:
        self.max, self._stop = rss_mb(), threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(0.1):
            self.max = max(self.max, rss_mb())

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *_a):
        self._stop.set()
        self._t.join()
        self.max = max(self.max, rss_mb())


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    ap.add_argument("--source", default="")
    a = ap.parse_args()
    cfg = get_settings()
    engine = create_engine(cfg)
    sm = create_session_maker(engine)
    async with sm() as db:
        srcs = [s for s in (await db.execute(select(KscSource).where(KscSource.is_active.is_(True)).order_by(KscSource.position))).scalars().all() if not a.source or a.source in s.name]
    base = rss_mb()
    print(f"старт: RSS {base:.0f} МБ; источников {len(srcs)}")
    from ..vdb.sync import analyze  # noqa: PLC0415

    for s in srcs:
        t0 = time.perf_counter()
        with Peak() as pk:
            if a.scenario == "analyze":
                async with sm() as db:
                    n = await analyze(db, s.id, None)
                    await db.rollback()
                res = f"находок {n}"
            elif a.scenario == "scores":
                from ..vdb import store  # noqa: PLC0415
                async with sm() as db:
                    res = f"записей {await store.upgrade_scores(db)}"
                    await db.rollback()
            elif a.scenario == "catalog":
                from ..ksc import catalog_build as CB  # noqa: PLC0415
                from ..ksc.driver import Session  # noqa: PLC0415
                from ..reports.runner import conn_params  # noqa: PLC0415
                from ..services.settings import SettingsService  # noqa: PLC0415
                from ..security.secretbox import SecretBox  # noqa: PLC0415

                svc = SettingsService(SecretBox(cfg.app_master_key))
                params = conn_params(s, svc.decrypt(s.password_enc, f"source.{s.id}"))

                def work():
                    with Session(params) as sess:
                        return CB.build(sess, activity_days=30, overrides=CB.Overrides(), progress=lambda _t: None)

                fams, stats = await asyncio.to_thread(work)
                res = f"продуктов {stats['products']}, установок {stats['installs']}, компьютеров {stats['hosts']}"
            else:
                raise SystemExit(f"неизвестный сценарий {a.scenario}")
        print(f"{a.scenario} · {s.name}: {time.perf_counter() - t0:.1f} с, пик RSS {pk.max:.0f} МБ (+{pk.max - base:.0f}); {res}")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
