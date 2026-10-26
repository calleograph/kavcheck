"""Помощник тестов: выполнить фоновый расчёт данных зон так, как это делает worker (после изменения зон, закреплений, источников)."""
from sqlalchemy import select

from app.models import ZcJob
from app.zones.zjobs import ZoneCache


def cache(app) -> ZoneCache:
    st = app.state
    return ZoneCache(st.session_maker, st.settings, st.settings_svc, st.sources, st.journal)


async def settle(app, *, full: bool = True) -> dict:
    """Полный расчёт всех источников и зон (full) либо выполнение очереди заданий; возвращает сводку по заданиям. Ошибки расчёта поднимаются как AssertionError."""
    zc = cache(app)
    async with app.state.session_maker() as db:
        cfg, _tz = await zc.settings(db)
    if full:
        errors = await zc._execute("all", None, cfg)  # noqa: SLF001
        assert not errors, errors
    n = 0
    while await zc.run_next():
        n += 1
        assert n < 20
    async with app.state.session_maker() as db:
        jobs = (await db.execute(select(ZcJob))).scalars().all()
    bad = [j for j in jobs if j.status == "failed"]
    assert not bad, [(j.kind, j.error) for j in bad]
    return {"jobs": len(jobs)}
