"""Сводка инвентаризации для главной страницы и отчёта."""
from datetime import date, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import InvAsset, InvCount, InvDoc, InvHistory, InvLicense, KscSource, utcnow
from ..services.settings import InventorySettings
from . import core as C
from . import model as M


async def read_overview(db: AsyncSession, acc: C.Access, cfg: InventorySettings, *, actor: str) -> dict:
    f = acc.asset_filter()
    base = [f] if f is not None else []
    today = date.today()
    by_cls = dict((await db.execute(select(InvAsset.cls, func.count()).where(*base, InvAsset.st_cls.in_(M.ST_ACTIVE)).group_by(InvAsset.cls))).all())
    by_st = dict((await db.execute(select(InvAsset.st_cls, func.count()).where(*base).group_by(InvAsset.st_cls))).all())
    total = sum(by_st.values())
    cost = (await db.execute(select(func.coalesce(func.sum(InvAsset.cost), 0)).where(*base, InvAsset.st_cls.in_(M.ST_ACTIVE)))).scalar_one()

    async def cnt(*w) -> int:
        return (await db.execute(select(func.count()).select_from(InvAsset).where(*base, *w))).scalar_one()

    warn = await cnt(InvAsset.st_cls.in_(M.ST_ACTIVE), InvAsset.warranty_until.is_not(None), InvAsset.warranty_until >= today, InvAsset.warranty_until <= today + timedelta(days=cfg.warranty_days))
    comp = InvAsset.cls.in_(M.COMPUTERS)
    act = InvAsset.st_cls.in_(M.ST_ACTIVE)
    stats = {"total": total, "active": sum(by_st.get(s, 0) for s in M.ST_ACTIVE), "cost": int(cost or 0), "cost_text": C.money_str(int(cost or 0)), "warranty_soon": warn,
             "no_owner": await cnt(act, InvAsset.st_cls == "use", InvAsset.user_id.is_(None), InvAsset.owner_id.is_(None)),
             "no_location": await cnt(act, InvAsset.location_id.is_(None)), "no_resp": await cnt(act, InvAsset.resp_id.is_(None)),
             "computers": await cnt(act, comp), "ksc_linked": await cnt(act, comp, InvAsset.ksc_host_id.is_not(None), InvAsset.ksc_link != "lost"),
             "ksc_unlinked": await cnt(act, comp, InvAsset.ksc_host_id.is_(None)), "ksc_lost": await cnt(InvAsset.ksc_link == "lost"),
             "in_transit": await cnt(InvAsset.transit_doc_id.is_not(None)),
             "stale": await cnt(act, InvAsset.updated_at < utcnow() - timedelta(days=cfg.stale_days))}
    lic_soon, lic_expired = (await db.execute(select(func.count(), func.count().filter(InvLicense.valid_until < today)).select_from(InvLicense).where(
        InvLicense.active.is_(True), InvLicense.valid_until <= today + timedelta(days=cfg.license_days)))).one()
    df = acc.document_filter(actor)
    docs = [df] if df is not None else []
    docs_open = dict((await db.execute(select(InvDoc.kind, func.count()).where(*docs, InvDoc.status.not_in(("done", "cancelled"))).group_by(InvDoc.kind))).all())
    rep_open, rep_long = (await db.execute(select(func.count(), func.count().filter(InvDoc.doc_date < today - timedelta(days=cfg.repair_days)))
        .select_from(InvDoc).where(*docs, InvDoc.kind == "repair", InvDoc.status == "sent"))).one()
    transit_late = (await db.execute(select(func.count()).select_from(InvDoc).where(*docs, InvDoc.kind == "move", InvDoc.status == "sent", InvDoc.doc_date < today - timedelta(days=cfg.transit_days)))).scalar_one()
    hq = select(InvHistory, InvAsset.inv_no, InvAsset.name).join(InvAsset, InvAsset.id == InvHistory.asset_id).where(*base).order_by(InvHistory.at.desc(), InvHistory.id.desc()).limit(12)
    recent = [{"at": C._iso(h.at), "by": h.by, "kind": h.kind, "title": h.title, "asset_id": h.asset_id, "inv_no": no, "name": nm, "doc_id": h.doc_id} for h, no, nm in (await db.execute(hq)).all()]
    sources = (await db.execute(select(func.count()).select_from(KscSource))).scalar_one()
    counts = [InvCount.status == "active"]
    if acc.scopes:
        counts.append(InvCount.location_id.in_(acc.loc_ids()))
    counts_open = (await db.execute(select(func.count()).select_from(InvCount).where(*counts))).scalar_one()
    return {"stats": stats, "by_cls": [{"cls": k, "name": M.CLS_RU.get(k, k), "n": v} for k, v in sorted(by_cls.items(), key=lambda x: -x[1])],
            "by_st": [{"st": k, "name": M.ST_RU.get(k, k), "n": by_st.get(k, 0)} for k in M.ST_RU if by_st.get(k)], "licenses_soon": lic_soon,
            "licenses_expired": lic_expired, "docs_open": [{"kind": k, "name": M.DOC_SHORT.get(k, k), "n": v} for k, v in docs_open.items()],
            "repair_open": rep_open, "repair_long": rep_long, "transit_late": transit_late,
            "recent": recent, "ksc_sources": sources, "counts_open": counts_open, "cfg": {"warranty_days": cfg.warranty_days, "license_days": cfg.license_days, "stale_days": cfg.stale_days}}
