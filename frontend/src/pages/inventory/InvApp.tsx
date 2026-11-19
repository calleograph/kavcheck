/** Подсистема «Инвентаризация» (учёт ИТ-активов): своя шапка и навигация, общий контекст (справочники, права, местоположения), вложенные маршруты.
 *  Общие с KAV Checker — вход, роли, тема и меню; данные KSC только читаются, учётные сведения живут в своих таблицах. */
import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Icon } from "../../components/Icons";
import { Empty, SkelRows } from "../../components/ui";
import { INV_NAV } from "../../navModel";
import { InvCtx, type InvCtxValue } from "./InvBits";
import { inv, type Loc, type Meta } from "./invApi";

const Overview = lazy(() => import("./InvOverview"));
const Assets = lazy(() => import("./InvAssets"));
const AssetPage = lazy(() => import("./InvAsset"));
const AssetNew = lazy(() => import("./InvAsset").then((m) => ({ default: m.AssetNew })));
const Docs = lazy(() => import("./InvDocs"));
const DocPage = lazy(() => import("./InvDocs").then((m) => ({ default: m.DocPage })));
const DocNew = lazy(() => import("./InvDocs").then((m) => ({ default: m.DocNew })));
const DocPrint = lazy(() => import("./InvDocs").then((m) => ({ default: m.DocPrint })));
const Locations = lazy(() => import("./InvLocations"));
const People = lazy(() => import("./InvPeople"));
const PersonPage = lazy(() => import("./InvPeople").then((m) => ({ default: m.PersonPage })));
const Licenses = lazy(() => import("./InvLicenses"));
const LicensePage = lazy(() => import("./InvLicenses").then((m) => ({ default: m.LicensePage })));
const Reports = lazy(() => import("./InvReports"));
const Refs = lazy(() => import("./InvRefs"));
const ImportPage = lazy(() => import("./InvImport"));
const Settings = lazy(() => import("./InvSettings"));
const Scan = lazy(() => import("./InvScan"));

export default function InvApp({ ctx }: { ctx: Ctx }) {
  const [meta, setMeta] = useState<Meta | null>(null); const [err, setErr] = useState("");
  const [locs, setLocs] = useState<Loc[] | null>(null);
  const reload = useCallback(() => { inv.meta().then((m) => { setMeta(m); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, []);
  const reloadLocs = useCallback(() => { inv.locations().then((r) => setLocs(r.items)).catch(() => setLocs([])); }, []);
  useEffect(() => { reload(); reloadLocs(); }, [reload, reloadLocs]);
  const value = useMemo<InvCtxValue | null>(() => meta && ({ meta, reload, can: (p) => meta.perms.includes(p), isAdmin: ctx.me.user.is_admin, role: ctx.me.user.role, locs, reloadLocs, activityDays: ctx.me.activity_days }),
    [meta, reload, ctx.me, locs, reloadLocs]);
  const nav = useNavigate();
  const { pathname } = useLocation();
  const [code, setCode] = useState(""); const [codeErr, setCodeErr] = useState("");
  const find = async () => {
    const c = code.trim(); if (!c) return;
    try { const a = await inv.lookup(c); setCode(""); setCodeErr(""); nav(`/inventory/assets/${a.id}`); }
    catch { nav(`/inventory/assets?q=${encodeURIComponent(c)}`); setCode(""); }
  };
  if (err) return <section><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!value) return <section className="inv"><div className="inv-bar"><span className="skel skel-title" /></div><div className="card"><SkelRows rows={5} cols={4} /></div></section>;
  const items = INV_NAV.filter((n) => (!n.perm || value.can(n.perm)) && (!n.admin || ctx.me.user.is_admin));
  return (
    <InvCtx.Provider value={value}>
      <section className="inv">
        <header className="inv-bar no-print">
          <div className="inv-brand"><span className="inv-mark" aria-hidden><Icon name="package" size={18} /></span><div><b>Инвентаризация</b><span>учёт ИТ-имущества</span></div></div>
          <nav className="inv-nav" aria-label="Разделы инвентаризации">
            {items.map((n) => <NavLink key={n.to} to={n.to} end={n.end}><Icon name={n.icon} size={16} />{n.label}</NavLink>)}
          </nav>
          <label className="inv-nav-sel"><span className="sr-only">Раздел инвентаризации</span>
            <select value={[...items].reverse().find((n) => (n.end ? pathname === n.to : pathname.startsWith(n.to)))?.to ?? "/inventory"} onChange={(e) => nav(e.target.value)}>
              {items.map((n) => <option key={n.to} value={n.to}>{n.label}</option>)}</select></label>
          <form className="inv-code" role="search" onSubmit={(e) => { e.preventDefault(); void find(); }}>
            <Icon name="search" size={16} />
            <input value={code} onChange={(e) => { setCode(e.target.value); setCodeErr(""); }} placeholder="Инв. номер, S/N или скан" aria-label="Найти учётную единицу по номеру или коду" />
            {codeErr && <span className="field-err">{codeErr}</span>}
          </form>
        </header>
        <Suspense fallback={<div className="card"><SkelRows rows={5} cols={4} /></div>}>
          <Routes>
            <Route index element={<Overview />} />
            <Route path="assets" element={<Assets ctx={ctx} />} />
            <Route path="assets/new" element={<AssetNew />} />
            <Route path="assets/:id" element={<AssetPage ctx={ctx} />} />
            <Route path="a/:uid" element={<ByUid />} />
            <Route path="docs" element={<Docs ctx={ctx} />} />
            <Route path="docs/new" element={<DocNew />} />
            <Route path="docs/:id" element={<DocPage />} />
            <Route path="docs/:id/print" element={<DocPrint />} />
            <Route path="locations" element={<Locations ctx={ctx} />} />
            <Route path="people" element={<People ctx={ctx} />} />
            <Route path="people/:id" element={<PersonPage ctx={ctx} />} />
            <Route path="licenses" element={<Licenses ctx={ctx} />} />
            <Route path="licenses/:id" element={<LicensePage />} />
            <Route path="reports" element={<Reports ctx={ctx} />} />
            <Route path="refs" element={<Refs />} />
            <Route path="import" element={<ImportPage ctx={ctx} />} />
            <Route path="settings" element={ctx.me.user.is_admin ? <Settings /> : <Navigate to="/inventory" replace />} />
            <Route path="scan" element={<Scan />} />
            <Route path="*" element={<Empty icon="package" title="Страница не найдена">Проверьте адрес или вернитесь к обзору инвентаризации.</Empty>} />
          </Routes>
        </Suspense>
      </section>
    </InvCtx.Provider>
  );
}

/** QR-код этикетки ведёт сюда: /inventory/a/<uid> → карточка. */
function ByUid() {
  const { uid } = useParams(); const nav = useNavigate(); const [err, setErr] = useState("");
  useEffect(() => { if (uid) inv.byUid(uid).then((r) => nav(`/inventory/assets/${r.id}`, { replace: true })).catch((e) => setErr((e as ApiError).message)); }, [uid, nav]);
  return err ? <div className="card"><Empty icon="package" title="Карточка не найдена">{err}</Empty></div> : <div className="card"><SkelRows rows={3} cols={2} /></div>;
}
