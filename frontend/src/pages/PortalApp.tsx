import { lazy, useCallback, useEffect, useState } from "react";
import { Link, Navigate, NavLink, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { api, type ApiError, type Job, type Me } from "../api";
import { UserMenu, type Ctx } from "../App";
import { Icon, Mark } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Empty, PageHead, SkelRows } from "../components/ui";
import type { ThemeId } from "../theme";
import { fmt, num } from "../util";
import SecurityPage from "./SecurityPage";
import { StateBar, ZoneView } from "./ZonesPage";

const AppearancePage = lazy(() => import("./AppearancePage"));

type ZoneRow = Awaited<ReturnType<typeof api.zones.overview>>["items"][number];

/** Портал ответственного за зону: доменный пользователь, назначенный зоне, видит только свои зоны — панель зоны, карточки компьютеров и отчёты по ним (в браузер или себе на почту).
 * Остальной интерфейс KAV Checker, источники KSC и чужие зоны ему недоступны — это проверяет сервер; оболочка лишь не показывает лишнего. */
export default function PortalApp({ me, version, onLogout, onTheme }: { me: Me; version: string; onLogout: () => void; onTheme: (id: ThemeId | null) => void }) {
  const ctx: Ctx = { me, sources: [], current: null, all: false, reloadSources: async () => undefined, setScope: () => undefined, hier: false, onQuick: () => undefined };
  return (
    <div className="portal">
      <a className="skip-link" href="#main">К содержимому</a>
      <header className="topbar portal-top">
        <Link to="/" className="portal-brand" aria-label="Мои зоны"><Mark size={26} /><span><b>{me.site_name || "KAV Checker"}</b><small>портал ответственного</small></span></Link>
        <nav className="portal-nav" aria-label="Разделы портала">
          <NavLink to="/" end className={({ isActive }) => (isActive ? "on" : "")}><Icon name="grid" size={16} />Мои зоны</NavLink>
          <NavLink to="/reports" className={({ isActive }) => (isActive ? "on" : "")}><Icon name="file" size={16} />Мои отчёты</NavLink>
        </nav>
        <div className="spacer" />
        <UserMenu me={me} version={version} onLogout={onLogout} onTheme={onTheme} />
      </header>
      <main id="main" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<PortalHome />} />
          <Route path="/zones" element={<Navigate to="/" replace />} />
          <Route path="/zones/:zid" element={<PortalZone ctx={ctx} />} />
          <Route path="/reports" element={<PortalReports />} />
          <Route path="/reports/:jobId" element={<PortalReports />} />
          <Route path="/appearance" element={<AppearancePage me={me} onTheme={onTheme} />} />
          <Route path="/security" element={<SecurityPage me={me} onLogout={onLogout} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

/** Мои зоны: одна зона — сразу её панель; несколько — карточки с главными показателями. */
function PortalHome() {
  const [rows, setRows] = useState<ZoneRow[] | null>(null); const [err, setErr] = useState("");
  const [fetched, setFetched] = useState<string | null>(null);
  useEffect(() => { api.zones.overview({}).then((r) => { setRows(r.items); setFetched(r.fetched_at ?? null); }).catch((e) => setErr((e as ApiError).message)); }, []);
  if (err) return <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!rows) return <SkelRows rows={3} cols={4} />;
  if (rows.length === 1) return <Navigate to={`/zones/${rows[0].id}`} replace />;
  return (
    <section>
      <PageHead title="Мои зоны ответственности" lede={`Компьютеры, за которые вы отвечаете: уязвимости, состояние защиты, EOL. Данные подготовлены сервером${fetched ? ` (срез ${fmt(fetched)})` : ""}; отчёты — в браузер или себе на почту.`} />
      {!rows.length ? <Empty icon="grid" title="Зон пока нет">Администратор ещё не назначил вам зону ответственности или зона выключена.</Empty> : (
        <div className="portal-cards">
          {rows.map((z) => (
            <Link key={z.id} to={`/zones/${z.id}`} className="card portal-card">
              <h2>{z.name}</h2>
              <p className="muted small portal-desc">{z.description || "Без описания"}</p>
              <div className="portal-nums">
                <div><b>{num(z.stats.total)}</b><span>компьютеров</span></div>
                <div className={z.stats.critical ? "bad" : ""}><b>{num(z.stats.critical)}</b><span>с критическими</span></div>
                <div className={z.stats.protection ? "warn" : ""}><b>{num(z.stats.protection)}</b><span>проблем защиты</span></div>
              </div>
              <StateBar state={z.stats.state} total={z.stats.active} />
              <span className="portal-go">Открыть зону<Icon name="arrowR" size={15} /></span>
            </Link>))}
        </div>)}
    </section>
  );
}

function PortalZone({ ctx }: { ctx: Ctx }) {
  const { zid } = useParams();
  return <ZoneView key={zid} ctx={ctx} zid={zid ?? ""} portal />;
}

const FMT: [string, string][] = [["xlsx", "Excel"], ["pdf", "PDF"], ["html", "HTML"]];

/** Мои отчёты: сформированные мной отчёты по своим зонам — скачать или отправить себе на почту. */
function PortalReports() {
  const { jobId } = useParams();
  const navigate = useNavigate();
  const [items, setItems] = useState<Job[] | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState("");
  const [toast, show] = useToast();
  const load = useCallback(() => api.reports.list(false).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (!items?.some((j) => j.status === "queued" || j.status === "running")) return; const t = window.setTimeout(() => void load(), 3000); return () => window.clearTimeout(t); }, [items, load]);
  const mail = async (j: Job) => { setBusy(j.id); try { const r = await api.reports.mail(j.id, ["xlsx", "pdf"]); show(`Отправлено на ${r.to}`); } catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(""); } };
  return (
    <section>
      <PageHead title="Мои отчёты" lede="Отчёты по вашим зонам, которые вы формировали. Новый отчёт — кнопкой «Отчёт по зоне» на странице зоны (можно выбрать категории проблем, уровень и отдельные компьютеры)." />
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!items ? <SkelRows rows={4} cols={2} /> : !items.length ? <Empty icon="file" title="Отчётов пока нет" action={<button className="btn" onClick={() => navigate("/")}>К моим зонам</button>}>Сформируйте отчёт на странице своей зоны.</Empty> : (
        <div className="table-scroll"><table className="table">
          <thead><tr><th>Отчёт и файлы</th><th>Состояние</th></tr></thead>
          <tbody>{items.map((j) => <tr key={j.id} aria-current={jobId === j.id ? "true" : undefined}>
            <td>{j.title || "Отчёт по зоне"}<span className="sub">{fmt(j.finished_at ?? j.created_at)}{j.summary?.hosts != null ? `; компьютеров: ${num(Number(j.summary.hosts))}` : ""}</span>
              {j.status === "done" && <div className="row portal-files">{FMT.map(([k, l]) => <a key={k} className="btn" href={api.reports.downloadUrl(j.id, k as "xlsx")} download><Icon name="download" size={14} />{l}</a>)}
                <button className="btn" onClick={() => mail(j)} aria-busy={busy === j.id} disabled={!!busy}><Icon name="mail" size={14} />Себе на почту</button></div>}</td>
            <td>{j.status === "done" ? <span className="badge ok">готов</span> : j.status === "failed" ? <span className="badge err" title={j.error ?? ""}>ошибка</span> : <span className="badge">{j.progress || "формируется…"}</span>}</td></tr>)}</tbody>
        </table></div>)}
      {toast}
    </section>
  );
}
