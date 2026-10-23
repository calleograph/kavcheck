import { Suspense, lazy, useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setCsrf, setSourceId, setUnauthorizedHandler, type Me, type SourceRef } from "./api";
import { Icon, type IconName } from "./components/Icons";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import DashboardPage from "./pages/DashboardPage";
import SoftwarePage from "./pages/SoftwarePage";
import HostsPage, { HostPage } from "./pages/HostsPage";
import VulnsPage from "./pages/VulnsPage";
import { EventsPage, ProtectionPage } from "./pages/PlannedPages";
import ReportsPage from "./pages/ReportsPage";
import { versionLabel } from "./util";

const AdminPage = lazy(() => import("./pages/AdminPage"));

export interface Ctx { me: Me; sources: SourceRef[]; current: SourceRef | null; reloadSources: () => Promise<void> }

const NAV: { to: string; label: string; icon: IconName; soon?: boolean; end?: boolean }[] = [
  { to: "/", label: "Главная", icon: "home", end: true },
  { to: "/software", label: "Программное обеспечение", icon: "box" },
  { to: "/hosts", label: "Компьютеры", icon: "monitor" },
  { to: "/vulnerabilities", label: "Уязвимости", icon: "bug" },
  { to: "/protection", label: "Состояние защиты", icon: "shield", soon: true },
  { to: "/events", label: "События безопасности", icon: "bell", soon: true },
  { to: "/reports", label: "Отчёты", icon: "file" },
];
export const ADMIN_TABS: { id: string; label: string }[] = [
  { id: "system", label: "Состояние системы" }, { id: "sources", label: "Источники KSC" }, { id: "users", label: "Пользователи" }, { id: "ldap", label: "LDAP" },
  { id: "general", label: "Общие настройки" }, { id: "rules", label: "Правила группировки" }, { id: "updates", label: "Обновления" }, { id: "journal", label: "Журнал событий" }, { id: "audit", label: "Журнал действий" },
];

function UserMenu({ me, version, onLogout }: { me: Me; version: string; onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  useEffect(() => { if (!open) return; const away = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); }; document.addEventListener("mousedown", away); return () => document.removeEventListener("mousedown", away); }, [open]);
  const roles: Record<string, string> = { admin: "Администратор", analyst: "Аналитик", viewer: "Просмотр" };
  const theme = (t: string) => { try { localStorage.setItem("kc:theme", t); } catch { /* ignore */ } if (t === "system") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme", t); setOpen(false); };
  return (
    <div className={`dd ${open ? "open" : ""}`} ref={ref}>
      <button type="button" className="dd-btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="avatar" aria-hidden>{me.user.display_name.slice(0, 1).toUpperCase()}</span><span className="uname">{me.user.display_name}</span><Icon name="chevronD" size={14} />
      </button>
      <div className="dd-panel" role="menu">
        <div className="dd-text">{roles[me.user.role]} · {me.user.local ? "локальная учётная запись" : "учётная запись LDAP"}</div>
        {me.user.local && <button className="dd-item" role="menuitem" onClick={() => { setOpen(false); navigate("/password"); }}><span>Сменить пароль</span></button>}
        <div className="dd-sep" />
        <div className="dd-text">Тема</div>
        <div className="row tight" style={{ padding: "0 6px 6px" }}>
          <button className="btn mini" onClick={() => theme("system")}>Системная</button><button className="btn mini" onClick={() => theme("light")}>Светлая</button><button className="btn mini" onClick={() => theme("dark")}>Тёмная</button>
        </div>
        <div className="dd-sep" />
        {version && <div className="dd-text">Версия {version}</div>}
        <button className="dd-item danger" role="menuitem" onClick={onLogout}><span>Выйти</span></button>
      </div>
    </div>
  );
}

function SourcePicker({ sources, current, onPick }: { sources: SourceRef[]; current: SourceRef | null; onPick: (id: string) => void }) {
  if (!sources.length) return <span className="badge warn" title="Администратор добавляет источники в разделе «Администрирование → Источники KSC»">Источники KSC не настроены</span>;
  const dot = current ? (current.last_check_ok === true ? "ok" : current.last_check_ok === false ? "bad" : "off") : "off";
  return (
    <span className="source-pick" title={current ? `${current.host}:${current.port} / ${current.database}${current.ksc_version ? ` · KSC ${current.ksc_version}` : ""}` : ""}>
      <span className={`dot ${dot}`} aria-hidden />
      <select aria-label="Источник KSC" value={current?.id ?? ""} onChange={(e) => onPick(e.target.value)}>
        {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
      </select>
    </span>
  );
}

function Shell({ me, version, onLogout, children, sources, current, onPick }: { me: Me; version: string; onLogout: () => void; children: ReactNode; sources: SourceRef[]; current: SourceRef | null; onPick: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const { pathname, search } = useLocation();
  useEffect(() => setOpen(false), [pathname, search]);
  const tab = new URLSearchParams(search).get("tab") ?? "system";
  return (
    <div className="shell">
      <header className="topbar">
        <button type="button" className="burger" aria-label="Меню" aria-expanded={open} onClick={() => setOpen((o) => !o)}><span /><span /><span /></button>
        <NavLink to="/" className="brand"><Icon name="logo" size={24} /> {me.site_name || "KAV Checker"}</NavLink>
        <SourcePicker sources={sources} current={current} onPick={onPick} />
        <div className="spacer" />
        <UserMenu me={me} version={version} onLogout={onLogout} />
      </header>
      <div className="body">
        <nav className={`sidenav ${open ? "open" : ""}`} aria-label="Разделы">
          <div>
            <h4>Аудит</h4>
            {NAV.map((n) => <NavLink key={n.to} to={n.to} end={n.end}><Icon name={n.icon} size={18} />{n.label}{n.soon && <span className="soon">скоро</span>}</NavLink>)}
          </div>
          {me.user.is_admin && (
            <div>
              <h4>Администрирование</h4>
              <NavLink to="/admin" className={() => pathname.startsWith("/admin") ? "active" : ""}><Icon name="gear" size={18} />Администрирование</NavLink>
              <div className="sub">
                {ADMIN_TABS.map((t) => <NavLink key={t.id} to={`/admin?tab=${t.id}`} className={() => pathname.startsWith("/admin") && tab === t.id ? "active" : ""}>{t.label}</NavLink>)}
              </div>
            </div>
          )}
        </nav>
        <main>{children}</main>
      </div>
    </div>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [version, setVersion] = useState("");
  const [sources, setSources] = useState<SourceRef[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const navigate = useNavigate();

  const reloadSources = useCallback(async () => {
    try { const r = await api.mySources(); setSources(r.items); const cur = r.current && r.items.some((s) => s.id === r.current) ? r.current : (r.items[0]?.id ?? null); setCurrentId(cur); setSourceId(cur); }
    catch { setSources([]); }
  }, []);
  useEffect(() => {
    api.me().then((m) => { setCsrf(m.csrf_token); setMe(m); }).catch(() => setMe(null));
    api.version().then((v) => setVersion(versionLabel(v.version, v.commit))).catch(() => undefined);
  }, []);
  useEffect(() => { if (me) void reloadSources(); }, [me, reloadSources]);
  useEffect(() => { setUnauthorizedHandler(() => { setCsrf(""); setMe(null); }); return () => setUnauthorizedHandler(null); }, []);

  const onLogin = useCallback((m: Me) => { setCsrf(m.csrf_token); setMe(m); navigate("/"); }, [navigate]);
  const logout = async () => { await api.logout().catch(() => undefined); setCsrf(""); setMe(null); navigate("/"); };
  const pick = async (id: string) => { try { await api.selectSource(id); setCurrentId(id); setSourceId(id); } catch { /* ошибка показывается на странице */ } };

  if (me === undefined) return <div className="center muted">Загрузка…</div>;
  if (me === null) return <LoginPage onLogin={onLogin} />;
  if (me.must_change_password) return <ChangePasswordPage onDone={() => api.me().then((m) => { setCsrf(m.csrf_token); setMe(m); })} onLogout={logout} />;
  const current = sources.find((s) => s.id === currentId) ?? null;
  const ctx: Ctx = { me, sources, current, reloadSources };
  return (
    <Shell me={me} version={version} onLogout={logout} sources={sources} current={current} onPick={pick}>
      <Suspense fallback={<div className="muted">Загрузка…</div>}>
        <Routes>
          <Route path="/" element={<DashboardPage ctx={ctx} />} />
          <Route path="/software" element={<SoftwarePage ctx={ctx} />} />
          <Route path="/hosts" element={<HostsPage ctx={ctx} />} />
          <Route path="/hosts/:hostId" element={<HostPage ctx={ctx} />} />
          <Route path="/vulnerabilities" element={<VulnsPage ctx={ctx} />} />
          <Route path="/protection" element={<ProtectionPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/reports" element={<ReportsPage ctx={ctx} />} />
          <Route path="/reports/:jobId" element={<ReportsPage ctx={ctx} />} />
          <Route path="/password" element={<ChangePasswordPage inline onDone={() => navigate("/")} onLogout={logout} />} />
          <Route path="/admin" element={me.user.is_admin ? <AdminPage ctx={ctx} version={version} /> : <Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </Shell>
  );
}

/** Заглушка, когда источник не выбран: ссылки на настройку. */
export function NoSource({ ctx }: { ctx: Ctx }) {
  return (
    <div className="card">
      <h2>Источник KSC не выбран</h2>
      {ctx.sources.length === 0
        ? <p className="muted">Подключений к Kaspersky Security Center пока нет. {ctx.me.user.is_admin ? <>Добавьте источник в разделе <NavLink to="/admin?tab=sources">Администрирование → Источники KSC</NavLink>.</> : "Обратитесь к администратору."}</p>
        : <p className="muted">Выберите источник в верхней панели.</p>}
    </div>
  );
}
