import { Suspense, lazy, useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setCsrf, setSourceId, setUnauthorizedHandler, type Me, type SourceRef } from "./api";
import { Icon, Mark, type IconName } from "./components/Icons";
import { Empty, Segmented } from "./components/ui";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import DashboardPage from "./pages/DashboardPage";
import SoftwarePage from "./pages/SoftwarePage";
import HostsPage, { HostPage } from "./pages/HostsPage";
import VulnsPage, { VulnHostPage } from "./pages/VulnsPage";
import ProductPage from "./pages/ProductPage";
import { EventsPage, ProtectionPage } from "./pages/PlannedPages";
import ReportsPage from "./pages/ReportsPage";
import { fmt, versionLabel } from "./util";

const AdminPage = lazy(() => import("./pages/AdminPage"));

export interface Ctx { me: Me; sources: SourceRef[]; current: SourceRef | null; reloadSources: () => Promise<void> }

const NAV: { to: string; label: string; icon: IconName; soon?: boolean; end?: boolean }[] = [
  { to: "/", label: "Главная", icon: "home", end: true },
  { to: "/software", label: "Программы", icon: "layers" },
  { to: "/hosts", label: "Компьютеры", icon: "monitor" },
  { to: "/vulnerabilities", label: "Уязвимости", icon: "bug" },
  { to: "/protection", label: "Состояние защиты", icon: "shieldPulse", soon: true },
  { to: "/events", label: "События безопасности", icon: "bell", soon: true },
  { to: "/reports", label: "Отчёты", icon: "file" },
];
export const ADMIN_TABS: { id: string; label: string }[] = [
  { id: "system", label: "Состояние системы" }, { id: "sources", label: "Источники KSC" }, { id: "users", label: "Пользователи" }, { id: "ldap", label: "LDAP" },
  { id: "general", label: "Общие настройки" }, { id: "catalog", label: "Каталог программ" }, { id: "updates", label: "Обновления" }, { id: "journal", label: "Журнал событий" }, { id: "audit", label: "Журнал действий" },
];

type Theme = "system" | "light" | "dark";
const readTheme = (): Theme => { try { const t = localStorage.getItem("kc:theme"); return t === "light" || t === "dark" ? t : "system"; } catch { return "system"; } };
const applyTheme = (t: Theme) => { try { localStorage.setItem("kc:theme", t); } catch { /* не запомнится */ } if (t === "system") document.documentElement.removeAttribute("data-theme"); else document.documentElement.setAttribute("data-theme", t); };

/** Закрытие всплывающего элемента по щелчку снаружи и Escape (фокус возвращается на кнопку). */
function usePopover() {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => { if (!root.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); btn.current?.focus(); } };
    document.addEventListener("mousedown", away); document.addEventListener("touchstart", away, { passive: true }); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("touchstart", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return { open, setOpen, root, btn };
}

function UserMenu({ me, version, onLogout }: { me: Me; version: string; onLogout: () => void }) {
  const { open, setOpen, root, btn } = usePopover();
  const [theme, setTheme] = useState<Theme>(readTheme);
  const navigate = useNavigate();
  const roles: Record<string, string> = { admin: "Администратор", analyst: "Аналитик", viewer: "Просмотр" };
  return (
    <div className={`dd ${open ? "open" : ""}`} ref={root}>
      <button ref={btn} type="button" className="dd-btn" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="avatar" aria-hidden>{me.user.display_name.slice(0, 1).toUpperCase()}</span><span className="uname">{me.user.display_name}</span><Icon name="chevronD" size={16} className="chev" />
      </button>
      <div className="dd-panel" role="menu" aria-hidden={!open}>
        <div className="dd-who"><b>{me.user.display_name}</b><span>{roles[me.user.role]}, {me.user.local ? "локальная учётная запись" : "учётная запись каталога"}</span></div>
        <div className="dd-sep" />
        <div className="dd-row"><span>Тема</span>
          <Segmented label="Тема оформления" value={theme} onChange={(t) => { setTheme(t); applyTheme(t); }}
            options={[["system", <Icon key="s" name="system" size={15} />, "Как в системе"], ["light", <Icon key="l" name="sun" size={15} />, "Светлая"], ["dark", <Icon key="d" name="moon" size={15} />, "Тёмная"]]} />
        </div>
        {me.user.local && <button className="dd-item" role="menuitem" tabIndex={open ? 0 : -1} onClick={() => { setOpen(false); navigate("/password"); }}><Icon name="key" />Сменить пароль</button>}
        <div className="dd-sep" />
        <button className="dd-item danger" role="menuitem" tabIndex={open ? 0 : -1} onClick={onLogout}><Icon name="logout" />Выйти</button>
        {version && <div className="dd-text">KAV Checker {version}</div>}
      </div>
    </div>
  );
}

/** Выбор источника KSC: собственный список с состоянием проверки, адресом и версией; клавиатура — стрелки, Enter, Escape. */
function SourceSwitcher({ sources, current, onPick, isAdmin }: { sources: SourceRef[]; current: SourceRef | null; onPick: (id: string) => void; isAdmin: boolean }) {
  const { open, setOpen, root, btn } = usePopover();
  const [kb, setKb] = useState(-1);
  useEffect(() => { if (open) setKb(Math.max(0, sources.findIndex((s) => s.id === current?.id))); }, [open, sources, current]);
  if (!sources.length) return <span className="src-empty"><Icon name="alert" size={16} />Источники KSC не настроены</span>;
  const state = (s: SourceRef) => (s.last_check_ok === true ? "ok" : s.last_check_ok === false ? "bad" : "off");
  const stateText = (s: SourceRef) => (s.last_check_ok === true ? `проверен ${fmt(s.last_check_at)}` : s.last_check_ok === false ? "ошибка проверки" : "не проверялся");
  const choose = (id: string) => { onPick(id); setOpen(false); btn.current?.focus(); };
  const onKey = (e: React.KeyboardEvent) => {
    if (!open && (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ")) { e.preventDefault(); setOpen(true); return; }
    if (!open) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setKb((k) => (k + 1) % sources.length); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setKb((k) => (k - 1 + sources.length) % sources.length); }
    else if (e.key === "Enter" && kb >= 0) { e.preventDefault(); choose(sources[kb].id); }
    else if (e.key === "Tab") setOpen(false);
  };
  return (
    <div className={`dd left ${open ? "open" : ""}`} ref={root}>
      <button ref={btn} type="button" className="src-btn" aria-haspopup="listbox" aria-expanded={open} aria-label={`Источник KSC: ${current?.name ?? "не выбран"}`} onClick={() => setOpen((o) => !o)} onKeyDown={onKey}>
        <span className={`dot ${current ? state(current) : "off"}`} aria-hidden />
        <span className="src-main"><span className="src-name">{current?.name ?? "Выберите источник"}</span>{current && <span className="src-meta">{current.database} @ {current.host}{current.ksc_version ? ` · KSC ${current.ksc_version}` : ""}</span>}</span>
        <Icon name="chevronD" size={16} className="chev" />
      </button>
      <div className="dd-panel src-list" role="listbox" aria-label="Источники KSC" aria-hidden={!open}>
        <div className="dd-text">Данные всех разделов берутся из выбранного источника</div>
        {sources.map((s, i) => (
          <button key={s.id} type="button" role="option" tabIndex={-1} aria-selected={s.id === current?.id} className={`src-opt ${i === kb ? "kb" : ""}`} onMouseEnter={() => setKb(i)} onClick={() => choose(s.id)}>
            <span className={`dot ${state(s)}`} aria-hidden /><span className="src-name">{s.name}</span>{s.id === current?.id ? <Icon name="check" size={16} className="tick" /> : <span />}
            <span className="src-meta">{s.database} @ {s.host}:{s.port}{s.ksc_version ? ` · KSC ${s.ksc_version}` : ""} · {stateText(s)}</span>
          </button>
        ))}
        {isAdmin && <><div className="dd-sep" /><Link className="dd-item" to="/admin?tab=sources" onClick={() => setOpen(false)} tabIndex={open ? 0 : -1}><Icon name="database" />Управление источниками</Link></>}
      </div>
    </div>
  );
}

/** Подложка активного пункта меню, скользящая к нему при переходе (Kinetics «Tab Pill Glide»). */
function NavIndicator({ deps }: { deps: unknown[] }) {
  const self = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ y: number; h: number } | null>(null);
  useLayoutEffect(() => {
    const measure = () => {
      const el = self.current?.parentElement?.querySelector<HTMLElement>("a.active, a[aria-current='page']");
      setPos(el ? { y: el.offsetTop, h: el.offsetHeight } : null);
    };
    measure();
    const ro = new ResizeObserver(measure);
    if (self.current?.parentElement) ro.observe(self.current.parentElement);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return <span ref={self} className={`nav-indicator ${pos ? "on" : ""}`} style={pos ? { transform: `translateY(${pos.y}px)`, height: pos.h } : undefined} aria-hidden />;
}

function Shell({ me, version, onLogout, children, sources, current, onPick }: { me: Me; version: string; onLogout: () => void; children: ReactNode; sources: SourceRef[]; current: SourceRef | null; onPick: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const { pathname, search } = useLocation();
  useEffect(() => setOpen(false), [pathname, search]);
  useEffect(() => { if (!open) return; const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); document.querySelector<HTMLElement>(".topbar .burger")?.focus(); } }; document.addEventListener("keydown", esc); return () => document.removeEventListener("keydown", esc); }, [open]);
  const inAdmin = pathname.startsWith("/admin");
  const tab = new URLSearchParams(search).get("tab") ?? "system";
  return (
    <div className="shell">
      <a className="skip-link" href="#main">Перейти к содержимому</a>
      <aside className={`sidenav ${open ? "open" : ""}`} aria-label="Разделы">
        <Link to="/" className="side-brand"><Mark size={28} /><span className="site-name">{me.site_name || "KAV Checker"}</span></Link>
        <div className="side-scroll">
          <div className="nav-list">
            <NavIndicator deps={[pathname, search]} />
            <div className="nav-label">Аудит</div>
            {NAV.map((n) => <NavLink key={n.to} to={n.to} end={n.end}><Icon name={n.icon} />{n.label}{n.soon && <span className="soon">скоро</span>}</NavLink>)}
            {me.user.is_admin && <>
              <div className="nav-label">Администрирование</div>
              {ADMIN_TABS.map((t) => {
                const active = inAdmin && tab === t.id;
                return <Link key={t.id} to={`/admin?tab=${t.id}`} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>
                  <Icon name={({ system: "gauge", sources: "database", users: "users", ldap: "key", general: "sliders", catalog: "layers", updates: "upload", journal: "journal", audit: "history" } as Record<string, IconName>)[t.id]} />{t.label}</Link>;
              })}
            </>}
          </div>
        </div>
        <div className="side-foot">KAV Checker {version}</div>
      </aside>
      <div className={`scrim ${open ? "on" : ""}`} onClick={() => setOpen(false)} aria-hidden />
      <div className="workspace">
        <header className="topbar">
          <button type="button" className="btn ghost icon burger" aria-label="Открыть меню разделов" aria-expanded={open} onClick={() => setOpen(true)}><Icon name="menu" size={20} /></button>
          <SourceSwitcher sources={sources} current={current} onPick={onPick} isAdmin={me.user.is_admin} />
          <div className="spacer" />
          <UserMenu me={me} version={version} onLogout={onLogout} />
        </header>
        <main id="main" tabIndex={-1}>{children}</main>
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
  const { pathname } = useLocation();

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
  useEffect(() => {
    const titles: [string, string][] = [["/software", "Программное обеспечение"], ["/hosts", "Компьютеры"], ["/vulnerabilities", "Уязвимости"], ["/protection", "Состояние защиты"], ["/events", "События безопасности"], ["/reports", "Отчёты"], ["/admin", "Администрирование"], ["/password", "Смена пароля"]];
    const t = me ? (titles.find(([p]) => pathname.startsWith(p))?.[1] ?? "Главная") : "Вход";
    document.title = `${t} — ${me?.site_name || "KAV Checker"}`;
  }, [pathname, me]);

  const onLogin = useCallback((m: Me) => { setCsrf(m.csrf_token); setMe(m); navigate("/"); }, [navigate]);
  const logout = async () => { await api.logout().catch(() => undefined); setCsrf(""); setMe(null); navigate("/"); };
  const pick = async (id: string) => { try { await api.selectSource(id); setCurrentId(id); setSourceId(id); } catch { /* ошибка покажется на странице */ } };

  if (me === undefined) return <div className="center"><span className="spin" aria-label="Загрузка" /></div>;
  if (me === null) return <LoginPage onLogin={onLogin} />;
  if (me.must_change_password) return <ChangePasswordPage onDone={() => api.me().then((m) => { setCsrf(m.csrf_token); setMe(m); })} onLogout={logout} />;
  const current = sources.find((s) => s.id === currentId) ?? null;
  const ctx: Ctx = { me, sources, current, reloadSources };
  return (
    <Shell me={me} version={version} onLogout={logout} sources={sources} current={current} onPick={pick}>
      <Suspense fallback={<div className="center"><span className="spin" aria-label="Загрузка" /></div>}>
        <Routes>
          <Route path="/" element={<DashboardPage key={currentId} ctx={ctx} />} />
          <Route path="/software" element={<SoftwarePage key={currentId} ctx={ctx} />} />
          <Route path="/software/p/:key" element={<ProductPage key={currentId} ctx={ctx} />} />
          <Route path="/hosts" element={<HostsPage key={currentId} ctx={ctx} />} />
          <Route path="/hosts/:hostId" element={<HostPage key={currentId} ctx={ctx} />} />
          <Route path="/vulnerabilities" element={<VulnsPage key={currentId} ctx={ctx} />} />
          <Route path="/vulnerabilities/hosts/:hostId" element={<VulnHostPage key={currentId} ctx={ctx} />} />
          <Route path="/protection" element={<ProtectionPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/reports" element={<ReportsPage key={currentId} ctx={ctx} />} />
          <Route path="/reports/:jobId" element={<ReportsPage ctx={ctx} />} />
          <Route path="/password" element={<ChangePasswordPage inline onDone={() => navigate("/")} onLogout={logout} />} />
          <Route path="/admin" element={me.user.is_admin ? <AdminPage ctx={ctx} version={version} /> : <Navigate to="/" replace />} />
          <Route path="*" element={<Empty icon="target" title="Страница не найдена" action={<Link className="btn" to="/">На главную</Link>}>Проверьте адрес или вернитесь на главную.</Empty>} />
        </Routes>
      </Suspense>
    </Shell>
  );
}

/** Заглушка, когда источник не выбран: ссылки на настройку. */
export function NoSource({ ctx }: { ctx: Ctx }) {
  return (
    <div className="card">
      {ctx.sources.length === 0
        ? <Empty icon="database" title="Подключите первый источник KSC"
            action={ctx.me.user.is_admin ? <Link className="btn primary" to="/admin?tab=sources"><Icon name="plus" />Добавить источник</Link> : undefined}>
            KAV Checker читает данные из базы Сервера администрирования Kaspersky Security Center. {ctx.me.user.is_admin ? "Укажите SQL Server, базу и учётную запись только для чтения." : "Попросите администратора добавить источник или выдать вам доступ."}
          </Empty>
        : <Empty icon="database" title="Источник не выбран">Выберите источник KSC в верхней панели.</Empty>}
    </div>
  );
}
