import { Suspense, lazy, useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setAllSources, setCsrf, setSourceId, setUnauthorizedHandler, type Me, type SourceRef } from "./api";
import { Icon, Mark, type IconName } from "./components/Icons";
import { Empty, ToTop } from "./components/ui";
import { GlobalSearch } from "./components/GlobalSearch";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import SecurityPage from "./pages/SecurityPage";
import DashboardPage from "./pages/DashboardPage";
import HierarchyPage from "./pages/HierarchyPage";
// разделы загружаются по первому обращению: стартовая загрузка — оболочка, вход и главная
const PentestPage = lazy(() => import("./pages/PentestPage"));
const HuntPage = lazy(() => import("./pages/HuntPage"));
const SoftwarePage = lazy(() => import("./pages/SoftwarePage"));
const HostsPage = lazy(() => import("./pages/HostsPage"));
const HostPage = lazy(() => import("./pages/HostsPage").then((m) => ({ default: m.HostPage })));
const VulnsPage = lazy(() => import("./pages/VulnsPage"));
const VdbPage = lazy(() => import("./pages/VdbPage"));
const VulnHostPage = lazy(() => import("./pages/VulnsPage").then((m) => ({ default: m.VulnHostPage })));
const ProductPage = lazy(() => import("./pages/ProductPage"));
const EventsPage = lazy(() => import("./pages/EventsPage"));
const ProtectionPage = lazy(() => import("./pages/ProtectionPage"));
const ZonesPage = lazy(() => import("./pages/ZonesPage"));
const ReportsPage = lazy(() => import("./pages/ReportsPage"));
import { fmt, versionLabel } from "./util";

const AdminPage = lazy(() => import("./pages/AdminPage"));
const EolPage = lazy(() => import("./pages/EolPage"));
const DevicesPage = lazy(() => import("./pages/DevicesPage"));
const AppearancePage = lazy(() => import("./pages/AppearancePage"));
import { DEFAULT_THEME, THEMES, chooseTheme, isTheme, syncTheme, type ThemeId } from "./theme";

export interface Ctx { me: Me; sources: SourceRef[]; current: SourceRef | null; /** выбрано «Все источники» (разделы, которые это умеют, показывают данные всех доступных источников) */ all: boolean; reloadSources: () => Promise<void>; /** переключить источник или «Все источники» (id = "all") */ setScope: (id: string) => void }

/** Разделы, работающие со всеми источниками сразу; остальные показывают выбранный источник. */
export const ALL_PAGES = ["/eol", "/devices", "/reports", "/zones"];
/** Страницы, для которых «Все источники» не требуют пояснения: главная и независимые от KSC разделы. */
const scopeAware = (pathname: string) => pathname === "/" || pathname.startsWith("/pentest") || pathname.startsWith("/hunt") || ALL_PAGES.some((p) => pathname.startsWith(p));

const NAV: { to: string; label: string; icon: IconName; end?: boolean; roles?: string[] }[] = [
  { to: "/", label: "Главная", icon: "home", end: true },
  { to: "/software", label: "Программы", icon: "layers" },
  { to: "/hosts", label: "Компьютеры", icon: "monitor" },
  { to: "/devices", label: "Устройства и пользователи", icon: "users" },
  { to: "/vulnerabilities", label: "Уязвимости", icon: "bug" },
  { to: "/vdb", label: "База уязвимостей", icon: "vault" },
  { to: "/eol", label: "EOL", icon: "clock" },
  { to: "/protection", label: "Состояние защиты", icon: "shieldPulse" },
  { to: "/events", label: "События безопасности", icon: "bell" },
  { to: "/zones", label: "Зоны ответственности", icon: "grid" },
  { to: "/hunt", label: "CVE Hunt", icon: "search", roles: ["analyst", "admin"] },
  { to: "/pentest", label: "Pentest", icon: "target", roles: ["analyst", "admin"] },
  { to: "/reports", label: "Отчёты", icon: "file" },
];
export const ADMIN_TABS: { id: string; label: string }[] = [
  { id: "system", label: "Техническое состояние" }, { id: "sources", label: "Источники данных" }, { id: "licenses", label: "Лицензии" }, { id: "users", label: "Пользователи" }, { id: "ldap", label: "LDAPS" }, { id: "hier", label: "Иерархия предприятия" },
  { id: "general", label: "Общие настройки" }, { id: "zones", label: "Зоны ответственности" }, { id: "zcache", label: "Расчёт данных зон" }, { id: "eolcfg", label: "EOL и пользователи" }, { id: "mail", label: "Рассылки отчётов" }, { id: "org", label: "Организация и отчёты" }, { id: "catalog", label: "Каталог программ" }, { id: "vdb", label: "База уязвимостей" }, { id: "pentest", label: "Pentest" }, { id: "ptchecks", label: "Pentest: шаблоны и проверки" }, { id: "updates", label: "Обновления" }, { id: "components", label: "Компоненты" }, { id: "journal", label: "Журнал событий" }, { id: "audit", label: "Журнал действий" }, { id: "logs", label: "Журналы и хранение" },
];


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

function UserMenu({ me, version, onLogout, onTheme }: { me: Me; version: string; onLogout: () => void; onTheme: (id: ThemeId | null) => void }) {
  const { open, setOpen, root, btn } = usePopover();
  const cur = isTheme(me.theme) ? me.theme : isTheme(me.default_theme) ? me.default_theme : DEFAULT_THEME;
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
          <div className="theme-swatches" role="group" aria-label="Тема оформления">{THEMES.map((t) => <button key={t.id} type="button" className="theme-swatch" tabIndex={open ? 0 : -1} aria-pressed={cur === t.id}
            title={t.name} aria-label={t.name} style={{ background: `linear-gradient(135deg, ${t.preview.bg} 0 55%, ${t.preview.accent} 55% 100%)` }} onClick={() => onTheme(t.id)} />)}</div>
        </div>
        <button className="dd-item" role="menuitem" tabIndex={open ? 0 : -1} onClick={() => { setOpen(false); navigate("/appearance"); }}><Icon name="sliders" />Внешний вид</button>
        <button className="dd-item" role="menuitem" tabIndex={open ? 0 : -1} onClick={() => { setOpen(false); navigate("/security"); }}><Icon name="key" />Безопасность входа</button>
        <div className="dd-sep" />
        <button className="dd-item danger" role="menuitem" tabIndex={open ? 0 : -1} onClick={onLogout}><Icon name="logout" />Выйти</button>
        {version && <div className="dd-text dd-about">
          <span><a href="https://github.com/calleograph/kavcheck" target="_blank" rel="noopener noreferrer">KAV Checker</a> {version}</span>
          <span><a href="https://github.com/calleograph" target="_blank" rel="noopener noreferrer">calleograph</a> · <a href={`https://github.com/calleograph/kavcheck/blob/${/^\d+\.\d+\.\d+$/.test(version.split(" ")[0]) && version.split(" ")[0] !== "0.0.0" ? `v${version.split(" ")[0]}` : "master"}/CHANGELOG.md`} target="_blank" rel="noopener noreferrer">Список изменений</a></span>
        </div>}
      </div>
    </div>
  );
}

/** Выбор источника KSC: собственный список с состоянием проверки, адресом и версией; клавиатура — стрелки, Enter, Escape. */
function SourceSwitcher({ sources, current, onPick, isAdmin, all, onAll }: { sources: SourceRef[]; current: SourceRef | null; onPick: (id: string) => void; isAdmin: boolean; all: boolean; onAll: (on: boolean) => void }) {
  const { open, setOpen, root, btn } = usePopover();
  const [kb, setKb] = useState(-1);
  const many = sources.length > 1;
  // позиции списка: 0 — «Все источники» (если источников больше одного), далее источники
  useEffect(() => { if (open) setKb(all && many ? 0 : Math.max(0, sources.findIndex((s) => s.id === current?.id)) + (many ? 1 : 0)); }, [open, sources, current, all, many]);
  if (!sources.length) return <span className="src-empty"><Icon name="alert" size={16} />Источники KSC не настроены</span>;
  const state = (s: SourceRef) => (s.last_check_ok === true ? "ok" : s.last_check_ok === false ? "bad" : "off");
  const stateText = (s: SourceRef) => (s.last_check_ok === true ? `проверен ${fmt(s.last_check_at)}` : s.last_check_ok === false ? "ошибка проверки" : "не проверялся");
  const choose = (id: string) => { onAll(false); onPick(id); setOpen(false); btn.current?.focus(); };
  const chooseAll = () => { onAll(true); setOpen(false); btn.current?.focus(); };
  const count = sources.length + (many ? 1 : 0);
  const bad = sources.filter((s) => s.last_check_ok === false);
  const onKey = (e: React.KeyboardEvent) => {
    if (!open && (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ")) { e.preventDefault(); setOpen(true); return; }
    if (!open) return;
    if (e.key === "ArrowDown") { e.preventDefault(); setKb((k) => (k + 1) % count); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setKb((k) => (k - 1 + count) % count); }
    else if (e.key === "Enter" && kb >= 0) { e.preventDefault(); if (many && kb === 0) chooseAll(); else choose(sources[kb - (many ? 1 : 0)].id); }
    else if (e.key === "Tab") setOpen(false);
  };
  return (
    <div className={`dd left ${open ? "open" : ""}`} ref={root}>
      <button ref={btn} type="button" className="src-btn" aria-haspopup="listbox" aria-expanded={open} aria-label={`Источник KSC: ${all && many ? "все источники" : current?.name ?? "не выбран"}`} onClick={() => setOpen((o) => !o)} onKeyDown={onKey}>
        <span className={`dot ${all && many ? (bad.length ? "bad" : "ok") : current ? state(current) : "off"}`} aria-hidden />
        <span className="src-main"><span className="src-name">{all && many ? `Все источники (${sources.length})` : current?.name ?? "Выберите источник"}</span>{all && many ? <span className="src-meta">{bad.length ? `недоступно: ${bad.map((s) => s.name).join(", ")}` : "данные всех доступных вам источников"}</span> : current && <span className="src-meta">{current.database} @ {current.host}{current.ksc_version ? ` · KSC ${current.ksc_version}` : ""}</span>}</span>
        <Icon name="chevronD" size={16} className="chev" />
      </button>
      <div className="dd-panel src-list" role="listbox" aria-label="Источники KSC" aria-hidden={!open}>
        <div className="dd-text">Данные всех разделов берутся из выбранного источника</div>
        {many && (
          <button type="button" role="option" tabIndex={-1} aria-selected={all} className={`src-opt ${kb === 0 ? "kb" : ""}`} onMouseEnter={() => setKb(0)} onClick={chooseAll}>
            <span className={`dot ${bad.length ? "bad" : "ok"}`} aria-hidden /><span className="src-name">Все источники</span>{all ? <Icon name="check" size={16} className="tick" /> : <span />}
            <span className="src-meta">{sources.length} · новые источники добавляются сами · EOL, устройства и отчёты; остальные разделы показывают выбранный источник</span>
          </button>)}
        {sources.map((s, j) => { const i = j + (many ? 1 : 0); return (
          <button key={s.id} type="button" role="option" tabIndex={-1} aria-selected={!all && s.id === current?.id} className={`src-opt ${i === kb ? "kb" : ""}`} onMouseEnter={() => setKb(i)} onClick={() => choose(s.id)}>
            <span className={`dot ${state(s)}`} aria-hidden /><span className="src-name">{s.name}</span>{!all && s.id === current?.id ? <Icon name="check" size={16} className="tick" /> : <span />}
            <span className="src-meta">{s.database} @ {s.host}:{s.port}{s.ksc_version ? ` · KSC ${s.ksc_version}` : ""} · {stateText(s)}</span>
          </button>); })}
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

function Shell({ me, hierOk, version, onLogout, onTheme, children, sources, current, onPick, all, onAll }: { me: Me; hierOk: boolean | null; version: string; onLogout: () => void; onTheme: (id: ThemeId | null) => void; children: ReactNode; sources: SourceRef[]; current: SourceRef | null; onPick: (id: string) => void; all: boolean; onAll: (on: boolean) => void }) {
  const [open, setOpen] = useState(false);
  const { pathname, search } = useLocation();
  useEffect(() => setOpen(false), [pathname, search]);
  const [vdbNew, setVdbNew] = useState(0);        // новые серьёзные уязвимости из внешних баз, затрагивающие установленное ПО (уведомление внутри приложения)
  useEffect(() => { if (current) api.vdb.summary().then((c) => setVdbNew(c.new_serious)).catch(() => setVdbNew(0)); else setVdbNew(0); }, [current?.id, pathname]);
  useEffect(() => { window.scrollTo({ top: 0, behavior: "instant" }); }, [pathname]);   // новая страница — с начала; списки при возврате восстанавливают своё место сами
  useEffect(() => { if (!open) return; const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); document.querySelector<HTMLElement>(".topbar .burger")?.focus(); } }; document.addEventListener("keydown", esc); return () => document.removeEventListener("keydown", esc); }, [open]);
  const inAdmin = pathname.startsWith("/admin");
  const tab = new URLSearchParams(search).get("tab") ?? "system";
  // группа администрирования сворачивается (запоминается в браузере) и раскрывается сама при входе в раздел
  const [adminOpen, setAdminOpen] = useState(() => { try { return localStorage.getItem("kc:nav-admin") !== "0"; } catch { return true; } });
  useEffect(() => { if (inAdmin) setAdminOpen(true); }, [inAdmin]);
  const toggleAdmin = () => setAdminOpen((o) => { try { localStorage.setItem("kc:nav-admin", o ? "0" : "1"); } catch { /* не запомнится */ } return !o; });
  return (
    <div className="shell">
      <a className="skip-link" href="#main">Перейти к содержимому</a>
      <aside className={`sidenav ${open ? "open" : ""}`} aria-label="Разделы">
        <Link to="/" className="side-brand"><Mark size={28} /><span className="site-name">{me.site_name || "KAV Checker"}</span></Link>
        <div className="side-scroll">
          <div className="nav-list">
            <NavIndicator deps={[pathname, search, adminOpen]} />
            <div className="nav-label">Аудит</div>
            {(hierOk ? [...NAV.slice(0, -1), { to: "/hierarchy", label: "Иерархия. Предприятие", icon: "sitemap" as IconName }, NAV[NAV.length - 1]] : NAV).filter((n) => !n.roles || n.roles.includes(me.user.role)).map((n) => <NavLink key={n.to} to={n.to === "/vdb" && vdbNew > 0 ? "/vdb?tab=mine" : n.to} end={n.end}><Icon name={n.icon} />{n.label}{n.to === "/vdb" && vdbNew > 0 && <span className="nav-badge" title="Новых уязвимостей с высокой и критической опасностью или признаком эксплуатации, затрагивающих установленное ПО">{vdbNew}</span>}</NavLink>)}
            {me.user.is_admin && <>
              <button type="button" className="nav-label nav-toggle" aria-expanded={adminOpen} onClick={toggleAdmin}>Администрирование<Icon name="chevronD" size={14} /></button>
              {adminOpen && ADMIN_TABS.map((t) => {
                const active = inAdmin && tab === t.id;
                return <Link key={t.id} to={`/admin?tab=${t.id}`} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>
                  <Icon name={({ system: "gauge", sources: "database", licenses: "key", users: "users", ldap: "key", hier: "sitemap", general: "sliders", zones: "grid", zcache: "clock", eolcfg: "users", mail: "mail", org: "file", catalog: "package", vdb: "vault", pentest: "target", ptchecks: "shieldPulse", updates: "upload", components: "package", journal: "journal", audit: "history", logs: "database" } as Record<string, IconName>)[t.id]} />{t.label}</Link>;
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
          <SourceSwitcher sources={sources} current={current} onPick={onPick} isAdmin={me.user.is_admin} all={all} onAll={onAll} />
          <GlobalSearch sourceId={current?.id ?? null} />
          <div className="spacer" />
          <UserMenu me={me} version={version} onLogout={onLogout} onTheme={onTheme} />
        </header>
        <main id="main" tabIndex={-1}>
          {all && sources.length > 1 && !scopeAware(pathname) && !inAdmin && (
            <p className="scope-note" role="status"><Icon name="info" size={15} />Выбрано «Все источники», но этот раздел работает с одним источником — показан «{current?.name}». <button type="button" className="link-btn" onClick={() => onAll(false)}>Работать с «{current?.name}»</button></p>)}
          {all && sources.some((s) => s.last_check_ok === false) && scopeAware(pathname) && !pathname.startsWith("/pentest") && (
            <p className="scope-note warn" role="status"><Icon name="alert" size={15} />Источник «{sources.filter((s) => s.last_check_ok === false).map((s) => s.name).join("», «")}» недоступен или не прошёл проверку: показаны сохранённые данные, они могут быть неактуальными.</p>)}
          {children}
        </main>
        <ToTop />
      </div>
    </div>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [version, setVersion] = useState("");
  const [sources, setSources] = useState<SourceRef[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [all, setAll] = useState<boolean>(() => { try { return localStorage.getItem("kc:scope-all") === "1"; } catch { return false; } });
  useLayoutEffect(() => { setAllSources(all && sources.length > 1); }, [all, sources.length]);      // до эффектов страниц: их первый запрос уже должен идти с заголовком «все источники»
  const onAll = useCallback((on: boolean) => { setAll(on); try { localStorage.setItem("kc:scope-all", on ? "1" : "0"); } catch { /* не запомнится */ } }, []);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [hierOk, setHierOk] = useState<boolean | null>(null);   // раздел «Иерархия. Предприятие» доступен роли пользователя (решает сервер; пункт меню — только удобство)
  useEffect(() => { if (me) api.hier.access().then((r) => setHierOk(r.allowed)).catch(() => setHierOk(false)); else setHierOk(null); }, [me?.user.id, me?.user.role, pathname]);   // eslint-disable-line react-hooks/exhaustive-deps

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
    const titles: [string, string][] = [["/software", "Программное обеспечение"], ["/hosts", "Компьютеры"], ["/devices", "Устройства и пользователи"], ["/eol", "EOL"], ["/vulnerabilities", "Уязвимости"], ["/protection", "Состояние защиты"], ["/events", "События безопасности"], ["/zones", "Зоны ответственности"], ["/pentest", "Pentest"], ["/hunt", "CVE Hunt"], ["/reports", "Отчёты"], ["/admin", "Администрирование"], ["/security", "Безопасность входа"]];
    const t = me ? (titles.find(([p]) => pathname.startsWith(p))?.[1] ?? "Главная") : "Вход";
    document.title = `${t} — ${me?.site_name || "KAV Checker"}`;
  }, [pathname, me]);

  const onLogin = useCallback((m: Me) => { setCsrf(m.csrf_token); setMe(m); navigate("/"); }, [navigate]);
  useEffect(() => { if (me) syncTheme(me); }, [me]);
  const onTheme = (id: ThemeId | null) => { setMe((m) => (m ? { ...m, theme: id } : m)); void chooseTheme(id, me?.default_theme ?? DEFAULT_THEME).catch(() => undefined); };
  const logout = async () => { await api.logout().catch(() => undefined); setCsrf(""); setMe(null); navigate("/"); };
  const pick = async (id: string) => { try { await api.selectSource(id); setCurrentId(id); setSourceId(id); } catch { /* ошибка покажется на странице */ } };

  if (me === undefined) return <div className="center"><span className="spin" role="status" aria-label="Загрузка" /></div>;
  if (me === null) return <LoginPage onLogin={onLogin} />;
  if (me.must_change_password) return <ChangePasswordPage onDone={() => api.me().then((m) => { setCsrf(m.csrf_token); setMe(m); })} onLogout={logout} />;
  if (me.must_enroll_totp) return <main className="forced-shell"><SecurityPage me={me} forced onLogout={logout} onEnrolled={() => api.me().then((m) => { setCsrf(m.csrf_token); setMe(m); })} /></main>;
  const current = sources.find((s) => s.id === currentId) ?? null;
  const allOn = all && sources.length > 1;
  const setScope = (id: string) => { if (id === "all") onAll(true); else { onAll(false); void pick(id); } };
  const ctx: Ctx = { me, sources, current, all: allOn, reloadSources, setScope };
  return (
    <Shell me={me} hierOk={hierOk} version={version} onLogout={logout} onTheme={onTheme} sources={sources} current={current} onPick={pick} all={allOn} onAll={onAll}>
      <Suspense fallback={<div className="center"><span className="spin" role="status" aria-label="Загрузка" /></div>}>
        <Routes>
          <Route path="/" element={<DashboardPage key={`${currentId}:${allOn}`} ctx={ctx} />} />
          <Route path="/software" element={<SoftwarePage key={currentId} ctx={ctx} />} />
          <Route path="/software/p/:key" element={<ProductPage key={currentId} ctx={ctx} />} />
          <Route path="/eol" element={<EolPage key={`${currentId}:${allOn}`} ctx={ctx} />} />
          <Route path="/devices" element={<DevicesPage key={`${currentId}:${allOn}`} ctx={ctx} />} />
          <Route path="/hosts" element={<HostsPage key={currentId} ctx={ctx} />} />
          <Route path="/hosts/:hostId" element={<HostPage key={currentId} ctx={ctx} />} />
          <Route path="/vulnerabilities" element={<VulnsPage key={currentId} ctx={ctx} />} />
          <Route path="/vulnerabilities/hosts/:hostId" element={<VulnHostPage key={currentId} ctx={ctx} />} />
          <Route path="/vdb" element={<VdbPage key={currentId} ctx={ctx} />} />
          <Route path="/protection" element={<ProtectionPage key={currentId} ctx={ctx} />} />
          <Route path="/events" element={<EventsPage key={currentId} ctx={ctx} />} />
          <Route path="/hunt" element={me.user.role === "viewer" ? <Navigate to="/" replace /> : <HuntPage ctx={ctx} />} />
          <Route path="/pentest" element={me.user.role === "viewer" ? <Navigate to="/" replace /> : <PentestPage ctx={ctx} />} />
          <Route path="/zones" element={<ZonesPage key={currentId} ctx={ctx} />} />
          <Route path="/zones/:zid" element={<ZonesPage key={currentId} ctx={ctx} />} />
          <Route path="/hierarchy" element={hierOk === null ? null : hierOk ? <HierarchyPage /> : <Navigate to="/" replace />} />
          <Route path="/reports" element={<ReportsPage key={currentId} ctx={ctx} />} />
          <Route path="/reports/:jobId" element={<ReportsPage ctx={ctx} />} />
          <Route path="/security" element={<SecurityPage me={me} onLogout={logout} />} />
          <Route path="/appearance" element={<AppearancePage me={me} onTheme={onTheme} />} />
          <Route path="/password" element={<Navigate to="/security" replace />} />
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
