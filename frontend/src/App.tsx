import { Suspense, lazy, useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setAllSources, setCsrf, setSourceId, setUnauthorizedHandler, type Me, type QuickPrefs, type SourceRef } from "./api";
import { Icon, Mark } from "./components/Icons";
import { Empty, ToTop } from "./components/ui";
import { GlobalSearch } from "./components/GlobalSearch";
import LoginPage from "./pages/LoginPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import SecurityPage from "./pages/SecurityPage";
import DashboardPage from "./pages/DashboardPage";
import HierarchyPage from "./pages/HierarchyPage";
import QuickPage from "./pages/QuickPage";
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
import { ADMIN_GROUPS, ADMIN_ICONS, ADMIN_TABS, NAV_GROUPS, NAV_REPORTS, NAV_TOP, roleOk, type NavItem } from "./navModel";
import { pushRecent } from "./recent";
import { DEFAULT_THEME, THEMES, chooseTheme, isTheme, syncTheme, type ThemeId } from "./theme";

export interface Ctx { me: Me; sources: SourceRef[]; current: SourceRef | null; /** выбрано «Все источники» (разделы, которые это умеют, показывают данные всех доступных источников) */ all: boolean; reloadSources: () => Promise<void>; /** раздел «Иерархия. Предприятие» доступен роли */ hier: boolean; /** сохранить личную панель «Быстрый доступ» в профиле (null — исходный набор) */ onQuick: (q: QuickPrefs | null) => void; /** переключить источник или «Все источники» (id = "all") */ setScope: (id: string) => void }

/** Разделы, работающие со всеми источниками сразу; остальные показывают выбранный источник. */
export const ALL_PAGES = ["/eol", "/devices", "/reports", "/zones"];
/** Страницы, для которых «Все источники» не требуют пояснения: главная и независимые от KSC разделы. */
const scopeAware = (pathname: string) => pathname === "/" || pathname === "/overview" || pathname.startsWith("/pentest") || pathname.startsWith("/hunt") || ALL_PAGES.some((p) => pathname.startsWith(p));

export { ADMIN_TABS };

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
      const host = self.current?.parentElement;
      const el = host?.querySelector<HTMLElement>("a.active, a[aria-current='page']");
      setPos(el && host ? { y: el.getBoundingClientRect().top - host.getBoundingClientRect().top, h: el.offsetHeight } : null);   // вложенные группы: отсчёт от списка, а не от offsetParent
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
  // группы меню сворачиваются и раскрываются; состояние запоминается для пользователя в этом браузере, раздел с открытой страницей раскрывается сам
  const navKey = `kc:nav:${me.user.id}`;
  const [navOpen, setNavOpen] = useState<Record<string, boolean>>(() => { try { return JSON.parse(localStorage.getItem(navKey) ?? "{}"); } catch { return {}; } });
  const isOpen = (id: string) => navOpen[id] ?? (id === "admin" ? inAdmin : !id.startsWith("a:"));
  const setNav = (next: Record<string, boolean>) => { setNavOpen(next); try { localStorage.setItem(navKey, JSON.stringify(next)); } catch { /* не запомнится */ } };
  const toggle = (id: string) => setNav({ ...navOpen, [id]: !isOpen(id) });
  const setAdminAll = (on: boolean) => setNav({ ...navOpen, admin: true, ...Object.fromEntries(ADMIN_GROUPS.map((g) => [`a:${g.id}`, on])) });
  useEffect(() => {                                                                  // страница открыта по ссылке: её группа раскрывается
    const g = inAdmin ? ADMIN_GROUPS.find((x) => x.tabs.includes(tab)) : NAV_GROUPS.find((x) => x.items.some((i) => pathname === i.to || pathname.startsWith(`${i.to}/`)));
    if (!g) return;
    const ids = inAdmin ? ["admin", `a:${g.id}`] : [g.id];
    if (ids.some((id) => !isOpen(id))) setNav({ ...navOpen, ...Object.fromEntries(ids.map((id) => [id, true])) });
  }, [pathname, tab]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { const t = window.setTimeout(() => document.querySelector<HTMLElement>(".sidenav a.active")?.scrollIntoView({ block: "nearest" }), 80); return () => window.clearTimeout(t); }, [pathname, search]);   // открытый раздел всегда виден в меню
  const link = (n: NavItem) => {
    if (!roleOk(n.roles, me.user.role) || (n.hier && !hierOk)) return null;
    return <NavLink key={n.to} to={n.to === "/vdb" && vdbNew > 0 ? "/vdb?tab=mine" : n.to} end={n.end}><Icon name={n.icon} />{n.label}{n.to === "/vdb" && vdbNew > 0 && <span className="nav-badge" title="Новых уязвимостей с высокой и критической опасностью или признаком эксплуатации, затрагивающих установленное ПО">{vdbNew}</span>}</NavLink>;
  };
  return (
    <div className="shell">
      <a className="skip-link" href="#main">Перейти к содержимому</a>
      <aside className={`sidenav ${open ? "open" : ""}`} aria-label="Разделы">
        <Link to="/" className="side-brand"><Mark size={28} /><span className="site-name">{me.site_name || "KAV Checker"}</span></Link>
        <div className="side-scroll">
          <div className="nav-list">
            <NavIndicator deps={[pathname, search, JSON.stringify(navOpen)]} />
            {NAV_TOP.map(link)}
            {NAV_GROUPS.map((g) => {
              const items = g.items.filter((n) => roleOk(n.roles, me.user.role) && (!n.hier || hierOk));
              if (!items.length) return null;
              return <div key={g.id} className="nav-group">
                <button type="button" className="nav-label nav-toggle" aria-expanded={isOpen(g.id)} aria-controls={`ng-${g.id}`} onClick={() => toggle(g.id)}>{g.label}<Icon name="chevronD" size={14} /></button>
                {isOpen(g.id) && <div id={`ng-${g.id}`} className="nav-sub">{items.map(link)}</div>}</div>;
            })}
            {link(NAV_REPORTS)}
            {me.user.is_admin && <div className="nav-group nav-admin">
              <button type="button" className="nav-label nav-toggle" aria-expanded={isOpen("admin")} aria-controls="ng-admin" onClick={() => toggle("admin")}>Администрирование<Icon name="chevronD" size={14} /></button>
              {isOpen("admin") && <div id="ng-admin" className="nav-sub"><span className="nav-all"><button type="button" onClick={() => setAdminAll(true)}>Развернуть все</button><button type="button" onClick={() => setAdminAll(false)}>Свернуть все</button></span>{ADMIN_GROUPS.map((g) => <div key={g.id} className="nav-agroup">
                <button type="button" className={`nav-toggle sub ${inAdmin && g.tabs.includes(tab) ? "has-active" : ""}`} aria-expanded={isOpen(`a:${g.id}`)} aria-controls={`na-${g.id}`} onClick={() => toggle(`a:${g.id}`)}><Icon name="chevronD" size={12} />{g.label}</button>
                {isOpen(`a:${g.id}`) && <div id={`na-${g.id}`} className="nav-sub">{g.tabs.map((id) => {
                  const t = ADMIN_TABS.find((x) => x.id === id)!;
                  const active = inAdmin && tab === t.id;
                  return <Link key={t.id} to={`/admin?tab=${t.id}`} className={active ? "active" : ""} aria-current={active ? "page" : undefined}><Icon name={ADMIN_ICONS[t.id]} />{t.label}</Link>;
                })}</div>}</div>)}</div>}
            </div>}
          </div>
        </div>
        <div className="side-foot">KAV Checker {version}</div>
      </aside>
      <div className={`scrim ${open ? "on" : ""}`} onClick={() => setOpen(false)} aria-hidden />
      <div className="workspace">
        <header className="topbar">
          <button type="button" className="btn ghost icon burger" aria-label="Открыть меню разделов" aria-expanded={open} onClick={() => setOpen(true)}><Icon name="menu" size={20} /></button>
          <SourceSwitcher sources={sources} current={current} onPick={onPick} isAdmin={me.user.is_admin} all={all} onAll={onAll} />
          <GlobalSearch sourceId={current?.id ?? null} role={me.user.role} hier={!!hierOk} />
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
  const { pathname, search: urlSearch } = useLocation();
  useEffect(() => { if (!me) return; const t = window.setTimeout(() => pushRecent(me.user.id, pathname, urlSearch), 600); return () => window.clearTimeout(t); }, [pathname, urlSearch, me?.user.id]);   // eslint-disable-line react-hooks/exhaustive-deps
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
    const titles: [string, string][] = [["/overview", "Обзор"], ["/software", "Программное обеспечение"], ["/hosts", "Компьютеры"], ["/devices", "Устройства и пользователи"], ["/eol", "EOL"], ["/vulnerabilities", "Уязвимости"], ["/protection", "Состояние защиты"], ["/events", "События безопасности"], ["/zones", "Зоны ответственности"], ["/pentest", "Pentest"], ["/hunt", "CVE Hunt"], ["/reports", "Отчёты"], ["/admin", "Администрирование"], ["/security", "Безопасность входа"]];
    const t = me ? (titles.find(([p]) => pathname.startsWith(p))?.[1] ?? "Быстрый доступ") : "Вход";
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
  const ctx: Ctx = { me, sources, current, all: allOn, reloadSources, setScope, hier: !!hierOk, onQuick: (q) => setMe((m) => (m ? { ...m, quick: q } : m)) };
  return (
    <Shell me={me} hierOk={hierOk} version={version} onLogout={logout} onTheme={onTheme} sources={sources} current={current} onPick={pick} all={allOn} onAll={onAll}>
      <Suspense fallback={<div className="center"><span className="spin" role="status" aria-label="Загрузка" /></div>}>
        <Routes>
          <Route path="/" element={<QuickPage ctx={ctx} />} />
          <Route path="/overview" element={<DashboardPage key={`${currentId}:${allOn}`} ctx={ctx} />} />
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
          <Route path="/hierarchy" element={hierOk === null ? null : hierOk ? <HierarchyPage ctx={ctx} /> : <Navigate to="/" replace />} />
          <Route path="/reports" element={<ReportsPage key={currentId} ctx={ctx} />} />
          <Route path="/reports/:jobId" element={<ReportsPage ctx={ctx} />} />
          <Route path="/security" element={<SecurityPage me={me} onLogout={logout} />} />
          <Route path="/appearance" element={<AppearancePage me={me} onTheme={onTheme} />} />
          <Route path="/password" element={<Navigate to="/security" replace />} />
          <Route path="/admin" element={me.user.is_admin ? <AdminPage ctx={ctx} version={version} /> : <Navigate to="/" replace />} />
          <Route path="*" element={<Empty icon="target" title="Страница не найдена" action={<Link className="btn" to="/">К быстрому доступу</Link>}>Проверьте адрес или вернитесь к быстрому доступу.</Empty>} />
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
