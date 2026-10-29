import { Fragment, useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type ApiError, type SettingsValues, type SystemStatus, type TechJob, type TechLevel, type TechRes, type TechService, type TechState } from "../../api";
import { ExpandCell, ExpandTh, ExpandedRow, XGrid, XItem, useExpanded } from "../../components/ExpandRow";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, Segmented, SkelRows, Tabs } from "../../components/ui";
import { ago, bytes, fmt, fmtTs, num, versionLabel } from "../../util";
import ComponentsAdmin from "./ComponentsAdmin";

type View = "overview" | "resources" | "services" | "jobs" | "pg" | "sources" | "components" | "diag";
const VIEWS: { id: View; label: string }[] = [{ id: "overview", label: "Обзор" }, { id: "resources", label: "Ресурсы" }, { id: "services", label: "Службы" }, { id: "jobs", label: "Задания и Worker" },
  { id: "pg", label: "PostgreSQL" }, { id: "sources", label: "Источники" }, { id: "components", label: "Компоненты" }, { id: "diag", label: "Диагностика" }];
const LEVEL_RU: Record<TechLevel, string> = { ok: "Работает", warn: "Предупреждение", bad: "Неисправность", unknown: "Неизвестно" };
const LEVEL_CLS: Record<TechLevel, string> = { ok: "ok", warn: "warn", bad: "err", unknown: "" };
const DOT: Record<TechLevel, string> = { ok: "ok", warn: "warn", bad: "bad", unknown: "" };
const JOB_CLS: Record<string, string> = { waiting: "warn", captured: "accent", running: "ok", expired: "err" };
const RUN_CLS: Record<string, string> = { success: "ok", error: "err", interrupted: "warn", lost: "err", deferred: "warn" };
const DOCKER_RU: Record<string, string> = { running: "работает", exited: "остановлен", restarting: "перезапускается", paused: "приостановлен", dead: "не работает", created: "не запущен",
  healthy: "исправен", unhealthy: "проверка не проходит", starting: "запускается" };
const dk = (v: string) => DOCKER_RU[v] ?? v;
const CAT_RU: Record<string, string> = { ready: "построен", failed: "ошибка", building: "строится", interrupted: "прервано, будет повторено", empty: "не построен" };
const secs = (s: number | null | undefined) => (s == null ? "—" : s < 90 ? `${Math.round(s)} с` : s < 5400 ? `${Math.round(s / 60)} мин` : `${(s / 3600).toFixed(1).replace(".", ",")} ч`);
const pct = (v: number | null | undefined, d = 0) => (v == null ? "—" : `${v.toFixed(d).replace(".", ",")} %`);

/** Мини-график: последние точки замеров (без осей), 100 % — верх. Пустые точки — разрыв. */
function Spark({ points, max = 100, label, warn }: { points: (number | null)[]; max?: number; label: string; warn?: number }) {
  const pts = points.slice(-120);
  if (pts.filter((p) => p != null).length < 2) return <span className="spark empty" aria-hidden />;
  const w = 120, h = 28, top = Math.max(max, ...pts.map((p) => p ?? 0));
  const xy = pts.map((p, i) => (p == null ? null : [Math.round((i / (pts.length - 1)) * w * 10) / 10, Math.round((h - 2 - (p / top) * (h - 4)) * 10) / 10]));
  const d = xy.map((p, i) => (p ? `${i && xy[i - 1] ? "L" : "M"}${p[0]},${p[1]}` : "")).join("");
  const last = pts[pts.length - 1];
  return (
    <svg className={`spark ${warn != null && last != null && last >= warn ? "hot" : ""}`} viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`${label}: последние ${pts.length} замеров, сейчас ${last ?? "—"}`}>
      <path d={`${d}`} fill="none" strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  );
}

function Level({ l, text }: { l: TechLevel; text?: string }) { return <span className={`badge ${LEVEL_CLS[l]}`}>{text ?? LEVEL_RU[l]}</span>; }

function Explain({ children, title = "Что это значит" }: { children: ReactNode; title?: string }) {
  return <details className="explain"><summary><Icon name="info" size={14} />{title}</summary><div className="explain-body">{children}</div></details>;
}

/** «450 МБ / 3 ГБ · 15 % лимита» — память контейнера относительно его лимита (без лимита — от памяти сервера). */
function MemOf({ r, total }: { r: TechRes; total?: number | null }) {
  if (r.mem == null) return <span className="muted">нет данных</span>;
  const lim = r.mem_limit;
  const p = lim ? (r.mem / lim) * 100 : null;
  return <span className="nowrap">{bytes(r.mem)}{lim ? <> / {bytes(lim)} <span className={`muted small ${p != null && p >= 90 ? "bad-text" : ""}`}>· {pct(p)} лимита</span></> : <span className="muted small"> · без лимита{total ? ` (из ${bytes(total)} сервера)` : ""}</span>}</span>;
}

/** CPU контейнера: 100 % = одно ядро. Показываем и долю сервера — «одно ядро на 100 %» на 20-ядерном сервере не равно «сервер загружен». */
function CpuOf({ r, cpus }: { r: TechRes; cpus?: number }) {
  if (r.cpu_pct == null) return <span className="muted">нет данных</span>;
  return <span className="nowrap">{pct(r.cpu_pct)} ядра{cpus ? <span className="muted small"> · {pct(r.cpu_pct / cpus, 1)} сервера</span> : null}{r.cpu_limit ? <span className="muted small"> · лимит {String(r.cpu_limit).replace(".", ",")} ядра</span> : null}</span>;
}

export default function TechAdmin({ onOpen }: { onOpen: (tab: string) => void }) {
  const [sp, setSp] = useSearchParams();
  const view = (VIEWS.some((v) => v.id === sp.get("view")) ? sp.get("view") : "overview") as View;
  const setView = (v: View) => setSp((p) => { p.set("view", v); return p; });
  const [s, setS] = useState<TechState | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.tech().then((x) => { setS(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => {
    void load();
    const t = window.setInterval(() => { if (document.visibilityState === "visible") void load(); }, 10000);      // сводка в кэше 5 с: опрос раз в 10 с не нагружает сервер
    return () => window.clearInterval(t);
  }, [load]);
  const refresh = async () => {
    setBusy(true);
    try { setS(await api.admin.techRefresh()); show("Данные обновлены"); } catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(false); }
  };
  if (err && !s) return <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!s) return <div className="card"><SkelRows rows={5} cols={4} /></div>;
  const age = Math.max(0, Math.round(Date.now() / 1000 - s.at));
  const nprob = s.problems.length;
  return (
    <div className="stack tech">
      <div className="tech-head">
        <div className={`tech-state ${s.level}`} role="status">
          <span className={`dot ${DOT[s.level]}`} aria-hidden />
          <div><b>{s.level === "ok" ? "KAV Checker работает исправно" : s.level === "warn" ? `Есть предупреждения: ${nprob}` : `Обнаружены неисправности: ${s.problems.filter((p) => p.level === "bad").length}`}</b>
            <span className="block small muted">данные на {fmtTs(s.at)}{age > 40 ? <span className="warn-text"> · устарели на {secs(age)}</span> : ""} · версия {versionLabel(s.version, s.commit)}</span></div>
        </div>
        <div className="tech-actions">
        <button type="button" className="btn" onClick={() => void refresh()} disabled={busy} aria-busy={busy} title="Пересчитать сейчас (не чаще раза в 10 с)"><Icon name="refresh" size={15} />{busy ? "Обновление…" : "Обновить данные"}</button>
        <ReportMenu />
        </div>
      </div>
      <Tabs value={view} onChange={setView} label="Разделы технического состояния" items={VIEWS.map((v) => ({ ...v, ...(v.id === "overview" && nprob ? { count: nprob } : {}) }))} />
      <div className="tab-panel" key={view}>
        {view === "overview" && <Overview s={s} go={setView} />}
        {view === "resources" && <Resources s={s} />}
        {view === "services" && <Services s={s} onOpen={onOpen} />}
        {view === "jobs" && <Jobs s={s} />}
        {view === "pg" && <Pg s={s} />}
        {view === "sources" && <Sources s={s} onOpen={onOpen} />}
        {view === "components" && <ComponentsAdmin />}
        {view === "diag" && <Diag s={s} onOpen={onOpen} />}
      </div>
      {toast}
    </div>
  );
}

function ReportMenu() {
  const [open, setOpen] = useState(false);
  const [ext, setExt] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return (
    <div className="menu-wrap" ref={box}>
      <button type="button" className="btn primary" aria-expanded={open} onClick={() => setOpen((o) => !o)}><Icon name="download" size={15} />Скачать диагностический отчёт</button>
      {open && <div className="menu-pop" role="dialog" aria-label="Диагностический отчёт">
        <p className="small muted">Версия, ресурсы, службы, задания, PostgreSQL, источники, ошибки и ограничения. Пароли, токены, строки подключения и содержимое Excel в отчёт не попадают.</p>
        <label className="check"><input type="checkbox" checked={ext} onChange={(e) => setExt(e.target.checked)} />Для передачи вне организации: заменить IP-адреса, имена компьютеров и источников, почту и идентификаторы</label>
        <div className="row tight">{(["html", "txt", "json"] as const).map((f) => <a key={f} className="btn mini" href={api.admin.techReportUrl(f, ext)} onClick={() => setOpen(false)}>{f.toUpperCase()}</a>)}</div>
      </div>}
    </div>
  );
}

function Overview({ s, go }: { s: TechState; go: (v: View) => void }) {
  const h = s.host, j = s.jobs.counts;
  const sv = (k: string) => s.services.find((x) => x.key === k);
  const memUsed = h?.mem_total && h.mem_available != null ? ((h.mem_total - h.mem_available) / h.mem_total) * 100 : null;
  const tile = (label: string, v: ReactNode, sub: ReactNode, to: View, l?: TechLevel) => (
    <button type="button" className={`meter tile ${l ?? ""}`} onClick={() => go(to)}><span className="l">{l && <span className={`dot ${DOT[l]}`} aria-hidden />}{label}</span><span className="v">{v}</span><span className="t">{sub}</span></button>);
  const svcTile = (k: string, label: string) => { const x = sv(k); if (!x) return null; const l: TechLevel = x.level === "ok" && x.func.level !== "ok" ? x.func.level : x.level;
    const sub = l !== "ok" ? (x.func.level !== "ok" ? x.func.text : x.text) : x.func.text || (x.heartbeat_age_s != null ? `пульс ${ago(x.heartbeat_age_s)}` : "");
    return tile(label, <span className="v text">{LEVEL_RU[l]}</span>, sub, "services", l); };
  return (<>
    {s.problems.length > 0 ? (
      <div className="card flush">
        <div className="card-head"><h2>Что требует внимания</h2><span className="muted small">по порогам из «Диагностика → Пороги»</span></div>
        <ul className="rows pad-x tech-problems">{s.problems.map((p, i) => (
          <li key={i}><span className={`dot ${DOT[p.level]}`} aria-hidden /><div className="r-main"><b>{p.area}</b><span className="r-sub">{p.text}</span></div>
            <button type="button" className="btn mini ghost" onClick={() => go(p.tab as View)}>Подробнее</button></li>))}</ul>
      </div>) : <div className="alert ok"><Icon name="checkCircle" /><div className="alert-body">Проблем не обнаружено: службы отвечают, задания продвигаются, ресурсов достаточно.</div></div>}
    <div className="meters">
      {tile("Процессор сервера", pct(h?.cpu_pct), <><Spark points={(h?.hist ?? []).map((p) => p[1])} label="Загрузка процессора" warn={s.thresholds.cpu_pct} /> {h ? `${h.cpus} ядер · load ${h.load?.[0]?.toFixed(2).replace(".", ",") ?? "—"}` : "нет данных"}</>, "resources", h?.cpu_pct != null && h.cpu_pct >= s.thresholds.cpu_pct ? "warn" : undefined)}
      {tile("Оперативная память", pct(memUsed), h ? `${bytes(h.mem_available)} доступно из ${bytes(h.mem_total)}` : "нет данных", "resources")}
      {tile("Свободно на диске данных", s.disk ? bytes(s.disk.free) : "—", s.disk ? `из ${bytes(s.disk.total)} · ${pct((s.disk.free / s.disk.total) * 100)}` : "нет данных", "resources")}
      {svcTile("postgres", "PostgreSQL")}
      {svcTile("backend", "Backend")}
      {svcTile("worker", "Worker")}
      {svcTile("pentest", "Pentest")}
      {tile("Выполняются", num(j.running), j.stalled ? <span className="warn-text">без хода выполнения: {j.stalled}</span> : `завершено за сутки ${num(j.done_24h)}`, "jobs", j.stalled || j.expired ? "warn" : undefined)}
      {tile("Ожидают исполнителя", num(j.waiting), j.oldest_wait_s ? `дольше всех — ${secs(j.oldest_wait_s)}` : "очереди нет", "jobs", j.oldest_wait_s && j.oldest_wait_s >= s.thresholds.job_wait_minutes * 60 ? "warn" : undefined)}
      {tile("Ошибки за 24 часа", num(s.journal.errors_24h), `заданий с ошибкой: ${num(j.failed_24h)}`, "diag", s.journal.errors_24h > s.thresholds.errors_24h ? "warn" : undefined)}
    </div>
    <ServiceTable s={s} compact />
  </>);
}

function ServiceTable({ s, compact, onOpen }: { s: TechState; compact?: boolean; onOpen?: (t: string) => void }) {
  const ex = useExpanded<string>();
  const cpus = s.host?.cpus;
  return (
    <div className="card flush">
      <div className="card-head"><h2>Службы и контейнеры</h2><span className="muted small">{s.helper.available ? `сведения Docker — помощник на сервере, ${s.helper.age_s != null ? ago(s.helper.age_s) : "—"}` : "сведений Docker нет: помощник обновлений не запущен — показаны пульсы служб"}</span></div>
      <div className="table-scroll flat"><table className="table compact">
        <thead><tr>{!compact && <ExpandTh />}<th>Служба</th><th>Контейнер</th><th>Функции</th><th className="num">CPU</th><th>Память</th><th className="hide-sm">Работает</th></tr></thead>
        <tbody>{s.services.map((x) => (
          <Fragment key={x.key}><tr>
            {!compact && <ExpandCell id={`sv-${x.key}`} open={ex.has(x.key)} onToggle={() => ex.toggle(x.key)} label={x.title} />}
            <td><b>{x.title}</b><span className="sub small">{x.purpose}</span></td>
            <td><Level l={x.level} text={x.container ? `${dk(x.container.state)}${x.container.health ? ` · ${dk(x.container.health)}` : ""}` : LEVEL_RU[x.level]} />{x.level !== "ok" && <span className="sub small">{x.text}</span>}</td>
            <td>{x.func.text ? <span className={x.func.level === "ok" ? "" : x.func.level === "bad" ? "bad-text" : "warn-text"}>{x.func.text}</span> : <span className="muted small">{x.key === "worker" ? "см. «Задания и Worker»" : "—"}</span>}</td>
            <td className="num"><Spark points={x.res.hist.map((p) => p[2])} max={100} label={`CPU ${x.title}`} warn={s.thresholds.core_pct} /><span className="block small"><CpuOf r={{ ...x.res, cpu_limit: null }} cpus={cpus} /></span></td>
            <td className="small"><MemOf r={x.res} total={s.host?.mem_total} /></td>
            <td className="small hide-sm nowrap">{x.container?.started_at ? fmt(x.container.started_at) : x.started_at ? fmt(x.started_at) : "—"}{x.heartbeat_age_s != null && <span className="sub">пульс {ago(x.heartbeat_age_s)}</span>}</td></tr>
            {!compact && <ExpandedRow id={`sv-${x.key}`} open={ex.has(x.key)} colSpan={7}><ServiceDetail x={x} onOpen={onOpen} /></ExpandedRow>}
          </Fragment>))}</tbody>
      </table></div>
      <div className="pad-x pad-b"><Explain>Состояние контейнера (Docker «running», «healthy») и работа его функций проверяются отдельно: контейнер может быть исправным, а worker при этом не продвигать задания — это видно в столбце «Функции» и на вкладке «Задания и Worker». CPU контейнера считается в долях одного ядра: 100 % — одно ядро занято полностью; рядом — доля всего сервера.</Explain></div>
    </div>
  );
}

function ServiceDetail({ x, onOpen }: { x: TechService; onOpen?: (t: string) => void }) {
  const c = x.container, r = x.res;
  return (<>
    <XGrid>
      <XItem label="Образ и версия">{c?.image || "—"}{x.version ? <span className="sub small">приложение {x.version}</span> : null}</XItem>
      <XItem label="Docker">{c ? <>{dk(c.state)}{c.health ? `, проверка здоровья: ${dk(c.health)}` : ""}; перезапусков {c.restarts}{c.oom_killed ? "; завершён по нехватке памяти (OOM)" : ""}{c.exit_code ? `; код выхода ${c.exit_code}` : ""}</> : "нет сведений (нужен помощник на сервере)"}</XItem>
      <XItem label="Лимиты">CPU {r.cpu_limit ?? c?.cpu_limit ?? "без лимита"} · память {bytes(r.mem_limit ?? c?.mem_limit) === "—" ? "без лимита" : bytes(r.mem_limit ?? c?.mem_limit)}{r.mem_peak ? ` · пик ${bytes(r.mem_peak)}` : ""}</XItem>
      <XItem label="Процессы и потоки">{r.pids ?? c?.pids ?? "—"} процессов · {r.threads ?? "—"} потоков{r.oom_kill ? <span className="bad-text"> · OOM-завершений: {r.oom_kill}</span> : null}</XItem>
      {r.io_pressure != null && <XItem label="Ожидание диска">{pct(r.io_pressure, 1)} времени за 10 с</XItem>}
      {c?.health_out && <XItem label="Последняя проверка здоровья" wide><code className="small">{c.health_out}</code></XItem>}
      {c?.error && <XItem label="Ошибка Docker" wide><span className="bad-text">{c.error}</span></XItem>}
      {r.high_since && <XItem label="Высокая нагрузка">непрерывно с {fmtTs(r.high_since)} ({secs(Date.now() / 1000 - r.high_since)})</XItem>}
    </XGrid>
    {r.top.length > 0 && <><h4 className="mt-sm">Процессы контейнера</h4><table className="table compact"><thead><tr><th>PID</th><th>Процесс</th><th className="num">CPU</th><th className="num">Потоки</th><th className="num">Память</th></tr></thead>
      <tbody>{r.top.map((p) => <tr key={p.pid}><td className="mono small">{p.pid}</td><td className="mono small">{p.name}</td><td className="num">{pct(p.cpu_pct)}</td><td className="num">{p.threads}</td><td className="num">{bytes(p.rss)}</td></tr>)}</tbody></table></>}
    {onOpen && <div className="row tight mt-sm"><button type="button" className="btn mini" onClick={() => onOpen("journal")}>Журнал событий</button></div>}
  </>);
}

function Resources({ s }: { s: TechState }) {
  const h = s.host;
  const dirs = s.dirs?.dirs ?? {};
  const tables = s.pg.tables?.items ?? [];
  const cat = (pre: string[]) => tables.filter((t) => pre.some((p) => t.table.startsWith(p))).reduce((a, t) => a + t.total, 0);
  const GROUPS: [string, string[]][] = [["Уязвимости (кеши NVD, KEV, OSV, БДУ и результаты анализа)", ["vdb_", "host_vuln"]], ["Данные зон (копия KSC)", ["zc_", "zone"]], ["EOL", ["eol_"]],
    ["Устройства и пользователи", ["dev_"]], ["Каталог программ", ["catalog_"]], ["BI-выгрузки", ["bi_"]], ["Pentest и CVE Hunt", ["pt_", "hunt_"]], ["Журналы событий и действий", ["event_log", "audit_log"]],
    ["История заданий", ["job_"]], ["Отчёты (метаданные)", ["report"]]];
  const groups: [string, number][] = GROUPS.map(([k, pre]) => [k, cat(pre)]);
  const rest = tables.reduce((a, t) => a + t.total, 0) - groups.reduce((a, [, v]) => a + v, 0);
  if (rest > 0) groups.push(["Остальное", rest]);
  const DIR_RU: Record<string, string> = { postgres: "База PostgreSQL (каталог)", reports: "Сформированные отчёты и архивы журналов", bi: "Копии BI-выгрузок", backups: "Резервные копии", "pentest-import": "Импорт Pentest", updater: "Журналы помощника обновлений", state: "Состояние установки" };
  return (<>
    <div className="split even">
      <div className="card">
        <h2>Процессор</h2>
        {!h ? <p className="muted">Нет замеров: службы ещё не прислали пульс.</p> : <>
          <div className="big-spark"><Spark points={h.hist.map((p) => p[1])} label="Загрузка процессора сервера" warn={s.thresholds.cpu_pct} /><span className="v">{pct(h.cpu_pct)}</span></div>
          <dl className="kv compact">
            <div><dt>Ядер</dt><dd>{h.cpus}</dd></div>
            <div><dt>Load average 1 / 5 / 15 мин</dt><dd>{h.load ? h.load.map((x) => x.toFixed(2).replace(".", ",")).join(" / ") : "—"}<span className="muted small"> · на ядро {h.load ? (h.load[0] / h.cpus).toFixed(2).replace(".", ",") : "—"}</span></dd></div>
            <div><dt>Ожидание диска (PSI)</dt><dd>{pct(h.io_pressure, 1)} <span className="muted small">времени за 10 с</span></dd></div>
          </dl>
          <Explain>Процент CPU — какая доля всех ядер сервера была занята за последние секунды. Load average — среднее число задач, которые выполняются или ждут процессор и диск; сравнивайте его с числом ядер: {h.cpus} ядер выдерживают load до {h.cpus} без очереди. Одна служба, загрузившая одно ядро на 100 %, на многоядерном сервере даёт лишь несколько процентов общей загрузки — поэтому у служб CPU показан в долях одного ядра.</Explain></>}
      </div>
      <div className="card">
        <h2>Память</h2>
        {!h ? <p className="muted">Нет замеров.</p> : <dl className="kv compact">
          <div><dt>Всего</dt><dd>{bytes(h.mem_total)}</dd></div>
          <div><dt>Используется</dt><dd>{h.mem_total && h.mem_available != null ? `${bytes(h.mem_total - h.mem_available)} · ${pct(((h.mem_total - h.mem_available) / h.mem_total) * 100)}` : "—"}</dd></div>
          <div><dt>Доступно</dt><dd>{bytes(h.mem_available)}</dd></div>
          <div><dt>Swap</dt><dd>{h.swap_total ? `${bytes((h.swap_total ?? 0) - (h.swap_free ?? 0))} из ${bytes(h.swap_total)}` : "не используется"}</dd></div>
          <div><dt>Ожидание памяти (PSI)</dt><dd>{pct(h.mem_pressure, 1)}</dd></div>
        </dl>}
        <h3 className="mt">Диск данных</h3>
        {s.disk ? <dl className="kv compact"><div><dt>Свободно</dt><dd>{bytes(s.disk.free)} из {bytes(s.disk.total)} · {pct((s.disk.free / s.disk.total) * 100)}</dd></div>
          {s.dirs && <div><dt>Том DATA_ROOT</dt><dd>{bytes(s.dirs.free)} свободно из {bytes(s.dirs.total)} <span className="muted small">(помощник, {fmtTs(s.dirs.checked_at)})</span></dd></div>}</dl> : <p className="muted">нет данных</p>}
      </div>
    </div>
    <div className="card flush">
      <div className="card-head"><h2>Контейнеры: CPU и память</h2></div>
      <div className="table-scroll flat"><table className="table compact">
        <thead><tr><th>Служба</th><th>CPU</th><th>Память / лимит</th><th className="hide-sm">Пик</th><th className="hide-sm num">Процессы · потоки</th><th className="hide-md">OOM</th></tr></thead>
        <tbody>{s.services.map((x) => <tr key={x.key}><td><b>{x.title}</b><span className="sub small">{x.res.source || "нет сведений"}{x.res.at ? `, ${ago(Math.round(Date.now() / 1000 - x.res.at))}` : ""}</span></td>
          <td className="small"><CpuOf r={x.res} cpus={s.host?.cpus} />{x.res.high_since && <span className="sub warn-text">высокая нагрузка {secs(Date.now() / 1000 - x.res.high_since)}</span>}</td>
          <td className="small"><MemOf r={x.res} total={s.host?.mem_total} /></td><td className="small hide-sm">{bytes(x.res.mem_peak)}</td>
          <td className="num small hide-sm">{x.res.pids ?? x.container?.pids ?? "—"} · {x.res.threads ?? "—"}</td>
          <td className="small hide-md">{x.res.oom_kill || x.container?.oom_killed ? <span className="bad-text">да{x.res.oom_kill ? ` (${x.res.oom_kill})` : ""}</span> : "нет"}</td></tr>)}</tbody>
      </table></div>
    </div>
    <div className="split even">
      <div className="card flush">
        <div className="card-head"><h2>Хранилища</h2>{s.dirs && <span className="muted small">размеры каталогов — {fmtTs(s.dirs.checked_at)}, раз в 15 мин</span>}</div>
        {!s.dirs ? <p className="muted small pad">Размеры каталогов собирает помощник обновлений на сервере (раз в 15 минут): он не запущен.</p> : (
          <dl className="kv compact pad-x">{Object.entries(dirs).map(([k, v]) => <div key={k}><dt>{DIR_RU[k] ?? k}</dt><dd>{v == null ? "—" : bytes(v)}{k === "postgres" && !v ? <span className="muted small"> · база в томе Docker — размер ниже</span> : null}</dd></div>)}</dl>)}
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Внутренняя база по данным</h2><span className="muted small">{s.pg.stats ? `всего ${bytes(s.pg.stats.size)}` : ""}{s.pg.tables?.at ? ` · ${fmtTs(s.pg.tables.at)}, раз в 10 мин` : ""}</span></div>
        <dl className="kv compact pad-x">{groups.filter(([, v]) => v > 0).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{bytes(v)}</dd></div>)}</dl>
      </div>
    </div>
  </>);
}

function Services({ s, onOpen }: { s: TechState; onOpen: (t: string) => void }) { return <ServiceTable s={s} onOpen={onOpen} />; }

function Jobs({ s }: { s: TechState }) {
  const [grp, setGrp] = useState("");
  const [st, setSt] = useState("");
  const ex = useExpanded<string>();
  const j = s.jobs, c = j.counts;
  const groups = ["", ...Object.keys(j.groups).filter((g) => j.items.some((i) => i.group === g) || j.by_kind.some((k) => k.group === g))];
  const items = j.items.filter((i) => (!grp || i.group === grp) && (!st || (st === "running" ? ["running", "captured"].includes(i.state) : st === "problem" ? i.stalled || i.state === "expired" : i.state === st)));
  return (<>
    <div className="meters">
      <div className="meter"><span className="l">Всего сейчас</span><span className="v">{num(c.total)}</span><span className="t">выполняются {c.running}, ожидают {c.waiting}</span></div>
      <div className="meter"><span className="l">Без хода выполнения</span><span className={`v ${c.stalled || c.expired ? "warn-text" : ""}`}>{num(c.stalled + c.expired)}</span><span className="t">порог {s.thresholds.no_progress_minutes} мин</span></div>
      <div className="meter"><span className="l">Самое долгое ожидание</span><span className="v">{secs(c.oldest_wait_s)}</span><span className="t">за сутки: среднее {secs(c.wait_avg_s)}, максимум {secs(c.wait_max_s)}</span></div>
      <div className="meter"><span className="l">Завершено за сутки</span><span className="v">{num(c.done_24h)}</span><span className={`t ${c.failed_24h ? "bad-text" : ""}`}>с ошибкой или прервано: {num(c.failed_24h)}</span></div>
      <div className="meter"><span className="l">Места worker</span><span className="v">{j.slots.slots ?? "—"}</span><span className="t">{j.running_slots.length ? `заняты: ${j.running_slots.map((r) => r.task).join(", ")}` : "свободны"}</span></div>
      <div className="meter"><span className="l">Память worker</span><span className="v">{j.slots.rss_mb != null ? `${num(j.slots.rss_mb)} МБ` : "—"}</span><span className="t">мягкий предел {num(j.slots.soft_mb ?? 0)}, жёсткий {num(j.slots.hard_mb ?? 0)} МБ</span></div>
    </div>
    {j.worker_pulse_age_s == null || j.worker_pulse_age_s > s.thresholds.heartbeat_seconds ? <div className="alert error"><Icon name="alert" /><div className="alert-body">Нет пульса worker {j.worker_pulse_age_s != null ? `${secs(j.worker_pulse_age_s)}` : ""}: список ожидающих мест недоступен, задания не продвигаются. Проверьте контейнер worker.</div></div> : null}
    <div className="card flush">
      <div className="card-head wrap"><h2>Фоновые задания</h2><div className="spacer" />
        <Segmented label="Тип заданий" value={grp} onChange={setGrp} options={groups.map((g) => [g, g ? j.groups[g] : "Все"] as [string, string])} />
        <Segmented label="Состояние" value={st} onChange={setSt} options={[["", "Все"], ["waiting", "Ожидают"], ["running", "Выполняются"], ["problem", "Без хода"]]} /></div>
      {!items.length ? <Empty icon="checkCircle" title={j.items.length ? "Нет заданий с этим отбором" : "Сейчас заданий нет"}>Завершённые — в истории ниже.</Empty> : (
        <div className="table-scroll flat"><table className="table compact">
          <thead><tr><ExpandTh /><th>Задание</th><th>Состояние</th><th>Этап</th><th className="num">Ожидание</th><th className="num">Длительность</th><th className="num" title="Последний полезный шаг: порция, этап, запрос к KSC">Ход выполнения</th><th className="num hide-sm" title="Продление аренды исполнителем">Пульс</th><th className="hide-md">Исполнитель</th></tr></thead>
          <tbody>{items.map((i) => <JobRow key={i.id} i={i} ex={ex} />)}</tbody>
        </table></div>)}
      <div className="pad-x pad-b"><Explain title="Почему живой пульс не значит, что задание работает">Исполнитель продлевает аренду задания отдельным циклом каждые ~30 с, даже если само задание остановилось — ждёт ответа SQL Server, бесконечно считает или зависло. Поэтому отдельно показан «ход выполнения» — время последнего полезного шага (порция данных, этап, запрос к KSC). Пульс свежий, а хода нет дольше порога — задание, вероятно, зависло. «Ожидает исполнителя» — задание стоит в очереди ограничителя и аренды не держит; причина ожидания берётся из самого планировщика (какие задания занимают места, предел памяти), а не из загрузки процессора.</Explain></div>
    </div>
    <div className="split even">
      <div className="card flush">
        <div className="card-head"><h2>Время выполнения по типам · сутки</h2><span className="muted small">история хранит последние 20 выполнений каждой задачи по каждому источнику: для частых задач число — нижняя оценка</span></div>
        {!j.by_kind.length ? <p className="muted small pad">Завершённых заданий за сутки нет.</p> : <div className="table-scroll flat"><table className="table compact">
          <thead><tr><th>Тип</th><th className="num">Раз</th><th className="num">Среднее</th><th className="num">Максимум</th><th className="num hide-sm">Ожидание</th></tr></thead>
          <tbody>{j.by_kind.filter((k) => !grp || k.group === grp).map((k) => <tr key={k.kind}><td>{k.kind_ru}{k.failed > 0 && <span className="sub small bad-text">с ошибкой: {k.failed}</span>}</td><td className="num">{k.n}</td><td className="num">{secs(k.avg_s)}</td><td className="num">{secs(k.max_s)}</td><td className="num hide-sm">{secs(k.wait_avg_s)}</td></tr>)}</tbody></table></div>}
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Последние завершённые</h2></div>
        <ul className="rows pad-x">{j.history.filter((r) => !grp || r.group === grp).slice(0, 15).map((r) => (
          <li key={r.id}><span className={`dot ${RUN_CLS[r.status] === "ok" ? "ok" : RUN_CLS[r.status] === "err" ? "bad" : "warn"}`} aria-hidden /><div className="r-main"><b>{r.kind_ru}{r.scope ? ` · ${r.scope}` : ""}</b>
            <span className="r-sub">{r.status_ru} · {fmt(r.finished_at)} · {secs(r.duration_s)}{r.wait_s ? `, ожидание ${secs(r.wait_s)}` : ""}{r.error ? ` · ${r.error}` : ""}</span></div></li>))}</ul>
      </div>
    </div>
  </>);
}

function JobRow({ i, ex }: { i: TechJob; ex: ReturnType<typeof useExpanded<string>> }) {
  const hot = i.stalled || i.state === "expired";
  return (<>
    <tr className={hot ? "row-warn" : undefined}>
      <ExpandCell id={`j-${i.id}`} open={ex.has(i.id)} onToggle={() => ex.toggle(i.id)} label={`${i.kind_ru}${i.scope ? ` · ${i.scope}` : ""}`} />
      <td><b>{i.kind_ru}</b>{i.scope && <span className="sub small">{i.scope}</span>}</td>
      <td><span className={`badge ${i.stalled ? "warn" : JOB_CLS[i.state]}`}>{i.state_ru}</span>{i.reason && <span className={`sub small ${hot ? "warn-text" : ""}`}>{i.reason}</span>}</td>
      <td className="small">{i.stage || "—"}{i.progress && <span className="sub">{i.progress}</span>}</td>
      <td className="num small">{secs(i.wait_s)}</td><td className="num small">{secs(i.duration_s)}</td>
      <td className={`num small ${i.stalled ? "warn-text" : ""}`}>{i.progress_age_s != null ? ago(i.progress_age_s) : "—"}</td>
      <td className={`num small hide-sm ${i.state === "expired" ? "bad-text" : ""}`}>{i.heartbeat_age_s != null ? ago(i.heartbeat_age_s) : "—"}</td>
      <td className="small hide-md">{i.executor}{i.res && <span className="sub">CPU {pct(i.res.cpu_pct)} ядра · {bytes(i.res.mem)}</span>}{i.lane && <span className="sub">очередь: {i.lane}</span>}</td>
    </tr>
    <ExpandedRow id={`j-${i.id}`} open={ex.has(i.id)} colSpan={9}>
      <XGrid>
        <XItem label="Идентификатор"><span className="mono small">{i.id}</span></XItem>
        <XItem label="Поставлено в очередь">{i.queued_at ? fmt(i.queued_at) : "—"}</XItem>
        <XItem label="Фактическое начало">{i.started_at ? fmt(i.started_at) : "ещё не начато"}</XItem>
        {i.owner && <XItem label="Исполнитель (процесс)"><span className="mono small">{i.owner}</span>{i.app_version ? <span className="sub small">версия {i.app_version}</span> : null}</XItem>}
        {i.res && <XItem label="Ресурсы" wide>{i.res.note}: CPU {pct(i.res.cpu_pct)} одного ядра, память {bytes(i.res.mem)}</XItem>}
        {i.reason && <XItem label="Причина задержки" wide>{i.reason}</XItem>}
      </XGrid>
    </ExpandedRow>
  </>);
}

function Pg({ s }: { s: TechState }) {
  const p = s.pg;
  const [sql, setSql] = useState(false);
  if (!p.ok) return <div className="alert error"><Icon name="alert" /><div className="alert-body">PostgreSQL не отвечает: {p.error}</div></div>;
  if (p.unsupported) return <Empty icon="database" title="Внутренняя база — не PostgreSQL">Подробная диагностика доступна только для PostgreSQL.</Empty>;
  const st = p.stats;
  const proc = (x: { app: string; kind: string; table: string; query_s: number | null; state?: string; wait?: string; sql?: string; xact_s?: number | null }, k: number) => (
    <tr key={k}><td className="num">{secs(x.query_s)}</td><td className="small">{x.state || "—"}{x.wait && <span className="sub">ожидание: {x.wait}</span>}</td><td className="small">{x.app}</td>
      <td className="small"><b>{x.kind}</b>{x.table ? ` · ${x.table}` : ""}{sql && x.sql && <code className="sub small sql">{x.sql}</code>}</td><td className="num small hide-sm">{secs(x.xact_s)}</td></tr>);
  return (<>
    <div className="meters">
      <div className="meter"><span className="l">Версия</span><span className="v text">{p.version}</span><span className="t">ответ {p.ping_ms} мс · {fmtTs(p.at)}</span></div>
      <div className="meter"><span className="l">Соединения</span><span className="v">{p.connections}<span className="unit">из {p.max_connections}</span></span><span className="t">{Object.entries(p.by_app ?? {}).map(([k, v]) => `${k}: ${v}`).join(" · ")}</span></div>
      <div className="meter"><span className="l">Активные запросы</span><span className="v">{p.active}</span><span className={`t ${p.waiting ? "warn-text" : ""}`}>ожидают блокировку: {p.waiting}</span></div>
      <div className="meter"><span className="l">Кеш</span><span className="v">{pct(st?.cache_hit_pct, 1)}</span><span className="t">доля чтений из памяти; ниже 95 % — база часто читает диск</span></div>
      <div className="meter"><span className="l">Размер базы</span><span className="v">{bytes(st?.size)}</span><span className="t">с момента сброса статистики: временных файлов {num(st?.temp_files)} ({bytes(st?.temp_bytes)}), взаимоблокировок {num(st?.deadlocks)}</span></div>
    </div>
    <div className="card flush">
      <div className="card-head wrap"><h2>Долгие запросы и транзакции</h2><div className="spacer" /><label className="check small"><input type="checkbox" checked={sql} onChange={(e) => setSql(e.target.checked)} />Показать текст запросов (обезличенный: значения заменены на «?»)</label></div>
      {!(p.long?.length || p.long_xact?.length) ? <p className="muted small pad">Запросов дольше 30 с и транзакций дольше минуты нет.</p> : <div className="table-scroll flat"><table className="table compact">
        <thead><tr><th className="num">Длительность</th><th>Состояние</th><th>Служба</th><th>Операция</th><th className="num hide-sm">Транзакция</th></tr></thead>
        <tbody>{[...(p.long ?? []), ...(p.long_xact ?? []).filter((x) => x.state !== "active")].map(proc)}</tbody></table></div>}
    </div>
    {(p.locks?.length ?? 0) > 0 && <div className="card flush"><div className="card-head"><h2>Блокировки</h2></div><div className="table-scroll flat"><table className="table compact">
      <thead><tr><th>Ожидает</th><th className="num">Сколько</th><th>Мешает</th><th>Состояние мешающего</th></tr></thead>
      <tbody>{p.locks!.map((l, i) => <tr key={i}><td className="small"><b>{l.waiting.app}</b><span className="sub">{l.waiting.kind}{l.waiting.table ? ` · ${l.waiting.table}` : ""}</span></td><td className="num">{secs(l.waiting.query_s)}</td>
        <td className="small"><b>{l.holder.app}</b><span className="sub">{l.holder.kind || "—"}{l.holder.table ? ` · ${l.holder.table}` : ""}</span></td><td className="small">{l.holder.state || "—"}{l.holder.xact_s ? <span className="sub">транзакция {secs(l.holder.xact_s)}</span> : null}</td></tr>)}</tbody></table></div></div>}
    {(p.autovacuum?.length ?? 0) > 0 && <div className="alert"><Icon name="info" /><div className="alert-body">Сейчас идёт autovacuum: {p.autovacuum!.map((a) => `${a.table} (${secs(a.query_s)})`).join(", ")}.</div></div>}
    <div className="card flush">
      <div className="card-head"><h2>Крупнейшие таблицы</h2><span className="muted small">оценка числа строк — по статистике PostgreSQL, без COUNT(*); замер {fmtTs(p.tables?.at)}</span></div>
      <div className="table-scroll flat"><table className="table compact">
        <thead><tr><th>Таблица</th><th className="num">Всего</th><th className="num hide-sm">Индексы</th><th className="num">Строк ≈</th><th className="num">Мёртвых</th><th className="hide-md">Vacuum / analyze</th></tr></thead>
        <tbody>{(p.tables?.items ?? []).slice(0, 25).map((t) => <tr key={t.table}><td className="mono small">{t.table}</td><td className="num">{bytes(t.total)}</td><td className="num hide-sm">{bytes(t.indexes)}</td><td className="num">{num(t.rows_est)}</td>
          <td className={`num ${t.dead_pct >= 20 && t.dead > 10000 ? "warn-text" : ""}`}>{pct(t.dead_pct, 1)}</td><td className="small hide-md">{fmt(t.last_vacuum)}<span className="sub">{fmt(t.last_analyze)}</span></td></tr>)}</tbody></table></div>
      <div className="pad-x pad-b"><Explain>Мёртвые строки — версии, оставшиеся после изменений и удалений; их убирает autovacuum. Высокая доля (больше 20 % на крупной таблице) замедляет чтение и раздувает диск — проверьте, не держит ли долгая транзакция очистку. Подробная диагностика выполняется не чаще раза в 30 с (активность) и 10 минут (размеры).</Explain></div>
    </div>
  </>);
}

function Sources({ s, onOpen }: { s: TechState; onOpen: (t: string) => void }) {
  const pt = s.sources.pentest;
  const [pings, setPings] = useState<Record<string, { ok: boolean; ms: number; error?: string } | "run">>({});
  const ping = async (id: string) => { setPings((p) => ({ ...p, [id]: "run" })); try { const r = await api.admin.pingSource(id); setPings((p) => ({ ...p, [id]: r })); } catch (e) { setPings((p) => ({ ...p, [id]: { ok: false, ms: 0, error: (e as ApiError).message } })); } };
  return (<>
    <div className="card flush">
      <div className="card-head"><h2>Kaspersky Security Center</h2><div className="spacer" /><button type="button" className="btn mini ghost" onClick={() => onOpen("sources")}>Источники данных</button></div>
      {!s.sources.ksc.length ? <Empty icon="database" title="Источники KSC не добавлены" /> : <div className="table-scroll flat"><table className="table compact">
        <thead><tr><th>Источник</th><th>Соединение</th><th>Данные (чтение KSC)</th><th className="hide-sm">Каталог программ</th><th className="hide-md">EOL · пользователи</th><th>Сейчас</th><th>Доступность</th></tr></thead>
        <tbody>{s.sources.ksc.map((k) => <tr key={k.id}><td><b>{k.name}</b>{!k.active && <span className="badge ml">выключен</span>}{k.ksc_version && <span className="sub small">KSC {k.ksc_version}</span>}</td>
          <td className="small">{k.check_ok == null ? <span className="muted">не проверялось</span> : k.check_ok ? <span className="ok-text">проверка успешна</span> : <span className="bad-text">ошибка{k.check_error ? `: ${k.check_error}` : ""}</span>}<span className="sub">{fmt(k.check_at)}</span></td>
          <td className="small">{k.sync.status === "failed" ? <span className="bad-text">ошибка: {k.sync.error}</span> : k.sync.at ? <span className={k.stale ? "warn-text" : ""}>{fmt(k.sync.at)}{k.stale ? " · устарели" : ""}</span> : <span className="muted">не выполнялось</span>}
            <span className="sub">{k.sync.hosts != null ? `${num(k.sync.hosts)} устройств` : ""}{k.sync.duration_ms ? ` · ${secs(k.sync.duration_ms / 1000)}` : ""}</span></td>
          <td className="small hide-sm">{k.catalog.status === "failed" ? <span className="bad-text" title={k.catalog.error ?? ""}>ошибка</span> : fmt(k.catalog.at)}
            <span className="sub">{CAT_RU[k.catalog.status ?? ""] ?? k.catalog.status ?? ""}{k.catalog.error && k.catalog.status !== "failed" ? " · последняя попытка не удалась" : ""}</span></td>
          <td className="small hide-md">{k.eol.error ? <span className="bad-text">ошибка EOL</span> : fmt(k.eol.at)}<span className="sub">опрос {fmt(k.devices.at)}{k.devices.error ? " — ошибка" : ""}</span></td>
          <td className="small">{k.current.length ? k.current.map((c) => <span key={c} className="block">{c}</span>) : <span className="muted">—</span>}</td>
          <td className="small nowrap">{(() => { const p = pings[k.id]; return p === "run" ? <span className="spin" aria-label="Проверка" /> : p ? (p.ok ? <span className="ok-text">отвечает за {p.ms} мс</span> : <span className="bad-text">{p.error}</span>)
            : <button type="button" className="btn mini" onClick={() => void ping(k.id)} title="Лёгкая проверка (SELECT 1) — без нагрузки на SQL Server"><Icon name="plug" size={14} />Проверить</button>; })()}</td></tr>)}</tbody></table></div>}
      <div className="pad-x pad-b"><Explain>«Соединение» — результат проверки подключения (кнопка в «Источниках данных»). «Данные» — последнее успешное чтение KSC фоновым расчётом зон: соединение может проходить, а данные при этом устареть, если расчёт не выполняется.</Explain></div>
    </div>
    <div className="card flush">
      <div className="card-head"><h2>BI-выгрузки</h2><div className="spacer" /><button type="button" className="btn mini ghost" onClick={() => onOpen("sources")}>Настроить</button></div>
      {!s.sources.bi.length ? <p className="muted small pad">BI-источники не подключены.</p> : <div className="table-scroll flat"><table className="table compact">
        <thead><tr><th>Источник</th><th>Последняя попытка</th><th>Последний успех</th><th className="hide-sm">Последний импорт</th><th className="hide-md">Следующий</th><th>Сейчас</th></tr></thead>
        <tbody>{s.sources.bi.map((b) => <tr key={b.id}><td><b>{b.name}</b>{!b.active && <span className="badge ml">выключен</span>}<span className="sub small mono">{b.smb ?? (b.kind === "upload" ? "загрузка файла" : b.kind)}</span></td>
          <td className="small">{fmt(b.last_try_at)}{b.last_error && <span className="sub bad-text">{b.last_error}</span>}</td><td className="small">{fmt(b.last_ok_at)}</td>
          <td className="small hide-sm">{b.last ? <>{b.last.status_ru}<span className="sub">{num(b.last.rows)} записей · {num(b.last.persons)} сотрудников · {num(b.last.devices)} устройств</span></> : "—"}</td>
          <td className="small hide-md">{fmt(b.next_run_at)}</td><td className="small">{b.now ?? <span className="muted">—</span>}</td></tr>)}</tbody></table></div>}
      <div className="pad-x pad-b"><Explain>Страница не подключается к SMB: показаны результаты последних фоновых попыток (по расписанию или по кнопке «Получить сейчас»).</Explain></div>
    </div>
    <div className="card">
      <h2>Pentest и CVE Hunt</h2>
      {!pt.installed ? <p className="muted">Сканер не установлен или ещё не запускался.</p> : <dl className="kv compact">
        <div><dt>Сканер</dt><dd>{pt.alive ? <span className="ok-text">отвечает</span> : <span className="bad-text">не отвечает</span>}<span className="muted small"> · пульс {ago(pt.heartbeat_age_s)}</span></dd></div>
        <div><dt>Nmap</dt><dd>{pt.nmap || <span className="bad-text">не найден</span>}{pt.net_raw === false && <span className="muted small"> · без прав raw-сокетов: только TCP connect</span>}</dd></div>
        <div><dt>NSE</dt><dd>{pt.nse_scripts ? `${num(pt.nse_scripts)} скриптов в образе` : "—"}</dd></div>
        <div><dt>Nuclei</dt><dd>{pt.nuclei.version || <span className="muted">не установлен</span>}{pt.nuclei.status === "error" && <span className="sub bad-text">{pt.nuclei.message}</span>}</dd></div>
        <div><dt>Шаблоны Nuclei</dt><dd>{pt.nuclei.templates ? `${pt.nuclei.templates} · ${num(pt.nuclei.templates_n)} шаблонов · ${fmt(pt.nuclei.templates_at)}` : <span className="muted">не загружены</span>}</dd></div>
        <div><dt>Очередь</dt><dd>в очереди {pt.queued}, выполняется {pt.running}{pt.failed_24h ? <span className="bad-text"> · с ошибкой за сутки: {pt.failed_24h}</span> : ""}</dd></div>
      </dl>}
    </div>
  </>);
}

const TH: [string, string, string][] = [["cpu_pct", "Загрузка процессора сервера", "%"], ["core_pct", "Служба: загрузка одного ядра", "%"], ["cpu_minutes", "…и держится дольше", "мин"], ["mem_free_pct", "Доступная память сервера ниже", "%"],
  ["container_mem_pct", "Память контейнера от лимита выше", "%"], ["disk_free_pct", "Свободно на диске данных ниже", "%"], ["disk_free_gb", "…или меньше", "ГБ"], ["job_wait_minutes", "Задание ждёт исполнителя дольше", "мин"],
  ["no_progress_minutes", "Нет хода выполнения дольше", "мин"], ["ksc_stale_hours", "Данные KSC старше", "ч"], ["bi_stale_hours", "Нет успешного импорта BI дольше", "ч"], ["sql_long_seconds", "Запрос PostgreSQL дольше", "с"],
  ["errors_24h", "Ошибок в журнале за сутки больше", ""], ["heartbeat_seconds", "Нет пульса службы дольше", "с"]];

function Diag({ s, onOpen }: { s: TechState; onOpen: (t: string) => void }) {
  const [th, setTh] = useState<SettingsValues | null>(null);
  const [saving, setSaving] = useState(false);
  const [sys, setSys] = useState<SystemStatus | null>(null);
  const [toast, show] = useToast();
  useEffect(() => { api.admin.settings("tech").then(setTh).catch(() => undefined); api.admin.system().then(setSys).catch(() => undefined); }, []);
  const save = async () => { if (!th) return; setSaving(true); try { setTh(await api.admin.saveSettings("tech", th)); show("Пороги сохранены: применяются при следующем обновлении данных"); } catch (e) { show((e as ApiError).message, "error"); } finally { setSaving(false); } };
  const jr = s.journal;
  return (<>
    <div className="split even">
      <div className="card flush">
        <div className="card-head"><h2>Журнал событий</h2><div className="spacer" /><button type="button" className="btn mini" onClick={() => onOpen("journal")}>Открыть журнал</button><button type="button" className="btn mini ghost" onClick={() => onOpen("logs")}>Настройки хранения</button></div>
        <dl className="kv compact pad-x">
          <div><dt>Ошибок за сутки</dt><dd className={jr.errors_24h ? "bad-text" : ""}>{num(jr.errors_24h)} <span className="muted small">· предупреждений {num(jr.warn_24h)}</span></dd></div>
          <div><dt>Последняя ошибка</dt><dd>{jr.last_error ? <>{jr.last_error.message}<span className="sub small">{fmt(jr.last_error.at)} · {jr.last_error.category}{jr.last_error.source ? ` · ${jr.last_error.source}` : ""}</span></> : "нет"}</dd></div>
        </dl>
        <ul className="rows pad-x">{jr.recent.slice(0, 8).map((e, i) => <li key={i}><span className={`dot ${e.level === "error" ? "bad" : "warn"}`} aria-hidden /><div className="r-main"><b className="clamp2">{e.message ?? e.event}</b><span className="r-sub">{fmt(e.at)} · {e.category}{e.source ? ` · ${e.source}` : ""}</span></div></li>)}</ul>
      </div>
      <div className="card">
        <h2>Как собираются показатели</h2>
        <dl className="kv compact">
          <div><dt>CPU, память, процессы служб</dt><dd>пульс каждой службы раз в 15 с (чтение /proc и cgroup), история около часа</dd></div>
          <div><dt>Контейнеры Docker</dt><dd>{s.helper.available ? `помощник на сервере раз в минуту, последний замер ${ago(s.helper.age_s)}` : "помощник обновлений не запущен — состояние Docker недоступно"}</dd></div>
          <div><dt>PostgreSQL</dt><dd>активность — раз в 30 с, размеры таблиц — раз в 10 минут</dd></div>
          <div><dt>Каталоги данных</dt><dd>раз в 15 минут (помощник)</dd></div>
          <div><dt>Версии компонентов</dt><dd>фоновая проверка по расписанию · {fmt(s.components.checked_at)}</dd></div>
          <div><dt>Эта страница</dt><dd>обновляется раз в 10 с, пока открыта; сводка кэшируется на 5 с</dd></div>
        </dl>
        <p className="muted small mt-sm">Раздел только читает: он не выполняет команды на сервере, не перезапускает службы и не снимает задания.</p>
      </div>
    </div>
    <div className="card">
      <div className="row"><h2>Пороги предупреждений</h2><div className="spacer" /><button type="button" className="btn primary mini" disabled={!th || saving} onClick={() => void save()}>Сохранить</button></div>
      {!th ? <SkelRows rows={3} cols={3} /> : <div className="th-grid">{TH.map(([k, label, unit]) => (
        <label key={k} className="field"><span>{label}</span><span className="row tight"><input type="number" inputMode="numeric" value={String(th[k] ?? "")} onChange={(e) => setTh({ ...th, [k]: Number(e.target.value) })} />{unit && <span className="muted small">{unit}</span>}</span></label>))}</div>}
    </div>
    {sys && <div className="split even">
      <div className="card flush">
        <div className="card-head"><h2>История обновлений</h2><div className="spacer" /><button type="button" className="btn mini ghost" onClick={() => onOpen("updates")}>Обновления</button></div>
        {!sys.update_history.length ? <p className="muted small pad">Обновлений через помощника ещё не было.</p> : (
          <ul className="rows pad-x">{sys.update_history.map((h, i) => <li key={i}><span className={`dot ${h.result === "ok" ? "ok" : "bad"}`} aria-hidden /><div className="r-main"><b>{h.action}: {h.from_version} → {h.to_version}</b>
            <span className="r-sub">{fmtTs(h.at)} · {h.by}{h.result !== "ok" ? ` · ошибка на этапе ${h.stage ?? "?"}` : ""}</span></div></li>)}</ul>)}
      </div>
      <div className="card">
        <h2>Безопасность</h2>
        <dl className="kv compact">
          <div><dt>Публичный адрес</dt><dd className="mono small">{sys.public_url}</dd></div>
          <div><dt>HTTPS</dt><dd>{sys.security.https ? <span className="ok-text">да</span> : <span className="warn-text">нет</span>}</dd></div>
          <div><dt>Cookie сессии</dt><dd>{sys.security.secure_cookie ? "с флагом Secure" : "без флага Secure"}</dd></div>
          <div><dt>Ключ шифрования</dt><dd>{sys.master_key_ok ? <span className="ok-text">задан</span> : <span className="bad-text">не задан</span>}</dd></div>
        </dl>
      </div>
    </div>}
    {toast}
  </>);
}
