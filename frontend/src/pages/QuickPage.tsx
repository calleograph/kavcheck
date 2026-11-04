import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { Ctx } from "../App";
import { api, type Job, type QuickPrefs } from "../api";
import { Icon, type IconName } from "../components/Icons";
import { GlobalSearch } from "../components/GlobalSearch";
import { QuickReportPanel } from "../components/QuickReport";
import { PageHead } from "../components/ui";
import { DEFAULT_ITEMS, DEFAULT_REPORTS, FUNCTIONS, QUICK_ACTIONS, QUICK_REPORTS, roleOk, type QuickReportDef, type Role } from "../navModel";
import { readRecent } from "../recent";
import { fmt, num } from "../util";

/** «Быстрый доступ»: стартовая рабочая панель. Частые действия и готовые отчёты настраиваются под себя (избранное, порядок, восстановление исходного набора) и хранятся в профиле;
 *  «Требует внимания» — показатели с переходом к выборке; «Последняя работа» — разделы и карточки, открытые на этом устройстве. Видны только разрешённые роли действия и отчёты. */
interface Card { id: string; title: string; hint: string; icon: IconName; to?: string; search?: "hosts" | "software" | "users" | "vuln" }
interface Tile { id: string; label: string; value: number; to?: string; tone: "bad" | "warn" | "info"; hint?: string; icon: IconName }

export const SEARCH_EVENT = "kc:search";

function useCards(ctx: Ctx) {
  const role = ctx.me.user.role as Role;
  return useCallback((id: string): Card | null => {
    if (id.startsWith("fn:")) {
      const f = FUNCTIONS.find((x) => x.to === id.slice(3));
      return f && roleOk(f.roles, role) && (!f.hier || ctx.hier) ? { id, title: f.title, hint: f.group, icon: f.icon, to: f.to } : null;
    }
    const a = QUICK_ACTIONS.find((x) => x.id === id);
    return a && roleOk(a.roles, role) && (!a.hier || ctx.hier) ? { id, title: a.title, hint: a.hint, icon: a.icon, to: a.to, search: a.search } : null;
  }, [role, ctx.hier]);
}

export default function QuickPage({ ctx }: { ctx: Ctx }) {
  const role = ctx.me.user.role as Role;
  const navigate = useNavigate();
  const resolve = useCards(ctx);
  const prefs = ctx.me.quick ?? null;
  const items = (prefs?.items ?? DEFAULT_ITEMS[role]).map(resolve).filter((x): x is Card => !!x);
  const reportIds = prefs?.reports ?? DEFAULT_REPORTS[role];
  const reports = reportIds.map((id) => QUICK_REPORTS.find((r) => r.id === id)).filter((r): r is QuickReportDef => !!r && roleOk(r.roles, role));
  const hidden = prefs?.hidden ?? [];
  const [edit, setEdit] = useState(false);
  const [picker, setPicker] = useState<"items" | "reports" | null>(null);
  const [panel, setPanel] = useState<QuickReportDef | null>(null);
  const [drag, setDrag] = useState<{ list: "items" | "reports"; i: number } | null>(null);
  const [saved, setSaved] = useState("");

  const save = (next: QuickPrefs) => {
    ctx.onQuick(next);
    api.setQuick(next).then(() => setSaved("Сохранено")).catch(() => setSaved("Не удалось сохранить: изменения действуют до обновления страницы"));
  };
  const current = (): Required<QuickPrefs> => ({ items: prefs?.items ?? DEFAULT_ITEMS[role].filter((id) => resolve(id)), reports: prefs?.reports ?? DEFAULT_REPORTS[role], hidden });
  const move = (list: "items" | "reports", from: number, to: number) => {
    const c = current(); const a = [...c[list]];
    if (to < 0 || to >= a.length) return;
    a.splice(to, 0, a.splice(from, 1)[0]); save({ ...c, [list]: a });
  };
  const remove = (list: "items" | "reports", id: string) => { const c = current(); save({ ...c, [list]: c[list].filter((x) => x !== id) }); };
  const add = (list: "items" | "reports", id: string) => { const c = current(); if (!c[list].includes(id)) save({ ...c, [list]: [...c[list], id] }); };
  const reset = () => { ctx.onQuick(null); api.setQuick({}).then(() => setSaved("Восстановлен исходный набор")).catch(() => setSaved("Не удалось сохранить")); };

  const search = (c: Card) => window.dispatchEvent(new CustomEvent(SEARCH_EVENT, { detail: { cat: c.search } }));
  const open = (c: Card) => (c.search ? search(c) : c.to && navigate(c.to));
  const drop = (list: "items" | "reports", to: number) => { if (drag && drag.list === list && drag.i !== to) move(list, drag.i, to); setDrag(null); };

  return (
    <section className="qa">
      <PageHead title="Быстрый доступ" lede="Частые действия, готовые отчёты и то, что требует внимания. Панель настраивается под вашу работу.">
        <div className="row">
          {edit && <button type="button" className="btn ghost" onClick={reset}><Icon name="refresh" size={15} />Восстановить исходный набор</button>}
          <button type="button" className={`btn ${edit ? "primary" : ""}`} aria-pressed={edit} onClick={() => { setEdit((e) => !e); setSaved(""); }}><Icon name={edit ? "check" : "sliders"} size={15} />{edit ? "Готово" : "Настроить панель"}</button>
        </div>
      </PageHead>

      <GlobalSearch page sourceId={ctx.current?.id ?? null} role={role} hier={ctx.hier} />

      <div className="qa-cols">
        <div className="qa-main">
          <Attention ctx={ctx} hidden={hidden} edit={edit} onHide={(id, on) => { const c = current(); save({ ...c, hidden: on ? [...new Set([...c.hidden, id])] : c.hidden.filter((x) => x !== id) }); }} />
          <div className="qa-head mt"><h2>Частые действия</h2>{edit && <button type="button" className="btn mini" onClick={() => setPicker("items")}><Icon name="plus" size={14} />Добавить</button>}</div>
          {!items.length ? <p className="muted small">Здесь пока ничего нет. {edit ? "Нажмите «Добавить»." : "Нажмите «Настроить панель», чтобы собрать свой набор."}</p> :
            <ul className="qa-grid" aria-label="Частые действия">
              {items.map((c, i) => (
                <li key={c.id} className={`qa-card ${edit ? "edit" : ""} ${drag?.list === "items" && drag.i === i ? "drag" : ""}`} draggable={edit} style={{ "--i": i } as React.CSSProperties}
                  onDragStart={() => setDrag({ list: "items", i })} onDragOver={(e) => edit && e.preventDefault()} onDrop={() => drop("items", i)} onDragEnd={() => setDrag(null)}>
                  <button type="button" className="qa-open" onClick={() => !edit && open(c)} disabled={edit} aria-label={c.title}>
                    <span className="qa-ic"><Icon name={c.icon} size={20} /></span><span className="qa-t"><b>{c.title}</b><span>{c.hint}</span></span></button>
                  {edit && <span className="qa-tools"><span className="qa-grip" aria-hidden><Icon name="grip" size={16} /></span>
                    <button type="button" className="btn mini ghost icon" aria-label={`Сдвинуть «${c.title}» назад`} disabled={i === 0} onClick={() => move("items", i, i - 1)}><Icon name="arrowL" size={14} /></button>
                    <button type="button" className="btn mini ghost icon" aria-label={`Сдвинуть «${c.title}» вперёд`} disabled={i === items.length - 1} onClick={() => move("items", i, i + 1)}><Icon name="arrowR" size={14} /></button>
                    <button type="button" className="btn mini ghost icon danger" aria-label={`Убрать «${c.title}» с панели`} onClick={() => remove("items", c.id)}><Icon name="close" size={14} /></button></span>}
                </li>))}
              {!edit && <li className="qa-card add"><button type="button" className="qa-open" onClick={() => setPicker("items")}><span className="qa-ic"><Icon name="plus" size={20} /></span><span className="qa-t"><b>Добавить</b><span>раздел, настройку или действие</span></span></button></li>}
            </ul>}

          <div className="qa-head mt"><h2>Быстрые отчёты</h2>{edit && <button type="button" className="btn mini" onClick={() => setPicker("reports")}><Icon name="plus" size={14} />Добавить</button>}<div className="spacer" /><Link className="small" to="/reports">Все отчёты</Link></div>
          {!reports.length ? <p className="muted small">Готовых отчётов на панели нет. {edit ? "Нажмите «Добавить»." : ""}</p> :
            <ul className="qa-grid rep" aria-label="Быстрые отчёты">
              {reports.map((r, i) => {
                const blocked = !!r.needsSource && !ctx.current;
                return (
                  <li key={r.id} className={`qa-card ${blocked && !edit ? "blocked" : ""} ${edit ? "edit" : ""} ${drag?.list === "reports" && drag.i === i ? "drag" : ""}`} draggable={edit} style={{ "--i": i } as React.CSSProperties}
                    onDragStart={() => setDrag({ list: "reports", i })} onDragOver={(e) => edit && e.preventDefault()} onDrop={() => drop("reports", i)} onDragEnd={() => setDrag(null)}>
                    <button type="button" className="qa-open" disabled={edit || blocked} title={blocked ? "Выберите источник KSC" : undefined}
                      onClick={() => (r.kind ? setPanel(r) : navigate(r.section))}>
                      <span className="qa-ic rep"><Icon name={r.icon} size={20} /></span><span className="qa-t"><b>{r.title}</b><span>{r.kind ? r.hint : `${r.hint} · в разделе`}</span></span></button>
                    {!edit && r.kind && <Link className="qa-sec" to={r.section} aria-label={`${r.title}: открыть раздел`} title="Открыть раздел и настроить условия на странице"><Icon name="arrowR" size={14} /></Link>}
                    {edit && <span className="qa-tools"><span className="qa-grip" aria-hidden><Icon name="grip" size={16} /></span>
                      <button type="button" className="btn mini ghost icon" aria-label={`Сдвинуть «${r.title}» назад`} disabled={i === 0} onClick={() => move("reports", i, i - 1)}><Icon name="arrowL" size={14} /></button>
                      <button type="button" className="btn mini ghost icon" aria-label={`Сдвинуть «${r.title}» вперёд`} disabled={i === reports.length - 1} onClick={() => move("reports", i, i + 1)}><Icon name="arrowR" size={14} /></button>
                      <button type="button" className="btn mini ghost icon danger" aria-label={`Убрать «${r.title}» с панели`} onClick={() => remove("reports", r.id)}><Icon name="close" size={14} /></button></span>}
                  </li>);
              })}
              {!edit && <li className="qa-card add"><button type="button" className="qa-open" onClick={() => setPicker("reports")}><span className="qa-ic rep"><Icon name="plus" size={20} /></span><span className="qa-t"><b>Добавить отчёт</b><span>из готовых шаблонов</span></span></button></li>}
            </ul>}
          {saved && <p className="muted small mt-sm" role="status">{saved}</p>}
        </div>
        <aside className="qa-side"><Sources ctx={ctx} /><Recent ctx={ctx} /><Reports ctx={ctx} /></aside>
      </div>

      {picker && <Picker kind={picker} ctx={ctx} have={current()[picker]} onPick={(id) => add(picker, id)} onClose={() => setPicker(null)} />}
      {panel && panel.kind && <QuickReportPanel kind={panel.kind} title={`Отчёт: ${panel.title}`} lede="Условия можно изменить перед формированием; тот же конструктор открывается и в самом разделе"
        options={panel.options} params={panel.params} activityDays={ctx.me.activity_days} canReport={role !== "viewer"} onClose={() => setPanel(null)} />}
    </section>
  );
}

/** Окно добавления: действия, разделы и настройки (любой пункт указателя функций можно сделать избранным) либо готовые отчёты. */
function Picker({ kind, ctx, have, onPick, onClose }: { kind: "items" | "reports"; ctx: Ctx; have: string[]; onPick: (id: string) => void; onClose: () => void }) {
  const role = ctx.me.user.role as Role;
  const [q, setQ] = useState("");
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    const all: { id: string; title: string; hint: string; icon: IconName }[] = kind === "reports"
      ? QUICK_REPORTS.filter((r) => roleOk(r.roles, role)).map((r) => ({ id: r.id, title: r.title, hint: r.hint, icon: r.icon }))
      : [...QUICK_ACTIONS.filter((a) => roleOk(a.roles, role) && (!a.hier || ctx.hier)).map((a) => ({ id: a.id, title: a.title, hint: a.hint, icon: a.icon })),
        ...FUNCTIONS.filter((f) => roleOk(f.roles, role) && (!f.hier || ctx.hier)).map((f) => ({ id: `fn:${f.to}`, title: f.title, hint: f.group, icon: f.icon }))];
    return all.filter((r) => !have.includes(r.id) && (!t || `${r.title} ${r.hint}`.toLowerCase().includes(t)));
  }, [q, kind, role, have, ctx.hier]);
  useEffect(() => { const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose(); document.addEventListener("keydown", esc); return () => document.removeEventListener("keydown", esc); }, [onClose]);
  return (
    <div className="qa-picker-wrap" role="dialog" aria-modal="true" aria-label={kind === "reports" ? "Добавить отчёт" : "Добавить на панель"}>
      <div className="qa-picker-scrim" onClick={onClose} />
      <div className="qa-picker card">
        <div className="row"><h2>{kind === "reports" ? "Добавить отчёт" : "Добавить на панель"}</h2><div className="spacer" /><button type="button" className="btn ghost icon" aria-label="Закрыть" onClick={onClose}><Icon name="close" /></button></div>
        <div className="input-icon"><Icon name="search" size={16} /><input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="Название или раздел" aria-label="Фильтр списка" /></div>
        <ul className="qa-pick-list">
          {!rows.length ? <li className="muted small pad">Ничего не найдено или всё уже добавлено.</li> : rows.map((r) => (
            <li key={r.id}><button type="button" onClick={() => onPick(r.id)}><Icon name={r.icon} size={17} /><span className="qa-t"><b>{r.title}</b><span>{r.hint}</span></span><Icon name="plus" size={15} /></button></li>))}
        </ul>
      </div>
    </div>
  );
}

/** «Требует внимания»: каждая плитка — выборка с переходом; источники данных независимы, сбой одного не прячет остальные. */
function Attention({ ctx, hidden, edit, onHide }: { ctx: Ctx; hidden: string[]; edit: boolean; onHide: (id: string, on: boolean) => void }) {
  const role = ctx.me.user.role as Role;
  const [tiles, setTiles] = useState<Tile[] | null>(null);
  const days = ctx.me.activity_days;
  const sid = ctx.current?.id;
  useEffect(() => {
    let alive = true;
    const out: Tile[] = [];
    const bad = ctx.sources.filter((s) => s.last_check_ok === false);
    if (bad.length) out.push({ id: "src-err", label: "Ошибки источников", value: bad.length, to: ctx.me.user.is_admin ? "/admin?tab=sources" : undefined, tone: "bad", hint: bad.slice(0, 2).map((s) => s.name).join(", "), icon: "database" });
    const jobs: Promise<void>[] = [
      sid ? api.overview(days).then((o) => {
        const t = o.totals;
        if (t?.rtp_off) out.push({ id: "rtp", label: "Защита не работает", value: t.rtp_off, to: "/protection?problem=rtp_off", tone: "bad", icon: "shieldPulse" });
        if (t?.no_av) out.push({ id: "noav", label: "Компьютеры без антивируса", value: t.no_av, to: "/protection?problem=no_av", tone: "bad", icon: "alert" });
        if (t?.bases_old) out.push({ id: "bases", label: "Устаревшие базы", value: t.bases_old, to: "/protection?problem=bases_old", tone: "warn", icon: "clock" });
        if (o.security?.hosts_crit) out.push({ id: "crit", label: "Устройства с критическими уязвимостями", value: o.security.hosts_crit, to: "/vulnerabilities", tone: "bad", icon: "bug" });
      }).catch(() => undefined) : Promise.resolve(),
      api.reports.list(false).then((r) => {
        const run = r.items.filter((j: Job) => j.status === "queued" || j.status === "running");
        const fail = r.items.filter((j: Job) => j.status === "failed" && Date.now() - new Date(j.created_at).getTime() < 86_400_000);
        if (run.length) out.push({ id: "job-run", label: "Отчёты в работе", value: run.length, to: "/reports", tone: "info", hint: run[0].title, icon: "play" });
        if (fail.length) out.push({ id: "job-fail", label: "Отчёты с ошибкой за сутки", value: fail.length, to: "/reports", tone: "warn", hint: fail[0].title, icon: "alert" });
      }).catch(() => undefined),
    ];
    if (role !== "viewer") {
      jobs.push(api.bi.matches({ level: "needs_manual", limit: 1 }).then((r) => {
        const c = (r as { counts?: Record<string, number> }).counts ?? {};
        if (c.needs_manual) out.push({ id: "bi-manual", label: "Сопоставление BI требует решения", value: c.needs_manual, to: "/devices?tab=match", tone: "warn", icon: "branch" });
      }).catch(() => undefined));
      jobs.push(api.bi.devices({ filter: "unknown_owner", limit: 1 }).then((r) => {
        if (r.total) out.push({ id: "bi-owner", label: "Устройства без подтверждённого владельца", value: r.total, to: "/devices?tab=bi", tone: "warn", icon: "users" });
      }).catch(() => undefined));
    }
    void Promise.all(jobs).then(() => { if (alive) setTiles(out.sort((a, b) => ({ bad: 0, warn: 1, info: 2 })[a.tone] - ({ bad: 0, warn: 1, info: 2 })[b.tone])); });
    return () => { alive = false; };
  }, [sid, days, role, ctx.sources]); // eslint-disable-line react-hooks/exhaustive-deps
  const shown = (tiles ?? []).filter((t) => edit || !hidden.includes(t.id));
  return (
    <div className="qa-att">
      <div className="qa-head"><h2>Требует внимания</h2>{tiles && <span className="count">{num(shown.length)}</span>}</div>
      {!tiles ? <div className="qa-tiles" aria-busy><span className="qa-tile skel" /><span className="qa-tile skel" /><span className="qa-tile skel" /></div>
        : !shown.length ? <p className="qa-ok"><Icon name="checkCircle" size={16} />Срочных проблем не видно: защита, источники и задания в порядке.</p>
        : <ul className="qa-tiles">{shown.map((t) => {
          const body = <><span className="qa-ic sm"><Icon name={t.icon} size={16} /></span><span className="qa-n">{num(t.value)}</span><span className="qa-l">{t.label}{t.hint && <small>{t.hint}</small>}</span></>;
          return <li key={t.id} className={`qa-tile ${t.tone} ${hidden.includes(t.id) ? "off" : ""}`}>
            {t.to && !edit ? <Link to={t.to}>{body}</Link> : <span className="qa-tile-in">{body}</span>}
            {edit && <button type="button" className="btn mini ghost" onClick={() => onHide(t.id, !hidden.includes(t.id))}>{hidden.includes(t.id) ? "Показать" : "Скрыть"}</button>}</li>;
        })}</ul>}
    </div>
  );
}

function Recent({ ctx }: { ctx: Ctx }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  useEffect(() => { api.reports.list(false).then((r) => setJobs(r.items.filter((j) => j.status === "queued" || j.status === "running").slice(0, 3))).catch(() => setJobs([])); }, []);
  const recent = readRecent(ctx.me.user.id);
  return (
    <div className="card pad qa-recent">
      <h2>Последняя работа</h2>
      {jobs.length > 0 && <ul className="qa-rl">{jobs.map((j) => <li key={j.id}><Link to={`/reports/${j.id}`}><Icon name="play" size={15} /><span><b>{j.title}</b><small>{j.status === "queued" ? "в очереди" : `формируется${j.progress ? `: ${j.progress}` : ""}`}</small></span></Link></li>)}</ul>}
      {!recent.length && !jobs.length ? <p className="muted small">Откройте любой раздел — он появится здесь, чтобы вернуться одним щелчком.</p> :
        <ul className="qa-rl">{recent.map((r) => <li key={r.to}><Link to={r.to}><Icon name="history" size={15} /><span><b>{r.label}</b><small>{fmt(new Date(r.at).toISOString())}</small></span></Link></li>)}</ul>}
    </div>
  );
}

/** Состояние подключённых источников KSC: видно сразу, что данные свежие и подключение работает. */
function Sources({ ctx }: { ctx: Ctx }) {
  if (!ctx.sources.length) return null;
  return (
    <div className="card pad qa-recent">
      <div className="qa-head"><h2>Источники данных</h2><div className="spacer" />{ctx.me.user.is_admin && <Link className="small" to="/admin?tab=sources">Настроить</Link>}</div>
      <ul className="qa-rl">{ctx.sources.slice(0, 6).map((s) => <li key={s.id}><span className="qa-src">
        <i className={`qa-dot ${s.last_check_ok === false ? "bad" : s.last_check_ok ? "ok" : ""}`} aria-hidden /><span><b>{s.name}{ctx.current?.id === s.id ? " · выбран" : ""}</b>
          <small>{s.last_check_ok === false ? "проверка не пройдена" : s.last_check_ok ? "доступен" : "не проверялся"}{s.last_check_at ? ` · ${fmt(s.last_check_at)}` : ""}</small></span></span></li>)}</ul>
    </div>
  );
}

/** Последние отчёты: статус и прямые ссылки на готовые файлы. */
function Reports({ ctx }: { ctx: Ctx }) {
  const [jobs, setJobs] = useState<Job[] | null>(null);
  useEffect(() => { api.reports.list(false).then((r) => setJobs(r.items.slice(0, 5))).catch(() => setJobs([])); }, []);
  if (!jobs?.length) return null;
  const st: Record<string, string> = { queued: "в очереди", running: "формируется", done: "готов", failed: "ошибка", cancelled: "отменён" };
  return (
    <div className="card pad qa-recent">
      <div className="qa-head"><h2>Последние отчёты</h2><div className="spacer" /><Link className="small" to="/reports">Все</Link></div>
      <ul className="qa-rl">{jobs.map((j) => <li key={j.id}><Link to={`/reports/${j.id}`}><Icon name="file" size={15} /><span><b>{j.title}</b><small>{st[j.status] ?? j.status} · {fmt(j.created_at)}</small></span></Link>
        {j.status === "done" && ctx.me.user.role !== "viewer" && <span className="qa-dl">{(["xlsx", "pdf"] as const).map((f) => <a key={f} href={api.reports.downloadUrl(j.id, f)} download aria-label={`${j.title}: скачать ${f.toUpperCase()}`}>{f.toUpperCase()}</a>)}</span>}</li>)}</ul>
    </div>
  );
}
