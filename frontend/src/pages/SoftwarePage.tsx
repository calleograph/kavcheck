import { FormEvent, Fragment, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Branch, type Grouped, type Host, type Product, type ReportParams, type SoftwareRow, type Summary } from "../api";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Fetched, Pager } from "../components/Common";
import { Modal } from "../components/Dialogs";
import { useToast } from "../components/Toast";
import { fmt, fmtDate, num } from "../util";

const DAYS = [1, 3, 7, 14, 30];

/** Раздел «Программное обеспечение»: исходный реестр KSC и логическая группировка; отметка версий → компьютеры → отчёт / сценарий аудита. */
export default function SoftwarePage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const mode = sp.get("mode") === "grouped" ? "grouped" : "registry";
  const setMode = (m: string) => setSp((p) => { p.set("mode", m); return p; });
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <h1>Программное обеспечение</h1>
      <div className="tabs" role="tablist">
        <button className={`tab ${mode === "registry" ? "active" : ""}`} role="tab" aria-selected={mode === "registry"} onClick={() => setMode("registry")}>Реестр KSC</button>
        <button className={`tab ${mode === "grouped" ? "active" : ""}`} role="tab" aria-selected={mode === "grouped"} onClick={() => setMode("grouped")}>Группировка по продуктам и версиям</button>
      </div>
      {mode === "registry" ? <Registry ctx={ctx} /> : <GroupedView ctx={ctx} />}
    </section>
  );
}

function Registry({ ctx }: { ctx: Ctx }) {
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") ?? ""); const [publisher, setPublisher] = useState(""); const [version, setVersion] = useState(""); const [platform, setPlatform] = useState("");
  const [installedOnly, setInstalledOnly] = useState(true);
  const [sort, setSort] = useState("name"); const [desc, setDesc] = useState(false);
  const [applied, setApplied] = useState({ q, publisher, version });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: Product[]; total: number } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Map<number, Product>>(new Map());
  const [open, setOpen] = useState<Product | null>(null);
  const [action, setAction] = useState<"hosts" | null>(null);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, publisher, version }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, publisher, version]);
  useEffect(() => {
    if (!ctx.current) return;
    setBusy(true);
    api.software.registry({ ...applied, platform, installed_only: installedOnly, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, applied, platform, installedOnly, sort, desc, offset]);
  const toggle = (p: Product) => setSelected((s) => { const n = new Map(s); if (n.has(p.product_id)) n.delete(p.product_id); else n.set(p.product_id, p); return n; });
  const th = (key: string, label: string, cls = "") => <th className={`sortable ${cls}`} onClick={() => { if (sort === key) setDesc(!desc); else { setSort(key); setDesc(false); } setOffset(0); }}>{label}{sort === key ? (desc ? " ▾" : " ▴") : ""}</th>;
  const params: ReportParams = { product_ids: [...selected.keys()] };
  return (
    <>
      <p className="muted">Записи реестра приложений KSC как они есть: одна строка — одно сочетание названия, версии и производителя. «Установок» — действующие установки (bDeleted = 0), «Компьютеров» — уникальные устройства. Отметьте версии, чтобы получить список компьютеров или сохранить сценарий аудита.</p>
      <div className="card filters">
        <div className="row filter-row">
          <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Название или часть названия, например php" aria-label="Поиск по названию" />
          <input value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="Производитель" aria-label="Производитель" style={{ maxWidth: 220 }} />
          <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Версия начинается с" aria-label="Версия" style={{ maxWidth: 180 }} />
          <select value={platform} onChange={(e) => { setPlatform(e.target.value); setOffset(0); }} aria-label="Платформа" style={{ width: "auto" }}><option value="">Любая платформа</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
          <label className="check" style={{ margin: 0 }}><input type="checkbox" checked={installedOnly} onChange={(e) => { setInstalledOnly(e.target.checked); setOffset(0); }} /> только установленные</label>
        </div>
      </div>
      {selected.size > 0 && (
        <div className="bulkbar" role="toolbar" aria-label="Выбранные версии">
          <b>Выбрано версий: {selected.size}</b>
          <button className="btn mini primary" onClick={() => setAction("hosts")}>Найти компьютеры</button>
          <Link className="btn mini" to={`/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(params))}`}>Сформировать отчёт</Link>
          <button className="btn mini ghost" onClick={() => setSelected(new Map())}>Снять выбор</button>
        </div>
      )}
      {err && <div className="alert error">{err}</div>}
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th style={{ width: 30 }} /> {th("name", "Программа")}{th("version", "Версия")}{th("publisher", "Производитель")}<th>Платформа</th><th className="num">Установок</th><th className="num">Компьютеров</th>{th("first_seen", "Впервые в сети")}<th /></tr></thead>
        <tbody>{(data?.items ?? []).map((p) => (
          <tr key={p.product_id} className={selected.has(p.product_id) ? "sel" : ""}>
            <td><input type="checkbox" checked={selected.has(p.product_id)} onChange={() => toggle(p)} aria-label={`Выбрать ${p.name} ${p.version}`} /></td>
            <td>{p.name}</td><td className="nowrap">{p.version}{p.upstream_version !== p.version && <div className="small muted">upstream {p.upstream_version}</div>}</td><td className="small">{p.publisher}</td><td>{p.platform}</td>
            <td className="num">{num(p.installs)}</td><td className="num">{num(p.hosts)}</td><td className="nowrap small">{fmtDate(p.first_seen)}</td>
            <td className="actions"><button className="btn mini" onClick={() => setOpen(p)} disabled={!p.installs}>Компьютеры</button></td>
          </tr>))}
          {data && !data.items.length && !busy && <tr><td colSpan={9} className="empty">Программ по этим условиям нет.</td></tr>}
        </tbody>
      </table></div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
      {open && <ProductHostsDialog product={open} onClose={() => setOpen(null)} />}
      {action === "hosts" && <HostsPreview ctx={ctx} params={params} title={`Компьютеры с выбранными версиями (${selected.size})`} onClose={() => setAction(null)} />}
    </>
  );
}

function ProductHostsDialog({ product, onClose }: { product: Product; onClose: () => void }) {
  const [d, setD] = useState<Awaited<ReturnType<typeof api.software.productHosts>> | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.software.productHosts(product.product_id).then(setD).catch((e) => setErr((e as ApiError).message)); }, [product.product_id]);
  return (
    <Modal title={`${product.name} ${product.version}`} onClose={onClose} wide>
      {err && <div className="alert error">{err}</div>}
      {!d && !err && <div className="muted">Загрузка…</div>}
      {d && (<>
        <div className="row"><span className="badge ok">активных: {d.active}</span><span className="badge warn">без связи &gt; {d.activity_days} сут: {d.inactive}</span><div className="spacer" /><Fetched at={d.fetched_at} /></div>
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Компьютер</th><th>IP</th><th>ОС</th><th>Группа</th><th>Установлена</th><th>Последнее подключение (UTC)</th><th>Активность</th></tr></thead>
          <tbody>{d.items.map((h) => <tr key={h.install_id ?? h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link></td><td className="nowrap">{h.ip}</td><td>{h.os}</td><td className="small">{h.group}</td><td className="nowrap">{fmtDate(h.install_date)}</td><td className="nowrap">{fmt(h.last_connected)}</td><td><ActivityBadge days={h.days_since_connection} activityDays={d.activity_days} /></td></tr>)}</tbody>
        </table></div>
        {d.total >= 5000 && <p className="muted small">Показаны первые 5000 установок. Полный список — через отчёт.</p>}
      </>)}
    </Modal>
  );
}

function GroupedView({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const [rules, setRules] = useState<{ key: string; name: string; description: string | null }[]>([]);
  const ruleKey = sp.get("rule") ?? "";
  const [platform, setPlatform] = useState("");
  const [g, setG] = useState<Grouped | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [openBranch, setOpenBranch] = useState<string | null>(null);
  const [action, setAction] = useState<"hosts" | null>(null);
  useEffect(() => { api.software.rules().then((r) => { setRules(r.items); if (!ruleKey && r.items[0]) setSp((p) => { p.set("rule", r.items[0].key); return p; }, { replace: true }); }).catch((e) => setErr((e as ApiError).message)); }, [ruleKey, setSp]);
  useEffect(() => {
    if (!ctx.current || !ruleKey) return;
    setBusy(true); setG(null); setPicked(new Set());
    api.software.grouped(ruleKey, platform).then((r) => { setG(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, ruleKey, platform]);
  const rule = rules.find((r) => r.key === ruleKey);
  const key = (b: Branch) => b.branch ?? "";
  const toggle = (b: Branch) => setPicked((s) => { const n = new Set(s); if (n.has(key(b))) n.delete(key(b)); else n.add(key(b)); return n; });
  const params: ReportParams = { rule: ruleKey, branches: [...picked] };
  const totalPicked = (g?.branches ?? []).filter((b) => picked.has(key(b)));
  return (
    <>
      <p className="muted">Один продукт часто представлен множеством пакетов (ядро, CLI, FPM, расширения). Группировка объединяет их по веткам версий (major.minor) по правилу, а исходные записи остаются доступны: разверните ветку, чтобы увидеть пакеты и по какому полю определена версия.</p>
      <div className="card filters">
        <div className="row filter-row">
          <label className="inline">Продукт
            <select value={ruleKey} onChange={(e) => setSp((p) => { p.set("rule", e.target.value); return p; })}>{rules.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</select>
          </label>
          <select value={platform} onChange={(e) => setPlatform(e.target.value)} aria-label="Платформа" style={{ width: "auto" }}><option value="">Любая платформа</option><option value="windows">Windows</option><option value="linux">Linux</option></select>
          <div className="spacer" />
          {g && <Fetched at={g.fetched_at} />}
        </div>
        {rule?.description && <div className="muted small">{rule.description}</div>}
        {g && <details className="small muted"><summary>Как отбираются пакеты</summary>Шаблон отбора: <code>{g.rule.name_like}</code> → регулярное выражение <code>{g.rule.name_regex}</code>{g.rule.branch_regex && <> · ветка из имени: <code>{g.rule.branch_regex}</code></>}</details>}
      </div>
      {err && <div className="alert error">{err}</div>}
      {busy && <div className="muted">Чтение реестра и установок…</div>}
      {picked.size > 0 && (
        <div className="bulkbar" role="toolbar" aria-label="Выбранные ветки">
          <b>Выбрано веток: {picked.size}</b><span className="muted small">установок {num(totalPicked.reduce((a, b) => a + b.installs, 0))}</span>
          <button className="btn mini primary" onClick={() => setAction("hosts")}>Найти компьютеры</button>
          <Link className="btn mini" to={`/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(params))}&title=${encodeURIComponent(`Аудит ${rule?.name ?? ""}: ветки ${[...picked].map((x) => x || "не определена").join(", ")}`)}`}>Сформировать отчёт</Link>
          <button className="btn mini ghost" onClick={() => setPicked(new Set())}>Снять выбор</button>
        </div>
      )}
      {g && (<>
        <div className="row" style={{ margin: "10px 0" }}><span className="badge">записей реестра: {num(g.products)}</span><span className="badge">установок: {num(g.installs)}</span><span className="badge">уникальных компьютеров: {num(g.hosts)}</span></div>
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th style={{ width: 30 }} /><th>Ветка</th><th className="num">Установок</th><th className="num">Компьютеров</th><th className="num">Пакетов</th><th>Версии пакетов</th><th /></tr></thead>
          <tbody>{g.branches.map((b) => (
            <Fragment key={key(b)}>
              <tr className={picked.has(key(b)) ? "sel" : ""}>
                <td><input type="checkbox" checked={picked.has(key(b))} onChange={() => toggle(b)} aria-label={`Выбрать ветку ${b.branch ?? "не определена"}`} /></td>
                <td>{b.branch ? <b>{rule?.name} {b.branch}</b> : <span className="badge warn" title="Версия пакета не позволяет достоверно определить ветку (метапакет, эпоха дистрибутива)">версия не определена</span>}</td>
                <td className="num">{num(b.installs)}</td><td className="num">{num(b.hosts)}</td><td className="num">{num(b.packages_count)}</td>
                <td className="small">{b.versions.slice(0, 6).join(", ")}{b.versions.length > 6 ? ` … (+${b.versions.length - 6})` : ""}</td>
                <td className="actions"><button className="btn mini" onClick={() => setOpenBranch(openBranch === key(b) ? null : key(b))}>{openBranch === key(b) ? "Скрыть пакеты" : "Пакеты"}</button></td>
              </tr>
              {openBranch === key(b) && (
                <tr className="detail"><td colSpan={7}>
                  <table className="table compact" style={{ boxShadow: "none" }}><thead><tr><th>Пакет (запись реестра)</th><th>Версия пакета</th><th>Сравниваемая версия</th><th>Производитель</th><th>Платформа</th></tr></thead>
                    <tbody>{b.packages.map((p) => <tr key={p.product_id}><td>{p.name}</td><td>{p.version}</td><td>{p.compared_version}{p.compared_version !== p.version && <span className="muted small"> ← {/^\d+\.\d+$/.test(p.compared_version) && !p.version.startsWith(p.compared_version) ? "ветка из имени пакета" : "upstream без эпохи и ревизии"}</span>}</td><td className="small">{p.publisher}</td><td>{p.platform}</td></tr>)}</tbody></table>
                </td></tr>
              )}
            </Fragment>))}
            {!g.branches.length && <tr><td colSpan={7} className="empty">Под правило не подпало ни одной установленной записи.</td></tr>}
          </tbody>
        </table></div>
      </>)}
      {action === "hosts" && <HostsPreview ctx={ctx} params={params} title={`Компьютеры: ${rule?.name} ${[...picked].map((x) => x || "не определена").join(", ")}`} onClose={() => setAction(null)} />}
    </>
  );
}

/** Быстрый просмотр компьютеров по выбору (с фильтром активности) и сохранение сценария аудита. */
function HostsPreview({ ctx, params, title, onClose }: { ctx: Ctx; params: ReportParams; title: string; onClose: () => void }) {
  const navigate = useNavigate();
  const [days, setDays] = useState<number | null>(null);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [data, setData] = useState<{ items: SoftwareRow[]; total: number; summary: Summary; branches: Summary["branches"]; fetched_at: string } | null>(null);
  const [offset, setOffset] = useState(0);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [save, setSave] = useState(false);
  const [toast, show] = useToast();
  const full = useMemo<ReportParams>(() => ({ ...params, active_days: days ?? undefined, include_inactive: includeInactive }), [params, days, includeInactive]);
  useEffect(() => { setBusy(true); api.software.hosts(full, offset, 100).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false)); }, [full, offset]);
  const byHost = useMemo(() => { const m = new Map<number, SoftwareRow[]>(); for (const r of data?.items ?? []) m.set(r.host_id, [...(m.get(r.host_id) ?? []), r]); return [...m.values()]; }, [data]);
  const canEdit = ctx.me.user.role !== "viewer";
  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="row filter-row">
        <label className="inline">Активность, сут<select value={days ?? ""} onChange={(e) => { setDays(e.target.value ? Number(e.target.value) : null); setOffset(0); }}><option value="">по настройке ({data?.summary.active_days ?? "…"})</option>{DAYS.map((d) => <option key={d} value={d}>{d}</option>)}</select></label>
        <label className="check" style={{ margin: 0 }}><input type="checkbox" checked={includeInactive} onChange={(e) => { setIncludeInactive(e.target.checked); setOffset(0); }} /> включать компьютеры без связи</label>
        <div className="spacer" />
        {canEdit && <button className="btn" onClick={() => setSave(true)}>Сохранить как сценарий аудита</button>}
        {canEdit && <button className="btn primary" onClick={() => navigate(`/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(full))}&title=${encodeURIComponent(title)}`)}>Сформировать отчёт (XLSX/CSV)</button>}
      </div>
      {err && <div className="alert error">{err}</div>}
      {busy && !data && <div className="muted">Чтение установок и компьютеров…</div>}
      {data && (<>
        <div className="row"><span className="badge accent">установок: {num(data.summary.rows)}</span><span className="badge accent">уникальных компьютеров: {num(data.summary.hosts)}</span>
          {!includeInactive && <span className="badge warn" title="Компьютеры, не подключавшиеся к KSC дольше порога, исключены из списка">исключено без связи: {num(data.summary.excluded_inactive_hosts)}</span>}
          {data.summary.excluded_not_computers > 0 && <span className="badge">не компьютеры (кластеры): {num(data.summary.excluded_not_computers)}</span>}
          <div className="spacer" /><Fetched at={data.fetched_at} /></div>
        {data.branches && data.branches.length > 1 && <div className="chips">{data.branches.map((b) => <span key={b.branch} className="chip">{b.branch}: {b.installs} уст. · {b.hosts} комп.</span>)}</div>}
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Компьютер</th><th>IP</th><th>ОС</th><th>Группа</th><th>Последнее подключение (UTC)</th><th>Активность</th><th>Пакеты (на этой странице)</th></tr></thead>
          <tbody>{byHost.map((rs) => { const h = rs[0]; return (
            <tr key={h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link>{h.linux_release && <div className="small muted">{h.linux_release}</div>}</td><td className="nowrap">{h.ip}</td><td>{h.os}</td><td className="small">{h.group}</td><td className="nowrap">{fmt(h.last_connected)}</td>
              <td><ActivityBadge days={h.days_since_connection} activityDays={data.summary.active_days ?? 7} /></td><td className="small">{rs.map((r) => `${r.app_name} ${r.app_version}`).join("; ")}</td></tr>); })}
            {!data.items.length && <tr><td colSpan={7} className="empty">Компьютеров по этим условиям нет.</td></tr>}
          </tbody>
        </table></div>
        <Pager total={data.total} offset={offset} limit={100} onPage={setOffset} />
        <p className="muted small">Строки сгруппированы по компьютеру в пределах страницы; полный список с листами «Установки», «Версии», «Компьютеры» — в отчёте.</p>
      </>)}
      {save && <SaveCheckDialog params={full} defaultName={title} onClose={() => setSave(false)} onSaved={() => { setSave(false); show("Сценарий аудита сохранён — см. «Уязвимости → Пользовательские критерии»"); }} />}
      {toast}
    </Modal>
  );
}

function SaveCheckDialog({ params, defaultName, onClose, onSaved }: { params: ReportParams; defaultName: string; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(defaultName.slice(0, 200)); const [cve, setCve] = useState(""); const [severity, setSeverity] = useState("medium"); const [desc, setDesc] = useState(""); const [comment, setComment] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); setBusy(true); try { await api.reports.saveCheck({ name, selection: params, cve: cve || null, severity, description: desc || null, comment: comment || null }); onSaved(); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); } };
  return (
    <Modal title="Сохранить сценарий аудита" onClose={onClose}>
      <form onSubmit={submit}>
        <p className="muted small">Ручная отметка версий — пользовательский критерий проверки. Он показывается отдельно от уязвимостей, подтверждённых KSC.</p>
        <label>Название<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} /></label>
        <div className="cols">
          <label>CVE (через запятую)<input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2024-…" maxLength={300} /></label>
          <label>Уровень опасности<select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="low">низкая</option><option value="medium">средняя</option><option value="high">высокая</option><option value="critical">критическая</option></select></label>
        </div>
        <label>Описание проблемы<textarea rows={3} value={desc} onChange={(e) => setDesc(e.target.value)} maxLength={4000} /></label>
        <label>Комментарий<textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} maxLength={4000} /></label>
        {err && <div className="alert error">{err}</div>}
        <div className="row"><button className="btn primary" disabled={busy || !name}>Сохранить</button><button type="button" className="btn ghost" onClick={onClose}>Отмена</button></div>
      </form>
    </Modal>
  );
}

export type { Host };
