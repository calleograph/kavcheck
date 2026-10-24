import { FormEvent, Fragment, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type ApiError, type AuditItem, type AuditParams, type AuditResultRow, type AuditSummary, type SavedCheck, type VersionOp } from "../api";
import type { Ctx } from "../App";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { ProductPicker, type PickedProduct } from "../components/ProductPicker";
import { useToast } from "../components/Toast";
import { Empty, TagInput } from "../components/ui";
import { VirtualRows, useStaticList } from "../components/Infinite";
import { fmt, num } from "../util";

export const OP_LABEL: Record<VersionOp, string> = { lt: "ниже", le: "ниже или равна", eq: "равна", ge: "не ниже", gt: "выше", range: "в диапазоне", any: "любая" };

export interface Draft {
  id: number; kind: "product" | "pattern" | "rule"; product: PickedProduct | null; family: PickedProduct[]; op: VersionOp; value: string; min: string; max: string; target: string;
  exclude: string[]; branches: string[]; platform: "" | "windows" | "linux"; name_like: string; name_regex: string; publisher_like: string; rule: string; label: string; open: boolean;
}
let seq = 1;
export const emptyDraft = (over: Partial<Draft> = {}): Draft => ({ id: seq++, kind: "product", product: null, family: [], op: "lt", value: "", min: "", max: "", target: "", exclude: [], branches: [], platform: "",
  name_like: "", name_regex: "", publisher_like: "", rule: "", label: "", open: false, ...over });

export function draftFromItem(it: AuditItem): Draft {
  return emptyDraft({ kind: it.kind ?? "product", product: it.product_key ? { key: it.product_key, name: it.product_name ?? it.product_key } : null,
    family: (it.product_keys?.length ?? 0) > 1 ? it.product_keys!.map((k) => ({ key: k, name: k })) : [], op: it.op, value: it.value ?? "",
    min: it.min ?? "", max: it.max ?? "", target: it.target_version ?? "", exclude: it.exclude ?? [], branches: it.branches ?? [], platform: (it.platform as Draft["platform"]) ?? "",
    name_like: it.name_like ?? "", name_regex: it.name_regex ?? "", publisher_like: it.publisher_like ?? "", rule: it.rule ?? "", label: it.kind !== "product" ? it.product_name ?? "" : "",
    open: it.op !== "lt" || !!(it.exclude?.length || it.branches?.length || it.platform || it.target_version || it.kind !== "product") });
}

function toItem(d: Draft): AuditItem {
  const base: AuditItem = { kind: d.kind, op: d.op, value: d.value.trim() || null, min: d.min.trim() || null, max: d.max.trim() || null, target_version: d.target.trim() || null,
    exclude: d.exclude, branches: d.branches, platform: d.platform || null };
  if (d.kind === "product") {
    const fam = d.family.length > 1;   // семейство или несколько компонентов — один пункт с одним условием, у строк отчёта — точный пакет
    return { ...base, product_key: d.product?.key ?? null, product_keys: fam ? d.family.map((p) => p.key) : [],
      product_name: fam ? (d.label || `${d.product?.name ?? ""} и компоненты`) : d.product?.name ?? null };
  }
  if (d.kind === "rule") return { ...base, rule: d.rule || null, product_name: d.label || null };
  return { ...base, name_like: d.name_like.trim() || null, name_regex: d.name_regex.trim() || null, publisher_like: d.publisher_like.trim() || null, product_name: d.label.trim() || null };
}

function draftProblem(d: Draft): string | null {
  if (d.kind === "product" && !d.product) return "выберите программу";
  if (d.kind === "pattern" && !d.name_like.trim() && !d.name_regex.trim()) return "укажите шаблон названия";
  if (d.kind === "rule" && !d.rule) return "выберите правило";
  if (d.op === "range" && !d.min.trim() && !d.max.trim()) return "укажите границы диапазона";
  if (d.op !== "range" && d.op !== "any" && !d.value.trim()) return "укажите версию";
  return null;
}

export const itemSummary = (it: AuditItem) => {
  const name = it.product_name || it.product_key || it.name_like || it.rule || "?";
  const cond = it.op === "range" ? `${it.min ?? "…"}–${it.max ?? "…"}` : it.op === "any" ? "любая версия" : `${OP_LABEL[it.op]} ${it.value ?? ""}`;
  return `${name}: ${cond}`;
};

/** Конструктор проверки версий: программа → граница устаревших версий → источники → «Найти устаревшие версии» / XLSX / «Сохранить проверку». */
export type PreviewState = { result: { summary: AuditSummary; items: AuditResultRow[]; total: number }; multi: boolean; xlsx?: () => void } | null;

export function AuditBuilder({ ctx, initial, editing, onSaved, onResult }: { ctx: Ctx; initial: { items: Draft[]; sources?: string[]; params?: Partial<AuditParams>; name?: string } | null;
  editing: SavedCheck | null; onSaved: (c: SavedCheck) => void; onResult: (r: PreviewState) => void }) {
  const navigate = useNavigate();
  const [items, setItems] = useState<Draft[]>(initial?.items.length ? initial.items : [emptyDraft()]);
  const [sources, setSources] = useState<string[]>(initial?.sources?.length ? initial.sources : ctx.current ? [ctx.current.id] : []);
  const [includeInactive, setIncludeInactive] = useState(!!initial?.params?.include_inactive);
  const [days, setDays] = useState<string>(initial?.params?.active_days ? String(initial.params.active_days) : "");
  const [group, setGroup] = useState(initial?.params?.group_contains ?? "");
  const [rules, setRules] = useState<{ key: string; name: string }[]>([]);
  const [busy, setBusy] = useState<"" | "preview" | "xlsx">("");
  const [err, setErr] = useState("");
  const [save, setSave] = useState(false);
  const [scopeOpen, setScopeOpen] = useState(!!(initial?.params?.include_inactive || initial?.params?.active_days || initial?.params?.group_contains));
  const [toast, show] = useToast();
  const canEdit = ctx.me.user.role !== "viewer";
  useEffect(() => { api.software.rules().then((r) => setRules(r.items)).catch(() => undefined); }, []);
  const set = (id: number, patch: Partial<Draft>) => setItems((xs) => xs.map((x) => (x.id === id ? { ...x, ...patch } : x)));
  const params = (): AuditParams => ({ items: items.map(toItem), include_inactive: includeInactive, active_days: days ? Number(days) : null, group_contains: group.trim() || null });
  const problems = items.map(draftProblem);
  const ready = problems.every((p) => !p) && sources.length > 0;
  const preview = async (e?: FormEvent) => {
    e?.preventDefault(); if (!ready) return; setBusy("preview"); setErr("");
    try { onResult({ result: await api.audit.preview(params(), sources, 20000), multi: sources.length > 1, xlsx: canEdit ? xlsx : undefined }); window.requestAnimationFrame(() => document.getElementById("audit-result")?.scrollIntoView({ behavior: "smooth", block: "start" })); }
    catch (x) { setErr((x as ApiError).message); } finally { setBusy(""); }
  };
  const xlsx = async () => {
    if (!ready) return; setBusy("xlsx"); setErr("");
    try { const j = await api.reports.create("version_audit", editing?.name ?? initial?.name ?? "", params(), sources); navigate(`/reports/${j.id}`, { state: { toast: "Отчёт XLSX поставлен в очередь" } }); }
    catch (x) { setErr((x as ApiError).message); setBusy(""); }
  };
  const many = ctx.sources.length > 1;
  return (<>
    <form className="card builder" onSubmit={preview} noValidate>
      <div className="card-head"><h2>{editing ? `Проверка «${editing.name}»` : "Проверка версий"}</h2>
        {editing && <span className="badge accent">изменение сохранённой проверки</span>}</div>
      <ol className="items">
        {items.map((d, n) => (
          <li key={d.id} className="item">
            <div className="item-head"><span className="item-n">{n + 1}</span>
              <div className="item-prog"><span className="cap" aria-hidden>{d.family.length > 1 ? "Программа и компоненты" : "Программа"}</span>{d.kind === "product" && d.family.length > 1
                ? <div className="picked fam"><span className="picked-name"><b>{d.product?.name}</b><span className="muted"> и {d.family.length - 1} компонент.</span></span>
                    <span className="fam-chips">{d.family.map((p) => <span key={p.key} className="tag">{p.name}<button type="button" aria-label={`Убрать ${p.name}`} disabled={d.family.length <= 1}
                      onClick={() => set(d.id, { family: d.family.filter((x) => x.key !== p.key) })}><Icon name="close" size={12} /></button></span>)}</span>
                    <button type="button" className="btn mini ghost" onClick={() => set(d.id, { family: [] })}>Только основной</button></div>
                : d.kind === "product"
                ? <ProductPicker value={d.product} onChange={(p) => set(d.id, { product: p, branches: [], exclude: [] })} sourceIds={sources} autoFocus={n > 0 && !d.product} label={`Программа ${n + 1}`} />
                : <div className="picked"><span className="picked-name"><b>{d.kind === "rule" ? "Правило группировки" : "Отбор по шаблону названия"}</b><span className="muted"> · дополнительные настройки ниже</span></span>
                  <button type="button" className="btn mini ghost" onClick={() => set(d.id, { kind: "product" })}>Выбрать из каталога</button></div>}</div>
              {items.length > 1 && <button type="button" className="btn ghost icon" onClick={() => setItems((xs) => xs.filter((x) => x.id !== d.id))} aria-label={`Убрать программу ${n + 1}`}><Icon name="close" /></button>}
            <div className="item-cond">
              {d.op === "range" ? (<>
                <label>Версия от<input className="mono" value={d.min} onChange={(e) => set(d.id, { min: e.target.value })} placeholder="100" /></label>
                <label>до (включительно)<input className="mono" value={d.max} onChange={(e) => set(d.id, { max: e.target.value })} placeholder="129.99" /></label>
              </>) : d.op === "any" ? <p className="muted small any-note">Все версии программы</p> : (
                <label>{d.op === "lt" ? "Устаревшие: ниже версии" : `Версия ${OP_LABEL[d.op]}`}<input className="mono" value={d.value} onChange={(e) => set(d.id, { value: e.target.value })} placeholder={d.product?.latest_version ? d.product.latest_version.split(".")[0] : "130"} aria-invalid={!!problems[n] && problems[n] === "укажите версию"} />
                  {d.product?.latest_version && d.value !== d.product.latest_version && <span className="help">Новейшая в каталоге: <button type="button" className="link-btn mono" onClick={() => set(d.id, { value: d.product!.latest_version! })} title="Устаревшими считать все версии ниже новейшей">{d.product.latest_version}</button></span>}</label>)}
            </div>
            </div>
            <details className="disclosure" open={d.open} onToggle={(e) => set(d.id, { open: (e.target as HTMLDetailsElement).open })}>
              <summary>Дополнительные условия{(d.op !== "lt" || d.exclude.length || d.branches.length || d.platform || d.target || d.kind !== "product") ? <span className="badge accent">заданы</span> : null}</summary>
              <div className="adv">
                <div className="cols">
                  <label>Целевая версия<input className="mono" value={d.target} onChange={(e) => set(d.id, { target: e.target.value })} placeholder={d.op === "lt" && d.value ? `${d.value} или выше` : "до какой обновить"} /><span className="help">Попадёт в отчёт в столбец «Нужна»</span></label>
                  <label>Условие сравнения<select value={d.op} onChange={(e) => set(d.id, { op: e.target.value as VersionOp })}>
                    {(Object.keys(OP_LABEL) as VersionOp[]).map((o) => <option key={o} value={o}>Версия {OP_LABEL[o]}</option>)}</select></label>
                </div>
                <div className="cols">
                  <label>Платформа<select value={d.platform} onChange={(e) => set(d.id, { platform: e.target.value as Draft["platform"] })}><option value="">Любая</option><option value="windows">Windows</option><option value="linux">Linux</option></select></label>
                </div>
                <label>Исключить версии или ветки<TagInput value={d.exclude} onChange={(v) => set(d.id, { exclude: v })} label="Исключённые версии" placeholder="115, 7.4.33 — Enter после каждой" />
                  <span className="help">Поддерживаемые производителем сборки и ветки: «115» исключает 115.x, «7.4.33» — одну сборку.</span></label>
                {d.kind === "product" && d.product && <BranchPicker productKey={d.product.key} value={d.branches} onChange={(v) => set(d.id, { branches: v })} />}
                <fieldset className="group expert"><legend>Для опытных: отбор без каталога</legend>
                  <div className="seg-line">
                    {(["product", "pattern", "rule"] as const).map((k) => <label key={k} className="check"><input type="radio" name={`kind-${d.id}`} checked={d.kind === k} onChange={() => set(d.id, { kind: k })} />{k === "product" ? "Программа из каталога" : k === "pattern" ? "Шаблон названия" : "Правило группировки"}</label>)}
                  </div>
                  {d.kind === "pattern" && (<>
                    <div className="cols">
                      <label>SQL LIKE по названию<input className="mono" value={d.name_like} onChange={(e) => set(d.id, { name_like: e.target.value })} placeholder="%nginx%" /></label>
                      <label>Регулярное выражение<input className="mono" value={d.name_regex} onChange={(e) => set(d.id, { name_regex: e.target.value })} placeholder="^nginx(-core)?$" /></label>
                    </div>
                    <div className="cols">
                      <label>Производитель (SQL LIKE)<input value={d.publisher_like} onChange={(e) => set(d.id, { publisher_like: e.target.value })} placeholder="%Oracle%" /></label>
                      <label>Название в отчёте<input value={d.label} onChange={(e) => set(d.id, { label: e.target.value })} placeholder="nginx" maxLength={300} /></label>
                    </div></>)}
                  {d.kind === "rule" && <div className="cols"><label>Правило<select value={d.rule} onChange={(e) => set(d.id, { rule: e.target.value, label: rules.find((r) => r.key === e.target.value)?.name ?? "" })}><option value="">—</option>{rules.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</select></label>
                    <label>Ветки<TagInput value={d.branches} onChange={(v) => set(d.id, { branches: v })} label="Ветки правила" placeholder="7.4, 8.1" /></label></div>}
                </fieldset>
              </div>
            </details>
            {problems[n] && problems[n] !== "укажите версию" && problems[n] !== "выберите программу" && (d.value || d.min || d.max || d.kind !== "product") && <p className="field-err">Программа {n + 1}: {problems[n]}</p>}
          </li>
        ))}
      </ol>
      <button type="button" className="btn ghost add-item" onClick={() => setItems((xs) => [...xs, emptyDraft()])} disabled={items.length >= 50}><Icon name="plus" />Добавить программу</button>

      {many && <fieldset className="group"><legend>Где искать</legend>
        {(
          <div className="source-checks" role="group" aria-label="Источники KSC">
            {ctx.sources.map((s) => <label key={s.id} className="check"><input type="checkbox" checked={sources.includes(s.id)} onChange={() => setSources((x) => (x.includes(s.id) ? x.filter((y) => y !== s.id) : [...x, s.id]))} />
              <span className="check-body">{s.name}<span className="help">{s.database} · KSC {s.ksc_version ?? "?"}</span></span></label>)}
            <span className="help">Одна и та же проверка выполняется в каждом источнике; компьютеры разных источников не объединяются.</span>
          </div>)}
      </fieldset>}
      <details className="disclosure scope" open={scopeOpen} onToggle={(e) => setScopeOpen((e.target as HTMLDetailsElement).open)}>
        <summary>Какие компьютеры учитывать: <span className="scope-now">{includeInactive ? "все, включая без связи с KSC" : `активные за ${days || ctx.me.activity_days} сут`}{group.trim() ? `, группа «${group.trim()}»` : ""}</span>{!many && <span className="muted"> · {ctx.current?.name}</span>}</summary>
        <div className="adv">
          <label className="check"><input type="checkbox" className="switch" checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} />
            <span className="check-body">Включать давно не подключавшиеся компьютеры<span className="help">{includeInactive ? "Учитываются все устройства." : `Учитываются компьютеры, подключавшиеся к KSC за ${days || ctx.me.activity_days} сут.`}</span></span></label>
          <div className="cols">
            <label>Свой порог активности, сут<input type="number" min={1} max={3650} value={days} onChange={(e) => setDays(e.target.value)} placeholder={String(ctx.me.activity_days)} disabled={includeInactive} /></label>
            <label>Группа администрирования содержит<input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Серверы" /></label>
          </div>
        </div>
      </details>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="form-actions">
        <button className="btn primary" aria-busy={busy === "preview"} disabled={!ready || !!busy}><Icon name="search" size={15} /><span>Найти устаревшие версии</span></button>
        <button type="button" className="btn" onClick={xlsx} aria-busy={busy === "xlsx"} disabled={!ready || !!busy || !canEdit}><Icon name="download" size={15} /><span>Сформировать XLSX</span></button>
        <button type="button" className="btn ghost" onClick={() => setSave(true)} disabled={!ready || !canEdit}><Icon name="save" size={15} />{editing ? "Сохранить изменения" : "Сохранить проверку"}</button>
        {!ready && <span className="help">{sources.length ? "Выберите программу и укажите версию" : "Выберите хотя бы один источник"}</span>}
        {!canEdit && <span className="help">XLSX и сохранение проверок — для аналитиков и администраторов.</span>}
      </div>
    </form>
      {save && <SaveCheck editing={editing} defaultName={initial?.name ?? items.map((d) => d.product?.name ?? d.label).filter(Boolean).slice(0, 3).join(", ")} params={params()} sources={sources}
        onClose={() => setSave(false)} onSaved={(c) => { setSave(false); show(editing ? "Проверка обновлена" : "Проверка сохранена — её можно запустить повторно одним щелчком"); onSaved(c); }} />}
      {toast}
  </>);
}

function BranchPicker({ productKey, value, onChange }: { productKey: string; value: string[]; onChange: (v: string[]) => void }) {
  const [branches, setBranches] = useState<{ branch: string; hosts: number }[] | null>(null);
  useEffect(() => { api.catalog.product(productKey).then((p) => setBranches(p.branches.map((b) => ({ branch: b.branch, hosts: b.hosts_shown })))).catch(() => setBranches([])); }, [productKey]);
  if (!branches || branches.length < 2) return null;
  const toggle = (b: string) => onChange(value.includes(b) ? value.filter((x) => x !== b) : [...value, b]);
  return (
    <div className="branch-pick" role="group" aria-label="Только ветки">
      <span className="lbl">Только ветки <span className="help">(ничего не выбрано — все ветки)</span></span>
      <div className="chips">{branches.map((b) => <button key={b.branch || "-"} type="button" className={`chip toggle ${value.includes(b.branch) ? "on" : ""}`} aria-pressed={value.includes(b.branch)} onClick={() => toggle(b.branch)}>
        <span className="mono">{b.branch || "не определена"}</span><span className="muted small">{num(b.hosts)}</span></button>)}</div>
    </div>
  );
}

/** Результат быстрой проверки: итог по программам и источникам, найденные пакеты и версии (подходят ли под условие) и все строки «что обновить и где»
 *  одним непрерывным списком (виртуализация строк). */
export function AuditResult({ id, result, multi, onXlsx }: { id?: string; result: { summary: AuditSummary; items: AuditResultRow[]; total: number }; multi: boolean; onXlsx?: () => void }) {
  const s = result.summary;
  const [program, setProgram] = useState<string | null>(null);
  const [found, setFound] = useState<string | null>(null);
  const rows = useMemo(() => (program ? result.items.filter((r) => r.program === program) : result.items), [program, result.items]);
  const list = useStaticList(`audit:${program ?? ""}:${result.total}:${s.fetched_at}`, rows);
  const byProduct = result.items.some((r) => r.product && r.product !== r.program);
  const pick = (p: string) => { setProgram(program === p ? null : p); window.requestAnimationFrame(() => document.getElementById("audit-rows")?.scrollIntoView({ behavior: "smooth", block: "start" })); };
  return (
    <div className="audit-result" id={id} aria-live="polite">
      <div className="meters">
        <div className="meter"><span className="l">Компьютеров требуют обновления</span><span className="v">{num(s.hosts)}</span><span className="t">{multi ? "в пределах каждого источника" : `данные на ${fmt(s.fetched_at)}`}</span></div>
        <div className="meter"><span className="l">Установок с устаревшей версией</span><span className="v">{num(s.rows)}</span></div>
        <div className="meter"><span className="l">Программ проверено</span><span className="v">{num(s.programs.length)}</span><span className="t">{num(s.programs.filter((p) => p.hosts > 0).length)} с находками</span></div>
        <div className="meter"><span className="l">Не учтено неактивных</span><span className="v">{s.include_inactive ? "—" : num(s.hidden_inactive_hosts)}</span><span className="t">{s.include_inactive ? "учтены все устройства" : `без связи дольше ${s.active_days} сут`}</span></div>
      </div>
      {s.errors?.map((e) => <div key={e.source} className="alert error"><Icon name="alert" /><div className="alert-body"><b>{e.source}:</b> {e.message}</div></div>)}
      {s.notes?.map((n) => <div key={n} className="alert warn"><Icon name="info" /><div className="alert-body">{n}</div></div>)}
      <div className="table-scroll">
        <table className="table">
          <thead><tr><th>Программа</th><th>Условие</th><th>Требуемая версия</th><th>Найдено записей реестра</th>{multi && s.sources.map((x) => <th key={x.source} className="num">{x.source}</th>)}<th className="num">Компьютеров</th></tr></thead>
          <tbody>{s.programs.map((p) => {
            const f = p.found ?? []; const ok = f.filter((x) => x.matched).length;
            return (<Fragment key={p.program}>
              <tr className={`clickable ${program === p.program ? "sel" : ""}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("button")) pick(p.program); }}>
                <td><b>{p.program}</b></td><td className="small">{p.condition}</td><td className="mono small">{p.target_version || "—"}</td>
                <td className="small">{f.length ? <button type="button" className="link-btn" aria-expanded={found === p.program} onClick={() => setFound(found === p.program ? null : p.program)}>
                  {num(f.length)}, подходят {num(ok)}</button> : <span className="muted">—</span>}</td>
                {multi && p.by_source.map((b) => <td key={b.source} className="num">{num(b.hosts)}</td>)}
                <td className="num"><b className={p.hosts ? "bad-text" : "ok-text"}>{num(p.hosts)}</b></td></tr>
              {found === p.program && <tr className="detail"><td colSpan={multi ? 5 + s.sources.length : 5}>
                <ul className="found-list">{f.map((x) => <li key={`${x.name}|${x.version}`} className={x.matched ? "hit" : ""} title={x.matched ? "подходит под условие" : "не подходит под условие"}>
                  <Icon name={x.matched ? "alert" : "check"} size={13} /><span>{x.name}</span><span className="mono">{x.version}</span>{x.product && x.product !== p.program && <span className="muted">{x.product}</span>}</li>)}</ul>
              </td></tr>}
            </Fragment>);
          })}</tbody>
        </table>
      </div>
      <div className="section-head" id="audit-rows"><h2>{program ? `Компьютеры: ${program}` : "Компьютеры, где нужно обновление"}</h2><span className="count">{num(program ? rows.length : result.total)}</span>
        {program && <button type="button" className="link-btn" onClick={() => setProgram(null)}>все программы</button>}<div className="spacer" />
        {result.total > result.items.length && <span className="muted small">Показаны первые {num(result.items.length)} из {num(result.total)} — полный список в XLSX</span>}
        {onXlsx && <button type="button" className="btn mini" onClick={onXlsx}><Icon name="download" size={15} />Сформировать XLSX</button>}</div>
      <p className="muted small">Компьютеры, где версия соответствует условию проверки, — это не подтверждённые уязвимости; уязвимости, найденные KSC, — в разделе «Уязвимости».</p>
      <div className="table-scroll">
        <table className="table compact virt">
          <thead><tr>{multi && <th>Источник</th>}<th>Программа</th>{byProduct && <th>Продукт</th>}<th>Установлена</th><th>Нужна</th><th>Компьютер</th><th>IP-адрес</th><th className="hide-sm">ОС</th><th>Подключение к KSC</th></tr></thead>
          <tbody>
            <VirtualRows list={list} colSpan={8 + (multi ? 1 : 0) + (byProduct ? 1 : 0)} estimate={40} row={(r) => (
              <tr>{multi && <td className="small">{r.source}</td>}<td>{r.program}{r.app_name !== r.program && <span className="sub">{r.app_name}</span>}</td>
                {byProduct && <td className="small">{r.product !== r.program ? r.product : ""}</td>}
                <td className="mono nowrap"><b>{r.app_version}</b>{r.compared_version && r.compared_version !== r.app_version && <span className="sub mono">{r.compared_version}</span>}</td>
                <td className="mono small nowrap">{r.target_version || "—"}</td>
                <td>{multi ? r.name : <Link to={`/hosts/${r.host_id}`}>{r.name}</Link>}</td><td className="mono nowrap">{r.ip || "—"}</td><td className="small hide-sm">{r.os}</td><td className="nowrap">{fmt(r.last_connected)}</td></tr>)} />
            {!rows.length && <tr><td colSpan={9}><Empty icon="checkCircle" title="Устаревших версий не найдено">На {s.include_inactive ? "компьютерах" : "активных компьютерах"} выбранных источников версий, подходящих под условие, нет.</Empty></td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SaveCheck({ editing, defaultName, params, sources, onClose, onSaved }: { editing: SavedCheck | null; defaultName: string; params: AuditParams; sources: string[]; onClose: () => void; onSaved: (c: SavedCheck) => void }) {
  const [name, setName] = useState(editing?.name ?? defaultName); const [desc, setDesc] = useState(editing?.description ?? ""); const [shared, setShared] = useState(editing?.shared ?? true);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true);
    const body = { name, description: desc || null, params: { ...params, active_days: params.active_days ?? null }, source_ids: sources, shared };
    try { onSaved(editing ? await api.checks.update(editing.id, body) : await api.checks.create(body)); } catch (x) { setErr((x as ApiError).message); setBusy(false); }
  };
  return (
    <Modal title={editing ? "Сохранить изменения проверки" : "Сохранить проверку"} onClose={onClose}>
      <form onSubmit={submit}>
        <p className="muted small mb">Сохранённая проверка запускается повторно одним действием, без заполнения параметров: программы, условия, целевые версии и источники сохраняются.</p>
        <label>Название<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} autoFocus placeholder="Браузеры: устаревшие версии" /></label>
        <label>Описание<textarea rows={2} value={desc} onChange={(e) => setDesc(e.target.value)} maxLength={4000} placeholder="Например: бюллетень, ради которого проверяем" /></label>
        <label className="check"><input type="checkbox" className="switch" checked={shared} onChange={(e) => setShared(e.target.checked)} />Доступна всем пользователям</label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={!name.trim()}><span>Сохранить</span></button></div>
      </form>
    </Modal>
  );
}
