import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type QuickCol, type QuickKind, type QuickPreview, type Template } from "../api";
import { fmt, num, plural } from "../util";
import { CompactList } from "./CompactList";
import { Modal } from "./Dialogs";
import { Icon } from "./Icons";
import { Dock, Segmented } from "./ui";
import { ZoneField } from "./ZoneBits";
import { ZONE_CATEGORIES } from "../pages/zoneCats";

/** Выбор строк флажками: идентификаторы живут, пока открыта страница (между вкладками одного раздела — отдельные наборы). */
export function useRowSel<K extends string | number>() {
  const [ids, setIds] = useState<K[]>([]);
  const set = useMemo(() => new Set(ids), [ids]);
  return {
    ids, count: ids.length, has: (k: K) => set.has(k),
    toggle: (k: K) => setIds((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k])),
    // «выбрать все загруженные»: если все уже выбраны — снять их
    toggleMany: (keys: K[]) => setIds((cur) => { const s = new Set(cur); const all = keys.length > 0 && keys.every((k) => s.has(k)); return all ? cur.filter((k) => !keys.includes(k)) : [...cur, ...keys.filter((k) => !s.has(k))]; }),
    allOf: (keys: K[]) => keys.length > 0 && keys.every((k) => set.has(k)),
    someOf: (keys: K[]) => keys.some((k) => set.has(k)),
    clear: () => setIds([]),
  };
}

/** Панель над выбранными строками: количество, «Сформировать отчёт», снять выбор. */
export function ReportDock({ label, count, noun, canReport, onReport, onClear }: { label: string; count: number; noun: [string, string, string]; canReport: boolean; onReport: () => void; onClear: () => void }) {
  if (!count) return null;
  return (
    <Dock label={label}>
      <span><b>{num(count)}</b> <span className="muted">{plural(count, ...noun)}</span></span>
      <button className="btn mini primary" onClick={onReport}><Icon name="file" size={15} />Сформировать отчёт</button>
      <button className="btn mini icon" onClick={onClear} aria-label="Снять выбор"><Icon name="close" size={15} /></button>
      {!canReport && <span className="muted small">Просмотр доступен, выгрузка — аналитику и администратору</span>}
    </Dock>
  );
}

/** Флажок «выбрать все загруженные» для заголовка таблицы. */
export function CheckAll({ all, some, onToggle, label = "Выбрать все загруженные" }: { all: boolean; some: boolean; onToggle: () => void; label?: string }) {
  return <th className="check"><input type="checkbox" aria-label={label} checked={all} ref={(el) => { if (el) el.indeterminate = !all && some; }} onChange={onToggle} /></th>;
}

const SEV_CLASS: Record<string, string> = { "Критическая": "crit", "Высокая": "high", "Предупреждение": "warn" };
function cell(c: QuickCol, v: string | number | null | undefined) {
  if (v === null || v === undefined || v === "") return <span className="muted">—</span>;
  if (c.type === "sev") return <span className={`sev ${SEV_CLASS[String(v)] ?? "warn"}`}>{v}</span>;
  if (c.type === "date") return <span className="nowrap">{fmt(String(v))}</span>;
  if (c.type === "num") return <span className="num">{typeof v === "number" ? num(v) : v}</span>;
  if (typeof v === "string" && v.includes("; ")) return <CompactList items={v.split("; ")} sep="; " />;       // списки значений в ячейке: три значения и «+N»; в файлах — полностью
  return c.type === "mono" ? <span className="mono small nowrap">{v}</span> : <>{v}</>;
}

export type QuickScopeOpts = { bi?: boolean; hunt?: boolean; levels?: boolean; period?: boolean; severity?: boolean; patchable?: boolean; scope?: boolean; sections?: boolean; ext?: boolean; zone?: boolean; zoneFilter?: boolean; eol?: boolean };
const EXT_STATUSES: [string, string][] = [["confirmed", "Подтверждено источником"], ["potential", "Потенциально затронуто"], ["clarify", "Требуется уточнение"], ["insufficient", "Данных недостаточно"], ["fixed", "Исправлено (показать отдельно)"]];
const EOL_STATUSES: [string, string][] = [["eol", "Стандартная поддержка закончилась (EOL)"], ["extended", "Только расширенная (платная) поддержка"], ["upcoming", "Окончание поддержки приближается"], ["undetermined", "ОС: не удалось определить EOL (причина указана)"]];
export const BI_VIEWS: [string, string][] = [["owners", "Устройства и владельцы"], ["history", "История принадлежности устройств"], ["unknown", "Неопределённые владельцы"], ["discrepancies", "Расхождения BI и KSC"], ["problems", "Проблемы защиты и контактные лица"]];
const SECTIONS: [string, string][] = [["software", "Установленное ПО"], ["vulns", "Уязвимости"], ["protection", "Состояние защиты"]];
const FORMATS: [string, string][] = [["xlsx", "Excel (XLSX)"], ["csv", "CSV"], ["pdf", "PDF"], ["html", "HTML для руководства"]];
const PREVIEW_SHOWN = 60;
export const LEVELS: [string, string][] = [["critical", "Критические"], ["high", "Высокие"], ["medium", "Средние"], ["low", "Низкие"], ["info", "Информационные"]];
const SEV_NAMES = LEVELS.map((l) => l[0]);
/** Уровни по умолчанию: только критические; если отчёт открыт со страницы с фильтром критичности — уровни этого фильтра. */
export const defaultLevels = (base: Record<string, unknown>): string[] => {
  const fromPage = String(base.severity ?? "").split(",").map((x) => x.trim()).filter((x) => SEV_NAMES.includes(x));
  return fromPage.length ? fromPage : ["critical"];
};

/** Выбор уровней критичности отчёта: независимые галочки, «Выбрать все» и «Сбросить» (возврат к критическим). Общий для отчётов, данные которых имеют уровень критичности; на результаты в базе не влияет. */
export function SeverityLevels({ value, onChange, levels = LEVELS, def = ["critical"] }: { value: string[]; onChange: (v: string[]) => void; levels?: [string, string][]; def?: string[] }) {
  const toggle = (k: string, on: boolean) => onChange(on ? levels.map((l) => l[0]).filter((x) => value.includes(x) || x === k) : value.filter((x) => x !== k));
  return (
    <fieldset className="qr-levels" aria-label="Уровни критичности">
      <legend>Уровни критичности</legend>
      <div className="qr-levels-row">
        {levels.map(([k, l]) => <label key={k} className="check"><input type="checkbox" checked={value.includes(k)} disabled={value.length === 1 && value.includes(k)} onChange={(e) => toggle(k, e.target.checked)} /><span className={`dot-sev lv-${k}`} />{l}</label>)}
        <span className="qr-levels-btns"><button type="button" className="link-btn" onClick={() => onChange(levels.map((l) => l[0]))}>Выбрать все</button><button type="button" className="link-btn" onClick={() => onChange(def)}>Сбросить</button></span>
      </div>
      <p className="muted small">В отчёт, все его таблицы и показатели войдут только выбранные уровни. По умолчанию — критические. Общее число находок всех уровней показывается отдельно.</p>
    </fieldset>
  );
}

/** Затронутые компьютеры одной строкой (имена-ссылки на карточки); длинный список сворачивается. Список строится по строкам предпросмотра (до 1 000), полный — в файле. */
function AffectedHosts({ rows, total, expected, link, onClose }: { rows: Record<string, unknown>[]; total: number; expected: number | null; link: boolean; onClose: () => void }) {
  const [all, setAll] = useState(false);
  const hosts = useMemo(() => { const m = new Map<number, string>(); for (const r of rows) if (typeof r.host_id === "number" && typeof r.name === "string" && !m.has(r.host_id)) m.set(r.host_id, r.name); return [...m]; }, [rows]);
  if (!hosts.length) return null;
  const shown = all ? hosts : hosts.slice(0, 12);
  return (
    <div className="qr-hosts">
      <b>Затронутые компьютеры ({num(hosts.length)}):</b>{" "}
      {shown.map(([id, name], i) => <span key={id}>{link ? <Link to={`/hosts/${id}`} onClick={onClose} className="strong-link">{name}</Link> : name}{i < shown.length - 1 ? ", " : ""}</span>)}
      {hosts.length > shown.length && <> <button type="button" className="link-btn" onClick={() => setAll(true)}>Показать все</button></>}
      {all && hosts.length > 12 && <> <button type="button" className="link-btn" onClick={() => setAll(false)}>Свернуть</button></>}
      {rows.length < total && hosts.length !== expected && <span className="muted small"> · по первым {num(rows.length)} строкам предпросмотра; полный список — в файле</span>}
    </div>
  );
}

const BUILDABLE = ["quick_vulns", "quick_hosts", "quick_protection", "quick_events", "quick_extvulns", "quick_eol", "quick_devices", "quick_overview", "quick_hunt", "quick_bi"];
// выбор строк и фильтры страницы в шаблон не попадают: они берутся с той страницы, откуда открыт конструктор
const CONTEXT_KEYS = ["host_ids", "descr_ids", "cves", "vp_ids", "product_names", "vuln_keys", "product_keys", "event_ids", "host_id", "finding", "q", "zone", "group_contains", "threat", "product", "build", "problem"];

/** Конструктор отчёта: подробность (краткий — показатели и сводные таблицы, подробный — все записи, полные перечни CVE, устройств и пользователей), столбцы основной таблицы и шаблоны. */
function Builder({ kind, params, columnsAll, onChange, canSave }: { kind: string; params: Record<string, unknown>; columnsAll: { key: string; title: string }[]; onChange: (patch: Record<string, unknown>) => void; canSave: boolean }) {
  const detail = (params.detail as string) ?? "full";
  const picked = (params.columns as string[] | undefined) ?? [];
  const [tpls, setTpls] = useState<Template[]>([]); const [name, setName] = useState(""); const [saving, setSaving] = useState(false); const [note, setNote] = useState("");
  const load = useCallback(() => { api.reports.templates().then((r) => setTpls(r.items.filter((t) => t.kind === kind))).catch(() => setTpls([])); }, [kind]);
  useEffect(load, [load]);
  const apply = (id: string) => { const t = tpls.find((x) => x.id === id); if (t) { const keep = Object.fromEntries(Object.entries(t.params as Record<string, unknown>).filter(([k]) => !CONTEXT_KEYS.includes(k))); onChange({ detail: "full", columns: [], ...keep }); setNote(`Применён шаблон «${t.name}»`); } };
  const save = async () => {
    setSaving(true); setNote("");
    try { const settings = Object.fromEntries(Object.entries(params).filter(([k]) => !CONTEXT_KEYS.includes(k))); await api.reports.saveTemplate(name.trim(), kind as QuickKind, settings); setName(""); setNote("Шаблон сохранён: он хранит настройки отчёта, а фильтры берутся со страницы."); load(); }
    catch (e) { setNote((e as ApiError).message); } finally { setSaving(false); }
  };
  const toggle = (k: string) => { const cur = picked.length ? picked : columnsAll.map((c) => c.key); onChange({ columns: cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k] }); };
  return (
    <div className="qr-build">
      <div className="qr-build-row">
        <span className="qr-build-l" id="qr-detail">Подробность</span>
        <Segmented label="Подробность отчёта" value={detail} onChange={(v) => onChange({ detail: v })} options={[["full", "Подробный"], ["summary", "Краткий"]]} />
        <span className="muted small">{detail === "summary" ? "Показатели и сводные таблицы." : "Все соответствующие записи: полные списки CVE, устройств и пользователей, без сокращений «+N»."}</span>
      </div>
      {detail === "full" && columnsAll.length > 0 && (
        <details className="disclosure qr-cols">
          <summary>Столбцы основной таблицы{picked.length ? ` · выбрано ${picked.length} из ${columnsAll.length}` : ` · все ${columnsAll.length}`}</summary>
          <div className="qr-cols-grid">{columnsAll.map((c) => <label key={c.key} className="check"><input type="checkbox" checked={picked.length === 0 || picked.includes(c.key)} onChange={() => toggle(c.key)} />{c.title}</label>)}</div>
          {picked.length > 0 && <button type="button" className="link-btn" onClick={() => onChange({ columns: [] })}>Включить все столбцы</button>}
        </details>)}
      <div className="qr-build-row qr-tpl">
        <label className="inline">Шаблон
          <select value="" onChange={(e) => apply(e.target.value)} aria-label="Применить шаблон отчёта"><option value="">{tpls.length ? "Выбрать…" : "Нет сохранённых"}</option>{tpls.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>
        {canSave && <span className="qr-tpl-save"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="Название шаблона" aria-label="Название нового шаблона" maxLength={200} />
          <button type="button" className="btn mini" disabled={!name.trim() || saving} onClick={save}>{saving ? <span className="spin" /> : null}Сохранить шаблон</button></span>}
        {note && <span className="muted small" role="status">{note}</span>}
      </div>
    </div>
  );
}

/** Боковая панель быстрого отчёта: предпросмотр (число компьютеров, условия, замечания, первые строки) и выгрузка в Excel/HTML/CSV.
 *  Просмотр и выгрузка строятся на сервере из одного документа — числа совпадают. Дополнительные условия — в «Дополнительно». */
export function QuickReportPanel({ kind, params: base, title, lede, options = { scope: true }, activityDays, canReport, sourceIds = [], onClose }: {
  kind: QuickKind | "version_audit"; params: Record<string, unknown>; title: string; lede?: string; options?: QuickScopeOpts; activityDays: number; canReport: boolean; sourceIds?: string[]; onClose: () => void;
}) {
  const [extra, setExtra] = useState<Record<string, unknown>>(() => (options.levels ? { levels: defaultLevels(base) } : options.hunt ? { columns: ["host", "user", "zone", "ip", "product", "version", "status_ru", "evidence"] } : {}));
  const params = useMemo(() => ({ ...base, ...extra }), [base, extra]);
  const key = JSON.stringify(params);
  const [data, setData] = useState<QuickPreview | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string>("");
  const [jobId, setJobId] = useState<{ key: string; id: string } | null>(null);
  const [msg, setMsg] = useState("");
  const seq = useRef(0);
  useEffect(() => {
    const n = ++seq.current; setData(null); setErr("");
    const t = window.setTimeout(() => {
      api.quick.preview(kind, params, false, sourceIds).then((r) => { if (n === seq.current) setData(r); }).catch((e) => { if (n === seq.current) setErr((e as ApiError).message); });
    }, 150);
    return () => window.clearTimeout(t);
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps

  const download = useCallback((id: string, fmtKey: string) => {
    const a = document.createElement("a"); a.href = api.reports.downloadUrl(id, fmtKey as "xlsx"); a.download = ""; document.body.appendChild(a); a.click(); a.remove();
  }, []);
  // Один отчёт формирует все три файла, поэтому после первого скачивания остальные форматы берутся без повторного чтения KSC.
  const make = async (fmtKey: string) => {
    setMsg(""); setBusy(fmtKey);
    try {
      let id = jobId && jobId.key === key ? jobId.id : "";
      if (!id) {
        let j = await api.reports.create(kind, "", params, sourceIds);
        id = j.id; setJobId({ key, id });
        while (j.status === "queued" || j.status === "running") {
          setMsg(j.status === "queued" ? "Отчёт в очереди…" : `Формируется: ${j.progress ?? "чтение данных"}`);
          await new Promise((r) => setTimeout(r, 1000)); j = await api.reports.get(id);
        }
        if (j.status !== "done") { setJobId(null); throw new Error(j.error || "Отчёт не сформирован"); }
      }
      download(id, fmtKey); setMsg("Файл сформирован и скачан.");
    } catch (e) { setMsg(""); setErr((e as Error).message); } finally { setBusy(""); }
  };

  const doc = data?.doc ?? null;
  const hosts = doc?.metrics.find((m) => m.key === "hosts");
  const cols = (data?.columns ?? []).slice(0, 7);
  const showScope = options.scope !== false && !options.zone;
  const zoneCats = (params.categories as string[] | undefined) ?? [];
  const days = Number(params.active_days ?? activityDays);
  return (
    <Modal side wide title={title} lede={lede} onClose={onClose}
      footer={canReport ? <div className="qr-actions">
        {FORMATS.map(([k, l], i) => <button key={k} className={`btn ${i === 0 ? "primary" : ""}`} disabled={!!busy || !data || !!data.unsupported || data.total === 0} onClick={() => make(k)}>
          {busy === k ? <span className="spin" /> : <Icon name="download" />}{l}</button>)}
        {jobId && jobId.key === key && <Link className="btn ghost" to={`/reports/${jobId.id}`} onClick={onClose}>Открыть в «Отчётах»</Link>}
      </div> : <span className="muted small">Выгрузка доступна аналитику и администратору.</span>}>
      <div className="qr">
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        {msg && <div className="alert info" role="status"><span className="spin accent" /><div className="alert-body">{msg}</div></div>}
        {!data && !err && <div className="qr-loading" role="status"><span className="spin accent" />Считаем затронутые компьютеры…</div>}
        {data?.unsupported && <div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет нужных объектов KSC ({data.unsupported.join(", ")}): отчёт недоступен.</div></div>}
        {options.hunt && <fieldset className="qr-sections"><legend>Результаты в отчёте</legend>
          {([["confirmed", "Подтверждено"], ["probable", "Вероятно"], ["needs_check", "Требует проверки"]] as [string, string][]).map(([k, l]) => {
            const cur = (params.statuses as string[] | undefined) ?? ["confirmed", "probable"];
            return <label key={k} className="check"><input type="checkbox" checked={cur.includes(k)} disabled={cur.length === 1 && cur.includes(k)} onChange={(e) => setExtra({ ...extra, statuses: e.target.checked ? [...cur, k] : cur.filter((x) => x !== k) })} />{l}</label>; })}
          <label className="check"><input type="checkbox" checked={!!params.coverage} onChange={(e) => setExtra({ ...extra, coverage: e.target.checked })} />Добавить журнал охвата (все проверенные адреса, включая не затронутые)</label></fieldset>}
        {options.bi && <label className="field">Вид отчёта<select value={String(params.view ?? "owners")} onChange={(e) => setExtra({ ...extra, view: e.target.value })}>
          {BI_VIEWS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>}
        {options.levels && <SeverityLevels value={(params.levels as string[] | undefined) ?? ["critical"]} onChange={(v) => setExtra({ ...extra, levels: v })} />}
        {doc && (<>
          <div className="qr-hero">
            <span className="qr-big">{hosts ? num(Number(hosts.value)) : num(data!.total)}</span>
            <span className="qr-cap">{hosts ? (kind === "quick_eol" ? plural(Number(hosts.value), "устройство с проблемой поддержки", "устройства с проблемой поддержки", "устройств с проблемой поддержки") : kind === "quick_vulns" || kind === "quick_extvulns" || kind === "version_audit" ? plural(Number(hosts.value), "затронутый компьютер", "затронутых компьютера", "затронутых компьютеров") : kind === "quick_devices" ? plural(Number(hosts.value), "устройство", "устройства", "устройств") : kind === "quick_overview" ? plural(Number(hosts.value), "компьютер в списке", "компьютера в списке", "компьютеров в списке") : plural(Number(hosts.value), "компьютер", "компьютера", "компьютеров")) : plural(data!.total, "строка", "строки", "строк")}
              {hosts?.hint && <span className="muted small"> · {hosts.hint}</span>}</span>
          </div>
          {BUILDABLE.includes(kind) && <Builder kind={kind} params={params} columnsAll={doc.columns_all ?? []} onChange={(patch) => setExtra({ ...extra, ...patch })} canSave={canReport} />}
          {data && (kind === "quick_extvulns" || kind === "quick_vulns" || kind === "version_audit" || kind === "quick_eol") && <AffectedHosts rows={data.items} total={data.total} expected={hosts ? Number(hosts.value) : null} link={sourceIds.length <= 1 && kind !== "quick_eol"} onClose={onClose} />}
          <dl className="qr-cond">{doc.conditions.map((c) => <div key={c.label}><dt>{c.label}</dt><dd>{c.text}</dd></div>)}</dl>
          <div className="qr-metrics">{doc.metrics.filter((m) => m !== hosts).map((m) => (
            <div key={m.key} className="qr-metric" title={m.hint}><b className={m.tone === "danger" ? "bad-text" : ""}>{typeof m.value === "number" ? num(m.value) : m.value}</b><span>{m.label}</span></div>))}</div>
          {doc.severity && doc.severity.levels.some((l) => l.value > 0) && (
            <div className="qr-sev" aria-label={doc.severity.title}>
              <div className="qr-sev-bar">{doc.severity.levels.filter((l) => l.value > 0).map((l) => <span key={l.key} className={`qs-${l.key}`} style={{ flexGrow: l.value }} title={`${l.label}: ${l.value} (${l.hint})`} />)}</div>
              <ul className="qr-sev-legend">{doc.severity.levels.map((l) => <li key={l.key} className={l.value ? "" : "zero"}><span className={`dot-sev qs-${l.key}`} />{l.label}: <b>{num(l.value)}</b></li>)}</ul>
              <p className="muted small">{doc.severity.title}</p>
            </div>)}
          {doc.notes.length > 0 && <div className="alert warn qr-notes"><Icon name="info" /><div className="alert-body"><ul>{doc.notes.map((n) => <li key={n}>{n}</li>)}</ul></div></div>}
        </>)}
        {data && !data.unsupported && data.total === 0 && <div className="alert info"><Icon name="info" /><div className="alert-body">По этим условиям данных нет. Измените условия в «Дополнительно» или выбор в таблице.</div></div>}
        {data && data.total > 0 && (<>
          <h3 className="qr-h">Предпросмотр{data.total > PREVIEW_SHOWN ? `: первые ${PREVIEW_SHOWN} из ${num(data.total)}` : `: ${num(data.total)}`}</h3>
          <div className="table-scroll"><table className="table compact">
            <thead><tr>{cols.map((c) => <th key={c.key} className={c.type === "num" ? "num" : ""}>{c.title}</th>)}</tr></thead>
            <tbody>{data.items.slice(0, PREVIEW_SHOWN).map((r, i) => <tr key={i}>{cols.map((c) => <td key={c.key} className={c.type === "num" ? "num" : ""}>{cell(c, r[c.key])}</td>)}</tr>)}</tbody>
          </table></div>
          <p className="muted small">В файле — полный набор столбцов и дополнительные листы со сводкой.</p>
        </>)}
        <details className="disclosure qr-more">
          <summary>Дополнительно</summary>
          <div className="qr-fields">
            {options.period && <label className="field">Период<select value={String(params.days ?? 7)} onChange={(e) => setExtra({ ...extra, days: Number(e.target.value) })}>
              <option value="1">Сутки</option><option value="7">7 суток</option><option value="30">30 суток</option></select></label>}
            {showScope && <>
              <label className="field">Связь с KSC не старше, суток<input type="number" min={1} max={3650} value={days} disabled={!!params.include_inactive}
                onChange={(e) => setExtra({ ...extra, active_days: Math.max(1, Number(e.target.value) || activityDays) })} /></label>
              <label className="check"><input type="checkbox" checked={!!params.include_inactive} onChange={(e) => setExtra({ ...extra, include_inactive: e.target.checked })} />Включить давно не подключавшиеся</label>
              <label className="check"><input type="checkbox" checked={!!params.online_only} onChange={(e) => setExtra({ ...extra, online_only: e.target.checked })} />Только в сети сейчас (флаг KSC «видимо в сети»)</label>
              <p className="muted small">«Связь за {days} сут» и «в сети сейчас» — разные условия: устройство могло выйти на связь вчера и быть выключенным сейчас.</p>
            </>}
            {options.zone && <>
              <fieldset className="qr-sections"><legend>Что включить в отчёт</legend>{ZONE_CATEGORIES.map(([k, l]) => (
                <label key={k} className="check"><input type="checkbox" checked={zoneCats.includes(k)} disabled={zoneCats.length === 1 && zoneCats.includes(k)}
                  onChange={(e) => setExtra({ ...extra, categories: e.target.checked ? [...zoneCats, k] : zoneCats.filter((x) => x !== k) })} />{l}</label>))}</fieldset>
              <div className="field">Подробность<Segmented label="Подробность отчёта" value={String(params.level ?? "management")} onChange={(v) => setExtra({ ...extra, level: v })} options={[["management", "Для руководства"], ["technical", "Для администраторов"]]} /></div>
              <label className="field">Критичность уязвимостей<select value={String(params.severity ?? "")} onChange={(e) => setExtra({ ...extra, severity: e.target.value })}><option value="">Все уровни</option><option value="high">Высокие и критические</option><option value="critical">Только критические</option></select></label>
              <label className="check"><input type="checkbox" checked={!!params.include_inactive} onChange={(e) => setExtra({ ...extra, include_inactive: e.target.checked })} />Включить давно не подключавшиеся к KSC</label>
              <label className="check"><input type="checkbox" checked={!!params.online_only} onChange={(e) => setExtra({ ...extra, online_only: e.target.checked })} />Только в сети сейчас</label>
              <label className="check"><input type="checkbox" checked={!!params.refresh_data} onChange={(e) => setExtra({ ...extra, refresh_data: e.target.checked })} />Обновить данные зоны из KSC перед формированием (дольше; иначе — подготовленные, дата среза указана в отчёте)</label>
              <label className="check"><input type="checkbox" checked={!!params.show_excluded} onChange={(e) => setExtra({ ...extra, show_excluded: e.target.checked })} />Перечислить исключённые обнаружения с обоснованиями</label>
              <p className="muted small">Ложные срабатывания не входят в показатели; их число и правила исключения указываются в конце отчёта. Принятые риски учитываются отдельно.</p>
            </>}
            {options.eol && <>
              <fieldset className="qr-sections"><legend>Состояние поддержки</legend>{EOL_STATUSES.map(([k, l]) => {
                const cur = (params.statuses as string[] | undefined) ?? ["eol", "extended", "upcoming"];
                return <label key={k} className="check"><input type="checkbox" checked={cur.includes(k)} disabled={cur.length === 1 && cur.includes(k)}
                  onChange={(e) => setExtra({ ...extra, statuses: e.target.checked ? [...cur, k] : cur.filter((x) => x !== k) })} />{l}</label>; })}</fieldset>
              <fieldset className="qr-sections"><legend>Что включить</legend>{([["app", "Программы"], ["os", "Операционные системы"]] as [string, string][]).map(([k, l]) => {
                const cur = (params.kinds as string[] | undefined) ?? ["app", "os"];
                return <label key={k} className="check"><input type="checkbox" checked={cur.includes(k)} disabled={cur.length === 1 && cur.includes(k)}
                  onChange={(e) => setExtra({ ...extra, kinds: e.target.checked ? [...cur, k] : cur.filter((x) => x !== k) })} />{l}</label>; })}</fieldset>
              <label className="field">Критичность<select value={String(params.severity ?? "")} onChange={(e) => setExtra({ ...extra, severity: e.target.value })}>
                <option value="">Все уровни</option><option value="critical">Только критические</option><option value="high">Только высокие</option><option value="warning">Только предупреждения</option></select></label>
              <label className="check"><input type="checkbox" checked={params.devices !== false} onChange={(e) => setExtra({ ...extra, devices: e.target.checked })} />Таблица устройств (полный список, без сокращений)</label>
              <label className="check"><input type="checkbox" checked={!!params.include_inactive} onChange={(e) => setExtra({ ...extra, include_inactive: e.target.checked })} />Включить давно не подключавшиеся к KSC</label>
            </>}
            {options.zoneFilter && <ZoneField value={String(params.zone ?? "")} onChange={(v) => setExtra({ ...extra, zone: v })} />}
            {options.sections && <fieldset className="qr-sections"><legend>Что включить</legend>{SECTIONS.map(([k, l]) => {
              const cur = (params.sections as string[] | undefined) ?? SECTIONS.map(([x]) => x);
              return <label key={k} className="check"><input type="checkbox" checked={cur.includes(k)} disabled={cur.length === 1 && cur.includes(k)}
                onChange={(e) => setExtra({ ...extra, sections: e.target.checked ? [...cur, k] : cur.filter((x) => x !== k) })} />{l}</label>; })}</fieldset>}
            {options.ext && <>
              <fieldset className="qr-sections"><legend>Результат сопоставления</legend>{EXT_STATUSES.map(([k, l]) => {
                const cur = (params.statuses as string[] | undefined) ?? ["confirmed", "potential", "clarify", "insufficient"];
                return <label key={k} className="check"><input type="checkbox" checked={cur.includes(k)} disabled={cur.length === 1 && cur.includes(k)}
                  onChange={(e) => setExtra({ ...extra, statuses: e.target.checked ? [...cur, k] : cur.filter((x) => x !== k) })} />{l}</label>; })}</fieldset>
              <label className="field">Опасность не ниже<select value={String(params.min_severity ?? "")} onChange={(e) => setExtra({ ...extra, min_severity: e.target.value })}>
                <option value="">Любая</option><option value="critical">Критическая</option><option value="high">Высокая</option><option value="medium">Средняя</option></select></label>
              <label className="check"><input type="checkbox" checked={!!params.exploited_only} onChange={(e) => setExtra({ ...extra, exploited_only: e.target.checked })} />Только уязвимости из каталога CISA KEV</label>
            </>}
            {options.severity && <label className="field">Опасность<select value={String(params.severity ?? "")} onChange={(e) => setExtra({ ...extra, severity: e.target.value })}>
              <option value="">Все уровни</option><option value="critical">Только критические</option><option value="high">Только высокие</option><option value="warning">Только предупреждения</option></select></label>}
            {options.patchable && <label className="check"><input type="checkbox" checked={!!params.patchable} onChange={(e) => setExtra({ ...extra, patchable: e.target.checked })} />Только с доступным исправлением</label>}
          </div>
        </details>
        {data && data.html_row_limit && data.doc && data.doc.tables.some((t) => t.n > data.html_row_limit!) && (
          <div className="alert warn"><Icon name="info" /><div className="alert-body">В HTML войдут только первые {num(data.html_row_limit)} строк каждой таблицы (сокращённая выборка), показатели в сводке — по полному результату. Полный список — в Excel и CSV.</div></div>)}
        {data?.fetched_at && <p className="muted small">Данные KSC получены {fmt(data.fetched_at)}.</p>}
      </div>
    </Modal>
  );
}
