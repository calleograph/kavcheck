import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type QuickCol, type QuickKind, type QuickPreview } from "../api";
import { fmt, num, plural } from "../util";
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
  return c.type === "mono" ? <span className="mono small nowrap">{v}</span> : <>{v}</>;
}

export type QuickScopeOpts = { period?: boolean; severity?: boolean; patchable?: boolean; scope?: boolean; sections?: boolean; ext?: boolean; zone?: boolean; zoneFilter?: boolean };
const EXT_STATUSES: [string, string][] = [["confirmed", "Подтверждено источником"], ["potential", "Потенциально затронуто"], ["clarify", "Требуется уточнение"], ["insufficient", "Данных недостаточно"], ["fixed", "Исправлено (показать отдельно)"]];
const SECTIONS: [string, string][] = [["software", "Установленное ПО"], ["vulns", "Уязвимости"], ["protection", "Состояние защиты"]];
const FORMATS: [string, string][] = [["xlsx", "Excel (XLSX)"], ["html", "HTML для руководства"], ["csv", "CSV"]];
const PREVIEW_SHOWN = 60;

/** Боковая панель быстрого отчёта: предпросмотр (число компьютеров, условия, замечания, первые строки) и выгрузка в Excel/HTML/CSV.
 *  Просмотр и выгрузка строятся на сервере из одного документа — числа совпадают. Дополнительные условия — в «Дополнительно». */
export function QuickReportPanel({ kind, params: base, title, lede, options = { scope: true }, activityDays, canReport, sourceIds = [], onClose }: {
  kind: QuickKind | "version_audit"; params: Record<string, unknown>; title: string; lede?: string; options?: QuickScopeOpts; activityDays: number; canReport: boolean; sourceIds?: string[]; onClose: () => void;
}) {
  const [extra, setExtra] = useState<Record<string, unknown>>({});
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
        {doc && (<>
          <div className="qr-hero">
            <span className="qr-big">{hosts ? num(Number(hosts.value)) : num(data!.total)}</span>
            <span className="qr-cap">{hosts ? (kind === "quick_vulns" || kind === "quick_extvulns" || kind === "version_audit" ? plural(Number(hosts.value), "затронутый компьютер", "затронутых компьютера", "затронутых компьютеров") : plural(Number(hosts.value), "компьютер", "компьютера", "компьютеров")) : plural(data!.total, "строка", "строки", "строк")}
              {hosts?.hint && <span className="muted small"> · {hosts.hint}</span>}</span>
          </div>
          <dl className="qr-cond">{doc.conditions.map((c) => <div key={c.label}><dt>{c.label}</dt><dd>{c.text}</dd></div>)}</dl>
          <div className="qr-metrics">{doc.metrics.filter((m) => m.key !== "hosts").map((m) => (
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
