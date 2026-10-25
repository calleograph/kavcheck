import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./Icons";
import { SkelRows } from "./ui";
import { api, type ApiError, type VdbStatus, type VdbVulnRow } from "../api";
import { num } from "../util";

const SEV_CLS: Record<string, string> = { critical: "crit", high: "high", medium: "med", low: "low", none: "zero", "": "na" };
/** Диапазоны CVSS для фильтра: границы включены; «Нет данных» — уязвимости без достоверной оценки. */
export const CVSS_RANGES: { id: string; label: string; min?: number; max?: number; none?: boolean }[] = [
  { id: "", label: "Любая" }, { id: "critical", label: "Критическая 9.0–10.0", min: 9, max: 10 }, { id: "high", label: "Высокая 7.0–8.9", min: 7, max: 8.9 },
  { id: "medium", label: "Средняя 4.0–6.9", min: 4, max: 6.9 }, { id: "low", label: "Низкая 0.1–3.9", min: 0.1, max: 3.9 }, { id: "none", label: "Нет данных", none: true }];
export const cvssText = (v: { score: number | null; score_version?: string }) => (v.score == null ? "Нет данных" : `${v.score.toFixed(1)}${v.score_version ? ` (CVSS ${v.score_version})` : ""}`);
export const STATUS_TONE: Record<VdbStatus, string> = { confirmed: "err", potential: "warn", clarify: "accent", insufficient: "", fixed: "ok" };

/** Заметная отметка: эксплуатация уязвимости подтверждена каталогом CISA KEV. */
export function Kev({ title = "Эксплуатация подтверждена по каталогу CISA KEV" }: { title?: string }) {
  return <span className="badge kev" title={title}>эксплуатируется</span>;
}
/** Числовая оценка CVSS 0.0–10.0 и версия методики; нет достоверной оценки — «Нет данных» (ноль не подставляется). */
export function CvssCell({ v }: { v: { score: number | null; score_version: string; score_source?: string; severity: string } }) {
  if (v.score == null) return <span className="cvss na" title="Достоверной оценки CVSS в источниках нет">Нет данных</span>;
  return <span className={`cvss ${SEV_CLS[v.severity] ?? "na"}`} title={`CVSS ${v.score_version || "?"}${v.score_source ? `, источник: ${v.score_source.toUpperCase()}` : ""}`}><b>{v.score.toFixed(1)}</b>{v.score_version && <i>v{v.score_version}</i>}</span>;
}
/** Уровень критичности. Если числовой оценки нет, но источник назвал уровень, он показывается с пометкой «по данным источника». */
export function LevelBadge({ v }: { v: { severity: string; severity_ru: string; severity_basis?: string } }) {
  if (!v.severity) return <span className="muted small" title="Ни числовой оценки CVSS, ни уровня источники не назвали">—</span>;
  return <span className={`sev ${SEV_CLS[v.severity] ?? "na"}`} title={v.severity_basis === "source" ? "Уровень назван источником, числовой оценки CVSS нет" : undefined}>{v.severity_ru}{v.severity_basis === "source" && <span className="mark">*</span>}</span>;
}
export function SevBadge({ v }: { v: { severity: string; severity_ru: string; score?: number | null } }) {
  return <span className={`sev ${SEV_CLS[v.severity] ?? "warn"}`}>{v.severity_ru}{v.score != null && <b className="score">{v.score.toFixed(1)}</b>}</span>;
}
export function StatusBadge({ s, label }: { s: VdbStatus; label: string }) {
  return <span className={`badge wrap ${STATUS_TONE[s]}`}>{label}</span>;
}

export type VdbCount = { total: number; kev: number; critical: number; confirmed: number };
/** Число известных уязвимостей (внешние базы) для продуктов каталога: догружается пачкой по видимым продуктам и не блокирует таблицу. */
export function useVdbCounts(keys: string[], enabled: boolean): Record<string, VdbCount> {
  const [c, setC] = useState<Record<string, VdbCount>>({});
  const sig = keys.join(",");
  useEffect(() => {
    if (!enabled || !keys.length) return;
    const need = keys.filter((k) => !(k in c));
    if (!need.length) return;
    let live = true;
    // ключи пакетов длинные: порциями по 40, чтобы адрес запроса не превышал предел сервера
    for (let i = 0; i < need.length; i += 40) api.vdb.counts(need.slice(i, i + 40)).then((r) => { if (live) setC((p) => ({ ...p, ...r.items })); }).catch(() => undefined);
    return () => { live = false; };
  }, [sig, enabled]); // eslint-disable-line react-hooks/exhaustive-deps
  return c;
}
export function VdbCountBadge({ c, productKey }: { c: VdbCount | undefined; productKey: string }) {
  if (!c || !c.total) return <span className="muted small">—</span>;
  return <Link to={`/software/p/${encodeURIComponent(productKey)}#vdb`} className="vdb-count" title={`Известных уязвимостей: ${c.total}; эксплуатируются: ${c.kev}; критических: ${c.critical}`}>
    <span className={`badge ${c.kev || c.critical ? "err" : "warn"}`}>{num(c.total)}</span>{c.kev > 0 && <span className="badge kev">KEV {c.kev}</span>}</Link>;
}

/** Известные уязвимости продукта (внешние базы) для установленных версий: карточка в разделе «Программы». Не путать с уязвимостями, подтверждёнными KSC. */
export function ProductVulns({ productKey, canReport, onCheck }: { productKey: string; canReport: boolean; onCheck: () => void }) {
  const [d, setD] = useState<{ items: (VdbVulnRow & { versions: string[] })[]; total: number } | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { setD(null); setErr(""); api.vdb.product(productKey).then(setD).catch((e) => setErr((e as ApiError).message)); }, [productKey]);
  return (
    <div className="card flush" id="vdb">
      <div className="card-head"><h2>Известные уязвимости (внешние базы)</h2><span className="muted small">NVD, CISA KEV, OSV, БДУ — потенциальные, не подтверждённые KSC</span><div className="spacer" />
        {canReport && d && d.total > 0 && <button className="btn mini primary" onClick={onCheck}><Icon name="target" size={15} />Проверить инфраструктуру ({d.total})</button>}</div>
      {err ? <div className="alert error pad"><Icon name="alert" /><div className="alert-body">{err}</div></div> : !d ? <div className="pad"><SkelRows rows={3} cols={3} /></div> : !d.total ? (
        <p className="muted small pad">Для установленных версий продукта уязвимости во внешних базах не найдены (или базы ещё не загружены: Администрирование → База уязвимостей).</p>) : (
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Уязвимость</th><th>CVSS</th><th>Критичность</th><th>Результат</th><th>Версии на компьютерах</th></tr></thead>
          <tbody>{d.items.map((v) => <tr key={v.key}><td><Link className="mono strong-link" to={`/vdb?tab=search&q=${encodeURIComponent(v.key)}&v=${encodeURIComponent(v.key)}`}>{v.key}</Link><span className="sub">{v.title}</span></td>
            <td className="nowrap"><CvssCell v={v} /></td><td className="nowrap"><LevelBadge v={v} />{v.exploited && <> <Kev /></>}</td><td>{v.finding && <StatusBadge s={v.finding.status} label={v.finding.status_ru} />}</td><td className="mono small">{v.versions.slice(0, 4).join(", ")}{v.versions.length > 4 ? "…" : ""}</td></tr>)}</tbody></table></div>)}
    </div>
  );
}
