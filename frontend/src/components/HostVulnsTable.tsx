import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { HostVulnRow, HostVulnsAll } from "../api";
import { maskMatcher } from "../mask";
import { CompactList } from "./CompactList";
import { Icon } from "./Icons";
import { Kev } from "./VdbBits";
import { Empty, MaskHint, Segmented } from "./ui";
import { fmtDate, num } from "../util";

type V = "" | "confirmed_ksc" | "other";
const SEV_CLS: Record<string, string> = { critical: "crit", high: "high", warning: "warn" };
const DB: Record<string, string> = { nvd: "NVD", kev: "CISA KEV", osv: "OSV", bdu: "БДУ ФСТЭК" };

/** Единый список уязвимостей компьютера: данные KSC и внешних баз в одной таблице. Подтверждённое KSC и предварительное совпадение по версии различаются явно. */
export function HostVulnsTable({ data }: { data: HostVulnsAll }) {
  const [q, setQ] = useState(""); const [v, setV] = useState<V>(""); const [limit, setLimit] = useState(100);
  const rows = useMemo(() => { const hit = maskMatcher(q); return data.items.filter((r) => (v === "" || (v === "confirmed_ksc" ? r.verdict === "confirmed_ksc" : r.verdict !== "confirmed_ksc")) && (!hit || hit(...r.keys, r.kla_id, r.product, r.title))); }, [data.items, q, v]);
  const c = data.counts;
  const other = c.confirmed_ext + c.potential;
  return (
    <>
      {!data.external_checked && <div className="alert info calc-progress"><span className="spin sm" /><div className="alert-body">Показаны данные KSC. Идёт проверка установленного ПО по внешним базам (NVD, CISA KEV, OSV, БДУ) — результаты появятся здесь автоматически, это может занять до минуты.</div></div>}
      {data.notes.map((n) => <div key={n} className="alert warn"><Icon name="alert" /><div className="alert-body">{n}</div></div>)}
      <div className="alert info"><Icon name="info" /><div className="alert-body">
        {data.external_checked ? <>Все найденные уязвимости независимо от источника: <b>{num(c.confirmed_ksc)}</b> подтверждено Kaspersky Security Center, <b>{num(other)}</b> найдено только по внешним базам (NVD, CISA KEV, OSV, БДУ ФСТЭК) —
          это предварительное совпадение установленной версии с описанием уязвимости, а не доказанный факт. Уязвимость, найденная обоими источниками, показана одной строкой.</>
          : <>Подтверждено Kaspersky Security Center: <b>{num(c.confirmed_ksc)}</b>. Отсутствие других записей пока ничего не значит: проверка по внешним базам ещё не завершена.</>}</div></div>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE, KLA или программа" aria-label="Поиск уязвимости" /><MaskHint /></div>
        <Segmented<V> label="Достоверность" value={v} onChange={setV} options={[["", `Все · ${c.total}`], ["confirmed_ksc", `Подтверждены KSC · ${c.confirmed_ksc}`], ["other", `Только внешние базы · ${other}`]]} />
      </div>
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Критичность</th><th>Уязвимость</th><th>Программа и версия</th><th>Источник обнаружения</th><th>Статус проверки</th><th className="hide-sm">Описание</th></tr></thead>
        <tbody>
          {rows.slice(0, limit).map((r) => <Row key={r.id} r={r} />)}
          {!rows.length && <tr><td colSpan={6}><Empty icon={data.items.length ? "search" : "checkCircle"} title={data.items.length ? "Ничего не найдено" : "Уязвимостей по доступным источникам не найдено"}>
            {data.items.length ? "Измените поиск или фильтр достоверности." : data.notes.length ? "Часть источников недоступна (см. замечания выше): это не означает, что уязвимостей нет." : "Ни KSC, ни внешние базы для установленного ПО этого компьютера уязвимостей не нашли (если базы загружены и каталог построен)."}</Empty></td></tr>}
        </tbody></table></div>
      {rows.length > limit && <p><button type="button" className="btn mini" onClick={() => setLimit(limit + 200)}>Показать ещё ({num(Math.min(200, rows.length - limit))} из {num(rows.length - limit)})</button></p>}
      {data.items.length >= 1000 && <p className="muted small">Показаны первые 1 000 уязвимостей.</p>}
    </>
  );
}

function Row({ r }: { r: HostVulnRow }) {
  const ext = r.external; const ksc = r.ksc;
  const vdbKey = ext?.key ?? r.keys.find((k) => k.startsWith("CVE-")) ?? "";
  return (
    <tr>
      <td className="nowrap"><span className={`sev ${SEV_CLS[r.severity] ?? "warn"}`}>{r.severity_ru}</span>{r.exploited && <> <Kev /></>}</td>
      <td><CompactList items={r.keys} label="идентификаторы" sep=" " render={(k) => (/^(CVE|BDU|GHSA)/i.test(k) ? <Link className="mono strong-link nowrap" to={`/vdb?tab=search&q=${encodeURIComponent(k)}&v=${encodeURIComponent(k)}`}>{k}</Link> : <span className="mono">{k}</span>)} />
        {r.kla_id && r.keys[0] !== r.kla_id && <span className="sub mono small">{r.kla_id}</span>}{r.title && <span className="sub clamp2" title={r.title}>{r.title}</span>}</td>
      <td>{r.product || "—"}<span className="sub mono">{r.version}</span></td>
      <td>{r.detected_by.includes("ksc") && <span className="chip tiny" title="Найдено Kaspersky Security Center">KSC</span>}
        {r.detected_by.includes("external") && <span className="chip tiny" title="Совпадение с внешней базой уязвимостей">{ext?.databases.length ? ext.databases.map((d) => DB[d] ?? d).join(", ") : "Внешняя база"}</span>}</td>
      <td><span className={`badge ${r.verdict === "confirmed_ksc" ? "err" : r.verdict === "confirmed_ext" ? "warn" : "accent"}`}>{r.verdict_ru}</span>
        {ext && r.verdict === "confirmed_ksc" && <span className="sub small">внешняя база: {ext.status_ru}</span>}
        {r.verdict !== "confirmed_ksc" && <span className="sub small clamp2" title={r.basis}>{r.basis}</span>}{ksc?.detected && <span className="sub small">обнаружено {fmtDate(ksc.detected)}</span>}</td>
      <td className="small hide-sm">{ksc?.url && <a href={ksc.url} target="_blank" rel="noopener noreferrer" className="block">Описание KSC<Icon name="external" size={12} className="ext" /></a>}
        {vdbKey && <Link className="block" to={`/vdb?tab=search&q=${encodeURIComponent(vdbKey)}&v=${encodeURIComponent(vdbKey)}`}>В базе уязвимостей</Link>}
        {ksc?.patches_available && <span className="badge ok">есть исправление</span>}</td>
    </tr>
  );
}
