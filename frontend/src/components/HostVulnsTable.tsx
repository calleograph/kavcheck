import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type HostVulnGroup, type HostVulnRow, type HostVulnsAll } from "../api";
import { maskMatcher } from "../mask";
import { CompactList } from "./CompactList";
import { Icon } from "./Icons";
import { Kev } from "./VdbBits";
import { Empty, MaskHint, Segmented } from "./ui";
import { fmtDate, num } from "../util";

type V = "" | "confirmed_ksc" | "other";
const SEV_CLS: Record<string, string> = { critical: "crit", high: "high", warning: "warn" };
const DB: Record<string, string> = { nvd: "NVD", kev: "CISA KEV", osv: "OSV", bdu: "БДУ ФСТЭК" };
const EOL_TONE: Record<string, string> = { eol: "err", extended: "warn", upcoming: "warn" };
const idLink = (k: string) => (/^(CVE|BDU|GHSA)/i.test(k) ? <Link className="mono strong-link nowrap" to={`/vdb?tab=search&q=${encodeURIComponent(k)}&v=${encodeURIComponent(k)}`}>{k}</Link> : <span className="mono nowrap">{k}</span>);

/** Уязвимости компьютера по установленным продуктам: одна строка на продукт и версию (критичность, число уникальных CVE, KEV, EOL, первые три идентификатора). Полный список раскрывается по требованию и подгружается с сервера страницами.
 *  Это только представление: счётчики считаются по всем уязвимостям, выгрузки и отчёты не сокращаются. */
export function HostVulnsTable({ data, hostId, onMore }: { data: HostVulnsAll; hostId: number; onMore?: (offset: number) => Promise<HostVulnGroup[]> }) {
  const [q, setQ] = useState(""); const [v, setV] = useState<V>(""); const [extra, setExtra] = useState<HostVulnGroup[]>([]); const [more, setMore] = useState(false);
  useEffect(() => { setExtra([]); }, [data.fetched_at]);
  const all = useMemo(() => [...data.groups, ...extra], [data.groups, extra]);
  const rows = useMemo(() => { const hit = maskMatcher(q); return all.filter((g) => (v === "" || (v === "confirmed_ksc" ? g.confirmed_ksc > 0 : g.external_only > 0)) && (!hit || hit(g.product, g.version, ...g.sample))); }, [all, q, v]);
  const c = data.counts;
  const other = c.confirmed_ext + c.potential;
  const left = data.groups_total - all.length;
  return (
    <>
      {!data.external_checked && <div className="alert info calc-progress"><span className="spin sm" /><div className="alert-body">Показаны данные KSC. Идёт проверка установленного ПО по внешним базам (NVD, CISA KEV, OSV, БДУ) — результаты появятся здесь автоматически.</div></div>}
      {data.notes.map((n) => <div key={n} className="alert warn"><Icon name="alert" /><div className="alert-body">{n}</div></div>)}
      <div className="alert info"><Icon name="info" /><div className="alert-body">
        {data.external_checked ? <>Продуктов с уязвимостями: <b>{num(data.groups_total)}</b>; уязвимостей всего <b>{num(c.total)}</b>: <b>{num(c.confirmed_ksc)}</b> подтверждено Kaspersky Security Center, <b>{num(other)}</b> найдено только по внешним базам (NVD, CISA KEV, OSV, БДУ ФСТЭК) —
          это предварительное совпадение установленной версии с описанием уязвимости, а не доказанный факт. Уязвимость, найденная обоими источниками, показана одной строкой. Нажмите на продукт, чтобы увидеть полный список.</>
          : <>Подтверждено Kaspersky Security Center: <b>{num(c.confirmed_ksc)}</b>. Отсутствие других записей пока ничего не значит: проверка по внешним базам ещё не завершена.</>}</div></div>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Программа или идентификатор в списке" aria-label="Поиск продукта" /><MaskHint /></div>
        <Segmented<V> label="Достоверность" value={v} onChange={setV} options={[["", `Все · ${data.groups_total}`], ["confirmed_ksc", "Подтверждены KSC"], ["other", "Только внешние базы"]]} />
      </div>
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Программа и версия</th><th>Критичность</th><th className="num" title="Уникальных уязвимостей (один идентификатор считается один раз)">CVE</th><th className="num" title="Из них в каталоге CISA KEV (эксплуатируются)">KEV</th><th>EOL</th><th>Уязвимости</th><th className="hide-sm">Источники</th></tr></thead>
        <tbody>
          {rows.map((g) => <GroupRow key={g.gid} g={g} hostId={hostId} external={data.external_checked} />)}
          {!rows.length && <tr><td colSpan={7}><Empty icon={all.length ? "search" : "checkCircle"} title={all.length ? "Ничего не найдено" : "Уязвимостей по доступным источникам не найдено"}>
            {all.length ? "Измените поиск или фильтр достоверности." : data.notes.length ? "Часть источников недоступна (см. замечания выше): это не означает, что уязвимостей нет." : "Ни KSC, ни внешние базы для установленного ПО этого компьютера уязвимостей не нашли."}</Empty></td></tr>}
        </tbody></table></div>
      {left > 0 && onMore && <p><button type="button" className="btn mini" disabled={more} onClick={async () => { setMore(true); try { setExtra([...extra, ...await onMore(all.length)]); } finally { setMore(false); } }}>{more ? <span className="spin sm" /> : null}Показать ещё продукты ({num(left)})</button></p>}
    </>
  );
}

function GroupRow({ g, hostId, external }: { g: HostVulnGroup; hostId: number; external: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr className={`grp ${open ? "open" : ""}`}>
        <td><button type="button" className="linklike strong-link" aria-expanded={open} onClick={() => setOpen(!open)}><Icon name={open ? "chevronD" : "chevronR"} size={14} /> {g.product}</button><span className="sub mono">{g.version || "версия не указана"}</span></td>
        <td className="nowrap"><span className={`sev ${SEV_CLS[g.severity] ?? "warn"}`}>{g.severity_ru}</span></td>
        <td className="num"><b>{num(g.cves)}</b></td>
        <td className="num">{g.kev ? <Kev /> : <span className="muted">0</span>}{g.kev > 1 && <span className="sub small">{g.kev}</span>}</td>
        <td>{g.eol ? <span className={`badge ${EOL_TONE[g.eol.status] ?? "warn"}`} title={g.eol.status_ru}>{g.eol.status === "eol" ? "EOL" : g.eol.status_ru}</span> : <span className="muted">—</span>}</td>
        <td>{g.sample.map((k, i) => <span key={k}>{i > 0 && ", "}{idLink(k)}</span>)}{g.more > 0 && <>{", "}<button type="button" className="clist-more" aria-expanded={open} onClick={() => setOpen(true)} title="Показать полный список">+{g.more}</button></>}</td>
        <td className="hide-sm">{g.detected_by.includes("ksc") && <span className="chip tiny">KSC</span>}{g.detected_by.includes("external") && <span className="chip tiny">внешние базы</span>}
          <span className="sub small">{g.confirmed_ksc ? `${num(g.confirmed_ksc)} подтв. KSC` : ""}{g.confirmed_ksc && g.external_only ? ", " : ""}{g.external_only ? `${num(g.external_only)} по базам` : ""}</span></td>
      </tr>
      {open && <tr className="grp-detail"><td colSpan={7}><GroupItems g={g} hostId={hostId} external={external} /></td></tr>}
    </>
  );
}

/** Полный список уязвимостей одного продукта: подгружается при раскрытии, страницами по 25. */
function GroupItems({ g, hostId, external }: { g: HostVulnGroup; hostId: number; external: boolean }) {
  const [items, setItems] = useState<HostVulnRow[]>([]); const [total, setTotal] = useState<number | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const load = (offset: number) => { setBusy(true); api.hosts.vulnItems(hostId, g.product === "—" ? "" : g.product, g.version, offset, external).then((r) => { setItems((cur) => (offset ? [...cur, ...r.items] : r.items)); setTotal(r.total); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false)); };
  useEffect(() => { load(0); }, [g.gid, hostId, external]);  // eslint-disable-line react-hooks/exhaustive-deps
  if (err) return <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (total === null) return <p className="muted small"><span className="spin sm" /> Загрузка списка…</p>;
  return (
    <div className="table-scroll"><table className="table compact nested">
      <thead><tr><th>Критичность</th><th>Уязвимость</th><th>Источник обнаружения</th><th>Статус проверки</th><th className="hide-sm">Описание</th></tr></thead>
      <tbody>{items.map((r) => <Row key={r.id} r={r} />)}</tbody>
      <tfoot><tr><td colSpan={5} className="small muted">Показано {num(items.length)} из {num(total)}{items.length < total && <> <button type="button" className="btn mini" disabled={busy} onClick={() => load(items.length)}>{busy ? <span className="spin sm" /> : null}Показать ещё</button></>}</td></tr></tfoot>
    </table></div>
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
