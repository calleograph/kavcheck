import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type HuntCompare, type HuntDetail, type HuntJob, type HuntRow, type HuntStatus } from "../../api";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useInfinite, type Chunk } from "../../components/Infinite";
import { QuickReportPanel } from "../../components/QuickReport";
import { Empty, SkelRows, SortTh } from "../../components/ui";
import { fmt, num } from "../../util";
import { STATUS_TONE, isActive } from "../pentest/common";
import { JobProgress, RunConsole } from "../pentest/RunLog";

const ST_TONE: Record<HuntStatus, string> = { confirmed: "err", probable: "warn", needs_check: "", failed: "" };
const COLS: [string, string][] = [["host", "Компьютер"], ["user", "Пользователь"], ["zone", "Зона ответственности"], ["ip", "IP"], ["product", "Продукт"], ["version", "Версия"], ["status", "Результат"], ["basis", "Источник доказательства"]];
const readCols = (): Set<string> => { try { const v = JSON.parse(localStorage.getItem("kc:hunt-cols") || "null"); if (Array.isArray(v)) return new Set(v); } catch { /* по умолчанию */ } return new Set(COLS.map((c) => c[0])); };
const KIND_RU: Record<string, string> = { banner: "Ответ сервиса", nmap: "Nmap", ksc: "KSC", nuclei: "Nuclei", nse: "Nmap NSE", diff: "Различие версий", note: "Примечание", error: "Ошибка" };

/** Результат целевого поиска: главный список — компьютеры, соответствующие критериям; строка открывает боковую панель с подробностями и «Как определено». */
export default function Results({ jobId, canReport, admin, activityDays, currentSource, go }: { jobId: string | null; canReport: boolean; admin: boolean; activityDays: number; currentSource: string | null; go: (tab: string, extra?: Record<string, string>) => void }) {
  const [job, setJob] = useState<HuntJob | null>(null); const [err, setErr] = useState("");
  const [status, setStatus] = useState("confirmed,probable,needs_check"); const [q, setQ] = useState(""); const [aq, setAq] = useState("");
  const [basis, setBasis] = useState(""); const [zone, setZone] = useState(""); const [crit, setCrit] = useState("");
  const [sort, setSort] = useState("status"); const [desc, setDesc] = useState(false);
  const [cols, setCols] = useState<Set<string>>(readCols);
  const [open, setOpen] = useState<HuntRow | null>(null); const [report, setReport] = useState(false);
  const [cmp, setCmp] = useState<HuntCompare | null>(null);
  useEffect(() => { const t = window.setTimeout(() => setAq(q), 300); return () => window.clearTimeout(t); }, [q]);
  const load = useCallback(() => { if (!jobId) return; api.hunt.job(jobId).then((j) => { setJob(j); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [jobId]);
  useEffect(() => { setJob(null); load(); }, [load]);
  useEffect(() => { if (!job || !isActive(job.status)) return; const t = window.setInterval(load, 3000); return () => window.clearInterval(t); }, [job, load]);
  useEffect(() => { if (job && job.base_job_id && !isActive(job.status)) api.hunt.compare(job.id).then(setCmp).catch(() => setCmp(null)); else setCmp(null); }, [job?.id, job?.status, job?.base_job_id]);        // eslint-disable-line react-hooks/exhaustive-deps
  const finishedKey = job ? `${job.status}:${job.findings_n}` : "";
  const list = useInfinite<HuntRow>(`hunt:${jobId}`, [jobId, status, aq, basis, zone, crit, sort, desc, finishedKey], (offset, limit) => api.hunt.results(jobId!, { status, q: aq, basis, zone, crit, sort, desc, offset, limit }) as unknown as Promise<Chunk<HuntRow>>, 50);
  const extra = list.extra as { counts?: Record<HuntStatus, number>; zones?: string[] } | null;
  if (!jobId) return <Empty icon="target" title="Выберите задание" action={<button className="btn primary" onClick={() => go("new")}>Новое задание</button>}>Результаты появятся после запуска целевого поиска; прежние — на вкладке «История».</Empty>;
  if (err && !job) return <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!job) return <SkelRows rows={5} cols={5} />;
  const running = isActive(job.status);
  const sortBy = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  const toggle = (k: string) => { const n = new Set(cols); if (n.has(k)) { if (n.size > 1) n.delete(k); } else n.add(k); setCols(n); try { localStorage.setItem("kc:hunt-cols", JSON.stringify([...n])); } catch { /* не запомнится */ } };
  const counts = extra?.counts ?? job.hunt.counts;
  const repeat = async () => { try { const j = await api.hunt.repeat(job.id); go("results", { job: j.id }); } catch (e) { setErr((e as ApiError).message); } };
  const chips: [string, string, string][] = [["confirmed,probable,needs_check", "Все совпадения", String((counts.confirmed ?? 0) + (counts.probable ?? 0) + (counts.needs_check ?? 0))], ["confirmed", "Подтверждено", String(counts.confirmed ?? 0)], ["probable", "Вероятно", String(counts.probable ?? 0)],
    ["needs_check", "Требует проверки", String(counts.needs_check ?? 0)], ["failed", "Не удалось проверить", String(counts.failed ?? 0)]];
  return (
    <div className="stack">
      <section className="card">
        <div className="card-head"><div><h2>{job.title}</h2><p className="muted small">{job.created_by} · {fmt(job.created_at)} · {job.hunt.mode === "ksc" ? "по данным KSC" : job.hunt.mode === "network" ? "сетевая проверка" : "комбинированный режим"}{job.hunt.criteria.length > 1 ? ` · ${job.hunt.logic === "all" ? "все критерии" : "любой из критериев"}` : ""}</p></div><div className="spacer" />
          <span className={`badge ${STATUS_TONE[job.status]}`}>{job.status_ru}</span>
          {canReport && !running && <button className="btn mini primary" onClick={() => setReport(true)}><Icon name="file" size={15} />Сформировать отчёт</button>}
          {!running && <button className="btn mini" onClick={() => void repeat()}><Icon name="refresh" size={15} />Повторить проверку</button>}
          {running && <button className="btn mini" onClick={() => void api.hunt.cancel(job.id).then(load)}>Отменить</button>}</div>
        {running && <JobProgress job={job} />}
        {job.error && <div className="alert error"><Icon name="alert" /><div className="alert-body">{job.error}</div></div>}
        {job.status === "partial" && <div className="alert warn"><Icon name="alert" /><div className="alert-body"><b>Задание завершено частично</b>: не удалось проверить адресов — {num(job.errors_n)}, неполных проверок — {num(job.incomplete_n)}. Результаты по остальным компьютерам сохранены.
          {job.diag?.reasons?.length > 0 && <ul className="pt-reasons">{job.diag.reasons.map((r, i) => <li key={i}>{r.text}</li>)}</ul>}</div></div>}
        <ul className="hunt-crit">{job.hunt.criteria.map((c) => <li key={c.key}><b>{c.title}</b><span className="sub small">{c.condition}</span>{c.warnings.filter((w) => job.hunt.mode !== "ksc" || !/сетев/.test(w)).slice(0, 2).map((w) => <span key={w} className="sub small muted">{w}</span>)}</li>)}</ul>
        {job.hunt.mode === "ksc" ? <p className="muted small">Только сведения KSC о программах, без сетевой проверки: устройства без Агента администрирования или с устаревшей инвентаризацией сюда не попадают.</p> : <p className="muted small">Проверено адресов: {num(job.hosts_done)} из {num(job.targets_n)}{job.hunt.ports.length ? ` · TCP-порты: ${job.hunt.ports.join(", ")}` : ""}. Отсутствие совпадения при сетевой проверке не доказывает отсутствие программы: продукт может не раскрывать версию или не иметь открытого порта.</p>}
      </section>
      <RunConsole job={job} admin={admin} />
      {cmp && <section className="card"><h2>Сравнение с предыдущей проверкой</h2>
        <div className="pt-sum"><div className={cmp.counts.new ? "bad" : ""}><b>{cmp.counts.new}</b><span>новые совпадения</span></div><div><b>{cmp.counts.kept}</b><span>сохранились</span></div><div><b>{cmp.counts.gone}</b><span>больше не соответствуют</span></div><div className={cmp.counts.unknown ? "warn" : ""}><b>{cmp.counts.unknown}</b><span>повторная проверка не удалась</span></div></div>
        <p className="muted small">{cmp.note}</p>
        {(["new", "gone", "unknown"] as const).map((k) => cmp[k].length > 0 && <details key={k} className="disclosure"><summary>{k === "new" ? "Новые" : k === "gone" ? "Больше не соответствуют" : "Не удалось перепроверить"}: {cmp.counts[k]}</summary>
          <ul className="pt-rej">{cmp[k].slice(0, 50).map((r) => <li key={r.id}><b>{r.host_name || r.ip}</b> <span className="mono small">{r.ip}</span> — {r.product} {r.version}</li>)}</ul></details>)}</section>}

      <div className="toolbar hunt-bar">
        <div className="seg-chips" role="group" aria-label="Результат">{chips.map(([k, l, n]) => <button key={k} type="button" className={`chip ${status === k ? "on" : ""}`} aria-pressed={status === k} onClick={() => setStatus(k)}>{l} · {n}</button>)}</div>
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Компьютер, пользователь, зона, IP, продукт" aria-label="Поиск" /></div>
        <select value={basis} onChange={(e) => setBasis(e.target.value)} aria-label="Источник данных" className="w-auto"><option value="">Любой источник</option><option value="ksc">KSC</option><option value="network">Сеть</option><option value="both">KSC и сеть</option></select>
        {(extra?.zones?.length ?? 0) > 0 && <select value={zone} onChange={(e) => setZone(e.target.value)} aria-label="Зона" className="w-auto"><option value="">Любая зона</option>{extra!.zones!.map((z) => <option key={z} value={z}>{z}</option>)}</select>}
        {job.hunt.criteria.length > 1 && <select value={crit} onChange={(e) => setCrit(e.target.value)} aria-label="Критерий" className="w-auto"><option value="">Все критерии</option>{job.hunt.criteria.map((c) => <option key={c.key} value={c.key}>{c.title.slice(0, 50)}</option>)}</select>}
        <details className="popover-lite"><summary className="btn mini">Столбцы</summary><div className="pop">{COLS.map(([k, l]) => <label key={k} className="check"><input type="checkbox" checked={cols.has(k)} onChange={() => toggle(k)} />{l}</label>)}</div></details>
      </div>
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table compact hunt-table"><thead><tr>{COLS.filter(([k]) => cols.has(k)).map(([k, l]) => (k === "basis" ? <th key={k}>{l}</th> : <SortTh key={k} k={k} label={l} sort={sort} desc={desc} onSort={sortBy} />))}</tr></thead>
            <tbody>{list.items.map((r) => (
              <tr key={r.id} className="clickable" tabIndex={0} onClick={() => setOpen(r)} onKeyDown={(e) => { if (e.key === "Enter") setOpen(r); }}>
                {cols.has("host") && <td><b className="nowrap">{r.host_name || <span className="muted">{r.ip ? "нет в KSC" : "—"}</span>}</b>{r.ambiguous && <span className="badge" title="Адрес совпал с несколькими устройствами KSC">неоднозначно</span>}</td>}
                {cols.has("user") && <td className={r.user === "Не определён" ? "muted" : ""}>{r.user}</td>}
                {cols.has("zone") && <td className={r.zone === "Не назначена" ? "muted" : ""}>{r.zone}</td>}
                {cols.has("ip") && <td className="mono small nowrap">{r.ip}{r.port ? `:${r.port}` : ""}</td>}
                {cols.has("product") && <td>{r.product || "—"}{r.vuln_key && job.hunt.criteria.length > 1 && <span className="sub mono small">{r.vuln_key}</span>}</td>}
                {cols.has("version") && <td className="mono small"><span className="nowrap">{r.version || "не определена"}</span>{r.diff && <span className="badge warn" title="Версии в KSC и по сети различаются">различие</span>}</td>}
                {cols.has("status") && <td><span className={`badge ${ST_TONE[r.status]}`}>{r.status_ru}</span></td>}
                {cols.has("basis") && <td className="small">{r.basis_ru}<span className="sub">{r.evidence_short}</span></td>}</tr>))}
              {!list.items.length && !list.loading && <tr><td colSpan={cols.size}><Empty icon="checkCircle" title={running ? "Ожидаем результаты…" : "Совпадений нет"}>{running ? "Совпадения появляются по мере проверки." : "По выбранным критериям и фильтрам затронутых компьютеров не найдено. Это не доказывает отсутствие программы."}</Empty></td></tr>}
            </tbody></table>)}
      </div>
      {!list.done && !list.loading && list.items.length > 0 && <button type="button" className="btn mini" onClick={list.loadMore}>Показать ещё</button>}
      <p className="muted small">Найдено записей: {num(list.total)}.</p>
      {open && <Detail jobId={job.id} row={open} currentSource={currentSource} onClose={() => setOpen(null)} />}
      {report && <QuickReportPanel kind="quick_hunt" title={`Целевой поиск: ${job.title}`} lede="Компактный перечень затронутых компьютеров: имя, пользователь, зона, IP, продукт, версия, результат и основание" options={{ scope: false, hunt: true }}
        params={{ job_id: job.id, q: aq || undefined, zone: zone || undefined }} sourceIds={[]} activityDays={activityDays} canReport={canReport} onClose={() => setReport(false)} />}
    </div>
  );
}

function Detail({ jobId, row, currentSource, onClose }: { jobId: string; row: HuntRow; currentSource: string | null; onClose: () => void }) {
  const [d, setD] = useState<HuntDetail | null>(null);
  useEffect(() => { api.hunt.detail(jobId, row.id).then(setD).catch(() => setD(null)); }, [jobId, row.id]);
  return (
    <Modal title={row.host_name || row.ip || "Компьютер"} side lede={<span className={`badge ${ST_TONE[row.status]}`}>{row.status_ru}</span>} onClose={onClose}>
      <dl className="kv">
        <div><dt>IP-адрес</dt><dd className="mono">{row.ip || "—"}{row.port ? `:${row.port}` : ""}</dd></div>
        <div><dt>Продукт и версия</dt><dd>{row.product || "—"} <span className="mono">{row.version || "не определена"}</span></dd></div>
        <div><dt>Критерий</dt><dd className="mono">{row.vuln_key || row.crit_key}</dd></div>
        <div><dt>Зона ответственности</dt><dd>{row.zone}</dd></div>
        <div><dt>Пользователь</dt><dd>{row.user}{row.user_kind && <span className="sub small">{row.user_kind}: последнее наблюдение в списках KSC, не владелец устройства</span>}</dd></div>
        <div><dt>ОС</dt><dd>{row.os || "—"}</dd></div>
        <div><dt>Группа KSC</dt><dd>{row.group || "—"}</dd></div>
        <div><dt>Источник данных</dt><dd>{row.basis_ru}{row.data_at && <span className="sub small">сведения получены {fmt(row.data_at)}</span>}</dd></div>
        <div><dt>Последняя связь с KSC</dt><dd>{row.last_connected ? fmt(row.last_connected) : "—"}</dd></div>
      </dl>
      <details className="disclosure" open><summary>Как определено</summary>
        {!d ? <span className="skel skel-text" style={{ width: "70%" }} /> : <ul className="hunt-ev">{d.evidence.map((e, i) => <li key={i}><b>{KIND_RU[e.kind] ?? e.kind}</b><span>{e.text}</span></li>)}{!d.evidence.length && <li className="muted">Исходный признак не записан.</li>}</ul>}</details>
      {row.host_id && row.source_id === currentSource && <p className="mt"><Link className="btn mini" to={`/hosts/${row.host_id}`}>Карточка компьютера</Link></p>}
      {row.host_id && row.source_id !== currentSource && <p className="muted small mt">Карточка компьютера открывается в источнике KSC, к которому относится устройство: переключите источник в шапке.</p>}
      <p className="pt-note">Статус «Вероятно» означает, что продукт и версия соответствуют условию, но дополнительные условия уязвимости не подтверждены; «Подтверждено» — только если безопасная проверка подтвердила проблему.</p>
    </Modal>
  );
}
