import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type Check, type Vuln } from "../api";
import { NoSource, type Ctx } from "../App";
import { Pager } from "../components/Common";
import { ConfirmDialog } from "../components/Dialogs";
import { fmt } from "../util";

const SEV: Record<string, string> = { low: "низкая", medium: "средняя", high: "высокая", critical: "критическая" };

export default function VulnsPage({ ctx }: { ctx: Ctx }) {
  const [tab, setTab] = useState<"ksc" | "user">("ksc");
  const [host, setHost] = useState(""); const [cve, setCve] = useState(""); const [product, setProduct] = useState(""); const [severity, setSeverity] = useState("");
  const [applied, setApplied] = useState({ host: "", cve: "", product: "", severity: "" });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: Vuln[]; total: number; unsupported?: string[]; approximate_total?: boolean } | null>(null);
  const [checks, setChecks] = useState<Check[]>([]);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [del, setDel] = useState<Check | null>(null);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ host, cve, product, severity }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [host, cve, product, severity]);
  useEffect(() => {
    if (!ctx.current) return;
    setBusy(true);
    api.vulns({ ...applied, severity: applied.severity || undefined, offset, limit: 50 }).then((d) => { setData(d); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
    api.reports.checks().then((r) => setChecks(r.items)).catch(() => undefined);
  }, [ctx.current, applied, offset]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <h1>Уязвимости</h1>
      <div className="tabs" role="tablist">
        <button className={`tab ${tab === "ksc" ? "active" : ""}`} role="tab" aria-selected={tab === "ksc"} onClick={() => setTab("ksc")}>Подтверждённые KSC</button>
        <button className={`tab ${tab === "user" ? "active" : ""}`} role="tab" aria-selected={tab === "user"} onClick={() => setTab("user")}>Пользовательские критерии ({checks.length})</button>
      </div>
      {tab === "ksc" && (
        <>
          <p className="muted">Действующие обнаружения из базы KSC (не исправлены и не игнорируются). KSC оценивает уязвимости только по своему справочнику: для Linux-пакетов и программ вне справочника (например, PHP) используйте ручные критерии на вкладке «Пользовательские критерии».</p>
          <div className="card filters">
            <div className="row filter-row">
              <input className="grow" value={host} onChange={(e) => setHost(e.target.value)} placeholder="Компьютер" aria-label="Компьютер" />
              <input className="grow" value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE, например CVE-2024-" aria-label="CVE" />
              <input className="grow" value={product} onChange={(e) => setProduct(e.target.value)} placeholder="Программа" aria-label="Программа" />
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Опасность" style={{ width: "auto" }}><option value="">Любая опасность</option><option value="4">критическая</option><option value="2">высокая</option><option value="1">предупреждение</option></select>
            </div>
          </div>
          {err && <div className="alert error">{err}</div>}
          {data?.unsupported && <div className="alert warn">Источник не содержит объектов уязвимостей KSC ({data.unsupported.join(", ")}): функция недоступна для этого источника.</div>}
          <div className="table-scroll"><table className="table compact">
            <thead><tr><th>Компьютер</th><th>Обнаружено (UTC)</th><th>KLA</th><th>Опасность</th><th>CVE</th><th>Программа</th><th>Версия</th><th>Исправление</th></tr></thead>
            <tbody>{(data?.items ?? []).map((v) => (
              <tr key={`${v.occurrence_id}-${v.cve}`}><td><Link to={`/hosts/${v.host_id}`}>{v.host}</Link></td><td className="nowrap">{fmt(v.detected)}</td><td>{v.url ? <a href={v.url} target="_blank" rel="noopener">{v.kla_id}</a> : v.kla_id}</td>
                <td><span className={`badge ${v.severity === "критическая" ? "err" : v.severity === "высокая" ? "warn" : ""}`}>{v.severity}</span></td><td>{v.cve || "—"}</td><td>{v.product}</td><td>{v.product_version}</td><td>{v.patches_available ? "доступно" : "—"}</td></tr>))}
              {data && !data.items.length && !busy && <tr><td colSpan={8} className="empty">Действующих уязвимостей по этим условиям нет.</td></tr>}
            </tbody>
          </table></div>
          {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} approximate={data.approximate_total} />}
        </>
      )}
      {tab === "user" && (
        <>
          <p className="muted">Сохранённые сценарии аудита: версии, которые вы сами отметили как потенциально уязвимые в разделе «Программное обеспечение». Это пользовательский критерий, а не подтверждение KSC.</p>
          <div className="table-scroll"><table className="table">
            <thead><tr><th>Название</th><th>CVE</th><th>Уровень</th><th>Критерий</th><th>Автор</th><th>Создан</th><th /></tr></thead>
            <tbody>{checks.map((c) => (
              <tr key={c.id}><td><b>{c.name}</b>{c.description && <div className="small muted">{c.description}</div>}</td><td>{c.cve || "—"}</td><td><span className={`badge ${c.severity === "critical" ? "err" : c.severity === "high" ? "warn" : ""}`}>{SEV[c.severity]}</span></td>
                <td className="small">{describe(c.selection as Record<string, unknown>)}</td><td>{c.created_by}</td><td className="nowrap">{fmt(c.created_at)}</td>
                <td className="actions"><Link className="btn mini" to={`/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(c.selection))}&title=${encodeURIComponent(c.name)}`}>Отчёт</Link> {ctx.me.user.role !== "viewer" && <button className="btn mini ghost danger" onClick={() => setDel(c)}>Удалить</button>}</td></tr>))}
              {!checks.length && <tr><td colSpan={7} className="empty">Пользовательских критериев пока нет. Отметьте версии в разделе «Программное обеспечение» и нажмите «Сохранить как сценарий аудита».</td></tr>}
            </tbody>
          </table></div>
          {del && <ConfirmDialog title="Удалить сценарий?" confirmLabel="Удалить" body={<p>Сценарий «{del.name}» будет удалён.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.reports.deleteCheck(del.id); setChecks((c) => c.filter((x) => x.id !== del.id)); }} />}
        </>
      )}
    </section>
  );
}

export function describe(p: Record<string, unknown>): string {
  const parts: string[] = [];
  if (p.rule) parts.push(`правило ${p.rule}`);
  if (Array.isArray(p.branches) && p.branches.length) parts.push(`ветки ${p.branches.join(", ")}`);
  if (Array.isArray(p.product_ids) && p.product_ids.length) parts.push(`записей реестра: ${p.product_ids.length}`);
  if (p.name_like) parts.push(`название ${p.name_like}`);
  if (p.min_version || p.below_version || p.max_version) parts.push(`версия ${p.min_version ? `≥ ${p.min_version}` : ""} ${p.max_version ? `≤ ${p.max_version}` : ""} ${p.below_version ? `< ${p.below_version}` : ""}`.replace(/\s+/g, " ").trim());
  if (p.platform) parts.push(String(p.platform));
  if (p.include_inactive) parts.push("включая без связи"); else if (p.active_days) parts.push(`связь за ${p.active_days} сут`);
  return parts.join(" · ") || "—";
}
