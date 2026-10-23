import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type Check, type Vuln } from "../api";
import { NoSource, type Ctx } from "../App";
import { Pager } from "../components/Common";
import { ConfirmDialog } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { Empty, PageHead, SkelRows, Tabs } from "../components/ui";
import { fmt } from "../util";

const SEV: Record<string, [string, string]> = { low: ["низкий", ""], medium: ["средний", "accent"], high: ["высокий", "warn"], critical: ["критический", "err"] };

export default function VulnsPage({ ctx }: { ctx: Ctx }) {
  const [tab, setTab] = useState<"ksc" | "user">("ksc");
  const [host, setHost] = useState(""); const [cve, setCve] = useState(""); const [product, setProduct] = useState(""); const [severity, setSeverity] = useState("");
  const [applied, setApplied] = useState({ host: "", cve: "", product: "", severity: "" });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: Vuln[]; total: number; unsupported?: string[]; approximate_total?: boolean } | null>(null);
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [del, setDel] = useState<Check | null>(null);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ host, cve, product, severity }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [host, cve, product, severity]);
  useEffect(() => {
    if (!ctx.current) return;
    setBusy(true);
    api.vulns({ ...applied, severity: applied.severity || undefined, offset, limit: 50 }).then((d) => { setData(d); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, applied, offset]);
  useEffect(() => { if (ctx.current) api.reports.checks().then((r) => setChecks(r.items)).catch(() => setChecks([])); }, [ctx.current]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  return (
    <section>
      <PageHead title="Уязвимости" lede="Найденные KSC уязвимости программ и ваши собственные критерии — версии, отмеченные как потенциально уязвимые." />
      <Tabs label="Вид уязвимостей" value={tab} onChange={setTab} items={[{ id: "ksc", label: "Найдены KSC", count: data?.total }, { id: "user", label: "Пользовательские критерии", count: checks?.length }]} />
      {tab === "ksc" && (
        <>
          <div className="toolbar">
            <div className="input-icon grow"><Icon name="monitor" size={16} /><input value={host} onChange={(e) => setHost(e.target.value)} placeholder="Компьютер" aria-label="Компьютер" /></div>
            <input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE, например CVE-2024-" aria-label="CVE" style={{ width: 210 }} />
            <input value={product} onChange={(e) => setProduct(e.target.value)} placeholder="Программа" aria-label="Программа" style={{ width: 200 }} />
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Опасность" style={{ width: "auto" }}><option value="">Любая опасность</option><option value="4">Критическая</option><option value="2">Высокая</option><option value="1">Предупреждение</option></select>
            <p className="note">Действующие обнаружения: не исправлены и не игнорируются. KSC оценивает только программы из своего справочника; пакеты Linux и, например, PHP он не проверяет — для них используйте пользовательские критерии.</p>
          </div>
          {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          {data?.unsupported && <div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет объектов уязвимостей KSC ({data.unsupported.join(", ")}). Функция недоступна для этого источника.</div></div>}
          <div className="table-scroll">
            {!data && busy ? <SkelRows cols={6} /> : (
              <table className="table">
                <thead><tr><th>Компьютер</th><th>Обнаружено</th><th>Уязвимость</th><th>Опасность</th><th>CVE</th><th>Программа и версия</th><th>Исправление</th></tr></thead>
                <tbody style={{ opacity: busy ? .55 : 1, transition: "opacity .15s" }}>{(data?.items ?? []).map((v) => (
                  <tr key={`${v.occurrence_id}-${v.cve}`}><td><Link to={`/hosts/${v.host_id}`}>{v.host}</Link></td><td className="nowrap">{fmt(v.detected)}</td>
                    <td>{v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="mono">{v.kla_id}<Icon name="external" size={13} style={{ marginLeft: 4, verticalAlign: -2 }} /></a> : <span className="mono">{v.kla_id}</span>}</td>
                    <td><span className={`badge ${v.severity === "критическая" ? "err" : v.severity === "высокая" ? "warn" : ""}`}>{v.severity}</span></td><td className="mono nowrap">{v.cve || "—"}</td>
                    <td>{v.product}<span className="sub mono">{v.product_version}</span></td><td>{v.patches_available ? <span className="badge ok">доступно</span> : <span className="muted">—</span>}</td></tr>))}
                  {data && !data.items.length && <tr><td colSpan={7}><Empty icon="checkCircle" title="Действующих уязвимостей нет">По этим условиям KSC не нашёл неисправленных уязвимостей.</Empty></td></tr>}
                </tbody>
              </table>)}
          </div>
          {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} approximate={data.approximate_total} />}
        </>
      )}
      {tab === "user" && (
        <>
          <p className="muted" style={{ marginBottom: 14, maxWidth: "76ch" }}>Сценарии аудита — версии, которые вы сами отметили как потенциально уязвимые в разделе «Программное обеспечение». Это пользовательский критерий, а не подтверждение KSC.</p>
          <div className="table-scroll">
            <table className="table">
              <thead><tr><th>Сценарий</th><th>CVE</th><th>Уровень</th><th>Критерий</th><th>Автор</th><th>Создан</th><th><span className="sr-only">Действия</span></th></tr></thead>
              <tbody>{(checks ?? []).map((c) => { const [l, cl] = SEV[c.severity] ?? [c.severity, ""]; return (
                <tr key={c.id}><td><b>{c.name}</b>{c.description && <span className="sub">{c.description}</span>}</td><td className="mono small">{c.cve || "—"}</td><td><span className={`badge ${cl}`}>{l}</span></td>
                  <td className="small">{describe(c.selection as Record<string, unknown>)}</td><td>{c.created_by}</td><td className="nowrap">{fmt(c.created_at)}</td>
                  <td className="actions"><Link className="btn mini" to={`/reports?kind=software_hosts&params=${encodeURIComponent(JSON.stringify(c.selection))}&title=${encodeURIComponent(c.name)}`}><Icon name="file" size={15} />Отчёт</Link>
                    {ctx.me.user.role !== "viewer" && <button className="btn mini ghost danger icon" onClick={() => setDel(c)} aria-label={`Удалить сценарий ${c.name}`}><Icon name="trash" size={15} /></button>}</td></tr>); })}
                {checks && !checks.length && <tr><td colSpan={7}><Empty icon="target" title="Сценариев пока нет" action={<Link className="btn" to="/software?mode=grouped">Перейти к версиям</Link>}>Отметьте версии в разделе «Программное обеспечение», откройте «Найти компьютеры» и сохраните сценарий аудита.</Empty></td></tr>}
              </tbody>
            </table>
          </div>
          {del && <ConfirmDialog title="Удалить сценарий?" confirmLabel="Удалить" body={<p>Сценарий «{del.name}» будет удалён. Сформированные по нему отчёты останутся.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.reports.deleteCheck(del.id); setChecks((c) => (c ?? []).filter((x) => x.id !== del.id)); }} />}
        </>
      )}
    </section>
  );
}

export function describe(p: Record<string, unknown>): string {
  const parts: string[] = [];
  if (p.rule) parts.push(`правило «${p.rule}»`);
  if (Array.isArray(p.branches) && p.branches.length) parts.push(`ветки ${p.branches.map((b) => b || "не определена").join(", ")}`);
  if (Array.isArray(p.product_ids) && p.product_ids.length) parts.push(`записей реестра: ${p.product_ids.length}`);
  if (p.name_like) parts.push(`название ${p.name_like}`);
  const v = [p.min_version ? `≥ ${p.min_version}` : "", p.max_version ? `≤ ${p.max_version}` : "", p.below_version ? `< ${p.below_version}` : ""].filter(Boolean).join(", ");
  if (v) parts.push(`версия ${v}`);
  if (p.platform) parts.push(p.platform === "windows" ? "Windows" : "Linux");
  if (p.inactive_only) parts.push("только без связи"); else if (p.include_inactive) parts.push("включая без связи"); else if (p.active_days) parts.push(`связь за ${p.active_days} сут`);
  return parts.join("; ") || "—";
}
