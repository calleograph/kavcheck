import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type EolFinding } from "../api";
import { EolBadge, EolDates, EolSev } from "./EolBits";
import { Empty, SkelRows } from "./ui";
import { num, plural } from "../util";

/** Проблемы поддержки (EOL) в общем списке проблем: тот же вид, что в разделе «EOL», без двойного подсчёта с CVE (EOL — отдельный тип записей). */
export function EolList({ limit = 8, sources }: { limit?: number; sources?: boolean }) {
  const [items, setItems] = useState<EolFinding[] | null>(null); const [total, setTotal] = useState(0); const [err, setErr] = useState("");
  useEffect(() => { api.eol.infra({ limit, sort: "severity", desc: true }).then((r) => { setItems(r.items); setTotal(r.total); }).catch((e) => setErr((e as Error).message)); }, [limit]);
  if (err) return <div className="alert error"><div className="alert-body">{err}</div></div>;
  if (!items) return <SkelRows cols={5} rows={3} />;
  if (!items.length) return <Empty icon="checkCircle" title="Проблем поддержки не найдено">Программы и ОС с закончившейся или приближающейся датой окончания поддержки не найдены (или сопоставление ещё не рассчитано).</Empty>;
  return (
    <>
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Критичность</th><th>Тип</th><th>Программа или ОС</th><th>Поддержка</th><th className="num">Устройств</th>{sources && <th className="hide-sm">Источник</th>}</tr></thead>
        <tbody>{items.map((f) => (
          <tr key={`${f.source_id}${f.kind}${f.subject}${f.version}`}><td><EolSev f={f} /></td><td><span className="badge">EOL</span></td>
            <td><strong>{f.title}</strong>{f.kind === "app" && <span className="sub mono small">{f.version}</span>}<span className="sub small">{f.eol_label}, ветка {f.eol_release}</span></td>
            <td><EolBadge s={f.status} short /><EolDates f={f} /></td><td className="num">{num(f.hosts_active)}</td>{sources && <td className="small hide-sm">{f.source}</td>}</tr>))}</tbody></table></div>
      <p className="muted small">{total > items.length ? `Показаны ${items.length} из ${num(total)} ${plural(total, "записи", "записей", "записей")}. ` : ""}<Link to="/eol">Открыть раздел EOL</Link>: фильтры, устройства, экспорт.</p>
    </>
  );
}
