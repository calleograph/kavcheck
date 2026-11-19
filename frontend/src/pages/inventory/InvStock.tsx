/** Склад: оборудование по состояниям учёта, свободное и зарезервированное по моделям, комплектующие (установлены / свободны), поступления. */
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { Empty, SkelRows } from "../../components/ui";
import { fmtDate, num } from "../../util";
import { useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { inv, money, type Stock } from "./invApi";

export default function InvStock() {
  const { meta, can } = useInv(); const nav = useNavigate();
  const [d, setD] = useState<Stock | null>(null); const [err, setErr] = useState("");
  const rep = useInvReport();
  useEffect(() => { inv.stock().then(setD).catch((e) => setErr((e as ApiError).message)); }, []);
  if (err) return <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!d) return <div className="card"><SkelRows rows={5} cols={4} /></div>;
  const order: [string, string][] = [["stock", "На складе"], ["reserve", "Зарезервировано"], ["use", "Выдано / в эксплуатации"], ["repair", "В ремонте"], ["writeoff", "Списано"], ["decom", "Выведено"], ["lost", "Утрачено"]];
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Склад</h1>
        <div className="row wrap">{can("create") && <button className="btn primary" onClick={() => nav("/inventory/docs/new?kind=receipt")}><Icon name="plus" size={16} />Поступление</button>}
          <button className="btn" onClick={() => rep.open(["stock", "components"], {}, "Склад")}><Icon name="download" size={16} />Отчёт</button></div></div>
      <div className="meters">{order.map(([k, lb]) => <div key={k} className="meter"><Link className="meter-link" to={`/inventory/assets?st=${k}`}><span className="l">{lb}</span><span className="v">{num(d.by_st[k] ?? 0)}</span><span className="t">{meta.st[k]}</span></Link></div>)}</div>
      <div className="split">
        <div className="card flush"><div className="card-head"><h2>Свободное и резерв по моделям</h2></div>
          {!d.models.length ? <p className="muted small pad">На складе пусто.</p> : <div className="table-scroll"><table className="table compact"><thead><tr><th>Тип</th><th>Производитель и модель</th><th className="num">На складе</th><th className="num">Резерв</th><th className="num hide-sm">Стоимость</th></tr></thead>
            <tbody>{d.models.map((m, i) => <tr key={i}><td>{m.type || "—"}</td><td>{m.model ? <Link to={`/inventory/assets?st=stock,reserve${m.model_id ? `&model_id=${m.model_id}` : m.type_id ? `&type_id=${m.type_id}` : ""}`}>{m.model}</Link> : <span className="muted">модель не указана</span>}</td>
              <td className="num">{num(m.stock)}</td><td className="num">{m.reserve ? num(m.reserve) : ""}</td><td className="num hide-sm">{m.cost ? money(m.cost) : ""}</td></tr>)}</tbody></table></div>}
        </div>
        <div className="stack">
          <div className="card"><h2>Комплектующие</h2>
            <div className="meters compact"><div className="meter"><Link className="meter-link" to="/inventory/assets?cls=component&st=active"><span className="l">Установлены в оборудование</span><span className="v">{num(d.components.installed)}</span></Link></div>
              <div className="meter"><span className="l">Свободны</span><span className="v">{num(d.components.free)}</span></div></div>
            <p className="muted small">Установка и снятие — во вкладке «Состав и связи» карточки; каждое событие в истории обеих карточек.</p></div>
          <div className="card flush"><div className="card-head"><h2>Поступления</h2><div className="spacer" /><Link className="btn mini ghost" to="/inventory/docs?kind=receipt">Все</Link></div>
            {!d.receipts.length ? <Empty icon="file" title="Поступлений не было">Поступление создаёт карточки на складе — по одной на единицу.</Empty> :
              <ul className="inv-list pad">{d.receipts.map((r) => <li key={r.id}><Link to={`/inventory/docs/${r.id}`} className="mono">{r.no}</Link><span>{fmtDate(r.date)}</span><span className={`badge ${r.status === "done" ? "ok" : r.status === "cancelled" ? "" : "accent"}`}>{r.status_ru}</span>
                <span className="muted small">{r.status === "done" ? `создано ${r.created}` : `${r.qty} ед.`}</span></li>)}</ul>}
          </div>
        </div>
      </div>
      {rep.node}
    </div>
  );
}
