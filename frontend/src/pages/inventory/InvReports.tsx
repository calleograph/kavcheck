/** Отчёты инвентаризации: каталог видов с параметрами (отбор, период) → общий конструктор (XLSX, CSV, PDF, HTML с вкладками). Сформированные отчёты — в разделе «Отчёты». */
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { Ctx } from "../../App";
import { Icon } from "../../components/Icons";
import { LocationPicker, PersonPicker, useInv } from "./InvBits";
import { REPORT_VIEWS, useInvReport } from "./InvReport";

const PERIOD = new Set(["owner_history", "moves", "docs"]);

export default function InvReports({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { meta } = useInv();
  const [sp] = useSearchParams();
  const rep = useInvReport();
  const [loc, setLoc] = useState<number | null>(null); const [person, setPerson] = useState<number | null>(null); const [pname, setPname] = useState("");
  const [cls, setCls] = useState(""); const [st, setSt] = useState("active");
  const year = new Date().getFullYear();
  const [from, setFrom] = useState(`${year}-01-01`); const [to, setTo] = useState(new Date().toISOString().slice(0, 10));
  const groups = [...new Set(REPORT_VIEWS.map((v) => v.group))];
  const params = (view: string) => ({ ...(loc ? { location: loc } : {}), ...(person ? { person } : {}), ...(cls ? { cls } : {}), ...(st && !["stock", "repair", "writtenoff", "licenses", "license_usage", "docs"].includes(view) ? { st } : {}),
    ...(PERIOD.has(view) ? { date_from: from, date_to: to } : {}) });
  const auto = sp.get("view");
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Отчёты</h1><Link className="btn ghost" to="/reports"><Icon name="file" size={16} />Сформированные отчёты</Link></div>
      <div className="card inv-rep-filter">
        <h2>Отбор для отчётов</h2>
        <div className="inv-grid">
          <LocationPicker label="Местоположение (с вложенными)" value={loc} onChange={setLoc} placeholder="все" />
          <PersonPicker label="Сотрудник (любая роль)" value={person} name={pname} onChange={(id, nm) => { setPerson(id); setPname(nm); }} />
          <label className="field">Класс<select value={cls} onChange={(e) => setCls(e.target.value)}><option value="">Все</option>{Object.entries(meta.cls).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Состояние<select value={st} onChange={(e) => setSt(e.target.value)}><option value="">Любое</option><option value="active">Действующее</option>{Object.entries(meta.st).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Период с<input type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
          <label className="field">по<input type="date" value={to} onChange={(e) => setTo(e.target.value)} /></label>
        </div>
        <p className="muted small">Период применяется к истории и журналу документов. Отчёт по конкретной единице — кнопка «Отчёт» в её карточке; по выборке — кнопка на странице «Оборудование».</p>
      </div>
      {groups.map((g) => <section key={g} className="inv-rep-group"><h2 className="vdb-h">{g}</h2><div className="inv-rep-grid">
        {REPORT_VIEWS.filter((v) => v.group === g).map((v) => <button key={v.view} type="button" className={`inv-rep-card ${auto === v.view ? "on" : ""}`} onClick={() => rep.open([v.view], params(v.view))}>
          <Icon name="file" size={18} /><b>{v.title}</b><span className="muted small">{v.hint}</span></button>)}</div></section>)}
      {rep.node}
    </div>
  );
}
