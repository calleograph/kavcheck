/** Главная инвентаризации: состав и состояние имущества, что требует внимания (каждое число открывает список), связь с KSC, незавершённые документы, последние изменения. */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";
import { useInv } from "./InvBits";
import { inv, type Overview } from "./invApi";

export default function InvOverview() {
  const { can } = useInv();
  const [d, setD] = useState<Overview | null>(null); const [err, setErr] = useState("");
  useEffect(() => { inv.overview().then(setD).catch((e) => setErr((e as ApiError).message)); }, []);
  if (err) return <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!d) return <div className="card"><SkelRows rows={5} cols={4} /></div>;
  const s = d.stats;
  if (!s.total) return (
    <div className="card inv-start">
      <Empty icon="package" title="Учёт ещё не начат" action={<div className="row wrap">
        {can("create") && <Link className="btn primary" to="/inventory/assets?ksc_import=1"><Icon name="monitor" size={16} />Создать карточки из KSC</Link>}
        {can("import") && <Link className="btn" to="/inventory/import"><Icon name="upload" size={16} />Загрузить из Excel</Link>}
        {can("create") && <Link className="btn" to="/inventory/assets/new"><Icon name="plus" size={16} />Добавить вручную</Link>}</div>}>
        Технические сведения уже есть в KAV Checker: карточки компьютеров можно создать из KSC одной операцией — они сразу будут связаны с компьютером. Затем укажите местоположения, владельцев и ответственных.
      </Empty>
    </div>);
  const attn: [string, number, string, string][] = [
    ["Гарантия заканчивается", s.warranty_soon, `в ближайшие ${d.cfg.warranty_days} дн.`, "/inventory/assets?warranty=soon&st=active"],
    ["Лицензии с истекающим сроком", d.licenses_soon, `в ближайшие ${d.cfg.license_days} дн. или истекли`, "/inventory/licenses?state=soon"],
    ["Выдано, но без пользователя и владельца", s.no_owner, "статус «в эксплуатации»", "/inventory/assets?no_owner=1&st=use"],
    ["Без ответственного", s.no_resp, "действующее оборудование", "/inventory/assets?no_resp=1&st=active"],
    ["Без местоположения", s.no_location, "не указано, где находится", "/inventory/assets?no_location=1&st=active"],
    ["В пути", s.in_transit, d.transit_late ? `из них просрочено перемещений: ${d.transit_late}` : "отправлено, ещё не принято", "/inventory/assets?transit=1"],
    ["Долго в ремонте", d.repair_long, "ремонты дольше срока из настроек", "/inventory/docs?kind=repair&status=sent"],
    ["Незавершённые инвентаризации", d.counts_open, "идёт сканирование", "/inventory/counts"],
    ["Сведения давно не обновлялись", s.stale, `более ${d.cfg.stale_days} дн.`, "/inventory/assets?stale=1&st=active"],
  ];
  const maxCls = Math.max(1, ...d.by_cls.map((c) => c.n));
  return (
    <div className="inv-ov">
      <div className="meters">
        <div className="meter"><Link className="meter-link" to="/inventory/assets?st=active"><span className="l">Действующее оборудование</span><span className="v">{num(s.active)}</span><span className="t">всего карточек {num(s.total)}</span></Link></div>
        <div className="meter"><Link className="meter-link" to="/inventory/reports?view=cost"><span className="l">Учётная стоимость</span><span className="v inv-money">{s.cost_text || "0,00"} ₽</span><span className="t">действующего оборудования</span></Link></div>
        <div className="meter"><Link className="meter-link" to="/inventory/assets?cls=workstation,laptop,server,vm&ksc=linked"><span className="l">Связано с KSC</span><span className="v">{num(s.ksc_linked)}<small> / {num(s.computers)}</small></span><span className="t">компьютеров и серверов</span></Link></div>
        <div className="meter"><Link className="meter-link" to="/inventory/assets?ksc=unlinked&st=active"><span className="l">Без связи с KSC</span><span className={`v ${s.ksc_unlinked ? "warn-text" : ""}`}>{num(s.ksc_unlinked)}</span><span className="t">{s.ksc_lost ? `и пропали из KSC: ${num(s.ksc_lost)}` : "компьютеры без технических сведений"}</span></Link></div>
      </div>
      <div className="split inv-ov-split">
        <div className="card">
          <div className="card-head"><h2>Требует внимания</h2></div>
          <ul className="inv-attn">{attn.map(([t, n, h, to]) => (
            <li key={t}><Link to={to} className={n ? "" : "zero"}><span className="inv-attn-t">{t}<span className="sub muted">{h}</span></span><b className={n ? "warn-text" : "muted"}>{num(n)}</b><Icon name="chevronR" size={14} /></Link></li>))}</ul>
        </div>
        <div className="stack">
          <div className="card">
            <div className="card-head"><h2>Состав</h2><div className="spacer" /><Link className="btn mini ghost" to="/inventory/locations">По местоположениям</Link></div>
            <ul className="inv-bars">{d.by_cls.map((c) => (
              <li key={c.cls}><Link to={`/inventory/assets?cls=${c.cls}&st=active`}><span className="inv-bars-l">{c.name}</span><span className="inv-bars-b"><i style={{ width: `${(c.n / maxCls) * 100}%` }} /></span><b>{num(c.n)}</b></Link></li>))}</ul>
            <div className="row wrap tight inv-st">{d.by_st.map((x) => <Link key={x.st} className="chip" to={`/inventory/assets?st=${x.st}`}>{x.name}: <b>{num(x.n)}</b></Link>)}</div>
          </div>
          <div className="card">
            <div className="card-head"><h2>Документы в работе</h2><div className="spacer" />{can("docs") && <Link className="btn mini" to="/inventory/docs"><Icon name="file" size={14} />Сформировать документ</Link>}</div>
            {d.docs_open.length ? <div className="row wrap tight">{d.docs_open.map((x) => <Link key={x.kind} className="chip" to={`/inventory/docs?kind=${x.kind}&open_only=1`}>{x.name}: <b>{x.n}</b></Link>)}</div> : <p className="muted small">Незавершённых документов нет.</p>}
          </div>
        </div>
      </div>
      <div className="card flush mt">
        <div className="card-head"><h2>Последние изменения</h2></div>
        {d.recent.length ? <div className="table-scroll"><table className="table compact"><thead><tr><th>Когда</th><th>Единица</th><th>Событие</th><th className="hide-sm">Кто</th></tr></thead><tbody>
          {d.recent.map((r, i) => <tr key={i}><td className="nowrap">{fmt(r.at)}</td><td><Link to={`/inventory/assets/${r.asset_id}`} className="mono">{r.inv_no}</Link>{r.name && <span className="sub">{r.name}</span>}</td><td>{r.title}</td><td className="hide-sm small">{r.by}</td></tr>)}</tbody></table></div>
          : <p className="muted small pad">Изменений пока нет.</p>}
      </div>
    </div>
  );
}
