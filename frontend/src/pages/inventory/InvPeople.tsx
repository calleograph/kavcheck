/** Сотрудники учёта: список с числом закреплённых единиц по ролям, перенос из адресной книги, карточка — оборудование по ролям, история закреплений, снятие при увольнении. */
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "../../components/Infinite";
import { CheckAll, useRowSel } from "../../components/QuickReport";
import { useToast } from "../../components/Toast";
import { BackLink, Empty, SkelRows } from "../../components/ui";
import { fmt } from "../../util";
import { StBadge, shortLabel, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { inv, type Person, type PersonCard } from "./invApi";

export default function InvPeople({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { meta, can } = useInv();
  const [q, setQ] = useState(""); const [aq, setAq] = useState("");
  useEffect(() => { const t = window.setTimeout(() => setAq(q), 300); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<Person>("inv-people", [aq], (offset, limit) => inv.people({ q: aq, offset, limit, with_bi: false }) as unknown as Promise<Chunk<Person>>);
  const [form, setForm] = useState<Partial<Person> | null>(null);
  const [importing, setImporting] = useState(false);
  const [toast, show] = useToast();
  const rep = useInvReport();
  const hier = async () => {
    setImporting(true);
    try {
      const r = await inv.importHier();
      show(`Перенос из адресной книги завершён. Добавлено ${r.added}, обновлено ${r.updated}`);
      list.reload();
    } catch (e) { show((e as ApiError).message, "error"); }
    finally { setImporting(false); }
  };
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Сотрудники</h1>
        <div className="row wrap">{can("refs") && <button className="btn" disabled={importing} onClick={() => void hier()} title="ФИО, почта, должность и подразделение из последней выгрузки «Иерархии предприятия»"><Icon name="sitemap" size={16} />{importing ? "Перенос…" : "Перенести из адресной книги"}</button>}
          {can("people") && <button className="btn primary" onClick={() => setForm({ name: "", active: true })}><Icon name="plus" size={16} />Добавить</button>}</div></div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "ФИО, логин, почта, подразделение", label: "Поиск сотрудника" }} count={{ n: list.initial ? null : list.total, noun: ["сотрудник", "сотрудника", "сотрудников"] }}
        onRefresh={() => list.reload()} refreshing={list.refreshing} report={{ onClick: () => rep.open(["by_person", "by_resp", "owner_history"], {}, "Оборудование по сотрудникам"), title: "Отчёт по сотрудникам" }} />
      <div className="table-scroll">{list.initial ? <SkelRows cols={4} /> : <table className="table virt"><thead><tr><th>Сотрудник</th><th className="hide-sm">Подразделение</th><th>Закреплено</th><th className="hide-sm">Источник</th></tr></thead>
        <tbody><VirtualRows list={list} colSpan={4} estimate={48} row={(p) => <tr className={p.active ? "" : "muted"}>
          <td><Link to={`/inventory/people/${p.id}`}>{p.name}</Link>{!p.active && <span className="badge">не работает</span>}<span className="sub">{[p.email, p.title].filter(Boolean).join(" · ")}</span></td>
          <td className="hide-sm small">{p.dept}</td>
          <td className="small">{Object.entries(p.counts).filter(([, n]) => n).map(([r, n]) => `${meta.roles[r]}: ${n}`).join(" · ") || <span className="muted">—</span>}</td>
          <td className="hide-sm small">{{ manual: "вручную", bi: "BI", hier: "адресная книга", ad: "AD" }[p.source] ?? p.source}</td></tr>} />
          {!list.items.length && !list.loading && <tr><td colSpan={4}><Empty icon="users" title="Сотрудников нет">Добавьте вручную, перенесите из адресной книги или выберите сотрудника BI при выдаче оборудования.</Empty></td></tr>}</tbody></table>}</div>
      <ListFoot list={list} />
      {form && <PersonForm init={form} onClose={() => setForm(null)} onSaved={() => { setForm(null); list.reload(); show("Сохранено"); }} />}
      {rep.node}{toast}
    </div>
  );
}

function PersonForm({ init, onClose, onSaved }: { init: Partial<Person>; onClose: () => void; onSaved: (p: Person) => void }) {
  const [f, setF] = useState<Partial<Person>>(init); const [err, setErr] = useState("");
  const save = async () => { try { onSaved(init.id ? await inv.editPerson(init.id, f) : await inv.addPerson(f)); } catch (e) { setErr((e as ApiError).message); } };
  const fld = (k: keyof Person, lb: string, ph = "") => <label className="field">{lb}<input value={String(f[k] ?? "")} onChange={(e) => setF({ ...f, [k]: e.target.value })} placeholder={ph} /></label>;
  return (
    <Modal title={init.id ? "Сотрудник" : "Новый сотрудник"} onClose={onClose} footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={!f.name?.trim()} onClick={() => void save()}>Сохранить</button></>}>
      <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        {fld("name", "ФИО")}<div className="row wrap">{fld("email", "Почта", "user@example.local")}{fld("login", "Логин")}</div>
        <div className="row wrap">{fld("dept", "Подразделение")}{fld("title", "Должность")}</div>{fld("phone", "Телефон")}
        {init.id && <label className="check-row"><input type="checkbox" checked={f.active ?? true} onChange={(e) => setF({ ...f, active: e.target.checked })} />Работает (уволенный остаётся в истории)</label>}
        {err && <p className="field-err">{err}</p>}
      </form>
    </Modal>
  );
}

export function PersonPage({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { id } = useParams(); const pid = Number(id);
  const { can } = useInv(); const nav = useNavigate();
  const [p, setP] = useState<PersonCard | null>(null); const [err, setErr] = useState(""); const [edit, setEdit] = useState(false);
  const sel = useRowSel<number>();
  const [toast, show] = useToast();
  const rep = useInvReport();
  const load = useCallback(() => inv.person(pid).then(setP).catch((e) => setErr((e as ApiError).message)), [pid]);
  useEffect(() => { void load(); }, [load]);
  if (err) return <div className="card"><Empty icon="users" title="Сотрудник не найден">{err}</Empty></div>;
  if (!p) return <div className="card"><SkelRows rows={6} cols={3} /></div>;
  const ids = sel.count ? sel.ids : p.assets.map((a) => a.id);
  const clear = async () => {
    if (!window.confirm(`Снять ${p.name} со всех ролей у ${ids.length} единиц? Для возврата с актом используйте «Оформить возврат».`)) return;
    try { for (const f of ["user_id", "owner_id", "resp_id", "mol_id", "it_id"]) { const own = p.assets.filter((a) => ids.includes(a.id) && (a as unknown as Record<string, number | null>)[f] === p.id).map((a) => a.id); if (own.length) await inv.bulk(own, { [f]: null }, `снятие ролей: ${p.name}`); }
      show("Роли сняты"); sel.clear(); void load(); } catch (e) { show((e as ApiError).message, "error"); }
  };
  return (
    <div className="inv-page">
      <BackLink to="/inventory/people" label="Сотрудники" />
      <div className="inv-card-head"><div className="inv-card-title"><h1>{p.name}</h1><div className="row tight wrap">{!p.active && <span className="badge">не работает</span>}<span className="muted small">{[p.title, p.dept, p.email].filter(Boolean).join(" · ")}</span></div></div>
        <div className="row wrap inv-card-actions">{can("people") && <button className="btn" onClick={() => setEdit(true)}><Icon name="edit" size={16} />Изменить</button>}
          <button className="btn primary" onClick={() => rep.open(["by_person", "owner_history"], { person: p.id }, p.name)}><Icon name="download" size={16} />Отчёт</button></div></div>
      <div className="card flush"><div className="card-head"><h2>Закреплённое оборудование ({p.assets.length})</h2><div className="spacer" />
        {can("docs") && p.assets.length > 0 && <button className="btn mini" onClick={() => nav(`/inventory/docs/new?kind=return&ids=${ids.join(",")}&from=${p.id}`)}>Оформить возврат{sel.count ? ` (${sel.count})` : ""}</button>}
        {can("people") && p.assets.length > 0 && <button className="btn mini ghost" onClick={() => void clear()}>Снять без акта</button>}</div>
        {p.assets.length ? <div className="table-scroll"><table className="table compact"><thead><tr><CheckAll all={sel.allOf(p.assets.map((a) => a.id))} some={sel.someOf(p.assets.map((a) => a.id))} onToggle={() => sel.toggleMany(p.assets.map((a) => a.id))} /><th>Инв. номер</th><th>Наименование</th><th>Роль</th><th>Статус</th><th className="hide-sm">Местоположение</th></tr></thead>
          <tbody>{p.assets.map((a) => <tr key={a.id} className={sel.has(a.id) ? "sel" : ""}><td className="check"><input type="checkbox" checked={sel.has(a.id)} onChange={() => sel.toggle(a.id)} aria-label={`Выбрать ${a.inv_no}`} /></td>
            <td><Link to={`/inventory/assets/${a.id}`} className="mono">{a.inv_no}</Link></td><td>{shortLabel(a)}<span className="sub mono">{a.serial}</span></td><td className="small">{a.roles.join(", ")}</td><td><StBadge st={a.st_cls} label={a.status} /></td><td className="hide-sm small">{a.location}</td></tr>)}</tbody></table></div>
          : <p className="muted small pad">За сотрудником ничего не закреплено.</p>}
      </div>
      <div className="card mt"><h2>История закреплений</h2>
        {p.history.length ? <ol className="inv-timeline compact">{p.history.map((h, i) => <li key={i}><div className="inv-tl-head"><b>{h.action === "закреплено" ? "Закреплено" : "Снято"}: {h.role}</b><Link to={`/inventory/assets/${h.asset_id}`} className="mono small">{h.inv_no}</Link><span className="muted small">{fmt(h.at)} · {h.by}</span></div><p className="small muted">{h.name} — {h.title}</p></li>)}</ol>
          : <p className="muted small">Событий нет.</p>}</div>
      {edit && <PersonForm init={p} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); void load(); }} />}
      {rep.node}{toast}
    </div>
  );
}
