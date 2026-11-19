/** Реестр оборудования: отбор в адресной строке (возврат из карточки сохраняет фильтры и место), сохранённые фильтры, группировка, массовые операции, создание карточек из KSC, отчёт по выборке. */
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "../../components/Infinite";
import { CheckAll, useRowSel } from "../../components/QuickReport";
import { useToast } from "../../components/Toast";
import { Dock, Empty, Segmented, SkelRows, SortTh } from "../../components/ui";
import { fmtDate, num, plural } from "../../util";
import { KscBadge, LocCell, LocationPicker, PersonPicker, RefSelect, StBadge, refsOf, shortLabel, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { FILTER_KEYS, inv, type Asset, type Group, type View } from "./invApi";

const GROUP_BY: [string, string][] = [["", "Без группировки"], ["type", "Тип"], ["cls", "Класс"], ["manufacturer", "Производитель"], ["model", "Модель"], ["status", "Статус"], ["location", "Местоположение"],
  ["dept", "Подразделение"], ["branch", "Филиал"], ["user", "Пользователь"], ["resp", "Ответственный"], ["mol", "МОЛ"], ["supplier", "Поставщик"]];
const GROUP_PARAM: Record<string, string> = { type: "type_id", cls: "cls", manufacturer: "manufacturer_id", model: "model_id", status: "status_id", location: "location", dept: "dept_id", branch: "branch_id",
  user: "person", resp: "person", mol: "person", supplier: "supplier_id" };

export default function InvAssets({ ctx }: { ctx: Ctx }) {
  const { meta, can, locs } = useInv();
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const f = useMemo(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, sp.get(k) ?? ""]).concat([...sp.entries()].filter(([k]) => k.startsWith("p.")))) as Record<string, string>, [sp]);
  const [q, setQ] = useState(f.q);
  useEffect(() => setQ(f.q), [f.q]);
  useEffect(() => { const t = window.setTimeout(() => { if (q !== f.q) set({ q }); }, 350); return () => window.clearTimeout(t); }, [q]); // eslint-disable-line react-hooks/exhaustive-deps
  const set = (kv: Record<string, string | null>) => setSp((p) => { for (const [k, v] of Object.entries(kv)) { if (v) p.set(k, v); else p.delete(k); } return p; }, { replace: true });
  const sort = sp.get("sort") ?? "inv_no", desc = sp.get("desc") === "1", groupBy = sp.get("group") ?? "";
  const params = useMemo(() => Object.fromEntries(Object.entries(f).filter(([, v]) => v)), [f]);
  const list = useInfinite<Asset>("inv-assets", [params, sort, desc], (offset, limit) => inv.assets({ ...params, sort, desc, offset, limit }) as unknown as Promise<Chunk<Asset>>);
  const sel = useRowSel<number>();
  const [groups, setGroups] = useState<Group[] | null>(null);
  useEffect(() => { if (!groupBy) { setGroups(null); return; } inv.groups(groupBy, params).then((r) => setGroups(r.items)).catch(() => setGroups([])); }, [groupBy, params]);
  const [views, setViews] = useState<View[]>([]);
  const loadViews = () => inv.views("assets").then((r) => setViews(r.items)).catch(() => setViews([]));
  useEffect(() => { void loadViews(); }, []);
  const [bulk, setBulk] = useState(false); const [kscOpen, setKscOpen] = useState(sp.get("ksc_import") === "1");
  const rep = useInvReport();
  const [toast, show] = useToast();
  const listProps = meta.props.filter((p) => p.active && p.in_list);
  const onSort = (k: string) => set(sort === k ? { desc: desc ? null : "1" } : { sort: k, desc: null });
  const reset = () => setSp(new URLSearchParams(), { replace: true });
  const refN = (kind: string, id: string) => meta.refs.find((r) => r.kind === kind && String(r.id) === id)?.name ?? id;
  const chips = [
    ...(f.q ? [{ id: "q", label: `Поиск: ${f.q}`, onRemove: () => { setQ(""); set({ q: null }); } }] : []),
    ...(f.cls ? [{ id: "cls", label: `Класс: ${f.cls.split(",").map((c) => meta.cls[c] ?? c).join(", ")}`, onRemove: () => set({ cls: null }) }] : []),
    ...(f.st ? [{ id: "st", label: `Состояние: ${f.st === "active" ? "действующее" : f.st.split(",").map((c) => meta.st[c] ?? c).join(", ")}`, onRemove: () => set({ st: null }) }] : []),
    ...(["type_id", "manufacturer_id", "model_id", "status_id", "dept_id", "branch_id", "supplier_id"] as const).filter((k) => f[k]).map((k) => ({ id: k, label: refN(k.replace("_id", ""), f[k]), onRemove: () => set({ [k]: null }) })),
    ...(f.location ? [{ id: "loc", label: `Местоположение: ${locs?.find((l) => String(l.id) === f.location)?.path ?? f.location}`, onRemove: () => set({ location: null }) }] : []),
    ...(f.person ? [{ id: "person", label: `Сотрудник${f.role ? ` (${meta.roles[f.role]})` : ""}`, onRemove: () => set({ person: null, role: null }) }] : []),
    ...(f.ksc ? [{ id: "ksc", label: { linked: "Связаны с KSC", unlinked: "Без связи с KSC", lost: "Пропали из KSC", auto: "Связь предполагается" }[f.ksc] ?? f.ksc, onRemove: () => set({ ksc: null }) }] : []),
    ...(f.warranty ? [{ id: "w", label: { soon: "Гарантия истекает", expired: "Гарантия истекла", none: "Гарантия не указана", valid: "На гарантии" }[f.warranty] ?? f.warranty, onRemove: () => set({ warranty: null }) }] : []),
    ...(["no_location", "no_owner", "no_resp", "transit", "stale"] as const).filter((k) => f[k]).map((k) => ({ id: k, label: { no_location: "Без местоположения", no_owner: "Без пользователя и владельца", no_resp: "Без ответственного", transit: "В пути", stale: "Давно не обновлялись" }[k], onRemove: () => set({ [k]: null }) })),
    ...(f.parent ? [{ id: "parent", label: "Состав единицы", onRemove: () => set({ parent: null }) }] : []),
    ...Object.keys(f).filter((k) => k.startsWith("p.")).map((k) => ({ id: k, label: `${meta.props.find((p) => `p.${p.code}` === k)?.name ?? k}: ${f[k]}`, onRemove: () => set({ [k]: null }) })),
  ];
  const saveView = async () => {
    const name = window.prompt("Название фильтра", "");
    if (!name) return;
    try { await inv.addView("assets", name, Object.fromEntries([...sp.entries()]), false); show("Фильтр сохранён"); void loadViews(); } catch (e) { show((e as ApiError).message, "error"); }
  };
  const ids = sel.ids;
  const reportParams = ids.length ? { ids } : params;
  return (
    <div className="inv-page">
      <div className="inv-head">
        <h1>Оборудование</h1>
        <div className="row wrap">
          {views.length > 0 && <label className="field inline"><span className="sr-only">Сохранённые фильтры</span><select value="" onChange={(e) => { const v = views.find((x) => String(x.id) === e.target.value); if (v) setSp(new URLSearchParams(v.params), { replace: true }); }}>
            <option value="">Сохранённые фильтры…</option>{views.map((v) => <option key={v.id} value={v.id}>{v.name}{v.shared ? " (общий)" : ""}</option>)}</select></label>}
          {can("create") && <button className="btn" onClick={() => setKscOpen(true)}><Icon name="monitor" size={16} />Из KSC</button>}
          {can("create") && <Link className="btn primary" to="/inventory/assets/new"><Icon name="plus" size={16} />Добавить</Link>}
        </div>
      </div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Номер, серийный, имя, модель, сотрудник, помещение, свойство…", label: "Поиск оборудования" }}
        primary={<>
          <label className="field inline"><span className="sr-only">Класс</span><select value={f.cls} onChange={(e) => set({ cls: e.target.value })}><option value="">Все классы</option>{Object.entries(meta.cls).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field inline"><span className="sr-only">Состояние</span><select value={f.st} onChange={(e) => set({ st: e.target.value })}><option value="">Любое состояние</option><option value="active">Действующее</option>{Object.entries(meta.st).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        </>}
        more={<div className="inv-more">
          <RefSelect kind="type" label="Тип" value={f.type_id ? Number(f.type_id) : null} onChange={(v) => set({ type_id: v ? String(v) : null })} empty="Любой" />
          <RefSelect kind="manufacturer" label="Производитель" value={f.manufacturer_id ? Number(f.manufacturer_id) : null} onChange={(v) => set({ manufacturer_id: v ? String(v) : null, model_id: null })} empty="Любой" />
          <RefSelect kind="model" label="Модель" parent={f.manufacturer_id ? Number(f.manufacturer_id) : undefined} value={f.model_id ? Number(f.model_id) : null} onChange={(v) => set({ model_id: v ? String(v) : null })} empty="Любая" />
          <RefSelect kind="status" label="Статус" value={f.status_id ? Number(f.status_id) : null} onChange={(v) => set({ status_id: v ? String(v) : null })} empty="Любой" />
          <LocationPicker label="Местоположение (с вложенными)" value={f.location ? Number(f.location) : null} onChange={(v) => set({ location: v ? String(v) : null })} placeholder="любое" />
          <RefSelect kind="dept" label="Подразделение" value={f.dept_id ? Number(f.dept_id) : null} onChange={(v) => set({ dept_id: v ? String(v) : null })} empty="Любое" />
          <RefSelect kind="branch" label="Филиал" value={f.branch_id ? Number(f.branch_id) : null} onChange={(v) => set({ branch_id: v ? String(v) : null })} empty="Любой" />
          <PersonPicker label="Сотрудник" value={f.person ? Number(f.person) : null} name={sp.get("person_name") ?? ""} onChange={(id, nm) => set({ person: id ? String(id) : null, person_name: nm || null })} />
          <label className="field">Роль сотрудника<select value={f.role} onChange={(e) => set({ role: e.target.value })}><option value="">Любая</option>{Object.entries(meta.roles).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Связь с KSC<select value={f.ksc} onChange={(e) => set({ ksc: e.target.value })}><option value="">Любая</option><option value="linked">Связаны</option><option value="unlinked">Без связи (компьютеры)</option><option value="auto">Предполагается</option><option value="lost">Пропали из KSC</option></select></label>
          <label className="field">Гарантия<select value={f.warranty} onChange={(e) => set({ warranty: e.target.value })}><option value="">Любая</option><option value="soon">Истекает (≤ {meta.settings.warranty_days} дн.)</option><option value="expired">Истекла</option><option value="valid">Действует</option><option value="none">Не указана</option></select></label>
          <fieldset className="field"><legend>Требует внимания</legend><div className="row wrap tight">
            {([["no_location", "без местоположения"], ["no_owner", "без пользователя и владельца"], ["no_resp", "без ответственного"], ["transit", "в пути"], ["stale", "давно не обновлялись"]] as const).map(([k, lb]) =>
              <label key={k} className="chip-check"><input type="checkbox" checked={!!f[k]} onChange={(e) => set({ [k]: e.target.checked ? "1" : null })} />{lb}</label>)}</div></fieldset>
          {meta.props.filter((p) => p.active).slice(0, 6).map((p) => <label key={p.code} className="field">{p.name}{p.type === "select" ? <select value={f[`p.${p.code}`] ?? ""} onChange={(e) => set({ [`p.${p.code}`]: e.target.value })}><option value="">Любое</option>{p.options.map((o) => <option key={o}>{o}</option>)}</select>
            : p.type === "bool" ? <select value={f[`p.${p.code}`] ?? ""} onChange={(e) => set({ [`p.${p.code}`]: e.target.value })}><option value="">Любое</option><option value="true">да</option><option value="false">нет</option></select>
              : <input value={f[`p.${p.code}`] ?? ""} onChange={(e) => set({ [`p.${p.code}`]: e.target.value })} placeholder="содержит…" />}</label>)}
          <div className="row"><button type="button" className="btn mini" onClick={() => void saveView()}><Icon name="save" size={14} />Сохранить фильтр</button>
            {views.filter((v) => v.mine).length > 0 && <select className="mini" value="" aria-label="Удалить сохранённый фильтр" onChange={(e) => { if (e.target.value) void inv.delView(Number(e.target.value)).then(loadViews); }}><option value="">Удалить фильтр…</option>{views.filter((v) => v.mine).map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select>}</div>
        </div>}
        moreActive={chips.length - (f.q ? 1 : 0) - (f.cls ? 1 : 0) - (f.st ? 1 : 0)} chips={chips} onReset={reset}
        count={{ n: list.initial ? null : list.total, noun: ["единица", "единицы", "единиц"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
        extra={<label className="field inline"><span className="sr-only">Группировка</span><select value={groupBy} onChange={(e) => set({ group: e.target.value })}>{GROUP_BY.map(([k, v]) => <option key={k} value={k}>{k ? `Группа: ${v}` : v}</option>)}</select></label>}
        report={{ onClick: () => rep.open(["registry", "computers", "by_person", "by_resp", "by_location", "cost", "warranty", "hardware", "software", "owner_history", "moves", "duplicates", "components"], reportParams, ids.length ? `Выбрано: ${ids.length}` : "Все единицы, подходящие под фильтры"),
          title: ids.length ? `Отчёт по отмеченным (${ids.length})` : "Отчёт по текущей выборке" }} />
      {groupBy && <div className="inv-groups card">
        {groups === null ? <SkelRows rows={2} cols={4} /> : groups.length === 0 ? <p className="muted small">Нет данных для группировки.</p> :
          <ul>{groups.map((g) => <li key={String(g.id)}><button type="button" disabled={g.id === null} onClick={() => g.id !== null && set({ [GROUP_PARAM[groupBy]]: String(g.id), ...(["user", "resp", "mol"].includes(groupBy) ? { role: groupBy, person_name: g.name } : {}), group: null })}>
            <span>{g.name}</span><b>{num(g.n)}</b>{g.cost ? <span className="muted small">{g.cost_text} ₽</span> : null}</button></li>)}</ul>}
      </div>}
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={7} /> : (
          <table className="table virt inv-table">
            <thead><tr><CheckAll all={sel.allOf(list.items.map((a) => a.id))} some={sel.someOf(list.items.map((a) => a.id))} onToggle={() => sel.toggleMany(list.items.map((a) => a.id))} />
              <SortTh k="inv_no" label="Инв. номер" sort={sort} desc={desc} onSort={onSort} /><SortTh k="name" label="Наименование" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="status" label="Статус" sort={sort} desc={desc} onSort={onSort} /><th className="hide-sm">Местоположение</th><th className="hide-sm">Пользователь · ответственный</th>
              <SortTh k="serial" label="Серийный номер" sort={sort} desc={desc} onSort={onSort} className="hide-md" /><SortTh k="warranty" label="Гарантия" sort={sort} desc={desc} onSort={onSort} className="hide-md" />
              {listProps.map((p) => <th key={p.code} className="hide-md">{p.name}</th>)}</tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={8 + listProps.length} estimate={52} row={(a) => (
                <tr className={sel.has(a.id) ? "sel" : ""}>
                  <td className="check"><input type="checkbox" aria-label={`Выбрать ${a.inv_no}`} checked={sel.has(a.id)} onChange={() => sel.toggle(a.id)} /></td>
                  <td className="nowrap"><Link to={`/inventory/assets/${a.id}`} className="mono">{a.inv_no}</Link>{a.acc_no && <span className="sub">бух. {a.acc_no}</span>}</td>
                  <td><Link to={`/inventory/assets/${a.id}`}>{shortLabel(a)}</Link><span className="sub">{[a.type, a.hostname].filter(Boolean).join(" · ")}</span><span className="row tight wrap"><KscBadge a={a} />{a.in_transit && <span className="badge accent">в пути</span>}</span></td>
                  <td><StBadge st={a.st_cls} label={a.status} /></td>
                  <td className="hide-sm small"><LocCell path={a.location} detail={a.loc_detail} /></td>
                  <td className="hide-sm small">{a.user || <span className="muted">—</span>}{a.resp && <span className="sub">отв.: {a.resp}</span>}</td>
                  <td className="hide-md mono small">{a.serial || "—"}</td>
                  <td className={`hide-md nowrap small ${a.warranty_until && a.warranty_until < new Date().toISOString().slice(0, 10) ? "muted" : ""}`}>{a.warranty_until ? fmtDate(a.warranty_until) : "—"}</td>
                  {listProps.map((p) => <td key={p.code} className="hide-md small">{a.props_text[p.code] ?? ""}</td>)}
                </tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={8 + listProps.length}><Empty icon="package" title={chips.length ? "Ничего не найдено" : "Карточек пока нет"}
                action={chips.length ? <button className="btn" onClick={reset}>Сбросить фильтры</button> : can("create") ? <Link className="btn primary" to="/inventory/assets/new">Добавить оборудование</Link> : undefined}>
                {chips.length ? "Измените условия отбора." : "Создайте карточки из KSC, загрузите таблицу Excel или добавьте вручную."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      {sel.count > 0 && <Dock label="Выбранное оборудование">
        <span><b>{num(sel.count)}</b> <span className="muted">{plural(sel.count, "единица выбрана", "единицы выбрано", "единиц выбрано")}</span></span>
        {(can("edit") || can("location") || can("people")) && <button className="btn mini" onClick={() => setBulk(true)}><Icon name="edit" size={15} />Изменить</button>}
        {can("docs") && <select className="mini" value="" aria-label="Оформить документ" onChange={(e) => e.target.value && nav(`/inventory/docs/new?kind=${e.target.value}&ids=${ids.join(",")}`)}>
          <option value="">Оформить документ…</option>{["issue", "return", "move", "accept", "handover", "defect", ...(can("repair") ? ["repair"] : []), ...(can("writeoff") ? ["writeoff"] : []), "work"].map((k) => <option key={k} value={k}>{meta.doc_short[k]}</option>)}</select>}
        <a className="btn mini" href={inv.labelsUrl(ids)} target="_blank" rel="noopener"><Icon name="file" size={15} />Этикетки</a>
        <button className="btn mini primary" onClick={() => rep.open(["registry", "computers", "by_person", "by_location", "hardware", "software", "owner_history", "moves"], { ids }, `Выбрано: ${ids.length}`)}><Icon name="download" size={15} />Отчёт</button>
        <button className="btn mini icon" onClick={sel.clear} aria-label="Снять выбор"><Icon name="close" size={15} /></button>
      </Dock>}
      {bulk && <BulkEdit ids={ids} onClose={() => setBulk(false)} onDone={(n) => { setBulk(false); sel.clear(); list.reload(); show(`Изменено карточек: ${n}`); }} />}
      {kscOpen && <KscImport ctx={ctx} onClose={() => { setKscOpen(false); set({ ksc_import: null }); }} onDone={(n) => { list.reload(); show(`Создано карточек: ${n}`); }} />}
      {rep.node}
      {toast}
    </div>
  );
}

function BulkEdit({ ids, onClose, onDone }: { ids: number[]; onClose: () => void; onDone: (n: number) => void }) {
  const { meta, can } = useInv();
  const [field, setField] = useState("status_id");
  const [val, setVal] = useState<number | string | null>(null); const [valName, setValName] = useState("");
  const [comment, setComment] = useState(""); const [plan, setPlan] = useState<{ found: number; would_change?: number; errors: { inv_no: string; error: string }[] } | null>(null);
  const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const FIELDS: [string, string, boolean][] = [["status_id", "Статус", can("edit")], ["location_id", "Местоположение", can("location")], ["user_id", "Пользователь", can("people")], ["owner_id", "Владелец", can("people")],
    ["resp_id", "Ответственный", can("people")], ["mol_id", "МОЛ", can("people")], ["it_id", "ИТ-специалист", can("people")], ["dept_id", "Подразделение", can("edit")], ["branch_id", "Филиал", can("edit")],
    ["warranty_until", "Гарантия до", can("edit")], ["supplier_id", "Поставщик", can("edit")]];
  useEffect(() => { setVal(null); setValName(""); setPlan(null); }, [field]);
  const data = { [field]: val === "" ? null : val };
  const check = async () => { setBusy(true); setErr(""); try { setPlan(await inv.bulk(ids, data, comment, true)); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); } };
  const apply = async () => { setBusy(true); try { const r = await inv.bulk(ids, data, comment); onDone(r.changed ?? 0); } catch (e) { setErr((e as ApiError).message); setBusy(false); } };
  const refKind = { status_id: "status", dept_id: "dept", branch_id: "branch", supplier_id: "supplier" }[field];
  return (
    <Modal title="Изменить выбранное" lede={`Единиц: ${ids.length}. Каждая карточка получит запись в истории.`} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn" disabled={busy} onClick={() => void check()}>Проверить</button>
        <button className="btn primary" disabled={busy || !plan || !plan.would_change} onClick={() => void apply()}>Применить{plan?.would_change ? ` к ${plan.would_change}` : ""}</button></>}>
      <div className="form-stack">
        <Segmented label="Что изменить" value={field} onChange={setField} options={FIELDS.filter((x) => x[2]).map(([k, v]) => [k, v] as [string, string])} />
        {refKind && <RefSelect kind={refKind} label={FIELDS.find((x) => x[0] === field)![1]} value={typeof val === "number" ? val : null} onChange={(v) => setVal(v)} empty="очистить значение" />}
        {field === "location_id" && <LocationPicker label="Новое местоположение" value={typeof val === "number" ? val : null} onChange={(v) => setVal(v)} />}
        {["user_id", "owner_id", "resp_id", "mol_id", "it_id"].includes(field) && <PersonPicker label={FIELDS.find((x) => x[0] === field)![1]} value={typeof val === "number" ? val : null} name={valName} onChange={(id, n) => { setVal(id); setValName(n); }} />}
        {field === "warranty_until" && <label className="field">Гарантия до<input type="date" value={String(val ?? "")} onChange={(e) => setVal(e.target.value)} /></label>}
        <label className="field">Основание или комментарий<input value={comment} onChange={(e) => setComment(e.target.value)} maxLength={2000} placeholder="например, служебная записка" /></label>
        {plan && <div className="alert flat"><Icon name="info" /><div className="alert-body">Изменится {plan.would_change} из {plan.found}.{plan.errors.length > 0 && <ul>{plan.errors.slice(0, 8).map((e) => <li key={e.inv_no}>{e.inv_no}: {e.error}</li>)}</ul>}</div></div>}
        {err && <p className="field-err">{err}</p>}
        <p className="muted small">Выдачу, возврат, перемещение и списание лучше оформлять документом: так появится печатный акт. {meta.doc_short.issue}, {meta.doc_short.move.toLowerCase()} — в меню «Оформить документ».</p>
      </div>
    </Modal>
  );
}

function KscImport({ ctx, onClose, onDone }: { ctx: Ctx; onClose: () => void; onDone: (n: number) => void }) {
  const { meta } = useInv();
  const sources = ctx.sources; const [src, setSrc] = useState(ctx.current?.id ?? ctx.sources[0]?.id ?? "");
  const [q, setQ] = useState(""); const [items, setItems] = useState<{ host_id: number; name: string; os: string; ip: string; group: string; active: boolean }[]>([]); const [total, setTotal] = useState(0);
  const [pick, setPick] = useState<number[]>([]); const [loc, setLoc] = useState<number | null>(null); const [st, setSt] = useState<number | null>(null);
  const [busy, setBusy] = useState(""); const [err, setErr] = useState(""); const [note, setNote] = useState("");
  const load = () => { if (!src) return; inv.kscHosts({ source: src, q, limit: 500 }).then((r) => { setItems(r.items); setTotal(r.total); setNote(r.note ?? ""); setErr(""); }).catch((e) => setErr((e as ApiError).message)); };
  useEffect(() => { const t = window.setTimeout(load, 250); return () => window.clearTimeout(t); }, [src, q]); // eslint-disable-line react-hooks/exhaustive-deps
  const run = async (all: boolean) => {
    setErr(""); let created = 0;
    try {
      if (all) {
        for (let guard = 0; guard < 100; guard++) {
          const r = await inv.kscHosts({ source: src, q, limit: 1000 });
          if (!r.items.length) break;
          setBusy(`Создано ${created}, осталось ${r.total}…`);
          const x = await inv.kscImport(src, r.items.map((h) => h.host_id), st, loc);
          created += x.created;
          if (!x.created) break;
        }
      } else {
        for (let i = 0; i < pick.length; i += 1000) { setBusy(`Создано ${created} из ${pick.length}…`); created += (await inv.kscImport(src, pick.slice(i, i + 1000), st, loc)).created; }
      }
      onDone(created); setPick([]); load();
    } catch (e) { setErr((e as ApiError).message); } finally { setBusy(""); }
  };
  return (
    <Modal side wide title="Создать карточки из KSC" lede="Компьютеры KSC без учётной карточки (подготовленные данные, KSC не опрашивается). Карточка сразу связывается с компьютером; повторный запуск дублей не создаёт." onClose={onClose}>
      <div className="form-stack">
        <div className="row wrap">
          <label className="field">Источник KSC<select value={src} onChange={(e) => { setSrc(e.target.value); setPick([]); }}>{sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
          <LocationPicker label="Местоположение для новых карточек" value={loc} onChange={setLoc} placeholder="не указывать" />
          <RefSelect kind="status" label="Статус" value={st} onChange={setSt} empty="«В эксплуатации»" />
        </div>
        <div className="input-icon"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Имя, адрес, группа KSC" aria-label="Поиск компьютеров KSC" /></div>
        {note && <div className="alert flat warn"><Icon name="info" /><div className="alert-body">{note}</div></div>}
        <div className="row"><span className="muted small">Без карточки: <b>{num(total)}</b>{pick.length ? ` · выбрано ${pick.length}` : ""}</span><div className="spacer" />
          <button className="btn" disabled={!!busy || !pick.length} onClick={() => void run(false)}>Создать для выбранных</button>
          <button className="btn primary" disabled={!!busy || !total} onClick={() => void run(true)}>Создать для всех ({num(total)})</button></div>
        {busy && <p className="muted small"><span className="spin sm" /> {busy}</p>}
        {err && <p className="field-err">{err}</p>}
        <div className="table-scroll inv-ksc-list"><table className="table compact"><thead><tr><th className="check"><input type="checkbox" aria-label="Выбрать все" checked={items.length > 0 && items.every((h) => pick.includes(h.host_id))} onChange={(e) => setPick(e.target.checked ? items.map((h) => h.host_id) : [])} /></th><th>Компьютер</th><th className="hide-sm">ОС</th><th className="hide-sm">Группа KSC</th></tr></thead>
          <tbody>{items.map((h) => <tr key={h.host_id}><td className="check"><input type="checkbox" aria-label={`Выбрать ${h.name}`} checked={pick.includes(h.host_id)} onChange={() => setPick(pick.includes(h.host_id) ? pick.filter((x) => x !== h.host_id) : [...pick, h.host_id])} /></td>
            <td>{h.name}<span className="sub mono">{h.ip}</span>{!h.active && <span className="badge">давно без связи</span>}</td><td className="hide-sm small">{h.os}</td><td className="hide-sm small">{h.group}</td></tr>)}
            {!items.length && <tr><td colSpan={4}><Empty icon="check" title="Все компьютеры источника уже учтены">Карточки без пары можно связать вручную в карточке оборудования.</Empty></td></tr>}</tbody></table></div>
        <p className="muted small">Тип определяется по операционной системе: серверная ОС — «{refsOf(meta, "type").find((r) => r.data.cls === "server")?.name ?? "сервер"}», иначе — «{refsOf(meta, "type").find((r) => r.data.cls === "workstation")?.name ?? "рабочая станция"}». Тип можно поменять массово.</p>
      </div>
    </Modal>
  );
}
