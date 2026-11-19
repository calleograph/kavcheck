/** Справочники инвентаризации (типы, производители и модели, статусы, поставщики и сервисные организации, подразделения, филиалы, типы лицензий, категории программ)
 *  и дополнительные свойства карточек (тип поля, варианты, обязательность, типы оборудования, показ в списке). */
import { useState } from "react";
import type { ApiError } from "../../api";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, Tabs, TagInput } from "../../components/ui";
import { refsOf, useInv } from "./InvBits";
import { inv, type Prop, type Ref } from "./invApi";

type T = "type" | "manufacturer" | "status" | "supplier" | "dept" | "branch" | "license_type" | "sw_category" | "props";

export default function InvRefs() {
  const { meta, can, reload } = useInv();
  const [tab, setTab] = useState<T>("type");
  const [form, setForm] = useState<Partial<Ref> | null>(null); const [pform, setPform] = useState<Partial<Prop> | null>(null);
  const [toast, show] = useToast();
  const edit = can("refs");
  const del = async (r: Ref) => { if (!window.confirm(`Удалить «${r.name}»?`)) return; try { const x = await inv.delRef(r.id); show(x.note ?? "Удалено"); reload(); } catch (e) { show((e as ApiError).message, "error"); } };
  const items = tab === "props" ? [] : refsOf(meta, tab);
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Справочники</h1></div>
      <Tabs<T> label="Справочник" value={tab} onChange={setTab} items={[...(Object.entries(meta.ref_kinds).filter(([k]) => k !== "model") as [T, string][]).map(([id, label]) => ({ id, label, count: refsOf(meta, id).length })), { id: "props" as T, label: "Дополнительные свойства", count: meta.props.length }]} />
      {!edit && <p className="muted small">Изменение справочников — по праву «управление справочниками» (настраивается администратором).</p>}
      {tab === "props" ? <PropsList onEdit={setPform} /> : <div className="card flush">
        <div className="card-head"><h2>{meta.ref_kinds[tab]}</h2><div className="spacer" />{edit && <button className="btn mini primary" onClick={() => setForm({ kind: tab, name: "", data: tab === "type" ? { cls: "other" } : tab === "status" ? { cls: "use" } : {} })}><Icon name="plus" size={14} />Добавить</button>}</div>
        {!items.length ? <Empty icon="layers" title="Пусто">Значения добавляются здесь или автоматически при импорте из Excel.</Empty> :
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Название</th>{tab === "type" && <th>Класс</th>}{tab === "status" && <th>Состояние учёта</th>}{tab === "supplier" && <th>Сервисная</th>}{tab === "manufacturer" && <th>Модели</th>}<th /></tr></thead><tbody>
            {items.map((r) => <tr key={r.id} className={r.active ? "" : "muted"}><td>{r.name}{!r.active && <span className="badge">скрыто</span>}{r.code && <span className="sub mono">{r.code}</span>}</td>
              {tab === "type" && <td className="small">{meta.cls[String(r.data.cls)]}</td>}{tab === "status" && <td className="small">{meta.st[String(r.data.cls)]}</td>}{tab === "supplier" && <td className="small">{r.data.service ? "да" : ""}</td>}
              {tab === "manufacturer" && <td className="small"><Models m={r} edit={edit} onAdd={() => setForm({ kind: "model", name: "", parent_id: r.id, data: {} })} onEdit={setForm} /></td>}
              <td className="nowrap">{edit && <><button className="btn mini ghost" onClick={() => setForm(r)}>Изменить</button><button className="btn mini ghost icon" aria-label={`Удалить ${r.name}`} onClick={() => void del(r)}><Icon name="trash" size={14} /></button></>}</td></tr>)}</tbody></table></div>}
      </div>}
      {form && <RefForm init={form} onClose={() => setForm(null)} onSaved={() => { setForm(null); reload(); show("Сохранено"); }} />}
      {pform && <PropForm init={pform} onClose={() => setPform(null)} onSaved={() => { setPform(null); reload(); show("Сохранено"); }} />}
      {toast}
    </div>
  );
}

function Models({ m, edit, onAdd, onEdit }: { m: Ref; edit: boolean; onAdd: () => void; onEdit: (r: Ref) => void }) {
  const { meta } = useInv();
  const ms = refsOf(meta, "model", m.id);
  return <span className="row wrap tight">{ms.map((x) => edit ? <button key={x.id} type="button" className="chip" onClick={() => onEdit(x)}>{x.name}</button> : <span key={x.id} className="chip">{x.name}</span>)}{edit && <button type="button" className="btn mini ghost" onClick={onAdd}><Icon name="plus" size={12} />модель</button>}</span>;
}

function RefForm({ init, onClose, onSaved }: { init: Partial<Ref>; onClose: () => void; onSaved: () => void }) {
  const { meta } = useInv();
  const [f, setF] = useState<Partial<Ref>>(init); const [err, setErr] = useState("");
  const data = (f.data ?? {}) as Record<string, unknown>;
  const setD = (k: string, v: unknown) => setF({ ...f, data: { ...data, [k]: v } });
  const save = async () => { try { const b = { kind: f.kind, name: f.name, code: f.code ?? "", parent_id: f.parent_id ?? null, data: f.data ?? {}, active: f.active ?? true, sort: 0 }; if (init.id) await inv.editRef(init.id, b); else await inv.addRef(b); onSaved(); } catch (e) { setErr((e as ApiError).message); } };
  return (
    <Modal title={init.id ? "Изменить значение" : `Новое значение: ${meta.ref_kinds[f.kind ?? ""] ?? ""}`} onClose={onClose} footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={!f.name?.trim()} onClick={() => void save()}>Сохранить</button></>}>
      <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <label className="field">Название<input autoFocus value={f.name ?? ""} onChange={(e) => setF({ ...f, name: e.target.value })} maxLength={300} /></label>
        {f.kind === "type" && <><label className="field">Класс оборудования<select value={String(data.cls ?? "other")} onChange={(e) => setD("cls", e.target.value)}>{Object.entries(meta.cls).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <p className="muted small">Класс определяет, какие сведения показываются в карточке (технические — для компьютеров и серверов) и как работают отчёты.</p></>}
        {f.kind === "status" && <label className="field">Состояние учёта<select value={String(data.cls ?? "use")} onChange={(e) => setD("cls", e.target.value)}>{Object.entries(meta.st).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>}
        {f.kind === "supplier" && <><label className="check-row"><input type="checkbox" checked={!!data.service} onChange={(e) => setD("service", e.target.checked)} />Сервисная организация (ремонты)</label>
          <label className="field">Контакты<input value={String(data.contacts ?? "")} onChange={(e) => setD("contacts", e.target.value)} /></label></>}
        {f.kind === "model" && <label className="field">Тип по умолчанию<select value={String(data.type_id ?? "")} onChange={(e) => setD("type_id", e.target.value ? Number(e.target.value) : null)}><option value="">—</option>{refsOf(meta, "type").map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></label>}
        <label className="field">Код<input value={f.code ?? ""} onChange={(e) => setF({ ...f, code: e.target.value })} maxLength={60} placeholder="необязательно" /></label>
        {init.id && <label className="check-row"><input type="checkbox" checked={f.active ?? true} onChange={(e) => setF({ ...f, active: e.target.checked })} />Предлагать при выборе</label>}
        {err && <p className="field-err">{err}</p>}
      </form>
    </Modal>
  );
}

function PropsList({ onEdit }: { onEdit: (p: Partial<Prop>) => void }) {
  const { meta, can } = useInv();
  return (
    <div className="card flush"><div className="card-head"><h2>Дополнительные свойства</h2><div className="spacer" />{can("refs") && <button className="btn mini primary" onClick={() => onEdit({ name: "", type: "text", options: [], type_ids: [], required: false, in_list: false, active: true })}><Icon name="plus" size={14} />Добавить свойство</button>}</div>
      {!meta.props.length ? <Empty icon="layers" title="Свойств нет">Добавьте поля, которых не хватает в карточке: например, «Номер договора аренды», «Класс энергопотребления», «Доступ к сети». Свойства участвуют в поиске, фильтрах, таблицах и отчётах.</Empty> :
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Свойство</th><th>Тип</th><th className="hide-sm">Типы оборудования</th><th>В списке</th><th /></tr></thead><tbody>
          {meta.props.map((p) => <tr key={p.id} className={p.active ? "" : "muted"}><td>{p.name}{p.required && <span className="badge">обязательное</span>}{!p.active && <span className="badge">скрыто</span>}<span className="sub mono">{p.code}</span></td>
            <td className="small">{meta.prop_types[p.type]}{p.options.length > 0 && <span className="sub">{p.options.slice(0, 5).join(", ")}{p.options.length > 5 ? "…" : ""}</span>}</td>
            <td className="hide-sm small">{p.type_ids.length ? p.type_ids.map((t) => meta.refs.find((r) => r.id === t)?.name).filter(Boolean).join(", ") : "все"}</td><td>{p.in_list ? "да" : ""}</td>
            <td>{can("refs") && <button className="btn mini ghost" onClick={() => onEdit(p)}>Изменить</button>}</td></tr>)}</tbody></table></div>}
    </div>
  );
}

function PropForm({ init, onClose, onSaved }: { init: Partial<Prop>; onClose: () => void; onSaved: () => void }) {
  const { meta } = useInv();
  const [f, setF] = useState<Partial<Prop>>(init); const [err, setErr] = useState("");
  const save = async () => { try { if (init.id) await inv.editProp(init.id, f); else await inv.addProp(f); onSaved(); } catch (e) { setErr((e as ApiError).message); } };
  const off = async () => { if (!init.id || !window.confirm("Скрыть свойство? Значения в карточках и истории сохранятся.")) return; try { await inv.delProp(init.id); onSaved(); } catch (e) { setErr((e as ApiError).message); } };
  const types = refsOf(meta, "type");
  return (
    <Modal title={init.id ? "Свойство" : "Новое свойство"} onClose={onClose} footer={<>{init.id && <button className="btn ghost" onClick={() => void off()}>Скрыть</button>}<button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={!f.name?.trim()} onClick={() => void save()}>Сохранить</button></>}>
      <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <label className="field">Название<input autoFocus value={f.name ?? ""} onChange={(e) => setF({ ...f, name: e.target.value })} maxLength={200} /></label>
        <div className="row wrap"><label className="field">Тип поля<select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}>{Object.entries(meta.prop_types).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          {!init.id && <label className="field">Код (латиницей)<input value={f.code ?? ""} onChange={(e) => setF({ ...f, code: e.target.value })} placeholder="создаётся из названия" /></label>}</div>
        <label className="field">Описание<input value={f.descr ?? ""} onChange={(e) => setF({ ...f, descr: e.target.value })} maxLength={500} placeholder="подсказка под полем" /></label>
        {(f.type === "select" || f.type === "multiselect") && <TagInput label="Варианты" value={f.options ?? []} onChange={(v) => setF({ ...f, options: v })} placeholder="значение — Enter" mono={false} />}
        <label className="field">Значение по умолчанию<input value={String(f.default ?? "")} onChange={(e) => setF({ ...f, default: e.target.value })} placeholder="необязательно" /></label>
        <fieldset className="field"><legend>Типы оборудования (пусто — все)</legend><div className="row wrap tight">{types.map((t) => <label key={t.id} className="chip-check"><input type="checkbox" checked={(f.type_ids ?? []).includes(t.id)} onChange={() => setF({ ...f, type_ids: (f.type_ids ?? []).includes(t.id) ? (f.type_ids ?? []).filter((x) => x !== t.id) : [...(f.type_ids ?? []), t.id] })} />{t.name}</label>)}</div></fieldset>
        <label className="check-row"><input type="checkbox" checked={!!f.required} onChange={(e) => setF({ ...f, required: e.target.checked })} />Обязательное</label>
        <label className="check-row"><input type="checkbox" checked={!!f.in_list} onChange={(e) => setF({ ...f, in_list: e.target.checked })} />Столбец в списке оборудования и в реестре</label>
        {err && <p className="field-err">{err}</p>}
      </form>
    </Modal>
  );
}
