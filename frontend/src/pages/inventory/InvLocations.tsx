/** Местоположения: дерево «регион → … → рабочее место» (и площадки, серверные, стойки, склады) с числом единиц в узле и поддереве, состав по классам, изменение структуры,
 *  этикетки помещений (код «LOC:…» для сканирования при инвентаризации). */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { num } from "../../util";
import { LocationPicker, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { inv, type Loc } from "./invApi";

const CHILD_KIND: Record<string, string> = { country: "region", region: "city", city: "address", address: "building", building: "floor", floor: "room", room: "workplace", site: "server_room", server_room: "rack", storage: "room" };

export default function InvLocations({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { meta, can, locs, reloadLocs } = useInv();
  const [q, setQ] = useState(""); const [open, setOpen] = useState<Set<number>>(new Set()); const [sel, setSel] = useState<number | null>(null);
  const [form, setForm] = useState<Partial<Loc> | null>(null);
  const [toast, show] = useToast();
  const rep = useInvReport();
  const kids = useMemo(() => { const m = new Map<number | null, Loc[]>(); for (const l of locs ?? []) { const k = l.parent_id; m.set(k, [...(m.get(k) ?? []), l]); } return m; }, [locs]);
  const hits = q ? (locs ?? []).filter((l) => l.path.toLowerCase().includes(q.toLowerCase())) : null;
  const cur = (locs ?? []).find((l) => l.id === sel) ?? null;
  const toggle = (id: number) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const del = async (l: Loc) => { if (!window.confirm(`Удалить «${l.name}»?`)) return; try { const r = await inv.delLoc(l.id); show(r.note ?? "Удалено"); setSel(null); reloadLocs(); } catch (e) { show((e as ApiError).message, "error"); } };
  const node = (l: Loc, depth: number): React.ReactNode => {
    const ch = kids.get(l.id) ?? []; const isOpen = open.has(l.id) || depth === 0;
    return <li key={l.id}>
      <div className={`inv-tree-row ${sel === l.id ? "sel" : ""} ${!l.active ? "muted" : ""}`} style={{ paddingLeft: 6 + depth * 18 }}>
        {ch.length ? <button type="button" className="btn ghost icon mini" aria-expanded={isOpen} aria-label={isOpen ? "Свернуть" : "Развернуть"} onClick={() => toggle(l.id)}><Icon name={isOpen ? "chevronD" : "chevronR"} size={14} /></button> : <span className="inv-tree-pad" />}
        <button type="button" className="inv-tree-name" onClick={() => setSel(l.id)}><b>{l.name}</b><span className="muted small">{l.kind_ru}</span></button>
        <span className="inv-tree-n" title="единиц в узле и во вложенных">{l.total ? num(l.total) : ""}</span>
      </div>
      {isOpen && ch.length > 0 && <ul>{ch.map((c) => node(c, depth + 1))}</ul>}
    </li>;
  };
  if (locs === null) return <div className="card"><SkelRows rows={6} cols={2} /></div>;
  const roots = kids.get(null) ?? [];
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Местоположения</h1>
        <div className="row wrap">{can("refs") && <button className="btn primary" onClick={() => setForm({ kind: "region", parent_id: null, name: "" })}><Icon name="plus" size={16} />Добавить</button>}
          <button className="btn" onClick={() => rep.open(["by_location"], {}, "Все местоположения")}><Icon name="download" size={16} />Отчёт</button></div></div>
      <div className="split inv-loc-split">
        <div className="card flush">
          <div className="pad"><div className="input-icon"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Найти регион, здание, помещение" aria-label="Поиск местоположения" /></div></div>
          {!roots.length ? <Empty icon="sitemap" title="Структура не задана" action={can("refs") ? <button className="btn primary" onClick={() => setForm({ kind: "region", parent_id: null, name: "" })}>Добавить регион или площадку</button> : undefined}>
            Структура настраивается: регион → город → адрес → здание → этаж → помещение → рабочее место. При импорте из Excel недостающие узлы создаются по пути.</Empty>
            : hits ? <ul className="inv-tree">{hits.map((l) => <li key={l.id}><div className={`inv-tree-row ${sel === l.id ? "sel" : ""}`}><button type="button" className="inv-tree-name" onClick={() => setSel(l.id)}><b>{l.path}</b><span className="muted small">{l.kind_ru}</span></button><span className="inv-tree-n">{l.total || ""}</span></div></li>)}</ul>
              : <ul className="inv-tree">{roots.map((r) => node(r, 0))}</ul>}
        </div>
        <div className="stack">
          {!cur ? <div className="card"><p className="muted">Выберите узел: здесь будет состав оборудования, вложенные местоположения и действия.</p></div> : <div className="card">
            <div className="card-head"><div><h2>{cur.name}</h2><span className="muted small">{cur.kind_ru} · {cur.path}</span></div></div>
            <div className="meters compact">
              <div className="meter"><Link className="meter-link" to={`/inventory/assets?location=${cur.id}&st=active`}><span className="l">Всего, с вложенными</span><span className="v">{num(cur.total)}</span></Link></div>
              <div className="meter"><span className="l">Непосредственно здесь</span><span className="v">{num(cur.n)}</span></div>
            </div>
            {cur.by_cls && Object.keys(cur.by_cls).length > 0 && <div className="row wrap tight">{Object.entries(cur.by_cls).sort((a, b) => b[1] - a[1]).map(([c, n]) => <Link key={c} className="chip" to={`/inventory/assets?location=${cur.id}&cls=${c}&st=active`}>{meta.cls[c] ?? c}: <b>{n}</b></Link>)}</div>}
            {cur.note && <p className="small">{cur.note}</p>}
            <div className="row wrap mt-sm">
              {can("refs") && <button className="btn mini" onClick={() => setForm({ kind: CHILD_KIND[cur.kind] ?? "room", parent_id: cur.id, name: "" })}><Icon name="plus" size={14} />Вложенное</button>}
              {can("refs") && <button className="btn mini" onClick={() => setForm(cur)}><Icon name="edit" size={14} />Изменить</button>}
              {can("create") && <Link className="btn mini" to={`/inventory/assets/new?location=${cur.id}`}>Добавить оборудование сюда</Link>}
              <a className="btn mini" href={inv.locLabelsUrl([cur.id, ...(locs ?? []).filter((l) => l.parent_id === cur.id).map((l) => l.id)])} target="_blank" rel="noopener">Этикетки помещений</a>
              <button className="btn mini" onClick={() => rep.open(["by_location", "registry"], { location: cur.id }, cur.path)}><Icon name="download" size={14} />Отчёт</button>
              {can("refs") && <button className="btn mini ghost" onClick={() => void del(cur)}><Icon name="trash" size={14} />Удалить</button>}
            </div>
          </div>}
        </div>
      </div>
      {form && <LocForm init={form} onClose={() => setForm(null)} onSaved={(l) => { setForm(null); reloadLocs(); setSel(l.id); if (l.parent_id) setOpen((s) => new Set(s).add(l.parent_id!)); show("Сохранено"); }} />}
      {rep.node}{toast}
    </div>
  );
}

function LocForm({ init, onClose, onSaved }: { init: Partial<Loc>; onClose: () => void; onSaved: (l: Loc) => void }) {
  const { meta } = useInv();
  const [f, setF] = useState<Partial<Loc>>(init); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const units = (f.data?.units as number | undefined) ?? "";
  const setCoord = (key: "lat" | "lon", value: string) => setF((prev) => ({ ...prev, data: { ...prev.data, [key]: value === "" ? null : Number(value) } }));
  const save = async () => {
    setBusy(true); setErr("");
    const body = { parent_id: f.parent_id ?? null, kind: f.kind, name: f.name, code: f.code ?? "", note: f.note ?? "", data: f.data ?? {}, active: f.active ?? true, sort: f.sort ?? 0 };
    try { onSaved(init.id ? await inv.editLoc(init.id, body) : await inv.addLoc(body)); } catch (e) { setErr((e as ApiError).message); setBusy(false); }
  };
  return (
    <Modal title={init.id ? "Изменить местоположение" : "Новое местоположение"} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={busy || !f.name?.trim()} onClick={() => void save()}>Сохранить</button></>}>
      <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <LocationPicker label="Входит в" value={f.parent_id ?? null} onChange={(v) => setF({ ...f, parent_id: v })} placeholder="верхний уровень" />
        <div className="row wrap"><label className="field">Вид<select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>{Object.entries(meta.loc_kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field grow">Название<input autoFocus value={f.name ?? ""} onChange={(e) => setF({ ...f, name: e.target.value })} maxLength={200} /></label></div>
        <div className="row wrap"><label className="field">Код<input value={f.code ?? ""} onChange={(e) => setF({ ...f, code: e.target.value })} maxLength={60} placeholder="номер кабинета, шифр" /></label>
          {f.kind === "rack" && <label className="field">Юнитов в стойке<input type="number" min={1} max={60} value={units} onChange={(e) => setF({ ...f, data: { ...(f.data ?? {}), units: Number(e.target.value) || undefined } })} /></label>}</div>
        <div className="row wrap">
          <label className="field">Широта<input type="number" step="any" min={-90} max={90} value={Number.isFinite(f.data?.lat) ? Number(f.data?.lat) : ""} onChange={(e) => setCoord("lat", e.target.value)} /></label>
          <label className="field">Долгота<input type="number" step="any" min={-180} max={180} value={Number.isFinite(f.data?.lon) ? Number(f.data?.lon) : ""} onChange={(e) => setCoord("lon", e.target.value)} /></label>
        </div>
        <label className="field">Описание<textarea rows={2} value={f.note ?? ""} onChange={(e) => setF({ ...f, note: e.target.value })} maxLength={1000} /></label>
        {init.id && <label className="check-row"><input type="checkbox" checked={f.active ?? true} onChange={(e) => setF({ ...f, active: e.target.checked })} />Используется (скрытое не предлагается при выборе)</label>}
        {err && <p className="field-err">{err}</p>}
      </form>
    </Modal>
  );
}
