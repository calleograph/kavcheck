/** Карточка учётной единицы (вкладки: учётные сведения, расположение и ответственные, техника из KSC, ПО и лицензии, состав, документы, история, вложения) и форма добавления/изменения. */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { BackLink, Empty, SkelRows, Tabs, TagInput } from "../../components/ui";
import { fmt, fmtDate, num } from "../../util";
import { AssetSearch, InvZoneSelect, KscBadge, Kv, LocationPicker, PersonPicker, PropField, RefSelect, StBadge, refsOf, shortLabel, useInv } from "./InvBits";
import InvGeoCard from "./InvGeoCard";
import { useInvReport } from "./InvReport";
import { FieldError, inv, type Asset, type AssetCard, type AssetInfra, type Hist, type Tech } from "./invApi";

type Tab = "main" | "place" | "tech" | "infra" | "soft" | "parts" | "docs" | "history" | "files";
const PEOPLE: [keyof Asset & string, string][] = [["user_id", "Пользователь"], ["owner_id", "Владелец"], ["resp_id", "Ответственный"], ["mol_id", "Материально ответственное лицо"], ["it_id", "Ответственный ИТ-специалист"]];

export default function InvAssetPage({ ctx }: { ctx: Ctx }) {
  const { id } = useParams(); const aid = Number(id);
  const { meta, can } = useInv();
  const [sp, setSp] = useSearchParams();
  const tab = ((["main", "place", "tech", "infra", "soft", "parts", "docs", "history", "files"] as Tab[]).includes(sp.get("tab") as Tab) ? sp.get("tab") : "main") as Tab;
  const [a, setA] = useState<AssetCard | null>(null); const [err, setErr] = useState("");
  const [edit, setEdit] = useState(false);
  const [tech, setTech] = useState<Tech | null>(null); const [techErr, setTechErr] = useState("");
  const [toast, show] = useToast();
  const rep = useInvReport();
  const nav = useNavigate();
  const load = useCallback(() => inv.asset(aid).then((x) => { setA(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), [aid]);
  useEffect(() => { setA(null); setTech(null); void load(); }, [load]);
  const loadTech = useCallback(() => { setTech(null); setTechErr(""); inv.tech(aid).then(setTech).catch((e) => setTechErr((e as ApiError).message)); }, [aid]);
  useEffect(() => { if (a && (tab === "tech" || tab === "soft") && !tech && !techErr) loadTech(); }, [a, tab, tech, techErr, loadTech]);
  if (err) return <div className="card"><Empty icon="package" title="Карточка недоступна" action={<Link className="btn" to="/inventory/assets">К списку</Link>}>{err}</Empty></div>;
  if (!a) return <div className="card"><SkelRows rows={8} cols={2} /></div>;
  const go = (t: Tab) => setSp((p) => { if (t === "main") p.delete("tab"); else p.set("tab", t); return p; }, { replace: true });
  const docKinds = ["issue", "return", "move", "accept", "handover", "defect", ...(can("repair") ? ["repair"] : []), ...(can("writeoff") ? ["writeoff"] : []), "work"];
  const today = new Date().toISOString().slice(0, 10);
  return (
    <div className="inv-page inv-card">
      <BackLink to="/inventory/assets" label="Оборудование" />
      <div className="inv-card-head">
        <div className="inv-card-title">
          <span className="inv-card-no mono">{a.inv_no}</span>
          <h1>{shortLabel(a)}</h1>
          <div className="row tight wrap"><StBadge st={a.st_cls} label={a.status} /><span className="badge">{a.type || a.cls_ru}</span><KscBadge a={a} />{a.in_transit && <Link className="badge accent" to={`/inventory/docs/${a.transit_doc_id}`}>в пути</Link>}
            {a.warranty_until && <span className={`badge ${a.warranty_until < today ? "" : "ok"}`}>{a.warranty_until < today ? "гарантия истекла" : `гарантия до ${fmtDate(a.warranty_until)}`}</span>}</div>
        </div>
        <div className="row wrap inv-card-actions">
          {(a.can.edit || a.can.location || a.can.people) && !edit && <button className="btn" onClick={() => { setEdit(true); go("main"); }}><Icon name="edit" size={16} />Изменить</button>}
          {a.can.docs && <select className="btn-select" value="" aria-label="Сформировать документ" onChange={(e) => e.target.value && nav(`/inventory/docs/new?kind=${e.target.value}&ids=${a.id}`)}>
            <option value="">Сформировать документ…</option>{docKinds.map((k) => <option key={k} value={k}>{meta.doc_short[k]}</option>)}</select>}
          <a className="btn" href={inv.labelsUrl([a.id])} target="_blank" rel="noopener"><Icon name="file" size={16} />Этикетка</a>
          <button className="btn primary" onClick={() => rep.open(["card"], { asset_id: a.id, ids: [a.id] })} title="Карточка учётной единицы: XLSX, PDF, HTML (вкладками)"><Icon name="download" size={16} />Отчёт</button>
        </div>
      </div>
      {edit ? <AssetForm initial={a} onCancel={() => setEdit(false)} onSaved={(x) => { setA(x); setEdit(false); show("Сохранено"); }} /> : <>
        <Tabs<Tab> label="Сведения об оборудовании" value={tab} onChange={go} items={[{ id: "main", label: "Учётные сведения" }, { id: "place", label: "Расположение и ответственные" },
          { id: "tech", label: "Техника (KSC)" }, ...(["server", "vm", "network", "storage"].includes(a.cls) ? [{ id: "infra" as Tab, label: "Инфраструктура" }] : []), { id: "soft", label: "ПО и лицензии", count: a.licenses.length || undefined }, { id: "parts", label: "Состав и связи", count: a.children.length || undefined },
          { id: "docs", label: "Документы", count: a.docs.length || undefined }, { id: "history", label: "История" }, { id: "files", label: "Вложения", count: a.files.length || undefined }]} />
        {tab === "main" && <MainTab a={a} />}
        {tab === "place" && <PlaceTab a={a} reload={load} />}
        {tab === "tech" && <TechTab a={a} tech={tech} err={techErr} reload={() => { loadTech(); void load(); }} ctx={ctx} show={show} />}
        {tab === "infra" && <InfraTab a={a} />}
        {tab === "soft" && <SoftTab a={a} tech={tech} err={techErr} />}
        {tab === "parts" && <PartsTab a={a} reload={load} show={show} />}
        {tab === "docs" && <DocsTab a={a} />}
        {tab === "history" && <HistoryTab a={a} />}
        {tab === "files" && <FilesTab a={a} reload={load} show={show} />}
      </>}
      {rep.node}
      {toast}
    </div>
  );
}

function MainTab({ a }: { a: AssetCard }) {
  const { meta } = useInv();
  const props = meta.props.filter((p) => p.code in a.props_text);
  return (
    <div className="split even">
      <div className="card"><h2>Учётные сведения</h2>
        <Kv rows={[["Инвентарный номер", <span className="mono">{a.inv_no}</span>], ["Бухгалтерский номер", a.acc_no], ["Наименование", a.name], ["Назначение", a.purpose], ["Сервис", a.service], ["Тип", a.type], ["Производитель", a.manufacturer], ["Модель", a.model],
          ["Серийный номер", a.serial && <span className="mono">{a.serial}</span>], ["Имя компьютера", a.hostname && <span className="mono">{a.hostname}</span>], ["Статус", a.status],
          ["Теги", (a.tags ?? []).join(", ")],
          ["Создана", `${fmt(a.created_at)}, ${a.created_by}`], ["Изменена", `${fmt(a.updated_at)}, ${a.updated_by}`]]} />
      </div>
      <div className="stack">
        <div className="card"><h2>Приобретение и гарантия</h2>
          <Kv rows={[["Дата приобретения", a.purchase_date && fmtDate(a.purchase_date)], ["Дата поступления", a.received_date && fmtDate(a.received_date)], ["Ввод в эксплуатацию", a.commissioned_date && fmtDate(a.commissioned_date)],
            ["Гарантия до", a.warranty_until && fmtDate(a.warranty_until)], ["Стоимость", a.cost_text && `${a.cost_text} ₽`], ["Поставщик", a.supplier], ["Документ приобретения", a.purchase_doc]]} />
          {!a.purchase_date && !a.cost && !a.warranty_until && <p className="muted small">Сведения о приобретении не заполнены.</p>}
        </div>
        {(props.length > 0 || a.note) && <div className="card"><h2>Дополнительно</h2>
          <Kv rows={props.map((p) => [p.name, p.type === "url" ? <a href={String(a.props[p.code])} target="_blank" rel="noopener noreferrer">{a.props_text[p.code]}</a> : a.props_text[p.code]] as [string, ReactNode])} />
          {a.note && <p className="inv-note">{a.note}</p>}</div>}
      </div>
    </div>
  );
}

function PlaceTab({ a, reload }: { a: AssetCard; reload: () => void }) {
  const { can } = useInv(); const nav = useNavigate();
  return (
    <div className="split even">
      <div className="stack"><div className="card"><h2>Учётное местоположение</h2>
        <Kv rows={[["Местоположение", a.location ? <Link to={`/inventory/assets?location=${a.location_id}`}>{a.location}</Link> : <span className="muted">не указано</span>], ["Уточнение", a.loc_detail],
          ["Юниты в стойке", a.rack_unit ? `${a.rack_unit}${a.rack_units && a.rack_units > 1 ? `–${a.rack_unit + a.rack_units - 1}` : ""}` : ""], ["Филиал", a.branch], ["Подразделение", a.dept],
          ["Зона ответственности", a.zone_id && a.zone ? <Link to={`/inventory/assets?zone_id=${encodeURIComponent(a.zone_id)}`}>{a.zone}</Link> : ""]]} />
        {can("docs") && <div className="row wrap"><button className="btn mini" onClick={() => nav(`/inventory/docs/new?kind=move&ids=${a.id}`)}><Icon name="arrowR" size={14} />Переместить документом</button></div>}
      </div><InvGeoCard id={a.id} onApplied={reload} /></div>
      <div className="card"><h2>Ответственные лица</h2>
        <Kv rows={PEOPLE.map(([f, lb]) => [lb, (a as unknown as Record<string, number | null>)[f] ? <Link to={`/inventory/people/${(a as unknown as Record<string, number>)[f]}`}>{(a as unknown as Record<string, string>)[f.replace("_id", "")]}</Link> : <span className="muted">не указан</span>] as [string, ReactNode])} />
        {can("docs") && <div className="row wrap">{a.user_id ? <button className="btn mini" onClick={() => nav(`/inventory/docs/new?kind=return&ids=${a.id}&from=${a.user_id}`)}>Оформить возврат</button>
          : <button className="btn mini primary" onClick={() => nav(`/inventory/docs/new?kind=issue&ids=${a.id}`)}>Выдать сотруднику</button>}</div>}
        <p className="muted small">Роли могут совпадать. Прежние владельцы и ответственные — во вкладке «История» и в просмотре на дату.</p>
      </div>
    </div>
  );
}

function TechTab({ a, tech, err, reload, ctx, show }: { a: AssetCard; tech: Tech | null; err: string; reload: () => void; ctx: Ctx; show: (t: string, tone?: "ok" | "error") => void }) {
  const { can } = useInv();
  const [linking, setLinking] = useState(false);
  const [src, setSrc] = useState(a.ksc_source_id ?? ctx.current?.id ?? ""); const [q, setQ] = useState(a.hostname || a.name);
  const [hosts, setHosts] = useState<{ host_id: number; name: string; os: string; ip: string; asset_id: number | null }[]>([]);
  useEffect(() => { if (!linking || !src) return; const t = window.setTimeout(() => inv.kscHosts({ source: src, q, unlinked: false, limit: 30 }).then((r) => setHosts(r.items)).catch(() => setHosts([])), 250); return () => window.clearTimeout(t); }, [linking, src, q]);
  const link = async (sid: string | null, hid: number | null) => { try { await inv.link(a.id, sid, hid); show(sid ? "Связь с компьютером KSC сохранена" : "Связь снята"); setLinking(false); reload(); } catch (e) { show((e as ApiError).message, "error"); } };
  const isComp = ["workstation", "laptop", "server", "vm"].includes(a.cls);
  const linkUi = linking && <div className="card inv-link">
    <h3 className="vdb-h">Связать с компьютером KSC</h3>
    <div className="row wrap"><label className="field">Источник<select value={src} onChange={(e) => setSrc(e.target.value)}>{ctx.sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
      <label className="field grow">Имя компьютера<input value={q} onChange={(e) => setQ(e.target.value)} /></label></div>
    <ul className="inv-asearch-list">{hosts.map((h) => <li key={h.host_id}><button type="button" disabled={!!h.asset_id && h.asset_id !== a.id} onClick={() => void link(src, h.host_id)}><b>{h.name}</b><span className="sub">{[h.os, h.ip].filter(Boolean).join(" · ")}</span>{h.asset_id && h.asset_id !== a.id && <span className="badge">уже связан</span>}</button></li>)}
      {!hosts.length && <li className="muted small inv-pop-empty">Компьютеры не найдены</li>}</ul>
    <button className="btn mini ghost" onClick={() => setLinking(false)}>Отмена</button></div>;
  if (!a.ksc_host_id) return <>
    <div className="card"><Empty icon="monitor" title={isComp ? "Карточка не связана с компьютером KSC" : "Технические сведения не собираются"}
      action={can("edit") && !linking ? <button className="btn primary" onClick={() => setLinking(true)}>Связать с компьютером KSC</button> : undefined}>
      {isComp ? "После связи здесь появятся процессор, память, накопители, сеть, установленное ПО и владелец по BI — из уже собранных данных KAV Checker." : "Для мониторов, принтеров и периферии учитываются только учётные сведения."}</Empty></div>
    {linkUi}</>;
  return (
    <div className="stack">
      <div className="row wrap inv-tech-line">
        <span className="muted small">Источник: <b>{a.ksc_source || "—"}</b> · компьютер KSC <b>{a.ksc_name}</b> (id {a.ksc_host_id}) · {a.ksc_link === "confirmed" ? "связь подтверждена" : a.ksc_link === "auto" ? "связь предполагается по имени" : "компьютер больше не найден в KSC"}</span>
        <div className="spacer" />
        {a.ksc_source_ok && <Link className="btn mini" to={`/hosts/${a.ksc_host_id}`} onClick={() => ctx.setScope(a.ksc_source_id!)}><Icon name="external" size={14} />Техническая карточка</Link>}
        {a.ksc_link === "auto" && can("edit") && <button className="btn mini primary" onClick={() => void link(a.ksc_source_id, a.ksc_host_id)}>Подтвердить связь</button>}
        {can("edit") && <button className="btn mini ghost" onClick={() => setLinking(true)}>Изменить</button>}
        {can("edit") && <button className="btn mini ghost" onClick={() => void link(null, null)}>Снять связь</button>}
      </div>
      {linkUi}
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!tech && !err && <div className="card"><SkelRows rows={5} cols={3} /></div>}
      {tech?.error && <div className="alert flat warn"><Icon name="alert" /><div className="alert-body">{tech.error}{tech.prepared && " Ниже — сведения из подготовленных данных."}</div></div>}
      {tech?.missing && <div className="alert flat warn"><Icon name="alert" /><div className="alert-body">Компьютер не найден в KSC: он удалён или перенесён. Карточка сохранена; при необходимости свяжите её с новой записью.</div></div>}
      {tech?.issues && tech.issues.length > 0 && <div className="alert flat warn"><Icon name="alert" /><div className="alert-body"><b>Расхождения с учётной карточкой</b><ul className="reasons">{tech.issues.map((i) => <li key={i}>{i}</li>)}</ul><span className="muted small">Автоматически не исправляются: решите, какое значение верно.</span></div></div>}
      {tech && (tech.hw || tech.prepared) && <div className="split even">
        <div className="card"><h2>Система</h2>
          <Kv rows={[["Имя", tech.host?.name || tech.prepared?.name], ["FQDN", tech.host?.fqdn], ["ОС", tech.host?.os || tech.prepared?.os], ["IP-адрес", tech.prepared?.ip && <span className="mono">{tech.prepared.ip}</span>],
            ["Группа KSC", tech.prepared?.group], ["Подключение к KSC", fmt(tech.host?.last_connected ?? tech.prepared?.last_connected)], ["Плата / BIOS", tech.hw?.board ? `${tech.hw.board.manuf} ${tech.hw.board.board} ${tech.hw.board.bios_version}`.trim() : ""],
            ["Серийный номер (KSC)", tech.ids?.board_serial && <span className="mono">{tech.ids.board_serial}</span>], ["MAC-адреса", tech.ids?.macs?.length ? <span className="mono small">{tech.ids.macs.join(", ")}</span> : ""],
            ["Владелец по BI", tech.bi_owner ? `${tech.bi_owner.name}${tech.bi_owner.department ? `, ${tech.bi_owner.department}` : ""} (${tech.bi_owner.state_ru})` : ""]]} />
          <p className="muted small">Сведения KSC — только чтение{tech.fetched_at ? `, получены ${fmt(tech.fetched_at)}` : ""}.</p></div>
        {tech.hw && <div className="card"><h2>Аппаратная часть {tech.hw.virtual && <span className="badge">виртуальная машина</span>}</h2>
          {!tech.hw.known ? <p className="muted">Агент не передавал сведений об оборудовании.</p> : <>
            <Kv rows={[["Процессор", tech.hw.cpus.map((c) => `${c.name}${c.cores ? `, ${c.cores} ядер` : ""}`).join("; ")], ["Оперативная память", tech.hw.ram_mb ? `${Math.round(tech.hw.ram_mb / 1024)} ГБ (${tech.hw.ram_modules.length} мод.)` : ""],
              ["Накопители", tech.hw.disks.map((d) => `${d.name}${d.total_gb ? ` — ${d.total_gb} ГБ` : ""}`).join("; ")], ["Сетевые адаптеры", tech.hw.nics.map((n) => n.name).join("; ")],
              ...tech.hw.other.map((o) => [o.type, o.name] as [string, string])]} /></>}
        </div>}
      </div>}
    </div>
  );
}

function SoftTab({ a, tech, err }: { a: AssetCard; tech: Tech | null; err: string }) {
  const [q, setQ] = useState("");
  const sw = (tech?.software ?? []).filter((s) => !q || `${s.name} ${s.publisher}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="stack">
      <div className="card"><div className="card-head"><h2>Лицензии</h2><div className="spacer" /><Link className="btn mini" to="/inventory/licenses">Все лицензии</Link></div>
        {a.licenses.length ? <ul className="inv-list">{a.licenses.map((l) => <li key={l.assign_id}><Link to={`/inventory/licenses/${l.id}`}>{l.name}</Link><span className="muted small">назначена {fmtDate(l.at)}, {l.by}</span></li>)}</ul> : <p className="muted small">Лицензии не назначены.</p>}</div>
      <div className="card flush"><div className="card-head"><h2>Установленное ПО (KSC)</h2><div className="spacer" />{tech?.software && <div className="input-icon w-search"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Программа или производитель" aria-label="Фильтр программ" /></div>}</div>
        {!a.ksc_host_id ? <p className="muted small pad">Карточка не связана с компьютером KSC.</p> : err ? <p className="field-err pad">{err}</p> : !tech ? <SkelRows rows={4} cols={3} /> : !tech.software ? <p className="muted small pad">{tech.error ?? "Нет сведений."}</p> :
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Программа</th><th>Версия</th><th className="hide-sm">Производитель</th><th className="hide-sm">Установлена</th></tr></thead>
            <tbody>{sw.slice(0, 1500).map((s, i) => <tr key={i}><td>{s.name}</td><td className="mono small">{s.version}</td><td className="hide-sm small">{s.publisher}</td><td className="hide-sm nowrap small">{fmtDate(s.install_date)}</td></tr>)}</tbody></table></div>}
      </div>
    </div>
  );
}

function PartsTab({ a, reload, show }: { a: AssetCard; reload: () => void; show: (t: string, tone?: "ok" | "error") => void }) {
  const { meta, can } = useInv();
  const attach = async (child: Asset) => {
    try { const c = await inv.asset(child.id); await inv.update(child.id, { parent_id: a.id }, c.version, `в составе ${a.inv_no}`); show(`${child.inv_no} добавлено в состав`); reload(); } catch (e) { show((e as ApiError).message, "error"); }
  };
  const detach = async (child: Asset) => { try { await inv.update(child.id, { parent_id: null }, child.version, `снято с ${a.inv_no}`); show("Связь снята"); reload(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <div className="stack">
      {a.parent_id && <div className="card"><h2>Входит в</h2><p><Link to={`/inventory/assets/${a.parent_id}`}>{a.parent}</Link> <span className="muted">({a.rel_ru || meta.rels[a.rel] || "связь"})</span></p></div>}
      <div className="card flush"><div className="card-head"><h2>Состав и подключённые единицы</h2></div>
        {a.children.length ? <div className="table-scroll"><table className="table compact"><thead><tr><th>Инв. номер</th><th>Наименование</th><th>Связь</th><th>Статус</th><th /></tr></thead><tbody>
          {a.children.map((c) => <tr key={c.id}><td><Link to={`/inventory/assets/${c.id}`} className="mono">{c.inv_no}</Link></td><td>{shortLabel(c)}<span className="sub">{c.serial}</span></td><td className="small">{c.rel_ru}</td><td><StBadge st={c.st_cls} label={c.status} /></td>
            <td>{can("edit") && <button className="btn mini ghost" onClick={() => void detach(c)}>Снять</button>}</td></tr>)}</tbody></table></div> : <p className="muted small pad">Связанных единиц нет. Добавьте монитор, док-станцию, комплектующие или виртуальные машины физического сервера.</p>}
        {can("edit") && <div className="pad"><AssetSearch onPick={(x) => void attach(x)} exclude={[a.id, ...a.children.map((c) => c.id)]} placeholder="Добавить в состав: номер или название" /></div>}
      </div>
    </div>
  );
}

function DocsTab({ a }: { a: AssetCard }) {
  return a.docs.length ? <div className="card flush"><div className="table-scroll"><table className="table compact"><thead><tr><th>Документ</th><th>Вид</th><th>Дата</th><th>Этап</th></tr></thead>
    <tbody>{a.docs.map((d) => <tr key={d.id}><td><Link to={`/inventory/docs/${d.id}`} className="mono">{d.no}</Link></td><td>{d.kind_ru}</td><td className="nowrap">{fmtDate(d.date)}</td><td><span className={`badge ${d.status === "done" ? "ok" : d.status === "cancelled" ? "" : "accent"}`}>{d.status_ru}</span></td></tr>)}</tbody></table></div></div>
    : <div className="card"><Empty icon="file" title="Документов нет">Выдачи, возвраты, перемещения и ремонты этой единицы появятся здесь.</Empty></div>;
}

function HistoryTab({ a }: { a: AssetCard }) {
  const [items, setItems] = useState<Hist[] | null>(null); const [err, setErr] = useState("");
  const [on, setOn] = useState(""); const [asof, setAsof] = useState<{ exists: boolean; state: Record<string, string> | null; note?: string; event?: Hist } | null>(null);
  const [kind, setKind] = useState("");
  useEffect(() => { inv.history(a.id).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); }, [a.id, a.version]);
  useEffect(() => { if (!on) { setAsof(null); return; } inv.asof(a.id, on).then(setAsof).catch(() => setAsof(null)); }, [a.id, on]);
  const shown = (items ?? []).filter((h) => !kind || (kind === "people" ? h.changes.some((c) => c.f.endsWith("_id") && ["user_id", "owner_id", "resp_id", "mol_id", "it_id"].includes(c.f)) : kind === "move" ? h.changes.some((c) => c.f === "location_id") || h.kind === "move" : h.kind === kind));
  return (
    <div className="stack">
      <div className="card inv-asof">
        <div className="row wrap"><label className="field">Состояние на дату<input type="date" value={on} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setOn(e.target.value)} /></label>
          {asof && (asof.exists && asof.state ? <Kv rows={[["Статус", asof.state.status], ["Местоположение", asof.state.location], ["Пользователь", asof.state.user], ["Владелец", asof.state.owner], ["Ответственный", asof.state.resp], ["МОЛ", asof.state.mol]]} />
            : <p className="muted">{asof.note}</p>)}</div>
      </div>
      <div className="row wrap tight">{([["", "Все события"], ["people", "Принадлежность"], ["move", "Перемещения"], ["doc", "Документы"], ["repair", "Ремонты"], ["link", "Связь с KSC"]] as [string, string][]).map(([k, v]) =>
        <button key={k} type="button" className={`chip ${kind === k ? "on" : ""}`} aria-pressed={kind === k} onClick={() => setKind(k)}>{v}</button>)}</div>
      {err && <p className="field-err">{err}</p>}
      {!items ? <div className="card"><SkelRows rows={5} cols={2} /></div> : (
        <ol className="inv-timeline">{shown.map((h) => (
          <li key={h.id} className={`k-${h.kind}`}>
            <div className="inv-tl-head"><b>{h.title}</b>{h.doc_id && <Link to={`/inventory/docs/${h.doc_id}`} className="mono small">{h.doc_no || "документ"}</Link>}<span className="muted small">{fmt(h.at)} · {h.by}</span></div>
            {h.changes.length > 0 && <ul className="inv-tl-ch">{h.changes.map((c, i) => <li key={i}><span className="muted">{c.label}:</span> <s>{c.old || "—"}</s> → <b>{c.new || "—"}</b></li>)}</ul>}
            {(h.basis || h.comment) && <p className="small muted">{[h.basis && `Основание: ${h.basis}`, h.comment].filter(Boolean).join(" · ")}</p>}
          </li>))}
          {!shown.length && <li className="muted">Событий нет.</li>}</ol>)}
    </div>
  );
}

function FilesTab({ a, reload, show }: { a: AssetCard; reload: () => void; show: (t: string, tone?: "ok" | "error") => void }) {
  const { can } = useInv(); const ref = useRef<HTMLInputElement>(null);
  const up = async (f: File | undefined) => { if (!f) return; try { await inv.upload("asset", a.id, f); show("Файл добавлен"); reload(); } catch (e) { show((e as ApiError).message, "error"); } };
  const del = async (id: number) => { if (!window.confirm("Удалить вложение?")) return; try { await inv.delFile(id); reload(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <div className="card">
      <div className="card-head"><h2>Вложения</h2><div className="spacer" />{can("edit") && <><input ref={ref} type="file" hidden onChange={(e) => void up(e.target.files?.[0])} /><button className="btn mini" onClick={() => ref.current?.click()}><Icon name="upload" size={14} />Добавить файл</button></>}</div>
      {a.files.length ? <ul className="inv-list">{a.files.map((f) => <li key={f.id}><a href={inv.fileUrl(f.id)}>{f.name}</a><span className="muted small">{num(Math.round(f.size / 1024))} КБ · {fmtDate(f.at)} · {f.by}</span>
        {can("edit") && <button className="btn mini ghost icon" aria-label={`Удалить ${f.name}`} onClick={() => void del(f.id)}><Icon name="trash" size={14} /></button>}</li>)}</ul>
        : <p className="muted small">Документы приобретения, сканы актов, фотографии — до 15 МБ на файл. Файлы хранятся в базе и попадают в резервные копии.</p>}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ форма
type Form = Record<string, unknown>;
const toForm = (a: Partial<Asset>): Form => ({ ...a, cost: a.cost !== null && a.cost !== undefined ? (a.cost / 100).toFixed(2).replace(".", ",") : "", props: { ...(a.props ?? {}) } });
const EDITABLE = ["purpose", "service", "rack_unit", "rack_units", "no_count", "inv_no", "acc_no", "serial", "name", "hostname", "type_id", "model_id", "manufacturer_id", "status_id", "location_id", "loc_detail", "user_id", "owner_id", "resp_id", "mol_id", "it_id", "dept_id", "branch_id", "zone_id", "tags",
  "purchase_date", "received_date", "commissioned_date", "warranty_until", "cost", "supplier_id", "purchase_doc", "note", "props", "parent_id", "rel"];

export function AssetForm({ initial, onCancel, onSaved }: { initial: Partial<AssetCard>; onCancel: () => void; onSaved: (a: AssetCard, more?: boolean) => void }) {
  const { meta, can } = useInv();
  const creating = !initial.id;
  const [f, setF] = useState<Form>(() => toForm(initial));
  const [names, setNames] = useState<Record<string, string>>(() => Object.fromEntries(PEOPLE.map(([k]) => [k, String((initial as Record<string, unknown>)[k.replace("_id", "")] ?? "")])));
  const [errors, setErrors] = useState<Record<string, string>>({}); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState(""); const [dup, setDup] = useState<number | null>(null);
  const [comment, setComment] = useState("");
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const cls = (refsOf(meta, "type").find((r) => r.id === f.type_id)?.data.cls as string) ?? initial.cls ?? "";
  const props = meta.props.filter((p) => p.active && (!p.type_ids.length || (typeof f.type_id === "number" && p.type_ids.includes(f.type_id))));
  const canF = (k: string) => creating || (k === "location_id" || k === "loc_detail" ? can("location") : PEOPLE.some(([p]) => p === k) ? can("people") : can("edit"));
  const save = async (more = false, force = false) => {
    setBusy(true); setErrors({}); setMsg(""); setDup(null);
    const data: Form = {};
    for (const k of EDITABLE) {
      if (!canF(k)) continue;
      const v = f[k]; const old = (initial as Record<string, unknown>)[k];
      if (creating ? v !== undefined && v !== "" && v !== null : JSON.stringify(v ?? null) !== JSON.stringify(k === "cost" ? toForm(initial).cost : k === "props" ? initial.props ?? {} : old ?? null)) data[k] = v === "" ? null : v;
    }
    if (creating && !data.type_id) { setErrors({ type_id: "Выберите тип оборудования" }); setBusy(false); return; }
    try {
      const r = creating ? await inv.create(data, comment, force) : await inv.update(initial.id!, data, initial.version!, comment);
      if (more) { setF((x) => ({ ...x, serial: "", inv_no: "", hostname: "", acc_no: "" })); setMsg(`Создана карточка ${r.inv_no}. Заполните следующую — остальные поля сохранены.`); }
      onSaved(r, more);
    } catch (e) {
      if (e instanceof FieldError) { setErrors(e.errors); setMsg(e.message); }
      else { const d = (e as ApiError & { duplicate?: number }).duplicate; if (d) setDup(d); setMsg((e as ApiError).message); }
    } finally { setBusy(false); }
  };
  const E = (k: string) => errors[k];
  const person = (k: string, lb: string) => <PersonPicker key={k} label={lb} value={f[k] as number | null} name={names[k]} disabled={!canF(k)} error={E(k)} onChange={(id, nm) => { set(k, id); setNames((x) => ({ ...x, [k]: nm })); }} />;
  return (
    <form className="inv-form" onSubmit={(e) => { e.preventDefault(); void save(); }} noValidate>
      {msg && <div className={`alert flat ${Object.keys(errors).length || dup ? "error" : "ok"}`} role="alert"><Icon name={Object.keys(errors).length || dup ? "alert" : "checkCircle"} /><div className="alert-body">{msg}
        {dup && <div className="row"><Link to={`/inventory/assets/${dup}`}>Открыть существующую карточку</Link><button type="button" className="btn mini" onClick={() => void save(false, true)}>Всё равно создать</button></div>}</div></div>}
      <fieldset className="inv-fs"><legend>Основное</legend><div className="inv-grid">
        <RefSelect kind="type" label="Тип" required value={f.type_id as number | null} onChange={(v) => set("type_id", v)} error={E("type_id")} disabled={!canF("type_id")} />
        <RefSelect kind="manufacturer" label="Производитель" value={f.manufacturer_id as number | null} onChange={(v) => { set("manufacturer_id", v); set("model_id", null); }} disabled={!canF("manufacturer_id")} />
        <RefSelect kind="model" label="Модель" parent={f.manufacturer_id as number | null} value={f.model_id as number | null} onChange={(v) => set("model_id", v)} disabled={!canF("model_id")} empty={f.manufacturer_id ? "—" : "сначала производитель"} />
        <label className={`field ${E("name") ? "invalid" : ""}`}>Наименование<input value={String(f.name ?? "")} onChange={(e) => set("name", e.target.value)} maxLength={300} disabled={!canF("name")} placeholder="например, «Ноутбук бухгалтера»" /></label>
        <label className={`field ${E("inv_no") ? "invalid" : ""}`}>Инвентарный номер<input className="mono" value={String(f.inv_no ?? "")} onChange={(e) => set("inv_no", e.target.value)} maxLength={60} disabled={!canF("inv_no")} placeholder={creating ? `автоматически (${meta.settings.inv_prefix}…)` : ""} />{E("inv_no") && <span className="field-err">{E("inv_no")}</span>}</label>
        <label className="field">Бухгалтерский номер<input className="mono" value={String(f.acc_no ?? "")} onChange={(e) => set("acc_no", e.target.value)} maxLength={60} disabled={!canF("acc_no")} /></label>
        <label className={`field ${E("serial") ? "invalid" : ""}`}>Серийный номер<input className="mono" value={String(f.serial ?? "")} onChange={(e) => set("serial", e.target.value)} maxLength={120} disabled={!canF("serial")} /></label>
        {["workstation", "laptop", "server", "vm"].includes(cls) && <label className="field">Имя компьютера<input className="mono" value={String(f.hostname ?? "")} onChange={(e) => set("hostname", e.target.value)} maxLength={255} disabled={!canF("hostname")} placeholder="как в KSC, без домена" /></label>}
        <RefSelect kind="status" label="Статус" value={f.status_id as number | null} onChange={(v) => set("status_id", v)} disabled={!canF("status_id")} empty={creating ? "«На складе»" : "—"} error={E("status_id")} />
        {["server", "vm", "network", "storage"].includes(cls) && <><label className="field wide">Назначение<input value={String(f.purpose ?? "")} onChange={(e) => set("purpose", e.target.value)} maxLength={500} disabled={!canF("purpose")} placeholder="для чего используется" /></label>
          <label className="field">Сервис или система<input value={String(f.service ?? "")} onChange={(e) => set("service", e.target.value)} maxLength={300} disabled={!canF("service")} /></label></>}
        <label className="check-row"><input type="checkbox" checked={!!f.no_count} onChange={(e) => set("no_count", e.target.checked)} disabled={!canF("no_count")} />Не подлежит инвентаризации</label>
        <div className={`field ${E("tags") ? "invalid" : ""}`}><span className="field-label">Теги</span>
          {canF("tags") ? <TagInput label="Теги" value={(f.tags as string[] | undefined) ?? []} onChange={(v) => set("tags", v)} mono={false} /> : <span>{((f.tags as string[] | undefined) ?? []).join(", ")}</span>}
          {E("tags") && <span className="field-err">{E("tags")}</span>}</div>
      </div></fieldset>
      <fieldset className="inv-fs"><legend>Расположение</legend><div className="inv-grid">
        <LocationPicker label="Местоположение" value={f.location_id as number | null} onChange={(v) => set("location_id", v)} error={E("location_id")} disabled={!canF("location_id")} />
        {["server", "network", "storage"].includes(cls) && <><label className="field">Юнит в стойке (нижний)<input type="number" min={1} max={60} value={String(f.rack_unit ?? "")} onChange={(e) => set("rack_unit", e.target.value)} disabled={!canF("rack_unit")} /></label>
          <label className="field">Высота, юнитов<input type="number" min={1} max={60} value={String(f.rack_units ?? "")} onChange={(e) => set("rack_units", e.target.value)} disabled={!canF("rack_units")} /></label></>}
        <label className="field">Уточнение<input value={String(f.loc_detail ?? "")} onChange={(e) => set("loc_detail", e.target.value)} maxLength={300} disabled={!canF("loc_detail")} placeholder="стол у окна, юнит 12…" /></label>
        <RefSelect kind="branch" label="Филиал" value={f.branch_id as number | null} onChange={(v) => set("branch_id", v)} disabled={!canF("branch_id")} />
        <RefSelect kind="dept" label="Подразделение" value={f.dept_id as number | null} onChange={(v) => set("dept_id", v)} disabled={!canF("dept_id")} />
        <InvZoneSelect value={f.zone_id as string | null | undefined} onChange={(v) => set("zone_id", v)} disabled={!canF("zone_id")} error={E("zone_id")} />
      </div></fieldset>
      <fieldset className="inv-fs"><legend>Ответственные лица</legend><div className="inv-grid">{PEOPLE.map(([k, lb]) => person(k, lb))}</div></fieldset>
      <fieldset className="inv-fs"><legend>Приобретение и гарантия</legend><div className="inv-grid">
        {(["purchase_date", "received_date", "commissioned_date", "warranty_until"] as const).map((k) => <label key={k} className={`field ${E(k) ? "invalid" : ""}`}>{{ purchase_date: "Дата приобретения", received_date: "Дата поступления", commissioned_date: "Ввод в эксплуатацию", warranty_until: "Гарантия до" }[k]}
          <input type="date" value={String(f[k] ?? "")} onChange={(e) => set(k, e.target.value)} disabled={!canF(k)} />{E(k) && <span className="field-err">{E(k)}</span>}</label>)}
        <label className={`field ${E("cost") ? "invalid" : ""}`}>Стоимость, ₽<input inputMode="decimal" value={String(f.cost ?? "")} onChange={(e) => set("cost", e.target.value)} disabled={!canF("cost")} placeholder="0,00" />{E("cost") && <span className="field-err">{E("cost")}</span>}</label>
        <RefSelect kind="supplier" label="Поставщик" value={f.supplier_id as number | null} onChange={(v) => set("supplier_id", v)} disabled={!canF("supplier_id")} />
        <label className="field">Документ приобретения<input value={String(f.purchase_doc ?? "")} onChange={(e) => set("purchase_doc", e.target.value)} maxLength={300} disabled={!canF("purchase_doc")} placeholder="счёт, накладная, договор" /></label>
      </div></fieldset>
      {props.length > 0 && <fieldset className="inv-fs"><legend>Дополнительные свойства</legend><div className="inv-grid">
        {props.map((p) => <PropField key={p.code} p={p} value={(f.props as Record<string, unknown>)[p.code]} error={E(`props.${p.code}`)} onChange={(v) => set("props", { ...(f.props as Record<string, unknown>), [p.code]: v })} />)}</div></fieldset>}
      <fieldset className="inv-fs"><legend>Примечание</legend>
        <label className="field wide"><span className="sr-only">Примечание</span><textarea rows={3} value={String(f.note ?? "")} onChange={(e) => set("note", e.target.value)} disabled={!canF("note")} placeholder="Любые сведения, для которых нет отдельного поля" /></label>
        {!creating && <label className="field wide">Основание изменения<input value={comment} onChange={(e) => setComment(e.target.value)} maxLength={2000} placeholder="попадёт в историю карточки" /></label>}
      </fieldset>
      <div className="inv-form-foot"><button type="button" className="btn" onClick={onCancel}>Отмена</button><div className="spacer" />
        {creating && <button type="button" className="btn" disabled={busy} onClick={() => void save(true)}>Сохранить и добавить ещё</button>}
        <button type="submit" className="btn primary" disabled={busy} aria-busy={busy}>{creating ? "Создать карточку" : "Сохранить"}</button></div>
    </form>
  );
}

export function AssetNew() {
  const nav = useNavigate(); const [sp] = useSearchParams();
  const { meta } = useInv();
  const initial = useMemo<Partial<AssetCard>>(() => {
    const t = sp.get("cls") ? refsOf(meta, "type").find((r) => r.data.cls === sp.get("cls"))?.id ?? null : null;
    return { type_id: t, location_id: sp.get("location") ? Number(sp.get("location")) : null, parent_id: sp.get("parent") ? Number(sp.get("parent")) : null, props: {} };
  }, [sp, meta]);
  return (
    <div className="inv-page">
      <BackLink to="/inventory/assets" label="Оборудование" />
      <div className="inv-head"><h1>Новая учётная единица</h1></div>
      <AssetForm initial={initial} onCancel={() => nav(-1)} onSaved={(a, more) => { if (!more) nav(`/inventory/assets/${a.id}`, { replace: true }); }} />
    </div>
  );
}

function InfraTab({ a }: { a: AssetCard }) {
  const [d, setD] = useState<AssetInfra | null>(null); const [err, setErr] = useState("");
  useEffect(() => { inv.assetInfra(a.id).then(setD).catch((e) => setErr((e as ApiError).message)); }, [a.id, a.version]);
  if (err) return <p className="field-err">{err}</p>;
  if (!d) return <div className="card"><SkelRows rows={5} cols={3} /></div>;
  if (!d.objects.length) return <div className="card"><Empty icon="server" title="Нет сведений источников" action={<Link className="btn" to="/inventory/infra?tab=objects">Объекты источников</Link>}>Объект ещё не сопоставлен ни с одним источником (мониторинг, виртуализация, реестр инфраструктуры). Сопоставить можно во вкладке «Объекты источников».</Empty></div>;
  const open = d.findings.filter((f) => ["attention", "review", "fixing"].includes(f.status));
  return (
    <div className="stack">
      {open.length > 0 && <div className="alert flat warn"><Icon name="alert" /><div className="alert-body"><b>Открытые расхождения</b><ul className="reasons">{open.map((f) => <li key={f.id}>{f.title}{f.found && ` — ${f.found}`} <span className="muted small">({f.status_ru})</span></li>)}</ul></div></div>}
      <div className="split">
        <div className="card flush"><div className="card-head"><h2>Сведения по приоритету источников</h2></div>
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Поле</th><th>Значение</th><th>Источник</th><th className="hide-sm">Другие источники</th></tr></thead>
            <tbody>{d.resolved.map((r) => <tr key={r.attr}><td className="small">{r.label}</td><td>{r.value}</td><td className="small">{r.source}<span className="sub">{fmt(r.at)}</span></td>
              <td className="hide-sm small">{r.conflicts.length ? <span className="warn-text">{r.conflicts.map((c) => `${c.source}: ${c.value}`).join("; ")}</span> : <span className="muted">совпадают</span>}</td></tr>)}</tbody></table></div></div>
        <div className="card flush"><div className="card-head"><h2>Объекты источников ({d.objects.length})</h2></div>
          <ul className="inv-list pad">{d.objects.map((o) => <li key={o.id}><b>{o.name}</b><span className="small">{o.source} · {o.kind_ru}</span>{!o.present && <span className="badge">нет в источнике</span>}<span className="muted small">{o.match === "confirmed" ? "подтверждено" : `автоматически: ${o.match_basis}`}</span></li>)}</ul></div>
      </div>
      <div className="card flush"><div className="card-head"><h2>История конфигурации</h2></div>
        {d.changes.length ? <div className="table-scroll"><table className="table compact"><thead><tr><th>Когда</th><th>Объект</th><th>Поле</th><th>Было → стало</th></tr></thead>
          <tbody>{d.changes.map((c, i) => <tr key={i}><td className="nowrap small">{fmt(c.at)}</td><td className="small">{c.object}</td><td className="small">{c.label}</td><td className="small"><s>{c.old || "—"}</s> → <b>{c.new || "—"}</b></td></tr>)}</tbody></table></div>
          : <p className="muted small pad">Изменений не было с первой синхронизации.</p>}</div>
    </div>
  );
}
