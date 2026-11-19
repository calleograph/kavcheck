/** Серверная и сетевая инфраструктура: обзор (показатели открывают списки), объекты источников и сопоставление с учётом, расхождения с решениями,
 *  источники (проверка соединения, синхронизация, выгрузки), IP-адреса, стойки. Внешние системы только читаются. */
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { ApiError } from "../../api";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { CheckAll, useRowSel } from "../../components/QuickReport";
import { useToast } from "../../components/Toast";
import { Empty, Segmented, SkelRows, Tabs } from "../../components/ui";
import { fmt, fmtDate, num } from "../../util";
import { AssetSearch, LocationPicker, PersonPicker, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { Netscan } from "./InvNetscan";
import { inv, type InfraFinding, type InfraObject, type InfraOverview, type InfraSource, type Rack } from "./invApi";

type Tab = "overview" | "objects" | "findings" | "sources" | "ips" | "racks" | "netscan";
const SEV: Record<string, string> = { high: "err", medium: "warn", low: "" };
const ST_TONE: Record<string, string> = { attention: "err", review: "warn", fixing: "accent", confirmed: "", fixed: "ok", exception: "" };
const MATCH_RU: Record<string, string> = { confirmed: "подтверждено", auto: "автоматически", ambiguous: "неоднозначно", none: "нет в учёте", rejected: "не связывать" };

export default function InvInfra() {
  const [sp, setSp] = useSearchParams();
  const tab = ((["overview", "objects", "findings", "sources", "ips", "racks", "netscan"] as Tab[]).includes(sp.get("tab") as Tab) ? sp.get("tab") : "overview") as Tab;
  const go = (t: Tab, extra: Record<string, string> = {}) => setSp(() => { const p = new URLSearchParams({ tab: t, ...extra }); if (t === "overview") p.delete("tab"); return p; });
  const rep = useInvReport();
  const [toast, show] = useToast();
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Инфраструктура</h1>
        <button className="btn" onClick={() => rep.open(["infra_registry", "infra_hypervisors", "infra_ips", "infra_racks", "infra_findings", "infra_changes", "infra_new_gone", "infra_sync", "infra_decom", "infra_asof", "infra_review", "infra_netscan"], {}, "Серверная и сетевая инфраструктура")}><Icon name="download" size={16} />Отчёт</button></div>
      <Tabs<Tab> label="Инфраструктура" value={tab} onChange={(t) => go(t)} items={[{ id: "overview", label: "Обзор" }, { id: "findings", label: "Расхождения" }, { id: "objects", label: "Объекты источников" },
        { id: "ips", label: "IP-адреса" }, { id: "racks", label: "Стойки" }, { id: "netscan", label: "Сетевое обнаружение" }, { id: "sources", label: "Источники" }]} />
      {tab === "overview" && <Overview go={go} />}
      {tab === "findings" && <Findings show={show} rep={rep.open} />}
      {tab === "objects" && <Objects show={show} />}
      {tab === "sources" && <Sources show={show} />}
      {tab === "ips" && <Ips />}
      {tab === "racks" && <Racks />}
      {tab === "netscan" && <Netscan show={show} report={(params) => rep.open(["infra_netscan"], params)} />}
      {rep.node}{toast}
    </div>
  );
}

function Overview({ go }: { go: (t: Tab, x?: Record<string, string>) => void }) {
  const [site, setSite] = useState<number | null>(null); const [resp, setResp] = useState<number | null>(null); const [rname, setRname] = useState("");
  const [d, setD] = useState<InfraOverview | null>(null); const [err, setErr] = useState("");
  useEffect(() => { inv.infraOverview({ site, resp }).then(setD).catch((e) => setErr((e as ApiError).message)); }, [site, resp]);
  if (err) return <p className="field-err">{err}</p>;
  if (!d) return <div className="card"><SkelRows rows={4} cols={4} /></div>;
  const c = d.counts, f = d.findings;
  const link = (to: string, l: string, v: number, t = "", tone = "") => <div className="meter"><Link className="meter-link" to={to}><span className="l">{l}</span><span className={`v ${tone}`}>{num(v)}</span>{t && <span className="t">{t}</span>}</Link></div>;
  const fb = (code: string, l: string, t = "") => <div className="meter"><button type="button" className="meter-link" onClick={() => go("findings", { code })}><span className="l">{l}</span><span className={`v ${f[code] ? "warn-text" : ""}`}>{num(f[code] ?? 0)}</span>{t && <span className="t">{t}</span>}</button></div>;
  return (
    <div className="stack">
      <div className="row wrap inv-infra-filter"><LocationPicker label="Площадка или здание" value={site} onChange={setSite} placeholder="все" /><PersonPicker label="Ответственный" value={resp} name={rname} onChange={(id, n) => { setResp(id); setRname(n); }} /></div>
      {!d.sources.length && <div className="card"><Empty icon="database" title="Источники не подключены" action={<button className="btn primary" onClick={() => go("sources")}>Подключить источник</button>}>
        Подключите мониторинг, системы виртуализации и реестр инфраструктуры: сведения о серверах и ВМ будут поступать автоматически, а работа сведётся к разбору расхождений.</Empty></div>}
      <div className="meters">
        {link("/inventory/assets?cls=server&st=active", "Физические серверы", c.server)}{link("/inventory/assets?cls=vm&st=active", "Виртуальные машины", c.vm)}
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("objects", { kind: "server" })}><span className="l">Хосты виртуализации · кластеры</span><span className="v">{num(c.hypervisors)} · {num(c.clusters)}</span></button></div>
        {link("/inventory/assets?cls=network&st=active", "Сетевое оборудование", c.network)}
        {link("/inventory/locations", "Площадки и серверные", c.sites)}
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("objects", { kind: "resource" })}><span className="l">Внешние ресурсы</span><span className="v">{num(c.resources)}</span></button></div>
        {link("/inventory/assets?cls=server,vm,network,storage&st=use", "Активных", c.active)}{link("/inventory/assets?cls=server,vm,network,storage&st=decom,writeoff", "Выведено из эксплуатации", c.decom)}
      </div>
      <h2 className="vdb-h">Контроль</h2>
      <div className="meters">
        {fb("no_monitoring", "Без мониторинга", "серверы и ВМ")}{fb("no_backup", "Без резервного копирования")}{fb("no_admin", "Без ответственного")}{fb("not_registered", "Нет в учёте", "есть в источнике")}
        {fb("unavailable", "Недоступны", "по данным мониторинга")}{fb("gone", "Исчезли из источников")}{fb("stale", "Устаревшие сведения")}
        <div className="meter"><button type="button" className="meter-link" onClick={() => go("findings")}><span className="l">Все открытые расхождения</span><span className={`v ${d.findings_total ? "warn-text" : ""}`}>{num(d.findings_total)}</span></button></div>
      </div>
      <div className="card flush"><div className="card-head"><h2>Источники</h2><div className="spacer" />{d.source_errors > 0 && <span className="badge err">с ошибкой: {d.source_errors}</span>}<button className="btn mini ghost" onClick={() => go("sources")}>Управление</button></div>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Источник</th><th>Тип</th><th>Последняя успешная синхронизация</th><th>Получено</th><th>Состояние</th></tr></thead>
          <tbody>{d.sources.map((s) => <tr key={s.id}><td>{s.name}</td><td className="small">{s.kind_ru}</td><td className="nowrap">{fmt(s.last_ok_at)}</td><td className="num">{num((s.last_stats.received as number | undefined) ?? null)}</td>
            <td>{!s.enabled ? <span className="badge">выключен</span> : s.last_error ? <span className="badge err" title={s.last_error}>ошибка</span> : s.last_ok_at ? <span className="badge ok">в порядке</span> : <span className="badge">ожидает</span>}</td></tr>)}</tbody></table></div></div>
    </div>
  );
}

function Findings({ show, rep }: { show: (t: string, tone?: "ok" | "error") => void; rep: (v: string[], p: Record<string, unknown>, l?: string) => void }) {
  const { can } = useInv();
  const [sp] = useSearchParams();
  const [status, setStatus] = useState("open"); const [code, setCode] = useState(sp.get("code") ?? ""); const [q, setQ] = useState("");
  const [d, setD] = useState<{ items: InfraFinding[]; total: number; codes: Record<string, string>; statuses: Record<string, string> } | null>(null);
  const sel = useRowSel<number>(); const [decide, setDecide] = useState<string | null>(null);
  const load = useCallback(() => inv.infraFindings({ status, code, q, limit: 1000 }).then(setD).catch((e) => show((e as ApiError).message, "error")), [status, code, q, show]);
  useEffect(() => { const t = window.setTimeout(load, 250); return () => window.clearTimeout(t); }, [load]);
  return (
    <div className="stack">
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Объект, адрес, описание", label: "Поиск расхождений" }}
        primary={<><Segmented label="Статус" value={status} onChange={setStatus} options={[["open", "Открытые"], ["exception", "Исключения"], ["fixed", "Устранённые"], ["", "Все"]]} />
          <label className="field inline"><span className="sr-only">Вид</span><select value={code} onChange={(e) => setCode(e.target.value)}><option value="">Все виды</option>{Object.entries(d?.codes ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label></>}
        count={{ n: d ? d.total : null, noun: ["расхождение", "расхождения", "расхождений"] }} onRefresh={() => void inv.infraReconcile().then(load)} report={{ onClick: () => rep(["infra_findings"], { code, status: status || "all" }, "Расхождения"), title: "Отчёт по расхождениям" }} />
      {!d ? <div className="card"><SkelRows rows={4} cols={5} /></div> : !d.items.length ? <div className="card"><Empty icon="check" title="Расхождений нет">Сверка выполняется после каждой синхронизации источников.</Empty></div> :
        <div className="table-scroll"><table className="table"><thead><tr>{can("edit") && <CheckAll all={sel.allOf(d.items.map((x) => x.id))} some={sel.someOf(d.items.map((x) => x.id))} onToggle={() => sel.toggleMany(d.items.map((x) => x.id))} />}
          <th>Расхождение</th><th>Объект</th><th className="hide-sm">Обнаружено · ожидалось</th><th className="hide-md">Рекомендация</th><th>Статус</th></tr></thead>
          <tbody>{d.items.map((f) => <tr key={f.id} className={sel.has(f.id) ? "sel" : ""}>
            {can("edit") && <td className="check"><input type="checkbox" aria-label={`Выбрать: ${f.title}`} checked={sel.has(f.id)} onChange={() => sel.toggle(f.id)} /></td>}
            <td><span className={`badge ${SEV[f.severity]}`}>{{ high: "высокая", medium: "средняя", low: "низкая" }[f.severity]}</span> {f.title}<span className="sub">{f.source}{f.source && " · "}с {fmtDate(f.first_seen)}</span></td>
            <td>{f.asset ? <Link to={`/inventory/assets/${f.asset_id}?tab=infra`} className="mono">{f.asset.inv_no}</Link> : <span className="muted small">нет в учёте</span>}{f.asset && <span className="sub">{f.asset.name}</span>}</td>
            <td className="hide-sm small">{f.found}{f.expected && <span className="sub">ожидалось: {f.expected}</span>}</td><td className="hide-md small">{f.action}</td>
            <td><span className={`badge ${ST_TONE[f.status]}`}>{f.status_ru}</span>{(f.owner || f.due) && <span className="sub">{[f.owner, f.due && `до ${fmtDate(f.due)}`].filter(Boolean).join(", ")}</span>}{f.comment && <span className="sub">{f.comment}</span>}</td></tr>)}</tbody></table></div>}
      {sel.count > 0 && <div className="row wrap inv-decide"><span><b>{sel.count}</b> выбрано</span>
        {([["confirmed", "Проверено"], ["fixing", "Исправляется"], ["fixed", "Устранено"], ["exception", "Исключение"]] as [string, string][]).map(([k, v]) => <button key={k} className={`btn mini ${k === "fixing" ? "primary" : ""}`} onClick={() => setDecide(k)}>{v}</button>)}</div>}
      {decide && <DecideDialog ids={sel.ids} status={decide} onClose={() => setDecide(null)} onDone={() => { setDecide(null); sel.clear(); void load(); show("Решение сохранено"); }} />}
    </div>
  );
}

function DecideDialog({ ids, status, onClose, onDone }: { ids: number[]; status: string; onClose: () => void; onDone: () => void }) {
  const [comment, setComment] = useState(""); const [owner, setOwner] = useState(""); const [due, setDue] = useState(""); const [err, setErr] = useState("");
  const go = async () => { try { await inv.infraDecide({ ids, status, comment, owner, due: due || null }); onDone(); } catch (e) { setErr((e as ApiError).message); } };
  return (
    <Modal title={{ confirmed: "Проверено", fixing: "Исправляется", fixed: "Устранено", exception: "Принять как исключение" }[status] ?? status} lede={`Выбрано: ${ids.length}`} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" onClick={() => void go()}>Сохранить</button></>}>
      <div className="form-stack">
        <label className="field">{status === "exception" ? "Основание (обязательно)" : "Комментарий"}<textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} placeholder={status === "exception" ? "кем и почему принято: например, резервное копирование не требуется" : ""} /></label>
        {status === "fixing" && <div className="row wrap"><label className="field">Ответственный<input value={owner} onChange={(e) => setOwner(e.target.value)} /></label><label className="field">Срок<input type="date" value={due} onChange={(e) => setDue(e.target.value)} /></label></div>}
        {status === "exception" && <label className="field">Действует до<input type="date" value={due} onChange={(e) => setDue(e.target.value)} /></label>}
        {err && <p className="field-err">{err}</p>}
      </div>
    </Modal>
  );
}

function Objects({ show }: { show: (t: string, tone?: "ok" | "error") => void }) {
  const [sp] = useSearchParams();
  const [kind, setKind] = useState(sp.get("kind") ?? ""); const [match, setMatch] = useState(""); const [q, setQ] = useState(sp.get("q") ?? ""); const [present, setPresent] = useState<"" | "1" | "0">("1");
  const [d, setD] = useState<{ items: InfraObject[]; total: number; kinds: Record<string, string> } | null>(null);
  const [open, setOpen] = useState<InfraObject | null>(null);
  const load = useCallback(() => inv.infraObjects({ kind, match, q, present: present === "" ? undefined : present === "1", limit: 1000 }).then(setD).catch((e) => show((e as ApiError).message, "error")), [kind, match, q, present, show]);
  useEffect(() => { const t = window.setTimeout(load, 250); return () => window.clearTimeout(t); }, [load]);
  return (
    <div className="stack">
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Имя, IP, MAC, UUID, серийный номер", label: "Поиск объектов" }}
        primary={<><label className="field inline"><span className="sr-only">Вид</span><select value={kind} onChange={(e) => setKind(e.target.value)}><option value="">Все виды</option>{Object.entries(d?.kinds ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field inline"><span className="sr-only">Сопоставление</span><select value={match} onChange={(e) => setMatch(e.target.value)}><option value="">Любое сопоставление</option>{Object.entries(MATCH_RU).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <Segmented label="Наличие" value={present} onChange={setPresent} options={[["1", "Есть в источнике"], ["0", "Исчезли"], ["", "Все"]]} /></>}
        count={{ n: d ? d.total : null, noun: ["объект", "объекта", "объектов"] }} onRefresh={() => void load()} />
      {!d ? <div className="card"><SkelRows rows={4} cols={5} /></div> : !d.items.length ? <div className="card"><Empty icon="database" title="Объектов нет">Подключите источники во вкладке «Источники».</Empty></div> :
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Объект</th><th>Вид</th><th className="hide-sm">Источник</th><th className="hide-sm">Адреса</th><th className="hide-md">Ресурсы</th><th>Учёт</th></tr></thead>
          <tbody>{d.items.map((o) => <tr key={o.id} className={o.present ? "clickable" : "clickable muted"} onClick={() => setOpen(o)}>
            <td><button type="button" className="link-btn" onClick={() => setOpen(o)}>{o.name || o.ext_id}</button>{!o.present && <span className="badge">нет в источнике</span>}<span className="sub mono">{o.fqdn}</span></td>
            <td className="small">{o.kind_ru}</td><td className="hide-sm small">{o.source}</td><td className="hide-sm mono small">{o.ips.slice(0, 3).join(", ")}</td>
            <td className="hide-md small">{[o.attrs.cpu && `${o.attrs.cpu} CPU`, o.attrs.ram_mb && `${Math.round(Number(o.attrs.ram_mb) / 1024)} ГБ`, o.attrs.power === "off" && "выключена", o.attrs.available === false && "недоступен"].filter(Boolean).join(" · ")}</td>
            <td>{o.asset ? <Link to={`/inventory/assets/${o.asset.id}?tab=infra`} className="mono" onClick={(e) => e.stopPropagation()}>{o.asset.inv_no}</Link> : null}<span className={`sub ${o.match === "ambiguous" || o.match === "none" ? "warn-text" : ""}`}>{MATCH_RU[o.match]}{o.match_basis && ` · ${o.match_basis}`}</span></td></tr>)}</tbody></table></div>}
      {open && <ObjectPanel id={open.id} onClose={() => setOpen(null)} onChanged={() => void load()} show={show} />}
    </div>
  );
}

function ObjectPanel({ id, onClose, onChanged, show }: { id: number; onClose: () => void; onChanged: () => void; show: (t: string, tone?: "ok" | "error") => void }) {
  const { can } = useInv();
  const [o, setO] = useState<(InfraObject & { changes: { at: string; label: string; old: string; new: string }[] }) | null>(null);
  const load = useCallback(() => inv.infraObject(id).then(setO).catch((e) => show((e as ApiError).message, "error")), [id, show]);
  useEffect(() => { void load(); }, [load]);
  const act = async (action: string, asset_id?: number) => { try { await inv.infraMatch(id, action, asset_id); show("Сохранено"); void load(); onChanged(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <Modal side wide title={o?.name ?? "Объект"} lede={o ? `${o.kind_ru} · ${o.source}` : undefined} onClose={onClose}>
      {!o ? <SkelRows rows={5} cols={2} /> : <div className="stack">
        <dl className="kv pairs">{([["Идентификатор в источнике", o.ext_id], ["FQDN", o.fqdn], ["IP-адреса", o.ips.join(", ")], ["MAC-адреса", o.macs.join(", ")], ["SMBIOS UUID", o.bios_uuid], ["Серийный номер", o.serial], ["Хост", o.parent_ext],
          ...Object.entries(o.attrs).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : typeof v === "boolean" ? (v ? "да" : "нет") : String(v)]), ["Впервые", fmt(o.first_seen)], ["Обновлено", fmt(o.last_seen)]] as [string, string][])
          .filter(([, v]) => v).map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={/UUID|MAC|IP|Идентификатор/.test(k) ? "mono small" : ""}>{v}</dd></div>)}</dl>
        <div className="card"><h3 className="vdb-h">Учёт</h3>
          <p>{o.asset ? <>Сопоставлен с <Link to={`/inventory/assets/${o.asset.id}?tab=infra`} className="mono">{o.asset.inv_no}</Link> {o.asset.name}</> : "Не сопоставлен с учётной карточкой."} <span className="muted small">({MATCH_RU[o.match]}{o.match_basis ? `: ${o.match_basis}` : ""})</span></p>
          {can("edit") && <div className="form-stack"><AssetSearch onPick={(a) => void act("link", a.id)} placeholder="Связать с карточкой: номер или имя" />
            <div className="row wrap">{["server", "vm", "network"].includes(o.kind) && !o.asset && can("create") && <button className="btn mini primary" onClick={() => void act("create")}>Создать карточку</button>}
              {o.match === "auto" && o.asset && <button className="btn mini" onClick={() => void act("link", o.asset!.id)}>Подтвердить</button>}
              <button className="btn mini ghost" onClick={() => void act("reject")}>Не связывать</button>{["confirmed", "rejected"].includes(o.match) && <button className="btn mini ghost" onClick={() => void act("reset")}>Вернуть автоматике</button>}</div></div>}
        </div>
        <div><h3 className="vdb-h">История изменений ({o.changes.length})</h3>
          {o.changes.length ? <ul className="inv-list">{o.changes.map((c, i) => <li key={i}><span className="muted small">{fmt(c.at)}</span><b>{c.label}</b><span className="small"><s>{c.old || "—"}</s> → {c.new || "—"}</span></li>)}</ul> : <p className="muted small">Изменений не было.</p>}</div>
      </div>}
    </Modal>
  );
}

function Sources({ show }: { show: (t: string, tone?: "ok" | "error") => void }) {
  const { isAdmin, can } = useInv();
  const [d, setD] = useState<{ items: (InfraSource & { objects: number })[]; kinds: Record<string, string> } | null>(null);
  const [form, setForm] = useState<Partial<InfraSource> | null>(null); const [test, setTest] = useState<Record<number, unknown>>({});
  const file = useRef<HTMLInputElement>(null); const [upFor, setUpFor] = useState<number | null>(null);
  const load = useCallback(() => inv.infraSources().then(setD).catch((e) => show((e as ApiError).message, "error")), [show]);
  useEffect(() => { void load(); const t = window.setInterval(() => void load(), 15000); return () => window.clearInterval(t); }, [load]);
  const runTest = async (s: InfraSource) => { setTest({ ...test, [s.id]: "…" }); try { setTest({ ...test, [s.id]: await inv.infraTest(s.id) }); } catch (e) { setTest({ ...test, [s.id]: { ok: false, error: (e as ApiError).message } }); } };
  const up = async (f: File | undefined) => { if (!f || upFor === null) return; try { const r = await inv.infraUpload(upFor, f); show(`Загружено объектов: ${r.received}, новых карточек: ${r.created}`); void load(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <div className="stack">
      <div className="row wrap"><p className="muted small grow">Источники только читаются: учётные записи — с правами только на чтение. Секреты хранятся в зашифрованном виде. Ошибка одного источника не останавливает остальные.</p>
        {isAdmin && <button className="btn primary" onClick={() => setForm({ kind: "zabbix", name: "", url: "", every_min: 60, verify_tls: true, enabled: true, options: {} })}><Icon name="plus" size={16} />Подключить источник</button>}</div>
      <input ref={file} type="file" accept=".json" hidden onChange={(e) => { void up(e.target.files?.[0]); e.target.value = ""; }} />
      {!d ? <div className="card"><SkelRows rows={3} cols={5} /></div> : !d.items.length ? <div className="card"><Empty icon="database" title="Источников нет">Мониторинг, системы виртуализации, реестр инфраструктуры, резервное копирование, API провайдеров.</Empty></div> :
        d.items.map((s) => { const t = test[s.id] as { ok?: boolean; error?: string; total?: number; by_kind?: Record<string, number>; sample?: { kind: string; name: string; ips: string[] }[] } | string | undefined;
          return <div key={s.id} className="card inv-src">
            <div className="card-head"><div><h2>{s.name}</h2><span className="muted small">{s.kind_ru}{s.url && ` · ${s.url}`}</span></div><div className="spacer" />
              {!s.enabled ? <span className="badge">выключен</span> : s.last_error ? <span className="badge err">ошибка</span> : s.last_ok_at ? <span className="badge ok">в порядке</span> : <span className="badge">ожидает синхронизации</span>}</div>
            <div className="row wrap small"><span>Объектов: <b>{num(s.objects)}</b></span><span>Успешно: {fmt(s.last_ok_at)}</span><span>Попытка: {fmt(s.last_try_at)}</span>
              {s.last_stats.received !== undefined && <span className="muted">получено {String(s.last_stats.received)}, новых {String(s.last_stats.new)}, изменено {String(s.last_stats.changed)}, исчезло {String(s.last_stats.gone)}{s.last_stats.created ? `, карточек создано ${String(s.last_stats.created)}` : ""}</span>}</div>
            {s.last_error && <div className="alert flat error"><Icon name="alert" /><div className="alert-body">{s.last_error}</div></div>}
            <div className="row wrap">
              {s.network && (isAdmin || can("edit")) && <button className="btn mini" disabled={s.requested} onClick={() => void inv.infraSync(s.id).then(load)}>{s.requested ? "Синхронизация запрошена…" : "Синхронизировать"}</button>}
              {s.network && isAdmin && <button className="btn mini" onClick={() => void runTest(s)}>Проверить соединение</button>}
              {s.upload && isAdmin && <button className="btn mini" onClick={() => { setUpFor(s.id); file.current?.click(); }}><Icon name="upload" size={14} />Загрузить выгрузку</button>}
              {isAdmin && <button className="btn mini ghost" onClick={() => setForm(s)}>Изменить</button>}
              {isAdmin && <button className="btn mini ghost" onClick={() => { if (window.confirm(`Удалить источник «${s.name}»? Его объекты и их история удалятся; учётные карточки останутся.`)) void inv.infraDelSource(s.id).then(load); }}><Icon name="trash" size={14} />Удалить</button>}
            </div>
            {t === "…" && <p className="muted small"><span className="spin sm" /> проверка…</p>}
            {t && typeof t === "object" && (t.ok ? <div className="alert flat ok"><Icon name="checkCircle" /><div className="alert-body">Соединение есть. Найдено объектов: <b>{t.total}</b> ({Object.entries(t.by_kind ?? {}).map(([k, v]) => `${k}: ${v}`).join(", ")}).
              <ul className="reasons">{(t.sample ?? []).slice(0, 8).map((x, i) => <li key={i}>{x.kind}: {x.name} {x.ips.join(", ")}</li>)}</ul></div></div>
              : <div className="alert flat error"><Icon name="alert" /><div className="alert-body">{t.error}</div></div>)}
          </div>; })}
      {form && <SourceForm init={form} kinds={d?.kinds ?? {}} onClose={() => setForm(null)} onSaved={() => { setForm(null); void load(); show("Сохранено"); }} />}
    </div>
  );
}

const KIND_HINT: Record<string, string> = {
  zabbix: "Адрес веб-интерфейса Zabbix; токен API пользователя с правом только на чтение нужных групп узлов (Zabbix 5.4+).",
  vsphere: "Адрес vCenter (https://vcenter.example.local); учётная запись с ролью «только чтение».",
  proxmox: "Адрес https://pve.example.local:8006; пользователь — идентификатор токена «user@realm!tokenid», секрет — значение токена (роль PVEAuditor).",
  ovirt: "Адрес движка (https://engine.example.local); учётная запись user@internal с правами только на чтение.",
  netbox: "Адрес реестра (https://netbox.example.local); токен API только на чтение.",
  hyperv: "Сведения загружаются файлом: запустите scripts/windows/Export-KavHyperV.ps1 на сервере с доступом к хостам и загрузите hyperv.json.",
  backup: "Список защищаемых объектов из системы резервного копирования: адрес JSON (или загрузка файла) и пути полей — массив, имя, дата последней копии.",
  generic: "Любой JSON-список по HTTP (API провайдера): укажите путь к массиву и пути полей; токен передаётся в заголовке.",
};

function SourceForm({ init, kinds, onClose, onSaved }: { init: Partial<InfraSource>; kinds: Record<string, string>; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<Partial<InfraSource> & { secret?: string }>({ ...init }); const [err, setErr] = useState("");
  const o = (f.options ?? {}) as Record<string, string | boolean>;
  const setO = (k: string, v: string | boolean) => setF({ ...f, options: { ...o, [k]: v } });
  const save = async () => {
    const body = { kind: f.kind, name: f.name, url: f.url ?? "", username: f.username ?? "", verify_tls: f.verify_tls ?? true, enabled: f.enabled ?? true, every_min: f.every_min ?? 60, options: f.options ?? {},
      ...(f.secret !== undefined ? { secret: f.secret } : {}) };
    try { if (init.id) await inv.infraEditSource(init.id, body); else await inv.infraAddSource(body); onSaved(); } catch (e) { setErr((e as ApiError).message); }
  };
  const generic = f.kind === "generic" || f.kind === "backup";
  return (
    <Modal side wide title={init.id ? "Источник" : "Подключить источник"} onClose={onClose} footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={!f.name?.trim()} onClick={() => void save()}>Сохранить</button></>}>
      <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <div className="inv-grid"><label className="field">Тип<select value={f.kind} disabled={!!init.id} onChange={(e) => setF({ ...f, kind: e.target.value })}>{Object.entries(kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Название<input value={f.name ?? ""} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="например, «Мониторинг ЦОД»" /></label></div>
        <p className="muted small">{KIND_HINT[f.kind ?? ""]}</p>
        {f.kind !== "hyperv" && <label className="field">Адрес API<input value={f.url ?? ""} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://…" /></label>}
        {["vsphere", "proxmox", "ovirt"].includes(f.kind ?? "") && <label className="field">{f.kind === "proxmox" ? "Идентификатор токена" : "Учётная запись"}<input value={f.username ?? ""} onChange={(e) => setF({ ...f, username: e.target.value })} autoComplete="off" /></label>}
        {f.kind !== "hyperv" && <label className="field">{["zabbix", "netbox", "proxmox", "generic", "backup"].includes(f.kind ?? "") ? "Токен" : "Пароль"}{init.secret_set && <span className="muted small"> (сохранён; пусто — без изменений)</span>}
          <input type="password" autoComplete="new-password" value={f.secret ?? ""} onChange={(e) => setF({ ...f, secret: e.target.value })} /></label>}
        {generic && <div className="inv-grid">{([["items", "Путь к массиву", "data.items"], ["id", "Поле идентификатора", "id"], ["name", "Поле имени", "name"], ["ip", "Поле IP", "ip"], ["uuid", "Поле UUID", "uuid"], ["serial", "Поле серийного номера", "serial"],
          ["status", "Поле состояния", "status"], ...(f.kind === "backup" ? [["last_backup", "Поле даты последней копии", "lastBackup"]] : [["cpu", "Поле CPU", "cpu"], ["ram_mb", "Поле ОЗУ (МБ)", "ram"]])] as [string, string, string][]).map(([k, l, ph]) =>
          <label key={k} className="field">{l}<input className="mono" value={String(o[k] ?? "")} onChange={(e) => setO(k, e.target.value)} placeholder={ph} /></label>)}</div>}
        <div className="inv-grid">
          <label className="field">Синхронизация каждые, мин<input type="number" min={5} max={10080} value={f.every_min ?? 60} onChange={(e) => setF({ ...f, every_min: Number(e.target.value) })} /></label>
          <label className="check-row"><input type="checkbox" checked={f.verify_tls ?? true} onChange={(e) => setF({ ...f, verify_tls: e.target.checked })} />Проверять сертификат TLS</label>
          {["vsphere", "proxmox", "ovirt", "netbox", "generic"].includes(f.kind ?? "") && <label className="check-row"><input type="checkbox" checked={o.create_assets !== undefined ? !!o.create_assets : f.kind !== "generic"} onChange={(e) => setO("create_assets", e.target.checked)} />Создавать учётные карточки для новых серверов и ВМ</label>}
          {init.id && <label className="check-row"><input type="checkbox" checked={f.enabled ?? true} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Включён</label>}
        </div>
        {err && <p className="field-err">{err}</p>}
      </form>
    </Modal>
  );
}

function Ips() {
  const [q, setQ] = useState(""); const [dup, setDup] = useState(false);
  const [d, setD] = useState<Awaited<ReturnType<typeof inv.infraIps>> | null>(null);
  useEffect(() => { const t = window.setTimeout(() => void inv.infraIps({ q, dup: dup || undefined }).then(setD), 250); return () => window.clearTimeout(t); }, [q, dup]);
  return (
    <div className="stack">
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Адрес или имя", label: "Поиск адреса", mask: false }} primary={<label className="chip-check"><input type="checkbox" checked={dup} onChange={(e) => setDup(e.target.checked)} />только повторы</label>}
        count={{ n: d ? d.total : null, noun: ["адрес", "адреса", "адресов"] }} />
      {!d ? <div className="card"><SkelRows rows={4} cols={4} /></div> : <div className="split">
        <div className="table-scroll"><table className="table compact"><thead><tr><th>IP-адрес</th><th>Учёт</th><th className="hide-sm">Объекты</th><th className="hide-md">Источники</th></tr></thead>
          <tbody>{d.items.map((i) => <tr key={i.ip} className={i.dup ? "row-bad" : ""}><td className="mono">{i.ip}{i.dup && <span className="badge err">повтор</span>}</td>
            <td>{i.assets.map((a) => <Link key={a.id} to={`/inventory/assets/${a.id}?tab=infra`} className="block mono small">{a.inv_no} {a.name}</Link>)}</td><td className="hide-sm small">{i.objects.join(", ")}</td><td className="hide-md small">{i.sources.join(", ")}</td></tr>)}
            {!d.items.length && <tr><td colSpan={4}><Empty icon="search" title="Адресов нет" /></td></tr>}</tbody></table></div>
        <div className="stack"><div className="card flush"><div className="card-head"><h2>Подсети</h2></div>{d.prefixes.length ? <ul className="inv-list pad">{d.prefixes.map((p) => <li key={p.id}><span className="mono">{p.name}</span><span className="muted small">{[p.attrs.vlan && `VLAN ${String(p.attrs.vlan)}`, p.attrs.site].filter(Boolean).join(" · ")}</span></li>)}</ul> : <p className="muted small pad">Подсети приходят из реестра инфраструктуры.</p>}</div>
          <div className="card flush"><div className="card-head"><h2>VLAN</h2></div>{d.vlans.length ? <ul className="inv-list pad">{d.vlans.map((v) => <li key={v.id}><span>{v.name}</span><span className="muted small">{String(v.attrs.site ?? "")}</span></li>)}</ul> : <p className="muted small pad">Нет данных.</p>}</div></div>
      </div>}
    </div>
  );
}

function Racks() {
  const [d, setD] = useState<Rack[] | null>(null);
  useEffect(() => { void inv.infraRacks().then((r) => setD(r.items)); }, []);
  if (!d) return <div className="card"><SkelRows rows={4} cols={3} /></div>;
  if (!d.length) return <div className="card"><Empty icon="server" title="Стоек нет">Создайте местоположение вида «Стойка» (с числом юнитов) и укажите у оборудования юнит и высоту.</Empty></div>;
  return (
    <div className="inv-racks">{d.map((r) => {
      const slots: (Rack["items"][number] | null | "cont")[] = Array.from({ length: r.units }, () => null);
      for (const it of r.items) if (it.unit) for (let k = 0; k < (it.units || 1); k++) { const idx = it.unit - 1 + k; if (idx < r.units) slots[idx] = k === 0 ? it : "cont"; }
      return <div key={r.id} className="card inv-rack"><div className="card-head"><div><h2>{r.name}</h2><span className="muted small">{r.path}</span></div><div className="spacer" /><span className="badge">свободно {r.free} из {r.units}</span></div>
        <ol className="inv-rack-units" reversed>{slots.map((s, i) => s === "cont" ? null : <li key={i} className={s ? `busy c-${s.cls}` : "free"} style={s ? { gridRow: `span ${s.units || 1}` } : undefined}>
          <span className="u">{s && s.units > 1 ? `${i + 1}–${i + s.units}` : i + 1}</span>{s ? <Link to={`/inventory/assets/${s.id}`}><b>{s.name}</b><span className="mono small">{s.inv_no}</span></Link> : <span className="muted small">свободно</span>}</li>).reverse()}</ol>
        {r.unplaced.length > 0 && <p className="muted small">Без указания юнита: {r.unplaced.length} ({r.unplaced.slice(0, 5).map((x) => x.inv_no).join(", ")}{r.unplaced.length > 5 ? "…" : ""}) — <Link to={`/inventory/assets?location=${r.id}`}>список</Link>. Юнит и высота задаются в карточке.</p>}</div>;
    })}</div>
  );
}
