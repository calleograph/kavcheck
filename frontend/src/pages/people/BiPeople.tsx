import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type BiDeviceCard, type BiDeviceRow, type BiPersonCard, type BiPersonRow, type BiState } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, useInfinite, useKept } from "../../components/Infinite";
import { BiDeviceView, personLink } from "../../components/OwnerBlock";
import { QuickReportPanel } from "../../components/QuickReport";
import { Empty, Segmented, SkelRows } from "../../components/ui";
import { fmtDate, num, plural } from "../../util";

type Summary = Awaited<ReturnType<typeof api.bi.summary>>;
const FLT: [string, string][] = [["", "Все"], ["unknown_owner", "Неопределённые владельцы"], ["multi", "Несколько владельцев"], ["no_ksc", "Нет в KSC"], ["candidates", "Требуют решения"], ["issues", "Расхождения BI и KSC"]];
const FLT_VIEW: Record<string, string> = { unknown_owner: "unknown", issues: "discrepancies" };
const ST_RU: Record<BiState, string> = { current: "текущие", past: "прежние", unknown: "статус неизвестен" };

/** «Пользователи BI»: сотрудники и устройства из BI-выгрузок с историей принадлежности. Поиск — ФИО, почта, подразделение, текущее и прежнее имя устройства. */
export default function BiPeople({ ctx, summary }: { ctx: Ctx; summary: Summary }) {
  const [sp, setSp] = useSearchParams();
  const [view, setView] = useKept<"people" | "devices">("bi.view", "people");
  const [q, setQ] = useKept("bi.q", ""); const [applied, setApplied] = useState(q);
  const [st, setSt] = useKept("bi.st", ""); const [flt, setFlt] = useKept("bi.flt", ""); const [src, setSrc] = useKept("bi.src", ""); const [dept, setDept] = useKept("bi.dept", "");
  const [os, setOs] = useKept("bi.os", ""); const [personal, setPersonal] = useKept("bi.personal", "");
  const [report, setReport] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const people = useInfinite<BiPersonRow>("bi:people", [view, applied, st, src, dept], (offset, limit) => (view === "people" ? api.bi.people({ q: applied, state: st, source_id: src, dept, offset, limit }) : Promise.resolve({ items: [], total: 0 })), 50);
  const devices = useInfinite<BiDeviceRow>("bi:devices", [view, applied, flt, src, os, personal], (offset, limit) => (view === "devices" ? api.bi.devices({ q: applied, filter: flt, source_id: src, os, personal, offset, limit }) : Promise.resolve({ items: [], total: 0 })), 50);
  const list = view === "people" ? people : devices;
  const person = sp.get("person"); const bidev = sp.get("bidev");
  const close = (k: string) => setSp((p) => { p.delete(k); return p; });
  const open = (k: string, v: number) => setSp((p) => { p.set("tab", "bi"); p.set(k, String(v)); return p; });
  const snap = summary.items.map((s) => `«${s.name}» — ${s.snapshot_at ? `выгрузка от ${fmtDate(s.snapshot_at)}` : "данных ещё нет"}${s.error ? " (последнее получение не удалось, показан прежний снимок)" : ""}`).join("; ");
  const chips = [...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []), ...(view === "people" && st ? [{ id: "st", label: st === "current" ? "Текущие владельцы" : "Прежние владельцы", onRemove: () => setSt("") }] : []),
    ...(view === "devices" && flt ? [{ id: "flt", label: FLT.find((f) => f[0] === flt)?.[1] ?? flt, onRemove: () => setFlt("") }] : []), ...(src ? [{ id: "src", label: `Источник: ${summary.items.find((s) => s.id === src)?.name ?? ""}`, onRemove: () => setSrc("") }] : []),
    ...(dept && view === "people" ? [{ id: "dept", label: `Подразделение: ${dept}`, onRemove: () => setDept("") }] : []), ...(os && view === "devices" ? [{ id: "os", label: `ОС: ${os}`, onRemove: () => setOs("") }] : []),
    ...(personal && view === "devices" ? [{ id: "pers", label: personal === "yes" ? "Личные устройства" : "Корпоративные устройства", onRemove: () => setPersonal("") }] : [])];
  return (<>
    <p className="muted small fbar-note">Сведения BI: {snap}. Даты связей — даты выгрузок, в которых связь наблюдалась, а не даты передачи устройства.</p>
    <FilterBar search={{ value: q, onChange: setQ, placeholder: view === "people" ? "ФИО, почта, подразделение или имя компьютера (в том числе прежнее)" : "Имя компьютера, прежнее имя, ФИО или почта владельца", label: "Поиск" }}
      primary={<>
        <Segmented label="Что показать" value={view} onChange={setView} options={[["people", "Сотрудники"], ["devices", "Устройства BI"]]} />
        {view === "people" ? <Segmented label="Владельцы" value={st} onChange={setSt} options={[["", "Все"], ["current", "Текущие"], ["past", "Прежние"]]} />
          : <label className="field inline">Отбор<select value={flt} onChange={(e) => setFlt(e.target.value)}>{FLT.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>}
      </>}
      more={<>
        {summary.items.length > 1 && <label className="field">Источник BI<select value={src} onChange={(e) => setSrc(e.target.value)}><option value="">Все</option>{summary.items.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>}
        {view === "people" ? <label className="field">Подразделение<input value={dept} onChange={(e) => setDept(e.target.value)} placeholder="Бухгалтерия" /></label> : <>
          <label className="field">ОС<select value={os} onChange={(e) => setOs(e.target.value)}><option value="">Все</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="mac">macOS</option><option value="unknown">Не указана</option></select></label>
          <label className="field">Тип<select value={personal} onChange={(e) => setPersonal(e.target.value)}><option value="">Все</option><option value="yes">Личные</option><option value="no">Корпоративные</option></select></label></>}
      </>}
      moreActive={[src, view === "people" ? dept : os, view === "devices" ? personal : ""].filter(Boolean).length} chips={chips}
      onReset={() => { setQ(""); setSt(""); setFlt(""); setSrc(""); setDept(""); setOs(""); setPersonal(""); }}
      count={{ n: list.initial ? null : list.total, noun: view === "people" ? ["сотрудник", "сотрудника", "сотрудников"] : ["устройство", "устройства", "устройств"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
      report={{ onClick: () => setReport(true), title: "Отчёт по текущему представлению с учётом фильтров" }} />
    {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
    <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
      {list.initial ? <SkelRows cols={5} /> : view === "people" ? (
        <table className="table">
          <thead><tr><th>Сотрудник</th><th className="hide-sm">Подразделение</th><th>Устройства сейчас</th><th className="hide-sm">Прежние устройства</th><th className="hide-md">Последняя выгрузка</th></tr></thead>
          <tbody>
            {people.items.map((p) => <tr key={p.id} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a, button")) open("person", p.id); }}>
              <td><button type="button" className="link-btn strong-link" onClick={() => open("person", p.id)}>{p.name}</button><span className="sub small">{p.email}</span>{!p.present && <span className="badge">нет в последней выгрузке</span>}</td>
              <td className="small hide-sm">{p.department || "—"}</td>
              <td className="small">{p.devices.current.length ? p.devices.current.slice(0, 3).join(", ") + (p.devices.current.length > 3 ? ` +${p.devices.current.length - 3}` : "") : <span className="muted">—</span>}</td>
              <td className="small hide-sm">{[...p.devices.past, ...p.devices.unknown].slice(0, 3).join(", ") || <span className="muted">—</span>}{p.devices.past.length + p.devices.unknown.length > 3 && ` +${p.devices.past.length + p.devices.unknown.length - 3}`}</td>
              <td className="small nowrap hide-md">{fmtDate(p.last_seen_at)}</td></tr>)}
            {!people.items.length && !people.loading && <tr><td colSpan={5}><Empty icon="users" title="Сотрудники не найдены">{applied || st || dept ? "Измените запрос или фильтры." : "Выгрузки ещё не импортированы."}</Empty></td></tr>}
          </tbody>
        </table>) : (
        <table className="table">
          <thead><tr><th>Устройство</th><th>Владелец</th><th className="hide-sm">Прежние</th><th className="hide-md">ОС и тип</th><th>KSC</th></tr></thead>
          <tbody>
            {devices.items.map((d) => <tr key={d.id} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a, button")) open("bidev", d.id); }}>
              <td><button type="button" className="link-btn strong-link" onClick={() => open("bidev", d.id)}>{d.name}</button>{d.generic && <span className="badge outline">условное имя</span>}{!d.present && <span className="badge">нет в последней выгрузке</span>}
                {d.issues.length > 0 && <span className="sub small warn-text" title={d.issues.join("; ")}><Icon name="alert" size={13} /> {d.issues[0]}{d.issues.length > 1 ? ` (+${d.issues.length - 1})` : ""}</span>}</td>
              <td className="small">{d.owners.length === 1 ? <><Link to={personLink(d.owners[0].id)}>{d.owners[0].name}</Link><span className="sub">{d.owners[0].department}</span></> : d.owners.length > 1 ? <span className="warn-text">несколько: {d.owners.map((o) => o.name).join(", ")}</span> : <span className="muted">не определён</span>}</td>
              <td className="small hide-sm">{d.previous.length ? d.previous.slice(0, 2).map((o) => <span key={o.id} className="block">{o.name} <span className="muted">({ST_RU[o.state]})</span></span>) : <span className="muted">—</span>}{d.previous_n > 2 && <span className="muted"> +{d.previous_n - 2}</span>}</td>
              <td className="small hide-md">{d.os || "—"}<span className="sub">{d.personal === true ? "личное" : d.personal === false ? "корпоративное" : ""}</span></td>
              <td className="small">{d.ksc_state === "linked" ? d.ksc.map((k) => <span key={`${k.ksc_source_id}:${k.host_id}`} className="block">{k.host_name}<span className="sub">{k.level_ru} · {k.ksc_source}</span></span>)
                : d.ksc_state === "candidates" ? <span className="warn-text">требует решения<span className="sub">{d.ksc[0]?.level_ru}</span></span> : <span className="muted">не найдено в KSC</span>}</td></tr>)}
            {!devices.items.length && !devices.loading && <tr><td colSpan={5}><Empty icon="monitor" title="Устройства не найдены">{applied || flt || os || personal ? "Измените запрос или фильтры." : "Выгрузки ещё не импортированы."}</Empty></td></tr>}
          </tbody>
        </table>)}
    </div>
    {view === "people" ? <ListFoot list={people} /> : <ListFoot list={devices} />}
    {report && <QuickReportPanel kind="quick_bi" title="Отчёт по данным BI" lede="Отчёт строится по фильтрам этой страницы; вид можно сменить" options={{ scope: false, bi: true }}
      params={{ view: view === "devices" ? (FLT_VIEW[flt] ?? "owners") : "history", q: applied || undefined, source_id: src || undefined, filter: view === "devices" && !FLT_VIEW[flt] ? flt || undefined : undefined, os: view === "devices" ? os || undefined : undefined, personal: view === "devices" ? personal || undefined : undefined }}
      activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
    {person && <PersonModal id={Number(person)} onClose={() => close("person")} onDevice={(id) => open("bidev", id)} activityDays={ctx.me.activity_days} />}
    {bidev && <DeviceModal id={Number(bidev)} onClose={() => close("bidev")} activityDays={ctx.me.activity_days} />}
  </>);
}

function PersonModal({ id, onClose, onDevice, activityDays }: { id: number; onClose: () => void; onDevice: (id: number) => void; activityDays: number }) {
  const [p, setP] = useState<BiPersonCard | null>(null); const [err, setErr] = useState(""); const [report, setReport] = useState(false);
  useEffect(() => { setP(null); api.bi.person(id).then(setP).catch((e) => setErr((e as ApiError).message)); }, [id]);
  const group = (k: BiState, title: string) => (p && p.devices[k].length > 0 ? <>
    <h3 className="h3">{title} ({p.devices[k].length})</h3>
    <div className="table-scroll"><table className="table compact"><thead><tr><th>Устройство</th><th>В выгрузках</th><th>Компьютер KSC</th></tr></thead>
      <tbody>{p.devices[k].map((d) => <tr key={d.device_id}><td><button type="button" className="link-btn strong-link" onClick={() => onDevice(d.device_id)}>{d.name}</button><span className="sub small">{d.os || "ОС не указана"}{d.personal ? " · личное" : ""}{d.others_now > 0 ? ` · сейчас за устройством ${d.state === "current" ? "также " : ""}${d.others_now} ${plural(d.others_now, "другой сотрудник", "других сотрудника", "других сотрудников")}` : ""}</span></td>
        <td className="small nowrap">{fmtDate(d.first_seen_at)} — {fmtDate(d.last_seen_at)}<span className="sub">{d.confidence_ru}</span></td>
        <td className="small">{d.ksc.some((m) => m.level === "auto" || m.level === "confirmed") ? d.ksc.map((m) => <span key={`${m.ksc_source_id}:${m.host_id}`} className="block">{m.host_name}<span className="sub">{m.level_ru} · {m.ksc_source}</span></span>)
          : d.ksc.length ? <span className="warn-text">требует решения<span className="sub">{d.ksc[0].level_ru}</span></span> : <span className="muted">не найдено в KSC</span>}</td></tr>)}</tbody></table></div></> : null);
  return (
    <Modal side wide title={p?.name ?? "Сотрудник"} onClose={onClose} lede={p ? [p.department, p.email, p.source].filter(Boolean).join(" · ") : undefined}
      footer={p ? <button type="button" className="btn" onClick={() => setReport(true)}><Icon name="file" />Отчёт: история устройств сотрудника</button> : undefined}>
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!p && !err && <SkelRows rows={4} cols={3} />}
      {p && <>
        <dl className="kv compact">
          <div><dt>Рабочая почта</dt><dd>{p.email ? <a href={`mailto:${p.email}`}>{p.email}</a> : "—"}</dd></div>
          <div><dt>В выгрузках</dt><dd>{fmtDate(p.first_seen_at)} — {fmtDate(p.last_seen_at)}{!p.present && " · в последней выгрузке нет"}</dd></div>
          <div><dt>Учётная запись создана</dt><dd>{fmtDate(p.account_created)}<span className="sub">не дата начала владения устройством</span></dd></div>
        </dl>
        {group("current", "Текущие устройства")}{group("past", "Прежние устройства")}{group("unknown", "Историческая связь, текущий статус неизвестен")}
        {!p.devices.current.length && !p.devices.past.length && !p.devices.unknown.length && <p className="muted">Связанных устройств нет.</p>}
        <p className="muted small">{p.note}</p>
      </>}
      {report && <QuickReportPanel kind="quick_bi" title="Отчёт: история устройств сотрудника" options={{ scope: false, bi: true }} params={{ view: "history", person_id: id }} activityDays={activityDays} canReport onClose={() => setReport(false)} />}
    </Modal>
  );
}

function DeviceModal({ id, onClose, activityDays }: { id: number; onClose: () => void; activityDays: number }) {
  const [d, setD] = useState<BiDeviceCard | null>(null); const [err, setErr] = useState(""); const [report, setReport] = useState(false);
  useEffect(() => { setD(null); api.bi.device(id).then(setD).catch((e) => setErr((e as ApiError).message)); }, [id]);
  const link = d?.matches.find((m) => m.level === "auto" || m.level === "confirmed");
  return (
    <Modal side wide title={d?.name ?? "Устройство BI"} onClose={onClose} lede={d ? `${d.source} · ${d.ksc_state_ru}` : undefined}
      footer={d ? <><button type="button" className="btn" onClick={() => setReport(true)}><Icon name="file" />Отчёт: история принадлежности</button>
        {link?.ksc && <Link className="btn ghost" to={`/devices?card=${link.ksc_source_id}:${link.host_id}`} onClick={onClose}>Карточка компьютера KSC</Link>}</> : undefined}>
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!d && !err && <SkelRows rows={5} cols={3} />}
      {d && <BiDeviceView d={d} canPeople />}
      {d && <p className="muted small">Впервые в выгрузках: {fmtDate(d.first_seen_at)}; последний раз: {fmtDate(d.last_seen_at)}; связей с сотрудниками: {num(d.owners.length)}.</p>}
      {report && <QuickReportPanel kind="quick_bi" title="Отчёт: история принадлежности" options={{ scope: false, bi: true }} params={{ view: "history", device_id: id }} activityDays={activityDays} canReport onClose={() => setReport(false)} />}
    </Modal>
  );
}
