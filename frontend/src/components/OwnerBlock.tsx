import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type BiDeviceCard, type BiHostBlock, type BiOwnerBrief, type BiOwnerRow } from "../api";
import { ReportButton } from "./FilterBar";
import { Icon } from "./Icons";
import { QuickReportPanel } from "./QuickReport";
import { fmt, fmtDate, num } from "../util";

const TYPE_RU = (p: boolean | null) => (p === true ? "личное" : p === false ? "корпоративное" : "тип не указан");
const AV_RU = (v: boolean | null | undefined) => (v === true ? "использует антивирус" : v === false ? "антивирус не используется" : "нет сведений");
export const personLink = (id: number) => `/devices?tab=bi&person=${id}`;
export const biDeviceLink = (id: number) => `/devices?tab=bi&bidev=${id}`;

function Who({ o, canPeople }: { o: BiOwnerRow; canPeople: boolean }) {
  const p = o.person;
  return <>{canPeople ? <Link to={personLink(p.id)} className="strong-link">{p.name}</Link> : <b>{p.name}</b>}
    {p.department && <span className="muted small"> · {p.department}</span>}
    {p.email && <> · <a href={`mailto:${p.email}`} className="small">{p.email}</a></>}</>;
}

/** Временная шкала владельцев: текущий, прежние, со статусом «неизвестен». Нажатие на запись раскрывает основание — выгрузку, в которой связь появилась. */
function Timeline({ owners, canPeople }: { owners: BiOwnerRow[]; canPeople: boolean }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <ol className="own-tl" aria-label="История принадлежности">
      {owners.map((o, i) => (
        <li key={`${o.person.id}-${i}`} className={`own-tl-i ${o.state}`}>
          <button type="button" className="own-tl-h" aria-expanded={open === i} onClick={() => setOpen(open === i ? null : i)}>
            <span className="own-tl-st">{o.state_ru}</span><span className="own-tl-d">{fmtDate(o.first_seen_at)} — {fmtDate(o.last_seen_at)}</span>
          </button>
          <div className="own-tl-who"><Who o={o} canPeople={canPeople} /></div>
          <div className="muted small">{o.note}</div>
          {open === i && <dl className="kv compact own-tl-x">
            <div><dt>Впервые указан</dt><dd>{o.first_import ? `выгрузка «${o.first_import.file}» от ${fmtDate(o.first_import.at)}` : fmtDate(o.first_seen_at)}</dd></div>
            <div><dt>Последний раз указан</dt><dd>{o.last_import ? `выгрузка «${o.last_import.file}» от ${fmtDate(o.last_import.at)}` : fmtDate(o.last_seen_at)} · выгрузок: {num(o.seen_n)}</dd></div>
            <div><dt>Период владения</dt><dd>{o.owned_from || o.owned_to ? `${fmtDate(o.owned_from)} — ${fmtDate(o.owned_to)} (по данным источника)` : "источник не передаёт; известны только даты выгрузок"}</dd></div>
            <div><dt>Дата наблюдения в источнике</dt><dd>{o.src_seen_at ? fmt(o.src_seen_at) : "нет достоверной даты"}</dd></div>
            <div><dt>Достоверность связи</dt><dd>{o.confidence_ru}</dd></div>
          </dl>}
        </li>))}
    </ol>
  );
}

/** Сведения одного устройства BI: владелец, шкала, BI против KSC, расхождения и сведения выгрузок. */
export function BiDeviceView({ d, canPeople, showKsc = true }: { d: BiDeviceCard; canPeople: boolean; showKsc?: boolean }) {
  const cur = d.owners.filter((o) => o.state === "current");
  const link = d.matches.filter((m) => m.level === "auto" || m.level === "confirmed");
  return (
    <div className="own">
      <div className="own-head">
        <div className="own-now">
          <span className="own-cap">{d.owner ? "Текущий владелец по BI" : cur.length > 1 ? `Несколько владельцев (${cur.length})` : d.present ? "Текущий владелец не указан" : "Текущий владелец неизвестен"}</span>
          {d.owner ? <span className="own-name"><Who o={d.owner} canPeople={canPeople} /></span> : cur.length > 1 ? <span className="own-name">{cur.map((o, i) => <span key={i} className="block"><Who o={o} canPeople={canPeople} /></span>)}</span>
            : <span className="muted small">{d.present ? "в последней выгрузке устройство без сотрудника" : "устройства нет в последней выгрузке: связи ниже — исторические"}</span>}
        </div>
        <div className="own-meta small">
          <span>{d.name}{d.generic && <span className="badge outline">условное имя</span>}</span>
          <span>{TYPE_RU(d.personal)}</span><span>{d.os || "ОС не указана"}</span>
          <span className="muted">Источник: {d.source}, выгрузка от {fmtDate(d.snapshot_at)}</span>
        </div>
      </div>
      {d.issues.length > 0 && <ul className="own-issues" aria-label="Противоречия между источниками">{d.issues.map((x, i) => <li key={i}><Icon name="alert" size={14} />{x.text}</li>)}</ul>}
      {d.owners.length > 0 ? <Timeline owners={d.owners} canPeople={canPeople} /> : <p className="muted small">Связей с сотрудниками нет.</p>}
      {d.names.length > 0 && <p className="muted small">Прежние имена: {d.names.map((n) => `${n.name} (до ${fmtDate(n.until)})`).join(", ")}</p>}
      <div className="own-cmp">
        <div><span className="own-cap">Антивирус по BI</span>{AV_RU(d.av.uses)}{d.av.other ? <span className="block small">сторонний: {d.av.other}</span> : null}
          {d.av.origin?.length ? <span className="block muted small">происхождение: {d.av.origin.join(", ")}</span> : null}
          <span className="block muted small">сведения на {fmtDate(d.snapshot_at)}; это не состояние Kaspersky</span></div>
        {showKsc && <div><span className="own-cap">Защита по KSC</span>
          {link.length ? link.map((m) => <span key={m.id} className="block">{m.ksc ? <><b>{m.ksc.name}</b> · {m.ksc.protection_ru}<span className="block muted small">{m.ksc_source} · связь с KSC {fmt(m.ksc.last_connected)}{m.ksc.ksc_user ? ` · пользователь KSC: ${m.ksc.ksc_user}` : ""}</span></> : m.host_name}
            <span className="block muted small">{m.level_ru}: {m.signals.join("; ")}</span></span>) : <span className="block">{d.ksc_state_ru}</span>}
          {!link.length && d.matches.length > 0 && <span className="block muted small">Возможные: {d.matches.map((m) => `${m.host_name} (${m.ksc_source}) — ${m.level_ru.toLowerCase()}`).join("; ")}</span>}</div>}
      </div>
      {d.versions.length > 0 && <details className="disclosure">
        <summary>Сведения выгрузок ({d.versions.length})</summary>
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Период в выгрузках</th><th>Выгрузка-основание</th><th>Сведения</th></tr></thead>
          <tbody>{d.versions.map((v, i) => <tr key={i}><td className="nowrap small">{fmtDate(v.first_seen_at)} — {fmtDate(v.last_seen_at)}</td>
            <td className="small">{v.first_import ? `${v.first_import.file}, строка ${v.row}` : "—"}</td>
            <td className="small">{Object.entries(v.attrs).filter(([k]) => k !== "extra").map(([k, val]) => <span key={k} className="block"><span className="muted">{ATTR_RU[k] ?? k}: </span>{fmtVal(val)}{v.flags.includes(`future:${k}`) && <span className="badge warn">дата из будущего</span>}</span>)}
              {v.attrs.extra && typeof v.attrs.extra === "object" ? Object.entries(v.attrs.extra as Record<string, string>).map(([k, val]) => <span key={k} className="block"><span className="muted">{k}: </span>{val}</span>) : null}</td></tr>)}</tbody>
        </table></div>
      </details>}
    </div>
  );
}

const ATTR_RU: Record<string, string> = { person_name: "Сотрудник", email: "Почта", department: "Подразделение", account_created: "Создание учётной записи", device_name: "Имя устройства", device_uid: "Идентификатор устройства", os: "ОС",
  personal: "Личное", av_uses: "Использует антивирус", av_other: "Сторонний антивирус", observed_at: "Дата наблюдения", manual_at: "Ручное исправление", owned_from: "Начало владения", owned_to: "Окончание владения", origin: "Происхождение" };
const fmtVal = (v: unknown) => (v === true ? "да" : v === false ? "нет" : Array.isArray(v) ? v.join(", ") : typeof v === "string" && /^\d{4}-\d\d-\d\dT/.test(v) ? fmt(v) : String(v ?? ""));

/** Блок «Владелец и история принадлежности» карточки компьютера KSC: сведения BI о сопоставленном устройстве или объяснение, почему владельца не показываем. */
export function OwnerBlock({ sid, hid, activityDays }: { sid: string; hid: number; activityDays: number }) {
  const [b, setB] = useState<BiHostBlock | null>(null); const [err, setErr] = useState(""); const [report, setReport] = useState<number | null>(null);
  useEffect(() => { setB(null); setErr(""); api.bi.host(sid, hid).then(setB).catch((e) => setErr((e as ApiError).message)); }, [sid, hid]);
  if (err) return <p className="muted small">Владелец по BI: {err}</p>;
  if (!b) return <div className="own-skel" aria-hidden />;
  if (!b.bi_sources) return null;
  return (
    <section className="own-block" aria-labelledby={`own-${sid}-${hid}`}>
      <div className="own-title"><h3 className="h3" id={`own-${sid}-${hid}`}>Владелец и история принадлежности</h3>
        {b.can_people && b.devices.length > 0 && <ReportButton onClick={() => setReport(b.devices[0].id)} title="Отчёт: история принадлежности этого устройства" />}</div>
      {b.devices.map((d) => <BiDeviceView key={d.id} d={d} canPeople={b.can_people} showKsc={false} />)}
      {!b.devices.length && <p className="muted small">{b.note}.
        {b.candidates.length > 0 && <> Возможные устройства BI: {b.candidates.map((c) => `${c.name} (${c.source}) — ${c.level_ru.toLowerCase()}`).join("; ")}.{b.can_decide && <> <Link to="/devices?tab=match">Решить в «Сопоставлении BI и KSC»</Link>.</>}</>}</p>}
      {report !== null && <QuickReportPanel kind="quick_bi" title="Отчёт: история принадлежности" lede="Связи устройства с сотрудниками по выгрузкам BI" options={{ scope: false, bi: true }}
        params={{ view: "history", device_id: report }} activityDays={activityDays} canReport={b.can_people} onClose={() => setReport(null)} />}
    </section>
  );
}

/** Владелец по BI под именем компьютера: текущий, иначе последний известный с пометкой. */
export function OwnerSub({ o }: { o?: BiOwnerBrief | null }) {
  if (!o) return null;
  return <span className="owner-sub" title={`${o.state_ru}${o.level === "auto" ? " · сопоставление предполагаемое" : ""}`}>{o.multi ? "владельцы: несколько" : o.name}{o.department && <span className="muted"> · {o.department}</span>}
    {o.email && <> · <a href={`mailto:${o.email}`}>{o.email}</a></>}{o.state !== "current" && <span className="muted"> ({o.state_ru.toLowerCase()})</span>}</span>;
}
