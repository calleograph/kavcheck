import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type EolFinding, type EolStatus } from "../api";
import { fmtDate, num, plural } from "../util";

export const EOL_STATUS_TEXT: Record<EolStatus, string> = { eol: "EOL: поддержка закончилась", extended: "Только расширенная поддержка", upcoming: "Поддержка скоро закончится", unknown: "Нет данных", undetermined: "Не удалось определить EOL" };
const TONE: Record<EolStatus, string> = { eol: "err", extended: "warn", upcoming: "accent", unknown: "", undetermined: "" };
const SEV_CLASS: Record<string, string> = { critical: "crit", high: "high", warning: "warn" };

export function EolBadge({ s, short }: { s: EolStatus; short?: boolean }) {
  return <span className={`badge ${TONE[s]}`}>{short ? ({ eol: "EOL", extended: "Расширенная", upcoming: "Скоро EOL", unknown: "Нет данных", undetermined: "Не определён" } as Record<EolStatus, string>)[s] : EOL_STATUS_TEXT[s]}</span>;
}

export function EolSev({ f }: { f: Pick<EolFinding, "severity" | "severity_ru"> }) {
  return f.severity ? <span className={`sev ${SEV_CLASS[f.severity]}`}>{f.severity_ru}</span> : <span className="muted">—</span>;
}

/** Срок поддержки: дата и сколько осталось или прошло; стандартная и расширенная поддержка — раздельно. */
export function EolDates({ f }: { f: Pick<EolFinding, "eol_from" | "eoes_from" | "days_left" | "status"> }) {
  if (!f.eol_from && !f.eoes_from) return <span className="muted">дат нет</span>;
  const d = f.days_left;
  const left = d === null ? "" : d < 0 ? `закончилась ${num(-d)} ${plural(-d, "день", "дня", "дней")} назад` : d === 0 ? "заканчивается сегодня" : `осталось ${num(d)} ${plural(d, "день", "дня", "дней")}`;
  return (
    <span className="eol-dates">
      {f.eol_from && <span className="nowrap">стандартная — до {fmtDate(f.eol_from)}</span>}
      {left && <span className="sub">{left}</span>}
      {f.eoes_from && <span className="sub nowrap">расширенная — до {fmtDate(f.eoes_from)}</span>}
    </span>
  );
}

/** Ссылка на карточку устройства (подготовленные данные, пользователи, EOL). */
export const deviceLink = (sourceId: string, hostId: number) => `/devices?card=${sourceId}:${hostId}`;
export function DeviceLink({ sourceId, hostId, name }: { sourceId: string; hostId: number; name: string }) {
  return <Link to={deviceLink(sourceId, hostId)} className="strong-link">{name}</Link>;
}

/** Блок карточки компьютера: программы и ОС без поддержки производителя (готовые результаты EOL, KSC не опрашивается). */
export function HostEol({ sourceId, hostId }: { sourceId: string; hostId: number }) {
  const [items, setItems] = useState<EolFinding[] | null>(null);
  useEffect(() => { setItems(null); api.eol.host(sourceId, hostId).then((r) => setItems(r.items)).catch(() => setItems([])); }, [sourceId, hostId]);
  if (items === null || items.length === 0) return null;                 // нет проблем или сопоставление ещё не рассчитано — блок не показывается
  return (
    <div className="card flush">
      <div className="card-head"><h2>EOL: поддержка закончилась или заканчивается</h2></div>
      <div className="table-scroll"><table className="table compact"><thead><tr><th>Критичность</th><th>Программа или ОС</th><th>Поддержка</th></tr></thead>
        <tbody>{items.map((f) => <tr key={`${f.kind}${f.subject}${f.version}`}><td><EolSev f={f} /></td><td><strong>{f.title}</strong>{f.kind === "app" && <span className="sub mono small">{f.version}</span>}<span className="sub small">{f.eol_label}, ветка {f.eol_release}</span></td>
          <td><EolBadge s={f.status} short /><EolDates f={f} /></td></tr>)}</tbody></table></div>
      <p className="muted small pad-x"><Link to="/eol">Раздел EOL</Link></p>
    </div>
  );
}
