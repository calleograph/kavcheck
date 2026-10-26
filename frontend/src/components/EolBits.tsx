import { Link } from "react-router-dom";
import { type EolFinding, type EolStatus } from "../api";
import { fmtDate, num, plural } from "../util";

export const EOL_STATUS_TEXT: Record<EolStatus, string> = { eol: "EOL: поддержка закончилась", extended: "Только расширенная поддержка", upcoming: "Поддержка скоро закончится", unknown: "Нет данных" };
const TONE: Record<EolStatus, string> = { eol: "err", extended: "warn", upcoming: "accent", unknown: "" };
const SEV_CLASS: Record<string, string> = { critical: "crit", high: "high", warning: "warn" };

export function EolBadge({ s, short }: { s: EolStatus; short?: boolean }) {
  return <span className={`badge ${TONE[s]}`}>{short ? ({ eol: "EOL", extended: "Расширенная", upcoming: "Скоро EOL", unknown: "Нет данных" } as Record<EolStatus, string>)[s] : EOL_STATUS_TEXT[s]}</span>;
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
