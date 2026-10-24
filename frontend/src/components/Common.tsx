import type { ReactNode } from "react";
import type { DiagResult } from "../api";
import { ago, fmt, num } from "../util";
import { Icon } from "./Icons";

const STAGE_TITLE: Record<string, string> = { dns: "DNS", tcp: "TCP", tls: "TLS и сертификат", bind: "Вход сервисной записи", user: "Поиск пользователя", groups: "Группы", access: "Доступ в KAV Checker",
  parse: "Имя пользователя", search: "Поиск", choose: "Выбор домена", session: "Вход в KAV Checker", connect: "Подключение", server: "SQL Server", objects: "Объекты KSC", rights: "Права учётной записи", ksc: "Версия KSC", read: "Пробное чтение", base_dn: "Чтение Base DN", auth: "Проверка пароля", error: "Ошибка", config: "Настройка" };

/** Результат пошаговой проверки (SQL Server, LDAPS, вход пользователя): каждый этап отдельной строкой. */
export function StageList({ result, okText = "Проверка пройдена" }: { result: DiagResult; okText?: string }) {
  return (
    <div className="diag" role="status">
      <div className={`diag-head ${result.ok ? "ok" : "bad"}`}><Icon name={result.ok ? "checkCircle" : "xCircle"} />{result.ok ? okText : "Проверка не пройдена"}</div>
      <ul className="stage-list">
        {result.stages.map((s, i) => (
          <li key={i} className={s.ok === false ? "bad" : s.ok === null ? "skip" : "ok"}>
            <span className="stage-mark" aria-hidden><Icon name={s.ok === false ? "close" : s.ok === null ? "info" : "check"} size={12} strokeWidth={2.6} /></span>
            <span><b>{STAGE_TITLE[s.stage] ?? s.stage}.</b> {s.message}{s.ms ? <span className="ms"> · {s.ms} мс</span> : null}</span>
          </li>
        ))}
      </ul>
      {result.warnings?.map((w, i) => <div key={i} className="warns"><Icon name="alert" size={16} /><span>{w}</span></div>)}
    </div>
  );
}

/** Секрет: сохранённое значение никогда не показывается — только «задан». Пустое поле при сохранении = не менять. */
export function SecretInput({ label, isSet, value, onChange, help, disabled }: { label: string; isSet: boolean; value: string; onChange: (v: string) => void; help?: ReactNode; disabled?: boolean }) {
  const editing = !isSet || value !== "";
  return (
    <label>{label}
      {isSet && !editing ? (
        <span className="row tight secret-row"><span className="badge ok"><Icon name="key" size={13} />пароль задан</span><button type="button" className="btn mini" onClick={() => onChange(" ")} disabled={disabled}>Заменить</button></span>
      ) : (
        <span className="row tight secret-row">
          <input type="password" autoComplete="new-password" value={value === " " ? "" : value} onChange={(e) => onChange(e.target.value)} placeholder={isSet ? "новый пароль" : ""} disabled={disabled} autoFocus={isSet} />
          {isSet && <button type="button" className="btn mini ghost" onClick={() => onChange("")}>Отмена</button>}
        </span>
      )}
      {help && <span className="help">{help}</span>}
    </label>
  );
}
export const secretToSend = (v: string): string | undefined => (v === "" || v === " " ? undefined : v);

export function Pager({ total, offset, limit, onPage, approximate }: { total: number; offset: number; limit: number; onPage: (o: number) => void; approximate?: boolean }) {
  if (!total) return null;
  const page = Math.floor(offset / limit) + 1, pages = Math.max(1, Math.ceil(total / limit));
  return (
    <nav className="pager" aria-label="Страницы">
      <span className="info">{num(offset + 1)}–{num(Math.min(offset + limit, total))} из {approximate ? "≈" : ""}{num(total)}</span>
      <div className="spacer" />
      {pages > 1 && <>
        <button className="btn mini icon" disabled={offset === 0} onClick={() => onPage(0)} aria-label="Первая страница"><Icon name="chevronsL" size={16} /></button>
        <button className="btn mini icon" disabled={offset === 0} onClick={() => onPage(Math.max(0, offset - limit))} aria-label="Предыдущая страница"><Icon name="chevronL" size={16} /></button>
        <span className="page">{page} / {pages}</span>
        <button className="btn mini icon" disabled={offset + limit >= total} onClick={() => onPage(offset + limit)} aria-label="Следующая страница"><Icon name="chevronR" size={16} /></button>
      </>}
    </nav>
  );
}

export function Fetched({ at, prefix = "Данные получены" }: { at: string | null | undefined; prefix?: string }) {
  return <span className="stamp" title="Время получения данных из базы KSC"><Icon name="clock" size={14} />{prefix} {fmt(at)}</span>;
}

/** Присутствие в сети сейчас — по флагу KSC «видимо», отдельно от давности последнего подключения Агента. */
export function OnlineBadge({ online, seen }: { online: boolean | null | undefined; seen?: string | null }) {
  if (online == null) return <span className="badge outline" title="KSC не передал сведения о присутствии устройства в сети">нет данных</span>;
  if (online) return <span className="badge ok" title="KSC сейчас видит устройство в сети"><span className="dot" />в сети</span>;
  const since = seen ? Math.max(0, Math.round((Date.now() - new Date(seen).getTime()) / 1000)) : null;
  return <span className="badge" title={seen ? `KSC последний раз видел устройство ${fmt(seen)}` : "KSC не видит устройство в сети"}><span className="dot off" />не в сети{since !== null && since > 600 ? `, ${ago(since)}` : ""}</span>;
}

export function ActivityBadge({ days, activityDays }: { days: number | null; activityDays: number }) {
  if (days === null) return <span className="badge err"><span className="dot" />нет подключений</span>;
  const on = days <= activityDays;
  const d = days < 1 ? "менее суток" : `${String(days).replace(".", ",")} сут`;
  return <span className={`badge ${on ? "ok" : "warn"}`} title={on ? `Связь с KSC в пределах ${activityDays} сут` : `Нет связи с KSC дольше ${activityDays} сут`}><span className="dot" />{d}</span>;
}
