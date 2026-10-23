import type { ReactNode } from "react";
import type { DiagResult } from "../api";
import { fmt, num } from "../util";

const STAGE_TITLE: Record<string, string> = { connect: "Подключение", server: "SQL Server", objects: "Объекты KSC", rights: "Права учётной записи", ksc: "Версия KSC", read: "Пробное чтение", base_dn: "Чтение Base DN", auth: "Тестовый вход", error: "Ошибка", config: "Настройка" };

/** Результат пошаговой проверки подключения (SQL Server, LDAP): каждый этап отдельной строкой. */
export function StageList({ result }: { result: DiagResult }) {
  return (
    <div className={`alert ${result.ok ? "ok" : "error"}`} role="status">
      <strong>{result.ok ? "✓ Проверка пройдена" : "✗ Проверка не пройдена"}</strong>
      <ul className="stage-list">
        {result.stages.map((s, i) => (
          <li key={i} className={s.ok === false ? "bad" : s.ok === null ? "skip" : "ok"}>
            <span className="stage-mark" aria-hidden>{s.ok === false ? "✗" : s.ok === null ? "•" : "✓"}</span>
            <span><b>{STAGE_TITLE[s.stage] ?? s.stage}.</b> {s.message}{s.ms ? <span className="muted small"> ({s.ms} мс)</span> : null}</span>
          </li>
        ))}
      </ul>
      {result.warnings?.map((w, i) => <div key={i} className="small" style={{ marginTop: 6 }}>⚠ {w}</div>)}
    </div>
  );
}

/** Секрет: сохранённое значение никогда не показывается — только «задан». Пустое поле при сохранении = не менять. */
export function SecretInput({ label, isSet, value, onChange, help, disabled }: { label: string; isSet: boolean; value: string; onChange: (v: string) => void; help?: ReactNode; disabled?: boolean }) {
  const editing = !isSet || value !== "";
  return (
    <label>{label}
      {isSet && !editing ? (
        <span className="row tight secret-row"><span className="badge ok">пароль задан</span><button type="button" className="btn mini" onClick={() => onChange(" ")} disabled={disabled}>Изменить</button></span>
      ) : (
        <span className="row tight secret-row">
          <input type="password" autoComplete="new-password" value={value === " " ? "" : value} onChange={(e) => onChange(e.target.value)} placeholder={isSet ? "новый пароль" : ""} disabled={disabled} autoFocus={isSet} />
          {isSet && <button type="button" className="btn mini" onClick={() => onChange("")}>Отмена</button>}
        </span>
      )}
      {help && <span className="help">{help}</span>}
    </label>
  );
}
export const secretToSend = (v: string): string | undefined => (v === "" || v === " " ? undefined : v);

export function Pager({ total, offset, limit, onPage, approximate }: { total: number; offset: number; limit: number; onPage: (o: number) => void; approximate?: boolean }) {
  const page = Math.floor(offset / limit) + 1, pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pager">
      <span className="muted small">{total ? `Показано ${num(offset + 1)}–${num(Math.min(offset + limit, total))} из ${approximate ? "≈" : ""}${num(total)}` : "Нет записей"}</span>
      <div className="spacer" />
      <button className="btn mini" disabled={offset === 0} onClick={() => onPage(0)}>«</button>
      <button className="btn mini" disabled={offset === 0} onClick={() => onPage(Math.max(0, offset - limit))}>‹ Назад</button>
      <span className="small num">{page} / {pages}</span>
      <button className="btn mini" disabled={offset + limit >= total} onClick={() => onPage(offset + limit)}>Вперёд ›</button>
    </div>
  );
}

export function Fetched({ at, prefix = "Данные получены" }: { at: string | null | undefined; prefix?: string }) {
  return <span className="muted small">{prefix}: {fmt(at)}</span>;
}

export function ActivityBadge({ days, activityDays }: { days: number | null; activityDays: number }) {
  if (days === null) return <span className="badge err">нет подключений</span>;
  return <span className={`badge ${days <= activityDays ? "ok" : "warn"}`}>{days <= activityDays ? "активен" : "без связи"} · {days} сут</span>;
}

export function Planned({ title, items, note }: { title: string; items: string[]; note?: string }) {
  return (
    <div className="card planned">
      <h2>{title}</h2>
      <p className="muted">{note ?? "Раздел подготовлен в архитектуре и навигации; реализация запланирована на следующие выпуски. Данные не формируются, пока модуль не реализован."}</p>
      <ul>{items.map((x) => <li key={x}>{x}</li>)}</ul>
    </div>
  );
}
