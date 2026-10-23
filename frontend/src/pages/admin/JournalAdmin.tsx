import { Fragment, useEffect, useState } from "react";
import { api, type ApiError, type AuditRow, type JournalRow } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { fmt } from "../../util";

const LEVEL: Record<string, string> = { debug: "отладка", info: "сведения", warn: "предупреждение", error: "ошибка" };
const CATEGORY: Record<string, string> = { auth: "вход", ksc: "подключения KSC", report: "отчёты", admin: "администрирование", system: "система" };
const RANGES: [string, string][] = [["1h", "Последний час"], ["24h", "Последние сутки"], ["7d", "7 дней"], ["30d", "30 дней"], ["", "За всё время"]];

/** Журнал событий: входы, подключения к SQL Server, формирование отчётов, ошибки. Секреты и полные SQL-строки в журнал не попадают. */
export function JournalAdmin() {
  const [q, setQ] = useState(""); const [level, setLevel] = useState(""); const [category, setCategory] = useState(""); const [range, setRange] = useState("24h");
  const [applied, setApplied] = useState(""); const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: JournalRow[]; errors_24h: number } | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [err, setErr] = useState(""); const [purge, setPurge] = useState(false); const [note, setNote] = useState("");
  useEffect(() => { const t = window.setTimeout(() => { setApplied(q); setOffset(0); }, 300); return () => window.clearTimeout(t); }, [q]);
  const load = () => api.admin.journal({ q: applied, level, category, range, offset, limit: 100 }).then(setData).catch((e) => setErr((e as ApiError).message));
  useEffect(() => { void load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [applied, level, category, range, offset]);
  return (
    <section>
      <div className="row"><h2>Журнал событий</h2><div className="spacer" /><a className="btn" href={api.admin.journalExportUrl(range || "30d")} download>⬇ CSV</a><button className="btn" onClick={() => setPurge(true)}>Применить срок хранения</button></div>
      <p className="muted small">Что происходило: входы, проверки и запросы к источникам KSC, формирование отчётов, действия администраторов и ошибки. Время, пользователь, источник, результат и длительность. Пароли и SQL с параметрами в журнал не записываются.</p>
      {data && <div className={`alert ${data.errors_24h ? "error" : "ok"}`}>{data.errors_24h ? `За сутки ошибок: ${data.errors_24h}.` : "За сутки ошибок нет."}</div>}
      {note && <div className="alert ok">{note}</div>}
      <div className="card filters">
        <div className="row filter-row">
          <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Поиск по сообщению, событию, пользователю, источнику" aria-label="Поиск" />
          <select value={range} onChange={(e) => { setRange(e.target.value); setOffset(0); }} aria-label="Период" style={{ width: "auto" }}>{RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
          <select value={level} onChange={(e) => { setLevel(e.target.value); setOffset(0); }} aria-label="Уровень" style={{ width: "auto" }}><option value="">любой уровень</option><option value="warn">предупреждения и ошибки</option><option value="error">только ошибки</option><option value="info">сведения</option></select>
          <select value={category} onChange={(e) => { setCategory(e.target.value); setOffset(0); }} aria-label="Категория" style={{ width: "auto" }}><option value="">любая категория</option>{Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        </div>
      </div>
      {err && <div className="alert error">{err}</div>}
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Время</th><th>Уровень</th><th>Категория</th><th>Событие</th><th>Пользователь</th><th>Источник</th><th>Сообщение</th><th className="num">мс</th></tr></thead>
        <tbody>{(data?.items ?? []).map((r) => (
          <Fragment key={r.id}>
            <tr onClick={() => setOpen(open === r.id ? null : r.id)} style={{ cursor: "pointer" }}><td className="nowrap">{fmt(r.at)}</td><td><span className={`badge ${r.level === "error" ? "err" : r.level === "warn" ? "warn" : ""}`}>{LEVEL[r.level] ?? r.level}</span></td><td>{CATEGORY[r.category] ?? r.category}</td><td><code>{r.event}</code></td><td>{r.user ?? "—"}</td><td>{r.source ?? "—"}</td><td className="small">{r.message ?? ""}</td><td className="num small">{r.duration_ms ?? ""}</td></tr>
            {open === r.id && <tr className="detail"><td colSpan={8}><div className="small">запись #{r.id}{r.ip ? ` · IP ${r.ip}` : ""}{r.request_id ? ` · запрос ${r.request_id}` : ""}</div>{r.data ? <pre className="debug">{JSON.stringify(r.data, null, 2)}</pre> : null}</td></tr>}
          </Fragment>))}
          {data && !data.items.length && <tr><td colSpan={8} className="empty">Записей по этим условиям нет.</td></tr>}
        </tbody>
      </table></div>
      <div className="pager"><div className="spacer" /><button className="btn mini" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>‹ Назад</button><button className="btn mini" disabled={!data || data.items.length < 100} onClick={() => setOffset(offset + 100)}>Вперёд ›</button></div>
      {purge && <ConfirmDialog title="Применить срок хранения?" confirmLabel="Применить" danger={false} body={<p>Записи старше срока хранения (настройка «Общие → Хранить журнал событий») будут удалены сразу.</p>} onClose={() => setPurge(false)} onConfirm={async () => { const r = await api.admin.journalPurge(); setNote(`Удалено записей: ${r.deleted}`); void load(); }} />}
    </section>
  );
}

/** Журнал действий пользователей: кто, что, когда, с каким результатом. */
export function AuditAdmin() {
  const [q, setQ] = useState(""); const [action, setAction] = useState(""); const [applied, setApplied] = useState({ q: "", action: "" }); const [offset, setOffset] = useState(0);
  const [items, setItems] = useState<AuditRow[]>([]); const [err, setErr] = useState("");
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, action }); setOffset(0); }, 300); return () => window.clearTimeout(t); }, [q, action]);
  useEffect(() => { api.admin.audit({ ...applied, offset, limit: 100 }).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); }, [applied, offset]);
  return (
    <section>
      <h2>Журнал действий</h2>
      <p className="muted small">Действия пользователей: входы, изменения настроек и источников, создание и скачивание отчётов, сценарии аудита. Хранится отдельно от журнала событий; пароли и секреты не записываются.</p>
      <div className="card filters"><div className="row filter-row">
        <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Поиск по исполнителю, действию, объекту" aria-label="Поиск" />
        <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="Действие начинается с, например report." aria-label="Действие" style={{ maxWidth: 260 }} />
      </div></div>
      {err && <div className="alert error">{err}</div>}
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Объект</th><th>Подробности</th><th>Результат</th><th>IP</th><th className="num">мс</th></tr></thead>
        <tbody>{items.map((r) => <tr key={r.id}><td className="nowrap">{fmt(r.at)}</td><td>{r.actor}</td><td><code>{r.action}</code></td><td>{r.target_type} <span className="muted small">{r.target_id.slice(0, 12)}</span></td><td className="small">{r.details ? JSON.stringify(r.details).slice(0, 200) : ""}</td><td>{r.result === "success" ? "успех" : <span className="badge warn">{r.result === "denied" ? "отказ" : "ошибка"}</span>}</td><td className="small">{r.ip ?? ""}</td><td className="num small">{r.duration_ms ?? ""}</td></tr>)}
          {!items.length && <tr><td colSpan={8} className="empty">Записей нет.</td></tr>}
        </tbody>
      </table></div>
      <div className="pager"><div className="spacer" /><button className="btn mini" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>‹ Назад</button><button className="btn mini" disabled={items.length < 100} onClick={() => setOffset(offset + 100)}>Вперёд ›</button></div>
    </section>
  );
}
