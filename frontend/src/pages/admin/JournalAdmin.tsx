import { useEffect, useState } from "react";
import { api, type AuditRow, type JournalRow } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { ListFoot, VirtualRows, useInfinite, type Chunk } from "../../components/Infinite";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows, MaskHint } from "../../components/ui";
import { fmt } from "../../util";

const LEVEL: Record<string, [string, string]> = { debug: ["отладка", "outline"], info: ["сведения", ""], warn: ["предупреждение", "warn"], error: ["ошибка", "err"] };
const CATEGORY: Record<string, string> = { auth: "Вход", ksc: "Источники KSC", report: "Отчёты", catalog: "Каталог программ", worker: "Фоновые задачи", admin: "Администрирование", system: "Система" };
const RANGES: [string, string][] = [["1h", "За час"], ["24h", "За сутки"], ["7d", "За 7 дней"], ["30d", "За 30 дней"], ["", "За всё время"]];

/** Журнал событий: входы, подключения к SQL Server, формирование отчётов, ошибки. Секреты и полные SQL-строки в журнал не попадают. */
export function JournalAdmin() {
  const [q, setQ] = useState(""); const [level, setLevel] = useState(""); const [category, setCategory] = useState(""); const [range, setRange] = useState("24h");
  const [since, setSince] = useState(""); const [until, setUntil] = useState("");
  const [applied, setApplied] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [purge, setPurge] = useState(false);
  const [toast, show] = useToast();
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 300); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<JournalRow>("journal", [applied, level, category, range, since, until], (offset, limit) => api.admin.journal({ q: applied, level, category,
    range: range === "custom" ? "" : range, since: range === "custom" && since ? new Date(since).toISOString() : undefined,
    until: range === "custom" && until ? new Date(until).toISOString() : undefined, offset, limit }) as unknown as Promise<Chunk<JournalRow>>);
  const data = list.extra as { errors_24h?: number } | null;
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Сообщение, событие, пользователь, источник" aria-label="Поиск по журналу" /><MaskHint /></div>
        <select value={range} onChange={(e) => setRange(e.target.value)} aria-label="Период" className="w-auto">{RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}<option value="custom">свой период…</option></select>
        {range === "custom" && <><input type="datetime-local" className="w-auto" value={since} onChange={(e) => setSince(e.target.value)} aria-label="С" />
          <input type="datetime-local" className="w-auto" value={until} onChange={(e) => setUntil(e.target.value)} aria-label="По" /></>}
        <select value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Уровень" className="w-auto"><option value="">Все уровни</option><option value="warn">Предупреждения и ошибки</option><option value="error">Только ошибки</option><option value="info">Сведения</option></select>
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Компонент" className="w-auto"><option value="">Все компоненты</option>{Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <a className="btn" href={api.admin.journalExportUrl(range === "custom" ? "30d" : range || "30d")} download><Icon name="download" />CSV</a>
      </div>
      {data && (data.errors_24h ? <div className="alert error"><Icon name="alert" /><div className="alert-body">За последние сутки ошибок: <b>{data.errors_24h}</b>. <button className="link-btn" onClick={() => { setLevel("error"); setRange("24h"); }}>Показать только их</button></div></div>
        : <div className="alert ok"><Icon name="checkCircle" /><div className="alert-body">За последние сутки ошибок нет.</div></div>)}
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table compact virt">
            <thead><tr><th>Время</th><th>Уровень</th><th>Категория</th><th>Событие</th><th>Пользователь</th><th>Источник</th><th>Сообщение</th><th className="num">мс</th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={8} estimate={34} row={(r) => { const [l, c] = LEVEL[r.level] ?? [r.level, ""]; return (
                <tr onClick={(e) => { if (!(e.target as HTMLElement).closest("pre")) setOpen(open === r.id ? null : r.id); }} className="clickable" aria-expanded={open === r.id}>
                  <td className="nowrap">{fmt(r.at)}</td><td><span className={`badge ${c}`}>{l}</span></td><td>{CATEGORY[r.category] ?? r.category}</td><td className="mono nowrap">{r.event}</td><td>{r.user ?? "—"}</td><td>{r.source ?? "—"}</td>
                  <td>{r.message ?? ""}{open === r.id && <div className="row-detail"><div className="small muted">Запись {r.id}{r.ip ? `, IP ${r.ip}` : ""}{r.request_id ? `, запрос ${r.request_id}` : ""}</div>{r.data ? <pre className="debug">{JSON.stringify(r.data, null, 2)}</pre> : null}</div>}</td>
                  <td className="num">{r.duration_ms ?? ""}</td></tr>); }} />
              {!list.items.length && !list.loading && <tr><td colSpan={8}><Empty icon="journal" title="Записей нет">За выбранный период по этим условиям событий не было.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <p className="muted small mt-sm">Редкое действие: <button className="link-btn" onClick={() => setPurge(true)}>удалить записи старше срока хранения</button> (срок — в разделе «Общие настройки»).</p>
      {purge && <ConfirmDialog title="Применить срок хранения?" confirmLabel="Удалить старые записи" danger={false} body={<p>Записи старше срока хранения из раздела «Общие настройки» будут удалены сейчас.</p>} onClose={() => setPurge(false)} onConfirm={async () => { const r = await api.admin.journalPurge(); show(`Удалено записей: ${r.deleted}`); list.reload(); }} />}
      {toast}
    </>
  );
}

/** Журнал действий пользователей: кто, что, когда, с каким результатом. */
export function AuditAdmin() {
  const [q, setQ] = useState(""); const [action, setAction] = useState(""); const [applied, setApplied] = useState({ q: "", action: "" });
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, action }), 300); return () => window.clearTimeout(t); }, [q, action]);
  const list = useInfinite<AuditRow>("audit", [applied], (offset, limit) => api.admin.audit({ ...applied, offset, limit }) as unknown as Promise<Chunk<AuditRow>>);
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Кто, что или объект" aria-label="Поиск" /><MaskHint /></div>
        <input className="mono w-md" value={action} onChange={(e) => setAction(e.target.value)} placeholder="report." aria-label="Действие начинается с" />
        <p className="note">Хранится отдельно от журнала событий. Пароли и секреты не записываются; у проверок подключения указана длительность.</p>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table compact virt">
            <thead><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Объект</th><th>Подробности</th><th>Результат</th><th>IP</th><th className="num">мс</th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={8} estimate={36} row={(r) => <tr><td className="nowrap">{fmt(r.at)}</td><td>{r.actor}</td><td className="mono">{r.action}</td><td>{r.target_type}<span className="sub mono">{r.target_id.slice(0, 12)}</span></td><td className="small mono">{r.details ? JSON.stringify(r.details).slice(0, 160) : ""}</td>
                <td>{r.result === "success" ? <span className="badge ok">успех</span> : <span className="badge warn">{r.result === "denied" ? "отказ" : "ошибка"}</span>}</td><td className="mono small">{r.ip ?? ""}</td><td className="num">{r.duration_ms ?? ""}</td></tr>} />
              {!list.items.length && !list.loading && <tr><td colSpan={8}><Empty icon="history" title="Записей нет">Измените условия поиска.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
    </>
  );
}
