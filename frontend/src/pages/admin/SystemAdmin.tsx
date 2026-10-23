import { useCallback, useEffect, useState } from "react";
import { api, type ApiError, type SystemStatus } from "../../api";
import { bytes, fmt, num, versionLabel } from "../../util";

/** Состояние системы: backend, внутренняя база, воркер отчётов, помощник обновлений, доступность источников KSC (лёгкая проверка по кнопке). */
export default function SystemAdmin({ onOpen }: { onOpen: (tab: string) => void }) {
  const [s, setS] = useState<SystemStatus | null>(null);
  const [err, setErr] = useState("");
  const [pings, setPings] = useState<Record<string, { ok: boolean; ms: number; error?: string } | "run">>({});
  const load = useCallback(() => api.admin.system().then((x) => { setS(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); const t = window.setInterval(load, 20000); return () => window.clearInterval(t); }, [load]);
  const ping = async (id: string) => { setPings((p) => ({ ...p, [id]: "run" })); try { setPings((p) => ({ ...p, [id]: undefined as never })); const r = await api.admin.pingSource(id); setPings((p) => ({ ...p, [id]: r })); } catch (e) { setPings((p) => ({ ...p, [id]: { ok: false, ms: 0, error: (e as ApiError).message } })); } };
  if (err && !s) return <div className="alert error">{err}</div>;
  if (!s) return <div className="muted">Загрузка…</div>;
  const names: Record<string, string> = { postgres: "Внутренняя база (PostgreSQL)", worker: "Фоновая обработка отчётов", updater: "Помощник обновлений (на сервере)" };
  return (
    <section>
      <h2>Состояние системы</h2>
      {!s.master_key_ok && <div className="alert error">APP_MASTER_KEY не задан или некорректен: пароли источников KSC и LDAP сохранить и использовать нельзя. Задайте ключ в .env и перезапустите контейнеры.</div>}
      <div className="kpi">
        <div className="card"><div className="l">Версия · commit</div><div className="v" style={{ fontSize: 16 }}>{versionLabel(s.version, s.commit)}</div><div className="t">сборка {s.built_at}</div></div>
        <div className="card"><div className="l">Свободно на диске данных</div><div className="v">{bytes(s.disk_free_bytes)}</div></div>
        <div className="card"><div className="l">Отчётов в очереди · выполняется</div><div className="v">{num(s.checks.worker?.queued)} · {num(s.checks.worker?.running)}</div><div className="t">последний готов: {fmt(s.checks.worker?.last_done)}</div></div>
        <div className="card"><div className="l">Событий за сутки · ошибок</div><div className="v">{num(s.counts.events_24h)} · <span className={s.counts.errors_24h ? "bad-text" : ""}>{num(s.counts.errors_24h)}</span></div><div className="t"><button className="btn mini" onClick={() => onOpen("journal")}>журнал</button></div></div>
      </div>
      <h3>Службы</h3>
      <div className="grid">
        <div className="card"><div className="row"><span className="dot ok" /><b>Backend API</b></div><div className="muted small">работает (ответил на этот запрос) · публичный адрес {s.public_url}</div></div>
        <div className="card"><div className="row"><span className="dot ok" /><b>Frontend</b></div><div className="muted small">страница загружена из контейнера web</div></div>
        {Object.entries(s.checks).map(([k, v]) => (
          <div key={k} className="card"><div className="row"><span className={`dot ${v.ok ? "ok" : v.optional ? "warn" : "bad"}`} /><b>{names[k] ?? k}</b></div>
            <div className="muted small">{v.ok ? "работает" : v.optional ? "не запущен (нужен только для обновлений из браузера)" : `недоступен${v.error ? `: ${v.error}` : ""}`}</div>
            {k === "updater" && !v.ok && <div className="row tight" style={{ marginTop: 6 }}><button className="btn mini" onClick={() => onOpen("updates")}>Обновления</button></div>}
          </div>))}
      </div>
      <h3 style={{ marginTop: 16 }}>Источники KSC</h3>
      <p className="muted small">Лёгкая проверка доступности (SELECT 1) выполняется только по кнопке — без нагрузки на SQL Server. Полная диагностика — в разделе «Источники KSC».</p>
      <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Источник</th><th>Состояние</th><th>Последняя диагностика</th><th>KSC</th><th>Доступность сейчас</th><th /></tr></thead>
        <tbody>{s.sources.map((x) => { const p = pings[x.id]; return (
          <tr key={x.id}><td>{x.name}</td><td>{x.is_active ? "активен" : <span className="badge warn">выключен</span>}</td><td>{x.last_check_ok == null ? <span className="muted">не проверялся</span> : x.last_check_ok ? <span className="ok-text">успешно · {fmt(x.last_check_at)}</span> : <span className="bad-text">ошибка · {fmt(x.last_check_at)}</span>}</td><td>{x.ksc_version ?? "—"}</td>
            <td>{p === "run" ? "проверка…" : p ? (p.ok ? <span className="ok-text">отвечает · {p.ms} мс</span> : <span className="bad-text">{p.error}</span>) : "—"}</td>
            <td className="actions"><button className="btn mini" onClick={() => void ping(x.id)} disabled={p === "run"}>Проверить</button></td></tr>); })}
          {!s.sources.length && <tr><td colSpan={6} className="empty">Источники не добавлены. <button className="btn mini" onClick={() => onOpen("sources")}>Добавить</button></td></tr>}
        </tbody>
      </table></div>
      <h3 style={{ marginTop: 16 }}>Данные</h3>
      <table className="table compact"><tbody>{Object.entries({ "Пользователей": s.counts.users, "Источников KSC": s.counts.sources, "Отчётов": s.counts.reports }).map(([k, v]) => <tr key={k}><td>{k}</td><td className="num">{num(v)}</td></tr>)}</tbody></table>
    </section>
  );
}
