import { useCallback, useEffect, useState } from "react";
import { api, type ApiError, type SystemStatus } from "../../api";
import { Icon } from "../../components/Icons";
import { Empty, SkelRows } from "../../components/ui";
import { bytes, fmt, num, versionLabel } from "../../util";

/** Состояние системы: backend, внутренняя база, воркер отчётов, помощник обновлений, доступность источников KSC (лёгкая проверка по кнопке). */
export default function SystemAdmin({ onOpen }: { onOpen: (tab: string) => void }) {
  const [s, setS] = useState<SystemStatus | null>(null);
  const [err, setErr] = useState("");
  const [pings, setPings] = useState<Record<string, { ok: boolean; ms: number; error?: string } | "run">>({});
  const load = useCallback(() => api.admin.system().then((x) => { setS(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); const t = window.setInterval(load, 20000); return () => window.clearInterval(t); }, [load]);
  const ping = async (id: string) => { setPings((p) => ({ ...p, [id]: "run" })); try { const r = await api.admin.pingSource(id); setPings((p) => ({ ...p, [id]: r })); } catch (e) { setPings((p) => ({ ...p, [id]: { ok: false, ms: 0, error: (e as ApiError).message } })); } };
  if (err && !s) return <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!s) return <div className="card"><SkelRows rows={4} cols={4} /></div>;
  const w = s.checks.worker;
  const services: { name: string; ok: boolean; warn?: boolean; text: string; action?: [string, string] }[] = [
    { name: "Backend API", ok: true, text: `отвечает; публичный адрес ${s.public_url}` },
    { name: "Веб-интерфейс", ok: true, text: "страница загружена из контейнера web" },
    { name: "Внутренняя база", ok: !!s.checks.postgres?.ok, text: s.checks.postgres?.ok ? "PostgreSQL доступен" : `недоступна${s.checks.postgres?.error ? `: ${s.checks.postgres.error}` : ""}` },
    { name: "Фоновые отчёты", ok: !!w?.ok, text: w?.ok ? `в очереди ${num(w.queued)}, выполняется ${num(w.running)}; последний готов ${fmt(w.last_done)}` : (w?.error ?? "не отвечает") },
    { name: "Помощник обновлений", ok: !!s.checks.updater?.ok, warn: !s.checks.updater?.ok, text: s.checks.updater?.ok ? "работает на сервере" : "не запущен — нужен только для обновлений из браузера", action: s.checks.updater?.ok ? undefined : ["updates", "Подробнее"] },
  ];
  return (
    <div className="stack">
      {!s.master_key_ok && <div className="alert error"><Icon name="alert" /><div className="alert-body">APP_MASTER_KEY не задан или некорректен: пароли источников KSC и LDAP сохранить и использовать нельзя. Задайте ключ в .env и перезапустите контейнеры.</div></div>}
      <div className="meters">
        <div className="meter"><span className="l">Версия</span><span className="v text">{versionLabel(s.version, s.commit)}</span><span className="t">сборка {s.built_at}</span></div>
        <div className="meter"><span className="l">Свободно на диске данных</span><span className="v">{bytes(s.disk_free_bytes)}</span></div>
        <div className="meter"><span className="l">События за сутки</span><span className="v">{num(s.counts.events_24h)}</span><span className="t">{s.counts.errors_24h ? <button className="link-btn" onClick={() => onOpen("journal")}>ошибок: {num(s.counts.errors_24h)}</button> : "ошибок нет"}</span></div>
        <div className="meter"><span className="l">Пользователей и отчётов</span><span className="v">{num(s.counts.users)}<span className="unit">/ {num(s.counts.reports)}</span></span></div>
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Службы</h2></div>
        <ul className="rows" style={{ padding: "4px 18px 8px" }}>{services.map((x) => (
          <li key={x.name}><span className={`dot ${x.ok ? "ok" : x.warn ? "warn" : "bad"}`} aria-hidden /><div className="r-main"><b>{x.name}</b><span className="r-sub">{x.text}</span></div>
            {x.action && <button className="btn mini" onClick={() => onOpen(x.action![0])}>{x.action[1]}</button>}</li>))}</ul>
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Источники KSC</h2><span className="muted small">Проверка доступности (SELECT 1) — только по кнопке, без нагрузки на SQL Server</span></div>
        {!s.sources.length ? <Empty icon="database" title="Источники не добавлены" action={<button className="btn primary" onClick={() => onOpen("sources")}><Icon name="plus" />Добавить источник</button>} /> : (
          <div className="table-scroll"><table className="table">
            <thead><tr><th>Источник</th><th>Последняя диагностика</th><th>Версия KSC</th><th>Доступность сейчас</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{s.sources.map((x) => { const p = pings[x.id]; return (
              <tr key={x.id}><td><b>{x.name}</b>{!x.is_active && <span className="badge warn" style={{ marginLeft: 8 }}>выключен</span>}</td>
                <td>{x.last_check_ok == null ? <span className="muted">не проверялся</span> : x.last_check_ok ? <span className="badge ok">успешно, {fmt(x.last_check_at)}</span> : <span className="badge err">ошибка, {fmt(x.last_check_at)}</span>}</td>
                <td className="mono">{x.ksc_version ?? "—"}</td>
                <td>{p === "run" ? <span className="spin" aria-label="Проверка" /> : p ? (p.ok ? <span className="ok-text">отвечает за {p.ms} мс</span> : <span className="bad-text">{p.error}</span>) : <span className="muted">—</span>}</td>
                <td className="actions"><button className="btn mini" onClick={() => void ping(x.id)} aria-busy={p === "run"}><Icon name="plug" size={15} /><span>Проверить</span></button></td></tr>); })}</tbody>
          </table></div>)}
      </div>
    </div>
  );
}
