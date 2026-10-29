import { useCallback, useEffect, useState } from "react";
import { api, type ApiError, type SystemStatus } from "../../api";
import { Icon } from "../../components/Icons";
import { Empty, SkelRows } from "../../components/ui";
import { bytes, fmt, fmtTs, num, versionLabel } from "../../util";

const CATALOG: Record<string, [string, string]> = { ready: ["построен", "ok"], interrupted: ["прервано, будет повторено", "warn"], building: ["строится", "accent"], failed: ["ошибка", "err"], empty: ["не построен", "warn"] };
const KIND_RU: Record<string, string> = { catalog: "каталог программ", eol: "расчёт EOL", vdb_sync: "загрузка базы уязвимостей", vdb_analyze: "анализ уязвимостей", zonecache: "данные зон", zjob: "расчёт зон", report: "отчёт", bi: "импорт BI", devices: "опрос пользователей", licenses: "чтение лицензий", ov_snapshot: "срез главной", pentest: "Pentest" };
const ACTION: Record<string, string> = { update: "обновление", rollback: "откат", backup: "резервная копия", restore: "восстановление" };

function Usage({ used, total, label }: { used: number | null | undefined; total: number | null | undefined; label: string }) {
  if (!used || !total) return <span className="muted">—</span>;
  const pct = Math.round((used / total) * 100);
  return (
    <span className="usage" role="img" aria-label={`${label}: занято ${pct}%`}>
      <span className="usage-bar"><span className={`usage-fill ${pct >= 90 ? "bad" : pct >= 75 ? "warn" : ""}`} style={{ width: `${pct}%` }} /></span>
      <span className="small">{bytes(total - used)} свободно из {bytes(total)}</span>
    </span>
  );
}

/** Состояние системы: компоненты, ресурсы сервера, данные, источники KSC и каталог, безопасность, ошибки фоновых задач, история обновлений. */
const LANE_RU: Record<string, string> = { bg: "очередь тяжёлых расчётов", bi: "очередь BI", interactive: "очередь отчётов" };

export default function SystemAdmin({ onOpen }: { onOpen: (tab: string) => void }) {
  const [s, setS] = useState<SystemStatus | null>(null);
  const [err, setErr] = useState("");
  const [pings, setPings] = useState<Record<string, { ok: boolean; ms: number; error?: string } | "run">>({});
  const load = useCallback(() => api.admin.system().then((x) => { setS(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); const t = window.setInterval(load, 20000); return () => window.clearInterval(t); }, [load]);
  const ping = async (id: string) => { setPings((p) => ({ ...p, [id]: "run" })); try { const r = await api.admin.pingSource(id); setPings((p) => ({ ...p, [id]: r })); } catch (e) { setPings((p) => ({ ...p, [id]: { ok: false, ms: 0, error: (e as ApiError).message } })); } };
  if (err && !s) return <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!s) return <div className="card"><SkelRows rows={4} cols={4} /></div>;
  const r = s.resources, st = s.storage;
  return (
    <div className="stack">
      {!s.master_key_ok && <div className="alert error"><Icon name="alert" /><div className="alert-body">APP_MASTER_KEY не задан или некорректен: пароли источников KSC и LDAPS, второй фактор недоступны. Задайте ключ в .env и перезапустите сервисы.</div></div>}
      {!s.security.https && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Приложение открывается по HTTP ({s.public_url}): cookie сессии передаётся без флага Secure. После перехода на HTTPS укажите адрес https:// в APP_PUBLIC_URL — защищённый режим включится сам (COOKIE_SECURE=auto).</div></div>}
      <div className="meters">
        <div className="meter"><span className="l">Версия</span><span className="v text">{versionLabel(s.version, s.commit)}</span><span className="t">сборка {s.built_at}</span></div>
        <div className="meter"><span className="l">Процессор</span><span className="v">{s.resources.load ? String(s.resources.load[0]).replace(".", ",") : "—"}</span><span className="t">нагрузка за минуту · ядер {r.cpu_count ?? "?"}</span></div>
        <div className="meter"><span className="l">Оперативная память</span><span className="v">{r.memory_total && r.memory_available ? `${Math.round(((r.memory_total - r.memory_available) / r.memory_total) * 100)}%` : "—"}</span><span className="t">{bytes(r.memory_available)} свободно из {bytes(r.memory_total)}</span></div>
        <div className="meter"><span className="l">Ошибки за сутки</span><span className={`v ${s.counts.errors_24h ? "bad-text" : ""}`}>{num(s.counts.errors_24h)}</span><span className="t">{s.counts.errors_24h ? <button className="link-btn" onClick={() => onOpen("journal")}>открыть журнал</button> : `событий ${num(s.counts.events_24h)}`}</span></div>
      </div>
      <div className="split even">
        <div className="card flush">
          <div className="card-head"><h2>Компоненты</h2></div>
          <ul className="rows pad-x">{s.components.map((c) => (
            <li key={c.key}><span className={`dot ${c.ok ? "ok" : c.ok === null ? "warn" : "bad"}`} aria-hidden /><div className="r-main"><b>{c.title}</b><span className="r-sub">{c.detail}</span></div>
              {c.key === "updater" && !c.ok && <button className="btn mini" onClick={() => onOpen("updates")}>Как запустить</button>}</li>))}</ul>
        </div>
        <div className="card flush">
          <div className="card-head"><h2>Диски и данные</h2>{st.host_checked_at && <span className="muted small">сведения с сервера {fmtTs(st.host_checked_at)}</span>}</div>
          <dl className="kv compact pad-x">
            <div><dt>Диск данных</dt><dd><Usage used={r.disk_data?.used} total={r.disk_data?.total} label="Диск данных" /></dd></div>
            <div><dt>Внутренняя база</dt><dd>{bytes(st.database)}{s.checks.postgres?.version && <span className="muted small"> · PostgreSQL {s.checks.postgres.version}</span>}</dd></div>
            <div><dt>Отчёты</dt><dd>{bytes(st.reports)} <span className="muted small">· отчётов {num(s.counts.reports)}</span></dd></div>
            <div><dt>Резервные копии</dt><dd>{st.backups == null ? <span className="muted">нет сведений (нужен помощник обновлений)</span> : bytes(st.backups)}</dd></div>
            <div><dt>Образы Docker</dt><dd>{st.images == null ? <span className="muted">нет сведений</span> : <>{bytes(st.images)} <span className="muted small">· {st.images_list.length} образ(ов) проекта; свободно на диске Docker {bytes(st.docker_free)}</span></>}</dd></div>
          </dl>
        </div>
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Источники KSC</h2><span className="muted small">Проверка доступности (SELECT 1) — по кнопке, без нагрузки на SQL Server</span></div>
        {!s.sources.length ? <Empty icon="database" title="Источники не добавлены" action={<button className="btn primary" onClick={() => onOpen("sources")}><Icon name="plus" />Добавить источник</button>} /> : (
          <div className="table-scroll flat"><table className="table">
            <thead><tr><th>Источник</th><th>Последняя диагностика</th><th>Версия KSC</th><th>Каталог программ</th><th>Доступность сейчас</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{s.sources.map((x) => { const p = pings[x.id]; const [cl, cc] = CATALOG[x.catalog_status] ?? [x.catalog_status, ""]; return (
              <tr key={x.id}><td><b>{x.name}</b>{!x.is_active && <span className="badge warn ml">выключен</span>}</td>
                <td>{x.last_check_ok == null ? <span className="muted">не проверялся</span> : x.last_check_ok ? <span className="badge ok">успешно, {fmt(x.last_check_at)}</span> : <span className="badge err">ошибка, {fmt(x.last_check_at)}</span>}</td>
                <td className="mono">{x.ksc_version ?? "—"}</td><td><span className={`badge ${cc}`}>{cl}</span>{x.catalog_built_at && <span className="sub">{fmt(x.catalog_built_at)}</span>}</td>
                <td>{p === "run" ? <span className="spin" aria-label="Проверка" /> : p ? (p.ok ? <span className="ok-text">отвечает за {p.ms} мс</span> : <span className="bad-text">{p.error}</span>) : <span className="muted">—</span>}</td>
                <td className="actions"><button className="btn mini" onClick={() => void ping(x.id)} aria-busy={p === "run"}><Icon name="plug" size={15} /><span>Проверить</span></button></td></tr>); })}</tbody>
          </table></div>)}
      </div>
      <div className="card flush">
        <div className="card-head"><h2>Фоновые расчёты</h2><span className="muted small">Что считает worker, что ждёт исполнителя и чем закончилось; BI и отчёты — в своих очередях и не ждут тяжёлые расчёты</span></div>
        <dl className="kv compact pad-x">
          <div><dt>Память worker</dt><dd>{s.jobs.worker.rss_mb != null ? <>{num(s.jobs.worker.rss_mb)} МБ <span className="muted small">· пик {num(s.jobs.worker.peak_mb ?? 0)} МБ, мягкий предел {num(s.jobs.worker.soft_mb ?? 0)}, жёсткий {num(s.jobs.worker.hard_mb ?? 0)} МБ{s.jobs.worker.deferred ? ` · отложено задач: ${s.jobs.worker.deferred}` : ""}</span></> : <span className="muted">нет сигнала</span>}</dd></div>
          <div><dt>Сейчас выполняется</dt><dd>{s.jobs.leases.length ? s.jobs.leases.map((l) => <span key={`${l.kind}:${l.scope}`} className="block">{KIND_RU[l.kind] ?? l.kind}{l.scope ? ` · ${l.scope}` : ""}: {l.stage || "…"}{l.progress ? <span className="muted small"> — {l.progress}</span> : null} <span className={`muted small ${l.alive ? "" : "bad-text"}`}>(сигнал {l.heartbeat_age_s} с назад{l.alive ? "" : ", исполнитель не отвечает — задание будет перезапущено"})</span></span>) : <span className="muted">ничего</span>}</dd></div>
          <div><dt>Ожидает исполнителя</dt><dd>{s.jobs.worker.waiting?.length ? s.jobs.worker.waiting.map((w, i) => <span key={i} className="block">{w.task} <span className="muted small">· {LANE_RU[w.lane] ?? w.lane}, ждёт {Math.round(w.wait_s / 60)} мин</span></span>)
            : <span className="muted">очереди нет</span>}{s.jobs.worker.slots != null && <span className="sub">мест для тяжёлых расчётов: {s.jobs.worker.slots}{s.jobs.worker.slots_requested && s.jobs.worker.slots_requested > s.jobs.worker.slots ? ` (задано ${s.jobs.worker.slots_requested}, ограничено процессорами и памятью контейнера: CPU ${s.jobs.worker.cpus})` : ""}; импорт BI и отчёты — отдельные очереди</span>}</dd></div>
          <div><dt>Прервано за сутки</dt><dd>{s.jobs.interrupted_24h ? <span className="warn-text">{s.jobs.interrupted_24h} — перезапуск или сбой; задания возобновляются автоматически</span> : <span className="ok-text">нет</span>}</dd></div>
          <div><dt>Отчёты</dt><dd>{s.jobs.reports.median_s != null ? <>типичная длительность {s.jobs.reports.median_s} с, самый долгий из последних {s.jobs.reports.done_sample} — {s.jobs.reports.max_s} с</> : <span className="muted">готовых отчётов ещё нет</span>}{s.jobs.reports.failed_24h > 0 && <span className="bad-text"> · неудачных за сутки: {s.jobs.reports.failed_24h}</span>}</dd></div>
          {s.jobs.postgres && <div><dt>Долгие транзакции PostgreSQL</dt><dd>{s.jobs.postgres.long_transactions.length ? s.jobs.postgres.long_transactions.map((t) => `${t.state}: ${t.count}, самая давняя ${t.oldest_s} с`).join("; ") : <span className="ok-text">нет (дольше минуты)</span>}</dd></div>}
        </dl>
        <div className="table-scroll flat"><table className="table compact">
          <thead><tr><th>Источник</th><th>EOL</th><th>Данные зон</th><th>Пользователи устройств</th><th>Каталог программ</th></tr></thead>
          <tbody>{s.jobs.sources.map((x) => <tr key={x.source}><td><b>{x.source}</b></td>
            <td>{!x.eol ? <span className="muted">не рассчитывался</span> : x.eol.running ? <span className="badge accent">выполняется{x.eol.progress ? `: ${x.eol.progress}` : ""}</span> : x.eol.error ? <span className="badge err" title={x.eol.error}>ошибка{x.eol.computed_at ? `, прежний результат от ${fmt(x.eol.computed_at)}` : ""}</span> : <>{fmt(x.eol.computed_at)}<span className="sub small">{num(x.eol.items)} находок, {x.eol.duration_ms != null ? `${Math.round(x.eol.duration_ms / 1000)} с` : ""}</span></>}</td>
            <td>{!x.zones ? <span className="muted">—</span> : x.zones.status === "building" ? <span className="badge accent">строится{x.zones.progress ? `: ${x.zones.progress}` : ""}</span> : x.zones.status === "failed" ? <span className="badge err" title={x.zones.error ?? ""}>ошибка</span> : x.zones.built_at ? <>{fmt(x.zones.built_at)}<span className="sub small">{num(x.zones.hosts)} устройств{x.zones.duration_ms != null ? `, ${Math.round(x.zones.duration_ms / 1000)} с` : ""}</span></> : <span className="muted">нет данных</span>}</td>
            <td>{!x.devices?.polled_at ? <span className="muted">опроса не было</span> : <>{fmt(x.devices.polled_at)}{x.devices.error && <span className="sub small bad-text">{x.devices.error}</span>}</>}</td>
            <td>{x.catalog ? <>{fmt(x.catalog.built_at)}<span className="sub small">{x.catalog.status}</span></> : <span className="muted">—</span>}</td></tr>)}</tbody>
        </table></div>
      </div>
      <div className="split even">
        <div className="card flush">
          <div className="card-head"><h2>Ошибки фоновых задач и приложения</h2><div className="spacer" /><button className="btn mini ghost" onClick={() => onOpen("journal")}>Журнал событий</button></div>
          {!s.recent_errors.length ? <p className="muted small pad">Ошибок нет.</p> : (
            <ul className="rows pad-x">{s.recent_errors.map((e, i) => <li key={i}><span className="dot bad" aria-hidden /><div className="r-main"><b>{e.message ?? e.event}</b><span className="r-sub">{fmt(e.at)} · {e.category}{e.source ? ` · ${e.source}` : ""}</span></div></li>)}</ul>)}
        </div>
        <div className="card flush">
          <div className="card-head"><h2>Проверки источников и каталога</h2></div>
          {!s.recent_checks.length ? <p className="muted small pad">Проверок ещё не было.</p> : (
            <ul className="rows pad-x">{s.recent_checks.slice(0, 6).map((e, i) => <li key={i}><span className={`dot ${e.level === "error" ? "bad" : e.level === "warn" ? "warn" : "ok"}`} aria-hidden /><div className="r-main"><b>{e.source ?? "—"}</b><span className="r-sub clamp2" title={e.message ?? ""}>{fmt(e.at)} · {e.message}</span></div></li>)}</ul>)}
        </div>
      </div>
      <div className="split even">
        <div className="card flush">
          <div className="card-head"><h2>История обновлений</h2><div className="spacer" /><button className="btn mini ghost" onClick={() => onOpen("updates")}>Обновления</button></div>
          {!s.update_history.length ? <p className="muted small pad">Обновлений через помощника ещё не было.</p> : (
            <ul className="rows pad-x">{s.update_history.map((h, i) => <li key={i}><span className={`dot ${h.result === "ok" ? "ok" : "bad"}`} aria-hidden /><div className="r-main"><b>{ACTION[h.action] ?? h.action}: {h.from_version} → {h.to_version}</b>
              <span className="r-sub">{fmtTs(h.at)} · {h.by}{h.result !== "ok" ? ` · ошибка на этапе ${h.stage ?? "?"}` : ""}</span></div></li>)}</ul>)}
        </div>
        <div className="card">
          <h2>Безопасность</h2>
          <dl className="kv compact">
            <div><dt>Публичный адрес</dt><dd className="mono small">{s.public_url}</dd></div>
            <div><dt>HTTPS</dt><dd>{s.security.https ? <span className="ok-text">да</span> : <span className="warn-text">нет</span>}</dd></div>
            <div><dt>Cookie сессии</dt><dd>{s.security.secure_cookie ? "с флагом Secure" : "без флага Secure"} <span className="muted small">(режим {s.security.cookie_mode})</span></dd></div>
            <div><dt>Ключ шифрования</dt><dd>{s.master_key_ok ? <span className="ok-text">задан</span> : <span className="bad-text">не задан</span>}</dd></div>
            <div><dt>Второй фактор</dt><dd>{({ off: "отключён", optional: "по желанию", admins: "обязателен администраторам", all: "обязателен всем", groups: "обязателен группам" } as Record<string, string>)[s.security.totp_policy] ?? s.security.totp_policy}
              <button className="link-btn small-gap" onClick={() => onOpen("users")}>изменить</button></dd></div>
          </dl>
        </div>
      </div>
    </div>
  );
}
