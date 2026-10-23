import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiError, type UpdatesOverview } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { ago, bytes, fmtTs, versionLabel } from "../../util";

const MAX_LOG = 400_000;
const ACTION: Record<string, string> = { update: "обновление", rollback: "откат", backup: "резервная копия", check: "проверка" };

/** Обновления через GitHub: установленная версия, доступный релиз и список изменений, обновление, откат, резервная копия.
 *  Backend ничего не обновляет сам — запрос передаётся помощнику на сервере (scripts/updater.sh), который выполняет scripts/update.sh. */
export default function UpdatesAdmin() {
  const [ov, setOv] = useState<UpdatesOverview | null>(null);
  const [err, setErr] = useState(""); const [log, setLog] = useState(""); const [lost, setLost] = useState(false);
  const [confirm, setConfirm] = useState<"update" | "rollback" | null>(null);
  const [busy, setBusy] = useState(""); const [ranHere, setRanHere] = useState(false); const [follow, setFollow] = useState(true);
  const offset = useRef(0); const term = useRef<HTMLPreElement>(null); const watchUntil = useRef(0);
  const loadOverview = useCallback(async () => { try { setOv(await api.admin.updates()); setErr(""); setLost(false); } catch (e) { const ae = e as ApiError; if (ae.status === 0 || ae.status >= 500) setLost(true); else setErr(ae.message); } }, []);
  const pollLog = useCallback(async () => { try { const r = await api.admin.updatesLog(offset.current); setLost(false); if (r.reset) setLog(""); offset.current = r.offset; if (r.text) setLog((l) => (l + r.text).slice(-MAX_LOG)); } catch (e) { const ae = e as ApiError; if (ae.status === 0 || ae.status >= 500) setLost(true); } }, []);
  useEffect(() => { void loadOverview(); void pollLog(); }, [loadOverview, pollLog]);
  const u = ov?.updater;
  const running = !!u && (["updating", "rolling_back", "backing_up", "checking"].includes(u.state) || u.request_pending || Date.now() < watchUntil.current);
  useEffect(() => { const t = window.setInterval(() => { void pollLog(); void loadOverview(); }, running ? 1500 : 8000); return () => window.clearInterval(t); }, [running, pollLog, loadOverview]);
  useEffect(() => { if (follow && term.current) term.current.scrollTop = term.current.scrollHeight; }, [log, follow]);
  const act = async (what: string, fn: () => Promise<unknown>) => { setBusy(what); setErr(""); try { await fn(); watchUntil.current = Date.now() + 20000; setRanHere(true); offset.current = 0; setLog(""); await loadOverview(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(""); } };
  const rem = ov?.remote;
  const pct = u?.step_total ? Math.min(100, Math.round(((u.step_no ?? 0) / u.step_total) * 100)) : 0;
  const finished = u?.state === "idle" && !!u.finished_at;
  return (
    <section>
      <div className="row"><h2>Обновления</h2><div className="spacer" /><button className="btn" onClick={() => act("check", api.admin.updatesCheck)} disabled={!!busy || !ov?.can_act}>{busy === "check" ? "Проверка…" : "Проверить релизы"}</button></div>
      <p className="muted">Установленная версия, доступный релиз в GitHub и список изменений. Обновление выполняет штатный <code>scripts/update.sh</code> на сервере: резервная копия внутренней базы и настроек → новые образы → миграции → перезапуск → проверка состояния; при ошибке — откат. Отчёты, настройки и подключения сохраняются.</p>
      {err && <div className="alert error" role="alert">{err}</div>}
      {lost && <div className="alert info">Связь с сервером прервана — вероятно, он перезапускается при обновлении. Окно переподключится само.</div>}
      <div className="card">
        <div className="upd-versions">
          <div><div className="l">Установлено</div><div className="v">{ov ? versionLabel(ov.installed.version, ov.installed.commit) : "—"}</div><div className="l">сборка {ov?.installed.built_at ?? "—"}</div></div>
          <div><div className="l">Доступный релиз (GitHub)</div><div className="v">{rem?.ok ? rem.latest_version || "—" : "—"}</div><div className="l">{rem ? `проверено ${ago(rem.age_s)}` : "проверка ещё не выполнялась"}{rem?.published_at ? ` · выпущен ${rem.published_at.slice(0, 10)}` : ""}</div></div>
          <div><div className="l">Помощник обновлений</div><div className="v">{u?.available ? <span className="ok-text">работает</span> : <span className="bad-text">не запущен</span>}</div><div className="l">{u?.heartbeat_age_s != null ? `пульс ${ago(u.heartbeat_age_s)}` : "нет данных"}</div></div>
        </div>
        {!u?.available && ov && (
          <div className="alert warn"><b>Помощник обновлений не запущен.</b> Он нужен, чтобы обновлять, откатывать и делать резервные копии из браузера. Установите его один раз на сервере (служба systemd от root, выполняет только фиксированный набор действий):
            <pre className="cmd">{ov.commands.install}</pre>Без помощника обновление выполняется на сервере командой <code>{ov.commands.manual}</code>.</div>
        )}
        {rem && !rem.ok && <div className="alert error">Не удалось проверить GitHub: {rem.error || "нет данных"}. Если у сервера нет доступа в интернет, обновляйте на сервере из заранее скопированного репозитория.</div>}
        {rem?.ok && !rem.behind && <div className="alert ok">Установлена актуальная версия.</div>}
        {rem?.ok && rem.behind && (
          <div className="alert info"><b>Доступно обновление: {rem.current_version} → {rem.latest_version}</b>
            {rem.notes && <details open><summary>Что нового</summary><pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit", margin: "6px 0 0" }}>{rem.notes}</pre></details>}
          </div>
        )}
        <div className="alert"><b>Что произойдёт.</b> Сервис перезапустится на 1–3 минуты. Перед обновлением создаётся резервная копия внутренней базы и .env; сохраняются текущая и предыдущая версии образов — откат делается без пересборки.</div>
        <div className="row">
          <button className="btn primary" disabled={!ov?.can_act || !!busy} onClick={() => setConfirm("update")} title={ov?.can_act ? "" : ov?.reasons.join(" ")}>⬆ Обновить{rem?.ok && rem.behind ? ` до ${rem.latest_version}` : ""}</button>
          <button className="btn" disabled={!ov?.can_act || !!busy} onClick={() => setConfirm("rollback")}>Откатить на предыдущую версию</button>
          <button className="btn" disabled={!ov?.can_act || !!busy} onClick={() => act("backup", api.admin.updatesBackup)}>Создать резервную копию</button>
          {ov && !ov.can_act && <span className="muted small">{ov.reasons.join(" ")}</span>}
        </div>
      </div>
      {(running || ranHere) && (
        <div className="card">
          <div className="row"><h3 style={{ margin: 0 }}>Ход выполнения{u?.action ? `: ${ACTION[u.action] ?? u.action}` : ""}</h3>
            {running && <span className="badge accent">выполняется</span>}{finished && u?.result === "ok" && <span className="badge ok">завершено успешно</span>}{finished && u?.result === "failed" && <span className="badge err">остановлено (код {u.exit_code})</span>}
            {u?.by && <span className="muted small">запустил: {u.by}</span>}<div className="spacer" />
            <label className="check small" style={{ margin: 0 }}><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> следить за концом</label></div>
          {u && (running || (u.step_no ?? 0) > 0) && <div><div className="bar"><i style={{ width: `${running ? Math.max(pct, 3) : finished && u.result === "ok" ? 100 : pct}%` }} /></div><div className="small">{u.step_no ? `Этап ${u.step_no} из ${u.step_total}: ${u.step_name}` : "Запуск…"}</div></div>}
          <pre className="term" ref={term} tabIndex={0} onScroll={(e) => { const t = e.currentTarget; setFollow(t.scrollHeight - t.scrollTop - t.clientHeight < 40); }}>{log || "Ожидание вывода…"}</pre>
          {finished && u?.result === "ok" && u.action === "update" && <div className="alert ok">Обновление выполнено. <button className="btn mini primary" onClick={() => window.location.reload()}>Обновить страницу</button></div>}
          {finished && u?.result === "failed" && <div className="alert error">Действие остановилось. Данные и настройки не затронуты; причина — в последних строках журнала. Повтор безопасен.</div>}
        </div>
      )}
      <div className="grid">
        <div className="card"><h3>История</h3>
          {!ov?.history.length ? <p className="muted small">Попыток пока не было.</p> : (
            <table className="table compact" style={{ boxShadow: "none" }}><thead><tr><th>Когда</th><th>Действие</th><th>Версии</th><th>Кто</th><th>Результат</th></tr></thead>
              <tbody>{ov.history.map((h, i) => <tr key={i}><td className="nowrap">{fmtTs(h.at)}</td><td>{ACTION[h.action] ?? h.action}</td><td>{[h.from_version, h.to_version].filter(Boolean).join(" → ")}</td><td>{h.by}</td><td>{h.result === "ok" ? <span className="badge ok">успешно</span> : <span className="badge warn">ошибка{h.stage ? ` · ${h.stage}` : ""}</span>}</td></tr>)}</tbody></table>)}
        </div>
        <div className="card"><h3>Резервные копии</h3>
          <p className="muted small">Копии внутренней базы (pg_dump) и .env в каталоге данных; хранятся последние 14. Восстановление: <code>./scripts/restore.sh &lt;файл&gt;</code> на сервере.</p>
          {!ov?.backups.length ? <p className="muted small">Копий пока нет.</p> : <ul className="plain">{ov.backups.slice(0, 10).map((b) => <li key={b.name} className="small"><code>{b.name}</code> · {bytes(b.size)} · {fmtTs(b.at)}</li>)}</ul>}
        </div>
      </div>
      {confirm && <ConfirmDialog title={confirm === "update" ? "Обновить KAV Checker?" : "Откатить на предыдущую версию?"} confirmLabel={confirm === "update" ? "Обновить" : "Откатить"} danger={confirm === "rollback"} onClose={() => setConfirm(null)}
        body={confirm === "update" ? <p>Будет выполнен <code>scripts/update.sh</code>: резервная копия, новые образы, миграции, перезапуск и проверка. Сервис недоступен 1–3 минуты.</p> : <p>Код и образы вернутся к предыдущей рабочей версии. Если схема базы изменилась, откат остановится с подсказкой восстановить резервную копию.</p>}
        onConfirm={() => act(confirm, confirm === "update" ? () => api.admin.updatesRun(rem?.ok && rem.behind ? rem.latest_tag : "") : api.admin.updatesRollback)} />}
    </section>
  );
}
