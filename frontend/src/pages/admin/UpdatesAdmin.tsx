import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiError, type UpdatesOverview } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { ago, bytes, fmtTs, versionLabel } from "../../util";

const MAX_LOG = 400_000;
const ACTION: Record<string, string> = { update: "Обновление", rollback: "Откат", backup: "Резервная копия", check: "Проверка релизов", restore: "Восстановление из копии", preflight: "Проверки перед обновлением" };
const PF: Record<string, [string, string]> = { ok: ["check", "ok-text"], warn: ["alert", "warn-text"], fail: ["xCircle", "bad-text"] };

/** Обновления через GitHub: установленная версия, доступный релиз и изменения, обновление, откат, резервная копия.
 *  Backend сам ничего не обновляет — запрос передаётся помощнику на сервере (scripts/updater.sh). */
export default function UpdatesAdmin() {
  const [ov, setOv] = useState<UpdatesOverview | null>(null);
  const [err, setErr] = useState(""); const [log, setLog] = useState(""); const [lost, setLost] = useState(false);
  const [confirm, setConfirm] = useState<"update" | "rollback" | null>(null);
  const [restore, setRestore] = useState<string | null>(null);
  const [busy, setBusy] = useState(""); const [ranHere, setRanHere] = useState(false); const [follow, setFollow] = useState(true);
  const [toast, show] = useToast();
  const offset = useRef(0); const term = useRef<HTMLPreElement>(null); const watchUntil = useRef(0);
  const loadOverview = useCallback(async () => { try { setOv(await api.admin.updates()); setErr(""); setLost(false); } catch (e) { const ae = e as ApiError; if (ae.status === 0 || ae.status >= 500) setLost(true); else setErr(ae.message); } }, []);
  const pollLog = useCallback(async () => { try { const r = await api.admin.updatesLog(offset.current); setLost(false); if (r.reset) setLog(""); offset.current = r.offset; if (r.text) setLog((l) => (l + r.text).slice(-MAX_LOG)); } catch (e) { const ae = e as ApiError; if (ae.status === 0 || ae.status >= 500) setLost(true); } }, []);
  useEffect(() => { void loadOverview(); void pollLog(); }, [loadOverview, pollLog]);
  const u = ov?.updater;
  const running = !!u && (["updating", "rolling_back", "backing_up", "checking", "restoring"].includes(u.state) || u.request_pending || Date.now() < watchUntil.current);
  useEffect(() => { const t = window.setInterval(() => { void pollLog(); void loadOverview(); }, running ? 1500 : 8000); return () => window.clearInterval(t); }, [running, pollLog, loadOverview]);
  useEffect(() => { if (follow && term.current) term.current.scrollTop = term.current.scrollHeight; }, [log, follow]);
  const act = async (what: string, fn: () => Promise<unknown>, note: string) => { setBusy(what); setErr(""); try { await fn(); watchUntil.current = Date.now() + 20000; if (what !== "check") { setRanHere(true); offset.current = 0; setLog(""); } show(note); await loadOverview(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(""); } };
  if (!ov) return err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <div className="card"><SkelRows rows={3} cols={3} /></div>;
  const rem = ov.remote;
  const pct = u?.step_total ? Math.min(100, Math.round(((u.step_no ?? 0) / u.step_total) * 100)) : 0;
  const finished = u?.state === "idle" && !!u.finished_at;
  return (
    <div className="stack">
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {lost && <div className="alert info"><Icon name="info" /><div className="alert-body">Связь с сервером прервана — вероятно, он перезапускается при обновлении. Страница переподключится сама.</div></div>}
      <div className="card">
        <div className="upd-versions">
          <div><div className="l">Установлено</div><div className="v">{versionLabel(ov.installed.version, ov.installed.commit)}</div><div className="l">сборка {ov.installed.built_at}</div></div>
          <div><div className="l">Последний релиз в GitHub</div><div className="v">{rem?.ok && rem.latest_version ? rem.latest_version : "—"}</div><div className="l">{rem ? `проверено ${ago(rem.age_s)}` : "проверка ещё не выполнялась"}{rem?.published_at ? `, выпущен ${rem.published_at.slice(0, 10)}` : ""}</div></div>
          <div><div className="l">Помощник обновлений</div><div className="v"><span className="row tight"><span className={`dot ${u?.available ? "ok" : "warn"}`} />{u?.available ? "работает" : "не запущен"}</span></div><div className="l">{u?.heartbeat_age_s != null ? `пульс ${ago(u.heartbeat_age_s)}` : "нет сведений"}</div></div>
        </div>
        {!u?.available && (
          <div className="alert warn mt"><Icon name="alert" /><div className="alert-body"><b>Помощник обновлений не запущен.</b> Он нужен для обновления, отката и резервных копий из браузера. Установите его один раз на сервере — служба выполняет только эти действия:
            <pre className="cmd">{ov.commands.install}</pre>Без помощника обновляйте на сервере командой <code>{ov.commands.manual}</code>.</div></div>
        )}
        {rem && !rem.ok && <div className="alert error mt"><Icon name="alert" /><div className="alert-body"><b>Не удалось проверить наличие новых версий.</b> Если у сервера нет доступа к GitHub, обновляйте его из заранее скопированного репозитория.{rem.error && <details className="disclosure"><summary>Техническая причина</summary><span className="mono small">{rem.error}</span></details>}</div></div>}
        {rem?.ok && !rem.behind && <div className="alert ok mt"><Icon name="checkCircle" /><div className="alert-body">Установлена последняя версия.</div></div>}
        {rem?.ok && rem.behind && (
          <div className="alert info mt"><Icon name="upload" /><div className="alert-body"><b>Доступна версия {rem.latest_version}</b> (установлена {rem.current_version}).
            {rem.notes && <details className="disclosure"><summary>Что изменилось</summary><pre className="notes-pre">{rem.notes}</pre></details>}</div></div>
        )}
        <p className="muted small prose-note">Обновление выполняет <code>scripts/update.sh</code>: резервная копия внутренней базы и .env, новые образы, миграции, перезапуск и проверка; при ошибке — откат. Сервис недоступен 1–3 минуты. Отчёты, настройки и подключения сохраняются.</p>
        <div className="preflight">
          <div className="row"><h3>Проверки перед обновлением</h3>{ov.preflight && <span className={`badge ${ov.preflight.ok ? "ok" : "err"}`}>{ov.preflight.ok ? "пройдены" : "есть препятствия"}</span>}
            {ov.preflight && <span className="muted small">{ago(ov.preflight.age_s)}</span>}<div className="spacer" />
            <button className="btn mini" disabled={!ov.can_act || !!busy} aria-busy={busy === "preflight"} onClick={() => act("preflight", api.admin.updatesPreflight, "Проверки запущены")}><Icon name="refresh" size={15} /><span>Проверить</span></button></div>
          {ov.preflight ? <ul className="pf-list">{ov.preflight.items.map((i) => { const [ic, cl] = PF[i.status] ?? ["info", ""]; return <li key={i.key} className={cl}><Icon name={ic as never} size={15} /><span>{i.message}</span></li>; })}</ul>
            : <p className="muted small">Свободное место, доступность GitHub и реестра образов (или npm и pip при локальной сборке), состояние базы, возможность отката. Те же проверки выполняются в начале обновления; при препятствиях обновление не начнётся.</p>}
        </div>
        <div className="row">
          <button className="btn primary" disabled={!ov.can_act || !!busy} onClick={() => setConfirm("update")} title={ov.can_act ? undefined : ov.reasons.join(" ")}><Icon name="upload" />{rem?.ok && rem.behind ? `Обновить до ${rem.latest_version}` : "Обновить"}</button>
          <button className="btn" disabled={!ov.can_act || !!busy} aria-busy={busy === "check"} onClick={() => act("check", api.admin.updatesCheck, "Проверка релизов запущена")}><Icon name="refresh" /><span>Проверить релизы</span></button>
          <button className="btn" disabled={!ov.can_act || !!busy} aria-busy={busy === "backup"} onClick={() => act("backup", api.admin.updatesBackup, "Резервная копия создаётся")}><Icon name="save" /><span>Создать резервную копию</span></button>
          <div className="spacer" />
          <button className="btn ghost danger" disabled={!ov.can_act || !!busy} onClick={() => setConfirm("rollback")}><Icon name="history" />Откатить версию</button>
        </div>
        {!ov.can_act && ov.reasons.length > 0 && <p className="help mt-sm">{ov.reasons.join(" ")}</p>}
      </div>
      {(running || ranHere) && (
        <div className="card">
          <div className="card-head"><h2>{ACTION[u?.action ?? ""] ?? "Выполнение"}</h2>
            {running && <span className="badge accent"><span className="spin sm" />выполняется</span>}
            {finished && u?.result === "ok" && <span className="badge ok">завершено</span>}{finished && u?.result === "failed" && <span className="badge err">остановлено, код {u.exit_code}</span>}
            {u?.by && <span className="muted small">запустил {u.by}</span>}<div className="spacer" />
            <label className="check inline-check"><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />Следить за концом</label></div>
          {u && (running || (u.step_no ?? 0) > 0) && <div className="mb"><div className="bar"><i style={{ width: `${running ? Math.max(pct, 3) : finished && u.result === "ok" ? 100 : pct}%` }} /></div><div className="small muted" style={{ marginTop: 6 }}>{u.step_no ? `Этап ${u.step_no} из ${u.step_total}: ${u.step_name}` : "Запуск…"}</div></div>}
          <pre className="term" ref={term} tabIndex={0} aria-label="Журнал выполнения" onScroll={(e) => { const t = e.currentTarget; setFollow(t.scrollHeight - t.scrollTop - t.clientHeight < 40); }}>{log || "Ожидание вывода…"}</pre>
          {finished && u?.result === "ok" && u.action === "update" && <div className="alert ok mt-sm"><Icon name="checkCircle" /><div className="alert-body">Обновление выполнено. Обновите страницу, чтобы загрузить новую версию интерфейса.</div><button className="btn mini primary" onClick={() => window.location.reload()}>Обновить страницу</button></div>}
          {finished && u?.result === "failed" && <div className="alert error mt-sm"><Icon name="alert" /><div className="alert-body">Действие остановилось. Данные и настройки не затронуты; причина — в последних строках журнала. Повтор безопасен.</div></div>}
        </div>
      )}
      {ov.report && (
        <div className={`card report-card ${ov.report.result}`}>
          <div className="card-head"><h2>Последнее обновление</h2><span className={`badge ${ov.report.result === "ok" ? "ok" : "err"}`}>{ov.report.result === "ok" ? "успешно" : `остановлено: ${ov.report.stage}`}</span>
            <span className="muted small">{ov.report.from_version} → {ov.report.to_version} · {fmtTs(ov.report.finished_at)}</span></div>
          {ov.report.advice && <p className="small">{ov.report.advice}</p>}
          {ov.report.actions.length > 0 && <details className="disclosure"><summary>Автоматические действия ({ov.report.actions.length})</summary><ul className="small mono-list">{ov.report.actions.map((a, i) => <li key={i}>{a}</li>)}</ul></details>}
        </div>)}
      <div className="split even">
        <div className="card flush"><div className="card-head"><h2>История</h2></div>
          {!ov.history.length ? <Empty icon="history" title="Действий ещё не было">Здесь появятся обновления, откаты и резервные копии.</Empty> : (
            <div className="table-scroll"><table className="table compact"><thead><tr><th>Когда</th><th>Действие</th><th>Версии</th><th>Кто</th><th>Итог</th></tr></thead>
              <tbody>{ov.history.map((h, i) => <tr key={i}><td className="nowrap">{fmtTs(h.at)}</td><td>{ACTION[h.action] ?? h.action}</td><td className="mono">{[h.from_version, h.to_version].filter(Boolean).join(" → ")}</td><td>{h.by}</td><td>{h.result === "ok" ? <span className="badge ok">успешно</span> : <span className="badge warn">ошибка{h.stage ? `: ${h.stage}` : ""}</span>}</td></tr>)}</tbody></table></div>)}
        </div>
        <div className="card flush"><div className="card-head"><h2>Резервные копии</h2><span className="muted small">последние 14</span></div>
          {!ov.backups.length ? <Empty icon="save" title="Копий пока нет">Копия создаётся перед каждым обновлением и по кнопке выше.</Empty> : (
            <ul className="rows pad-x">{ov.backups.slice(0, 8).map((b) => <li key={b.name}><Icon name="database" className="muted" /><div className="r-main"><span className="mono small">{b.name}</span><span className="r-sub">{fmtTs(b.at)}, {bytes(b.size)}</span></div>
              <button className="btn mini ghost" disabled={!ov.can_act || !!busy} onClick={() => setRestore(b.name)}>Восстановить</button></li>)}</ul>)}
          <p className="help pad-help">Восстановление заменяет текущие данные внутренней базы (пользователи, настройки, отчёты); перед ним помощник снимает копию текущей базы. На сервере: <code>./scripts/restore.sh &lt;файл&gt;</code></p>
        </div>
      </div>
      {confirm && <ConfirmDialog title={confirm === "update" ? "Обновить KAV Checker?" : "Откатить на предыдущую версию?"} confirmLabel={confirm === "update" ? "Обновить" : "Откатить"} danger={confirm === "rollback"} onClose={() => setConfirm(null)}
        body={confirm === "update" ? <p>Будет создана резервная копия, загружены новые образы, применены миграции и выполнен перезапуск. Сервис недоступен 1–3 минуты.</p> : <p>Код и образы вернутся к предыдущей рабочей версии без пересборки. Если новая версия изменила схему базы, откат остановится и предложит сначала восстановить резервную копию.</p>}
        onConfirm={() => act(confirm, confirm === "update" ? () => api.admin.updatesRun(rem?.ok && rem.behind ? rem.latest_tag : "") : api.admin.updatesRollback, confirm === "update" ? "Обновление запущено" : "Откат запущен")} />}
      {restore && <ConfirmDialog title="Восстановить базу из копии?" confirmLabel="Восстановить" typed="ВОССТАНОВИТЬ"
        body={<p>Внутренняя база KAV Checker будет заменена копией <b>{restore}</b>: пользователи, настройки, источники, проверки и сведения об отчётах вернутся к состоянию на момент копии. Перед восстановлением снимается копия текущей базы. Сервис будет недоступен около минуты.</p>}
        onClose={() => setRestore(null)} onConfirm={() => act("restore", () => api.admin.updatesRestore(restore, "ВОССТАНОВИТЬ"), "Восстановление запущено")} />}
      {toast}
    </div>
  );
}
