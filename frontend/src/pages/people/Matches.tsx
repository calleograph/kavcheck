import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type BiBulkOp, type BiBulkPlan, type BiMatchItem } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, VirtualRows, keep, useInfinite, useKept } from "../../components/Infinite";
import { biDeviceLink } from "../../components/OwnerBlock";
import { CheckAll, QuickReportPanel, useRowSel } from "../../components/QuickReport";
import { useToast } from "../../components/Toast";
import { Dock, Empty, Segmented, SkelRows } from "../../components/ui";
import { fmt, fmtDate, num, plural } from "../../util";

// «Требуют решения» (ключ "") = «Ручное решение» + «Точные»: в панели не повторяется, ключ остаётся у API для отчётов и ссылок
const FILTERS: [string, string][] = [["needs_manual", "Ручное решение"], ["exact", "Точные"], ["auto", "Предполагаемые"], ["ambiguous", "Неоднозначные"],
  ["unmatched", "Без пары в KSC"], ["stale", "Устаревшие записи"], ["confirmed", "Подтверждённые"], ["rejected", "Отклонённые"]];
const ACT_CLS: Record<string, string> = { active: "ok", stale: "", none: "warn", future: "err" };
const ACT_SHORT: Record<string, string> = { active: "активен", stale: "не активен", none: "нет данных о подключении", future: "дата недостоверна" };
const days = (iso: string | null) => (iso ? Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000)) : null);
const noun = (n: number) => plural(n, "день", "дня", "дней");

/** Последняя активность записи KSC: дата подключения Агента и состояние (активна / не активна / нет данных). */
function Activity({ at, act }: { at: string | null; act: string }) {
  const d = days(at);
  return <span className="sub small">{act && <span className={`badge ${ACT_CLS[act] ?? ""}`}>{ACT_SHORT[act] ?? act}</span>}{at ? <> подключение {fmtDate(at)}{d !== null && d > 0 ? ` (${d} ${noun(d)} назад)` : d === 0 ? " (сегодня)" : ""}</> : null}</span>;
}
const NAME_CLS: Record<string, string> = { exact: "ok", exact_dup: "warn", short: "" };
const NAME_SHORT: Record<string, string> = { exact: "точное имя", exact_dup: "точное имя, есть конкуренты", short: "короткое имя ↔ FQDN", moved: "переход между KSC" };
type Bulk = { action: "confirm" | "reject" | "reset"; scope: "exact" | "ids"; ids?: number[] };

/** «Сопоставление BI и KSC»: точные совпадения имён подтверждаются массово (предварительная сводка, выполнение на сервере), спорные — вручную; решения — в журнале действий. */
export default function Matches({ ctx }: { ctx: Ctx }) {
  const [q, setQ] = useKept("bm.q", ""); const [applied, setApplied] = useState(q); const [level, setLevel] = useKept("bm.level", "needs_manual");
  const [tick, setTick] = useState(0); const [busy, setBusy] = useState<number | null>(null); const [toast, show] = useToast(); const [report, setReport] = useState(false);
  const [bulk, setBulk] = useState<Bulk | null>(null);
  const sel = useRowSel<number>();
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  useEffect(() => { sel.clear(); }, [applied, level]); // eslint-disable-line react-hooks/exhaustive-deps
  const list = useInfinite<BiMatchItem>("bi:matches", [applied, level, tick], (offset, limit) => api.bi.matches({ q: applied, level, offset, limit }), 50);
  const counts = (list.extra as { counts?: Record<string, number> } | null)?.counts ?? {};
  const admin = ctx.me.user.is_admin;
  const act = async (m: BiMatchItem, decision: "confirm" | "reject" | "reset") => {
    setBusy(m.id);
    try { await api.bi.decide({ device_id: m.device_id, ksc_source_id: m.ksc_source_id, host_id: m.host_id, decision }); show(decision === "confirm" ? `Соответствие ${m.device} → ${m.host_name} подтверждено` : decision === "reject" ? "Соответствие отклонено и больше не предлагается" : "Решение отменено"); setTick((x) => x + 1); }
    catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(null); }
  };
  const ids = list.items.map((m) => m.id);
  return (<>
    <p className="muted small fbar-note">Записи с одним именем в разных источниках KSC не объединяются: актуальной считается запись, активная за период активности (по последнему подключению Агента); давно не подключавшиеся не мешают. «Точное совпадение» — полное имя совпадает (регистр и пробелы не учитываются), актуальная запись одна, признаки не противоречат: такие пары подтверждаются одним действием. Близкие даты подключения, даты в будущем и отсутствие сведений — ручное решение; прежние соответствия сохраняются, решения пишутся в журнал действий.</p>
    <FilterBar search={{ value: q, onChange: setQ, placeholder: "Имя устройства BI или компьютера KSC", label: "Поиск сопоставлений" }}
      primary={<Segmented label="Отбор" value={level} onChange={setLevel} options={FILTERS.map(([k, l]) => [k, `${l} ${num(counts[k] ?? 0)}`] as [string, string])} />}
      chips={q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []} onReset={() => { setQ(""); setLevel("needs_manual"); }}
      count={{ n: list.initial ? null : list.total, noun: ["сопоставление", "сопоставления", "сопоставлений"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
      report={{ onClick: () => setReport(true), title: "Отчёт «Расхождения BI и KSC»" }}
      extra={admin && (counts.exact ?? 0) > 0 ? <button type="button" className="btn mini primary" onClick={() => setBulk({ action: "confirm", scope: "exact" })}>
        <Icon name="checkCircle" size={15} />Подтвердить все актуальные точные совпадения · {num(counts.exact ?? 0)}</button> : undefined} />
    {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
    <div className="table-scroll">
      {list.initial ? <SkelRows cols={5} /> : level === "unmatched" ? (
        <Empty icon="monitor" title={`Устройств BI без пары в KSC: ${num(counts.unmatched ?? 0)}`}
          action={<Link className="btn mini" to="/devices?tab=bi" onClick={() => { keep("bi.view", "devices"); keep("bi.flt", "no_ksc"); }}>Открыть список устройств «Нет в KSC»</Link>}>
          Ни в одном подключённом источнике KSC нет компьютера с таким именем либо ни одна запись не подключалась за период активности — сопоставлять не с чем. Список и отчёт по ним — во вкладке «Пользователи BI», вид «Устройства»; записи без актуального компьютера — в отборе «Устаревшие записи».</Empty>
      ) : (
        <table className="table">
          <thead><tr>{admin && <CheckAll all={sel.allOf(ids)} some={sel.someOf(ids)} onToggle={() => sel.toggleMany(ids)} label="Отметить все загруженные" />}
            <th>Устройство BI</th><th>Компьютер KSC</th><th>Уровень и основание</th><th className="hide-md">Решение</th>{admin && <th />}</tr></thead>
          <tbody>
            <VirtualRows list={list} colSpan={admin ? 6 : 4} row={(m) => <tr key={m.id} className={`${sel.has(m.id) ? "sel" : ""}${["stale", "inactive", "history"].includes(m.level) ? " row-stale" : ""}`.trim() || undefined}>
              {admin && <td className="check"><input type="checkbox" checked={sel.has(m.id)} onChange={() => sel.toggle(m.id)} aria-label={`Отметить ${m.device} → ${m.host_name}`} /></td>}
              <td><Link to={biDeviceLink(m.device_id)} className="strong-link nowrap">{m.device}</Link><span className="sub small">{m.device_os || "ОС не указана"} · {m.bi_source}</span></td>
              <td><Link to={`/devices?card=${m.ksc_source_id}:${m.host_id}`} className="nowrap">{m.host_name}</Link><span className="sub small">{m.ksc_source}</span><Activity at={m.last_connected} act={m.activity} /></td>
              <td className="small"><span className={`badge ${m.level === "conflict" ? "err" : m.level === "auto" || m.level === "confirmed" ? "ok" : "warn"}`}>{m.level_ru}</span>
                {m.name_match && <span className={`badge ${NAME_CLS[m.name_match] ?? ""}`} title={m.name_ru}>{NAME_SHORT[m.name_match]}</span>}
                <span className="sub">{m.signals.join("; ")}</span>{m.issues.map((i, n) => <span key={n} className="sub warn-text">{i.text}</span>)}
                {m.others.length > 0 && <details className="others"><summary>Другие записи KSC с этим именем: {m.others.length}</summary>
                  <ul>{m.others.map((o, n) => <li key={n}><b>{o.host_name}</b> · {o.ksc_source}<Activity at={o.last_connected} act={o.activity} /><span className="sub small">{o.level_ru}{o.why ? ` — ${o.why}` : ""}</span></li>)}</ul></details>}</td>
              <td className="small hide-md">{m.decided_by ? <>{m.decided_by}<span className="sub">{fmt(m.decided_at)}{m.note ? ` · ${m.note}` : ""}</span></> : <span className="muted">автоматически</span>}</td>
              {admin && <td className="nowrap">{["confirmed", "rejected", "manual"].includes(m.level)
                ? <button type="button" className="btn mini ghost" disabled={busy === m.id} onClick={() => act(m, "reset")}>Отменить решение</button>
                : m.level === "history" ? <span className="muted small">прежняя связь</span>
                : <span className="row tight"><button type="button" className="btn mini" disabled={busy === m.id} onClick={() => act(m, "confirm")}>{["stale", "inactive"].includes(m.level) ? "Выбрать" : "Подтвердить"}</button>
                  {!["stale", "inactive"].includes(m.level) && <button type="button" className="btn mini ghost" disabled={busy === m.id} onClick={() => act(m, "reject")}>Отклонить</button>}</span>}</td>}</tr>} />
            {!list.items.length && !list.loading && <tr><td colSpan={admin ? 6 : 4}><Empty icon="checkCircle" title="Нет сопоставлений в этом состоянии">{level === "" || level === "needs_manual" ? "Спорных записей нет: совпадения либо подтверждены, либо приняты автоматически." : "Измените отбор или запрос."}</Empty></td></tr>}
          </tbody>
        </table>)}
    </div>
    <ListFoot list={list} />
    {admin && sel.count > 0 && <Dock label="Действия с отмеченными сопоставлениями">
      <span><b>{num(sel.count)}</b> <span className="muted">{plural(sel.count, "отмечено", "отмечено", "отмечено")}</span></span>
      <button type="button" className="btn mini primary" onClick={() => setBulk({ action: "confirm", scope: "ids", ids: sel.ids })}><Icon name="check" size={15} />Подтвердить</button>
      <button type="button" className="btn mini" onClick={() => setBulk({ action: "reject", scope: "ids", ids: sel.ids })}>Отклонить</button>
      <button type="button" className="btn mini" onClick={() => setBulk({ action: "reset", scope: "ids", ids: sel.ids })}>Отменить решения</button>
      <button type="button" className="btn mini icon" onClick={sel.clear} aria-label="Снять отметку"><Icon name="close" size={15} /></button>
    </Dock>}
    {bulk && <BulkDialog bulk={bulk} onClose={() => setBulk(null)} onDone={(op) => { setBulk(null); sel.clear(); setTick((x) => x + 1);
      show(op.status === "done" ? `${ACT_DONE[op.action]}: ${num(op.changed)}${op.total > op.changed ? ` (пропущено уже в этом состоянии: ${num(op.total - op.changed)})` : ""}` : `Операция не завершена: ${op.error}`, op.status === "done" ? "ok" : "error"); }} />}
    {report && <QuickReportPanel kind="quick_bi" title="Отчёт: расхождения BI и KSC" options={{ scope: false, bi: true }} params={{ view: "discrepancies", q: applied || undefined }} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
    {toast}
  </>);
}

const ACT_RU = { confirm: "Подтвердить", reject: "Отклонить", reset: "Отменить решения" } as const;
const ACT_PP = { confirm: ["подтверждено", "подтверждены"], reject: ["отклонено", "отклонены"], reset: ["отменено", "отменены"] } as const;
const ACT_DONE: Record<string, string> = { confirm: "Подтверждено соответствий", reject: "Отклонено соответствий", reset: "Отменено решений" };

/** Предварительная сводка массовой операции (точное число, источники, примеры, пропуски) → выполнение на сервере с ходом и итогом. */
function BulkDialog({ bulk, onClose, onDone }: { bulk: Bulk; onClose: () => void; onDone: (op: BiBulkOp) => void }) {
  const [plan, setPlan] = useState<BiBulkPlan | null>(null); const [err, setErr] = useState(""); const [op, setOp] = useState<BiBulkOp | null>(null);
  useEffect(() => { api.bi.bulk({ ...bulk, preview: true }).then(setPlan).catch((e) => setErr((e as ApiError).message)); }, [bulk]);
  useEffect(() => {
    if (!op || op.status !== "running") return;
    const t = window.setInterval(() => { api.bi.bulkStatus(op.id).then((o) => { setOp(o); if (o.status !== "running") onDone(o); }).catch(() => undefined); }, 600);
    return () => window.clearInterval(t);
  }, [op]); // eslint-disable-line react-hooks/exhaustive-deps
  const run = async () => {
    try { const r = await api.bi.bulk({ ...bulk, preview: false }); if (r.op) setOp({ id: r.op, status: "running", action: bulk.action, total: r.n, done: 0, changed: 0, skipped: r.skipped, error: null }); else onClose(); }
    catch (e) { setErr((e as ApiError).message); }
  };
  const title = bulk.scope === "exact" ? "Подтвердить все актуальные точные совпадения" : `${ACT_RU[bulk.action]}: отмеченные сопоставления`;
  return (
    <Modal title={title} onClose={op?.status === "running" ? () => undefined : onClose} guard={false}
      footer={op ? null : <><button className="btn ghost" onClick={onClose}>Отмена</button>
        <button className={`btn ${bulk.action === "reject" ? "danger" : "primary"}`} disabled={!plan?.n} onClick={() => void run()}>{plan ? `${ACT_RU[bulk.action]} · ${num(plan.n)}` : "…"}</button></>}>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!plan && !err && <SkelRows rows={4} cols={3} />}
      {plan && !op && <div className="bulk-plan">
        <p className="bulk-n"><b>{num(plan.n)}</b> {plural(plan.n, `соответствие будет ${ACT_PP[bulk.action][0]}`, `соответствия будут ${ACT_PP[bulk.action][1]}`, `соответствий будут ${ACT_PP[bulk.action][1]}`)}{bulk.action === "reset" ? " — пары вернутся к автоматическому сопоставлению" : ""}</p>
        {bulk.action === "reject" && plan.n > 0 && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Отклонённые пары больше не предлагаются. Отменить можно на отборе «Отклонённые».</div></div>}
        {bulk.action === "confirm" && <p className="muted small">Совпадение имени — операционный признак, а не доказательство физической идентичности: в основании будет указано «подтверждено администратором (массово)». Решение можно отменить.</p>}
        <dl className="kv compact"><div><dt>BI-источник</dt><dd>{Object.entries(plan.by_bi_source).map(([k, v]) => `${k}: ${num(v)}`).join("; ") || "—"}</dd></div>
          <div><dt>Источник KSC</dt><dd>{Object.entries(plan.by_ksc_source).map(([k, v]) => `${k}: ${num(v)}`).join("; ") || "—"}</dd></div>
          <div><dt>Будет пропущено</dt><dd>{plan.skipped.length ? plan.skipped.map((s) => <span key={s.reason} className="block">{num(s.n)} — {s.text}</span>) : "нет"}</dd></div>
          {bulk.scope === "exact" && <>
            <div><dt>Устаревшие записи KSC</dt><dd>{num(plan.stale_n)} — у этих компьютеров есть более актуальная запись в другом источнике; решения не требуют, остаются в отборе «Устаревшие записи»</dd></div>
            <div><dt>Спорные случаи</dt><dd>{num(plan.disputed_n)} — несколько активных записей с близкими датами, противоречия или недостаточно данных; не входят в операцию, остаются на ручное решение</dd></div>
            <div><dt>Без актуального компьютера</dt><dd>{num(plan.inactive_n)} — ни одна запись KSC не подключалась за период активности; не подтверждаются</dd></div></>}</dl>
        {plan.sample.length > 0 && <><h3 className="mt">Примеры{plan.n > plan.sample.length ? ` (первые ${plan.sample.length} из ${num(plan.n)})` : ""}</h3>
          <div className="table-scroll bulk-sample"><table className="table compact"><thead><tr><th>Устройство BI</th><th>Компьютер KSC</th><th className="hide-sm">Источник KSC</th><th className="hide-sm">Подключение</th></tr></thead>
            <tbody>{plan.sample.map((r, i) => <tr key={i}><td className="nowrap">{r.device}</td><td className="nowrap">{r.host_name}</td><td className="small hide-sm">{r.ksc_source}</td><td className="small hide-sm nowrap">{fmtDate(r.last_connected)}</td></tr>)}</tbody></table></div></>}
      </div>}
      {op && <div className="bulk-run" role="status" aria-live="polite">
        <p className="bulk-n">{op.status === "running" ? <>Выполняется… <b>{num(op.done)}</b> из {num(op.total)}</> : op.status === "done" ? <>Готово: <b>{num(op.changed)}</b> изменено</> : <>Ошибка: {op.error}</>}</p>
        <div className="pt-prog" role="progressbar" aria-valuemin={0} aria-valuemax={op.total} aria-valuenow={op.done} aria-label="Ход выполнения"><i style={{ width: `${op.total ? Math.round((op.done / op.total) * 100) : 100}%` }} /></div>
      </div>}
    </Modal>
  );
}
