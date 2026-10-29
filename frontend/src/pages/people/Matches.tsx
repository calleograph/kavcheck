import { useEffect, useState } from "react";
import { api, type ApiError, type BiMatchItem } from "../../api";
import type { Ctx } from "../../App";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { ListFoot, useInfinite, useKept } from "../../components/Infinite";
import { biDeviceLink } from "../../components/OwnerBlock";
import { QuickReportPanel } from "../../components/QuickReport";
import { useToast } from "../../components/Toast";
import { Empty, Segmented, SkelRows } from "../../components/ui";
import { fmt } from "../../util";
import { Link } from "react-router-dom";

const LEVELS: [string, string][] = [["", "Требуют решения"], ["auto", "Предполагаемые"], ["confirmed", "Подтверждённые"], ["rejected", "Отклонённые"]];

/** «Сопоставление BI и KSC»: кандидаты, неоднозначные и противоречивые совпадения — подтверждение или отклонение администратором (с журналом действий). */
export default function Matches({ ctx }: { ctx: Ctx }) {
  const [q, setQ] = useKept("bm.q", ""); const [applied, setApplied] = useState(q); const [level, setLevel] = useKept("bm.level", "");
  const [tick, setTick] = useState(0); const [busy, setBusy] = useState<number | null>(null); const [toast, show] = useToast(); const [report, setReport] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<BiMatchItem>("bi:matches", [applied, level, tick], (offset, limit) => api.bi.matches({ q: applied, level, offset, limit }), 50);
  const counts = (list.extra as { counts?: Record<string, number> } | null)?.counts ?? {};
  const admin = ctx.me.user.is_admin;
  const act = async (m: BiMatchItem, decision: "confirm" | "reject" | "reset") => {
    setBusy(m.id);
    try { await api.bi.decide({ device_id: m.device_id, ksc_source_id: m.ksc_source_id, host_id: m.host_id, decision }); show(decision === "confirm" ? `Соответствие ${m.device} → ${m.host_name} подтверждено` : decision === "reject" ? "Соответствие отклонено и больше не предлагается" : "Решение сброшено"); setTick((x) => x + 1); }
    catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(null); }
  };
  const pending = (counts.candidate ?? 0) + (counts.ambiguous ?? 0) + (counts.conflict ?? 0);
  return (<>
    <p className="muted small fbar-note">Одинаковое имя не доказывает, что это один компьютер. Автоматически принимается только «предполагаемое» соответствие: имя единственное среди источников KSC и подтверждено ещё одним признаком (ОС, FQDN, учётная запись KSC). Остальное решает администратор; решение записывается в журнал действий.</p>
    <FilterBar search={{ value: q, onChange: setQ, placeholder: "Имя устройства BI или компьютера KSC", label: "Поиск сопоставлений" }}
      primary={<Segmented label="Уровень" value={level} onChange={setLevel} options={LEVELS.map(([k, l]) => [k, k === "" ? `${l} ${pending}` : `${l} ${counts[k] ?? 0}`] as [string, string])} />}
      chips={q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []} onReset={() => { setQ(""); setLevel(""); }}
      count={{ n: list.initial ? null : list.total, noun: ["сопоставление", "сопоставления", "сопоставлений"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
      report={{ onClick: () => setReport(true), title: "Отчёт «Расхождения BI и KSC»" }} />
    {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
    <div className="table-scroll">
      {list.initial ? <SkelRows cols={5} /> : (
        <table className="table">
          <thead><tr><th>Устройство BI</th><th>Компьютер KSC</th><th>Уровень и основание</th><th className="hide-md">Решение</th>{admin && <th />}</tr></thead>
          <tbody>
            {list.items.map((m) => <tr key={m.id}>
              <td><Link to={biDeviceLink(m.device_id)} className="strong-link">{m.device}</Link><span className="sub small">{m.device_os || "ОС не указана"} · {m.bi_source}</span></td>
              <td><Link to={`/devices?card=${m.ksc_source_id}:${m.host_id}`}>{m.host_name}</Link><span className="sub small">{m.ksc_source}</span></td>
              <td className="small"><span className={`badge ${m.level === "conflict" ? "err" : m.level === "auto" || m.level === "confirmed" ? "ok" : "warn"}`}>{m.level_ru}</span>
                <span className="sub">{m.signals.join("; ")}</span>{m.issues.map((i, n) => <span key={n} className="sub warn-text">{i.text}</span>)}</td>
              <td className="small hide-md">{m.decided_by ? <>{m.decided_by}<span className="sub">{fmt(m.decided_at)}</span></> : <span className="muted">автоматически</span>}</td>
              {admin && <td className="nowrap">{m.level === "confirmed" || m.level === "rejected"
                ? <button type="button" className="btn mini ghost" disabled={busy === m.id} onClick={() => act(m, "reset")}>Сбросить</button>
                : <span className="row tight"><button type="button" className="btn mini" disabled={busy === m.id} onClick={() => act(m, "confirm")}>Подтвердить</button>
                  <button type="button" className="btn mini ghost" disabled={busy === m.id} onClick={() => act(m, "reject")}>Отклонить</button></span>}</td>}</tr>)}
            {!list.items.length && !list.loading && <tr><td colSpan={admin ? 5 : 4}><Empty icon="checkCircle" title="Нет сопоставлений в этом состоянии">{level === "" ? "Все совпадения по именам либо приняты автоматически, либо уже решены." : "Измените уровень или запрос."}</Empty></td></tr>}
          </tbody>
        </table>)}
    </div>
    <ListFoot list={list} />
    {report && <QuickReportPanel kind="quick_bi" title="Отчёт: расхождения BI и KSC" options={{ scope: false, bi: true }} params={{ view: "discrepancies", q: applied || undefined }} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
    {toast}
  </>);
}
