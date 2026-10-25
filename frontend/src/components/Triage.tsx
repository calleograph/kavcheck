import { useEffect, useState } from "react";
import { api, type ApiError, type TriageBody, type TriageDecision, type TriageMeta, type TriageStatus } from "../api";
import { fmt, fmtDate } from "../util";
import { Modal } from "./Dialogs";
import { Icon } from "./Icons";

const TRI_CLASS: Record<TriageStatus, string> = { review: "review", confirmed: "confirmed", false_positive: "fp", obsolete: "obsolete", risk_accepted: "risk" };
export const TRI_SHORT: Record<TriageStatus, string> = { review: "Требует проверки", confirmed: "Подтверждена", false_positive: "Ложное срабатывание", obsolete: "Неактуальна", risk_accepted: "Риск принят" };

/** Статус обработки обнаружения. Отсутствие решения — исходное состояние «Требует проверки». */
export function TriageBadge({ d }: { d: TriageDecision | null | undefined }) {
  if (!d) return <span className="tri review" title="Решения специалиста ещё нет">Требует проверки</span>;
  const tip = [d.scope_ru, d.reason_ru, d.comment, d.by && `${d.by}, ${fmt(d.at)}`, d.review_until && `пересмотр до ${fmtDate(d.review_until)}`, d.recheck_reason].filter(Boolean).join(" · ");
  return <span className={`tri ${TRI_CLASS[d.status]}`} title={tip}>{d.recheck ? <Icon name="refresh" size={12} /> : null}{TRI_SHORT[d.status]}{d.status === "risk_accepted" && d.review_until ? ` до ${fmtDate(d.review_until)}` : ""}</span>;
}

export interface TriageTarget { source_id: string; host_id: number; host_name: string; vuln_key: string; origin: "ksc" | "ext"; product: string; version: string; zone_id?: string; zone_name?: string }

/** Окно решения по обнаружению: статус, основание, комментарий и — явно — область действия. По умолчанию решение касается только этой уязвимости на этом компьютере. */
export function TriageDialog({ targets, current, onClose, onDone }: { targets: TriageTarget[]; current?: TriageDecision | null; onClose: () => void; onDone: (count: number) => void }) {
  const [meta, setMeta] = useState<TriageMeta | null>(null);
  const [status, setStatus] = useState<TriageStatus>(current && current.stored_status !== "review" ? current.stored_status : "false_positive");
  const [reason, setReason] = useState(current?.reason ?? "");
  const [comment, setComment] = useState(current?.comment ?? "");
  const [scope, setScope] = useState<"host" | "product" | "zone">("host");
  const [until, setUntil] = useState(() => new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10));
  const [sure, setSure] = useState(false);
  const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  useEffect(() => { api.triage.meta().then(setMeta).catch((e) => setErr((e as ApiError).message)); }, []);
  const one = targets.length === 1 ? targets[0] : null;
  const wide = scope !== "host";
  const needReason = status === "false_positive" || status === "obsolete" || status === "risk_accepted";
  const reasons = (meta?.reasons ?? []).filter((r) => (status === "risk_accepted" ? ["compensating", "business", "other"].includes(r.key) : status === "obsolete" ? ["fixed", "other"].includes(r.key) : status === "false_positive" ? r.key.startsWith("fp_") || r.key === "other" : true));
  const canRisk = !!meta?.can_wide;
  const ready = !busy && (!needReason || !!(reason || comment.trim())) && (!wide || sure) && (status !== "risk_accepted" || (!!until && canRisk));
  const submit = async () => {
    setBusy(true); setErr("");
    try {
      const items: TriageBody[] = targets.map((t) => ({ source_id: t.source_id, vuln_key: t.vuln_key, origin: t.origin, scope, host_id: t.host_id, host_name: t.host_name, product: t.product, version: scope === "product" ? t.version : t.version, zone_id: scope === "zone" ? t.zone_id : undefined,
        status, reason, comment, review_until: status === "risk_accepted" ? `${until}T23:59:59Z` : null }));
      if (items.length === 1) await api.triage.set(items[0]); else await api.triage.bulk(items);
      onDone(items.length); onClose();
    } catch (e) { setErr((e as ApiError).message); setBusy(false); }
  };
  const label = status === "false_positive" ? "Отметить как ложное срабатывание" : status === "obsolete" ? "Отметить как неактуальную" : status === "risk_accepted" ? "Принять риск" : status === "confirmed" ? "Подтвердить уязвимость" : "Вернуть на проверку";
  return (
    <Modal title={one ? `Обработка: ${one.vuln_key}` : `Обработка обнаружений: ${targets.length}`} onClose={onClose}
      lede={one ? <>Компьютер <b>{one.host_name}</b>, {one.product || "программа не определена"} {one.version}</> : "Одно решение для всех выбранных строк (на своих компьютерах)."}
      footer={<><button className="btn ghost" onClick={onClose}>Отмена</button><button className={`btn ${status === "confirmed" ? "danger" : "primary"}`} onClick={submit} disabled={!ready} aria-busy={busy}><span>{label}</span></button></>}>
      <div className="form">
        <fieldset className="qr-sections"><legend>Результат проверки</legend>
          {(meta?.statuses ?? []).map((s) => (
            <label key={s.key} className="check"><input type="radio" name="tri-status" checked={status === s.key} disabled={s.key === "risk_accepted" && !canRisk} onChange={() => { setStatus(s.key); setReason(""); }} />
              {s.title}{s.key === "risk_accepted" && !canRisk ? <span className="muted small"> — только администратор</span> : null}</label>))}
        </fieldset>
        {needReason && <label>Основание<select value={reason} onChange={(e) => setReason(e.target.value)}><option value="">— выберите —</option>{reasons.map((r) => <option key={r.key} value={r.key}>{r.title}</option>)}</select></label>}
        {status === "risk_accepted" && <label>Срок пересмотра<input type="date" value={until} min={new Date(Date.now() + 86400000).toISOString().slice(0, 10)} onChange={(e) => setUntil(e.target.value)} /><span className="help">По истечении срока запись снова потребует внимания и вернётся в отчёты как актуальная проблема.</span></label>}
        <label>Комментарий{needReason ? "" : " (необязательно)"}<textarea rows={3} value={comment} maxLength={4000} onChange={(e) => setComment(e.target.value)} placeholder="Что проверено и почему сделан такой вывод: версия, наличие исправления, настройка" /></label>
        {one && meta?.can_wide && (
          <fieldset className="qr-sections"><legend>Область действия</legend>
            <label className="check"><input type="radio" name="tri-scope" checked={scope === "host"} onChange={() => { setScope("host"); setSure(false); }} />Только эта уязвимость на этом компьютере <span className="muted small">(рекомендуется)</span></label>
            <label className="check"><input type="radio" name="tri-scope" checked={scope === "product"} onChange={() => { setScope("product"); setSure(false); }} disabled={!one.product} />Эта уязвимость для «{one.product || "—"}{one.version ? ` ${one.version}` : ""}» на всех компьютерах источника</label>
            <label className="check"><input type="radio" name="tri-scope" checked={scope === "zone"} onChange={() => { setScope("zone"); setSure(false); }} disabled={!one.zone_id} />Эта уязвимость на всех компьютерах зоны «{one.zone_name || "—"}»</label>
            {wide && <label className="check warn-text"><input type="checkbox" checked={sure} onChange={(e) => setSure(e.target.checked)} />Понимаю: исключение распространится на {scope === "product" ? "все компьютеры с этой программой" : "все компьютеры зоны"}</label>}
          </fieldset>)}
        {current && <p className="muted small">Сейчас: {current.status_ru}{current.by ? ` · ${current.by}, ${fmt(current.at)}` : ""}{current.recheck_reason ? ` · ${current.recheck_reason}` : ""}. Исходные сведения об уязвимости остаются в базе; изменение попадает в историю.</p>}
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </div>
    </Modal>
  );
}

/** История решения: кто, когда и что изменил. */
export function TriageHistory({ id, onClose }: { id: string; onClose: () => void }) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.triage.history>> | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.triage.history(id).then(setData).catch((e) => setErr((e as ApiError).message)); }, [id]);
  return (
    <Modal title="История обработки" onClose={onClose} guard={false} lede={data ? `${data.decision.vuln_key} · ${data.decision.host_name || data.decision.product}` : undefined}>
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {data && <table className="table compact"><thead><tr><th>Когда</th><th>Кто</th><th>Действие</th><th>Комментарий</th></tr></thead>
        <tbody>{data.events.map((e, i) => <tr key={i}><td className="nowrap">{fmt(e.at)}</td><td>{e.actor}</td><td>{e.from ? `${e.from} → ${e.to}` : e.to}</td><td>{e.comment}</td></tr>)}</tbody></table>}
    </Modal>
  );
}
