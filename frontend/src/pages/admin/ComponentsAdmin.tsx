import { AdminReportButton } from "../../components/QuickReport";
import { useCallback, useEffect, useState } from "react";
import { api, type ApiError, type CompRow, type CompStatus, type CompTable } from "../../api";
import { Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows } from "../../components/ui";
import { fmt, fmtDate } from "../../util";

const TONE: Record<CompStatus, string> = { current: "ok", update: "warn", deferred: "warn", incompatible: "err", review: "warn", unknown: "", unavailable: "" };
const DEC_RU: Record<string, string> = { ok: "обновлять по выпускам KAV Checker", deferred: "обновление отложено", incompatible: "несовместимо", review: "требует проверки" };

/** Реестр компонентов: установленная и доступная версии, статус и решение разработчика. Версии проверяются в фоне и берутся из кэша; ничего не обновляется отсюда. */
export default function ComponentsAdmin() {
  const [d, setD] = useState<CompTable | null>(null);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<CompRow | null>(null);
  const [filter, setFilter] = useState("");
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.components().then(setD).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (d?.requested) { const t = window.setTimeout(() => void load(), 6000); return () => window.clearTimeout(t); } }, [d, load]);
  if (!d) return err ? <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={6} cols={5} />;
  const rows = d.items.filter((r) => !filter || r.status === filter);
  const groups = [...new Set(rows.map((r) => r.group))];
  return (
    <div className="stack">
      <section className="card">
        <div className="pt-sum">
          {(Object.keys(d.counts) as CompStatus[]).filter((k) => d.counts[k] > 0).map((k) => <div key={k} className={k === "update" || k === "incompatible" ? "bad" : ""}><b>{d.counts[k]}</b><span>{d.items.find((r) => r.status === k)?.status_ru}</span></div>)}
        </div>
        <p className="muted small mt">Проверка доступных версий: {d.checked_at ? fmt(d.checked_at) : "ещё не выполнялась"} (в фоне, раз в сутки; страница внешние сервисы не опрашивает). Реестр рассмотрен для выпуска {d.reviewed_for} ({fmtDate(d.reviewed_at)}).{" "}
          <button type="button" className="link-btn" disabled={d.requested} onClick={async () => { try { await api.admin.checkComponents(); show("Проверка запрошена"); void load(); } catch (e) { setErr((e as ApiError).message); } }}>{d.requested ? "Проверка выполняется…" : "Проверить сейчас"}</button></p>
        <div className="toolbar"><select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Статус" className="w-auto"><option value="">Все статусы</option>{(Object.keys(d.counts) as CompStatus[]).filter((k) => d.counts[k] > 0).map((k) => <option key={k} value={k}>{d.items.find((r) => r.status === k)?.status_ru}</option>)}</select>
          <div className="spacer" /><AdminReportButton view="components" title="компоненты" params={{ status: filter }} /></div>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </section>
      {groups.map((g) => (
        <section key={g} className="card"><h2>{g}</h2>
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Компонент</th><th>Работает</th><th>Установлена</th><th>Доступна</th><th>Статус</th></tr></thead>
            <tbody>{rows.filter((r) => r.group === g).map((r) => (
              <tr key={r.key} className="clickable" tabIndex={0} onClick={() => setOpen(r)} onKeyDown={(e) => { if (e.key === "Enter") setOpen(r); }}>
                <td><b>{r.title}</b><span className="sub">{r.purpose}</span></td>
                <td>{r.running === null ? "—" : r.running ? <span className="badge ok">да</span> : <span className="badge warn">нет</span>}</td>
                <td className="mono small">{r.installed ?? "—"}</td><td className="mono small">{r.latest ?? "—"}</td>
                <td><span className={`badge ${TONE[r.status]}`}>{r.status_ru}</span>{r.status === "deferred" && r.why && <span className="sub small">{r.why.slice(0, 90)}{r.why.length > 90 ? "…" : ""}</span>}</td></tr>))}</tbody></table></div>
        </section>))}
      {open && (
        <Modal title={open.title} side lede={open.purpose} onClose={() => setOpen(null)}>
          <dl className="kv">
            <div><dt>Установленная версия</dt><dd className="mono">{open.installed ?? "неизвестна"}</dd></div>
            <div><dt>Проверена в этом выпуске</dt><dd className="mono">{open.verified ?? "—"}</dd></div>
            <div><dt>Доступная версия</dt><dd className="mono">{open.latest ?? "—"}{open.latest_url && <> · <a href={open.latest_url} target="_blank" rel="noopener noreferrer">страница выпуска</a></>}{open.published_at && ` · ${fmtDate(open.published_at)}`}</dd></div>
            <div><dt>Проверка обновлений</dt><dd>{open.checked_at ? fmt(open.checked_at) : "не выполнялась"}{open.check_error && <span className="sub bad-text">{open.check_error}</span>}</dd></div>
            <div><dt>Статус</dt><dd><span className={`badge ${TONE[open.status]}`}>{open.status_ru}</span></dd></div>
            <div><dt>Решение разработчика</dt><dd>{DEC_RU[open.decision.status] ?? open.decision.status}{open.decision.reason && <span className="sub">Причина: {open.decision.reason}</span>}{open.decision.note && <span className="sub">{open.decision.note}</span>}</dd></div>
            <div><dt>Совместимость</dt><dd>{open.compat || "—"}{open.branch && <span className="sub">Совместимая ветка: {open.branch}.x</span>}</dd></div>
            <div><dt>Известные ограничения</dt><dd>{open.limits || "нет"}</dd></div>
            <div><dt>Release Notes</dt><dd><a href={open.release_notes} target="_blank" rel="noopener noreferrer">Официальные заметки о выпусках</a></dd></div>
          </dl>
          <p className="pt-note">Обновление компонентов приложения выполняется только проверенным выпуском KAV Checker. Сигнатуры и разрешённые шаблоны Nuclei обновляются отдельно по модели проверки и утверждения.</p>
        </Modal>)}
      {toast}
    </div>
  );
}
