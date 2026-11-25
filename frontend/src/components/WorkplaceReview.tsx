import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { qs, req } from "../api";
import { fmt, num } from "../util";
import { ConfirmDialog, Modal } from "./Dialogs";
import { FilterBar } from "./FilterBar";
import { ListFoot, VirtualRows, useInfinite, usePanel, type Chunk } from "./Infinite";
import { QuickReportPanel } from "./QuickReport";
import { Empty, SkelRows } from "./ui";

const PATH = "/employee-protection/workplaces";
const CONFIDENCE = { confirmed: "Подтверждённая", likely: "Высокая вероятность", possible: "Предполагаемая", rejected: "Отклонена" } as const;
export const ASSIGNMENT_BASIS = { manual: "Решение администратора", inventory: "Назначение в учёте", bi: "Закрепление по BI", observed: "Автоматически по наблюдениям KSC" } as const;
type Choice = { id: string; name: string; detail?: string };
type Decision = "assigned" | "confirmed" | "rejected" | "reset";
type Change = { employee_id: string; device_id: string; decision: Decision };
type Edit = { action: "add" } | { action: "correct"; row: Workplace } | { action: "assign"; device?: Choice; employee?: Choice };
interface Workplace {
  id: string;
  employee: Choice & { login?: string; department?: string };
  device: Choice & { asset_id?: number; source_id?: string; host_id?: number; os?: string };
  confidence: keyof typeof CONFIDENCE;
  evidence: string[];
  observed_days?: number;
  span_days?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  decision?: Exclude<Decision, "reset">;
  decided_at?: string;
  primary?: boolean;
  assignment_basis?: keyof typeof ASSIGNMENT_BASIS | null;
  asset_version?: number;
  proposals?: Record<string, { label: string; value: string; id?: number | string }>;
}

function Picker({ label, path, scope, value, onChange }: {
  label: string; path: string; scope?: { inventory?: boolean; asset_id?: string }; value: Choice | null; onChange: (v: Choice | null) => void;
}) {
  const [q, setQ] = useState("");
  const [items, setItems] = useState<Choice[]>([]);
  const [status, setStatus] = useState("");
  useEffect(() => {
    setItems([]);
    setStatus("");
    if (value || (q.trim().length < 2 && !scope?.asset_id)) return;
    let active = true;
    const timer = window.setTimeout(() => {
      req<{ items: Choice[] }>("GET", `${PATH}/${path}${qs({ q: q.trim(), ...scope })}`).then((data) => {
        if (!active) return;
        setItems(data.items);
        if (!data.items.length) setStatus("Совпадений нет");
      }).catch((e: Error) => { if (active) setStatus(e.message); });
    }, 250);
    return () => { active = false; window.clearTimeout(timer); };
  }, [path, q, scope?.asset_id, scope?.inventory, value]);
  return <div>
    <label className="field"><span>{label}</span>
      {value ? <span><b>{value.name}</b>{value.detail && ` · ${value.detail}`}{" "}
        <button type="button" className="link-btn" onClick={() => onChange(null)}>Изменить</button></span>
        : <input value={q} maxLength={200} placeholder="Введите имя или учётную запись" onChange={(e) => setQ(e.target.value)} />}
    </label>
    {status && <span className="sub" role="status">{status}</span>}
    {!value && items.length > 0 && <div className="row" role="group" aria-label={`Результаты · ${label}`}>
      {items.map((x) => <button type="button" key={x.id} className="btn mini" onClick={() => onChange(x)}>{x.name}{x.detail && ` · ${x.detail}`}</button>)}
    </div>}
  </div>;
}

function WorkplaceEditor({ edit, scope, busy, error, onClose, onSave }: {
  edit: Edit; scope: { inventory?: boolean; asset_id?: string }; busy: boolean; error: string; onClose: () => void; onSave: (changes: Change[], comment: string) => void;
}) {
  const row = edit.action === "correct" ? edit.row : undefined;
  const assignment = edit.action === "assign" ? edit : null;
  const [person, setPerson] = useState<Choice | null>(row?.employee ?? assignment?.employee ?? null);
  const [target, setTarget] = useState<Choice | null>(row?.device ?? assignment?.device ?? null);
  const [comment, setComment] = useState("");
  const valid = person && target && (!row || person.id !== row.employee.id || target.id !== row.device.id);
  return <Modal title={assignment ? "Закрепить компьютер" : row ? "Исправить связь" : "Добавить рабочее место"} onClose={onClose}
    footer={<button type="button" className="btn primary" disabled={!valid || busy} onClick={() => {
      if (!valid) return;
      const changes: Change[] = [{ employee_id: person.id, device_id: target.id, decision: assignment ? "assigned" : "confirmed" }];
      if (row) changes.unshift({ employee_id: row.employee.id, device_id: row.device.id, decision: "rejected" });
      onSave(changes, comment);
    }}>{assignment ? "Закрепить" : "Сохранить"}</button>}>
    <div className="stack">
      {assignment && target && <p className="small"><b>{target.name}</b> будет закреплён за выбранным сотрудником после пересчёта.</p>}
      {row && <p className="muted small">Связь «{row.employee.name} · {row.device.name}» будет отклонена.</p>}
      <Picker label="Сотрудник" path="people" value={person} onChange={setPerson} />
      {!assignment?.device && <Picker label="Компьютер" path="targets" scope={scope} value={target} onChange={setTarget} />}
      <label className="field"><span>Основание решения</span><input value={comment} maxLength={500} onChange={(e) => setComment(e.target.value)} /></label>
      {error && <div className="alert error" role="alert"><div className="alert-body">{error}</div></div>}
    </div>
  </Modal>;
}

export function WorkplaceReview({ inventory, assetId, employeeId, deviceId }: {
  inventory?: boolean; assetId?: string; employeeId?: string; deviceId?: string;
}) {
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const [confidence, setConfidence] = useState("");
  const [selected, setSelected] = useState<Record<string, Workplace>>({});
  const [edit, setEdit] = useState<Edit | null>(null);
  const [apply, setApply] = useState<Workplace[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [report, setReport] = usePanel<Record<string, unknown>>("workplaces");
  const scope = { inventory, asset_id: assetId };
  const filters = { q: search, confidence, employee_id: employeeId, device_id: deviceId, ...scope };
  const list = useInfinite<Workplace>(`workplaces:${Boolean(inventory)}:${assetId ?? ""}:${employeeId ?? ""}:${deviceId ?? ""}`, [filters],
    (offset, limit) => req<Chunk<Workplace>>("GET", `${PATH}${qs({ ...filters, offset, limit })}`), 50, { snapshotKey: "generation" });
  const generation = typeof list.extra?.generation === "string" ? list.extra.generation : "";
  const canEdit = list.extra?.can_edit === true;
  const pending = list.extra?.pending === true;
  const applyBlocked = list.extra?.apply_blocked === true;
  const snapshotError = typeof list.extra?.snapshot_error === "string" ? list.extra.snapshot_error : "";
  const picked = Object.values(selected);
  const proposed = picked.filter((r) => r.asset_version && Object.values(r.proposals ?? {}).some((x) => x.id));
  const repeatedAsset = new Set(proposed.map((r) => r.device.asset_id)).size !== proposed.length;
  const warnings = (list.extra?.warnings ?? []) as string[];
  useEffect(() => {
    const id = window.setTimeout(() => setSearch(q.trim()), 250);
    return () => window.clearTimeout(id);
  }, [q]);
  useEffect(() => {
    if (!pending || list.loading) return;
    const id = window.setTimeout(list.reload, 5000);
    return () => window.clearTimeout(id);
  }, [list.reload, list.loading, pending]);
  useEffect(() => { setSelected({}); }, [generation, search, confidence, employeeId, deviceId, assetId]);

  const save = async (changes: Change[], comment = "") => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await req<{ changed: number }>("POST", `${PATH}/decide`, { generation, items: changes, comment });
      const saved = changes.some((change) => change.decision === "assigned") ?
        "Закрепление сохранено. Ожидается пересчёт." : `Решений сохранено · ${num(result.changed)}`;
      setMessage(result.changed ? saved : "Решения уже сохранены");
      setEdit(null);
      setSelected({});
      list.reload();
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };
  const decide = (decision: Decision) => void save(picked.map((r) =>
    ({ employee_id: r.employee.id, device_id: r.device.id, decision })));
  const locked = busy || pending || list.loading || q.trim() !== search || !generation;
  const scoped = Boolean(deviceId || assetId);
  const target = deviceId ? list.items[0]?.device ?? { id: deviceId, name: "Выбранный компьютер" } : list.items[0]?.device;
  return <>
    <FilterBar search={{ value: q, onChange: setQ, placeholder: "Сотрудник, учётная запись или компьютер" }}
      primary={<label className="field"><select aria-label="Оценка связи" value={confidence} onChange={(e) => setConfidence(e.target.value)}>
        <option value="">Все оценки</option>{Object.entries(CONFIDENCE).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
      </select></label>}
      count={{ n: list.initial ? null : list.total, noun: ["связь", "связи", "связей"] }}
      onRefresh={list.reload} refreshing={list.refreshing}
      report={{ onClick: () => setReport({ ...filters, view: "workplaces", ...(picked.length ? { pairs: picked.map((r) => r.id) } : {}) }),
        count: picked.length, disabled: !generation || q.trim() !== search || list.refreshing }}
      extra={canEdit ? <button type="button" className="btn mini" disabled={locked}
        onClick={() => setEdit(scoped ? { action: "assign", device: target } : { action: "add" })}>
        {scoped ? "Выбрать сотрудника для закрепления" : "Добавить связь"}
      </button> : null} />
    {canEdit && picked.length > 0 && <div className="row" role="group" aria-label="Решение для выбранных связей">
      <span className="small muted">Выбрано {num(picked.length)} из 100</span>
      <button className="btn mini" type="button" disabled={locked || picked.some((r) => r.decision === "assigned")} onClick={() => decide("confirmed")}>Подтвердить связи</button>
      <button className="btn mini" type="button" disabled={locked} onClick={() => decide("rejected")}>Отклонить</button>
      <button className="btn ghost mini" type="button" disabled={locked || !picked.some((r) => r.decision)} onClick={() => decide("reset")}>Снять решение</button>
      {picked.length === 1 && <button className="btn ghost mini" type="button" disabled={locked}
        onClick={() => setEdit(picked[0].decision === "assigned" ? { action: "assign", device: picked[0].device } : { action: "correct", row: picked[0] })}>
        {picked[0].decision === "assigned" ? "Изменить закрепление" : "Исправить связь"}
      </button>}
      {proposed.length > 0 && <button className="btn mini" type="button" disabled={locked || applyBlocked || repeatedAsset}
        title={repeatedAsset ? "Выберите одну связь на карточку" : undefined} onClick={() => setApply(proposed)}>Заполнить поля учёта</button>}
      <button className="btn ghost mini" type="button" onClick={() => setSelected({})}>Снять выбор</button>
    </div>}
    {pending && <p className="small muted" role="status">Ожидается фоновый пересчёт.</p>}
    {snapshotError && <p className="small warn-text" role="status">{snapshotError}</p>}
    {message && <p className="small muted" role="status">{message}</p>}
    {error && !edit && <div className="alert error" role="alert"><div className="alert-body">{error}</div></div>}
    {list.initial ? <SkelRows /> : list.items.length > 0 ? <div className="table-scroll">
      <table className="table compact virt"><thead><tr>{canEdit && <th aria-label="Выбор" />}
        <th>Сотрудник</th><th>Компьютер</th><th>Оценка и основания</th><th>Предложения по учёту</th>
      </tr></thead><tbody><VirtualRows list={list} colSpan={canEdit ? 5 : 4} estimate={86} row={(r) => {
        const d = r.device;
        const href = d.asset_id ? `/inventory/assets/${d.asset_id}?tab=place` : d.source_id && d.host_id != null ? `/devices?card=${d.source_id}:${d.host_id}` : "";
        return <tr>
          {canEdit && <td><input type="checkbox" checked={!!selected[r.id]} disabled={locked || (!selected[r.id] && picked.length >= 100)}
            aria-label={`Выбрать · ${r.employee.name} · ${d.name}`} onChange={(e) => {
              const checked = e.target.checked;
              setSelected((curr) => { const next = { ...curr }; if (checked) next[r.id] = r; else delete next[r.id]; return next; });
            }} /></td>}
          <td><b>{r.employee.name}</b><span className="sub">{r.employee.login}</span><span className="sub">{r.employee.department}</span></td>
          <td>{href ? <Link className="strong-link" to={href}>{d.name}</Link> : <b>{d.name}</b>}<span className="sub">{d.os}</span></td>
          <td><span className={`badge ${r.assignment_basis || r.confidence === "confirmed" ? "ok" : r.confidence === "possible" ? "warn" : ""}`}>
            {r.assignment_basis ? "Закреплено" : CONFIDENCE[r.confidence]}
          </span>
            {r.assignment_basis && <span className="sub">{ASSIGNMENT_BASIS[r.assignment_basis]}</span>}
            {r.primary && <span className="sub">Основное рабочее место</span>}
            {r.evidence.map((e) => <span className="sub" key={e}>{e}</span>)}
            {r.first_seen_at && <span className="sub">{!!r.observed_days && <>Подтверждённых дней {num(r.observed_days)} · </>}
              {fmt(r.first_seen_at)} — {fmt(r.last_seen_at)}{!!r.span_days && ` · ${num(r.span_days)} сут.`}</span>}
            {r.decided_at && <span className="sub">Решение {fmt(r.decided_at)}</span>}
            {canEdit && r.decision !== "assigned" && <span className="sub"><button className="link-btn" type="button" disabled={locked}
              aria-label={`Закрепить ${d.name} за сотрудником ${r.employee.name}`}
              onClick={() => setEdit({ action: "assign", device: d, employee: r.employee })}>Закрепить</button></span>}
          </td>
          <td>{Object.entries(r.proposals ?? {}).map(([k, v]) => <span className="sub" key={k}>{v.label} · {v.value}</span>)}
            {d.asset_id && !!Object.keys(r.proposals ?? {}).length && <Link to={href} className="link-btn">К карточке учёта</Link>}</td>
        </tr>;
      }} /></tbody></table>
    </div> : !list.error && <Empty icon="monitor" title={generation ? "Связи не найдены" : "Нет готового расчёта"}>{generation ? undefined : warnings.at(-1)}</Empty>}
    <ListFoot list={list} />
    {apply && <ConfirmDialog danger={false} title="Заполнить пустые поля учёта" confirmLabel="Применить" onClose={() => setApply(null)} onConfirm={async () => {
      const items = apply.map((r) => ({ pair: r.id, version: r.asset_version, values: Object.fromEntries(
        Object.entries(r.proposals ?? {}).flatMap(([key, field]) => field.id ? [[key, field.id]] : [])) }));
      const result = await req<{ changed: number }>("POST", `${PATH}/apply`, { generation, items });
      setSelected({});
      setMessage(`Карточек обновлено · ${num(result.changed)}`);
      list.reload();
    }} body={<>
      <p>Изменения будут записаны в историю карточек.</p>
      <ul>{apply.map((r) => <li key={r.id}><b>{r.device.name}</b> · {Object.values(r.proposals ?? {}).map((v) => `${v.label} — ${v.value}`).join(" · ")}</li>)}</ul>
    </>} />}
    {edit && <WorkplaceEditor edit={edit} scope={scope} busy={busy} error={error} onClose={() => { setEdit(null); setError(""); }}
      onSave={(changes, comment) => void save(changes, comment)} />}
    {report && <QuickReportPanel kind="quick_employee_protection" title="Рабочие места сотрудников" params={report} activityDays={0}
      options={{ scope: false }} canReport onClose={() => setReport(null)} />}
  </>;
}
