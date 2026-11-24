import { useEffect, useId, useState } from "react";
import { Link } from "react-router-dom";
import { req } from "../../api";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { ReportButton } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { Empty, MaskHint, SkelRows } from "../../components/ui";
import { num } from "../../util";
import { InvZoneSelect, LocationPicker, PersonPicker, RefSelect, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { inv } from "./invApi";

interface Rule {
  name: string;
  enabled: boolean;
  priority: number;
  networks: string[];
  ip_kind: "any" | "connection" | "device";
  source_id: string | null;
  host: string;
  group: string;
  domain: string;
  network_location: string;
  network_id: string;
  type_id: number | null;
  infra_source_id: number | null;
  infra_site: string;
  vpn: boolean;
  site_id: number | null;
  location_id: number | null;
  branch_id: number | null;
  dept_id: number | null;
  resp_id: number | null;
  zone_id: string | null;
}

type SavedRule = Rule & { id: number };
type Sources = { id: string; name: string }[];
type InfraSources = { id: number; name: string }[];

interface Preview {
  matched: number;
  effective: number;
  conflicts: number;
  would_fill: number;
  stale: number;
  items: { id: number; inv_no: string; name: string; status: string; effective: boolean; fresh: boolean }[];
}

const PATH = "/inv/geography/rules";
const NEW_RULE: Rule = {
  name: "", enabled: true, priority: 100, networks: [], ip_kind: "any", source_id: null, host: "", group: "", domain: "",
  network_location: "", network_id: "", type_id: null, infra_source_id: null, infra_site: "", vpn: false,
  site_id: null, location_id: null, branch_id: null, dept_id: null, resp_id: null, zone_id: null,
};
const STATUS: Record<string, string> = {
  site: "Площадка по правилу",
  approx: "Примерно по публичному IP",
  unknown: "Недостаточно данных",
  vpn: "VPN или прокси",
  conflict: "Противоречивые правила",
};
const MASKS = [
  ["host", "Имя компьютера", 200],
  ["group", "Группа администрирования KSC", 300],
  ["domain", "Домен", 200],
  ["network_location", "Сетевое местоположение KSC", 200],
  ["network_id", "Идентификатор сети KSC", 200],
  ["infra_site", "Площадка в источнике инфраструктуры", 200],
] as const;

export default function InvGeoRules({ sources, onChanged }: { sources: Sources; onChanged: () => void }) {
  const { locs } = useInv();
  const report = useInvReport();
  const [rules, setRules] = useState<SavedRule[] | null>(null);
  const [infraSources, setInfraSources] = useState<InfraSources>([]);
  const [edit, setEdit] = useState<SavedRule | "new" | null>(null);
  const [remove, setRemove] = useState<SavedRule | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    req<{ items: SavedRule[]; infra_sources: InfraSources }>("GET", PATH).then((r) => {
      if (active) { setRules(r.items); setInfraSources(r.infra_sources); }
    }).catch((e: Error) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [attempt]);

  const save = (rule: SavedRule) => {
    setRules((rows) => [...(rows ?? []).filter((r) => r.id !== rule.id), rule]);
    setEdit(null);
    onChanged();
  };
  const deleteRule = async (id: number) => {
    await req("DELETE", `${PATH}/${id}`);
    setRules((rows) => (rows ?? []).filter((r) => r.id !== id));
    onChanged();
  };
  const rows = [...(rules ?? [])].sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name, "ru"));

  return (
    <div className="card flush">
      <div className="card-head">
        <h2>Правила принадлежности</h2><div className="spacer" />
        <button type="button" className="btn mini primary" disabled={!rules} onClick={() => setEdit("new")}><Icon name="plus" size={15} />Добавить правило</button>
        <ReportButton onClick={() => report.open(["geography_rules"], {})} disabled={!rules || !!error} title="Сформировать отчёт по правилам принадлежности" />
      </div>
      <p className="muted small pad">Меньшее число даёт правилу больший приоритет. При равенстве применяется самый узкий диапазон. Противоречие между равными правилами требует проверки. Правило VPN имеет преимущество перед остальными.</p>
      {error ? <div className="pad"><p className="field-err" role="alert">{error}</p>
        <button type="button" className="btn mini" onClick={() => { setError(""); setAttempt((n) => n + 1); }}>Повторить</button></div>
        : !rules ? <SkelRows rows={4} cols={4} /> : !rows.length ? <Empty title="Правил пока нет">Добавьте условия, чтобы предложить учётные сведения или определить сетевую площадку.</Empty>
        : <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Правило</th><th>Приоритет</th><th>Результат</th><th aria-label="Действия" /></tr></thead>
          <tbody>{rows.map((r) => <tr key={r.id}>
            <td><button type="button" className="link-btn" onClick={() => setEdit(r)}>{r.name}</button>
              {!r.enabled && <span className="sub">Выключено</span>}</td>
            <td className="mono">{r.priority}</td>
            <td>{r.vpn ? STATUS.vpn : [r.site_id && (locs?.find((l) => l.id === r.site_id)?.path || "Сетевая площадка"),
              (r.location_id || r.branch_id || r.dept_id || r.resp_id || r.zone_id) && "Предложение учётных сведений"].filter(Boolean).join(" · ")}</td>
            <td><button type="button" className="btn mini icon ghost" onClick={() => setRemove(r)} aria-label={`Удалить правило «${r.name}»`}><Icon name="trash" size={15} /></button></td>
          </tr>)}</tbody>
        </table></div>}
      {edit && <RuleEditor key={edit === "new" ? "new" : edit.id} rule={edit === "new" ? null : edit}
        sources={sources} infraSources={infraSources} onSave={save} onClose={() => setEdit(null)} />}
      {remove && <ConfirmDialog title="Удалить правило?" body={remove.name} confirmLabel="Удалить"
        onConfirm={() => deleteRule(remove.id)} onClose={() => setRemove(null)} />}
      {report.node}
    </div>
  );
}

function RuleEditor({ rule, sources, infraSources, onSave, onClose }: { rule: SavedRule | null; sources: Sources; infraSources: InfraSources; onSave: (rule: SavedRule) => void; onClose: () => void }) {
  const { id: ruleId, ...initial } = rule ?? { id: null, ...NEW_RULE };
  const report = useInvReport();
  const [draft, setDraft] = useState<Rule>(initial);
  const [networkText, setNetworkText] = useState(initial.networks.join("\n"));
  const [person, setPerson] = useState("");
  const [plan, setPlan] = useState<{ result: Preview; input: { id: number | null; rule: Rule } } | null>(null);
  const [busy, setBusy] = useState<"preview" | "save" | null>(null);
  const [error, setError] = useState("");
  const formId = useId();

  useEffect(() => {
    const id = rule?.resp_id;
    if (!id || draft.resp_id !== id) return;
    let active = true;
    inv.person(id).then((p) => { if (active) setPerson(p.name); }).catch(() => undefined);
    return () => { active = false; };
  }, [rule?.resp_id, draft.resp_id]);

  function change<K extends keyof Rule>(key: K, value: Rule[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
    setPlan(null);
  }

  const submit = async (action: "preview" | "save") => {
    const data = { ...draft, networks: networkText.split(/[,;\n]+/).map((v) => v.trim()).filter(Boolean) };
    setError("");
    setBusy(action);
    try {
      if (action === "preview") {
        const input = { id: ruleId, rule: data };
        setPlan({ result: await req<Preview>("POST", `${PATH}/preview`, input), input });
      } else {
        onSave(await req<SavedRule>(ruleId ? "PUT" : "POST", ruleId ? `${PATH}/${ruleId}` : PATH, data));
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (<>
    <Modal title={ruleId ? "Изменить правило" : "Новое правило принадлежности"} wide onClose={busy ? () => undefined : onClose}
      footer={<div className="row wrap"><button type="button" className="btn" disabled={!!busy} onClick={onClose}>Отмена</button>
        <div className="spacer" />
        <button type="button" className="btn" disabled={!!busy || !draft.name.trim()} onClick={() => void submit("preview")}>{busy === "preview" ? "Проверяем…" : "Предпросмотр"}</button>
        <button className="btn primary" type="submit" form={formId} disabled={!!busy || !draft.name.trim()}>{busy === "save" ? "Сохраняем…" : "Сохранить правило"}</button></div>}>
      <form id={formId} className="inv-form" onSubmit={(e) => { e.preventDefault(); void submit("save"); }}>
        <div className="inv-grid">
          <label className="field">Название<input required maxLength={160} disabled={!!busy} value={draft.name} onChange={(e) => change("name", e.target.value)} /></label>
          <label className="field">Приоритет<input type="number" min={0} max={10000} disabled={!!busy} value={draft.priority} onChange={(e) => change("priority", e.target.valueAsNumber || 0)} /></label>
          <label className="check-row"><input type="checkbox" disabled={!!busy} checked={draft.enabled} onChange={(e) => change("enabled", e.target.checked)} />Правило включено</label>
        </div>
        <fieldset className="inv-fs" disabled={!!busy}>
          <legend>Условия <MaskHint /></legend>
          <p className="muted small">Заполненные признаки должны совпасть одновременно. Для нескольких сетей достаточно совпадения с одной.</p>
          <div className="inv-grid">
            <label className="field wide">Адреса, подсети и диапазоны
              <textarea rows={2} value={networkText} maxLength={2600} placeholder="192.0.2.0/24, 2001:db8::/32"
                onChange={(e) => { setNetworkText(e.target.value); setPlan(null); }} />
              <span className="field-help">До 24 значений через запятую или с новой строки.</span>
            </label>
            <label className="field">Какие адреса проверять<select value={draft.ip_kind} onChange={(e) => change("ip_kind", e.target.value as Rule["ip_kind"])}>
              <option value="any">Адреса устройства и подключения</option><option value="connection">Адрес подключения агента к KSC</option><option value="device">Адреса устройства</option>
            </select></label>
            <label className="field">Источник KSC<select value={draft.source_id ?? ""} onChange={(e) => change("source_id", e.target.value || null)}>
              <option value="">Любой источник</option>
              {draft.source_id && !sources.some((s) => s.id === draft.source_id) && <option value={draft.source_id}>Недоступный источник</option>}
              {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select></label>
            <RefSelect kind="type" label="Тип оборудования" empty="Любой тип" value={draft.type_id} onChange={(id) => change("type_id", id)} />
            <label className="field">Источник инфраструктуры<select value={draft.infra_source_id ?? ""} onChange={(e) => change("infra_source_id", Number(e.target.value) || null)}>
              <option value="">Любой источник</option>
              {draft.infra_source_id && !infraSources.some((s) => s.id === draft.infra_source_id) && <option value={draft.infra_source_id}>Недоступный источник</option>}
              {infraSources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select></label>
            {MASKS.map(([field, label, maxLength]) => <label key={field} className="field">{label}
              <input value={draft[field]} maxLength={maxLength} onChange={(e) => change(field, e.target.value)} />
            </label>)}
          </div>
        </fieldset>
        <fieldset className="inv-fs" disabled={!!busy}>
          <legend>Результат</legend>
          <label className="check-row"><input type="checkbox" checked={draft.vpn} onChange={(e) => change("vpn", e.target.checked)} />VPN или прокси</label>
          {draft.vpn ? <p className="muted small">При совпадении с VPN система скрывает автоматически определённое место и предложения учётных сведений.</p> : <>
            <div className="inv-grid">
              <LocationPicker label="Сетевая площадка" value={draft.site_id} onChange={(id) => change("site_id", id)} />
              <LocationPicker label="Предложить учётное местоположение" value={draft.location_id} onChange={(id) => change("location_id", id)} />
              <RefSelect kind="branch" label="Предложить филиал" value={draft.branch_id} onChange={(id) => change("branch_id", id)} />
              <RefSelect kind="dept" label="Предложить подразделение" value={draft.dept_id} onChange={(id) => change("dept_id", id)} />
              <PersonPicker label="Предложить ответственного" value={draft.resp_id} name={person} onChange={(id, name) => { change("resp_id", id); setPerson(name); }} />
              <InvZoneSelect value={draft.zone_id} onChange={(id) => change("zone_id", id)} />
            </div>
            <p className="muted small">Сетевая площадка требует сетевого признака или площадки связанного объекта инфраструктуры. Предложения можно применить к пустым полям карточки после проверки.</p>
          </>}
        </fieldset>
        {error && <p className="field-err" role="alert">{error}</p>}
        {plan && <PreviewResult plan={plan.result} onReport={() => report.open(["geography_preview"], {
          geo_rule_preview: plan.input, detail: plan.result.matched ? "full" : "summary",
        })} />}
      </form>
    </Modal>
    {report.node}
  </>);
}

function PreviewResult({ plan, onReport }: { plan: Preview; onReport: () => void }) {
  return (
    <div className="inv-fs" aria-live="polite">
      <div className="card-head"><h3>Предпросмотр</h3><div className="spacer" />
        <ReportButton onClick={onReport} title="Сформировать отчёт по проверенному правилу" /></div>
      <p className="small">
        Совпадений: <b>{num(plan.matched)}</b> · Сработает: <b>{num(plan.effective)}</b> · Противоречия: <b>{num(plan.conflicts)}</b> ·
        Можно заполнить учётные поля: <b>{num(plan.would_fill)}</b> · Устаревшие наблюдения: <b>{num(plan.stale)}</b>
      </p>
      {plan.items.length > 0 && <div className="table-scroll"><table className="table compact">
        <caption className="sr-only">Примеры совпадений правила</caption>
        <thead><tr><th>Карточка</th><th>Результат наблюдения</th><th>Правило</th></tr></thead>
        <tbody>{plan.items.map((r) => <tr key={r.id}>
          <td><Link to={`/inventory/assets/${r.id}`} target="_blank" rel="noopener">{r.inv_no}</Link><span className="sub">{r.name}</span></td>
          <td>{STATUS[r.status] ?? r.status}{!r.fresh && <span className="sub">Устарело</span>}</td>
          <td>{r.effective ? (r.status === "conflict" ? "Требует проверки" : "Выбрано") : "Уступает другому правилу"}</td>
        </tr>)}</tbody>
      </table></div>}
      {plan.items.length < plan.matched && <p className="muted small">Показано {num(plan.items.length)} из {num(plan.matched)} совпадений.</p>}
    </div>
  );
}
