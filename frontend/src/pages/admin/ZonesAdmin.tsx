import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, type Composition, type Conflict, type ContactRole, type CsvPlan, type ZoneBrief, type ZoneContact, type ZoneFull, type ZoneRuleKind, type ZoneRuleT } from "../../api";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { forgetZones } from "../../components/ZoneBits";
import { Empty, Segmented, SkelRows } from "../../components/ui";
import { fmt, num, plural } from "../../util";

const KIND: Record<ZoneRuleKind, string> = { net: "Сеть, адрес или диапазон", exclude: "Исключение", group: "Группа KSC", name: "Имя компьютера" };
const ROLE: Record<ContactRole, string> = { responsible: "Ответственный за устранение", cc: "Получает копию (руководитель)", group: "Группа рассылки" };
const EXAMPLE = "192.0.2.0/24\n198.51.100.10-198.51.100.50\nгруппа: Серверы*\nимя: srv-*\nисключить: 192.0.2.7";

/** Построчный ввод признаков: «192.0.2.0/24», «группа: Серверы*», «имя: srv-*», «исключить: 192.0.2.7». Пустые строки и # игнорируются. */
export function parseRules(text: string): ZoneRuleT[] {
  const out: ZoneRuleT[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(группа|имя|исключить|исключение|net|group|name|exclude)\s*[:=]\s*(.+)$/i.exec(line);
    if (m) { const k = m[1].toLowerCase(); out.push({ kind: k.startsWith("групп") || k === "group" ? "group" : k.startsWith("им") || k === "name" ? "name" : k.startsWith("искл") || k === "exclude" ? "exclude" : "net", value: m[2].trim(), note: "" }); }
    else for (const part of line.split(/[,;]\s*/).filter(Boolean)) out.push({ kind: "net", value: part.trim(), note: "" });
  }
  return out;
}

export default function ZonesAdmin() {
  const [sp, setSp] = useSearchParams();
  const view = sp.get("view") === "conflicts" ? "conflicts" : "list";
  const [items, setItems] = useState<ZoneBrief[] | null>(null); const [err, setErr] = useState("");
  const [edit, setEdit] = useState<ZoneFull | "new" | null>(null);
  const [csv, setCsv] = useState(false); const [del, setDel] = useState<ZoneBrief | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => { api.admin.zones.list().then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); forgetZones(); }, []);
  useEffect(load, [load]);
  const open = useCallback(async (id: string) => { try { setEdit(await api.admin.zones.get(id)); } catch (e) { setErr((e as ApiError).message); } }, []);
  const wanted = sp.get("zone");
  useEffect(() => { if (wanted) { void open(wanted); setSp((p) => { p.delete("zone"); return p; }, { replace: true }); } }, [wanted, open, setSp]);
  return (
    <div className="stack">
      <div className="toolbar">
        <Segmented label="Раздел" value={view} onChange={(v) => setSp(v === "list" ? { tab: "zones" } : { tab: "zones", view: v })} options={[["list", "Зоны"], ["conflicts", "Спорные компьютеры"]]} />
        <div className="spacer" />
        <a className="btn" href={api.admin.zones.csvUrl("export")}><Icon name="download" />Экспорт CSV</a>
        <button className="btn" onClick={() => setCsv(true)}><Icon name="upload" />Импорт из CSV</button>
        <button className="btn primary" onClick={() => setEdit("new")}><Icon name="plus" />Создать зону</button>
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {view === "conflicts" ? <Conflicts zones={items ?? []} /> : (
        <div className="table-scroll">{!items ? <SkelRows cols={6} /> : !items.length ? (
          <Empty icon="grid" title="Зон пока нет" action={<><button className="btn primary" onClick={() => setEdit("new")}><Icon name="plus" />Создать зону</button><button className="btn" onClick={() => setCsv(true)}><Icon name="upload" />Импорт из CSV</button></>}>
            Зона — это группа компьютеров, объединённая сетями или группами KSC и закреплённая за ответственными. Название, число и смысл зон выбираете вы: департаменты, филиалы, площадки, проекты. Для десятков зон удобнее загрузить CSV.</Empty>
        ) : (
          <table className="table"><thead><tr><th>Зона</th><th className="num">Приоритет</th><th className="num">Признаков</th><th className="num">Получателей</th><th className="hide-sm">Изменена</th><th /></tr></thead>
            <tbody>{items.map((z) => (
              <tr key={z.id}><td><button type="button" className="link-btn strong-link" onClick={() => open(z.id)}>{z.name}</button>{!z.enabled && <span className="badge outline"> выключена</span>}<span className="sub">{z.purpose || z.description}</span></td>
                <td className="num">{z.priority}</td><td className="num">{z.rules}</td><td className="num">{z.contacts || <span className="warn-text">0</span>}</td><td className="small hide-sm">{fmt(z.updated_at)}</td>
                <td className="nowrap"><Link className="btn mini ghost" to={`/zones/${z.id}`}>Открыть</Link> <button className="btn mini" onClick={() => open(z.id)}><Icon name="edit" size={14} />Изменить</button> <button className="btn mini ghost icon" aria-label={`Удалить ${z.name}`} onClick={() => setDel(z)}><Icon name="trash" size={15} /></button></td></tr>))}</tbody></table>)}</div>)}
      {edit && <ZoneEditor zone={edit === "new" ? null : edit} onClose={() => setEdit(null)} onSaved={(z) => { setEdit(null); load(); show(`Зона «${z.name}» сохранена`); }} />}
      {csv && <CsvImport onClose={() => setCsv(false)} onDone={(msg) => { setCsv(false); load(); show(msg); }} />}
      {del && <ConfirmDialog title={`Удалить зону «${del.name}»?`} body={<>Будут удалены признаки, получатели, закрепления компьютеров и решения по уязвимостям, заданные для всей зоны. Расписания, где была только эта зона, отключатся. Компьютеры не удаляются — они перейдут в другие зоны или в «Без ответственного».</>}
        confirmLabel="Удалить зону" onConfirm={async () => { await api.admin.zones.remove(del.id); load(); show("Зона удалена"); }} onClose={() => setDel(null)} />}
      {toast}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ редактор зоны
function ZoneEditor({ zone, onClose, onSaved }: { zone: ZoneFull | null; onClose: () => void; onSaved: (z: ZoneFull) => void }) {
  const [f, setF] = useState<Omit<ZoneFull, "id">>(() => zone ? { ...zone } : { name: "", description: "", purpose: "", priority: 100, activity_days: null, enabled: true, rules: [], contacts: [] });
  const [bulk, setBulk] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [comp, setComp] = useState<Composition | null>(null); const [cbusy, setCbusy] = useState(false);
  const [testing, setTesting] = useState<string | null>(null); const [note, setNote] = useState("");
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((x) => ({ ...x, [k]: v }));
  const addBulk = () => { const add = parseRules(bulk); if (!add.length) return; const have = new Set(f.rules.map((r) => `${r.kind}|${r.value}`)); set("rules", [...f.rules, ...add.filter((r) => !have.has(`${r.kind}|${r.value}`))]); setBulk(""); setComp(null); };
  const preview = async () => {
    setCbusy(true); setErr(""); setComp(null);
    try { const extra = parseRules(bulk); const rules = [...f.rules, ...extra]; setComp(await api.admin.zones.composition({ zone_id: zone?.id ?? null, name: f.name || "Новая зона", priority: f.priority, rules })); }
    catch (e) { setErr((e as ApiError).message); } finally { setCbusy(false); }
  };
  const save = async () => {
    setBusy(true); setErr("");
    try {
      const body = { ...f, rules: [...f.rules, ...parseRules(bulk)], contacts: f.contacts.filter((c) => c.email.trim()) };
      const z = zone ? await api.admin.zones.update(zone.id, body) : await api.admin.zones.create(body);
      onSaved(z);
    } catch (e) { setErr((e as ApiError).message); setBusy(false); }
  };
  const test = async (c: ZoneContact) => { setTesting(c.email); setNote(""); try { const r = await api.admin.mail.test(c.email); setNote(r.ok ? `Тестовое письмо принято сервером для ${c.email}. ${r.note}` : `Не отправлено: ${r.error}`); } catch (e) { setNote((e as ApiError).message); } finally { setTesting(null); } };
  const setC = (i: number, patch: Partial<ZoneContact>) => set("contacts", f.contacts.map((c, j) => (j === i ? { ...c, ...patch } : c)));
  return (
    <Modal wide title={zone ? `Зона: ${zone.name}` : "Новая зона"} onClose={onClose}
      lede="Зона — группа компьютеров по сетям и группам KSC с назначенными ответственными. Название и смысл выбираете вы."
      footer={<><button className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" onClick={save} disabled={busy || !f.name.trim()} aria-busy={busy}><span>Сохранить</span></button></>}>
      <div className="form">
        <div className="cols"><label>Название<input value={f.name} maxLength={120} onChange={(e) => set("name", e.target.value)} autoFocus placeholder="Департамент А" /></label>
          <label>Назначение<input value={f.purpose} maxLength={300} onChange={(e) => set("purpose", e.target.value)} placeholder="Рабочие станции бухгалтерии" /></label></div>
        <label>Описание<textarea rows={2} value={f.description} maxLength={4000} onChange={(e) => set("description", e.target.value)} /></label>
        <div className="cols">
          <label>Приоритет<input type="number" min={1} max={1000} value={f.priority} onChange={(e) => set("priority", Number(e.target.value) || 100)} /><span className="help">Если компьютер подходит нескольким зонам, побеждает меньшее число. При равных приоритетах компьютер остаётся спорным и виден во всех подходящих зонах.</span></label>
          <label>Своя давность активности, сут<input type="number" min={1} max={3650} value={f.activity_days ?? ""} placeholder="как в общих настройках" onChange={(e) => set("activity_days", e.target.value ? Number(e.target.value) : null)} /><span className="help">Пусто — общий период (по умолчанию 30 суток).</span></label>
        </div>
        <label className="check"><input type="checkbox" className="switch" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />Зона включена <span className="muted small">(выключенная не участвует в сопоставлении и рассылках)</span></label>

        <h3>Признаки принадлежности</h3>
        <p className="muted small">Компьютер входит в зону, если подходит хотя бы одному признаку и не попал в исключение. Основной признак — сети (CIDR, диапазоны, адреса, IPv4 и IPv6); дополнительно — группа KSC и имя (со звёздочкой).</p>
        {f.rules.length > 0 && <div className="table-scroll"><table className="table compact"><thead><tr><th style={{ width: 210 }}>Вид</th><th>Значение</th><th>Заметка</th><th /></tr></thead>
          <tbody>{f.rules.map((r, i) => (
            <tr key={i}><td><select value={r.kind} onChange={(e) => set("rules", f.rules.map((x, j) => (j === i ? { ...x, kind: e.target.value as ZoneRuleKind } : x)))} aria-label="Вид признака">{(Object.keys(KIND) as ZoneRuleKind[]).map((k) => <option key={k} value={k}>{KIND[k]}</option>)}</select></td>
              <td><input className="mono" value={r.value} onChange={(e) => set("rules", f.rules.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} aria-label="Значение" /></td>
              <td><input value={r.note} onChange={(e) => set("rules", f.rules.map((x, j) => (j === i ? { ...x, note: e.target.value } : x)))} aria-label="Заметка" /></td>
              <td><button className="btn mini ghost icon" aria-label="Убрать признак" onClick={() => set("rules", f.rules.filter((_, j) => j !== i))}><Icon name="close" size={14} /></button></td></tr>))}</tbody></table></div>}
        <label>Добавить списком (по одному в строке)<textarea className="rules-ta" rows={4} value={bulk} onChange={(e) => setBulk(e.target.value)} placeholder={EXAMPLE} spellCheck={false} />
          <span className="help">Формы записи: <span className="mono">192.0.2.0/24</span>, <span className="mono">192.0.2.10-192.0.2.50</span>, <span className="mono">192.0.2.5</span>, <span className="mono">2001:db8::/32</span>, <span className="mono">группа: Серверы*</span>, <span className="mono">имя: srv-*</span>, <span className="mono">исключить: 192.0.2.7</span>.</span></label>
        <div className="row"><button type="button" className="btn" onClick={addBulk} disabled={!bulk.trim()}><Icon name="plus" />Добавить в список</button>
          <button type="button" className="btn" onClick={preview} disabled={cbusy || (!f.rules.length && !bulk.trim())} aria-busy={cbusy}><Icon name="eye" />Предварительный просмотр состава</button></div>
        {comp && <CompositionView c={comp} />}

        <h3>Ответственные и получатели отчётов</h3>
        <p className="muted small">Учётные записи KAV Checker не нужны — достаточно адреса. «Ответственные» устраняют проблемы; «копия» получает тот же отчёт (руководитель); «группа рассылки» — общий адрес подразделения.</p>
        {f.contacts.length > 0 && <div className="table-scroll"><table className="table compact"><thead><tr><th>ФИО или название</th><th>Должность</th><th>Электронная почта</th><th>Роль</th><th>Рассылка</th><th /></tr></thead>
          <tbody>{f.contacts.map((c, i) => (
            <tr key={i}><td><input value={c.name} onChange={(e) => setC(i, { name: e.target.value })} aria-label="ФИО" /></td><td><input value={c.position} onChange={(e) => setC(i, { position: e.target.value })} aria-label="Должность" /></td>
              <td><input type="email" value={c.email} onChange={(e) => setC(i, { email: e.target.value })} aria-label="Электронная почта" /></td>
              <td><select value={c.role} onChange={(e) => setC(i, { role: e.target.value as ContactRole })} aria-label="Роль">{(Object.keys(ROLE) as ContactRole[]).map((k) => <option key={k} value={k}>{ROLE[k]}</option>)}</select></td>
              <td><label className="check"><input type="checkbox" className="switch" checked={c.enabled} onChange={(e) => setC(i, { enabled: e.target.checked })} aria-label="Отправлять этому получателю" /></label></td>
              <td className="nowrap"><button className="btn mini" onClick={() => test(c)} disabled={!c.email.includes("@") || testing === c.email}>{testing === c.email ? <span className="spin" /> : "Тест"}</button> <button className="btn mini ghost icon" aria-label="Убрать получателя" onClick={() => set("contacts", f.contacts.filter((_, j) => j !== i))}><Icon name="close" size={14} /></button></td></tr>))}</tbody></table></div>}
        <div className="row"><button type="button" className="btn" onClick={() => set("contacts", [...f.contacts, { name: "", position: "", email: "", role: "responsible", enabled: true }])}><Icon name="plus" />Добавить получателя</button></div>
        {note && <div className="alert info" role="status"><Icon name="info" /><div className="alert-body">{note}</div></div>}
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </div>
    </Modal>
  );
}

function CompositionView({ c }: { c: Composition }) {
  return (
    <div className="card">
      <div className="plan-sum"><div><b>{num(c.total)}</b><span>компьютеров подходит</span></div><div><b>{num(c.active)}</b><span>активных за период</span></div><div><b>{num(c.online)}</b><span>в сети сейчас</span></div><div><b className={c.shared ? "warn-text" : ""}>{num(c.shared)}</b><span>подходят и другим зонам</span></div></div>
      {c.total === 0 ? <p className="muted small">Ни один компьютер не подходит. Проверьте сети: адрес компьютера берётся из KSC (поле IP-адрес Агента).</p> : (
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Компьютер</th><th>IP</th><th>Группа KSC</th><th>Активность</th><th>Другие зоны</th></tr></thead>
          <tbody>{c.items.map((h, i) => <tr key={i}><td>{h.name}<span className="sub">{h.source}</span></td><td className="mono small">{h.ip}</td><td className="small">{h.group}</td><td className="small">{h.active ? "активен" : <span className="warn-text">давно не подключался</span>}</td>
            <td className="small">{h.also_in.length ? <span className="warn-text">{h.also_in.join(", ")}{h.assigned_here ? "" : " (выбрана другая)"}</span> : "—"}</td></tr>)}</tbody></table></div>)}
      {c.total > c.items.length && <p className="muted small">Показаны первые {c.items.length} из {num(c.total)}.</p>}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ спорные компьютеры
function Conflicts({ zones }: { zones: ZoneBrief[] }) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.admin.zones.conflicts>> | null>(null); const [err, setErr] = useState("");
  const [toast, show] = useToast();
  const load = useCallback(() => { api.admin.zones.conflicts().then(setData).catch((e) => setErr((e as ApiError).message)); }, []);
  useEffect(load, [load]);
  const pin = async (c: Conflict, zoneId: string) => { try { await api.admin.zones.pin({ source_id: c.source_id, host_id: c.host_id, host_name: c.name, zone_id: zoneId }); show(`${c.name}: закреплён`); load(); } catch (e) { setErr((e as ApiError).message); } };
  const unpin = async (c: Conflict) => { try { await api.admin.zones.unpin(c.source_id, c.host_id); load(); } catch (e) { setErr((e as ApiError).message); } };
  void zones;
  return (<>
    <p className="muted small">Компьютеры, которые подходят нескольким зонам. <b>Спорные</b> — приоритеты равны: компьютер показан во всех подходящих зонах и учитывается в итогах один раз. Решить спор можно приоритетом зоны, изменением сетей или закреплением компьютера за зоной.</p>
    {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    <div className="table-scroll">{!data ? <SkelRows cols={5} /> : !data.items.length ? <Empty icon="checkCircle" title="Пересечений нет">Каждый компьютер подходит не больше чем одной зоне.</Empty> : (
      <table className="table compact"><thead><tr><th>Компьютер</th><th>IP</th><th>Подходящие зоны</th><th>Как решено</th><th>Закрепить за</th></tr></thead>
        <tbody>{data.items.map((c) => (
          <tr key={`${c.source_id}:${c.host_id}`}><td>{c.name}<span className="sub">{c.source}</span></td><td className="mono small">{c.ip}</td>
            <td>{c.zones.map((z) => <span key={z.id} className={`zone-chip ${z.chosen ? "" : "warn"}`}>{z.name}</span>)} </td>
            <td className="small">{c.via === "pin" ? <span className="ok-text">закреплён вручную</span> : c.via === "priority" ? "решено приоритетом" : <span className="warn-text">спорный: показан во всех</span>}</td>
            <td className="nowrap">{c.zones.map((z) => <button key={z.id} className="btn mini" onClick={() => pin(c, z.id)} disabled={c.via === "pin" && z.chosen}>{z.name}</button>)} {c.via === "pin" && <button className="btn mini ghost" onClick={() => unpin(c)}>Снять</button>}</td></tr>))}</tbody></table>)}</div>
    {data && data.total > data.items.length && <p className="muted small">Показаны первые {data.items.length} из {num(data.total)}.</p>}
    {toast}
  </>);
}

// ------------------------------------------------------------------------------------------------ импорт CSV
const MODES: [string, string, string][] = [
  ["add_update", "Добавить новые и обновить существующие", "Существующие признаки и получатели не удаляются, даже если их нет в файле."],
  ["add_only", "Только добавить новые", "Зоны, которые уже есть, не изменяются."],
  ["replace", "Полная замена (опасно)", "Зоны из файла приводятся точно к файлу, а зоны, которых в файле нет, удаляются."],
];
const SUM_LABEL: [string, string][] = [["zones_create", "зон создаётся"], ["zones_update", "зон обновляется"], ["zones_unchanged", "без изменений"], ["rules_add", "признаков добавляется"], ["contacts_add", "получателей добавляется"], ["contacts_update", "получателей обновляется"]];

function CsvImport({ onClose, onDone }: { onClose: () => void; onDone: (msg: string) => void }) {
  const [file, setFile] = useState<{ name: string; data: ArrayBuffer } | null>(null);
  const [mode, setMode] = useState("add_update"); const [plan, setPlan] = useState<CsvPlan | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [over, setOver] = useState(false);
  const [confirm, setConfirm] = useState(false); const [word, setWord] = useState("");
  const [result, setResult] = useState<{ done: Record<string, number> } | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const check = useCallback(async (data: ArrayBuffer, m: string) => {
    setBusy(true); setErr(""); setPlan(null); setConfirm(false); setWord("");
    try { setPlan(await api.admin.zones.csvPreview(data, m)); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  }, []);
  const take = async (f: File | undefined) => { if (!f) return; const data = await f.arrayBuffer(); setFile({ name: f.name, data }); void check(data, mode); };
  useEffect(() => { if (file) void check(file.data, mode); }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps
  const apply = async () => {
    if (!file || !plan) return; setBusy(true); setErr("");
    try { const r = await api.admin.zones.csvApply(file.data, mode, plan.fingerprint, confirm); setResult(r); }
    catch (e) { const a = e as ApiError & { detail?: { errors?: { line: number; message: string }[] } }; setErr(a.message + (a.detail?.errors ? ": " + a.detail.errors.slice(0, 3).map((x) => `строка ${x.line} — ${x.message}`).join("; ") : "")); }
    finally { setBusy(false); }
  };
  const s = plan?.summary ?? {};
  const danger = mode === "replace";
  const canApply = !!plan && plan.ok !== false && !plan.errors.length && !busy && (!danger || (confirm && word.trim().toLowerCase() === "заменить"));
  if (result) {
    const d = result.done;
    return <Modal title="Импорт завершён" onClose={() => onDone(`Импорт: создано зон ${d.created}, обновлено ${d.updated}${d.deleted ? `, удалено ${d.deleted}` : ""}`)} guard={false}
      footer={<button className="btn primary" onClick={() => onDone(`Импорт: создано зон ${d.created}, обновлено ${d.updated}`)}>Готово</button>}>
      <div className="plan-sum"><div><b>{d.created}</b><span>зон создано</span></div><div><b>{d.updated}</b><span>зон обновлено</span></div><div><b>{d.rules_added}</b><span>признаков добавлено</span></div><div><b>{d.contacts_added}</b><span>получателей добавлено</span></div>
        <div><b>{d.contacts_updated}</b><span>получателей обновлено</span></div>{(d.deleted > 0 || d.rules_removed > 0) && <div><b>{d.deleted}</b><span>зон удалено</span></div>}</div>
      <p className="muted small">Зоны сразу доступны для сопоставления компьютеров и настройки рассылок.</p>
    </Modal>;
  }
  return (
    <Modal wide title="Импорт зон из CSV" onClose={onClose} guard={false}
      lede="Скачайте пример, заполните его в Excel (по одной сети или одному получателю в строке), загрузите и проверьте результат перед применением."
      footer={<><button className="btn ghost" onClick={onClose}>Отмена</button><button className={`btn ${danger ? "danger" : "primary"}`} onClick={apply} disabled={!canApply} aria-busy={busy}><span>{danger ? "Заменить" : "Применить"}</span></button></>}>
      <div className="form">
        <div className="row"><a className="btn" href={api.admin.zones.csvUrl("sample")}><Icon name="download" />Скачать пример CSV</a><a className="btn ghost" href={api.admin.zones.csvUrl("export")}>Выгрузить текущие зоны</a><span className="muted small">UTF-8 с BOM, разделитель «;» (Excel), также поддерживаются «,», табуляция и Windows-1251.</span></div>
        <div className={`csv-drop ${over ? "over" : ""}`} onClick={() => input.current?.click()} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={(e) => { e.preventDefault(); setOver(false); void take(e.dataTransfer.files[0]); }}
          role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.current?.click(); } }}>
          <input ref={input} type="file" accept=".csv,text/csv,text/plain" onChange={(e) => void take(e.target.files?.[0])} />
          <Icon name="upload" size={22} /><div><b>{file ? file.name : "Выберите файл или перетащите сюда"}</b></div><div className="muted small">{file ? `${(file.data.byteLength / 1024).toFixed(1)} КБ` : "до 5 МБ, до 20 000 строк"}</div>
        </div>
        <fieldset className="qr-sections"><legend>Режим</legend>{MODES.map(([k, t, h]) => <label key={k} className="check"><input type="radio" name="csv-mode" checked={mode === k} onChange={() => setMode(k)} /><span className="check-body">{t}<span className="help">{h}</span></span></label>)}</fieldset>
        {busy && !plan && <div className="qr-loading" role="status"><span className="spin accent" />Проверяем файл…</div>}
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        {plan && (<>
          <div className="plan-sum">{SUM_LABEL.filter(([k]) => Number(s[k]) > 0 || ["zones_create", "zones_update", "rules_add", "contacts_add"].includes(k)).map(([k, l]) => <div key={k}><b>{num(Number(s[k]))}</b><span>{l}</span></div>)}
            {Number(s.zones_delete) > 0 && <div><b className="bad-text">{num(Number(s.zones_delete))}</b><span>зон будет удалено</span></div>}{Number(s.rules_remove) > 0 && <div><b className="bad-text">{num(Number(s.rules_remove))}</b><span>признаков удалится</span></div>}
            {Number(s.contacts_remove) > 0 && <div><b className="bad-text">{num(Number(s.contacts_remove))}</b><span>получателей удалится</span></div>}</div>
          <p className="muted small">Строк в файле: {num(Number(s.rows))}; кодировка {String(s.encoding)}, разделитель «{String(s.delimiter)}».</p>
          {plan.errors.length > 0 && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body"><b>Ошибок: {plan.errors.length}. Изменения не будут применены, пока файл не исправлен.</b>
            <ul className="err-list">{plan.errors.slice(0, 30).map((e, i) => <li key={i}>{e.line ? <>строка <b>{e.line}</b>{e.column ? ` (${e.column})` : ""}: </> : null}{e.message}</li>)}</ul>{plan.errors.length > 30 && <p>…и ещё {plan.errors.length - 30}</p>}</div></div>}
          {plan.warnings.length > 0 && <details className="disclosure"><summary>Замечаний: {plan.warnings.length}</summary><ul className="err-list">{plan.warnings.slice(0, 40).map((e, i) => <li key={i}>{e.line ? <>строка {e.line}: </> : null}{e.message}</li>)}</ul></details>}
          {plan.overlaps.length > 0 && <div className="alert warn"><Icon name="alert" /><div className="alert-body"><b>Пересечения сетей между зонами: {plan.overlaps.length}.</b> Компьютеры из пересечения будут видны в обеих зонах, пока не заданы приоритеты или закрепления.
            <ul className="err-list">{plan.overlaps.slice(0, 8).map((o, i) => <li key={i}>«{o.a}» и «{o.b}»: {o.example} {o.resolved ? "(решается приоритетом)" : "(спорные: равные приоритеты)"}</li>)}</ul></div></div>}
          <h3>Что изменится</h3>
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Зона</th><th>Действие</th><th>Подробности</th></tr></thead>
            <tbody>{plan.zones.map((z, i) => (
              <tr key={i}><td>{z.name}</td><td><span className={`badge ${z.action === "create" ? "ok" : z.action === "delete" ? "err" : z.action === "update" ? "accent" : "outline"}`}>{({ create: "создать", update: "обновить", unchanged: "без изменений", skip: "пропустить (уже есть)", delete: "удалить" } as Record<string, string>)[z.action]}</span></td>
                <td className="small">{[...z.fields, ...z.rules_add.map((r) => `+ ${r}`), ...z.rules_remove.map((r) => `− ${r}`), ...z.contacts_add.map((r) => `+ ${r}`), ...z.contacts_update.map((r) => `~ ${r}`), ...z.contacts_remove.map((r) => `− ${r}`)].slice(0, 8).join("; ") || "—"}
                  {[...z.fields, ...z.rules_add, ...z.rules_remove, ...z.contacts_add, ...z.contacts_update, ...z.contacts_remove].length > 8 && <span className="muted"> …и ещё {[...z.fields, ...z.rules_add, ...z.rules_remove, ...z.contacts_add, ...z.contacts_update, ...z.contacts_remove].length - 8}</span>}</td></tr>))}</tbody></table></div>
          {danger && <div className="alert warn"><Icon name="alert" /><div className="alert-body"><label className="check"><input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />Я просмотрел все изменения: зоны, которых нет в файле, и их признаки будут удалены</label>
            <label>Для подтверждения введите «заменить»<input value={word} onChange={(e) => setWord(e.target.value)} autoComplete="off" /></label></div></div>}
          {plan.errors.length === 0 && <p className="muted small">{plural(plan.zones.length, "зона", "зоны", "зон")} в плане. Применение выполняется одной транзакцией: при сбое не изменится ничего.</p>}
        </>)}
      </div>
    </Modal>
  );
}
