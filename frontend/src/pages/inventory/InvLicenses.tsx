/** Лицензии ПО: реестр (куплено, назначено, установлено по KSC, сроки, расхождения), карточка с назначениями, фактическими установками и ключом активации (отдельное право, запись в журнал). */
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Modal } from "../../components/Dialogs";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { BackLink, Empty, Segmented, SkelRows, TagInput } from "../../components/ui";
import { fmt, fmtDate, num } from "../../util";
import { AssetSearch, Kv, PersonPicker, RefSelect, useInv } from "./InvBits";
import { useInvReport } from "./InvReport";
import { inv, type Install, type License, type LicenseCard } from "./invApi";

type St = "" | "soon" | "expired" | "issues" | "inactive";

export default function InvLicenses({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { can } = useInv(); const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const state = (sp.get("state") ?? "") as St;
  const [q, setQ] = useState(""); const [aq, setAq] = useState("");
  useEffect(() => { const t = window.setTimeout(() => setAq(q), 300); return () => window.clearTimeout(t); }, [q]);
  const [d, setD] = useState<{ items: License[]; usage_at: string | null; usage_requested: boolean } | null>(null); const [err, setErr] = useState("");
  const [form, setForm] = useState(false);
  const [toast, show] = useToast();
  const rep = useInvReport();
  const load = useCallback(() => inv.licenses({ q: aq, state }).then(setD).catch((e) => setErr((e as ApiError).message)), [aq, state]);
  useEffect(() => { void load(); }, [load]);
  const recount = async () => { try { await inv.recount(); show("Пересчёт поставлен в очередь: результат — в течение минуты"); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Лицензии</h1>{can("create") && <button className="btn primary" onClick={() => setForm(true)}><Icon name="plus" size={16} />Добавить</button>}</div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Продукт или производитель", label: "Поиск лицензий" }}
        primary={<Segmented<St> label="Отбор" value={state} onChange={(v) => setSp((p) => { if (v) p.set("state", v); else p.delete("state"); return p; }, { replace: true })}
          options={[["", "Действующие"], ["issues", "С расхождениями"], ["soon", "Истекают"], ["expired", "Истекли"], ["inactive", "Архив"]]} />}
        count={{ n: d ? d.items.length : null, noun: ["лицензия", "лицензии", "лицензий"] }}
        extra={can("edit") && <button className="btn ghost mini" onClick={() => void recount()} title={d?.usage_at ? `Последний подсчёт: ${fmt(d.usage_at)}` : "Подсчёт ещё не выполнялся"}><Icon name="refresh" size={15} />Пересчитать установки</button>}
        report={{ onClick: () => rep.open(["licenses", "license_usage"], {}, "Лицензии"), title: "Отчёт по лицензиям" }} />
      {err && <p className="field-err">{err}</p>}
      {!d ? <div className="card"><SkelRows rows={4} cols={6} /></div> : !d.items.length ? <div className="card"><Empty icon="key" title="Лицензий нет">Добавьте купленные лицензии: количество, срок, маски названия программы — установки посчитаются по данным KSC.</Empty></div> :
        <div className="table-scroll"><table className="table"><thead><tr><th>Продукт</th><th className="num">Куплено</th><th className="num">Назначено</th><th className="num">Установлено</th><th>Срок</th><th>Расхождения</th></tr></thead><tbody>
          {d.items.map((l) => <tr key={l.id} onClick={() => nav(`/inventory/licenses/${l.id}`)} className="clickable">
            <td><Link to={`/inventory/licenses/${l.id}`}>{l.name}</Link><span className="sub">{[l.vendor, l.version, l.edition, l.type].filter(Boolean).join(" · ")}</span></td>
            <td className="num">{l.qty === null ? "∞" : num(l.qty)}</td><td className="num">{num(l.assigned)}</td><td className="num" title={l.usage_at ? `подсчёт ${fmt(l.usage_at)}` : "не подсчитано"}>{num(l.installs)}</td>
            <td className="nowrap small">{l.valid_until ? fmtDate(l.valid_until) : "бессрочно"}</td>
            <td className="small">{l.issues.length ? <span className="warn-text">{l.issues.join("; ")}</span> : <span className="muted">нет</span>}</td></tr>)}</tbody></table></div>}
      {form && <LicForm onClose={() => setForm(false)} onSaved={(id) => nav(`/inventory/licenses/${id}`)} />}
      {rep.node}{toast}
    </div>
  );
}

function LicForm({ init, onClose, onSaved }: { init?: LicenseCard; onClose: () => void; onSaved: (id: number) => void }) {
  const { meta } = useInv();
  const [f, setF] = useState<Record<string, unknown>>(() => init ? { ...init, cost: init.cost !== null ? (init.cost / 100).toFixed(2).replace(".", ",") : "", drop_key: false } : { name: "", metric: "device", match: [], active: true });
  const [names, setNames] = useState({ resp: init?.resp ?? "" }); const [err, setErr] = useState("");
  const set = (k: string, v: unknown) => setF((x) => ({ ...x, [k]: v }));
  const save = async () => {
    const body = { name: f.name, vendor: f.vendor ?? "", version: f.version ?? "", edition: f.edition ?? "", type_id: f.type_id ?? null, category_id: f.category_id ?? null, metric: f.metric, qty: f.qty === "" || f.qty === undefined || f.qty === null ? null : Number(f.qty),
      match: f.match, purchase_date: f.purchase_date || null, valid_until: f.valid_until || null, supplier_id: f.supplier_id ?? null, cost: f.cost || null, purchase_doc: f.purchase_doc ?? "", resp_id: f.resp_id ?? null, note: f.note ?? "",
      active: f.active ?? true, key_ref: f.key_ref ?? "", ...(f.drop_key ? { key: "" } : {}) };
    try { if (init) { await inv.editLicense(init.id, body); onSaved(init.id); } else onSaved((await inv.addLicense(body)).id); } catch (e) { setErr((e as ApiError).message); }
  };
  const t = (k: string, lb: string, ph = "") => <label className="field">{lb}<input value={String(f[k] ?? "")} onChange={(e) => set(k, e.target.value)} placeholder={ph} /></label>;
  return (
    <Modal side wide title={init ? "Лицензия" : "Новая лицензия"} onClose={onClose} footer={<><button className="btn" onClick={onClose}>Отмена</button><div className="spacer" /><button className="btn primary" disabled={!String(f.name ?? "").trim()} onClick={() => void save()}>Сохранить</button></>}>
      <form className="form-stack" onSubmit={(e) => { e.preventDefault(); void save(); }}>
        {t("name", "Продукт", "например, «Офисный пакет»")}
        <div className="inv-grid">{t("vendor", "Производитель")}{t("version", "Версия")}{t("edition", "Редакция")}
          <RefSelect kind="license_type" label="Тип лицензии" value={f.type_id as number | null} onChange={(v) => set("type_id", v)} />
          <RefSelect kind="sw_category" label="Категория" value={f.category_id as number | null} onChange={(v) => set("category_id", v)} />
          <label className="field">Учёт<select value={String(f.metric)} onChange={(e) => set("metric", e.target.value)}>{Object.entries(meta.metrics).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          <label className="field">Куплено, шт.<input type="number" min={0} value={String(f.qty ?? "")} onChange={(e) => set("qty", e.target.value)} placeholder="без ограничения" /></label>
          <label className="field">Дата приобретения<input type="date" value={String(f.purchase_date ?? "")} onChange={(e) => set("purchase_date", e.target.value)} /></label>
          <label className="field">Действует до<input type="date" value={String(f.valid_until ?? "")} onChange={(e) => set("valid_until", e.target.value)} /></label>
          <RefSelect kind="supplier" label="Поставщик" value={f.supplier_id as number | null} onChange={(v) => set("supplier_id", v)} />
          {t("cost", "Стоимость, ₽", "0,00")}{t("purchase_doc", "Документ приобретения")}
          <PersonPicker label="Ответственный" value={f.resp_id as number | null} name={names.resp} onChange={(id, nm) => { set("resp_id", id); setNames({ resp: nm }); }} /></div>
        <TagInput label="Маски названия программы (KSC)" value={f.match as string[]} onChange={(v) => set("match", v)} placeholder="Офисный пакет* — Enter" mono={false} />
        <p className="muted small">По маскам считаются компьютеры, где программа установлена (по данным KSC, активные за период из общих настроек). «*» — любое число символов.</p>
        <label className="field">Где хранится ключ активации<input value={String(f.key_ref ?? "")} onChange={(e) => set("key_ref", e.target.value)} maxLength={500} placeholder="ссылка на запись в парольном менеджере или путь к ней" />
          <span className="muted small">Сам ключ здесь не хранится — только ссылка на запись, где он лежит.</span></label>
        {init?.key_set && <label className="check-row"><input type="checkbox" checked={!!f.drop_key} onChange={(e) => set("drop_key", e.target.checked)} />Удалить ключ, сохранённый прежней версией (сначала перенесите его в парольный менеджер)</label>}
        <label className="field">Примечание<textarea rows={2} value={String(f.note ?? "")} onChange={(e) => set("note", e.target.value)} /></label>
        {init && <label className="check-row"><input type="checkbox" checked={!!f.active} onChange={(e) => set("active", e.target.checked)} />Действующая (снятые — в архиве)</label>}
        {err && <p className="field-err">{err}</p>}
      </form>
    </Modal>
  );
}

export function LicensePage() {
  const { id } = useParams(); const lid = Number(id);
  const { can } = useInv();
  const [l, setL] = useState<LicenseCard | null>(null); const [err, setErr] = useState(""); const [edit, setEdit] = useState(false);
  const [inst, setInst] = useState<{ items: Install[]; errors: string[]; note?: string } | null>(null); const [instBusy, setInstBusy] = useState(false);
  const [key, setKey] = useState(""); const [pname, setPname] = useState("");
  const [toast, show] = useToast();
  const load = useCallback(() => inv.license(lid).then(setL).catch((e) => setErr((e as ApiError).message)), [lid]);
  useEffect(() => { void load(); }, [load]);
  if (err) return <div className="card"><Empty icon="key" title="Лицензия не найдена">{err}</Empty></div>;
  if (!l) return <div className="card"><SkelRows rows={6} cols={3} /></div>;
  const assignAsset = async (aid: number) => { try { await inv.assign(l.id, [aid], []); void load(); } catch (e) { show((e as ApiError).message, "error"); } };
  const assignPerson = async (pid: number | null) => { if (!pid) return; try { await inv.assign(l.id, [], [pid]); setPname(""); void load(); } catch (e) { show((e as ApiError).message, "error"); } };
  const loadInst = async () => { setInstBusy(true); try { setInst(await inv.installs(l.id)); } catch (e) { show((e as ApiError).message, "error"); } finally { setInstBusy(false); } };
  const missing = inst?.items.filter((i) => !i.assigned && i.asset_id) ?? [];
  return (
    <div className="inv-page">
      <BackLink to="/inventory/licenses" label="Лицензии" />
      <div className="inv-card-head"><div className="inv-card-title"><h1>{l.name}</h1><div className="row tight wrap"><span className="muted small">{[l.vendor, l.version, l.edition, l.type, l.metric_ru].filter(Boolean).join(" · ")}</span>{!l.active && <span className="badge">архив</span>}</div></div>
        <div className="row wrap inv-card-actions">{can("edit") && <button className="btn" onClick={() => setEdit(true)}><Icon name="edit" size={16} />Изменить</button>}</div></div>
      <div className="meters">
        <div className="meter"><span className="l">Куплено</span><span className="v">{l.qty === null ? "∞" : num(l.qty)}</span><span className="t">{l.valid_until ? `до ${fmtDate(l.valid_until)}` : "бессрочно"}</span></div>
        <div className="meter"><span className="l">Назначено</span><span className="v">{num(l.assigned)}</span><span className="t">{l.free !== null ? `свободно ${l.free}` : ""}</span></div>
        <div className="meter"><span className="l">Установлено (KSC)</span><span className={`v ${l.qty !== null && (l.installs ?? 0) > l.qty ? "bad-text" : ""}`}>{num(l.installs)}</span><span className="t">{l.usage_at ? `подсчёт ${fmt(l.usage_at)}` : "ещё не подсчитано"}</span></div>
      </div>
      {l.issues.length > 0 && <div className="alert flat warn"><Icon name="alert" /><div className="alert-body"><b>Расхождения</b><ul className="reasons">{l.issues.map((i) => <li key={i}>{i}</li>)}</ul></div></div>}
      {l.usage_errors.length > 0 && <details className="disclosure small"><summary>Подсчёт не по всем источникам: {l.usage_errors.map((e) => e.split(":")[0]).join(", ")}</summary><ul className="reasons muted">{l.usage_errors.map((e) => <li key={e}>{e}</li>)}</ul></details>}
      <div className="split even">
        <div className="card"><h2>Сведения</h2>
          <Kv rows={[["Поставщик", l.supplier], ["Дата приобретения", l.purchase_date && fmtDate(l.purchase_date)], ["Стоимость", l.cost_text && `${l.cost_text} ₽`], ["Документ", l.purchase_doc], ["Ответственный", l.resp],
            ["Маски программ", l.match.length ? <span className="mono small">{l.match.join("; ")}</span> : <span className="muted">не заданы — установки не считаются</span>],
            ["Ключ активации", l.key_ref ? (/^https?:\/\//i.test(l.key_ref) ? <a href={l.key_ref} target="_blank" rel="noopener noreferrer" className="inv-keyref"><Icon name="vault" size={14} />{l.key_ref}</a> : <span className="inv-keyref"><Icon name="vault" size={14} />{l.key_ref}</span>) : <span className="muted">не указано, где хранится</span>],
            ["Примечание", l.note]]} />
          {l.key_set && <div className="alert flat warn"><Icon name="alert" /><div className="alert-body">Сохранён ключ прежней версии. Перенесите его в парольный менеджер, укажите ссылку на запись и удалите ключ отсюда (Изменить → «Удалить ключ»).
            <div className="row mt-sm">{key ? <code className="inv-key">{key}</code> : l.can_key ? <button className="btn mini" onClick={() => inv.licKey(l.id).then((r) => setKey(r.key)).catch((e) => show((e as ApiError).message, "error"))}><Icon name="eye" size={14} />Показать ключ</button>
            : <span className="muted small">Ключ сохранён; просмотр — по праву «просмотр ключей лицензий».</span>}{key && <span className="muted small">открытие ключа записано в журнал действий</span>}</div></div></div>}
        </div>
        <div className="card"><h2>Назначения ({l.assignments.length})</h2>
          {l.assignments.length ? <ul className="inv-list">{l.assignments.map((a) => <li key={a.id}>{a.asset_id ? <Link to={`/inventory/assets/${a.asset_id}`}>{a.asset}</Link> : <Link to={`/inventory/people/${a.person_id}`}>{a.person}</Link>}
            <span className="muted small">{fmtDate(a.at)} · {a.by}</span>{can("edit") && <button className="btn mini ghost icon" aria-label="Снять назначение" onClick={() => void inv.unassign(l.id, a.id).then(load)}><Icon name="close" size={14} /></button>}</li>)}</ul>
            : <p className="muted small">Лицензия никому не назначена.</p>}
          {can("edit") && <div className="form-stack mt-sm"><AssetSearch onPick={(a) => void assignAsset(a.id)} exclude={l.assignments.map((a) => a.asset_id ?? 0)} placeholder="Назначить оборудованию: номер или имя" />
            {l.metric === "user" && <PersonPicker label="Назначить сотруднику" value={null} name={pname} onChange={(id, nm) => { setPname(nm); void assignPerson(id); }} />}</div>}
        </div>
      </div>
      <div className="card flush mt"><div className="card-head"><h2>Где установлено (KSC)</h2><div className="spacer" /><button className="btn mini" disabled={instBusy || !l.match.length} onClick={() => void loadInst()}>{instBusy ? <span className="spin" /> : <Icon name="refresh" size={14} />}Показать компьютеры</button>
        {missing.length > 0 && can("edit") && <button className="btn mini primary" onClick={() => void inv.assign(l.id, missing.map((i) => i.asset_id!), []).then(() => { show(`Назначено: ${missing.length}`); void load(); void loadInst(); })}>Назначить всем учтённым ({missing.length})</button>}</div>
        {!inst ? <p className="muted small pad">Запрос к KSC по маскам лицензии — по нажатию кнопки.</p> : <>
          {inst.errors.length > 0 && <p className="field-err pad">{inst.errors.join("; ")}</p>}
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Компьютер</th><th>Программа</th><th className="hide-sm">Источник</th><th>Карточка</th><th>Назначение</th></tr></thead><tbody>
            {inst.items.map((i) => <tr key={`${i.source_id}:${i.host_id}`}><td>{i.name}</td><td className="small">{i.product}<span className="sub mono">{i.version}</span></td><td className="hide-sm small">{i.source}</td>
              <td>{i.asset_id ? <Link to={`/inventory/assets/${i.asset_id}`} className="mono">{i.inv_no}</Link> : <span className="muted small">нет карточки</span>}</td>
              <td>{i.assigned ? <span className="badge ok">назначена</span> : <span className="badge warn">не назначена</span>}</td></tr>)}
            {!inst.items.length && <tr><td colSpan={5} className="muted">Установок не найдено.</td></tr>}</tbody></table></div></>}
      </div>
      {edit && <LicForm init={l} onClose={() => setEdit(false)} onSaved={() => { setEdit(false); void load(); show("Сохранено"); }} />}
      {toast}
    </div>
  );
}
