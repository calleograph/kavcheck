/** Настройки инвентаризации (администратор): права по ролям, личные права и области учёта по учётным записям, нумерация, печатные формы, этикетки, сроки контроля, связь с KSC. */
import { useEffect, useState } from "react";
import { api, type ApiError } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows, Tabs, TagInput } from "../../components/ui";
import { inv } from "./invApi";
import { useInv } from "./InvBits";

type S = Record<string, unknown> & { roles: Record<string, string>; grants: { login: string; perms: string[]; location_ids: number[] }[]; forms: Record<string, { title?: string; intro?: string; columns?: string[]; props?: string[]; signatures?: string[]; footer?: string }>;
  doc_prefix: Record<string, string>; label_fields: string[] };
type T = "access" | "numbers" | "forms" | "labels" | "control" | "notify";
const PERM_RU: Record<string, string> = { view: "Просмотр оборудования", create: "Создание карточек", edit: "Изменение учётных свойств", location: "Изменение местоположения", people: "Изменение владельцев и ответственных",
  docs: "Оформление документов (выдача, возврат, перемещение)", repair: "Оформление ремонтов", writeoff: "Списание", count: "Проведение инвентаризации", import: "Импорт из Excel/CSV", refs: "Управление справочниками и местоположениями",
  keys: "Просмотр ключей лицензий, сохранённых прежними версиями", templates: "Печатные формы и этикетки" };
const ROLE_RU: Record<string, string> = { viewer: "Просмотр", analyst: "Аналитик", security: "Специалист по ИБ", admin: "Администратор" };
const LABEL_FIELDS: Record<string, string> = { name: "Наименование", inv_no: "Инвентарный номер", serial: "Серийный номер", hostname: "Имя компьютера", location: "Местоположение", user: "Пользователь", acc_no: "Бухгалтерский номер" };

export default function InvSettings() {
  const { meta, locs, reload } = useInv();
  const [s, setS] = useState<S | null>(null); const [tab, setTab] = useState<T>("access"); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [formKind, setFormKind] = useState("issue");
  const [toast, show] = useToast();
  useEffect(() => { api.admin.settings("inventory").then((x) => setS(x as unknown as S)).catch((e) => setErr((e as ApiError).message)); }, []);
  if (err) return <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  if (!s) return <div className="card"><SkelRows rows={6} cols={3} /></div>;
  const set = (k: string, v: unknown) => setS({ ...s, [k]: v } as S);
  const save = async () => { setBusy(true); try { const r = await api.admin.saveSettings("inventory", s as never); setS(r as unknown as S); show("Настройки сохранены"); reload(); } catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(false); } };
  const form = s.forms[formKind] ?? {};
  const setForm = (k: string, v: unknown) => set("forms", { ...s.forms, [formKind]: { ...form, [k]: v } });
  const num = (k: string, lb: string, min: number, max: number, hint = "") => <label className="field">{lb}<input type="number" min={min} max={max} value={Number(s[k] ?? 0)} onChange={(e) => set(k, Number(e.target.value))} />{hint && <span className="field-help">{hint}</span>}</label>;
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Настройки инвентаризации</h1><button className="btn primary" disabled={busy} onClick={() => void save()}><Icon name="save" size={16} />Сохранить</button></div>
      <Tabs<T> label="Настройки" value={tab} onChange={setTab} items={[{ id: "access", label: "Права доступа" }, { id: "numbers", label: "Нумерация" }, { id: "forms", label: "Печатные формы" }, { id: "labels", label: "Этикетки" }, { id: "control", label: "Сроки и KSC" }, { id: "notify", label: "Уведомления" }]} />
      {tab === "access" && <div className="stack">
        <div className="card flush"><div className="card-head"><h2>Права по ролям</h2></div>
          <p className="muted small pad">Наименьшая роль KAV Checker, которой разрешено действие. Администратору разрешено всё.</p>
          <div className="table-scroll"><table className="table compact mid"><thead><tr><th>Действие</th><th>Разрешено начиная с роли</th></tr></thead><tbody>
            {Object.entries(PERM_RU).map(([p, lb]) => <tr key={p}><td>{lb}</td><td><select value={s.roles[p] ?? "admin"} onChange={(e) => set("roles", { ...s.roles, [p]: e.target.value })} aria-label={lb}>{Object.entries(ROLE_RU).map(([r, v]) => <option key={r} value={r}>{v}</option>)}</select></td></tr>)}</tbody></table></div></div>
        <div className="card"><div className="card-head"><h2>Учётные записи: дополнительные права и область учёта</h2><div className="spacer" /><button className="btn mini" onClick={() => set("grants", [...s.grants, { login: "", perms: [], location_ids: [] }])}><Icon name="plus" size={14} />Добавить</button></div>
          <p className="muted small">Например, ответственному за учёт в филиале — оформление документов только в его регионе. Если указаны местоположения, пользователь видит и меняет только оборудование в них (с вложенными).</p>
          {s.grants.map((g, i) => <div key={i} className="inv-grant">
            <label className="field">Логин<input value={g.login} onChange={(e) => set("grants", s.grants.map((x, j) => (j === i ? { ...x, login: e.target.value } : x)))} placeholder="логин в KAV Checker" /></label>
            <fieldset className="field"><legend>Дополнительные права</legend><div className="row wrap tight">{Object.entries(PERM_RU).map(([p, lb]) => <label key={p} className="chip-check" title={lb}><input type="checkbox" checked={g.perms.includes(p)} onChange={() => set("grants", s.grants.map((x, j) => (j === i ? { ...x, perms: x.perms.includes(p) ? x.perms.filter((y) => y !== p) : [...x.perms, p] } : x)))} />{lb.split(" (")[0]}</label>)}</div></fieldset>
            <fieldset className="field"><legend>Область учёта (местоположения)</legend><div className="row wrap tight">
              {g.location_ids.map((id) => <span key={id} className="chip">{locs?.find((l) => l.id === id)?.path ?? `#${id}`}<button type="button" aria-label="Убрать" onClick={() => set("grants", s.grants.map((x, j) => (j === i ? { ...x, location_ids: x.location_ids.filter((y) => y !== id) } : x)))}><Icon name="close" size={12} /></button></span>)}
              <select value="" aria-label="Добавить местоположение" onChange={(e) => e.target.value && set("grants", s.grants.map((x, j) => (j === i ? { ...x, location_ids: [...x.location_ids, Number(e.target.value)] } : x)))}><option value="">+ местоположение</option>
                {(locs ?? []).filter((l) => l.path.split(" / ").length <= 3).sort((a, b) => a.path.localeCompare(b.path, "ru")).map((l) => <option key={l.id} value={l.id}>{l.path}</option>)}</select></div></fieldset>
            <button className="btn mini ghost" onClick={() => set("grants", s.grants.filter((_, j) => j !== i))}><Icon name="trash" size={14} />Удалить</button>
          </div>)}
          {!s.grants.length && <p className="muted small">Личных прав нет — действуют права по ролям.</p>}</div>
      </div>}
      {tab === "numbers" && <div className="card"><h2>Инвентарные номера и номера документов</h2><div className="inv-grid">
        <label className="field">Префикс инвентарного номера<input value={String(s.inv_prefix ?? "")} onChange={(e) => set("inv_prefix", e.target.value)} maxLength={20} /></label>
        {num("inv_digits", "Цифр в номере", 3, 12, `пример: ${s.inv_prefix}${"1".padStart(Number(s.inv_digits), "0")}`)}
        {Object.entries(meta.doc_short).map(([k, v]) => <label key={k} className="field">Префикс: {v}<input value={s.doc_prefix[k] ?? ""} onChange={(e) => set("doc_prefix", { ...s.doc_prefix, [k]: e.target.value })} placeholder="встроенный" maxLength={10} /></label>)}
      </div><p className="muted small">Номер можно ввести вручную при создании карточки; уникальность проверяется. Документ получает номер «префикс-год-порядковый».</p></div>}
      {tab === "forms" && <div className="card"><h2>Печатная форма</h2>
        <div className="row wrap"><label className="field">Документ<select value={formKind} onChange={(e) => setFormKind(e.target.value)}>{Object.entries(meta.doc_kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label></div>
        <div className="form-stack">
          <label className="field">Заголовок<input value={form.title ?? ""} onChange={(e) => setForm("title", e.target.value)} placeholder="встроенный" /></label>
          <label className="field">Вводный текст<textarea rows={2} value={form.intro ?? ""} onChange={(e) => setForm("intro", e.target.value)} placeholder="встроенный; подстановки: {to_person}, {from_person}, {from_location}, {to_location}, {no}, {date}" /></label>
          <fieldset className="field"><legend>Столбцы таблицы оборудования (пусто — встроенные)</legend><div className="row wrap tight">{Object.entries(meta.doc_columns).map(([k, v]) => {
            const cur = form.columns ?? []; return <label key={k} className="chip-check"><input type="checkbox" checked={cur.includes(k)} onChange={() => setForm("columns", cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k])} />{v}</label>;
          })}</div></fieldset>
          <fieldset className="field"><legend>Дополнительные свойства в таблице</legend><div className="row wrap tight">{meta.props.filter((p) => p.active).map((p) => {
            const cur = form.props ?? []; return <label key={p.code} className="chip-check"><input type="checkbox" checked={cur.includes(p.code)} onChange={() => setForm("props", cur.includes(p.code) ? cur.filter((x) => x !== p.code) : [...cur, p.code])} />{p.name}</label>;
          })}{!meta.props.length && <span className="muted small">свойств нет</span>}</div></fieldset>
          <label className="field">Подписи (через «;»)<input value={(form.signatures ?? []).join("; ")} onChange={(e) => setForm("signatures", e.target.value.split(";").map((x) => x.trim()).filter(Boolean))} placeholder="встроенные: например, Передал; Принял" /></label>
          <label className="field">Заключительный текст<textarea rows={2} value={form.footer ?? ""} onChange={(e) => setForm("footer", e.target.value)} placeholder="встроенный" /></label>
          <p className="muted small">Шапка — из «Администрирование → Организация и отчёты». Пустое поле — встроенный текст.</p>
        </div></div>}
      {tab === "labels" && <div className="card"><h2>Этикетки</h2><div className="inv-grid">
        <label className="field">Печать<select value={String(s.label_sheet)} onChange={(e) => set("label_sheet", e.target.value)}><option value="label">Принтер этикеток (страница на этикетку)</option><option value="a4">Обычный принтер: лист A4 с сеткой</option></select></label>
        {num("label_w_mm", "Ширина, мм", 20, 150)}{num("label_h_mm", "Высота, мм", 15, 150)}
        {s.label_sheet === "a4" && <>{num("a4_cols", "Столбцов на листе", 1, 6)}{num("a4_rows", "Строк на листе", 1, 16)}</>}
        <label className="field">Код<select value={String(s.label_code)} onChange={(e) => set("label_code", e.target.value)}><option value="qr">QR (ссылка на карточку)</option><option value="code128">Штрихкод Code 128 (инвентарный номер)</option><option value="both">QR и штрихкод</option></select></label>
        <label className="field">Строка организации<input value={String(s.label_title ?? "")} onChange={(e) => set("label_title", e.target.value)} maxLength={80} placeholder="краткое название организации" /></label>
        <fieldset className="field wide"><legend>Поля на этикетке (по порядку)</legend><div className="row wrap tight">{Object.entries(LABEL_FIELDS).map(([k, v]) => <label key={k} className="chip-check"><input type="checkbox" checked={s.label_fields.includes(k)} onChange={() => set("label_fields", s.label_fields.includes(k) ? s.label_fields.filter((x) => x !== k) : [...s.label_fields, k])} />{v}</label>)}</div></fieldset>
      </div><p className="muted small">QR ведёт на карточку по адресу KAV Checker (APP_PUBLIC_URL): камера телефона открывает её сразу. Для принтеров Zebra доступна выгрузка ZPL (кнопка «Этикетки» → формат ZPL в адресе).</p></div>}
      {tab === "control" && <div className="card"><h2>Сроки контроля и связь с KSC</h2><div className="inv-grid">
        {num("warranty_days", "Гарантия «истекает» за, дней", 1, 730)}{num("license_days", "Лицензия «истекает» за, дней", 1, 730)}{num("transit_days", "Перемещение «в пути» дольше, дней", 1, 365)}
        {num("repair_days", "Ремонт «долго» дольше, дней", 1, 730)}{num("stale_days", "Сведения устарели через, дней", 30, 3650)}
        <label className="check-row wide"><input type="checkbox" checked={!!s.ksc_auto_link} onChange={(e) => set("ksc_auto_link", e.target.checked)} />Предлагать связь с компьютером KSC, если имя совпало ровно с одним компьютером (связь «предполагается», подтверждает пользователь)</label>
      </div></div>}
      {tab === "notify" && <Notify s={s} set={set} show={show} />}
      {toast}
    </div>
  );
}

function Notify({ s, set, show }: { s: S; set: (k: string, v: unknown) => void; show: (t: string, tone?: "ok" | "error") => void }) {
  const [pv, setPv] = useState<{ title: string; rows: string[] }[] | null>(null);
  useEffect(() => { inv.notifyPreview().then((r) => setPv(r.sections)).catch(() => setPv([])); }, []);
  const test = async () => { try { const r = await inv.notifyTest(); show(r.sent ? "Сводка отправлена" : r.error || "Не отправлено", r.sent ? "ok" : "error"); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <div className="split">
      <div className="card"><h2>Ежедневная сводка сроков</h2>
        <label className="check-row"><input type="checkbox" checked={!!s.notify_enabled} onChange={(e) => set("notify_enabled", e.target.checked)} />Отправлять раз в день</label>
        <TagInput label="Получатели" value={(s.notify_emails as string[]) ?? []} onChange={(v) => set("notify_emails", v)} placeholder="inventory@example.local — Enter" />
        <div className="inv-grid"><label className="field">Время<input type="time" value={String(s.notify_time ?? "08:00")} onChange={(e) => set("notify_time", e.target.value)} /></label>
          <label className="field">Часовой пояс<input value={String(s.notify_timezone ?? "UTC")} onChange={(e) => set("notify_timezone", e.target.value)} placeholder="Europe/Moscow" /></label></div>
        <label className="check-row"><input type="checkbox" checked={!!s.notify_empty} onChange={(e) => set("notify_empty", e.target.checked)} />Отправлять и тогда, когда сообщать не о чем</label>
        <p className="muted small">Сервер почты — «Администрирование → Рассылки отчётов». Сроки — во вкладке «Сроки и KSC». Сохраните настройки перед проверкой.</p>
        <button className="btn" onClick={() => void test()}><Icon name="mail" size={16} />Отправить сейчас</button></div>
      <div className="card"><h2>Что войдёт в сводку сейчас</h2>
        {!pv ? <SkelRows rows={3} cols={1} /> : !pv.length ? <p className="muted">Истекающих сроков и просроченных операций нет.</p> :
          pv.map((sec) => <div key={sec.title} className="mt-sm"><b>{sec.title}</b><ul className="reasons">{sec.rows.slice(0, 8).map((r) => <li key={r}>{r}</li>)}{sec.rows.length > 8 && <li className="muted">… и ещё {sec.rows.length - 8}</li>}</ul></div>)}
      </div>
    </div>
  );
}
