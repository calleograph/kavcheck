import { AdminReportButton } from "../../components/QuickReport";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiError, type BiImport, type BiOptions, type BiPreview, type BiProfile, type BiSourceInfo, type DiagResult } from "../../api";
import { SecretInput, StageList, secretToSend } from "../../components/Common";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows, TagInput } from "../../components/ui";
import { fmt, fmtDate, num } from "../../util";

interface Form { id?: string; name: string; is_active: boolean; smb_host: string; smb_port: number; smb_share: string; smb_path: string; username: string; password: string; password_set: boolean; smb_encrypt: boolean;
  file_mode: "fixed" | "auto"; file_name: string; schedule_time: string; timezone: string; options: BiOptions; profile: Partial<BiProfile> }
const DEF_OPT: BiOptions = { partial: true, max_reject_pct: 5, drift_pct: 20, max_mb: 50, max_rows: 200000, keep_files: 10, keep_days: 90, retry_minutes: 60, retries: 3, stable_s: 10, full_snapshot: true, owner_drift_pct: 25, auto_exact: false };
const empty = (): Form => ({ name: "", is_active: true, smb_host: "", smb_port: 445, smb_share: "", smb_path: "", username: "", password: "", password_set: false, smb_encrypt: true, file_mode: "fixed", file_name: "computers.xlsx",
  schedule_time: "06:00", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", options: { ...DEF_OPT }, profile: {} });
const ST_CLS: Record<string, string> = { ok: "ok", unchanged: "ok", partial: "warn", rejected: "err", failed: "err", running: "accent", queued: "", waiting: "warn", connecting: "accent", fetching: "accent",
  checking: "accent", importing: "accent", matching: "accent" };
/** Импорт в работе: от постановки в очередь до итога (страница обновляется сама). */
const ACTIVE = ["queued", "waiting", "connecting", "fetching", "checking", "importing", "matching", "running"];
const unc = (s: { smb_host: string; smb_share: string; smb_path: string }) => `\\\\${s.smb_host}\\${s.smb_share}${s.smb_path ? "\\" + s.smb_path.replace(/\//g, "\\") : ""}`;

/** BI-системы — Excel через SMB: подключение только на чтение, расписание, правило выбора файла, сопоставление столбцов, проверки, хранение и журнал импортов. */
export default function BiSourcesAdmin() {
  const [items, setItems] = useState<BiSourceInfo[] | null>(null); const [fields, setFields] = useState<Record<string, string>>({}); const [error, setError] = useState("");
  const [form, setForm] = useState<{ f: Form; storage?: boolean } | null>(null); const [busy, setBusy] = useState(false);
  const [diag, setDiag] = useState<Record<string, DiagResult | "run">>({}); const [struct, setStruct] = useState<BiSourceInfo | null>(null); const [log, setLog] = useState<BiSourceInfo | null>(null);
  const [del, setDel] = useState<BiSourceInfo | null>(null); const [allowed, setAllowed] = useState<string[] | null>(null); const [toast, show] = useToast();
  const upRef = useRef<HTMLInputElement>(null); const [upFor, setUpFor] = useState<string>("");
  const load = useCallback(() => api.bi.sources().then((r) => { setItems(r.items); setFields(r.fields); }).catch((e) => setError((e as ApiError).message)), []);
  useEffect(() => { void load(); api.admin.settings("bi").then((r) => setAllowed((r.allowed_hosts as string[] | undefined) ?? [])).catch(() => setAllowed([])); }, [load]);
  useEffect(() => { if (!items?.some((s) => s.queued || ACTIVE.includes(s.last?.status ?? ""))) return; const t = window.setInterval(() => void load(), 4000); return () => window.clearInterval(t); }, [items, load]);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((x) => (x ? { ...x, f: { ...x.f, [k]: v } } : x));
  const setOpt = <K extends keyof BiOptions>(k: K, v: BiOptions[K]) => setForm((x) => (x ? { ...x, f: { ...x.f, options: { ...x.f.options, [k]: v } } } : x));
  const body = (f: Form) => ({ name: f.name.trim(), is_active: f.is_active, smb_host: f.smb_host.trim(), smb_port: f.smb_port, smb_share: f.smb_share.trim(), smb_path: f.smb_path.trim(), username: f.username.trim(), smb_encrypt: f.smb_encrypt,
    file_mode: f.file_mode, file_name: f.file_name.trim(), schedule_time: f.schedule_time, timezone: f.timezone, options: f.options, profile: f.profile, password: secretToSend(f.password) ?? null });
  const save = async () => {
    if (!form) return; setError(""); setBusy(true);
    try { const f = form.f; const r = f.id ? await api.bi.update(f.id, body(f)) : await api.bi.create(body(f)); setForm(null); show(f.id ? "Источник сохранён" : "Источник добавлен: проверьте подключение и структуру файла"); await load(); if (!f.id) void test(r.id); }
    catch (e) { setError((e as ApiError).message); } finally { setBusy(false); }
  };
  const test = async (id: string) => { setDiag((d) => ({ ...d, [id]: "run" })); try { const r = await api.bi.test(id); setDiag((d) => ({ ...d, [id]: r })); } catch (e) { setDiag((d) => ({ ...d, [id]: { ok: false, stages: [{ stage: "error", ok: false, message: (e as ApiError).message, ms: 0 }] } })); } };
  const run = async (s: BiSourceInfo, force = false) => { try { await api.bi.run(s.id, force); show("Импорт поставлен в очередь: worker начнёт в течение минуты"); await load(); } catch (e) { show((e as ApiError).message, "error"); } };
  const upload = async (file: File) => { try { await api.bi.upload(upFor, file); show(`Файл «${file.name}» загружен: импорт выполнит worker`); await load(); } catch (e) { show((e as ApiError).message, "error"); } };
  const edit = (s: BiSourceInfo, storage = false) => { setError(""); setForm({ f: { ...empty(), ...s, password: "", options: { ...DEF_OPT, ...s.options } }, storage }); };
  const saveAllowed = async (v: string[]) => { setAllowed(v); try { await api.admin.saveSettings("bi", { allowed_hosts: v }); show("Список разрешённых серверов сохранён"); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <>
      <div className="row mb wrap">
        <span className="muted small">Регулярная Excel-выгрузка «сотрудник × устройство» из корпоративной BI-системы. Доступ к SMB — только чтение; исходный файл не изменяется, не удаляется и не переименовывается. Пароль хранится зашифрованным.</span>
        <div className="spacer" /><button className="btn primary" onClick={() => { setForm({ f: empty() }); setError(""); }}><Icon name="plus" />Добавить BI-источник</button>
      </div>
      <details className="disclosure mb"><summary>Разрешённые SMB-серверы{allowed?.length ? <span className="badge accent">{allowed.length}</span> : <span className="muted small"> · любые, кроме петлевых и link-local</span>}</summary>
        {allowed && <div className="adv"><TagInput label="Разрешённые SMB-серверы" value={allowed} onChange={(v) => void saveAllowed(v)} placeholder="files.example.local, *.example.local, 192.0.2.0/24" />
          <span className="help">Имя (маска со звёздочкой) или сеть CIDR. Пусто — подключение к любому серверу, кроме петлевых и link-local адресов.</span></div>}
      </details>
      <input ref={upRef} type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) void upload(f); }} />
      {error && !form && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{error}</div></div>}
      {!items && <div className="card"><SkelRows rows={3} cols={3} /></div>}
      {items && !items.length && <div className="card"><Empty icon="database" title="BI-источников пока нет" action={<button className="btn primary" onClick={() => setForm({ f: empty() })}><Icon name="plus" />Добавить BI-источник</button>}>
        Укажите SMB-папку с выгрузкой и учётную запись только для чтения, затем проверьте подключение и сопоставьте столбцы файла.</Empty></div>}
      {items?.map((s) => { const d = diag[s.id]; const r = d && d !== "run" ? d : null; const pub = s.published; const last = s.last; const stale = last && pub && last.id !== pub.id && ["failed", "rejected"].includes(last.status); return (
        <div key={s.id} className="card src-card">
          <div className="card-head">
            <span className={`dot ${s.last_error ? "bad" : s.last_ok_at ? "ok" : "off"}`} aria-hidden />
            <h2>{s.name}</h2>
            <span className="badge outline">Excel через SMB</span>
            {!s.is_active && <span className="badge warn">выключен</span>}{s.queued && <span className="badge accent">в очереди</span>}
            <div className="spacer" />
            <button className="btn mini" aria-busy={d === "run"} onClick={() => void test(s.id)}><Icon name="plug" size={15} /><span>Проверить подключение</span></button>
            <button className="btn mini ghost icon" aria-label={`Изменить ${s.name}`} onClick={() => edit(s)}><Icon name="edit" size={15} /></button>
            <button className="btn mini ghost danger icon" aria-label={`Удалить ${s.name}`} onClick={() => setDel(s)}><Icon name="trash" size={15} /></button>
          </div>
          <div className="addr">{s.username || "без учётной записи"} → {unc(s)}</div>
          <div className="muted small">{s.file_mode === "fixed" ? `Файл «${s.file_name}»` : `Новейший файл по маске «${s.file_name}»`} · ежедневно в {s.schedule_time} ({s.timezone}) · следующая загрузка {fmt(s.next_run_at)}
            {" "}· {s.smb_encrypt ? "шифрование SMB 3.x обязательно" : "без обязательного шифрования"} · {s.profile?.columns ? `столбцов сопоставлено: ${Object.keys(s.profile.columns).length}` : "сопоставление столбцов не настроено"}</div>
          {stale && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Последнее получение {last!.status === "failed" ? "не удалось" : "отклонено"}: {last!.message}. Показываются сведения последнего успешного снимка от {fmtDate(pub!.snapshot_at)}.</div></div>}
          {last && ACTIVE.includes(last.status) && <div className={`alert ${last.status === "waiting" ? "warn" : "info"}`} role="status"><span className="spin sm" aria-hidden />
            <div className="alert-body"><b>Импорт: {last.status_ru}</b>{last.message ? ` — ${last.message}` : ""}<span className="sub">поставлен в очередь {fmt(last.started_at)}{last.by ? ` · ${last.by}` : ""}</span></div></div>}
          {!pub && last && ["failed", "rejected"].includes(last.status) && <div className="alert warn"><Icon name="alert" /><div className="alert-body">{last.status_ru}: {last.message}</div></div>}
          <dl className="kv pairs bi-state">
            <div><dt>Последнее успешное получение</dt><dd>{fmt(s.last_ok_at)}</dd></div>
            <div><dt>Опубликованный снимок</dt><dd>{pub ? <>{pub.file_name}<span className="sub">файл от {fmt(pub.snapshot_at)} · SHA-256 <span className="mono">{pub.sha256.slice(0, 12)}…</span></span></> : "—"}</dd></div>
            <div><dt>Строк / записей</dt><dd>{pub ? `${num(pub.rows_read)} / ${num(pub.rows_valid)}` : "—"}<span className="sub">{pub ? `сотрудников ${num(pub.persons_n)}, устройств ${num(pub.devices_n)}` : ""}</span></dd></div>
            <div><dt>Изменения последнего импорта</dt><dd>{last ? <><span className={`badge ${ST_CLS[last.status] ?? ""}`}>{last.status_ru}</span>{["ok", "partial"].includes(last.status) && <span className="sub">новых {num(last.rows_new)}, изменено {num(last.rows_changed)}, без изменений {num(last.rows_same)}, исчезло {num(last.rows_gone)}, отклонено {num(last.rows_rejected)}</span>}</> : "импортов ещё не было"}</dd></div>
            <div><dt>Последняя ошибка</dt><dd>{s.last_error ? <span className="warn-text">{s.last_error}</span> : "—"}{s.fail_n > 0 && <span className="sub">неудачных попыток подряд: {s.fail_n}</span>}</dd></div>
          </dl>
          <div className="row wrap tight mt-sm">
            <button className="btn mini" onClick={() => setStruct(s)}><Icon name="grid" size={15} />Проверить структуру файла</button>
            <button className="btn mini" disabled={!s.profile?.columns || s.queued} onClick={() => void run(s)} title={s.profile?.columns ? "Получить файл с SMB сейчас" : "Сначала сопоставьте столбцы"}><Icon name="refresh" size={15} />Запустить импорт</button>
            {last?.status === "rejected" && /подтвержден|совпадает|старше/.test(last.message) && <button className="btn mini ghost" onClick={() => void run(s, true)} title="Принять снимок, отклонённый проверкой объёма, структуры или смены владельцев, или повторить без проверки совпадения">Принять и импортировать</button>}
            <button className="btn mini ghost" disabled={!s.profile?.columns} onClick={() => { setUpFor(s.id); upRef.current?.click(); }}><Icon name="upload" size={15} />Загрузить файл…</button>
            <button className="btn mini ghost" onClick={() => setLog(s)}><Icon name="journal" size={15} />Посмотреть журнал</button>
            <button className="btn mini ghost" onClick={() => edit(s, true)}><Icon name="database" size={15} />Настройки хранения</button>
          </div>
          {r && <StageList result={r} okText="Подключение проверено" />}
        </div>); })}
      {form && <SourceForm form={form.f} storage={!!form.storage} set={set} setOpt={setOpt} busy={busy} error={error} onSave={() => void save()} onClose={() => setForm(null)} />}
      {struct && <StructureDialog src={struct} fields={fields} onClose={() => setStruct(null)} onSaved={() => { setStruct(null); show("Сопоставление столбцов сохранено"); void load(); }} />}
      {log && <ImportLog src={log} onClose={() => setLog(null)} />}
      {del && <ConfirmDialog title={`Удалить BI-источник «${del.name}»?`} confirmLabel="Удалить источник" typed="УДАЛИТЬ" body={<p>Удалятся история импортов, сотрудники, устройства и история принадлежности этого источника, а также сохранённые копии файлов. Файлы на SMB не затрагиваются.</p>}
        onClose={() => setDel(null)} onConfirm={async () => { await api.bi.remove(del.id); await load(); }} />}
      {toast}
    </>
  );
}

function SourceForm({ form: f, storage, set, setOpt, busy, error, onSave, onClose }: { form: Form; storage: boolean; set: <K extends keyof Form>(k: K, v: Form[K]) => void; setOpt: <K extends keyof BiOptions>(k: K, v: BiOptions[K]) => void;
  busy: boolean; error: string; onSave: () => void; onClose: () => void }) {
  const o = f.options;
  const numIn = (k: keyof BiOptions, label: string, min: number, max: number, help?: string) => <label>{label}<input type="number" min={min} max={max} value={Number(o[k])} onChange={(e) => setOpt(k, Number(e.target.value) as never)} />{help && <span className="help">{help}</span>}</label>;
  return (
    <Modal title={f.id ? `BI-источник «${f.name}»` : "Новый BI-источник"} onClose={onClose}
      footer={<><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button type="submit" form="bi-form" className="btn primary" aria-busy={busy}>Сохранить</button></>}>
      <form id="bi-form" onSubmit={(e) => { e.preventDefault(); onSave(); }} noValidate>
        <label>Название<input value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="BI: компьютеры и сотрудники" maxLength={120} required autoFocus={!storage} /><span className="help">Тип источника — «BI-система — Excel через SMB»</span></label>
        <fieldset className="group"><legend>Сетевая папка (SMB)</legend>
          <div className="cols">
            <label>Сервер<input className="mono" value={f.smb_host} onChange={(e) => set("smb_host", e.target.value)} placeholder="files.example.local" spellCheck={false} required /></label>
            <label>Порт<input type="number" min={1} max={65535} value={f.smb_port} onChange={(e) => set("smb_port", Number(e.target.value))} /></label>
          </div>
          <div className="cols">
            <label>Общий ресурс<input className="mono" value={f.smb_share} onChange={(e) => set("smb_share", e.target.value)} placeholder="bi" spellCheck={false} required /></label>
            <label>Папка<input className="mono" value={f.smb_path} onChange={(e) => set("smb_path", e.target.value)} placeholder="exports\daily" spellCheck={false} /><span className="help">Внутри общего ресурса; пусто — корень</span></label>
          </div>
          <label className="check"><input type="checkbox" className="switch" checked={f.smb_encrypt} onChange={(e) => set("smb_encrypt", e.target.checked)} /><span className="check-body">Требовать шифрование SMB 3.x<span className="help">Без шифрования подключение к серверу SMB 2.x возможно, но трафик не защищён</span></span></label>
        </fieldset>
        <fieldset className="group"><legend>Учётная запись только для чтения</legend>
          <label>Пользователь<input className="mono" value={f.username} onChange={(e) => set("username", e.target.value)} placeholder="EXAMPLE\svc-bi-ro" spellCheck={false} autoComplete="off" /></label>
          <SecretInput label="Пароль" isSet={f.password_set} value={f.password} onChange={(v) => set("password", v)} help="Хранится зашифрованным, через API не возвращается и в журналы не попадает." />
        </fieldset>
        <fieldset className="group"><legend>Файл и расписание</legend>
          <div className="cols">
            <label>Выбор файла<select value={f.file_mode} onChange={(e) => { set("file_mode", e.target.value as Form["file_mode"]); if (e.target.value === "auto" && !f.file_name.includes("*")) set("file_name", "*.xlsx"); }}>
              <option value="fixed">Фиксированное имя (файл перезаписывается)</option><option value="auto">Новейший файл по маске</option></select></label>
            <label>{f.file_mode === "fixed" ? "Имя файла" : "Маска"}<input className="mono" value={f.file_name} onChange={(e) => set("file_name", e.target.value)} placeholder={f.file_mode === "fixed" ? "computers.xlsx" : "export_*.xlsx"} spellCheck={false} />
              <span className="help">{f.file_mode === "fixed" ? "Рекомендуемая публикация: BI пишет во временный файл, затем заменяет готовый" : "Временные файлы (~$…, .tmp, .part) пропускаются; при двух одинаково новых файлах импорт не выполняется"}</span></label>
          </div>
          <div className="cols">
            <label>Время получения<input type="time" value={f.schedule_time} onChange={(e) => set("schedule_time", e.target.value)} /></label>
            <label>Часовой пояс<input value={f.timezone} onChange={(e) => set("timezone", e.target.value)} placeholder="Europe/Moscow" spellCheck={false} /><span className="help">Для расписания и дат без пояса в выгрузке</span></label>
          </div>
        </fieldset>
        <details className="disclosure" open={storage}>
          <summary>Проверки и поведение при ошибках</summary>
          <div className="adv">
            <label className="check"><input type="checkbox" className="switch" checked={o.partial} onChange={(e) => setOpt("partial", e.target.checked)} /><span className="check-body">Частичный импорт<span className="help">Некорректные строки отклоняются с отчётом, остальные импортируются; исчезновение устройств в таком снимке не учитывается</span></span></label>
            <div className="cols">{numIn("max_reject_pct", "Допустимо отклонённых строк, %", 0, 100)}{numIn("drift_pct", "Порог изменения числа записей, %", 1, 1000, "Больше — импорт отклоняется до подтверждения")}</div>
            <div className="cols">{numIn("retries", "Повторов после сбоя", 0, 20)}{numIn("retry_minutes", "Интервал повтора, мин", 5, 1440)}</div>
            <div className="cols">{numIn("stable_s", "Ожидание стабильности файла, с", 0, 300, "Размер и время изменения не должны меняться")}{numIn("max_mb", "Наибольший размер файла, МБ", 1, 500)}</div>
            <div className="cols">{numIn("max_rows", "Наибольшее число строк", 100, 2000000)}{numIn("owner_drift_pct", "Порог смены владельцев, %", 1, 100, "Доля устройств, у которых сменился владелец; больше — импорт отклоняется до подтверждения (защита истории от сдвига столбцов)")}</div>
            <label className="check"><input type="checkbox" className="switch" checked={o.full_snapshot} onChange={(e) => setOpt("full_snapshot", e.target.checked)} /><span className="check-body">Выгрузка полная<span className="help">Отсутствие устройства в снимке означает, что BI его больше не показывает (связь — «текущий статус неизвестен»). Выключите для выгрузок изменений</span></span></label>
            <label className="check"><input type="checkbox" className="switch" checked={o.auto_exact} onChange={(e) => setOpt("auto_exact", e.target.checked)} /><span className="check-body">Автоматически подтверждать однозначные точные совпадения имён устройств<span className="help">Только если имя единственное среди устройств BI и компьютеров всех источников KSC, нет противоречий и другого подтверждённого соответствия, имя не условное. Основание — «подтверждено автоматически по правилу точного совпадения имени»; решение можно отменить. По умолчанию выключено</span></span></label>
          </div>
        </details>
        <details className="disclosure" open={storage}>
          <summary>Хранение исходных файлов</summary>
          <div className="adv">
            <div className="cols">{numIn("keep_files", "Хранить копий файлов", 0, 1000)}{numIn("keep_days", "Не дольше, суток", 1, 3650)}</div>
            <span className="help">Копии исходных Excel удаляются по сроку и числу. История импортов и история принадлежности устройств хранятся отдельно и при этом не удаляются. События импорта записываются в общий журнал событий с его сроком хранения.</span>
          </div>
        </details>
        <label className="check"><input type="checkbox" className="switch" checked={f.is_active} onChange={(e) => set("is_active", e.target.checked)} /><span className="check-body">Источник включён<span className="help">Выключенный источник не получает файлы по расписанию; накопленные данные сохраняются</span></span></label>
        {error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{error}</div></div>}
      </form>
    </Modal>
  );
}

/** Проверка структуры: листы, столбцы и примеры значений образца (загруженного или пробного чтения с SMB), сопоставление с полями внутренней модели. В базу ничего не записывается. */
function StructureDialog({ src, fields, onClose, onSaved }: { src: BiSourceInfo; fields: Record<string, string>; onClose: () => void; onSaved: () => void }) {
  const [pv, setPv] = useState<BiPreview | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [prof, setProf] = useState<Partial<BiProfile> | null>(src.profile?.columns ? src.profile : null); const [file, setFile] = useState<File | null>(null);
  const check = async (f: File | null, p?: Partial<BiProfile> | null) => {
    setBusy(true); setErr("");
    try { const r = await api.bi.preview(src.id, f, p ?? undefined); setPv(r); setProf((cur) => (p ?? cur) ?? r.suggested); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  const cols = prof?.columns ?? {};
  const setCol = (k: string, h: string) => setProf((p) => ({ ...(p ?? {}), columns: Object.fromEntries(Object.entries({ ...(p?.columns ?? {}), [k]: h }).filter(([, v]) => v)) }));
  const save = async () => {
    setBusy(true); setErr("");
    try { await api.bi.update(src.id, { name: src.name, is_active: src.is_active, smb_host: src.smb_host, smb_port: src.smb_port, smb_share: src.smb_share, smb_path: src.smb_path, username: src.username, smb_encrypt: src.smb_encrypt,
      file_mode: src.file_mode, file_name: src.file_name, schedule_time: src.schedule_time, timezone: src.timezone, options: src.options, profile: { ...prof, sheet: pv?.sheet ?? prof?.sheet ?? "" }, password: null }); onSaved(); }
    catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  const warnEntries = Object.entries(pv?.check.warnings ?? {});
  return (
    <Modal side wide title={`Структура файла: ${src.name}`} onClose={onClose} lede="Пробное чтение без записи в базу: листы, столбцы, примеры и проверка первых строк"
      footer={<><button type="button" className="btn ghost" onClick={onClose}>Закрыть</button><button type="button" className="btn primary" disabled={!pv || busy || !Object.keys(cols).length} onClick={() => void save()}>Сохранить сопоставление</button></>}>
      <div className="row wrap tight">
        <button className="btn" aria-busy={busy && !file} disabled={busy} onClick={() => { setFile(null); void check(null, prof); }}><Icon name="plug" size={15} />Прочитать актуальный файл с SMB</button>
        <label className="btn ghost">{file ? `Образец: ${file.name}` : "Загрузить образец…"}<input type="file" hidden accept=".xlsx" onChange={(e) => { const f = e.target.files?.[0] ?? null; e.target.value = ""; if (f) { setFile(f); void check(f, prof); } }} /></label>
        {pv && <button className="btn ghost" disabled={busy} onClick={() => void check(file, prof)}>Проверить с этим сопоставлением</button>}
      </div>
      {err && <div className="alert error mt-sm" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {pv && <>
        <p className="small mt-sm">Лист «{pv.sheet}» (листов: {pv.sheets.length}), заголовки в строке {pv.header_row}, столбцов {pv.headers.length}. {pv.origin.kind === "smb" ? `Файл с SMB: «${pv.origin.name}», изменён ${fmt(pv.origin.mtime)}.` : `Загруженный образец «${pv.origin.name}».`}</p>
        {pv.archive_warnings.map((w) => <div key={w} className="alert info"><Icon name="info" /><div className="alert-body">{w}</div></div>)}
        {pv.missing.length > 0 && <div className="alert error"><Icon name="alert" /><div className="alert-body">Нет обязательных столбцов: {pv.missing.join(", ")}.</div></div>}
        {pv.check.profile_error && <div className="alert warn"><Icon name="alert" /><div className="alert-body">{pv.check.profile_error}</div></div>}
        {pv.check.rows > 0 && <div className="alert info"><Icon name="info" /><div className="alert-body">Проверено {pv.check.truncated ? "первых " : ""}{num(pv.check.rows)} строк: пригодны {num(pv.check.ok)}, пустых {num(pv.check.empty)}, будут отклонены {num(pv.check.rejected.length)}.
          {warnEntries.length > 0 && <ul className="reasons">{warnEntries.map(([k, n]) => { const [code, col] = k.split(":"); return <li key={k}>{({ future_date: "Даты из будущего", bad_date: "Нераспознанные даты", old_date: "Даты раньше 1990 года", bad_email: "Некорректная почта" } as Record<string, string>)[code] ?? code} — «{col}»: {num(n)}</li>; })}</ul>}
          {pv.check.rejected.length > 0 && <span className="block small">Например: {pv.check.rejected.slice(0, 3).map((r) => `строка ${r.row} — ${r.reason}`).join("; ")}</span>}</div></div>}
        <h3 className="h3">Сопоставление столбцов</h3>
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Поле KAV Checker</th><th>Столбец файла</th><th>Пример значения</th></tr></thead>
          <tbody>{Object.entries(fields).map(([k, label]) => <tr key={k}><td className="small">{label}{["device_name", "person_name", "email"].includes(k) && <span className="sub">{k === "device_name" ? "обязательно (или идентификатор устройства)" : "обязательно ФИО или почта"}</span>}</td>
            <td><select value={cols[k] ?? ""} onChange={(e) => setCol(k, e.target.value)} aria-label={label}><option value="">— не использовать —</option>{pv.headers.map((h) => <option key={h} value={h}>{h}</option>)}</select></td>
            <td className="small muted">{cols[k] ? pv.samples.map((s) => s[cols[k]]).filter(Boolean).slice(0, 2).join("; ") || "пусто" : ""}</td></tr>)}</tbody>
        </table></div>
        <fieldset className="qr-sections"><legend>Происхождение сведений (флаги «да/нет»)</legend>
          {pv.headers.filter((h) => !Object.values(cols).includes(h)).map((h) => <label key={h} className="check"><input type="checkbox" checked={(prof?.origin ?? []).includes(h)}
            onChange={(e) => setProf((p) => ({ ...(p ?? {}), origin: e.target.checked ? [...(p?.origin ?? []), h] : (p?.origin ?? []).filter((x) => x !== h) }))} />{h}</label>)}
        </fieldset>
        <TagInput label="Условные имена устройств" value={prof?.generic_names ?? pv.suggested.generic_names} onChange={(v) => setProf((p) => ({ ...(p ?? {}), generic_names: v }))} placeholder="личный пк" mono={false} />
        <span className="help">Записи с такими именами (и с пробелами в имени) хранятся отдельно для каждого сотрудника и не сопоставляются с KSC по имени. Несопоставленные столбцы сохраняются как дополнительные сведения.</span>
        <details className="disclosure"><summary>Примеры строк ({pv.samples.length})</summary>
          <div className="table-scroll"><table className="table compact"><thead><tr>{pv.headers.map((h) => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>{pv.samples.map((s, i) => <tr key={i}>{pv.headers.map((h) => <td key={h} className="small">{s[h]}</td>)}</tr>)}</tbody></table></div></details>
      </>}
    </Modal>
  );
}

function ImportLog({ src, onClose }: { src: BiSourceInfo; onClose: () => void }) {
  const [items, setItems] = useState<BiImport[] | null>(null); const [one, setOne] = useState<BiImport | null>(null); const [err, setErr] = useState("");
  useEffect(() => { api.bi.imports(src.id).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)); }, [src.id]);
  return (
    <Modal side wide title={`Журнал импортов: ${src.name}`} onClose={onClose} lede="Каждое получение файла: контрольная сумма, счётчики, предупреждения и отклонённые строки">
      {items && items.length > 0 && <div className="toolbar"><div className="spacer" /><AdminReportButton view="bi_imports" title={`журнал импортов «${src.name}»`} params={{ source_id: src.id }} className="btn mini" /></div>}
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!items && !err && <SkelRows rows={5} cols={5} />}
      {items && !items.length && <Empty icon="journal" title="Импортов ещё не было">Запустите импорт или загрузите файл.</Empty>}
      {items && items.length > 0 && <div className="table-scroll"><table className="table compact">
        <thead><tr><th>Начало</th><th>Файл</th><th>Итог</th><th className="num">Строк</th><th className="num">Новых</th><th className="num">Изм.</th><th className="num">Откл.</th><th className="num hide-sm">Время</th></tr></thead>
        <tbody>{items.map((i) => <tr key={i.id} className="clickable" onClick={() => api.bi.importOne(i.id).then(setOne).catch((e) => setErr((e as ApiError).message))}>
          <td className="nowrap small">{fmt(i.started_at)}<span className="sub">{({ schedule: "по расписанию", manual: "вручную", upload: "загружен" } as Record<string, string>)[i.trigger]}{i.by ? ` · ${i.by}` : ""}</span></td>
          <td className="small">{i.file_name || "—"}<span className="sub mono">{i.sha256 ? i.sha256.slice(0, 12) + "…" : ""}{i.stored ? " · копия хранится" : ""}</span></td>
          <td className="small"><span className={`badge ${ST_CLS[i.status] ?? ""}`}>{i.status_ru}</span>{i.warnings_n > 0 && <span className="sub">предупреждений: {i.warnings_n}</span>}</td>
          <td className="num">{num(i.rows_read)}</td><td className="num">{num(i.rows_new)}</td><td className="num">{num(i.rows_changed)}</td><td className="num">{num(i.rows_rejected)}</td>
          <td className="num small hide-sm">{i.ms != null ? `${(i.ms / 1000).toFixed(1)} с` : "—"}</td></tr>)}</tbody></table></div>}
      {one && <div className="card mt-sm">
        <div className="card-head"><h3>{one.file_name || "Импорт"} · {one.status_ru}</h3><div className="spacer" /><button className="btn mini ghost icon" aria-label="Закрыть подробности" onClick={() => setOne(null)}><Icon name="close" size={15} /></button></div>
        <p className="small">{one.message}</p>
        <dl className="kv compact">
          <div><dt>Дата снимка</dt><dd>{fmt(one.snapshot_at)}</dd></div><div><dt>SHA-256</dt><dd className="mono small">{one.sha256 || "—"}</dd></div>
          <div><dt>Строк прочитано / пустых</dt><dd>{num(one.rows_read)} / {num(one.rows_empty)}</dd></div>
          <div><dt>Записей: новых / изменено / без изменений / исчезло</dt><dd>{num(one.rows_new)} / {num(one.rows_changed)} / {num(one.rows_same)} / {num(one.rows_gone)}</dd></div>
        </dl>
        {!!one.warnings?.length && <><h4 className="h4">Предупреждения</h4><ul className="reasons small">{one.warnings.map((w, i) => <li key={i}>{w.text}</li>)}</ul></>}
        {!!one.errors?.length && <><h4 className="h4">Отклонённые строки ({num(one.rows_rejected)}{one.errors.length < one.rows_rejected ? `, показаны первые ${one.errors.length}` : ""})</h4>
          <div className="table-scroll"><table className="table compact"><thead><tr><th className="num">Строка</th><th>Причина</th></tr></thead><tbody>{one.errors.map((e, i) => <tr key={i}><td className="num">{e.row}</td><td className="small">{e.reason}</td></tr>)}</tbody></table></div></>}
      </div>}
    </Modal>
  );
}
