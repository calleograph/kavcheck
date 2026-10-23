import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type ApiError, type DiagResult, type SourceFull } from "../../api";
import type { Ctx } from "../../App";
import { SecretInput, StageList, secretToSend } from "../../components/Common";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { fmt } from "../../util";

interface Form { id?: string; name: string; host: string; port: number; database: string; auth_type: string; username: string; password: string; password_set: boolean; tls_mode: string; trust_server_cert: boolean; connect_timeout_s: number; query_timeout_s: number; is_active: boolean }
const empty: Form = { name: "", host: "", port: 1433, database: "KAV", auth_type: "sql", username: "", password: "", password_set: false, tls_mode: "require", trust_server_cert: true, connect_timeout_s: 10, query_timeout_s: 60, is_active: true };

/** Источники данных: подключения к базам Серверов администрирования KSC (только чтение), проверка подключения с диагностикой. */
export default function SourcesAdmin({ ctx }: { ctx: Ctx }) {
  const [items, setItems] = useState<SourceFull[] | null>(null);
  const [form, setForm] = useState<Form | null>(null);
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const [diag, setDiag] = useState<Record<string, DiagResult | "run">>({});
  const [del, setDel] = useState<SourceFull | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.sources().then((r) => setItems(r.items)).catch((e) => setError((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const body = (f: Form) => ({ name: f.name.trim(), host: f.host.trim(), port: f.port, database: f.database.trim(), auth_type: f.auth_type, username: f.username.trim(), tls_mode: f.tls_mode, trust_server_cert: f.trust_server_cert, connect_timeout_s: f.connect_timeout_s, query_timeout_s: f.query_timeout_s, is_active: f.is_active, ...(secretToSend(f.password) !== undefined ? { password: secretToSend(f.password) } : {}) });
  const test = async (id: string) => { setDiag((d) => ({ ...d, [id]: "run" })); try { const r = await api.admin.testSource(id); setDiag((d) => ({ ...d, [id]: r })); await load(); await ctx.reloadSources(); } catch (e) { setDiag((d) => ({ ...d, [id]: { ok: false, stages: [{ stage: "error", ok: false, message: (e as ApiError).message, ms: 0 }] } })); } };
  const save = async (thenTest: boolean) => {
    if (!form) return; setError(""); setBusy(true);
    try { const saved = form.id ? await api.admin.updateSource(form.id, body(form)) : await api.admin.createSource(body(form)); setForm(null); show(form.id ? "Источник сохранён" : "Источник добавлен"); await load(); await ctx.reloadSources(); if (thenTest) void test(saved.id); }
    catch (err) { setError((err as ApiError).message); }
    setBusy(false);
  };
  const submit = (e: FormEvent) => { e.preventDefault(); void save(false); };
  return (
    <>
      <div className="row" style={{ marginBottom: 14 }}>
        <span className="muted small">Пароль хранится зашифрованным ключом APP_MASTER_KEY и после сохранения не показывается.</span><div className="spacer" />
        <button className="btn primary" onClick={() => { setForm({ ...empty }); setError(""); }}><Icon name="plus" />Добавить источник</button>
      </div>
      {!items && <div className="card"><SkelRows rows={3} cols={3} /></div>}
      {items && !items.length && <div className="card"><Empty icon="database" title="Источников пока нет" action={<button className="btn primary" onClick={() => setForm({ ...empty })}><Icon name="plus" />Добавить источник</button>}>Укажите SQL Server и базу Сервера администрирования, затем проверьте подключение.</Empty></div>}
      {items?.map((s) => { const d = diag[s.id]; const r = d && d !== "run" ? d : null; const feats = s.last_check?.features ? Object.values(s.last_check.features) : []; return (
        <div key={s.id} className="card src-card">
          <div className="card-head">
            <span className={`dot ${s.last_check_ok === true ? "ok" : s.last_check_ok === false ? "bad" : "off"}`} aria-hidden />
            <h2>{s.name}</h2>
            {!s.is_active && <span className="badge warn">выключен</span>}
            {s.ksc_version && <span className="badge accent">KSC {s.ksc_version}</span>}
            <span className="muted small">{s.last_check_ok == null ? "не проверялся" : `${s.last_check_ok ? "проверен" : "ошибка проверки"} ${fmt(s.last_check_at)}`}</span>
            <div className="spacer" />
            <button className="btn mini" aria-busy={d === "run"} onClick={() => void test(s.id)}><Icon name="plug" size={15} /><span>Проверить</span></button>
            <button className="btn mini ghost icon" aria-label={`Изменить ${s.name}`} onClick={() => { setForm({ ...s, password: "", password_set: s.password_set }); setError(""); }}><Icon name="edit" size={15} /></button>
            <button className="btn mini ghost danger icon" aria-label={`Удалить ${s.name}`} onClick={() => setDel(s)}><Icon name="trash" size={15} /></button>
          </div>
          <div className="addr">{s.username} → {s.host}:{s.port} / {s.database}</div>
          <div className="muted small">{s.auth_type === "windows" ? "Windows (NTLM)" : "SQL Server"}, TLS: {({ require: "обязательно", request: "по возможности", off: "выключено" } as Record<string, string>)[s.tls_mode]}, тайм-аут запроса {s.query_timeout_s} с, пароль {s.password_set ? "задан" : "не задан"}</div>
          {feats.length > 0 && <ul className="feat-list" aria-label="Доступные функции">{feats.map((f) => <li key={f.title} className={f.ok ? "" : "no"} title={f.ok ? "объекты найдены" : `нет объектов: ${f.missing.join(", ")}`}><Icon name={f.ok ? "check" : "close"} size={14} />{f.title}</li>)}</ul>}
          {r && <StageList result={r} />}
        </div>); })}
      {form && (
        <Modal title={form.id ? `Источник «${form.name}»` : "Новый источник KSC"} onClose={() => setForm(null)}
          footer={<><button type="button" className="btn ghost" onClick={() => setForm(null)}>Отмена</button><button type="button" className="btn" disabled={busy} onClick={() => void save(true)}>Сохранить и проверить</button><button type="submit" form="src-form" className="btn primary" aria-busy={busy}><span>Сохранить</span></button></>}>
          <form id="src-form" onSubmit={submit} noValidate>
            <div className="cols">
              <label>Название<input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Kaspersky 01" maxLength={120} required autoFocus /><span className="help">Так источник называется в переключателе</span></label>
              <label className="check" style={{ alignSelf: "center" }}><input type="checkbox" className="switch" checked={form.is_active} onChange={(e) => set("is_active", e.target.checked)} />Источник активен</label>
            </div>
            <fieldset className="group"><legend>SQL Server</legend>
              <div className="cols">
                <label>Сервер<input className="mono" value={form.host} onChange={(e) => set("host", e.target.value)} placeholder="sql01.example.local" spellCheck={false} required /><span className="help">Имя или IP-адрес</span></label>
                <label>Порт<input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", Number(e.target.value))} /></label>
                <label>База данных<input className="mono" value={form.database} onChange={(e) => set("database", e.target.value)} spellCheck={false} required /><span className="help">По умолчанию KAV</span></label>
              </div>
              <div className="cols">
                <label>Шифрование<select value={form.tls_mode} onChange={(e) => set("tls_mode", e.target.value)}><option value="require">Обязательно</option><option value="request">По возможности</option><option value="off">Выключено</option></select></label>
                <label className="check" style={{ alignSelf: "center" }}><input type="checkbox" className="switch" checked={form.trust_server_cert} onChange={(e) => set("trust_server_cert", e.target.checked)} /><span className="check-body">Доверять сертификату сервера<span className="help">Нужно для самоподписанного сертификата SQL Server</span></span></label>
              </div>
              <div className="cols">
                <label>Тайм-аут подключения, с<input type="number" min={1} max={120} value={form.connect_timeout_s} onChange={(e) => set("connect_timeout_s", Number(e.target.value))} /></label>
                <label>Тайм-аут запроса, с<input type="number" min={5} max={3600} value={form.query_timeout_s} onChange={(e) => set("query_timeout_s", Number(e.target.value))} /></label>
              </div>
            </fieldset>
            <fieldset className="group"><legend>Учётная запись только для чтения</legend>
              <div className="cols">
                <label>Тип авторизации<select value={form.auth_type} onChange={(e) => set("auth_type", e.target.value)}><option value="sql">SQL Server</option><option value="windows">Windows (DOMAIN\user)</option></select></label>
                <label>Пользователь<input className="mono" value={form.username} onChange={(e) => set("username", e.target.value)} placeholder={form.auth_type === "windows" ? "EXAMPLE\\svc-kavcheck" : "kavcheck_ro"} spellCheck={false} autoComplete="off" required /></label>
              </div>
              <SecretInput label="Пароль" isSet={form.password_set} value={form.password} onChange={(v) => set("password", v)} help="Хранится зашифрованным, через API не возвращается и в журналы не попадает." />
            </fieldset>
            {error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{error}</div></div>}
          </form>
        </Modal>
      )}
      {del && <ConfirmDialog title={`Удалить источник «${del.name}»?`} confirmLabel="Удалить источник" typed="УДАЛИТЬ" body={<p>Вместе с источником удалятся сформированные по нему отчёты и сценарии аудита. База KSC не затрагивается.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.deleteSource(del.id); await load(); await ctx.reloadSources(); }} />}
      {toast}
    </>
  );
}
