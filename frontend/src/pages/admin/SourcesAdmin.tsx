import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type ApiError, type DiagResult, type SourceFull } from "../../api";
import type { Ctx } from "../../App";
import { SecretInput, StageList, secretToSend } from "../../components/Common";
import { ConfirmDialog } from "../../components/Dialogs";
import { fmt } from "../../util";

interface Form { id?: string; name: string; host: string; port: number; database: string; auth_type: string; username: string; password: string; password_set: boolean; tls_mode: string; trust_server_cert: boolean; connect_timeout_s: number; query_timeout_s: number; is_active: boolean }
const empty: Form = { name: "", host: "", port: 1433, database: "", auth_type: "sql", username: "", password: "", password_set: false, tls_mode: "require", trust_server_cert: true, connect_timeout_s: 10, query_timeout_s: 60, is_active: true };

/** Источники данных: подключения к базам Серверов администрирования KSC (только чтение), проверка подключения с диагностикой. */
export default function SourcesAdmin({ ctx }: { ctx: Ctx }) {
  const [items, setItems] = useState<SourceFull[]>([]);
  const [form, setForm] = useState<Form | null>(null);
  const [error, setError] = useState(""); const [note, setNote] = useState(""); const [busy, setBusy] = useState(false);
  const [diag, setDiag] = useState<Record<string, DiagResult | "run">>({});
  const [del, setDel] = useState<SourceFull | null>(null);
  const load = useCallback(() => api.admin.sources().then((r) => setItems(r.items)).catch((e) => setError((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));
  const body = (f: Form) => ({ name: f.name.trim(), host: f.host.trim(), port: f.port, database: f.database.trim(), auth_type: f.auth_type, username: f.username.trim(), tls_mode: f.tls_mode, trust_server_cert: f.trust_server_cert, connect_timeout_s: f.connect_timeout_s, query_timeout_s: f.query_timeout_s, is_active: f.is_active, ...(secretToSend(f.password) !== undefined ? { password: secretToSend(f.password) } : {}) });
  const test = async (id: string) => { setDiag((d) => ({ ...d, [id]: "run" })); try { const r = await api.admin.testSource(id); setDiag((d) => ({ ...d, [id]: r })); await load(); await ctx.reloadSources(); } catch (e) { setDiag((d) => ({ ...d, [id]: { ok: false, stages: [{ stage: "error", ok: false, message: (e as ApiError).message, ms: 0 }] } })); } };
  const save = async (e: FormEvent, thenTest = false) => {
    e.preventDefault(); if (!form) return; setError(""); setNote(""); setBusy(true);
    try { const saved = form.id ? await api.admin.updateSource(form.id, body(form)) : await api.admin.createSource(body(form)); setForm(null); setNote("Сохранено."); await load(); await ctx.reloadSources(); if (thenTest) void test(saved.id); }
    catch (err) { setError((err as ApiError).message); }
    setBusy(false);
  };
  return (
    <section>
      <div className="row"><h2>Источники KSC</h2><div className="spacer" />{!form && <button className="btn primary" onClick={() => { setForm({ ...empty }); setError(""); setNote(""); }}>＋ Добавить источник</button>}</div>
      <p className="muted">Каждый источник — база одного Сервера администрирования на Microsoft SQL Server. Подключение только для чтения: используйте отдельную учётную запись с ролью <code>db_datareader</code>. Пароль хранится зашифрованно (ключ APP_MASTER_KEY) и не показывается после сохранения.</p>
      {note && <div className="alert ok" role="status">{note}</div>}
      {error && <div className="alert error" role="alert">{error}</div>}
      {form && (
        <form className="card form" onSubmit={(e) => void save(e)} noValidate>
          <h3 style={{ margin: 0 }}>{form.id ? `Изменение источника «${form.name}»` : "Новый источник"}</h3>
          <div className="cols">
            <label>Название<input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Kaspersky 01" maxLength={120} required /></label>
            <label className="check" style={{ marginTop: 26 }}><input type="checkbox" checked={form.is_active} onChange={(e) => set("is_active", e.target.checked)} /> Источник активен</label>
          </div>
          <fieldset className="group"><legend>SQL Server</legend>
            <div className="cols">
              <label>Сервер (имя или IP)<input value={form.host} onChange={(e) => set("host", e.target.value)} placeholder="sql01.example.local" spellCheck={false} required /></label>
              <label>Порт<input type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", Number(e.target.value))} /></label>
              <label>База данных<input value={form.database} onChange={(e) => set("database", e.target.value)} placeholder="KAV" spellCheck={false} required /><span className="help">Имя базы Сервера администрирования (по умолчанию KAV).</span></label>
            </div>
            <div className="cols">
              <label>Шифрование (TLS)<select value={form.tls_mode} onChange={(e) => set("tls_mode", e.target.value)}><option value="require">обязательно</option><option value="request">по возможности</option><option value="off">выключено</option></select></label>
              <label className="check" style={{ marginTop: 26 }}><input type="checkbox" checked={form.trust_server_cert} onChange={(e) => set("trust_server_cert", e.target.checked)} /> <span>Доверять сертификату сервера<span className="help">Самоподписанные сертификаты SQL Server — обычное дело; снимите, если сертификат выпущен доверенным ЦС.</span></span></label>
            </div>
            <div className="cols">
              <label>Тайм-аут подключения, с<input type="number" min={1} max={120} value={form.connect_timeout_s} onChange={(e) => set("connect_timeout_s", Number(e.target.value))} /></label>
              <label>Тайм-аут запроса, с<input type="number" min={5} max={3600} value={form.query_timeout_s} onChange={(e) => set("query_timeout_s", Number(e.target.value))} /></label>
            </div>
          </fieldset>
          <fieldset className="group"><legend>Учётная запись (только чтение)</legend>
            <div className="cols">
              <label>Тип авторизации<select value={form.auth_type} onChange={(e) => set("auth_type", e.target.value)}><option value="sql">SQL Server (логин и пароль)</option><option value="windows">Windows (DOMAIN\user, NTLM)</option></select></label>
              <label>Пользователь<input value={form.username} onChange={(e) => set("username", e.target.value)} placeholder={form.auth_type === "windows" ? "EXAMPLE\\svc-kavcheck" : "kavcheck_ro"} spellCheck={false} autoComplete="off" required /></label>
            </div>
            <SecretInput label="Пароль" isSet={form.password_set} value={form.password} onChange={(v) => set("password", v)} help="Хранится в зашифрованном виде, через API не возвращается и в журналы не попадает." />
          </fieldset>
          <div className="row form-actions">
            <button className="btn primary" disabled={busy}>{busy ? "Сохранение…" : "Сохранить"}</button>
            <button type="button" className="btn" disabled={busy} onClick={(e) => void save(e as unknown as FormEvent, true)}>Сохранить и проверить</button>
            <button type="button" className="btn ghost" onClick={() => setForm(null)}>Отмена</button>
          </div>
        </form>
      )}
      {!items.length && !form && <div className="alert info">Источников пока нет. Нажмите «Добавить источник», укажите SQL Server и базу KSC, затем «Проверить подключение».</div>}
      {items.map((s) => { const d = diag[s.id]; const r = d && d !== "run" ? d : null; return (
        <div key={s.id} className="card conn-card">
          <div className="row"><h3 style={{ margin: 0 }}>{s.name}</h3>
            <span className={`badge ${s.is_active ? "ok" : "warn"}`}>{s.is_active ? "активен" : "выключен"}</span>
            {s.last_check_ok === true && <span className="badge ok">проверен {fmt(s.last_check_at)}</span>}{s.last_check_ok === false && <span className="badge err">ошибка проверки {fmt(s.last_check_at)}</span>}{s.last_check_ok == null && <span className="badge">не проверялся</span>}
            {s.ksc_version && <span className="badge accent">KSC {s.ksc_version}</span>}
          </div>
          <div className="muted small"><code>{s.host}:{s.port}</code> · база <code>{s.database}</code> · {s.auth_type === "windows" ? "Windows" : "SQL"} · пользователь <code>{s.username}</code> · пароль {s.password_set ? "задан" : "не задан"} · TLS {s.tls_mode} · тайм-аут запроса {s.query_timeout_s} с</div>
          {s.last_check?.features && <div className="chips">{Object.values(s.last_check.features).map((f) => <span key={f.title} className={`chip ${f.ok ? "" : ""}`} aria-pressed={f.ok} title={f.ok ? "объекты найдены" : `нет объектов: ${f.missing.join(", ")}`}>{f.ok ? "✓" : "✗"} {f.title}</span>)}</div>}
          <div className="row form-actions">
            <button className="btn primary" disabled={d === "run"} onClick={() => void test(s.id)}>{d === "run" ? "Проверка…" : "Проверить подключение"}</button>
            <button className="btn" onClick={() => { setForm({ ...s, password: "", password_set: s.password_set }); setError(""); setNote(""); }}>Изменить</button>
            <button className="btn ghost danger" onClick={() => setDel(s)}>Удалить</button>
          </div>
          {r && <StageList result={r} />}
        </div>); })}
      {del && <ConfirmDialog title={`Удалить источник «${del.name}»?`} confirmLabel="Удалить" typed="УДАЛИТЬ" body={<p>Вместе с источником будут удалены сформированные по нему отчёты и сценарии аудита. База KSC не затрагивается.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.deleteSource(del.id); await load(); await ctx.reloadSources(); }} />}
    </section>
  );
}
