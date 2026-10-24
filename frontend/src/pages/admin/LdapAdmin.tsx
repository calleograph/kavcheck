import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type AccessRuleT, type ApiError, type CaCert, type CertPreview, type LdapConn, type LdapDiag, type SourceRef } from "../../api";
import { StageList } from "../../components/Common";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows, Tabs } from "../../components/ui";
import { fmt, fmtDate } from "../../util";

type Tab = "connections" | "certs" | "rules" | "check";
const ROLE: Record<string, string> = { admin: "Администратор", analyst: "Аналитик", viewer: "Просмотр" };

/** Вход доменных пользователей по LDAPS: подключения (несколько доменов), доверенные сертификаты CA, правила доступа по группам,
 *  проверка входа пользователя тем же путём, что и настоящий вход. */
export default function LdapAdmin({ sources }: { sources: SourceRef[] }) {
  const [tab, setTab] = useState<Tab>("connections");
  return (
    <div className="stack">
      <Tabs label="Разделы LDAPS" value={tab} onChange={setTab} items={[{ id: "connections", label: "Подключения" }, { id: "certs", label: "Сертификаты CA" },
        { id: "rules", label: "Правила доступа" }, { id: "check", label: "Проверка входа" }]} />
      {tab === "connections" && <Connections onCheckLogin={() => setTab("check")} />}
      {tab === "certs" && <Certs />}
      {tab === "rules" && <Rules sources={sources} />}
      {tab === "check" && <CheckLogin />}
    </div>
  );
}

// ------------------------------------------------------------------------------------------------ подключения
const EMPTY: Partial<LdapConn> & { url: string; bind_password: string } = { name: "", url: "", enabled: true, is_primary: false, ldap_version: 3, timeout_s: 5, base_dn: "", domain_dns: "", netbios: "",
  bind_dn: "", bind_password: "", login_attribute: "sAMAccountName", display_name_attribute: "displayName", email_attribute: "mail", user_filter: "(&(objectCategory=person)(objectClass=user))", nested_groups: true };

function Connections({ onCheckLogin }: { onCheckLogin: () => void }) {
  const [items, setItems] = useState<LdapConn[] | null>(null);
  const [edit, setEdit] = useState<(typeof EMPTY & { id?: string; bind_password_set?: boolean }) | null>(null);
  const [test, setTest] = useState<LdapConn | null>(null);
  const [del, setDel] = useState<LdapConn | null>(null); const [delSecret, setDelSecret] = useState<LdapConn | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.ldap.connections().then((r) => setItems(r.items)).catch(() => setItems([])), []);
  useEffect(() => { void load(); }, [load]);
  return (
    <>
      <div className="row"><p className="muted small grow">Каждое подключение — домен Active Directory по LDAPS. Пользователи входят по имени учётной записи без домена (например, ivan.petrov): оно ищется во всех включённых доменах; если имя есть в нескольких, на странице входа выбирается домен. Шифрование и проверка сертификата сервера обязательны.</p>
        <button className="btn primary" onClick={() => setEdit({ ...EMPTY, is_primary: !items?.length })}><Icon name="plus" />Добавить подключение</button></div>
      {!items ? <div className="card"><SkelRows rows={2} cols={4} /></div> : !items.length ? (
        <div className="card"><Empty icon="key" title="Подключений нет" action={<button className="btn primary" onClick={() => setEdit({ ...EMPTY, is_primary: true })}><Icon name="plus" />Добавить подключение</button>}>
          Пока каталог не подключён, вход возможен только локальными учётными записями KAV Checker.</Empty></div>
      ) : items.map((c) => (
        <div key={c.id} className="card conn-card">
          <div className="card-head"><span className={`dot ${!c.enabled ? "muted-dot" : c.last_check_ok === false ? "bad-dot" : c.last_check_ok ? "ok-dot" : ""}`} />
            <h2>{c.name}</h2>{c.is_primary && <span className="badge accent">основное</span>}{!c.enabled && <span className="badge">выключено</span>}<div className="spacer" />
            <button className="btn mini" onClick={() => setTest(c)}><Icon name="plug" size={15} />Проверить</button>
            <button className="btn mini ghost icon" onClick={() => setEdit({ ...EMPTY, ...c, url: c.url, bind_password: "" })} aria-label={`Изменить ${c.name}`}><Icon name="edit" size={15} /></button>
            <button className="btn mini ghost danger icon" onClick={() => setDel(c)} aria-label={`Удалить ${c.name}`}><Icon name="trash" size={15} /></button></div>
          <dl className="kv compact">
            <div><dt>LDAPS URL</dt><dd className="mono">{c.url}{c.protocol === "starttls" && " (STARTTLS)"}</dd></div>
            <div><dt>Домен</dt><dd>{c.domain_dns || "—"}{c.netbios ? ` · NetBIOS ${c.netbios}` : ""}</dd></div>
            <div><dt>Base DN</dt><dd className="mono">{c.base_dn}</dd></div>
            <div><dt>Сервисная учётная запись</dt><dd><span className="mono">{c.bind_dn}</span> {c.bind_password_set ? <span className="badge ok">пароль задан</span> : <span className="badge warn">пароля нет</span>}
              {c.bind_password_set && <button className="link-btn small-gap" onClick={() => setDelSecret(c)}>удалить учётные данные</button>}</dd></div>
            <div><dt>Версия LDAP, тайм-аут</dt><dd>v{c.ldap_version}, {c.timeout_s} с</dd></div>
            <div><dt>Последняя проверка</dt><dd>{c.last_check_at ? <>{fmt(c.last_check_at)} — {c.last_check_ok ? <span className="ok-text">успешно</span> : <span className="bad-text">с ошибкой</span>}</> : "не проверялось"}</dd></div>
          </dl>
        </div>))}
      {edit && <ConnDialog value={edit} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); void load(); show("Подключение сохранено"); }} />}
      {test && <TestDialog conn={test} onClose={() => { setTest(null); void load(); }} onCheckLogin={() => { setTest(null); onCheckLogin(); }} />}
      {del && <ConfirmDialog title="Удалить подключение?" confirmLabel="Удалить" body={<p>Подключение «{del.name}» и его правила доступа будут удалены. Пользователи этого домена не смогут войти.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.ldap.remove(del.id); void load(); }} />}
      {delSecret && <ConfirmDialog title="Удалить учётные данные?" confirmLabel="Удалить учётные данные" body={<p>Пароль сервисной учётной записи «{delSecret.bind_dn}» будет удалён, подключение выключится. Чтобы снова включить вход, задайте новый пароль.</p>}
        onClose={() => setDelSecret(null)} onConfirm={async () => { await api.admin.ldap.removeSecret(delSecret.id); void load(); }} />}
      {toast}
    </>
  );
}

function ConnDialog({ value, onClose, onSaved }: { value: typeof EMPTY & { id?: string; bind_password_set?: boolean }; onClose: () => void; onSaved: () => void }) {
  const [v, setV] = useState(value);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const set = (k: string, x: unknown) => setV((o) => ({ ...o, [k]: x }));
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    const body = { ...v, bind_password: v.bind_password || (v.id ? null : "") };
    try { if (v.id) await api.admin.ldap.update(v.id, body); else await api.admin.ldap.create({ ...body, bind_password: v.bind_password }); onSaved(); } catch (x) { setErr((x as ApiError).message); setBusy(false); }
  };
  return (
    <Modal title={v.id ? `Подключение LDAPS «${value.name}»` : "Новое подключение LDAPS"} onClose={onClose} wide>
      <form onSubmit={submit}>
        <div className="cols">
          <label>Отображаемое название<input value={v.name} onChange={(e) => set("name", e.target.value)} required maxLength={120} autoFocus placeholder="Основной домен" /></label>
          <label>LDAPS URL<input className="mono" value={v.url} onChange={(e) => set("url", e.target.value)} required placeholder="ldaps://dc1.example.local:636" />
            <span className="help">ldaps://контроллер:636; для STARTTLS — ldap://контроллер:389. Имя должно совпадать с сертификатом сервера.</span></label>
        </div>
        <div className="cols three">
          <label>Версия LDAP<select value={v.ldap_version} onChange={(e) => set("ldap_version", Number(e.target.value))}><option value={3}>3 (рекомендуется)</option><option value={2}>2</option></select></label>
          <label>Сетевой тайм-аут, с<input type="number" min={1} max={60} value={v.timeout_s} onChange={(e) => set("timeout_s", Number(e.target.value))} /></label>
          <label className="check align-end"><input type="checkbox" className="switch" checked={!!v.is_primary} onChange={(e) => set("is_primary", e.target.checked)} />Основной домен</label>
        </div>
        <fieldset className="group"><legend>Домен</legend>
          <div className="cols three">
            <label>Base DN<input className="mono" value={v.base_dn} onChange={(e) => set("base_dn", e.target.value)} required placeholder="DC=example,DC=local" /></label>
            <label>DNS-имя домена<input className="mono" value={v.domain_dns} onChange={(e) => set("domain_dns", e.target.value)} placeholder="example.local" /><span className="help">домен в именах вида логин@домен; в журналах</span></label>
            <label>NetBIOS-имя<input className="mono" value={v.netbios} onChange={(e) => set("netbios", e.target.value.toUpperCase())} placeholder="EXAMPLE" maxLength={15} /><span className="help">для имён вида DOMAIN\логин (необязательно)</span></label>
          </div>
        </fieldset>
        <fieldset className="group"><legend>Сервисная учётная запись (поиск пользователей и групп, только чтение)</legend>
          <div className="cols">
            <label>Учётная запись<input className="mono" value={v.bind_dn} onChange={(e) => set("bind_dn", e.target.value)} required placeholder="svc-kavcheck@example.local или CN=…" /></label>
            <label>Пароль<input type="password" value={v.bind_password} onChange={(e) => set("bind_password", e.target.value)} autoComplete="new-password" required={!v.id || !v.bind_password_set}
              placeholder={v.bind_password_set ? "задан — оставьте пустым, чтобы не менять" : ""} /><span className="help">Хранится зашифрованным, через интерфейс и API не возвращается.</span></label>
          </div>
        </fieldset>
        <details className="disclosure"><summary>Атрибуты и фильтр (для опытных)</summary>
          <div className="cols three adv">
            <label>Логин<input className="mono" value={v.login_attribute} onChange={(e) => set("login_attribute", e.target.value)} /></label>
            <label>Отображаемое имя<input className="mono" value={v.display_name_attribute} onChange={(e) => set("display_name_attribute", e.target.value)} /></label>
            <label>Почта<input className="mono" value={v.email_attribute} onChange={(e) => set("email_attribute", e.target.value)} /></label>
          </div>
          <label>Фильтр пользователей<input className="mono" value={v.user_filter} onChange={(e) => set("user_filter", e.target.value)} /></label>
          <label className="check"><input type="checkbox" className="switch" checked={!!v.nested_groups} onChange={(e) => set("nested_groups", e.target.checked)} />Учитывать вложенные группы (Active Directory)</label>
        </details>
        <label className="check"><input type="checkbox" className="switch" checked={!!v.enabled} onChange={(e) => set("enabled", e.target.checked)} />Подключение включено</label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy}><span>Сохранить</span></button></div>
      </form>
    </Modal>
  );
}

function TestDialog({ conn, onClose, onCheckLogin }: { conn: LdapConn; onClose: () => void; onCheckLogin: () => void }) {
  const [r, setR] = useState<LdapDiag | null>(null); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const run = async () => { setBusy(true); setErr(""); setR(null); try { setR(await api.admin.ldap.test(conn.id)); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); } };
  useEffect(() => { void run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Modal title={`Проверка подключения «${conn.name}»`} onClose={onClose} wide>
      <p className="muted small">Контроллер домена: DNS → TCP → TLS и цепочка сертификатов → вход сервисной учётной записи → чтение Base DN. Вход конкретного пользователя (поиск, пароль, группы, роль) —
        во вкладке <button type="button" className="link-btn" onClick={onCheckLogin}>«Проверка входа»</button>.</p>
      {busy && <div className="row"><span className="spin accent" /><span className="muted small">Проверка…</span></div>}
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {r && <div><StageList result={r} okText="Подключение LDAPS работает" />
        {r.server_certificate && <dl className="kv compact mt-sm"><div><dt>Сертификат сервера</dt><dd className="mono small">{r.server_certificate.subject}</dd></div><div><dt>Издатель</dt><dd className="mono small">{r.server_certificate.issuer}</dd></div>
          <div><dt>Имена (SAN)</dt><dd className="mono small">{r.server_certificate.san.join(", ") || "—"}</dd></div><div><dt>Действует до</dt><dd>{r.server_certificate.not_after}</dd></div></dl>}
      </div>}
      <div className="modal-foot"><button className="btn" onClick={() => void run()} aria-busy={busy} disabled={busy}><Icon name="refresh" size={15} /><span>Проверить снова</span></button></div>
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------------ сертификаты
function readFile(f: File): Promise<string> {
  return new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => res(String(fr.result).split(",")[1] ?? ""); fr.onerror = () => rej(fr.error); fr.readAsDataURL(f); });
}

function Certs() {
  const [items, setItems] = useState<CaCert[] | null>(null);
  const [add, setAdd] = useState(false); const [del, setDel] = useState<CaCert | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.ldap.certs().then((r) => setItems(r.items)).catch(() => setItems([])), []);
  useEffect(() => { void load(); }, [load]);
  return (
    <>
      <div className="row"><p className="muted small grow">Корневые (Root CA) и промежуточные (Intermediate CA) сертификаты, которыми выдан сертификат контроллера домена. Если сертификатов нет, используется системное хранилище. Закрытые ключи загружать нельзя.</p>
        <button className="btn primary" onClick={() => setAdd(true)}><Icon name="upload" />Добавить сертификат</button></div>
      <div className="table-scroll">
        {!items ? <SkelRows rows={2} cols={4} /> : (
          <table className="table">
            <thead><tr><th>Сертификат</th><th>Тип</th><th>Издатель</th><th>Действует до</th><th className="hide-sm">SHA-256</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{items.map((c) => (
              <tr key={c.id}><td><b>{c.label}</b><span className="sub mono">{c.subject}</span></td><td className="small">{c.type}</td><td className="small mono">{c.issuer}</td>
                <td className="nowrap">{fmtDate(c.not_after)} {c.expired ? <span className="badge err">истёк</span> : c.expires_soon ? <span className="badge warn">скоро истечёт</span> : null}</td>
                <td className="mono small hide-sm" title={c.sha256}>{c.sha256.slice(0, 16)}…</td>
                <td className="actions"><button className="btn mini ghost danger icon" onClick={() => setDel(c)} aria-label={`Удалить сертификат ${c.label}`}><Icon name="trash" size={15} /></button></td></tr>))}
              {!items.length && <tr><td colSpan={6}><Empty icon="key" title="Сертификатов нет">Сервер каталога проверяется по системному хранилищу сертификатов. Для внутреннего CA организации загрузите его корневой сертификат.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {add && <AddCert onClose={() => setAdd(false)} onDone={(n) => { setAdd(false); void load(); show(n ? `Добавлено сертификатов: ${n}` : "Эти сертификаты уже есть"); }} />}
      {del && <ConfirmDialog title="Удалить сертификат?" confirmLabel="Удалить" body={<p>Сертификат «{del.label}» перестанет использоваться для проверки LDAPS. Если контроллер выдан этим CA, вход через каталог перестанет работать.</p>}
        onClose={() => setDel(null)} onConfirm={async () => { await api.admin.ldap.deleteCert(del.id); void load(); }} />}
      {toast}
    </>
  );
}

function AddCert({ onClose, onDone }: { onClose: () => void; onDone: (added: number) => void }) {
  const [pem, setPem] = useState(""); const [b64, setB64] = useState(""); const [fileName, setFileName] = useState(""); const [label, setLabel] = useState("");
  const [preview, setPreview] = useState<{ new: CertPreview[]; existing: CertPreview[] } | null>(null);
  const [confirmNonCa, setConfirmNonCa] = useState(false);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const body = () => (b64 ? { data_base64: b64 } : { pem });
  const doPreview = async () => { setBusy(true); setErr(""); setPreview(null); try { setPreview(await api.admin.ldap.previewCert(body())); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); } };
  const save = async (e: FormEvent) => { e.preventDefault(); setBusy(true); setErr(""); try { const r = await api.admin.ldap.addCert({ ...body(), label, confirm_non_ca: confirmNonCa }); onDone(r.added.length); } catch (x) { setErr((x as ApiError).message); setBusy(false); } };
  const nonCa = preview?.new.some((c) => !c.is_ca);
  return (
    <Modal title="Добавить сертификат CA" onClose={onClose} wide>
      <form onSubmit={save}>
        <div className="cols">
          <label>Файл сертификата (PEM или DER)<input type="file" accept=".pem,.crt,.cer,.der" onChange={async (e) => { const f = e.target.files?.[0]; if (!f) return; setFileName(f.name); setB64(await readFile(f)); setPem(""); setPreview(null); }} />
            {fileName && <span className="help">{fileName}</span>}</label>
          <label>Название<input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Корневой CA организации" maxLength={200} /></label>
        </div>
        <label>…или вставьте текст PEM<textarea className="mono" rows={5} value={pem} onChange={(e) => { setPem(e.target.value); setB64(""); setFileName(""); setPreview(null); }} placeholder="-----BEGIN CERTIFICATE-----" /></label>
        <div className="row"><button type="button" className="btn" onClick={doPreview} disabled={(!pem.trim() && !b64) || busy}><Icon name="eye" size={15} />Показать сведения</button></div>
        {preview && (
          <div className="cert-preview">
            {[...preview.new.map((c) => ({ c, isNew: true })), ...preview.existing.map((c) => ({ c, isNew: false }))].map(({ c, isNew }) => (
              <dl key={c.sha256} className="kv compact card-lite">
                <div><dt>Subject</dt><dd className="mono small">{c.subject}</dd></div><div><dt>Issuer</dt><dd className="mono small">{c.issuer}</dd></div>
                <div><dt>Тип</dt><dd>{c.type}{!isNew && <span className="badge"> уже добавлен</span>}</dd></div><div><dt>Серийный номер</dt><dd className="mono small">{c.serial}</dd></div>
                <div><dt>SHA-256</dt><dd className="mono small">{c.sha256}</dd></div>
                <div><dt>Срок действия</dt><dd>{fmtDate(c.not_before)} — {fmtDate(c.not_after)} {c.expired && <span className="badge err">истёк</span>}{c.not_yet_valid && <span className="badge warn">ещё не действует</span>}</dd></div>
              </dl>))}
            {nonCa && <label className="check"><input type="checkbox" checked={confirmNonCa} onChange={(e) => setConfirmNonCa(e.target.checked)} />Это не CA-сертификат. Всё равно добавить (только если сервер использует самоподписанный сертификат)</label>}
          </div>)}
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button>
          <button className="btn primary" aria-busy={busy} disabled={!preview || !preview.new.length || (nonCa && !confirmNonCa)}><span>Добавить</span></button></div>
      </form>
    </Modal>
  );
}

// ------------------------------------------------------------------------------------------------ правила доступа
function Rules({ sources }: { sources: SourceRef[] }) {
  const [items, setItems] = useState<AccessRuleT[] | null>(null);
  const [conns, setConns] = useState<LdapConn[]>([]);
  const [edit, setEdit] = useState<Partial<AccessRuleT> | null>(null); const [del, setDel] = useState<AccessRuleT | null>(null);
  const load = useCallback(() => { api.admin.ldap.rules().then((r) => setItems(r.items)).catch(() => setItems([])); api.admin.ldap.connections().then((r) => setConns(r.items)).catch(() => undefined); }, []);
  useEffect(() => { load(); }, [load]);
  const names = Object.fromEntries(sources.map((s) => [s.id, s.name]));
  return (
    <>
      <div className="row"><p className="muted small grow">Доменный пользователь входит, только если состоит (в том числе через вложенные группы) хотя бы в одной группе из правил. Действует старшая из подходящих ролей; источники KSC объединяются. Роль и источники обновляются при каждом входе.</p>
        <button className="btn primary" onClick={() => setEdit({ role: "viewer", all_sources: true, source_ids: [], connection_id: null })}><Icon name="plus" />Добавить правило</button></div>
      <div className="table-scroll">
        {!items ? <SkelRows rows={2} cols={4} /> : (
          <table className="table">
            <thead><tr><th>Группа каталога</th><th>Роль</th><th>Источники KSC</th><th>Подключение</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{items.map((r) => (
              <tr key={r.id}><td className="mono small">{r.group_dn}{r.note && <span className="sub">{r.note}</span>}</td><td><span className={`badge ${r.role === "admin" ? "err" : r.role === "analyst" ? "accent" : ""}`}>{ROLE[r.role]}</span></td>
                <td className="small">{r.all_sources ? "все" : r.source_ids.map((s) => names[s] ?? "удалён").join(", ") || "—"}</td><td className="small">{r.connection}</td>
                <td className="actions"><button className="btn mini ghost icon" onClick={() => setEdit(r)} aria-label="Изменить правило"><Icon name="edit" size={15} /></button>
                  <button className="btn mini ghost danger icon" onClick={() => setDel(r)} aria-label="Удалить правило"><Icon name="trash" size={15} /></button></td></tr>))}
              {!items.length && <tr><td colSpan={5}><Empty icon="users" title="Правил нет">Без правил доменные пользователи войти не смогут. Добавьте группы администраторов, аналитиков и пользователей с правом просмотра.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {edit && <RuleDialog value={edit} conns={conns} sources={sources} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); load(); }} />}
      {del && <ConfirmDialog title="Удалить правило?" confirmLabel="Удалить" body={<p>Участники группы «{del.group_dn}» при следующем входе потеряют роль «{ROLE[del.role]}» (если нет других правил).</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.ldap.deleteRule(del.id); load(); }} />}
    </>
  );
}

function RuleDialog({ value, conns, sources, onClose, onSaved }: { value: Partial<AccessRuleT>; conns: LdapConn[]; sources: SourceRef[]; onClose: () => void; onSaved: () => void }) {
  const [v, setV] = useState(value);
  const [q, setQ] = useState(""); const [found, setFound] = useState<{ dn: string; name: string; description: string; connection: string }[] | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const find = async () => { setFound(null); try { const r = await api.admin.ldap.groups(q); setFound(r.items); if (r.errors.length) setErr(r.errors.join("; ")); } catch (x) { setErr((x as ApiError).message); } };
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    const body = { connection_id: v.connection_id ?? null, group_dn: (v.group_dn ?? "").trim(), role: v.role ?? "viewer", all_sources: !!v.all_sources, source_ids: v.source_ids ?? [], note: v.note ?? null };
    try { if (v.id) await api.admin.ldap.updateRule(v.id, body); else await api.admin.ldap.createRule(body); onSaved(); } catch (x) { setErr((x as ApiError).message); setBusy(false); }
  };
  return (
    <Modal title={v.id ? "Правило доступа" : "Новое правило доступа"} onClose={onClose} wide>
      <form onSubmit={submit}>
        <label>Группа каталога (DN)<input className="mono" value={v.group_dn ?? ""} onChange={(e) => setV({ ...v, group_dn: e.target.value })} required placeholder="CN=KAV-Admins,OU=Groups,DC=example,DC=local" autoFocus /></label>
        <div className="row group-find"><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Найти группу в каталоге по названию" aria-label="Поиск группы" onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); void find(); } }} />
          <button type="button" className="btn" onClick={find} disabled={q.trim().length < 2}><Icon name="search" size={15} />Найти</button></div>
        {found && <ul className="rows found-groups">{found.map((g) => <li key={g.dn}><button type="button" className="link-btn" onClick={() => { setV({ ...v, group_dn: g.dn }); setFound(null); }}>{g.name}</button><span className="sub mono">{g.dn}</span><span className="muted small">{g.connection}</span></li>)}
          {!found.length && <li className="muted small">Ничего не найдено</li>}</ul>}
        <div className="cols">
          <label>Роль<select value={v.role} onChange={(e) => setV({ ...v, role: e.target.value as AccessRuleT["role"] })}><option value="viewer">Просмотр</option><option value="analyst">Аналитик</option><option value="admin">Администратор</option></select></label>
          <label>Подключение<select value={v.connection_id ?? ""} onChange={(e) => setV({ ...v, connection_id: e.target.value || null })}><option value="">Любое</option>{conns.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
        </div>
        <label className="check"><input type="checkbox" className="switch" checked={!!v.all_sources} onChange={(e) => setV({ ...v, all_sources: e.target.checked })} />Все источники KSC</label>
        {!v.all_sources && <div className="source-checks">{sources.map((s) => <label key={s.id} className="check"><input type="checkbox" checked={(v.source_ids ?? []).includes(s.id)}
          onChange={() => setV({ ...v, source_ids: (v.source_ids ?? []).includes(s.id) ? (v.source_ids ?? []).filter((x) => x !== s.id) : [...(v.source_ids ?? []), s.id] })} />{s.name}</label>)}</div>}
        <label>Комментарий<input value={v.note ?? ""} onChange={(e) => setV({ ...v, note: e.target.value })} maxLength={500} /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy}><span>Сохранить</span></button></div>
      </form>
    </Modal>
  );
}

function CheckLogin() {
  const [login, setLogin] = useState(""); const [pw, setPw] = useState(""); const [domain, setDomain] = useState("");
  const [conns, setConns] = useState<LdapConn[]>([]);
  const [r, setR] = useState<Awaited<ReturnType<typeof api.admin.ldap.checkUser>> | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { api.admin.ldap.connections().then((x) => setConns(x.items.filter((c) => c.enabled))).catch(() => undefined); }, []);
  const run = async (e: FormEvent) => { e.preventDefault(); setBusy(true); setErr(""); setR(null); try { setR(await api.admin.ldap.checkUser(login.trim(), pw, domain)); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); setPw(""); } };
  return (
    <div className="card narrow">
      <form onSubmit={run}>
        <p className="muted small lead-in">Тот же путь, что при входе, но без открытия сессии: поиск имени в доменах, пароль (если указан), группы, правила доступа и второй фактор. На каждом шаге — причина ошибки. Пароль не сохраняется и не пишется в журналы.</p>
        <div className="cols">
          <label>Имя пользователя<input value={login} onChange={(e) => setLogin(e.target.value)} placeholder="ivan.petrov" autoComplete="off" spellCheck={false} required /></label>
          <label>Пароль (необязательно)<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" /></label>
        </div>
        {conns.length > 1 && <label>Домен<select value={domain} onChange={(e) => setDomain(e.target.value)}><option value="">Определить автоматически, как при входе</option>{conns.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>}
        <div className="row"><button className="btn primary" aria-busy={busy}><Icon name="key" size={15} /><span>Проверить вход</span></button></div>
      </form>
      {err && <div className="alert error mt-sm" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {r && <div className="mt-sm"><StageList result={r} okText={r.stages.some((s) => s.stage === "auth" && s.ok) ? "Вход будет выполнен" : "Пользователь найден, доступ определён"} />
        {r.found && (
          <dl className="kv mt-sm">
            <div><dt>Пользователь</dt><dd>{r.display_name} ({r.username}){r.disabled && <span className="badge err">отключён в каталоге</span>}</dd></div>
            <div><dt>Подключение</dt><dd>{r.connection}</dd></div>
            <div><dt>Роль в KAV Checker</dt><dd>{r.role ? <b>{ROLE[r.role]}</b> : <span className="bad-text">нет — вход будет отклонён</span>}</dd></div>
            <div><dt>Источники KSC</dt><dd>{r.all_sources ? "все" : r.sources?.join(", ") || "—"}</dd></div>
            <div><dt>Подходящие правила</dt><dd className="mono small">{r.rules?.join("; ") || "—"}</dd></div>
            <div><dt>Групп</dt><dd><details className="disclosure"><summary>{r.groups?.length ?? 0}</summary><ul className="mono small group-list">{r.groups?.map((g) => <li key={g}>{g}</li>)}</ul></details></dd></div>
          </dl>)}
      </div>}
    </div>
  );
}
