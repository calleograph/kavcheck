import { FormEvent, useEffect, useState } from "react";
import { api, type ApiError, type DiagResult, type SettingsValues } from "../../api";
import { SecretInput, StageList, secretToSend } from "../../components/Common";

/** LDAP/LDAPS: параметры подключения, Base DN, Bind DN, фильтры, группы ролей, проверка соединения и тестовый вход. */
export default function LdapAdmin() {
  const [v, setV] = useState<SettingsValues | null>(null);
  const [pw, setPw] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [diag, setDiag] = useState<DiagResult | null>(null);
  const [testLogin, setTestLogin] = useState(""); const [testPw, setTestPw] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.admin.settings("ldap").then(setV).catch((e) => setMsg({ ok: false, text: (e as ApiError).message })); }, []);
  if (!v) return <div className="muted">Загрузка…</div>;
  const set = (k: string, val: string | number | boolean) => setV({ ...v, [k]: val });
  const str = (k: string) => String(v[k] ?? "");
  const save = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg(null); setDiag(null);
    const body: SettingsValues = { ...v }; delete body.bind_password_set;
    const s = secretToSend(pw); if (s !== undefined) body.bind_password = s;
    try { setV(await api.admin.saveSettings("ldap", body)); setPw(""); setMsg({ ok: true, text: "Сохранено" }); } catch (x) { setMsg({ ok: false, text: (x as ApiError).message }); } finally { setBusy(false); }
  };
  const test = async () => { setBusy(true); setDiag(null); try { setDiag(await api.admin.ldapTest(testLogin || undefined, testPw || undefined)); } catch (x) { setDiag({ ok: false, stages: [{ stage: "error", ok: false, message: (x as ApiError).message, ms: 0 }] }); } finally { setBusy(false); setTestPw(""); } };
  return (
    <section>
      <h2>Каталог LDAP / Active Directory</h2>
      <p className="muted">Вход доменных пользователей. Сервисной учётной записи достаточно прав на чтение. Роль пользователя определяется членством в группах (DN); без единой настроенной группы вход по LDAP невозможен. Локальный администратор продолжает работать всегда.</p>
      <form className="card form" onSubmit={save}>
        <label className="check"><input type="checkbox" checked={!!v.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Вход по LDAP включён</label>
        <fieldset className="group"><legend>Сервер</legend>
          <div className="cols">
            <label>Сервер<input value={str("host")} onChange={(e) => set("host", e.target.value)} placeholder="dc1.example.local" spellCheck={false} /></label>
            <label>Протокол<select value={str("protocol")} onChange={(e) => { set("protocol", e.target.value); if (e.target.value === "ldaps") set("port", 636); else set("port", 389); }}><option value="ldaps">LDAPS (636)</option><option value="starttls">LDAP + STARTTLS (389)</option><option value="ldap">LDAP без шифрования (не рекомендуется)</option></select></label>
            <label>Порт<input type="number" min={1} max={65535} value={Number(v.port ?? 636)} onChange={(e) => set("port", Number(e.target.value))} /></label>
            <label>Тайм-аут, с<input type="number" min={1} max={60} value={Number(v.timeout_s ?? 5)} onChange={(e) => set("timeout_s", Number(e.target.value))} /></label>
          </div>
          <label className="check"><input type="checkbox" checked={!!v.verify_cert} onChange={(e) => set("verify_cert", e.target.checked)} /> Проверять сертификат сервера</label>
          <label>Сертификат ЦС (PEM, необязательно)<textarea rows={4} value={str("ca_pem")} onChange={(e) => set("ca_pem", e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} /><span className="help">Корневой сертификат вашего удостоверяющего центра, если сертификат контроллера домена не доверенный системно.</span></label>
        </fieldset>
        <fieldset className="group"><legend>Поиск</legend>
          <label>Base DN<input value={str("base_dn")} onChange={(e) => set("base_dn", e.target.value)} placeholder="DC=example,DC=local" spellCheck={false} /></label>
          <div className="cols">
            <label>Bind DN (сервисная запись)<input value={str("bind_dn")} onChange={(e) => set("bind_dn", e.target.value)} placeholder="CN=svc-kavcheck,OU=Service,DC=example,DC=local" spellCheck={false} autoComplete="off" /></label>
            <SecretInput label="Пароль сервисной записи" isSet={!!v.bind_password_set} value={pw} onChange={setPw} />
          </div>
          <div className="cols">
            <label>Фильтр пользователя<input value={str("user_filter")} onChange={(e) => set("user_filter", e.target.value)} spellCheck={false} /><span className="help">{"{login}"} заменяется введённым логином</span></label>
            <label>Фильтр групп<input value={str("group_filter")} onChange={(e) => set("group_filter", e.target.value)} spellCheck={false} /></label>
          </div>
          <label className="check"><input type="checkbox" checked={!!v.nested_groups} onChange={(e) => set("nested_groups", e.target.checked)} /> Учитывать вложенные группы (Active Directory, правило LDAP_MATCHING_RULE_IN_CHAIN)</label>
          <details className="group"><summary>Атрибуты (обычно менять не нужно)</summary>
            <div className="cols">
              <label>Логин<input value={str("login_attribute")} onChange={(e) => set("login_attribute", e.target.value)} /></label>
              <label>Отображаемое имя<input value={str("display_name_attribute")} onChange={(e) => set("display_name_attribute", e.target.value)} /></label>
              <label>Электронная почта<input value={str("email_attribute")} onChange={(e) => set("email_attribute", e.target.value)} /></label>
              <label>Идентификатор<input value={str("guid_attribute")} onChange={(e) => set("guid_attribute", e.target.value)} /></label>
            </div>
          </details>
        </fieldset>
        <fieldset className="group"><legend>Роли по группам (DN)</legend>
          <label>Администраторы<input value={str("admin_group_dn")} onChange={(e) => set("admin_group_dn", e.target.value)} placeholder="CN=KAVCheck-Admins,OU=Groups,DC=example,DC=local" spellCheck={false} /></label>
          <label>Аналитики<input value={str("analyst_group_dn")} onChange={(e) => set("analyst_group_dn", e.target.value)} placeholder="CN=KAVCheck-Analysts,OU=Groups,DC=example,DC=local" spellCheck={false} /></label>
          <label>Просмотр<input value={str("viewer_group_dn")} onChange={(e) => set("viewer_group_dn", e.target.value)} placeholder="CN=KAVCheck-Viewers,OU=Groups,DC=example,DC=local" spellCheck={false} /><span className="help">Пусто — роль «просмотр» получают все пользователи каталога, если задана хотя бы группа администраторов или аналитиков.</span></label>
        </fieldset>
        <div className="row"><button className="btn primary" disabled={busy}>Сохранить</button>{msg && <span className={msg.ok ? "ok-text" : "bad-text"}>{msg.text}</span>}</div>
      </form>
      <div className="card form">
        <h3>Проверка сохранённых настроек</h3>
        <p className="muted small">Соединение → вход сервисной записи → чтение Base DN. Для проверки авторизации укажите логин и пароль пользователя: они не сохраняются.</p>
        <div className="cols">
          <label>Тестовый логин<input value={testLogin} onChange={(e) => setTestLogin(e.target.value)} autoCapitalize="none" autoComplete="off" /></label>
          <label>Пароль<input type="password" value={testPw} onChange={(e) => setTestPw(e.target.value)} autoComplete="new-password" /></label>
        </div>
        <button className="btn" onClick={() => void test()} disabled={busy}>{busy ? "Проверка…" : "Проверить подключение"}</button>
        {diag && <StageList result={diag} />}
        {diag?.test_user && <div className="alert ok">Пользователь <b>{diag.test_user.display_name}</b> ({diag.test_user.username}) → роль: <b>{diag.test_user.role ?? "нет (не входит в группы ролей)"}</b>. Групп: {diag.test_user.groups.length}.</div>}
      </div>
    </section>
  );
}
