import { FormEvent, useEffect, useState } from "react";
import { api, type ApiError, type DiagResult, type SettingsValues } from "../../api";
import { SecretInput, StageList, secretToSend } from "../../components/Common";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows } from "../../components/ui";

/** LDAP/LDAPS: подключение, Base DN, Bind DN, фильтры, группы ролей, проверка соединения и тестовый вход. */
export default function LdapAdmin() {
  const [v, setV] = useState<SettingsValues | null>(null);
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [diag, setDiag] = useState<DiagResult | null>(null);
  const [testLogin, setTestLogin] = useState(""); const [testPw, setTestPw] = useState("");
  const [busy, setBusy] = useState<"" | "save" | "test">("");
  const [toast, show] = useToast();
  useEffect(() => { api.admin.settings("ldap").then(setV).catch((e) => setErr((e as ApiError).message)); }, []);
  if (!v) return err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <div className="card"><SkelRows rows={6} cols={2} /></div>;
  const set = (k: string, val: string | number | boolean) => setV({ ...v, [k]: val });
  const str = (k: string) => String(v[k] ?? "");
  const save = async (e: FormEvent) => {
    e.preventDefault(); setBusy("save"); setErr(""); setDiag(null);
    const body: SettingsValues = { ...v }; delete body.bind_password_set;
    const s = secretToSend(pw); if (s !== undefined) body.bind_password = s;
    try { setV(await api.admin.saveSettings("ldap", body)); setPw(""); show("Настройки LDAP сохранены"); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(""); }
  };
  const test = async () => { setBusy("test"); setDiag(null); try { setDiag(await api.admin.ldapTest(testLogin || undefined, testPw || undefined)); } catch (x) { setDiag({ ok: false, stages: [{ stage: "error", ok: false, message: (x as ApiError).message, ms: 0 }] }); } finally { setBusy(""); setTestPw(""); } };
  return (
    <div className="split">
      <form className="card" onSubmit={save}>
        <div className="card-head"><h2>Подключение к каталогу</h2><div className="spacer" />
          <label className="check" style={{ margin: 0 }}><input type="checkbox" className="switch" checked={!!v.enabled} onChange={(e) => set("enabled", e.target.checked)} />Вход по LDAP</label></div>
        <p className="muted small" style={{ marginBottom: 14 }}>Сервисной учётной записи достаточно прав на чтение. Роль пользователя определяется членством в группах; без настроенной группы вход по LDAP невозможен. Локальный администратор работает всегда.</p>
        <fieldset className="group"><legend>Сервер</legend>
          <div className="cols">
            <label>Сервер<input className="mono" value={str("host")} onChange={(e) => set("host", e.target.value)} placeholder="dc1.example.local" spellCheck={false} /></label>
            <label>Протокол<select value={str("protocol")} onChange={(e) => setV({ ...v, protocol: e.target.value, port: e.target.value === "ldaps" ? 636 : 389 })}><option value="ldaps">LDAPS</option><option value="starttls">LDAP + STARTTLS</option><option value="ldap">LDAP без шифрования</option></select></label>
          </div>
          <div className="cols">
            <label>Порт<input type="number" min={1} max={65535} value={Number(v.port ?? 636)} onChange={(e) => set("port", Number(e.target.value))} /></label>
            <label>Тайм-аут, с<input type="number" min={1} max={60} value={Number(v.timeout_s ?? 5)} onChange={(e) => set("timeout_s", Number(e.target.value))} /></label>
          </div>
          {str("protocol") === "ldap" && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Без шифрования пароли пользователей передаются по сети открыто. Используйте только в изолированной тестовой среде.</div></div>}
          <label className="check"><input type="checkbox" className="switch" checked={!!v.verify_cert} onChange={(e) => set("verify_cert", e.target.checked)} />Проверять сертификат сервера</label>
          <label>Сертификат удостоверяющего центра<textarea className="mono" rows={3} value={str("ca_pem")} onChange={(e) => set("ca_pem", e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" spellCheck={false} /><span className="help">PEM корневого сертификата, если сертификат контроллера домена выпущен вашим ЦС</span></label>
        </fieldset>
        <fieldset className="group"><legend>Поиск пользователей</legend>
          <label>Base DN<input className="mono" value={str("base_dn")} onChange={(e) => set("base_dn", e.target.value)} placeholder="DC=example,DC=local" spellCheck={false} /></label>
          <label>Bind DN сервисной записи<input className="mono" value={str("bind_dn")} onChange={(e) => set("bind_dn", e.target.value)} placeholder="CN=svc-kavcheck,OU=Service,DC=example,DC=local" spellCheck={false} autoComplete="off" /></label>
          <SecretInput label="Пароль сервисной записи" isSet={!!v.bind_password_set} value={pw} onChange={setPw} />
          <div className="cols">
            <label>Фильтр пользователя<input className="mono" value={str("user_filter")} onChange={(e) => set("user_filter", e.target.value)} spellCheck={false} /><span className="help">{"{login}"} заменяется введённым логином</span></label>
            <label>Фильтр групп<input className="mono" value={str("group_filter")} onChange={(e) => set("group_filter", e.target.value)} spellCheck={false} /></label>
          </div>
          <label className="check"><input type="checkbox" className="switch" checked={!!v.nested_groups} onChange={(e) => set("nested_groups", e.target.checked)} /><span className="check-body">Учитывать вложенные группы<span className="help">Для Active Directory</span></span></label>
          <details className="disclosure"><summary>Атрибуты каталога</summary>
            <div className="cols" style={{ marginTop: 10 }}>
              <label>Логин<input className="mono" value={str("login_attribute")} onChange={(e) => set("login_attribute", e.target.value)} /></label>
              <label>Отображаемое имя<input className="mono" value={str("display_name_attribute")} onChange={(e) => set("display_name_attribute", e.target.value)} /></label>
              <label>Электронная почта<input className="mono" value={str("email_attribute")} onChange={(e) => set("email_attribute", e.target.value)} /></label>
              <label>Идентификатор<input className="mono" value={str("guid_attribute")} onChange={(e) => set("guid_attribute", e.target.value)} /></label>
            </div>
          </details>
        </fieldset>
        <fieldset className="group"><legend>Роли по группам</legend>
          <label>Администраторы<input className="mono" value={str("admin_group_dn")} onChange={(e) => set("admin_group_dn", e.target.value)} placeholder="CN=KAVCheck-Admins,OU=Groups,DC=example,DC=local" spellCheck={false} /></label>
          <label>Аналитики<input className="mono" value={str("analyst_group_dn")} onChange={(e) => set("analyst_group_dn", e.target.value)} placeholder="CN=KAVCheck-Analysts,OU=Groups,DC=example,DC=local" spellCheck={false} /></label>
          <label>Просмотр<input className="mono" value={str("viewer_group_dn")} onChange={(e) => set("viewer_group_dn", e.target.value)} placeholder="CN=KAVCheck-Viewers,OU=Groups,DC=example,DC=local" spellCheck={false} /><span className="help">Пусто — роль «просмотр» получают все пользователи каталога, если задана группа администраторов или аналитиков</span></label>
        </fieldset>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="form-actions"><button className="btn primary" aria-busy={busy === "save"}><span>Сохранить</span></button></div>
      </form>
      <div className="card">
        <h2>Проверка</h2>
        <p className="muted small" style={{ marginBottom: 14 }}>Проверяются сохранённые настройки: соединение, вход сервисной записи, чтение Base DN. Укажите логин и пароль, чтобы проверить вход и увидеть роль пользователя. Они не сохраняются.</p>
        <label>Логин<input value={testLogin} onChange={(e) => setTestLogin(e.target.value)} autoCapitalize="none" autoComplete="off" /></label>
        <label>Пароль<input type="password" value={testPw} onChange={(e) => setTestPw(e.target.value)} autoComplete="new-password" /></label>
        <button className="btn" aria-busy={busy === "test"} onClick={() => void test()}><Icon name="plug" /><span>Проверить подключение</span></button>
        {diag && <StageList result={diag} />}
        {diag?.test_user && <div className="alert ok" style={{ marginTop: 12 }}><Icon name="checkCircle" /><div className="alert-body"><b>{diag.test_user.display_name}</b> ({diag.test_user.username}) получит роль <b>{({ admin: "администратор", analyst: "аналитик", viewer: "просмотр" } as Record<string, string>)[diag.test_user.role ?? ""] ?? "— нет (не входит в группы ролей)"}</b>. Групп: {diag.test_user.groups.length}.</div></div>}
      </div>
      {toast}
    </div>
  );
}
