import { FormEvent, KeyboardEvent, useState } from "react";
import { api, ApiError, type Me } from "../api";
import { Icon, Mark } from "../components/Icons";

/** Декоративный мотив «спектр версий» на экране входа: абстрактные полосы без чисел и данных. */
const BARS = [[5, 3, 2, 1.2, .6], [2.5, 4, 1.5, 1], [6, 2, 1.8], [3, 3, 2.2, 1, .8], [1.6, 5, 2]];

export default function LoginPage({ onLogin }: { onLogin: (m: Me) => void }) {
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError("");
    try { onLogin(await api.login(login.trim(), password)); }
    catch (err) { const ae = err as ApiError; setError(ae.status === 429 && ae.retryAfter ? `Слишком много неудачных попыток. Повторите через ${Math.max(1, Math.ceil(ae.retryAfter / 60))} мин.` : ae.message); setPassword(""); }
    finally { setBusy(false); }
  };
  const checkCaps = (e: KeyboardEvent<HTMLInputElement>) => setCaps(e.getModifierState?.("CapsLock") ?? false);
  return (
    <div className="login">
      <section className="login-art" aria-label="KAV Checker">
        <span className="side-brand"><Mark size={30} />KAV Checker</span>
        <h1>Что установлено, на каких компьютерах и насколько свежи данные</h1>
        <p>Центр аудита Kaspersky Security Center: реестр программ и версий, активность устройств, уязвимости и отчёты XLSX. База KSC только читается.</p>
        <div className="login-bars" aria-hidden>
          {BARS.map((row, r) => (
            <div key={r} className="spectrum-track" style={{ width: `${62 + ((r * 17) % 35)}%` }}>
              {row.map((v, i) => <span key={i} className="sp-seg" style={{ flexGrow: v, flexBasis: 0, ["--seg" as string]: `var(--sp-${Math.min(i + (r % 2), 7)})`, ["--i" as string]: i, ["--r" as string]: r }} />)}
            </div>
          ))}
        </div>
      </section>
      <div className="login-form">
        <form className="login-card" onSubmit={submit} aria-label="Вход">
          <h2>Вход</h2>
          <p className="lede">Локальная учётная запись или учётная запись каталога, если администратор подключил LDAP.</p>
          <label>Логин<input value={login} onChange={(e) => setLogin(e.target.value)} autoComplete="username" autoFocus required maxLength={256} autoCapitalize="none" spellCheck={false} /></label>
          <label>Пароль
            <span className="pw">
              <input type={show ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} onKeyUp={checkCaps} onKeyDown={checkCaps} autoComplete="current-password" required maxLength={512} />
              <button type="button" className="btn ghost icon" onClick={() => setShow((s) => !s)} aria-label={show ? "Скрыть пароль" : "Показать пароль"} aria-pressed={show}><Icon name={show ? "eyeOff" : "eye"} /></button>
            </span>
            {caps && <span className="field-err" role="status">Включён Caps Lock</span>}
          </label>
          {error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{error}</div></div>}
          <button className="btn primary lg" aria-busy={busy} disabled={!login || !password}><span>Войти</span></button>
          <p className="foot">Пароли не записываются в журналы. После серии неверных попыток вход для логина временно блокируется.</p>
        </form>
      </div>
    </div>
  );
}
