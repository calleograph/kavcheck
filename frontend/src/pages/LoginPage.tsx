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
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [backup, setBackup] = useState(false);
  const fail = (err: unknown) => { const ae = err as ApiError; setError(ae.status === 429 && ae.retryAfter ? `Слишком много неудачных попыток. Повторите через ${Math.max(1, Math.ceil(ae.retryAfter / 60))} мин.` : ae.message); };
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const r = await api.login(login.trim(), password);
      if ("totp_required" in r) { setChallenge(r.challenge); setCode(""); setPassword(""); } else onLogin(r);
    } catch (err) { fail(err); setPassword(""); } finally { setBusy(false); }
  };
  const submitCode = async (e: FormEvent) => {
    e.preventDefault(); if (!challenge) return; setBusy(true); setError("");
    try { onLogin(await api.loginTotp(challenge, code)); }
    catch (err) { const ae = err as ApiError; if (ae.code === "totp_expired") { setChallenge(null); } fail(err); setCode(""); } finally { setBusy(false); }
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
        {challenge ? (
          <form className="login-card" onSubmit={submitCode} aria-label="Подтверждение входа">
            <h2>Подтверждение входа</h2>
            <p className="lede">{backup ? "Введите один из резервных кодов, выданных при включении двухфакторной аутентификации. Каждый код действует один раз." : "Введите шестизначный код из приложения-аутентификатора на телефоне."}</p>
            <label>{backup ? "Резервный код" : "Код из приложения"}
              <input className={backup ? "mono" : "otp"} value={code} onChange={(e) => setCode(backup ? e.target.value : e.target.value.replace(/\D/g, "").slice(0, 6))} autoFocus required
                inputMode={backup ? "text" : "numeric"} autoComplete="one-time-code" maxLength={backup ? 20 : 6} placeholder={backup ? "xxxxx-xxxxx" : "000000"} aria-describedby="otp-help" /></label>
            {error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{error}</div></div>}
            <button className="btn primary lg" aria-busy={busy} disabled={backup ? code.replace(/[^a-z0-9]/gi, "").length < 10 : code.length !== 6}><span>Подтвердить</span></button>
            <p className="foot" id="otp-help"><button type="button" className="link-btn" onClick={() => { setBackup(!backup); setCode(""); setError(""); }}>{backup ? "Ввести код из приложения" : "Нет доступа к телефону — ввести резервный код"}</button>
              <br /><button type="button" className="link-btn" onClick={() => { setChallenge(null); setError(""); }}>Войти под другой учётной записью</button></p>
          </form>
        ) : (
        <form className="login-card" onSubmit={submit} aria-label="Вход">
          <h2>Вход</h2>
          <p className="lede">Учётная запись домена или локальная учётная запись KAV Checker.</p>
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
          <p className="foot">Доменная учётная запись: логин, DOMAIN\\логин или логин@домен. Пароли не записываются в журналы; после серии неверных попыток вход временно блокируется.</p>
        </form>)}
      </div>
    </div>
  );
}
