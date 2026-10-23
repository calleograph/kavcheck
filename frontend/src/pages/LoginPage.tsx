import { FormEvent, useState } from "react";
import { api, ApiError, type Me } from "../api";
import { Icon } from "../components/Icons";

export default function LoginPage({ onLogin }: { onLogin: (m: Me) => void }) {
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError("");
    try { onLogin(await api.login(login.trim(), password)); }
    catch (err) { const ae = err as ApiError; setError(ae.status === 429 && ae.retryAfter ? `Слишком много неудачных попыток. Повторите через ${Math.max(1, Math.ceil(ae.retryAfter / 60))} мин.` : ae.message); setPassword(""); }
    finally { setBusy(false); }
  };
  return (
    <div className="login-wrap">
      <div className="login">
        <span className="brand"><Icon name="logo" size={30} /> KAV Checker</span>
        <p className="tag">Центр аудита и отчётности Kaspersky Security Center</p>
        <form className="card" onSubmit={submit} aria-label="Вход">
          <label>Логин<input value={login} onChange={(e) => setLogin(e.target.value)} autoComplete="username" autoFocus required maxLength={256} autoCapitalize="none" spellCheck={false} placeholder="admin или доменный логин" /></label>
          <label>Пароль
            <span className="row tight">
              <input type={show ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required maxLength={512} />
              <button type="button" className="btn ghost mini" onClick={() => setShow((s) => !s)} aria-label={show ? "Скрыть пароль" : "Показать пароль"} aria-pressed={show}><Icon name={show ? "eyeOff" : "eye"} size={18} /></button>
            </span>
          </label>
          {error && <div className="alert error" role="alert">{error}</div>}
          <button className="btn primary" disabled={busy || !login || !password}>{busy ? <><i className="spin" aria-hidden /> Проверка…</> : <>Войти <Icon name="arrowR" size={17} /></>}</button>
          <div className="foot">Локальная учётная запись или учётная запись каталога (LDAP), если он настроен администратором.</div>
        </form>
      </div>
    </div>
  );
}
