import { FormEvent, useState } from "react";
import { api, type ApiError } from "../api";
import { Icon } from "../components/Icons";
import { PageHead } from "../components/ui";

export default function ChangePasswordPage({ onDone, onLogout, inline = false, embedded = false }: { onDone: () => void; onLogout: () => void; inline?: boolean; embedded?: boolean }) {
  const [cur, setCur] = useState(""); const [n1, setN1] = useState(""); const [n2, setN2] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const mismatch = n2 !== "" && n1 !== n2;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (n1 !== n2) { setErr("Новые пароли не совпадают."); return; }
    setBusy(true); setErr("");
    try { await api.changePassword(cur, n1); setCur(""); setN1(""); setN2(""); onDone(); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  };
  const form = (
    <form className={inline ? "card form narrow-form" : "login-card"} onSubmit={submit}>
      {embedded && <><h2>Смена пароля</h2><p className="muted small lead-in">После смены пароля другие сеансы этой учётной записи завершатся.</p></>}
      {!inline && <><h2>Задайте свой пароль</h2><p className="lede">Вы вошли с первичным или сброшенным паролем. Новый пароль — не короче 12 символов, минимум два вида символов.</p></>}
      <label>Текущий пароль<input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" required autoFocus /></label>
      <label>Новый пароль<input type="password" value={n1} onChange={(e) => setN1(e.target.value)} autoComplete="new-password" required minLength={12} />
        <span className="help">Не короче 12 символов: буквы разного регистра, цифры или знаки.</span></label>
      <label>Повторите новый пароль<input type="password" value={n2} onChange={(e) => setN2(e.target.value)} autoComplete="new-password" required aria-invalid={mismatch} />
        {mismatch && <span className="field-err">Пароли не совпадают</span>}</label>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="row"><button className="btn primary" aria-busy={busy} disabled={!cur || n1.length < 12 || mismatch}><span>Сохранить пароль</span></button>{!inline && <button type="button" className="btn ghost" onClick={onLogout}>Выйти</button>}</div>
    </form>
  );
  if (embedded) return form;
  if (inline) return <section><PageHead title="Смена пароля" lede="После смены пароля другие сеансы этой учётной записи завершатся." />{form}</section>;
  return <div className="login single"><div className="login-form">{form}</div></div>;
}
