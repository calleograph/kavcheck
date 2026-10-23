import { FormEvent, useState } from "react";
import { api, type ApiError } from "../api";

export default function ChangePasswordPage({ onDone, onLogout, inline = false }: { onDone: () => void; onLogout: () => void; inline?: boolean }) {
  const [cur, setCur] = useState(""); const [n1, setN1] = useState(""); const [n2, setN2] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (n1 !== n2) { setErr("Пароли не совпадают."); return; }
    setBusy(true); setErr("");
    try { await api.changePassword(cur, n1); onDone(); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  };
  const form = (
    <form className="card form" onSubmit={submit} style={{ maxWidth: 440 }}>
      <h2>{inline ? "Смена пароля" : "Смените пароль"}</h2>
      {!inline && <p className="muted">Вы вошли с первичным или сброшенным паролем. Задайте новый: не короче 12 символов, минимум два вида символов.</p>}
      <label>Текущий пароль<input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" required autoFocus /></label>
      <label>Новый пароль<input type="password" value={n1} onChange={(e) => setN1(e.target.value)} autoComplete="new-password" required minLength={12} /></label>
      <label>Повторите новый пароль<input type="password" value={n2} onChange={(e) => setN2(e.target.value)} autoComplete="new-password" required /></label>
      {err && <div className="alert error" role="alert">{err}</div>}
      <div className="row"><button className="btn primary" disabled={busy}>Сохранить</button>{!inline && <button type="button" className="btn ghost" onClick={onLogout}>Выйти</button>}</div>
    </form>
  );
  return inline ? form : <div className="login-wrap"><div className="login">{form}</div></div>;
}
