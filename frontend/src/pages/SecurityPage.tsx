import { FormEvent, useEffect, useState } from "react";
import { api, type ApiError, type Me, type TotpStatus } from "../api";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { PageHead, SkelRows } from "../components/ui";
import { fmt } from "../util";
import ChangePasswordPage from "./ChangePasswordPage";

const POLICY: Record<string, string> = { off: "отключена администратором", optional: "по желанию", admins: "обязательна для администраторов", all: "обязательна для всех", groups: "обязательна для групп каталога" };

/** Безопасность входа: двухфакторная аутентификация (TOTP) и, для локальной учётной записи, смена пароля.
 *  forced — политика требует 2FA, а она не настроена: до настройки остальные разделы недоступны. */
export default function SecurityPage({ me, forced, onEnrolled, onLogout }: { me: Me; forced?: boolean; onEnrolled?: () => void; onLogout: () => void }) {
  const [st, setSt] = useState<TotpStatus | null>(null);
  const [err, setErr] = useState("");
  const [dialog, setDialog] = useState<"enable" | "disable" | "codes" | null>(null);
  const [toast, show] = useToast();
  const load = () => api.totp.status().then(setSt).catch((e) => setErr((e as ApiError).message));
  useEffect(() => { void load(); }, []);
  const body = (
    <div className="stack narrow">
      {forced && <div className="alert warn"><Icon name="key" /><div className="alert-body"><b>Нужна двухфакторная аутентификация.</b> Политика безопасности требует подтверждать вход кодом с телефона. Настройте её, чтобы продолжить работу.</div></div>}
      <div className="card">
        <div className="card-head"><h2>Двухфакторная аутентификация</h2>{st && <span className={`badge ${st.enabled ? "ok" : st.required ? "warn" : ""}`}>{st.enabled ? "включена" : "выключена"}</span>}</div>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        {!st ? <SkelRows rows={2} cols={2} /> : (<>
          <p className="muted small lead-in">После пароля вход подтверждается шестизначным кодом из приложения-аутентификатора (Яндекс Ключ, Google или Microsoft Authenticator, FreeOTP, Aegis). Политика: {POLICY[st.policy] ?? st.policy}.</p>
          {st.enabled ? (<>
            <dl className="kv"><div><dt>Включена</dt><dd>{fmt(st.enabled_at)}</dd></div><div><dt>Резервных кодов осталось</dt><dd className={st.backup_left <= 2 ? "warn-text" : ""}>{st.backup_left} из 10</dd></div></dl>
            <div className="form-actions"><button className="btn" onClick={() => setDialog("codes")}><Icon name="refresh" />Новые резервные коды</button>
              {!st.required && <button className="btn ghost danger" onClick={() => setDialog("disable")}>Отключить</button>}
              {st.required && <span className="help">Отключить нельзя: политика требует второй фактор.</span>}</div>
          </>) : st.available ? (
            <div className="form-actions"><button className="btn primary" onClick={() => setDialog("enable")}><Icon name="key" />Включить</button></div>
          ) : <p className="muted small">Недоступна: {st.policy === "off" ? "отключена администратором" : "на сервере не задан ключ шифрования APP_MASTER_KEY"}.</p>}
        </>)}
      </div>
      {forced && <div className="row"><button className="btn ghost" onClick={onLogout}>Выйти</button></div>}
    </div>
  );
  return (
    <section className={forced ? "forced-page" : ""}>
      <PageHead title="Безопасность входа" lede={`${me.user.display_name} · ${me.user.local ? "локальная учётная запись" : "учётная запись домена"}`} />
      {body}
      {!forced && me.user.local && <div className="section-gap"><ChangePasswordPage inline embedded onDone={() => show("Пароль изменён; другие сеансы завершены")} onLogout={onLogout} /></div>}
      {dialog === "enable" && <EnableDialog onClose={() => setDialog(null)} onDone={() => { setDialog(null); void load(); show("Двухфакторная аутентификация включена"); onEnrolled?.(); }} />}
      {dialog === "disable" && <PasswordCodeDialog title="Отключить двухфакторную аутентификацию" action="Отключить" danger onClose={() => setDialog(null)}
        submit={async (p, c) => { await api.totp.disable(p, c); setDialog(null); void load(); show("Двухфакторная аутентификация отключена"); }} />}
      {dialog === "codes" && <CodesDialog onClose={() => { setDialog(null); void load(); }} />}
      {toast}
    </section>
  );
}

function EnableDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState(""); const [setup, setSetup] = useState<{ secret: string; uri: string; qr_svg: string } | null>(null);
  const [code, setCode] = useState(""); const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const step1 = async (e: FormEvent) => { e.preventDefault(); setBusy(true); setErr(""); try { setSetup(await api.totp.setup(pw)); setPw(""); } catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); } };
  const step2 = async (e: FormEvent) => { e.preventDefault(); setBusy(true); setErr(""); try { setCodes((await api.totp.enable(code)).backup_codes); } catch (x) { setErr((x as ApiError).message); setCode(""); } finally { setBusy(false); } };
  return (
    <Modal title="Включить двухфакторную аутентификацию" onClose={codes ? onDone : onClose}>
      {codes ? <BackupCodes codes={codes} onDone={onDone} /> : !setup ? (
        <form onSubmit={step1}>
          <p className="muted small mb">Подтвердите личность паролем. Затем отсканируйте QR-код в приложении-аутентификаторе.</p>
          <label>Пароль<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" autoFocus required /></label>
          {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={!pw}><span>Продолжить</span></button></div>
        </form>
      ) : (
        <form onSubmit={step2}>
          <div className="totp-setup">
            {/* QR формирует сервер (segno); SVG без скриптов */}
            <div className="qr" aria-label="QR-код для приложения-аутентификатора" role="img" dangerouslySetInnerHTML={{ __html: setup.qr_svg }} />
            <div className="stack">
              <p className="small">1. Отсканируйте QR-код в приложении. Если камера недоступна, введите ключ вручную:</p>
              <code className="secret mono">{setup.secret}</code>
              <p className="small">2. Введите шестизначный код, который показывает приложение.</p>
              <label>Код из приложения<input className="otp" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" autoFocus required placeholder="000000" /></label>
            </div>
          </div>
          {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={code.length !== 6}><span>Включить</span></button></div>
        </form>
      )}
    </Modal>
  );
}

function BackupCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <div className="alert warn"><Icon name="alert" /><div className="alert-body"><b>Сохраните резервные коды.</b> Они показываются один раз. Каждый код позволяет войти без телефона — один раз.</div></div>
      <ol className="backup-codes mono">{codes.map((c) => <li key={c}>{c}</li>)}</ol>
      <div className="modal-foot"><button type="button" className="btn ghost" onClick={async () => { try { await navigator.clipboard.writeText(codes.join("\n")); setCopied(true); } catch { setCopied(false); } }}>
        <Icon name={copied ? "check" : "copy"} />{copied ? "Скопировано" : "Скопировать"}</button><button type="button" className="btn primary" onClick={onDone}>Я сохранил коды</button></div>
    </div>
  );
}

function PasswordCodeDialog({ title, action, danger, onClose, submit }: { title: string; action: string; danger?: boolean; onClose: () => void; submit: (p: string, c: string) => Promise<void> }) {
  const [pw, setPw] = useState(""); const [code, setCode] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  return (
    <Modal title={title} onClose={onClose}>
      <form onSubmit={async (e) => { e.preventDefault(); setBusy(true); setErr(""); try { await submit(pw, code); } catch (x) { setErr((x as ApiError).message); setBusy(false); } }}>
        <label>Пароль<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" autoFocus required /></label>
        <label>Код из приложения<input className="otp" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" required placeholder="000000" /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className={`btn ${danger ? "danger" : "primary"}`} aria-busy={busy} disabled={!pw || code.length !== 6}><span>{action}</span></button></div>
      </form>
    </Modal>
  );
}

function CodesDialog({ onClose }: { onClose: () => void }) {
  const [codes, setCodes] = useState<string[] | null>(null);
  if (codes) return <Modal title="Новые резервные коды" onClose={onClose}><BackupCodes codes={codes} onDone={onClose} /></Modal>;
  return <PasswordCodeDialog title="Новые резервные коды" action="Выпустить коды" onClose={onClose} submit={async (p, c) => { setCodes((await api.totp.backupCodes(p, c)).backup_codes); }} />;
}
