import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type AdminUser, type ApiError } from "../../api";
import type { Ctx } from "../../App";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, Segmented, SkelRows } from "../../components/ui";
import { fmt } from "../../util";

const ROLE: Record<string, [string, string]> = { admin: ["Администратор", "accent"], analyst: ["Аналитик", ""], viewer: ["Просмотр", "outline"] };
const RIGHTS: [string, boolean, boolean, boolean][] = [
  ["Программы, компьютеры, уязвимости, состояние защиты, события", true, true, true],
  ["Просмотр и выгрузка готовых отчётов", true, true, true],
  ["Проверка версий: предварительный просмотр", true, true, true],
  ["Формирование отчётов, сохранение и запуск проверок", false, true, true],
  ["Исправления каталога программ", false, true, true],
  ["Источники KSC, пользователи, LDAPS, настройки, обновления, журналы", false, false, true],
];
type Policy = "off" | "optional" | "admins" | "all" | "groups";

/** Права ролей и политика второго фактора. */
function RolesAndPolicy() {
  const [p, setP] = useState<{ totp_policy: Policy; totp_groups: string; totp_issuer: string } | null>(null);
  const [base, setBase] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  useEffect(() => { api.admin.settings("auth_security").then((x) => { setP(x as never); setBase(JSON.stringify(x)); }).catch((e) => setErr((e as ApiError).message)); }, []);
  const save = async () => { if (!p) return; setBusy(true); setErr(""); try { const x = await api.admin.saveSettings("auth_security", p); setP(x as never); setBase(JSON.stringify(x)); show("Политика сохранена"); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); } };
  return (
    <div className="split even section-gap">
      <div className="card flush">
        <div className="card-head"><h2>Права ролей</h2></div>
        <div className="table-scroll flat"><table className="table compact rights">
          <thead><tr><th>Что доступно</th><th className="ta-c">Просмотр</th><th className="ta-c">Аналитик</th><th className="ta-c">Администратор</th></tr></thead>
          <tbody>{RIGHTS.map(([t, v, a, ad]) => <tr key={t}><td>{t}</td>{[v, a, ad].map((x, i) => <td key={i} className="ta-c">{x ? <Icon name="check" size={16} className="ok-text" /> : <span className="faint">—</span>}</td>)}</tr>)}</tbody>
        </table></div>
        <p className="muted small pad">Доменным пользователям роль и источники назначают правила групп (Администрирование → LDAPS → Правила доступа) при каждом входе. Локальные учётные записи — резервный способ входа.</p>
      </div>
      <div className="card">
        <h2>Двухфакторная аутентификация</h2>
        <p className="muted small lead-in">Вход подтверждается кодом из приложения-аутентификатора. При обязательной политике пользователь без 2FA после пароля попадает на страницу её настройки.</p>
        {!p ? <SkelRows rows={2} cols={2} /> : (<>
          <label>Политика<Segmented<Policy> label="Политика второго фактора" value={p.totp_policy} onChange={(x) => setP({ ...p, totp_policy: x })}
            options={[["off", "Отключена"], ["optional", "По желанию"], ["admins", "Администраторам"], ["all", "Всем"], ["groups", "Группам"]]} /></label>
          {p.totp_policy === "groups" && <label>Группы каталога (DN, по одной в строке)<textarea className="mono" rows={3} value={p.totp_groups} onChange={(e) => setP({ ...p, totp_groups: e.target.value })} /></label>}
          <label>Название в приложении-аутентификаторе<input value={p.totp_issuer} onChange={(e) => setP({ ...p, totp_issuer: e.target.value })} maxLength={60} /></label>
          {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          <div className="form-actions"><button className="btn primary" onClick={save} aria-busy={busy} disabled={base === JSON.stringify(p)}><span>Сохранить политику</span></button></div>
        </>)}
        {toast}
      </div>
    </div>
  );
}

function ResetTotp({ user, onClose, onDone }: { user: AdminUser; onClose: () => void; onDone: () => void }) {
  const [pw, setPw] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  return (
    <Modal title={`Сбросить 2FA: ${user.display_name}`} onClose={onClose}>
      <form onSubmit={async (e) => { e.preventDefault(); setBusy(true); setErr(""); try { await api.admin.resetTotp(user.id, pw); onDone(); } catch (x) { setErr((x as ApiError).message); setBusy(false); } }}>
        <p className="muted small mb">Например, при потере телефона. Сеансы пользователя завершатся; при следующем входе он настроит второй фактор заново (если политика его требует). Подтвердите своим паролем.</p>
        <label>Ваш пароль<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" autoFocus required /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn danger" aria-busy={busy} disabled={!pw}><span>Сбросить</span></button></div>
      </form>
    </Modal>
  );
}

export default function UsersAdmin({ ctx }: { ctx: Ctx }) {
  const [items, setItems] = useState<AdminUser[] | null>(null);
  const [q, setQ] = useState(""); const [err, setErr] = useState("");
  const [edit, setEdit] = useState<Partial<AdminUser> & { password?: string; isNew?: boolean } | null>(null);
  const [del, setDel] = useState<AdminUser | null>(null);
  const [reset, setReset] = useState<AdminUser | null>(null);
  const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.users(q).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)), [q]);
  useEffect(() => { const t = window.setTimeout(load, 250); return () => window.clearTimeout(t); }, [load]);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); if (!edit) return; setErr(""); setBusy(true);
    const body = { display_name: edit.display_name, email: edit.email || null, role: edit.role, is_active: edit.is_active, all_sources: edit.all_sources, source_ids: edit.source_ids ?? [], must_change_password: edit.must_change_password, ...(edit.password ? { password: edit.password } : {}) };
    try { if (edit.isNew) await api.admin.createUser({ username: edit.username, ...body }); else await api.admin.patchUser(edit.id!, body); show(edit.isNew ? "Пользователь создан" : "Изменения сохранены"); setEdit(null); await load(); } catch (x) { setErr((x as ApiError).message); }
    setBusy(false);
  };
  const toggleSrc = (id: string) => setEdit((u) => { if (!u) return u; const s = new Set(u.source_ids ?? []); if (s.has(id)) s.delete(id); else s.add(id); return { ...u, source_ids: [...s] }; });
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Имя или логин" aria-label="Поиск пользователя" /></div>
        <button className="btn primary" onClick={() => { setErr(""); setEdit({ isNew: true, username: "", display_name: "", role: "viewer", is_active: true, all_sources: true, source_ids: [], must_change_password: true }); }}><Icon name="plus" />Локальный пользователь</button>
        <p className="note">Доменные пользователи появляются после первого входа; их роль и источники задают правила групп в разделе LDAPS. Права ролей и политика второго фактора — ниже.</p>
      </div>
      {err && !edit && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!items ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr><th>Пользователь</th><th>Вход</th><th>Роль</th><th>Источники</th><th>2FA</th><th>Последний вход</th><th>Статус</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{items.map((u) => { const [rl, rc] = ROLE[u.role]; return (
              <tr key={u.id}><td><b>{u.display_name}</b><span className="sub mono">{u.username}{u.email ? `, ${u.email}` : ""}</span></td><td>{u.auth_source === "local" ? "Локальный" : "Домен (LDAPS)"}</td><td><span className={`badge ${rc}`}>{rl}</span></td>
                <td className="small">{u.role === "admin" || u.all_sources ? "Все" : u.source_ids.map((id) => ctx.sources.find((s) => s.id === id)?.name ?? "удалённый").join(", ") || <span className="warn-text">нет доступа</span>}</td>
                <td>{u.totp_enabled ? <span className="badge ok">включена</span> : <span className="faint small">нет</span>}</td><td className="nowrap">{fmt(u.last_login_at)}</td>
                <td>{u.is_active ? <span className="badge ok"><span className="dot" />активен</span> : <span className="badge warn">отключён</span>}{u.must_change_password && <span className="sub">сменит пароль при входе</span>}</td>
                <td className="actions">{u.totp_enabled && <button className="btn mini ghost" onClick={() => setReset(u)} title="Сбросить двухфакторную аутентификацию (потеря телефона)">Сбросить 2FA</button>}
                  <button className="btn mini ghost icon" aria-label={`Изменить ${u.username}`} onClick={() => { setErr(""); setEdit({ ...u }); }}><Icon name="edit" size={15} /></button>{u.id !== ctx.me.user.id && <button className="btn mini ghost danger icon" aria-label={`Удалить ${u.username}`} onClick={() => setDel(u)}><Icon name="trash" size={15} /></button>}</td></tr>); })}
              {!items.length && <tr><td colSpan={8}><Empty icon="users" title="Никого не найдено">Измените поиск.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {edit && (
        <Modal title={edit.isNew ? "Новый локальный пользователь" : edit.display_name || edit.username || "Пользователь"} onClose={() => setEdit(null)}
          footer={<><button type="button" className="btn ghost" onClick={() => setEdit(null)}>Отмена</button><button type="submit" form="user-form" className="btn primary" aria-busy={busy}><span>{edit.isNew ? "Создать" : "Сохранить"}</span></button></>}>
          <form id="user-form" onSubmit={submit}>
            <div className="cols">
              <label>Логин<input className="mono" value={edit.username ?? ""} onChange={(e) => setEdit({ ...edit, username: e.target.value })} disabled={!edit.isNew} required pattern="[a-z][a-z0-9._-]{2,63}" autoCapitalize="none" autoFocus={edit.isNew} /><span className="help">Строчные латинские буквы, цифры, «.», «_», «-»</span></label>
              <label>Отображаемое имя<input value={edit.display_name ?? ""} onChange={(e) => setEdit({ ...edit, display_name: e.target.value })} maxLength={300} /></label>
            </div>
            <div className="cols">
              <label>Электронная почта<input type="email" value={edit.email ?? ""} onChange={(e) => setEdit({ ...edit, email: e.target.value })} /></label>
              <label>Роль<select value={edit.role} onChange={(e) => setEdit({ ...edit, role: e.target.value as AdminUser["role"] })} disabled={edit.id === ctx.me.user.id}><option value="admin">Администратор</option><option value="analyst">Аналитик</option><option value="viewer">Просмотр</option></select></label>
            </div>
            {edit.auth_source !== "ldap" && <>
              <label>{edit.isNew ? "Пароль" : "Новый пароль"}<input type="password" value={edit.password ?? ""} onChange={(e) => setEdit({ ...edit, password: e.target.value })} autoComplete="new-password" minLength={12} required={!!edit.isNew} /><span className="help">{edit.isNew ? "" : "Пусто — не менять. "}Не короче 12 символов, минимум два вида символов</span></label>
              <label className="check"><input type="checkbox" className="switch" checked={!!edit.must_change_password} onChange={(e) => setEdit({ ...edit, must_change_password: e.target.checked })} />Потребовать смену пароля при входе</label>
            </>}
            <label className="check"><input type="checkbox" className="switch" checked={!!edit.is_active} onChange={(e) => setEdit({ ...edit, is_active: e.target.checked })} disabled={edit.id === ctx.me.user.id} />Учётная запись активна</label>
            <fieldset className="group"><legend>Доступ к источникам KSC</legend>
              {edit.role === "admin" ? <p className="help">Администратор видит все источники.</p> : <>
                <label className="check"><input type="checkbox" className="switch" checked={!!edit.all_sources} onChange={(e) => setEdit({ ...edit, all_sources: e.target.checked })} />Все источники, включая будущие</label>
                {!edit.all_sources && (ctx.sources.length ? ctx.sources.map((s) => <label key={s.id} className="check"><input type="checkbox" checked={(edit.source_ids ?? []).includes(s.id)} onChange={() => toggleSrc(s.id)} />{s.name}</label>) : <p className="help">Источники ещё не добавлены.</p>)}
              </>}
            </fieldset>
            {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          </form>
        </Modal>
      )}
      {del && <ConfirmDialog title={`Удалить пользователя ${del.username}?`} confirmLabel="Удалить" body={<p>Пользователь потеряет доступ, его сеансы завершатся. Сформированные им отчёты и сценарии останутся.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.deleteUser(del.id); await load(); }} />}
      {reset && <ResetTotp user={reset} onClose={() => setReset(null)} onDone={() => { setReset(null); show("Двухфакторная аутентификация сброшена"); void load(); }} />}
      <RolesAndPolicy />
      {toast}
    </>
  );
}
