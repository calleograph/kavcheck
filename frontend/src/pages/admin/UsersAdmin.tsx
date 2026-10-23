import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type AdminUser, type ApiError } from "../../api";
import type { Ctx } from "../../App";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { fmt } from "../../util";

const ROLE: Record<string, string> = { admin: "администратор", analyst: "аналитик", viewer: "просмотр" };

export default function UsersAdmin({ ctx }: { ctx: Ctx }) {
  const [items, setItems] = useState<AdminUser[]>([]);
  const [q, setQ] = useState(""); const [err, setErr] = useState("");
  const [edit, setEdit] = useState<Partial<AdminUser> & { password?: string; isNew?: boolean } | null>(null);
  const [del, setDel] = useState<AdminUser | null>(null);
  const load = useCallback(() => api.admin.users(q).then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)), [q]);
  useEffect(() => { const t = window.setTimeout(load, 250); return () => window.clearTimeout(t); }, [load]);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); if (!edit) return; setErr("");
    const body = { display_name: edit.display_name, email: edit.email || null, role: edit.role, is_active: edit.is_active, all_sources: edit.all_sources, source_ids: edit.source_ids ?? [], must_change_password: edit.must_change_password, ...(edit.password ? { password: edit.password } : {}) };
    try { if (edit.isNew) await api.admin.createUser({ username: edit.username, ...body }); else await api.admin.patchUser(edit.id!, body); setEdit(null); await load(); } catch (x) { setErr((x as ApiError).message); }
  };
  const toggleSrc = (id: string) => setEdit((u) => { if (!u) return u; const s = new Set(u.source_ids ?? []); if (s.has(id)) s.delete(id); else s.add(id); return { ...u, source_ids: [...s] }; });
  return (
    <section>
      <div className="row"><h2>Пользователи</h2><div className="spacer" /><button className="btn primary" onClick={() => setEdit({ isNew: true, username: "", display_name: "", role: "viewer", is_active: true, all_sources: true, source_ids: [], must_change_password: true })}>＋ Локальный пользователь</button></div>
      <p className="muted">Роли: <b>администратор</b> — система, подключения и пользователи; <b>аналитик</b> — данные и отчёты; <b>просмотр</b> — только разрешённые данные и готовые отчёты. Пользователи каталога появляются после первого входа, их роль определяется группами LDAP. Доступ к отдельным источникам KSC назначается здесь.</p>
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Поиск по имени или логину" style={{ maxWidth: 360 }} aria-label="Поиск" />
      {err && <div className="alert error">{err}</div>}
      <div className="table-scroll"><table className="table">
        <thead><tr><th>Имя</th><th>Логин</th><th>Тип</th><th>Роль</th><th>Источники</th><th>Последний вход</th><th>Статус</th><th /></tr></thead>
        <tbody>{items.map((u) => (
          <tr key={u.id}><td>{u.display_name}{u.email && <div className="small muted">{u.email}</div>}</td><td>{u.username}</td><td>{u.auth_source === "local" ? "локальный" : "LDAP"}</td><td><span className={`badge ${u.role === "admin" ? "accent" : ""}`}>{ROLE[u.role]}</span></td>
            <td className="small">{u.role === "admin" || u.all_sources ? "все" : u.source_ids.map((id) => ctx.sources.find((s) => s.id === id)?.name ?? "?").join(", ") || "нет"}</td><td className="nowrap">{fmt(u.last_login_at)}</td>
            <td>{u.is_active ? "активен" : <span className="badge warn">отключён</span>}{u.must_change_password && <div className="small muted">сменит пароль при входе</div>}</td>
            <td className="actions"><button className="btn mini" onClick={() => setEdit({ ...u })}>Изменить</button> {u.id !== ctx.me.user.id && <button className="btn mini ghost danger" onClick={() => setDel(u)}>Удалить</button>}</td></tr>))}
        </tbody>
      </table></div>
      {edit && (
        <Modal title={edit.isNew ? "Новый локальный пользователь" : `Пользователь ${edit.username}`} onClose={() => setEdit(null)}>
          <form onSubmit={submit}>
            <div className="cols">
              <label>Логин<input value={edit.username ?? ""} onChange={(e) => setEdit({ ...edit, username: e.target.value })} disabled={!edit.isNew} required pattern="[a-z][a-z0-9._-]{2,63}" autoCapitalize="none" /><span className="help">строчные латинские буквы, цифры, «.», «_», «-»</span></label>
              <label>Отображаемое имя<input value={edit.display_name ?? ""} onChange={(e) => setEdit({ ...edit, display_name: e.target.value })} maxLength={300} /></label>
            </div>
            <div className="cols">
              <label>Электронная почта<input type="email" value={edit.email ?? ""} onChange={(e) => setEdit({ ...edit, email: e.target.value })} /></label>
              <label>Роль<select value={edit.role} onChange={(e) => setEdit({ ...edit, role: e.target.value as AdminUser["role"] })} disabled={edit.id === ctx.me.user.id}><option value="admin">администратор</option><option value="analyst">аналитик</option><option value="viewer">просмотр</option></select></label>
            </div>
            {edit.auth_source !== "ldap" && <label>{edit.isNew ? "Пароль" : "Новый пароль (пусто — не менять)"}<input type="password" value={edit.password ?? ""} onChange={(e) => setEdit({ ...edit, password: e.target.value })} autoComplete="new-password" minLength={12} required={!!edit.isNew} /><span className="help">не короче 12 символов, минимум два вида символов</span></label>}
            {edit.auth_source !== "ldap" && <label className="check"><input type="checkbox" checked={!!edit.must_change_password} onChange={(e) => setEdit({ ...edit, must_change_password: e.target.checked })} /> Потребовать смену пароля при следующем входе</label>}
            <label className="check"><input type="checkbox" checked={!!edit.is_active} onChange={(e) => setEdit({ ...edit, is_active: e.target.checked })} disabled={edit.id === ctx.me.user.id} /> Учётная запись активна</label>
            <fieldset className="group"><legend>Доступ к источникам KSC</legend>
              <label className="check"><input type="checkbox" checked={!!edit.all_sources} onChange={(e) => setEdit({ ...edit, all_sources: e.target.checked })} disabled={edit.role === "admin"} /> Все источники{edit.role === "admin" && <span className="help">администратор видит все источники</span>}</label>
              {!edit.all_sources && edit.role !== "admin" && (ctx.sources.length ? ctx.sources.map((s) => <label key={s.id} className="check"><input type="checkbox" checked={(edit.source_ids ?? []).includes(s.id)} onChange={() => toggleSrc(s.id)} /> {s.name}</label>) : <p className="muted small">Источники ещё не добавлены.</p>)}
            </fieldset>
            {err && <div className="alert error">{err}</div>}
            <div className="row"><button className="btn primary">Сохранить</button><button type="button" className="btn ghost" onClick={() => setEdit(null)}>Отмена</button></div>
          </form>
        </Modal>
      )}
      {del && <ConfirmDialog title={`Удалить пользователя ${del.username}?`} confirmLabel="Удалить" body={<p>Пользователь потеряет доступ. Его отчёты и сценарии останутся.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.deleteUser(del.id); await load(); }} />}
    </section>
  );
}
