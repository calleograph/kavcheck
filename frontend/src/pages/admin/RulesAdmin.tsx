import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type ApiError, type Rule } from "../../api";
import { ConfirmDialog, Modal } from "../../components/Dialogs";

const empty: Rule = { key: "", name: "", name_like: "", name_regex: "", branch_regex: null, branch_parts: 2, exclude_regex: null, description: null, enabled: true };

/** Правила логической группировки программ: SQL LIKE для первичного отбора, регулярное выражение для точного, ветка из имени пакета. */
export default function RulesAdmin() {
  const [items, setItems] = useState<Rule[]>([]);
  const [edit, setEdit] = useState<Rule | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [err, setErr] = useState(""); const [del, setDel] = useState<Rule | null>(null);
  const load = useCallback(() => api.admin.rules().then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const submit = async (e: FormEvent) => { e.preventDefault(); if (!edit) return; setErr(""); try { if (isNew) await api.admin.createRule(edit); else await api.admin.updateRule(edit.key, edit); setEdit(null); await load(); } catch (x) { setErr((x as ApiError).message); } };
  return (
    <section>
      <div className="row"><h2>Правила группировки программ</h2><div className="spacer" /><button className="btn" onClick={async () => { await api.admin.resetBuiltin(); await load(); }}>Восстановить встроенные</button><button className="btn primary" onClick={() => { setEdit({ ...empty }); setIsNew(true); }}>＋ Правило</button></div>
      <p className="muted">Правило описывает продукт, представленный множеством пакетов. <b>Шаблон LIKE</b> отбирает записи в базе, <b>регулярное выражение</b> уточняет отбор в приложении, <b>ветка из имени</b> извлекает major.minor из имени пакета (группа 1 — «7.4», группы 2 и 3 — «7» и «4»). Если версия пакета начинается с ветки из имени, берётся версия пакета; иначе — ветка из имени (версия расширения не выдаётся за версию продукта).</p>
      {err && !edit && <div className="alert error">{err}</div>}
      <div className="table-scroll"><table className="table">
        <thead><tr><th>Ключ</th><th>Продукт</th><th>LIKE</th><th>Регулярное выражение</th><th>Ветка из имени</th><th>Статус</th><th /></tr></thead>
        <tbody>{items.map((r) => (
          <tr key={r.key}><td><code>{r.key}</code>{r.builtin && <div className="small muted">встроенное</div>}</td><td>{r.name}{r.description && <div className="small muted">{r.description.slice(0, 160)}{r.description.length > 160 ? "…" : ""}</div>}</td><td><code>{r.name_like}</code></td><td className="small"><code style={{ overflowWrap: "anywhere" }}>{r.name_regex}</code></td><td className="small">{r.branch_regex ? <code style={{ overflowWrap: "anywhere" }}>{r.branch_regex}</code> : "—"}</td>
            <td>{r.enabled ? <span className="badge ok">включено</span> : <span className="badge warn">выключено</span>}</td>
            <td className="actions"><button className="btn mini" onClick={() => { setEdit({ ...r }); setIsNew(false); }}>Изменить</button> {!r.builtin && <button className="btn mini ghost danger" onClick={() => setDel(r)}>Удалить</button>}</td></tr>))}
        </tbody>
      </table></div>
      {edit && (
        <Modal title={isNew ? "Новое правило" : `Правило «${edit.name}»`} onClose={() => setEdit(null)} wide>
          <form onSubmit={submit}>
            <div className="cols">
              <label>Ключ<input value={edit.key} onChange={(e) => setEdit({ ...edit, key: e.target.value })} disabled={!isNew} pattern="[a-z0-9_-]+" required placeholder="nginx" /></label>
              <label>Название продукта<input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} required maxLength={120} /></label>
            </div>
            <div className="cols">
              <label>Шаблон LIKE<input value={edit.name_like} onChange={(e) => setEdit({ ...edit, name_like: e.target.value })} required placeholder="%nginx%" spellCheck={false} /></label>
              <label>Частей версии в ветке<input type="number" min={1} max={4} value={edit.branch_parts} onChange={(e) => setEdit({ ...edit, branch_parts: Number(e.target.value) })} /><span className="help">2 → 1.24; 1 → 1</span></label>
            </div>
            <label>Регулярное выражение по имени пакета<input value={edit.name_regex} onChange={(e) => setEdit({ ...edit, name_regex: e.target.value })} required spellCheck={false} placeholder="^(nginx|nginx-(core|common|full|light|extras))$" /></label>
            <label>Ветка из имени пакета (необязательно)<input value={edit.branch_regex ?? ""} onChange={(e) => setEdit({ ...edit, branch_regex: e.target.value || null })} spellCheck={false} placeholder="^php(\d+\.\d+)(?:-|$)" /></label>
            <label>Исключить по имени (необязательно)<input value={edit.exclude_regex ?? ""} onChange={(e) => setEdit({ ...edit, exclude_regex: e.target.value || null })} spellCheck={false} /></label>
            <label>Описание<textarea rows={3} value={edit.description ?? ""} onChange={(e) => setEdit({ ...edit, description: e.target.value || null })} /></label>
            <label className="check"><input type="checkbox" checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} /> Правило включено</label>
            {err && <div className="alert error">{err}</div>}
            <div className="row"><button className="btn primary">Сохранить</button><button type="button" className="btn ghost" onClick={() => setEdit(null)}>Отмена</button></div>
          </form>
        </Modal>
      )}
      {del && <ConfirmDialog title={`Удалить правило «${del.name}»?`} confirmLabel="Удалить" body={<p>Отчёты, ссылающиеся на правило, повторить будет нельзя.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.deleteRule(del.key); await load(); }} />}
    </section>
  );
}
