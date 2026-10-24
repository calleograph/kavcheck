import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type ApiError, type Rule } from "../../api";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows } from "../../components/ui";

const empty: Rule = { key: "", name: "", name_like: "", name_regex: "", branch_regex: null, branch_parts: 2, exclude_regex: null, description: null, enabled: true };

/** Правила логической группировки программ: SQL LIKE для первичного отбора, регулярное выражение для точного, ветка из имени пакета. */
export default function RulesAdmin() {
  const [items, setItems] = useState<Rule[] | null>(null);
  const [edit, setEdit] = useState<Rule | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [err, setErr] = useState(""); const [del, setDel] = useState<Rule | null>(null); const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.rules().then((r) => setItems(r.items)).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const submit = async (e: FormEvent) => { e.preventDefault(); if (!edit) return; setErr(""); setBusy(true); try { if (isNew) await api.admin.createRule(edit); else await api.admin.updateRule(edit.key, edit); setEdit(null); show("Правило сохранено"); await load(); } catch (x) { setErr((x as ApiError).message); } setBusy(false); };
  return (
    <>
      <div className="toolbar">
        <p className="muted small prose-note grow"><b>Шаблон LIKE</b> отбирает записи в базе KSC, <b>регулярное выражение</b> уточняет отбор, <b>ветка из имени</b> извлекает major.minor из имени пакета. Если версия пакета не начинается с ветки из имени, используется ветка: версия расширения не выдаётся за версию продукта.</p>
        <button className="btn ghost" onClick={async () => { await api.admin.resetBuiltin(); await load(); show("Встроенные правила восстановлены"); }}><Icon name="history" />Восстановить встроенные</button>
        <button className="btn primary" onClick={() => { setErr(""); setEdit({ ...empty }); setIsNew(true); }}><Icon name="plus" />Новое правило</button>
      </div>
      {err && !edit && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!items ? <SkelRows rows={2} cols={5} /> : (
          <table className="table">
            <thead><tr><th>Продукт</th><th>Шаблон LIKE</th><th>Отбор пакетов</th><th>Ветка из имени</th><th>Статус</th><th><span className="sr-only">Действия</span></th></tr></thead>
            <tbody>{items.map((r) => (
              <tr key={r.key}><td><b>{r.name}</b><span className="sub mono">{r.key}{r.builtin ? ", встроенное" : ""}</span></td><td className="mono">{r.name_like}</td><td className="mono small">{r.name_regex}</td><td className="mono small">{r.branch_regex ?? "—"}</td>
                <td>{r.enabled ? <span className="badge ok">включено</span> : <span className="badge warn">выключено</span>}</td>
                <td className="actions"><button className="btn mini ghost icon" aria-label={`Изменить правило ${r.name}`} onClick={() => { setErr(""); setEdit({ ...r }); setIsNew(false); }}><Icon name="edit" size={15} /></button>{!r.builtin && <button className="btn mini ghost danger icon" aria-label={`Удалить правило ${r.name}`} onClick={() => setDel(r)}><Icon name="trash" size={15} /></button>}</td></tr>))}
            </tbody>
          </table>)}
      </div>
      {edit && (
        <Modal title={isNew ? "Новое правило группировки" : `Правило «${edit.name}»`} onClose={() => setEdit(null)} wide
          footer={<><button type="button" className="btn ghost" onClick={() => setEdit(null)}>Отмена</button><button type="submit" form="rule-form" className="btn primary" aria-busy={busy}><span>Сохранить правило</span></button></>}>
          <form id="rule-form" onSubmit={submit}>
            <div className="cols">
              <label>Ключ<input className="mono" value={edit.key} onChange={(e) => setEdit({ ...edit, key: e.target.value })} disabled={!isNew} pattern="[a-z0-9_-]+" required placeholder="nginx" /><span className="help">Латиница, цифры, «-», «_»; используется в ссылках и отчётах</span></label>
              <label>Название продукта<input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} required maxLength={120} placeholder="nginx" /></label>
            </div>
            <div className="cols">
              <label>Шаблон LIKE<input className="mono" value={edit.name_like} onChange={(e) => setEdit({ ...edit, name_like: e.target.value })} required placeholder="%nginx%" spellCheck={false} /></label>
              <label>Частей версии в ветке<input type="number" min={1} max={4} value={edit.branch_parts} onChange={(e) => setEdit({ ...edit, branch_parts: Number(e.target.value) })} /><span className="help">2 — ветка 1.24, 1 — ветка 1</span></label>
            </div>
            <label>Регулярное выражение по имени пакета<input className="mono" value={edit.name_regex} onChange={(e) => setEdit({ ...edit, name_regex: e.target.value })} required spellCheck={false} placeholder="^(nginx|nginx-(core|common|full|light|extras))$" /></label>
            <label>Ветка из имени пакета<input className="mono" value={edit.branch_regex ?? ""} onChange={(e) => setEdit({ ...edit, branch_regex: e.target.value || null })} spellCheck={false} placeholder="^php(\d+\.\d+)(?:-|$)" /><span className="help">Необязательно. Первая группа — ветка вида 7.4</span></label>
            <label>Исключить по имени<input className="mono" value={edit.exclude_regex ?? ""} onChange={(e) => setEdit({ ...edit, exclude_regex: e.target.value || null })} spellCheck={false} /><span className="help">Необязательно</span></label>
            <label>Описание<textarea rows={3} value={edit.description ?? ""} onChange={(e) => setEdit({ ...edit, description: e.target.value || null })} /></label>
            <label className="check"><input type="checkbox" className="switch" checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} />Правило включено</label>
            {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
          </form>
        </Modal>
      )}
      {del && <ConfirmDialog title={`Удалить правило «${del.name}»?`} confirmLabel="Удалить правило" body={<p>Отчёты, построенные по этому правилу, повторить будет нельзя.</p>} onClose={() => setDel(null)} onConfirm={async () => { await api.admin.deleteRule(del.key); await load(); }} />}
      {toast}
    </>
  );
}
