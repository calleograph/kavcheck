import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type ApiError, type OvLicenseGroup, type OvLicenses, type SourceRef } from "../../api";
import { ConfirmDialog, Modal } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, fmtDate, num } from "../../util";

type Diag = Awaited<ReturnType<typeof api.licenses.diag>>["items"];
const STATE_RU: Record<OvLicenseGroup["state"], string> = { active: "действует", expiring: "скоро истекает", expired: "истекла", unknown: "срок не указан", perpetual: "бессрочная" };

/** Администрирование лицензий: что прочитано из KSC, общие пулы, ручной ввод (когда KSC не отдаёт сведения) и диагностика чтения. Ключи не хранятся и не показываются. */
export default function LicensesAdmin({ sources }: { sources: SourceRef[] }) {
  const [data, setData] = useState<OvLicenses | null>(null);
  const [diag, setDiag] = useState<Diag>([]);
  const [err, setErr] = useState("");
  const [add, setAdd] = useState(false);
  const [pool, setPool] = useState<{ source_id: string; lic_key: string; name: string; value: string } | null>(null);
  const [del, setDel] = useState<{ source_id: string; lic_key: string; product: string } | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => {
    api.licenses.all().then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message));
    api.licenses.diag().then((r) => setDiag(r.items)).catch(() => setDiag([]));
  }, []);
  useEffect(load, [load]);
  const refresh = async () => { try { await api.licenses.refresh(); show("Чтение лицензий запрошено: результат появится в течение минуты."); setTimeout(load, 8000); } catch (e) { setErr((e as ApiError).message); } };
  return (
    <div className="stack">
      {toast}
      <div className="card">
        <div className="card-head"><h2>Лицензии Kaspersky</h2><div className="spacer" />
          <button className="btn" onClick={refresh}><Icon name="refresh" />Прочитать из KSC заново</button>
          <button className="btn primary" onClick={() => setAdd(true)}><Icon name="plus" />Внести вручную</button></div>
        <p className="muted small">Данные читает фоновая служба раз в 6 часов. Лицензионные ключи не хранятся: один и тот же ключ на нескольких KSC узнаётся по отпечатку и считается один раз. Если KSC не отдаёт сведения или определяет их неверно, внесите лимит, использование и срок вручную — запись будет подписана «вручную» и не заменится чтением. Лицензии, которые используются совместно, можно объединить в общий пул.</p>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        {!data ? <SkelRows rows={4} cols={6} /> : data.groups.length === 0 ? <Empty icon="key" title="Лицензий нет">KSC не передал сведения о лицензиях. Внесите их вручную или посмотрите диагностику ниже.</Empty> : (
          <div className="table-scroll"><table className="table compact">
            <thead><tr><th>Продукт</th><th className="num">Лимит</th><th className="num">Использовано</th><th>Срок</th><th>Источник</th><th>Пул</th><th /></tr></thead>
            <tbody>{data.groups.map((g) => g.sources.map((s, i) => (
              <tr key={g.key + s.lic_key}>
                {i === 0 && <td rowSpan={g.sources.length}><b>{g.product}</b>{g.kind && <span className="sub">{g.kind}</span>}{g.shared && <span className="badge accent">общий пул</span>}{g.notes.map((n) => <span key={n} className="sub warn-text">{n}</span>)}</td>}
                <td className="num">{s.limit === null ? "—" : num(s.limit)}</td><td className="num">{s.used === null ? <span className="muted">нет данных</span> : num(s.used)}</td>
                {i === 0 && <td rowSpan={g.sources.length} className={`small ${g.state === "expired" ? "bad-text" : g.state === "expiring" ? "warn-text" : ""}`}>{g.expires_at ? fmtDate(g.expires_at) : "—"}<span className="sub">{STATE_RU[g.state]}</span></td>}
                <td className="small">{s.name}{s.origin === "manual" && <span className="badge">вручную</span>}<span className="sub">{s.updated_at ? fmt(s.updated_at) : ""}</span></td>
                <td className="small">{g.basis === "admin" ? g.pool : g.basis === "fp" ? "один ключ" : "—"}</td>
                <td className="row-actions">
                  <button className="btn mini ghost" onClick={() => setPool({ source_id: s.id, lic_key: s.lic_key, name: g.product, value: g.basis === "admin" ? g.pool : "" })}>Пул</button>
                  {s.origin === "manual" && <button className="btn mini ghost danger" aria-label="Удалить запись" onClick={() => setDel({ source_id: s.id, lic_key: s.lic_key, product: g.product })}><Icon name="trash" size={15} /></button>}
                </td></tr>)))}</tbody></table></div>)}
        {data && <p className="ov-foot">Итого без двойного счёта: лимит {data.totals.limit === null ? "нет данных" : num(data.totals.limit)}, использовано {data.totals.used === null ? "нет данных" : num(data.totals.used)}{data.totals.complete ? "" : " (учтены только известные значения)"}.</p>}
      </div>
      <div className="card">
        <div className="card-head"><h2>Диагностика чтения из KSC</h2></div>
        {diag.length === 0 ? <p className="muted small">Источники ещё не опрашивались.</p> : (
          <div className="stack tight">{diag.map((d) => (
            <details key={d.source_id} className="disclosure">
              <summary><b>{d.source}</b> · записей из KSC: {d.records}{d.error ? ` · ошибка: ${d.error}` : ""}{d.polled_at ? ` · прочитано ${fmt(d.polled_at)}` : " · ещё не читалось"}</summary>
              <div className="small stack tight">
                {d.diag?.note && <p className="warn-text">{d.diag.note}</p>}
                <p>Проверенные таблицы: {d.diag?.tables?.length ? d.diag.tables.join(", ") : "нет"}</p>
                {d.diag?.mapped && Object.entries(d.diag.mapped).map(([t, m]) => <p key={t} className="mono">{t}: {Object.keys(m).length ? Object.entries(m).map(([r, c]) => `${r}=${c}`).join(", ") : "нужные столбцы не распознаны"}</p>)}
              </div></details>))}</div>)}
      </div>
      {add && <ManualDialog sources={sources} onClose={() => setAdd(false)} onDone={() => { setAdd(false); load(); show("Лицензия внесена."); }} />}
      {pool && <PoolDialog p={pool} onClose={() => setPool(null)} onDone={() => { setPool(null); load(); show("Пул сохранён."); }} />}
      {del && <ConfirmDialog title="Удалить ручную запись?" body={<>Запись «{del.product}» будет удалена. Данные KSC не меняются.</>} confirmLabel="Удалить" onClose={() => setDel(null)}
        onConfirm={async () => { await api.licenses.removeManual(del.source_id, del.lic_key); setDel(null); load(); }} />}
    </div>
  );
}

function ManualDialog({ sources, onClose, onDone }: { sources: SourceRef[]; onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ source_id: sources[0]?.id ?? "", product: "", kind: "", expires: "", perpetual: false, limit: "", used: "", pool: "", note: "" });
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setErr("");
    try { await api.licenses.addManual({ source_id: f.source_id, product: f.product.trim(), kind: f.kind.trim(), expires_at: f.expires && !f.perpetual ? new Date(f.expires + "T23:59:59Z").toISOString() : null, perpetual: f.perpetual, limit_n: f.limit === "" ? null : Number(f.limit), used_n: f.used === "" ? null : Number(f.used), pool: f.pool.trim(), note: f.note.trim() }); onDone(); }
    catch (x) { setErr((x as ApiError).message); } finally { setBusy(false); }
  };
  const set = (k: keyof typeof f, v: string | boolean) => setF({ ...f, [k]: v });
  return (
    <Modal title="Внести лицензию вручную" lede="Не вводите лицензионные ключи — достаточно продукта, лимита и срока." onClose={onClose} footer={<><button className="btn" onClick={onClose}>Отмена</button><button className="btn primary" form="lic-manual" disabled={busy || !f.product.trim() || !f.source_id}>Сохранить</button></>}>
      <form id="lic-manual" onSubmit={submit} className="stack">
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <label className="field">Источник KSC<select value={f.source_id} onChange={(e) => set("source_id", e.target.value)}>{sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
        <label className="field">Продукт<input value={f.product} onChange={(e) => set("product", e.target.value)} maxLength={200} required /></label>
        <div className="grid-2"><label className="field">Лимит, шт.<input type="number" min={0} value={f.limit} onChange={(e) => set("limit", e.target.value)} /></label>
          <label className="field">Использовано, шт.<input type="number" min={0} value={f.used} onChange={(e) => set("used", e.target.value)} placeholder="не известно" /></label></div>
        <div className="grid-2"><label className="field">Срок действия до<input type="date" value={f.perpetual ? "" : f.expires} disabled={f.perpetual} onChange={(e) => set("expires", e.target.value)} /></label>
          <label className="field">Тип лицензии<input value={f.kind} onChange={(e) => set("kind", e.target.value)} maxLength={80} placeholder="коммерческая, подписка…" /></label></div>
        <label className="check"><input type="checkbox" checked={f.perpetual} onChange={(e) => set("perpetual", e.target.checked)} />Бессрочная лицензия (срока действия нет). Без даты и без этой отметки срок считается неизвестным, и лицензия не входит в лимит действующих.</label>
        <label className="field">Общий пул (необязательно)<input value={f.pool} onChange={(e) => set("pool", e.target.value)} maxLength={120} placeholder="одинаковое название у лицензий, которые используются совместно" /></label>
        <label className="field">Примечание<input value={f.note} onChange={(e) => set("note", e.target.value)} maxLength={300} /></label>
      </form>
    </Modal>
  );
}

function PoolDialog({ p, onClose, onDone }: { p: { source_id: string; lic_key: string; name: string; value: string }; onClose: () => void; onDone: () => void }) {
  const [v, setV] = useState(p.value); const [err, setErr] = useState("");
  const save = async (e: FormEvent) => { e.preventDefault(); try { await api.licenses.setPool(p.source_id, p.lic_key, v.trim()); onDone(); } catch (x) { setErr((x as ApiError).message); } };
  return (
    <Modal title={`Общий пул: ${p.name}`} lede="Лицензии с одинаковым названием пула считаются один раз: лимит общий, использование — сумма по серверам. Данные KSC не меняются." onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Отмена</button><button className="btn primary" form="lic-pool">Сохранить</button></>}>
      <form id="lic-pool" onSubmit={save} className="stack">
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <label className="field">Название пула<input value={v} onChange={(e) => setV(e.target.value)} maxLength={120} placeholder="пусто — вывести из пула" autoFocus /></label>
      </form>
    </Modal>
  );
}
