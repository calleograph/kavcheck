/** Импорт из Excel/CSV: файл → сопоставление столбцов (предложено по заголовкам) → проверка без записи (сколько создать, изменить, ошибки по строкам) → импорт с отчётом. */
import { useRef, useState } from "react";
import type { ApiError } from "../../api";
import type { Ctx } from "../../App";
import { Icon } from "../../components/Icons";
import { Segmented } from "../../components/ui";
import { num } from "../../util";
import { useInv } from "./InvBits";
import { inv, type ImportPreview, type ImportResult } from "./invApi";

export default function InvImport({ ctx }: { ctx: Ctx }) {
  void ctx;
  const { can, reloadLocs, reload } = useInv();
  const ref = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null); const [pv, setPv] = useState<ImportPreview | null>(null); const [map, setMap] = useState<Record<string, string>>({});
  const [mode, setMode] = useState<"upsert" | "create">("upsert"); const [createRefs, setCreateRefs] = useState(true);
  const [res, setRes] = useState<ImportResult | null>(null); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const pick = async (f: File | undefined) => {
    if (!f) return; setFile(f); setPv(null); setRes(null); setErr(""); setBusy(true);
    try { const p = await inv.importPreview(f); setPv(p); setMap(p.mapping); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  const run = async (dry: boolean) => {
    if (!file) return; setBusy(true); setErr("");
    try { const r = await inv.importRun(file, Object.fromEntries(Object.entries(map).filter(([, v]) => v)), { mode, create_refs: createRefs, dry_run: dry }); setRes(r); if (!dry) { reload(); reloadLocs(); } }
    catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  if (!can("import")) return <p className="muted">Импорт недоступен вашей роли.</p>;
  const used = new Set(Object.values(map).filter(Boolean));
  return (
    <div className="inv-page">
      <div className="inv-head"><h1>Импорт из Excel или CSV</h1></div>
      <div className="card inv-import-card">
        <ol className="inv-steps-text"><li>Нет готовой таблицы — скачайте шаблон ниже и заполните его.</li><li>Выберите файл: первая строка — заголовки, далее строка на единицу.</li><li>Проверьте сопоставление столбцов.</li><li>Нажмите «Проверить» — ничего не запишется, будут показаны ошибки по строкам.</li><li>Импортируйте. Повторная загрузка того же файла не создаёт дублей.</li></ol>
        <div className="row wrap inv-tpl"><span className="muted small">Шаблон файла:</span>
          <a className="btn ghost mini" href={inv.importTemplate("xlsx", false)}><Icon name="download" size={14} />Excel</a><a className="btn ghost mini" href={inv.importTemplate("csv", false)}><Icon name="download" size={14} />CSV</a>
          <span className="muted small">с примером заполнения:</span>
          <a className="btn ghost mini" href={inv.importTemplate("xlsx", true)}><Icon name="download" size={14} />Excel</a><a className="btn ghost mini" href={inv.importTemplate("csv", true)}><Icon name="download" size={14} />CSV</a></div>
        <p className="muted small">В шаблоне — все поля карточки и дополнительные свойства; в Excel на втором листе описано, что указывать в каждом столбце. Пример заполнен вымышленными данными — удалите его строки перед загрузкой. CSV — разделитель «;», кодировка UTF-8.</p>
        <div className="row wrap"><input ref={ref} type="file" accept=".xlsx,.csv,.txt" hidden onChange={(e) => void pick(e.target.files?.[0])} />
          <button className="btn primary" onClick={() => ref.current?.click()} disabled={busy}><Icon name="upload" size={16} />{file ? "Другой файл" : "Выбрать файл"}</button>
          {file && <span className="muted small">{file.name} · {num(Math.round(file.size / 1024))} КБ{pv ? ` · строк: ${num(pv.total)}` : ""}</span>}</div>
        <p className="muted small">Совпадение с существующей карточкой — по инвентарному номеру, иначе по однозначному серийному номеру. Местоположение — путь «Регион / Город / Здание / Помещение»; сотрудник — почта или ФИО.</p>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      </div>
      {pv && <div className="card mt"><h2>Сопоставление столбцов</h2>
        <div className="inv-map">{pv.headers.map((h, i) => <label key={h + i} className="field"><span className="mono small">{h || `(столбец ${i + 1})`}</span>
          <select value={map[h] ?? ""} onChange={(e) => setMap({ ...map, [h]: e.target.value })}><option value="">— не загружать —</option>
            <optgroup label="Поля карточки">{Object.entries(pv.fields).map(([k, v]) => <option key={k} value={k} disabled={used.has(k) && map[h] !== k}>{v}</option>)}</optgroup>
            {Object.keys(pv.props).length > 0 && <optgroup label="Дополнительные свойства">{Object.entries(pv.props).map(([k, v]) => <option key={k} value={`prop:${k}`} disabled={used.has(`prop:${k}`) && map[h] !== `prop:${k}`}>{v}</option>)}</optgroup>}</select>
          <span className="sub muted">{pv.rows.slice(0, 2).map((r) => r[i]).filter(Boolean).join(" · ").slice(0, 60)}</span></label>)}</div>
        <div className="row wrap mt-sm"><Segmented label="Режим" value={mode} onChange={setMode} options={[["upsert", "Новые и обновление"], ["create", "Только новые"]]} />
          <label className="check-row"><input type="checkbox" checked={createRefs} onChange={(e) => setCreateRefs(e.target.checked)} />Создавать недостающие значения справочников, местоположения и сотрудников</label></div>
        <div className="row wrap mt-sm"><button className="btn" disabled={busy} onClick={() => void run(true)}>{busy ? <span className="spin" /> : <Icon name="check" size={16} />}Проверить</button>
          <button className="btn primary" disabled={busy || !res || !res.dry_run} onClick={() => void run(false)}>Импортировать</button>
          <span className="muted small">Сначала проверьте: импорт открывается после проверки.</span></div>
      </div>}
      {res && <div className={`card mt ${res.dry_run ? "" : "inv-done"}`}><h2>{res.dry_run ? "Результат проверки (ничего не записано)" : "Импорт выполнен"}</h2>
        <div className="meters compact">
          <div className="meter"><span className="l">{res.dry_run ? "Будет создано" : "Создано"}</span><span className="v">{num(res.created)}</span></div>
          <div className="meter"><span className="l">{res.dry_run ? "Будет изменено" : "Изменено"}</span><span className="v">{num(res.updated)}</span></div>
          <div className="meter"><span className="l">Без изменений</span><span className="v">{num(res.unchanged)}</span></div>
          <div className="meter"><span className="l">Пропущено</span><span className={`v ${res.skipped ? "warn-text" : ""}`}>{num(res.skipped)}</span></div>
        </div>
        {(res.created_refs.refs + res.created_refs.locations + res.created_refs.people) > 0 && <p className="small">Новых значений справочников: {res.created_refs.refs}, местоположений: {res.created_refs.locations}, сотрудников: {res.created_refs.people}.</p>}
        {res.errors.length > 0 && <div className="table-scroll"><table className="table compact"><thead><tr><th>Строка</th><th>Причина</th></tr></thead><tbody>{res.errors.map((e, i) => <tr key={i}><td className="num">{e.row}</td><td>{e.error}</td></tr>)}</tbody></table></div>}
      </div>}
    </div>
  );
}
