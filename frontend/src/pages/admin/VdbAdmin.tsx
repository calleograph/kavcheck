import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiError, type VdbMapping, type VdbSourceInfo } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { bytes, fmt, num } from "../../util";

const INTERVALS: [number, string][] = [[1, "каждый час"], [6, "каждые 6 часов"], [12, "каждые 12 часов"], [24, "раз в сутки"], [72, "раз в 3 суток"], [168, "раз в неделю"]];
const STATUS: Record<string, [string, string]> = { never: ["не загружался", "warn"], running: ["идёт загрузка", "accent"], ok: ["загружен", "ok"], error: ["ошибка", "err"] };

/** Источники базы уязвимостей: включение, расписание, параметры, ручной запуск, состояние и история загрузок; решения по сопоставлению продуктов. */
export default function VdbAdmin() {
  const [d, setD] = useState<{ items: VdbSourceInfo[]; vulns: number; ecosystems: string[]; storage: { db_bytes: number | null; tmp_bytes: number; free_bytes: number } } | null>(null);
  const [toast, show] = useToast();
  const [err, setErr] = useState("");
  const load = useCallback(() => api.vdb.sources().then((x) => { setD(x); setErr(""); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  const busy = d?.items.some((s) => s.status === "running" || s.requested);
  useEffect(() => { if (!busy) return; const t = window.setInterval(load, 3000); return () => window.clearInterval(t); }, [busy, load]);
  if (!d) return <div className="card">{err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={4} cols={3} />}</div>;
  return (
    <div className="stack">
      <div className="alert info"><Icon name="info" /><div className="alert-body">В локальной базе <b>{num(d.vulns)}</b> уязвимостей. Загрузкой занимается фоновая служба: ручной запуск ставит источник в очередь, выполнение — в течение минуты.
        При ошибке очередной загрузки остаётся последняя корректная копия; полные выгрузки (CISA KEV, БДУ) заменяют данные только после проверки целостности, предыдущая копия хранится для отката.</div></div>
      <div className="row">
        <button className="btn" disabled={!d.items.some((s) => s.enabled && s.status !== "running")} onClick={async () => { try { const r = await api.vdb.syncAll(); show(r.queued.length ? `В очередь поставлено источников: ${r.queued.length}` : "Нет включённых источников"); void load(); } catch (e) { show((e as ApiError).message, "error"); } }}><Icon name="refresh" />Обновить все сейчас</button>
        <span className="muted small">Расписание работает само (у каждого источника — свой интервал). Занято базой уязвимостей: <b>{d.storage.db_bytes != null ? bytes(d.storage.db_bytes) : "—"}</b>; временных файлов загрузки: <b>{bytes(d.storage.tmp_bytes)}</b> (удаляются после каждой загрузки); свободно на диске: <b>{bytes(d.storage.free_bytes)}</b>.
          Данные не накапливаются: устаревшие поколения и отозванные записи удаляются, у крупных источников хранится одна копия.</span>{toast}</div>
      {d.items.some((s) => !s.enabled) && <EnableAll items={d.items} onChanged={load} />}
      {d.items.map((s) => <SourceCard key={s.key} s={s} ecosystems={d.ecosystems} onChanged={load} />)}
      <Mappings />
    </div>
  );
}

/** Включение всех источников одной кнопкой: настройки по умолчанию, первая загрузка ставится в очередь сама (помощник и учётные данные не нужны). */
function EnableAll({ items, onChanged }: { items: VdbSourceInfo[]; onChanged: () => void }) {
  const [busy, setBusy] = useState(false); const [toast, show] = useToast();
  const go = async () => {
    setBusy(true);
    try { for (const s of items.filter((x) => !x.enabled)) await api.vdb.updateSource(s.key, { enabled: true }); show("Источники включены, первая загрузка поставлена в очередь"); onChanged(); }
    catch (e) { show((e as ApiError).message, "error"); } finally { setBusy(false); }
  };
  return <div className="alert warn"><Icon name="database" /><div className="alert-body"><b>Не все источники включены.</b> Включите NVD, OSV, БДУ и CISA KEV одной кнопкой: приложение само выполнит первую загрузку (NVD и OSV — сотни мегабайт, потоком, на небольшом сервере — десятки минут), построит поиск и будет обновлять данные по расписанию.
    <div className="mt-sm"><button className="btn primary" onClick={go} aria-busy={busy}><Icon name="upload" />Включить все источники и загрузить</button></div></div>{toast}</div>;
}

const CHANNEL_NAME: Record<string, string> = { feeds: "ленты JSON 2.0", api: "API", archives: "архивы экосистем", site: "сайт bdu.fstec.ru", file: "файл, загруженный вручную", cisa: "cisa.gov", github: "GitHub cisagov/kev-data", supplement: "дополнения" };
const YEARS: [number, string][] = [[1, "текущий год"], [2, "2 года"], [3, "3 года"], [5, "5 лет"], [10, "10 лет"], [30, "всё (с 2002 года)"]];
const ECO_MB: Record<string, number> = { Debian: 75, Ubuntu: 755, Alpine: 4, "Red Hat": 26, AlmaLinux: 6, "Rocky Linux": 5, SUSE: 46, openSUSE: 21, Linux: 56, Go: 12, PyPI: 35, npm: 209, Maven: 10, NuGet: 3, Packagist: 10, RubyGems: 5, "crates.io": 3 };
const COMMON_ECO = ["Debian", "Ubuntu", "Alpine", "Red Hat", "AlmaLinux", "Rocky Linux", "SUSE", "openSUSE", "Linux", "Go", "PyPI", "npm", "Maven", "NuGet", "Packagist", "RubyGems", "crates.io"];

function SourceCard({ s, ecosystems, onChanged }: { s: VdbSourceInfo; ecosystems: string[]; onChanged: () => void }) {
  const [enabled, setEnabled] = useState(s.enabled); const [hours, setHours] = useState(s.interval_hours); const [st, setSt] = useState<Record<string, unknown>>(s.settings);
  const [key, setKey] = useState(""); const [clearKey, setClearKey] = useState(false);
  const [saving, setSaving] = useState(false); const [toast, show] = useToast(); const [confirm, setConfirm] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const dirty = enabled !== s.enabled || hours !== s.interval_hours || JSON.stringify(st) !== JSON.stringify(s.settings) || !!key || clearKey;
  const [label, tone] = STATUS[s.status] ?? [s.status, ""];
  const save = async () => {
    setSaving(true);
    try { await api.vdb.updateSource(s.key, { enabled, interval_hours: hours, settings: st, ...(key ? { api_key: key } : clearKey ? { api_key: "" } : {}) }); setKey(""); setClearKey(false); show("Настройки источника сохранены"); onChanged(); }
    catch (e) { show((e as ApiError).message, "error"); } finally { setSaving(false); }
  };
  const run = async () => { try { await api.vdb.sync(s.key); show("Загрузка поставлена в очередь"); onChanged(); } catch (e) { show((e as ApiError).message, "error"); } };
  const upload = async (f: File | undefined) => { if (!f) return; try { const r = await api.vdb.upload(f); show(`Файл получен (${Math.round(r.bytes / 1024)} КБ), разбор поставлен в очередь`); onChanged(); } catch (e) { show((e as ApiError).message, "error"); } };
  const set = (k: string, v: unknown) => setSt({ ...st, [k]: v });
  const eco = (st.ecosystems as string[] | undefined) ?? [];
  return (
    <section className="card vdb-source">
      <div className="card-head"><h2>{s.title}</h2><span className={`badge ${tone}`}>{s.enabled ? label : "выключен"}</span><div className="spacer" />
        <a className="small" href={s.url} target="_blank" rel="noopener noreferrer">{s.url.replace("https://", "")}<Icon name="external" size={12} className="ext" /></a></div>
      <p className="muted small">{s.terms}</p>
      <div className="vdb-state">
        <div><span className="l">Последняя успешная загрузка</span><b>{s.last_ok_at ? fmt(s.last_ok_at) : "—"}</b></div>
        <div><span className="l">Записей</span><b>{num(s.records)}</b></div>
        <div><span className="l">Длительность</span><b>{s.last_duration_ms != null ? `${(s.last_duration_ms / 1000).toFixed(1)} с` : "—"}</b></div>
        <div><span className="l">Канал</span><b>{s.channel ? CHANNEL_NAME[s.channel] ?? s.channel : "—"}</b></div>
        <div><span className="l">Режим</span><b>{s.mode === "full" ? "полная выгрузка, замена после проверки" : "первая загрузка — замена после проверки, затем только изменения"}</b></div>
      </div>
      {s.status === "running" && <div className="alert info" role="status"><span className="spin accent" /><div className="alert-body"><b>Этап:</b> {s.progress ?? "Выполняется загрузка…"}{s.last_started_at && <span className="muted small"> · идёт {Math.max(0, Math.round((Date.now() - new Date(s.last_started_at).getTime()) / 1000))} с</span>}</div></div>}
      {s.enabled && s.requested && s.status !== "running" && <div className="alert info" role="status"><Icon name="clock" /><div className="alert-body">Загрузка в очереди: фоновая служба начнёт её в течение минуты.</div></div>}
      {s.attempts.length > 0 && <details className="disclosure" open={!!s.last_error}><summary>Попытки последней загрузки ({s.attempts.length})</summary>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Канал</th><th>Результат</th><th className="num">Записей</th><th className="num">с</th><th>Причина</th></tr></thead>
          <tbody>{s.attempts.map((a, i) => <tr key={i}><td>{a.title}</td><td>{a.ok ? <span className="badge ok">успех</span> : <span className="badge err">ошибка</span>}</td><td className="num">{num(a.records)}</td><td className="num">{(a.ms / 1000).toFixed(1)}</td><td className="small">{a.error || "—"}</td></tr>)}</tbody></table></div>
        <p className="muted small">Каналы пробуются по порядку: при ошибке первого загрузка продолжается вторым; действующая база заменяется только после полной проверки.</p></details>}
      {s.last_error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body"><b>Последняя ошибка:</b> {s.last_error}{s.records > 0 && <> Используется последняя корректная копия ({num(s.records)} записей).</>}</div></div>}
      <div className="form">
        <div className="cols">
          <label className="check"><input type="checkbox" className="switch" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /><span className="check-body">Использовать источник</span></label>
          <label>Обновлять<select value={hours} onChange={(e) => setHours(Number(e.target.value))}>{INTERVALS.map(([h, l]) => <option key={h} value={h}>{l}</option>)}{!INTERVALS.some(([h]) => h === hours) && <option value={hours}>каждые {hours} ч</option>}</select></label>
        </div>
        {s.key === "nvd" && <div className="cols">
          <label>Глубина истории<select value={Number(st.years_back ?? 3)} onChange={(e) => set("years_back", Number(e.target.value))}>{YEARS.map(([y, l]) => <option key={y} value={y}>{l}</option>)}</select>
            <span className="help">Первая загрузка — официальные ленты по годам (потоком, без сотен тысяч запросов): год ≈ 25–30 МБ в сжатом виде; файл скачивается, проверяется по контрольной сумме NIST, разбирается потоком (память не растёт с размером) и сразу удаляется. Более старые эксплуатируемые CVE догружаются по одной. Глубину можно увеличить позже: недостающие годы будут добавлены.</span></label>
          <label>Ключ API NVD (запасной канал) {s.secret_set && !clearKey && <span className="badge ok">задан</span>}<input type="password" autoComplete="off" value={key} onChange={(e) => setKey(e.target.value)} placeholder={s.secret_set ? "оставьте пустым, чтобы не менять" : "необязательно"} />
            <span className="help">Нужен только запасному каналу API 2.0: без ключа NVD разрешает 5 запросов за 30 секунд, с ключом — 50. {s.secret_set && <button type="button" className="link-btn" onClick={() => setClearKey(!clearKey)}>{clearKey ? "Не удалять ключ" : "Удалить ключ"}</button>}</span></label></div>}
        {s.key === "osv" && <>
          <fieldset className="qr-sections"><legend>Экосистемы OSV</legend><div className="row wrap">{[...COMMON_ECO.filter((e) => ecosystems.includes(e)), ...ecosystems.filter((e) => !COMMON_ECO.includes(e))].map((e) => <label key={e} className="check"><input type="checkbox" checked={eco.includes(e)} disabled={!!st.all_ecosystems}
            onChange={(ev) => set("ecosystems", ev.target.checked ? [...eco, e] : eco.filter((x) => x !== e))} />{e}{ECO_MB[e] && <span className="muted small"> {ECO_MB[e]} МБ</span>}</label>)}</div>
            <span className="help">Для каждой выбранной экосистемы скачивается архив (Debian ≈ 80 МБ), затем — только изменённые записи (modified_id.csv). Linux-пакеты сверяются с исправлениями дистрибутива, включая переносимые. Архив удаляется сразу после разбора; на диске нужно места не меньше размера самого большого архива.</span></fieldset>
          <label className="check"><input type="checkbox" className="switch" checked={!!st.all_ecosystems} onChange={(e) => set("all_ecosystems", e.target.checked)} /><span className="check-body">Вся база OSV одним архивом (≈ 2,8 ГБ; нужно не менее 4 ГБ свободного места, загрузка и разбор — около часа)</span></label>
        </>}
        {s.key === "bdu" && <>
          <label>Адрес XML-выгрузки<input className="mono" value={String(st.url ?? "")} onChange={(e) => set("url", e.target.value)} /><span className="help">Если сервер не имеет доступа к сайту БДУ, скачайте выгрузку вручную и загрузите файл ниже.</span></label>
          <label className="check"><input type="checkbox" className="switch" checked={st.verify_tls !== false} onChange={(e) => set("verify_tls", e.target.checked)} /><span className="check-body">Проверять сертификат сайта</span></label>
          <label className="check"><input type="checkbox" className="switch" checked={st.builtin_ca !== false} onChange={(e) => set("builtin_ca", e.target.checked)} disabled={st.verify_tls === false} /><span className="check-body">Доверять корневому и промежуточному сертификатам Минцифры России (поставляются с приложением; применяются только к этому источнику)</span></label>
          <p className="muted small">Сертификат bdu.fstec.ru выдан удостоверяющим центром Минцифры, которого нет в системных хранилищах, а сервер не присылает промежуточный сертификат — без этих сертификатов проверка TLS не проходит. Дополнительные сертификаты можно добавить в «LDAPS → Сертификаты CA». Сайт может быть недоступен из-за границы: тогда скачайте файл на другом компьютере и загрузите его кнопкой ниже.</p>
        </>}
        <div className="form-actions">
          <button type="button" className="btn primary" onClick={save} aria-busy={saving} disabled={!dirty}><span>Сохранить</span></button>
          <button type="button" className="btn" onClick={run} disabled={s.status === "running" || s.requested}><Icon name="refresh" />Обновить сейчас</button>
          {s.upload && <><input ref={file} type="file" accept=".xml,.zip" hidden onChange={(e) => { void upload(e.target.files?.[0]); e.target.value = ""; }} />
            <button type="button" className="btn" onClick={() => file.current?.click()} disabled={s.status === "running"}><Icon name="upload" />Загрузить файл выгрузки</button></>}
          {s.can_restore && <button type="button" className="btn ghost" onClick={() => setConfirm(true)}>Вернуть предыдущую копию</button>}
          {dirty && <span className="badge warn">есть несохранённые изменения</span>}
        </div>
      </div>
      {s.runs.length > 0 && <details className="disclosure"><summary>История загрузок</summary>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Начало</th><th>Запуск</th><th>Канал</th><th>Результат</th><th className="num">Получено</th><th className="num">Изменено</th><th className="num">с</th></tr></thead>
          <tbody>{s.runs.map((r, i) => <tr key={i}><td className="nowrap">{fmt(r.started_at)}</td><td>{{ schedule: "по расписанию", manual: "вручную", file: "из файла" }[r.trigger] ?? r.trigger}</td><td className="small">{r.channel ? CHANNEL_NAME[r.channel] ?? r.channel : "—"}</td>
            <td>{r.status === "ok" ? <span className="badge ok">успех</span> : r.status === "running" ? <span className="badge accent">идёт</span> : <span className="badge err" title={r.error ?? ""}>ошибка</span>}{r.error && <span className="sub small">{r.error.slice(0, 120)}</span>}</td>
            <td className="num">{num(r.fetched)}</td><td className="num">{num(r.changed)}</td><td className="num">{r.duration_ms != null ? (r.duration_ms / 1000).toFixed(1) : "—"}</td></tr>)}</tbody></table></div></details>}
      {confirm && <ConfirmDialog title="Вернуть предыдущую копию?" confirmLabel="Вернуть" danger={false} body={<p>Действующие данные источника «{s.title}» будут заменены предыдущей полной копией; текущая останется как резервная.</p>}
        onClose={() => setConfirm(false)} onConfirm={async () => { try { await api.vdb.restore(s.key); show("Предыдущая копия возвращена"); onChanged(); } catch (e) { show((e as ApiError).message, "error"); } }} />}
      {toast}
    </section>
  );
}

function Mappings() {
  const [items, setItems] = useState<VdbMapping[] | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => api.vdb.mappings().then((r) => setItems(r.items)).catch(() => setItems([])), []);
  useEffect(() => { void load(); }, [load]);
  const [f, setF] = useState({ vendor: "", product: "", catalog: "", action: "map" as "map" | "exclude" });
  const [sug, setSug] = useState<{ key: string; name: string; publisher: string }[]>([]);
  useEffect(() => { const t = window.setTimeout(() => { if (f.catalog.length > 1) api.vdb.suggest(f.catalog).then((r) => setSug(r.items)).catch(() => setSug([])); else setSug([]); }, 250); return () => window.clearTimeout(t); }, [f.catalog]);
  const add = async () => { try { await api.vdb.addMapping({ vendor_key: f.vendor, product: f.product, catalog_key: f.catalog, action: f.action }); setF({ ...f, vendor: "", product: "", catalog: "" }); show("Решение сохранено"); void load(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <section className="card">
      <div className="card-head"><h2>Сопоставление продуктов</h2></div>
      <p className="muted small">Автоматическое сопоставление ищет продукт по названию и производителю. Здесь можно указать, что продукт из базы уязвимостей — это продукт каталога (например, <span className="mono">oracle / jre</span> → Java), или исключить ложное совпадение. Решения сохраняются при обновлении базы и приложения; результаты пересчитываются автоматически.</p>
      <div className="form"><div className="cols vdb-map-form">
        <label>Производитель (CPE)<input className="mono" value={f.vendor} onChange={(e) => setF({ ...f, vendor: e.target.value })} placeholder="oracle" /></label>
        <label>Продукт (CPE или пакет)<input className="mono" value={f.product} onChange={(e) => setF({ ...f, product: e.target.value })} placeholder="jre" /></label>
        <label>Продукт каталога<input value={f.catalog} onChange={(e) => setF({ ...f, catalog: e.target.value })} list="vdb-sug" placeholder="ключ или название" /><datalist id="vdb-sug">{sug.map((x) => <option key={x.key} value={x.key}>{x.name}</option>)}</datalist></label>
        <label>Действие<select value={f.action} onChange={(e) => setF({ ...f, action: e.target.value as "map" | "exclude" })}><option value="map">Считать этим продуктом</option><option value="exclude">Исключить как ложное</option></select></label></div>
        <div className="form-actions"><button type="button" className="btn" onClick={add} disabled={!f.product.trim() || !f.catalog.trim()}><Icon name="plus" />Добавить</button></div></div>
      <div className="table-scroll">
        {!items ? <SkelRows rows={3} cols={4} /> : (
          <table className="table compact"><thead><tr><th>Производитель / продукт</th><th>Действие</th><th>Продукт каталога</th><th className="hide-sm">Кто и когда</th><th><span className="sr-only">Удалить</span></th></tr></thead>
            <tbody>{items.map((m) => <tr key={m.id}><td className="mono">{m.vendor_key || "*"} / {m.product_key}</td><td>{m.action === "map" ? <span className="badge ok">считать</span> : <span className="badge warn">исключить</span>}</td><td className="mono">{m.catalog_key}</td>
              <td className="small hide-sm">{m.created_by} · {fmt(m.created_at)}</td><td className="actions"><button className="btn mini ghost icon" aria-label="Удалить решение" onClick={async () => { await api.vdb.removeMapping(m.id); void load(); }}><Icon name="trash" size={15} /></button></td></tr>)}
              {!items.length && <tr><td colSpan={5}><Empty icon="sliders" title="Решений нет">Сопоставление работает автоматически; добавляйте решения, если находите ложные или пропущенные совпадения.</Empty></td></tr>}</tbody></table>)}
      </div>
      {toast}
    </section>
  );
}
