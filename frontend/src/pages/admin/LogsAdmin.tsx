import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type LogType, type LogsOverview } from "../../api";
import { ConfirmDialog } from "../../components/Dialogs";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows } from "../../components/ui";
import { bytes, fmt, num } from "../../util";

const KIND_RU: Record<string, string> = { operational: "операционный", audit: "аудит (обязательные события)" };

const catsText = (c: unknown) => Object.entries((c as Record<string, number>) || {}).map(([k, v]) => `${k}=${v}`).join(", ");
const parseCats = (t: string): Record<string, number> => Object.fromEntries(t.split(/[,;\s]+/).filter(Boolean).map((x) => x.split("=")).filter((p) => p.length === 2).map(([k, v]) => [k.trim(), Number(v)]));

/** «Журналы и хранение»: реестр журналов (владелец, место, формат, назначение), сроки и объём каждого, архивы и общая квота. Аудит не удаляется молча; сбой записи журнала не влияет на работу приложения. */
export default function LogsAdmin() {
  const [sp] = useSearchParams();
  const focus = sp.get("type");
  const [d, setD] = useState<LogsOverview | null>(null);
  const [s, setS] = useState<Record<string, number | boolean | Record<string, number>> | null>(null);
  const [cats, setCats] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [del, setDel] = useState<string | null>(null);
  const [toast, show] = useToast();
  const load = useCallback(() => api.admin.logs().then((x) => { setD(x); setS(x.settings); setCats(catsText(x.settings.journal_by_category)); }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (d && d.requested) { const t = window.setTimeout(() => void load(), 5000); return () => window.clearTimeout(t); } }, [d, load]);
  if (!d || !s) return err ? <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={5} cols={4} />;
  const set = (k: string, v: number | boolean) => setS({ ...s, [k]: v });
  const num_ = (k: string) => Number(s[k] ?? 0);
  const save = async () => {
    setBusy(true); setErr("");
    try { await api.admin.saveLogs({ ...s, journal_by_category: parseCats(cats) }); show("Настройки хранения сохранены"); await load(); } catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  };
  const t = d.totals;
  const pct = t.quota_bytes ? Math.min(100, Math.round(100 * t.used_bytes / t.quota_bytes)) : null;
  return (
    <div className="stack">
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {d.disk.warn && <div className="alert warn" role="status"><Icon name="alert" /><div className="alert-body">На диске данных свободно всего {bytes(d.disk.free)}: освободите место, пока это не затронуло базу данных.</div></div>}
      {d.report?.warnings.map((w) => <div key={w} className="alert warn" role="status"><Icon name="alert" /><div className="alert-body">{w}</div></div>)}
      <section className="card">
        <div className="pt-sum">
          <div><b>{bytes(t.logs_bytes)}</b><span>занято журналами</span></div><div><b>{bytes(t.archive_bytes)}</b><span>занято архивами</span></div>
          <div><b>{t.quota_bytes ? bytes(t.quota_bytes) : "без предела"}</b><span>общий лимит</span></div><div><b>{num(t.files)}</b><span>архивных файлов</span></div>
          <div><b>{t.oldest ? fmt(t.oldest) : "—"}</b><span>самая старая запись</span></div><div><b>{d.next_run ? fmt(d.next_run) : "—"}</b><span>следующая очистка</span></div>
          <div><b>{bytes(d.disk.free)}</b><span>свободно на диске данных</span></div>
        </div>
        {pct !== null && <div className={`lic-bar mt ${pct >= 95 ? "bad" : ""}`} role="img" aria-label={`Квота использована на ${pct}%`}><i style={{ width: `${pct}%` }} className={pct >= 95 ? "bad" : pct >= 80 ? "warn" : ""} /></div>}
        <p className="muted small mt">Последняя очистка: {d.last_run ? fmt(d.last_run) : "ещё не выполнялась"}{d.report?.deferred ? " · отложена на время сканирования Pentest" : ""}{d.requested ? " · запрошена, выполняется воркером" : ""}.
          {" "}<button type="button" className="link-btn" disabled={d.requested} onClick={async () => { await api.admin.runLogs(); show("Очистка запрошена"); void load(); }}>Очистить сейчас</button></p>
      </section>

      <section className="card"><h2>Журналы</h2>
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Журнал</th><th className="num">Записей</th><th className="num">Объём</th><th className="num">Хранить, суток</th><th className="num">Предел, МБ</th><th>Архив</th><th className="num">Архивов</th></tr></thead>
          <tbody>{d.items.map((i: LogType) => { const dk = i.key === "journal" ? "journal_days" : i.key === "audit" ? "audit_days" : "pt_events_days"; const mk = i.key === "journal" ? "journal_max_mb" : i.key === "audit" ? "audit_max_mb" : "pt_events_max_mb"; const ak = i.key === "journal" ? "journal_archive" : "pt_events_archive";
            return (<tr key={i.key} className={focus === i.key ? "on" : ""} id={`log-${i.key}`}>
              <td><b>{i.title}</b><span className="sub">{i.purpose}</span><span className="sub small">Владелец: {i.owner} · {i.location} · {i.format} · {KIND_RU[i.kind]}</span>
                <span className="sub small"><Link to={`/admin?tab=${i.tab}`}>Открыть журнал</Link></span></td>
              <td className="num">{num(i.rows)}</td><td className="num">{bytes(i.bytes)}<span className="sub">с {i.oldest ? fmt(i.oldest) : "—"}</span></td>
              <td className="num"><input className="w-num" type="number" min={0} max={3650} value={num_(dk)} onChange={(e) => set(dk, Number(e.target.value))} aria-label={`Срок хранения: ${i.title}`} />{i.key === "audit" && <span className="sub small">0 — не удалять</span>}</td>
              <td className="num"><input className="w-num" type="number" min={0} max={102400} value={num_(mk)} onChange={(e) => set(mk, Number(e.target.value))} aria-label={`Предел объёма: ${i.title}`} />{i.key === "audit" ? <span className="sub small">только предупреждение</span> : <span className="sub small">0 — без предела</span>}</td>
              <td>{i.mandatory ? <span className="badge ok" title="Записи аудита удаляются только после переноса в архив">всегда</span> : <label className="check"><input type="checkbox" checked={!!s[ak]} onChange={(e) => set(ak, e.target.checked)} />перед удалением</label>}</td>
              <td className="num">{i.archives}<span className="sub">{bytes(i.archive_bytes)}</span></td></tr>); })}
            {d.external.map((x) => <tr key={x.key} className="muted"><td><b>{x.title}</b><span className="sub">{x.purpose}</span><span className="sub small">Владелец: {x.owner} · {x.location} · {x.format}</span></td><td colSpan={6} className="small">Ротация задаётся в deployment/compose.yml (max-size, max-file); из интерфейса не меняется.</td></tr>)}</tbody></table></div>
        <label className="field mt">Сроки по категориям журнала событий (необязательно)<input value={cats} onChange={(e) => setCats(e.target.value)} placeholder="auth=14, ksc=30" /><span className="help">Категории: auth, ksc, report, catalog, worker, admin, system. Для остальных действует общий срок.</span></label>
      </section>

      <section className="card"><h2>Архивы и квота</h2>
        <div className="cols">
          <label>Общая квота журналов и архивов, МБ<input type="number" min={0} value={num_("quota_mb")} onChange={(e) => set("quota_mb", Number(e.target.value))} /><span className="help">0 — без предела. При достижении: удаляются просроченные данные, старые записи сжимаются в архив, старейшие просроченные архивы удаляются. Если освободить место нельзя без нарушения сроков — предупреждение.</span></label>
          <label>Срок хранения архивов, суток<input type="number" min={1} value={num_("archive_days")} onChange={(e) => set("archive_days", Number(e.target.value))} /></label>
          <label>Предел числа архивных файлов<input type="number" min={1} value={num_("archive_max_files")} onChange={(e) => set("archive_max_files", Number(e.target.value))} /></label>
          <label>Размер файла архива, МБ<input type="number" min={1} value={num_("archive_file_mb")} onChange={(e) => set("archive_file_mb", Number(e.target.value))} /><span className="help">Ротация по размеру: по достижении начинается новый файл</span></label>
          <label>Ротация каждые, часов<input type="number" min={1} max={168} value={num_("rotate_hours")} onChange={(e) => set("rotate_hours", Number(e.target.value))} /></label>
          <label>Предупреждать при свободном месте менее, МБ<input type="number" min={100} value={num_("disk_warn_free_mb")} onChange={(e) => set("disk_warn_free_mb", Number(e.target.value))} /></label>
        </div>
        <div className="row gap"><label className="check"><input type="checkbox" className="switch" checked={!!s.auto_clean} onChange={(e) => set("auto_clean", e.target.checked)} />Автоматическая очистка по сроку и объёму</label>
          <label className="check"><input type="checkbox" className="switch" checked={!!s.compress} onChange={(e) => set("compress", e.target.checked)} />Сжимать архивы (gzip)</label></div>
        <div className="form-actions"><button className="btn primary" aria-busy={busy} onClick={() => void save()}>Сохранить</button></div>
        {d.archives.length > 0 ? <div className="table-scroll mt"><table className="table compact"><thead><tr><th>Файл</th><th>Журнал</th><th className="num">Размер</th><th>Создан</th><th /></tr></thead>
          <tbody>{d.archives.slice(0, 100).map((a) => <tr key={a.name}><td className="mono small">{a.name}</td><td>{d.items.find((i) => i.key === a.type)?.title ?? a.type}</td><td className="num">{bytes(a.bytes)}</td><td className="nowrap small">{fmt(a.at)}</td>
            <td className="nowrap"><a className="btn mini" href={api.admin.archiveUrl(a.name)} download>Скачать</a> <button className="btn mini" onClick={() => setDel(a.name)}>Удалить</button></td></tr>)}</tbody></table></div> : <p className="muted small mt">Архивов пока нет.</p>}
      </section>
      {del && <ConfirmDialog title="Удалить архив?" body={<>Файл {del} будет удалён без возможности восстановления.</>} confirmLabel="Удалить" onClose={() => setDel(null)} onConfirm={async () => { try { await api.admin.removeArchive(del); setDel(null); void load(); } catch (e) { setDel(null); setErr((e as ApiError).message); } }} />}
      {toast}
    </div>
  );
}
