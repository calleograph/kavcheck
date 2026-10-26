import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type ApiError, type ZoneCacheSettings, type ZoneCacheStatus } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";

const INTENSITY: Record<string, string> = { low: "Низкая: порции меньше, паузы длиннее (мягче для KSC и сервера)", normal: "Обычная", high: "Высокая: без пауз, быстрее" };
const JOB_STATUS: Record<string, string> = { queued: "в очереди", running: "выполняется", done: "готово", failed: "ошибка" };
const dur = (ms: number | null) => (ms == null ? "—" : ms < 60000 ? `${Math.round(ms / 1000)} с` : `${Math.floor(ms / 60000)} мин ${Math.round((ms % 60000) / 1000)} с`);

/** Ночной расчёт данных зон: расписание, ограничения ресурсов, состояние по источникам, очередь заданий. Страницы зон читают готовые данные. */
export default function CacheAdmin() {
  const [st, setSt] = useState<ZoneCacheStatus | null>(null); const [v, setV] = useState<ZoneCacheSettings | null>(null); const [base, setBase] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [toast, show] = useToast();
  const load = useCallback((withForm: boolean) => api.admin.zones.cache().then((s) => { setSt(s); if (withForm) { setV(s.settings); setBase(JSON.stringify(s.settings)); } }).catch((e) => setErr((e as ApiError).message)), []);
  useEffect(() => { void load(true); }, [load]);
  const active = !!st?.active.length;
  useEffect(() => { const t = window.setInterval(() => void load(false), active ? 3000 : 15000); return () => window.clearInterval(t); }, [load, active]);
  if (!st || !v) return <div className="card">{err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={4} cols={2} />}</div>;
  const set = <K extends keyof ZoneCacheSettings>(k: K, x: ZoneCacheSettings[K]) => setV({ ...v, [k]: x });
  const dirty = base !== JSON.stringify(v);
  const save = async (e: FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { const x = await api.admin.saveSettings("zonecache", v as unknown as Record<string, string | boolean | number>); setV(x as unknown as ZoneCacheSettings); setBase(JSON.stringify(x)); show("Сохранено"); void load(false); } catch (ex) { setErr((ex as ApiError).message); } finally { setBusy(false); }
  };
  const run = () => { setErr(""); api.admin.zones.cacheRun().then((r) => { show(r.created ? "Пересчёт поставлен в очередь" : "Такое задание уже выполняется или ждёт"); void load(false); }).catch((e) => setErr((e as ApiError).message)); };
  const r = st.resources;
  return (
    <div className="stack">
      <div className="card">
        <div className="row"><h2>Расчёт данных зон</h2><div className="spacer" /><button className="btn primary" onClick={run} disabled={active}><Icon name="refresh" /><span>Пересчитать все зоны сейчас</span></button></div>
        <p className="muted small lead-in">Страницы зон открываются мгновенно, потому что читают готовые данные из PostgreSQL. Тяжёлый расчёт (чтение KSC, сопоставление с базами уязвимостей, решения специалистов) выполняет фоновая служба по расписанию, по одному источнику за раз.
          Если расчёт не удался, остаются прежние данные с отметкой об их возрасте.</p>
        <div className="upd-versions">
          <div><div className="l">Следующий плановый расчёт</div><div className="v">{st.settings.enabled ? fmt(st.next_run) : "выключен"}</div><div className="l">часовой пояс: {st.timezone}</div></div>
          <div><div className="l">Последний успешный расчёт</div><div className="v">{st.last_success_at ? fmt(st.last_success_at) : "—"}</div><div className="l">длительность: {dur(st.last_duration_ms)}</div></div>
          <div><div className="l">Память фоновой службы</div><div className="v">{r.rss_mb} МБ</div><div className="l">пик {r.peak_mb} МБ · предел {r.soft_mb}/{r.hard_mb} МБ · тяжёлых задач {r.used} из {r.slots}{r.deferred ? ` · отложено из-за памяти: ${r.deferred}` : ""}</div></div>
        </div>
        {err && <div className="alert error mt" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        {st.active.map((j) => <div key={j.id} className="alert info mt calc-progress"><span className="spin sm" /><div className="alert-body"><b>{j.kind_ru}: {JOB_STATUS[j.status]}</b>{j.progress ? ` — ${j.progress}` : ""}{j.pct ? ` (${j.pct}%)` : ""}</div></div>)}
      </div>

      <form className="card form" onSubmit={save}>
        <h2>Расписание и ресурсы</h2>
        <label className="check"><input type="checkbox" className="switch" checked={v.enabled} onChange={(e) => set("enabled", e.target.checked)} />Ночной пересчёт включён</label>
        <div className="cols">
          <label>Время запуска<input type="time" value={v.at} onChange={(e) => set("at", e.target.value)} required /></label>
          <label>Часовой пояс<input value={v.timezone} placeholder={`как в общих настройках (${st.timezone})`} onChange={(e) => set("timezone", e.target.value.trim())} /><span className="help">Например Europe/Moscow. Пусто — часовой пояс организации.</span></label>
        </div>
        <div className="cols">
          <label>Тяжёлых задач одновременно<select value={v.parallel} onChange={(e) => set("parallel", Number(e.target.value))}><option value={1}>1 — по одной (рекомендуется)</option><option value={2}>2</option></select>
            <span className="help">Расчёт зон, анализ уязвимостей, сборка каталога и отчёты делят эти места: лишнее ждёт своей очереди, а не нагружает сервер.</span></label>
          <label>Интенсивность<select value={v.intensity} onChange={(e) => set("intensity", e.target.value as ZoneCacheSettings["intensity"])}>{Object.entries(INTENSITY).map(([k, t]) => <option key={k} value={k}>{t}</option>)}</select></label>
        </div>
        <div className="cols">
          <label>Потенциальных совпадений в списке на компьютер<input type="number" min={10} max={1000} value={v.ext_per_host} onChange={(e) => set("ext_per_host", Number(e.target.value))} /><span className="help">Сохраняются самые опасные (сначала из каталога CISA KEV); показатели учитывают все совпадения. Меньше — меньше данных в базе.</span></label>
        </div>
        <div className="cols">
          <label>Предел обнаружений на источник<input type="number" min={10000} max={20000000} step={10000} value={v.max_detections} onChange={(e) => set("max_detections", Number(e.target.value))} /><span className="help">Больше — сохраняются только счётчики по компьютерам, без списков и решений.</span></label>
          <label>Обновлять данные перед отчётом по расписанию, если им больше, часов<input type="number" min={1} max={720} value={v.stale_hours} onChange={(e) => set("stale_hours", Number(e.target.value))} /><span className="help">Свежие подготовленные данные используются как есть; в отчёте указана дата среза.</span></label>
        </div>
        <div className="form-actions"><button className="btn primary" aria-busy={busy} disabled={!dirty}><span>Сохранить</span></button>{dirty && <button type="button" className="btn ghost" onClick={() => setV(JSON.parse(base))}>Отменить изменения</button>}</div>
        {toast}
      </form>

      <div className="card flush"><div className="card-head"><h2>Источники KSC</h2></div>
        {!st.sources.length ? <Empty icon="database" title="Нет подключённых источников">Добавьте источник KSC в разделе «Источники KSC».</Empty> : (
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Источник</th><th>Данные от</th><th className="num">Компьютеров</th><th className="num">Обнаружений</th><th>Длительность</th><th>Состояние</th></tr></thead>
            <tbody>{st.sources.map((s) => <tr key={s.id}><td>{s.name}</td><td>{s.built_at ? fmt(s.built_at) : "не рассчитано"}</td><td className="num">{num(s.hosts)}</td><td className="num">{num(s.detections)}{s.agg_only ? " (счётчики)" : ""}</td><td>{dur(s.duration_ms)}</td>
              <td>{s.error ? <span className="warn-text" title={s.error}>ошибка: {s.error.slice(0, 120)}</span> : s.progress ? s.progress : s.newer ? <span className="muted">есть более свежие данные KSC</span> : s.gen ? <span className="ok-text">актуально</span> : "ожидает первого расчёта"}</td></tr>)}</tbody></table></div>)}
      </div>

      <div className="card flush"><div className="card-head"><h2>Последние задания</h2></div>
        {!st.jobs.length ? <p className="muted small pad-help">Заданий пока не было.</p> : (
          <div className="table-scroll"><table className="table compact"><thead><tr><th>Задание</th><th>Запросил</th><th>Создано</th><th>Длительность</th><th>Результат</th></tr></thead>
            <tbody>{st.jobs.map((j) => <tr key={j.id}><td>{j.kind_ru}{j.zone_id && j.zone_id !== "none" ? "" : ""}<span className="sub">{j.trigger === "nightly" ? "по расписанию" : j.trigger === "initial" ? "первый расчёт" : j.trigger === "auto" ? "после изменения зон или решений" : "вручную"}</span></td><td>{j.requested_by || "—"}</td><td>{fmt(j.requested_at)}</td>
              <td>{j.started_at && j.finished_at ? dur(new Date(j.finished_at).getTime() - new Date(j.started_at).getTime()) : "—"}</td>
              <td>{j.status === "failed" ? <span className="bad-text" title={j.error ?? ""}>ошибка: {(j.error ?? "").slice(0, 100)}</span> : <>{JOB_STATUS[j.status]}{j.error ? <span className="sub warn-text" title={j.error}>{j.error.slice(0, 90)}</span> : null}</>}</td></tr>)}</tbody></table></div>)}
      </div>
    </div>
  );
}
