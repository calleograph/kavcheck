import { useEffect, useState, type FormEvent } from "react";
import { api, type ApiError, type DevicesStatus, type EolSummary } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { SkelRows } from "../../components/ui";
import { fmt } from "../../util";

type Eol = { include_in_analytics: boolean; soon_days: number };
type Hw = { enabled: boolean; cpu_ok_cores: number; cpu_critical_cores: number; ram_min_mb: number; exclude_masks: string[] };
type Dev = { enabled: boolean; interval_minutes: number; retention_days: number; hide_service: boolean; service_masks: string[] };

/** Настройки EOL и пользователей устройств: что считается проблемой, как часто опрашивать списки пользователей KSC и какие записи считать служебными. Загрузка базы endoflife.date — «База уязвимостей». */
export default function EolAdmin() {
  const [eol, setEol] = useState<Eol | null>(null); const [dev, setDev] = useState<Dev | null>(null); const [masks, setMasks] = useState("");
  const [hw, setHw] = useState<Hw | null>(null); const [hwMasks, setHwMasks] = useState("");
  const [sum, setSum] = useState<EolSummary | null>(null); const [ds, setDs] = useState<DevicesStatus | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(""); const [toast, show] = useToast();
  useEffect(() => {
    api.admin.settings("eol").then((x) => setEol(x as unknown as Eol)).catch((e) => setErr((e as ApiError).message));
    api.admin.settings("devices").then((x) => { const d = x as unknown as Dev; setDev(d); setMasks((d.service_masks ?? []).join("\n")); }).catch((e) => setErr((e as ApiError).message));
    api.admin.settings("hardware").then((x) => { const h = x as unknown as Hw; setHw(h); setHwMasks((h.exclude_masks ?? []).join("\n")); }).catch((e) => setErr((e as ApiError).message));
    api.eol.summary().then(setSum).catch(() => undefined); api.devices.status().then(setDs).catch(() => undefined);
  }, []);
  if (!eol || !dev || !hw) return <div className="card">{err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={4} cols={2} />}</div>;
  const saveEol = async (e: FormEvent) => { e.preventDefault(); setErr(""); setBusy("eol"); try { setEol(await api.admin.saveSettings("eol", eol as unknown as Record<string, string | boolean | number>) as unknown as Eol); show("Сохранено; пересчёт EOL запустится сам"); } catch (ex) { setErr((ex as ApiError).message); } finally { setBusy(""); } };
  const saveDev = async (e: FormEvent) => {
    e.preventDefault(); setErr(""); setBusy("dev");
    try { const x = await api.admin.saveSettings("devices", { ...dev, service_masks: masks.split("\n").map((m) => m.trim()).filter(Boolean) } as unknown as Record<string, string | boolean | number>) as unknown as Dev; setDev(x); setMasks(x.service_masks.join("\n")); show("Сохранено"); }
    catch (ex) { setErr((ex as ApiError).message); } finally { setBusy(""); }
  };
  const saveHw = async (e: FormEvent) => {
    e.preventDefault(); setErr(""); setBusy("hw");
    try { const x = await api.admin.saveSettings("hardware", { ...hw, exclude_masks: hwMasks.split("\n").map((m) => m.trim()).filter(Boolean) } as unknown as Record<string, string | boolean | number>) as unknown as Hw; setHw(x); setHwMasks(x.exclude_masks.join("\n")); show("Сохранено"); }
    catch (ex) { setErr((ex as ApiError).message); } finally { setBusy(""); }
  };
  return (
    <div className="stack">
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <form className="card form" onSubmit={saveEol}>
        <h2>EOL: жизненный цикл ПО и ОС</h2>
        <p className="muted small lead-in">База сроков поддержки — endoflife.date (загрузка и расписание — «База уязвимостей» → источник «endoflife.date»). Сопоставление с вашим каталогом программ и ОС устройств считает фоновая служба; при недоступности сайта используется прежняя копия.</p>
        {sum && <p className="small">База: {sum.base.products} продуктов, {sum.base.releases} веток{sum.base.last_ok_at ? `, обновлена ${fmt(sum.base.last_ok_at)}` : ", ещё не загружена"}. {Object.values(sum.sources).map((s) => `${s.source}: ${s.computed_at ? `рассчитано ${fmt(s.computed_at)}` : "не рассчитано"}${s.error ? ` (ошибка: ${s.error})` : ""}`).join("; ")}.</p>}
        <label className="check"><input type="checkbox" className="switch" checked={eol.include_in_analytics} onChange={(e) => setEol({ ...eol, include_in_analytics: e.target.checked })} />Учитывать EOL в аналитике (общий список проблем, дашборды зон)</label>
        <label>Окончание поддержки «приближается» за, суток<input type="number" min={30} max={730} value={eol.soon_days} onChange={(e) => setEol({ ...eol, soon_days: Number(e.target.value) })} /></label>
        <div className="row"><button className="btn primary" disabled={busy === "eol"}>{busy === "eol" ? <span className="spin" /> : <Icon name="save" />}Сохранить</button></div>
      </form>
      <form className="card form" onSubmit={saveDev}>
        <h2>Пользователи устройств</h2>
        <p className="muted small lead-in">KSC хранит только списки «вошли сейчас» и «входили ранее» — без дат. KAV Checker опрашивает эти списки по расписанию и накапливает наблюдения; даты в таблицах — это даты наблюдений. Опрос лёгкий: одна выборка порциями из базы KSC (только чтение).</p>
        <label className="check"><input type="checkbox" className="switch" checked={dev.enabled} onChange={(e) => setDev({ ...dev, enabled: e.target.checked })} />Опрос включён</label>
        <div className="cols">
          <label>Интервал опроса, минут<input type="number" min={10} max={1440} value={dev.interval_minutes} onChange={(e) => setDev({ ...dev, interval_minutes: Number(e.target.value) })} /><span className="help">Короткие сеансы между опросами не видны.</span></label>
          <label>Хранить наблюдения, суток<input type="number" min={8} max={730} value={dev.retention_days} onChange={(e) => setDev({ ...dev, retention_days: Number(e.target.value) })} /><span className="help">Для пользователей, которых KSC уже не показывает.</span></label>
        </div>
        <label className="check"><input type="checkbox" className="switch" checked={dev.hide_service} onChange={(e) => setDev({ ...dev, hide_service: e.target.checked })} />Не показывать служебные и системные учётные записи</label>
        <label>Маски служебных учётных записей (по одной в строке; * — любое число символов)<textarea rows={5} value={masks} onChange={(e) => setMasks(e.target.value)} className="mono" /><span className="help">Системные (SYSTEM, DWM-1, UMFD-0, «имя$», root и т. п.) определяются сами.</span></label>
        {ds && <ul className="small">{ds.items.map((s) => <li key={s.source_id}>{s.source}: {!s.supported ? "в базе KSC нет таблиц пользователей" : s.polled_at ? `последний опрос ${fmt(s.polled_at)}, наблюдения с ${fmt(s.first_poll_at)}` : "опроса ещё не было"}{s.error ? ` — ошибка: ${s.error}` : ""}</li>)}</ul>}
        <div className="row"><button className="btn primary" disabled={busy === "dev"}>{busy === "dev" ? <span className="spin" /> : <Icon name="save" />}Сохранить</button></div>
      </form>
      <form className="card form" onSubmit={saveHw}>
        <h2>Ресурсы Linux-серверов</h2>
        <p className="muted small lead-in">Оценка только для Linux-устройств по данным инвентаризации KSC (агентов и прав не требуется). Windows и рабочие станции не проверяются; нет данных — оценка пропускается. Проблема показывается в «Состоянии защиты», в зонах ответственности и отчётах отдельно от уязвимостей.</p>
        <label className="check"><input type="checkbox" className="switch" checked={hw.enabled} onChange={(e) => setHw({ ...hw, enabled: e.target.checked })} />Контроль ресурсов включён</label>
        <div className="cols">
          <label>Норма: ядер CPU от<input type="number" min={1} max={64} value={hw.cpu_ok_cores} onChange={(e) => setHw({ ...hw, cpu_ok_cores: Number(e.target.value) })} /><span className="help">Меньше — предупреждение «Мало ядер CPU».</span></label>
          <label>Критично: ядер CPU не больше<input type="number" min={1} max={64} value={hw.cpu_critical_cores} onChange={(e) => setHw({ ...hw, cpu_critical_cores: Number(e.target.value) })} /><span className="help">«Недостаточно ядер CPU».</span></label>
          <label>Минимум ОЗУ, МБ<input type="number" min={256} max={1048576} step={256} value={hw.ram_min_mb} onChange={(e) => setHw({ ...hw, ram_min_mb: Number(e.target.value) })} /><span className="help">Меньше — предупреждение «Недостаточно ОЗУ».</span></label>
        </div>
        <label>Исключения: маски имён серверов (по одной в строке; * — любое число символов)<textarea rows={3} value={hwMasks} onChange={(e) => setHwMasks(e.target.value)} className="mono" /><span className="help">Для устройств, которым малые ресурсы допустимы (шлюзы, тестовые стенды).</span></label>
        <div className="row"><button className="btn primary" disabled={busy === "hw"}>{busy === "hw" ? <span className="spin" /> : <Icon name="save" />}Сохранить</button></div>
      </form>
      {toast}
    </div>
  );
}
