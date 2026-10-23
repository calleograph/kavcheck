import { FormEvent, useEffect, useState } from "react";
import { api, type ApiError, type SettingsValues } from "../../api";

function Group({ group, title, intro, children }: { group: string; title: string; intro: string; children: (v: SettingsValues, set: (k: string, val: string | number | boolean) => void) => React.ReactNode }) {
  const [v, setV] = useState<SettingsValues | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => { api.admin.settings(group).then(setV).catch((e) => setMsg({ ok: false, text: (e as ApiError).message })); }, [group]);
  if (!v) return <div className="muted">Загрузка…</div>;
  const save = async (e: FormEvent) => { e.preventDefault(); setMsg(null); try { setV(await api.admin.saveSettings(group, v)); setMsg({ ok: true, text: "Сохранено" }); } catch (x) { setMsg({ ok: false, text: (x as ApiError).message }); } };
  return (
    <form className="card form" onSubmit={save}>
      <h2>{title}</h2><p className="muted">{intro}</p>
      {children(v, (k, val) => setV({ ...v, [k]: val }))}
      <div className="row"><button className="btn primary">Сохранить</button>{msg && <span className={msg.ok ? "ok-text" : "bad-text"}>{msg.text}</span>}</div>
    </form>
  );
}

export default function GeneralAdmin() {
  return (
    <section>
      <Group group="general" title="Общие настройки" intro="Порог активности применяется по умолчанию в разделах и отчётах: компьютер считается актуальным, если подключался к KSC в течение этого числа суток. В каждом отчёте порог можно изменить или включить все компьютеры.">
        {(v, set) => (<>
          <div className="cols">
            <label>Название установки<input value={String(v.site_name ?? "")} onChange={(e) => set("site_name", e.target.value)} maxLength={80} /></label>
            <label>Порог активности, суток<select value={Number(v.activity_days ?? 7)} onChange={(e) => set("activity_days", Number(e.target.value))}>{[1, 3, 7, 14, 30].map((d) => <option key={d} value={d}>{d}</option>)}{![1, 3, 7, 14, 30].includes(Number(v.activity_days)) && <option value={Number(v.activity_days)}>{Number(v.activity_days)}</option>}</select>
              <span className="row tight"><span className="help">или произвольно:</span><input type="number" min={1} max={3650} value={Number(v.activity_days ?? 7)} onChange={(e) => set("activity_days", Number(e.target.value))} style={{ width: 100 }} aria-label="Произвольный порог" /></span></label>
          </div>
          <div className="cols">
            <label>Часовой пояс<input value={String(v.timezone ?? "UTC")} onChange={(e) => set("timezone", e.target.value)} placeholder="Europe/Moscow" /><span className="help">Даты KSC хранятся в UTC; в интерфейсе показывается время браузера, пояс — для служебных задач.</span></label>
            <label>Хранить отчёты, дней<input type="number" min={1} max={3650} value={Number(v.report_keep_days ?? 90)} onChange={(e) => set("report_keep_days", Number(e.target.value))} /></label>
            <label>Хранить журнал событий, дней<input type="number" min={1} max={3650} value={Number(v.journal_keep_days ?? 90)} onChange={(e) => set("journal_keep_days", Number(e.target.value))} /></label>
          </div>
        </>)}
      </Group>
      <Group group="reports" title="Ограничения отчётов и запросов" intro="Защита производственных SQL Server: предел строк одного отчёта и учёт только компьютеров (записи кластеров и подчинённых серверов не считаются компьютерами).">
        {(v, set) => (<>
          <div className="cols">
            <label>Предел строк отчёта<input type="number" min={1000} max={5000000} value={Number(v.max_rows ?? 100000)} onChange={(e) => set("max_rows", Number(e.target.value))} /></label>
          </div>
          <label className="check"><input type="checkbox" checked={!!v.exclude_slave_servers} onChange={(e) => set("exclude_slave_servers", e.target.checked)} /> Исключать записи кластеров и подчинённых серверов (bIsSlaveServer = 1)</label>
          <label className="check"><input type="checkbox" checked={!!v.include_inactive_default} onChange={(e) => set("include_inactive_default", e.target.checked)} /> По умолчанию включать в отчёты компьютеры без связи</label>
        </>)}
      </Group>
    </section>
  );
}
