import { FormEvent, useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, type ApiError, type SettingsValues } from "../../api";
import { Icon } from "../../components/Icons";
import { useToast } from "../../components/Toast";
import { Segmented, SkelRows } from "../../components/ui";

function Group({ group, title, intro, children }: { group: string; title: string; intro: string; children: (v: SettingsValues, set: (k: string, val: string | number | boolean) => void) => ReactNode }) {
  const [v, setV] = useState<SettingsValues | null>(null);
  const [base, setBase] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [toast, show] = useToast();
  useEffect(() => { api.admin.settings(group).then((x) => { setV(x); setBase(JSON.stringify(x)); }).catch((e) => setErr((e as ApiError).message)); }, [group]);
  if (!v) return <div className="card">{err ? <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div> : <SkelRows rows={3} cols={2} />}</div>;
  const dirty = base !== JSON.stringify(v);
  const save = async (e: FormEvent) => { e.preventDefault(); setErr(""); setBusy(true); try { const x = await api.admin.saveSettings(group, v); setV(x); setBase(JSON.stringify(x)); show("Настройки сохранены"); } catch (y) { setErr((y as ApiError).message); } finally { setBusy(false); } };
  return (
    <form className="card form" onSubmit={save}>
      <h2>{title}</h2><p className="muted small lead-in">{intro}</p>
      {children(v, (k, val) => setV({ ...v, [k]: val }))}
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="form-actions"><button className="btn primary" aria-busy={busy} disabled={!dirty}><span>Сохранить</span></button>
        {dirty && <><button type="button" className="btn ghost" onClick={() => setV(JSON.parse(base))}>Отменить изменения</button><span className="badge warn">есть несохранённые изменения</span></>}</div>
      {toast}
    </form>
  );
}

const PRESET = [1, 3, 7, 14, 30];

export default function GeneralAdmin() {
  return (
    <div className="stack">
      <Group group="general" title="Компьютеры и хранение" intro="Компьютеры, которые давно не подключались к KSC, скрываются в рабочих разделах: программы, карточки продуктов, списки компьютеров, уязвимости и отчёты (подсчёты тоже). Данные о них не удаляются — на каждой странице их можно показать кнопкой «Показать все».">
        {(v, set) => { const d = Number(v.activity_days ?? 30); const custom = !PRESET.includes(d); return (<>
          <label>Показывать компьютеры, активные за последние
            <span className="row">
              <Segmented label="Показывать компьютеры, активные за последние" value={custom ? "" : String(d)} onChange={(x) => set("activity_days", Number(x))} options={PRESET.map((p) => [String(p), `${p} сут`] as [string, string])} />
              <span className="row tight"><input type="number" min={1} max={3650} value={d} onChange={(e) => set("activity_days", Number(e.target.value))} className="w-num" aria-label="Произвольное число суток" /><span className="muted small">{custom ? "своё значение" : "или своё число"}</span></span>
            </span>
            <span className="help">Активность — давность последнего подключения Агента администрирования к KSC. После изменения каталог программ пересчитывается автоматически.</span></label>
          <div className="cols">
            <label>Название установки<input value={String(v.site_name ?? "")} onChange={(e) => set("site_name", e.target.value)} maxLength={80} /><span className="help">Показывается в меню и заголовке вкладки</span></label>
            <label>Часовой пояс<input className="mono" value={String(v.timezone ?? "UTC")} onChange={(e) => set("timezone", e.target.value)} placeholder="Europe/Moscow" /><span className="help">Даты KSC хранятся в UTC; интерфейс показывает время браузера</span></label>
          </div>
          <div className="cols">
            <label>Хранить отчёты, дней<input type="number" min={1} max={3650} value={Number(v.report_keep_days ?? 90)} onChange={(e) => set("report_keep_days", Number(e.target.value))} /></label>
            <div className="field"><span>Хранение журналов</span><Link className="link-btn" to="/admin?tab=logs">Администрирование → Журналы и хранение</Link><span className="help">Сроки, объём, архивы и квота журналов задаются там</span></div>
          </div>
        </>); }}
      </Group>
      <Group group="reports" title="Ограничения отчётов" intro="Защита производственных SQL Server: предел строк одного отчёта и учёт только компьютеров (записи кластеров и подчинённых серверов компьютерами не считаются).">
        {(v, set) => (<>
          <div className="cols"><label>Предел строк отчёта<input type="number" min={1000} max={5000000} value={Number(v.max_rows ?? 100000)} onChange={(e) => set("max_rows", Number(e.target.value))} /></label><span /></div>
          <label className="check"><input type="checkbox" className="switch" checked={!!v.exclude_slave_servers} onChange={(e) => set("exclude_slave_servers", e.target.checked)} /><span className="check-body">Исключать кластеры и подчинённые серверы<span className="help">Записи с признаком bIsSlaveServer = 1</span></span></label>
          <label className="check"><input type="checkbox" className="switch" checked={!!v.include_inactive_default} onChange={(e) => set("include_inactive_default", e.target.checked)} />По умолчанию включать в отчёты компьютеры без связи</label>
        </>)}
      </Group>
    </div>
  );
}
