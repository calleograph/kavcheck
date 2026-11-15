import { useCallback, useEffect, useState } from "react";
import { api, type ApiError, type SessionsNow as Data } from "../../api";
import type { Ctx } from "../../App";
import { FilterBar } from "../../components/FilterBar";
import { Icon } from "../../components/Icons";
import { useKept } from "../../components/Infinite";
import { QuickReportPanel } from "../../components/QuickReport";
import { Empty, SkelRows } from "../../components/ui";
import { fmt, num } from "../../util";

const KIND: Record<string, string> = { service: "служебная", system: "системная" };

/** «Сейчас в системе»: кто вошёл прямо сейчас — живой запрос к одному или нескольким KSC (текущий список вошедших, а не «входившие когда-либо»), с выгрузкой. */
export default function SessionsNow({ ctx }: { ctx: Ctx }) {
  const [q, setQ] = useKept("sn.q", ""); const [host, setHost] = useKept("sn.host", "");
  const [online, setOnline] = useKept("sn.online", true); const [service, setService] = useKept("sn.service", false);
  const [picked, setPicked] = useState<string[]>([]);
  const [applied, setApplied] = useState({ q, host });
  const [d, setD] = useState<Data | null>(null); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [report, setReport] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, host }), 450); return () => window.clearTimeout(t); }, [q, host]);
  const load = useCallback(async () => {
    setBusy(true); setErr("");
    try { setD(await api.devices.sessions({ q: applied.q, host: applied.host, online, show_service: service || undefined, source_ids: picked.join(",") || undefined })); }
    catch (e) { setErr((e as ApiError).message); } finally { setBusy(false); }
  }, [applied, online, service, picked]);
  useEffect(() => { void load(); }, [load, ctx.current?.id, ctx.all]);
  const choices = d?.choices ?? [];
  const chips = [...(q ? [{ id: "q", label: `Пользователь: ${q}`, onRemove: () => setQ("") }] : []), ...(host ? [{ id: "h", label: `Компьютер: ${host}`, onRemove: () => setHost("") }] : []),
    ...(!online ? [{ id: "on", label: "Включая не в сети", onRemove: () => setOnline(true) }] : []), ...(service ? [{ id: "sv", label: "Служебные и системные", onRemove: () => setService(false) }] : [])];
  return (<>
    <FilterBar search={{ value: q, onChange: setQ, placeholder: "Пользователь: логин, имя или UPN; маски *; несколько — через запятую", label: "Поиск пользователя" }}
      more={<div className="stack-sm">
        <label>Компьютер или IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="srv-*, 192.0.2.0/24" /></label>
        <label className="check"><input type="checkbox" className="switch" checked={online} onChange={(e) => setOnline(e.target.checked)} />Только компьютеры в сети сейчас</label>
        <label className="check"><input type="checkbox" className="switch" checked={service} onChange={(e) => setService(e.target.checked)} />Показывать служебные и системные учётные записи</label>
        {ctx.all && choices.length > 1 && <fieldset className="qr-sections"><legend>Источники KSC</legend>
          {choices.map((c) => <label key={c.id} className="check"><input type="checkbox" checked={!picked.length || picked.includes(c.id)} onChange={(e) => {
            const cur = picked.length ? picked : choices.map((x) => x.id); const next = e.target.checked ? [...cur, c.id] : cur.filter((x) => x !== c.id);
            setPicked(next.length === choices.length ? [] : next); }} />{c.name}</label>)}</fieldset>}
      </div>}
      moreActive={(host ? 1 : 0) + (online ? 0 : 1) + (service ? 1 : 0) + (picked.length ? 1 : 0)} chips={chips}
      onReset={() => { setQ(""); setHost(""); setOnline(true); setService(false); setPicked([]); }} count={{ n: d ? d.total : null, noun: ["сеанс", "сеанса", "сеансов"] }}
      onRefresh={() => void load()} refreshing={busy} report={{ onClick: () => setReport(true), disabled: !d || !d.total }} />
    {d && <p className="muted small fbar-note">{d.note} Получено {fmt(d.fetched_at)}.</p>}
    {d?.sources.filter((s) => s.error).map((s) => <div key={s.source_id} className="alert warn"><Icon name="alert" /><div className="alert-body">{s.source}: {s.error}</div></div>)}
    {d?.more && <div className="alert info"><Icon name="info" /><div className="alert-body">Показаны первые записи: уточните пользователя или компьютер, полный список — в отчёте.</div></div>}
    {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    <div className="table-scroll">
      {!d && busy ? <SkelRows cols={6} /> : (
        <table className="table">
          <thead><tr><th>Учётная запись</th><th>Компьютер</th><th className="hide-sm">IP-адрес</th><th className="hide-md">ОС</th><th className="hide-md">Группа</th><th>В сети</th><th className="hide-sm">Подключение к KSC</th>{ctx.all && <th className="hide-sm">Источник</th>}</tr></thead>
          <tbody>
            {(d?.items ?? []).map((r) => <tr key={`${r.source_id}:${r.host_id}:${r.login}`}>
              <td><span className="mono small">{r.domain && r.domain !== "локальная" ? `${r.domain}\\` : ""}{r.login}</span>{KIND[r.kind] && <span className="badge"> {KIND[r.kind]}</span>}{r.local && <span className="badge">локальная</span>}
                {r.user_name && <span className="sub">{r.user_name}</span>}</td>
              <td>{r.host}{r.fqdn && r.fqdn !== r.host && <span className="sub">{r.fqdn}</span>}</td>
              <td className="mono small hide-sm">{r.ip || "—"}</td><td className="small hide-md">{r.os || "—"}</td><td className="small hide-md">{r.group || "—"}</td>
              <td>{r.online ? <span className="badge ok">в сети</span> : r.online === false ? <span className="badge">не в сети</span> : <span className="muted">нет данных</span>}</td>
              <td className="small nowrap hide-sm">{fmt(r.last_connected)}</td>{ctx.all && <td className="small hide-sm">{r.source}</td>}</tr>)}
            {d && !d.items.length && <tr><td colSpan={ctx.all ? 8 : 7}><Empty icon="users" title="Никто не найден">{applied.q ? "Сейчас в системе нет пользователя с таким логином или именем" + (online ? " на компьютерах в сети." : ".") : "KSC не сообщает вошедших пользователей по этим условиям."}</Empty></td></tr>}
          </tbody>
        </table>)}
    </div>
    {d && <p className="muted small">Всего: {num(d.total)} {d.total === 1 ? "сеанс" : "сеансов"} · пользователей {num(new Set(d.items.map((r) => r.login.toLowerCase())).size)} · компьютеров {num(new Set(d.items.map((r) => `${r.source_id}:${r.host_id}`)).size)}</p>}
    {report && <QuickReportPanel kind="quick_sessions" title="Отчёт: кто сейчас в системе" lede="Пользователи в текущем списке вошедших KSC по условиям вкладки" options={{ scope: false }}
      params={{ q: applied.q || undefined, host: applied.host || undefined, online_only: online, show_service: service || undefined }}
      sourceIds={picked.length ? picked : ctx.all ? ctx.sources.map((s) => s.id) : []} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
  </>);
}
