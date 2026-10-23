import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Host } from "../api";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Fetched, Pager } from "../components/Common";
import { fmt, fmtDate, num } from "../util";

const DAYS = [1, 3, 7, 14, 30];

export default function HostsPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") ?? ""); const [group, setGroup] = useState(""); const [os, setOs] = useState("");
  const [activity, setActivity] = useState(sp.get("activity") ?? "all");
  const [days, setDays] = useState<number | "">("");
  const [customDays, setCustomDays] = useState("");
  const [sort, setSort] = useState("name"); const [desc, setDesc] = useState(false);
  const [applied, setApplied] = useState({ q, group, os });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: Host[]; total: number; activity_days: number; fetched_at: string } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, group, os }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, group, os]);
  useEffect(() => {
    if (!ctx.current) return;
    setBusy(true);
    const d = days === "" ? (Number(customDays) || undefined) : days;
    api.hosts.list({ ...applied, activity, days: d, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, applied, activity, days, customDays, sort, desc, offset]);
  useEffect(() => { setSp((p) => { if (activity === "all") p.delete("activity"); else p.set("activity", activity); return p; }, { replace: true }); }, [activity, setSp]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const th = (key: string, label: string) => <th className="sortable" onClick={() => { if (sort === key) setDesc(!desc); else { setSort(key); setDesc(false); } setOffset(0); }}>{label}{sort === key ? (desc ? " ▾" : " ▴") : ""}</th>;
  return (
    <section>
      <div className="row"><h1>Компьютеры</h1><div className="spacer" />{data && <Fetched at={data.fetched_at} />}</div>
      <p className="muted">Управляемые устройства источника <b>{ctx.current.name}</b>. Статус активности отражает давность последнего подключения Агента администрирования к KSC (поле tmLastNagentConnected), а не доступность компьютера прямо сейчас.</p>
      <div className="card filters">
        <div className="row filter-row">
          <input className="grow" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Имя компьютера или DNS-имя" aria-label="Поиск" />
          <input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Группа администрирования" aria-label="Группа" style={{ maxWidth: 240 }} />
          <input value={os} onChange={(e) => setOs(e.target.value)} placeholder="ОС содержит" aria-label="ОС" style={{ maxWidth: 200 }} />
        </div>
        <div className="row filter-row">
          <div className="seg" role="group" aria-label="Активность">
            <button aria-pressed={activity === "all"} onClick={() => { setActivity("all"); setOffset(0); }}>Все</button>
            <button aria-pressed={activity === "active"} onClick={() => { setActivity("active"); setOffset(0); }}>Активные</button>
            <button aria-pressed={activity === "inactive"} onClick={() => { setActivity("inactive"); setOffset(0); }}>Без связи</button>
          </div>
          <label className="inline">Порог, сут
            <select value={days} onChange={(e) => { setDays(e.target.value === "" ? "" : Number(e.target.value)); setOffset(0); }}>
              <option value="">по настройке ({data?.activity_days ?? "…"})</option>{DAYS.map((d) => <option key={d} value={d}>{d}</option>)}<option value="0">другое</option>
            </select>
          </label>
          {days === 0 && <input type="number" min={1} max={3650} value={customDays} onChange={(e) => setCustomDays(e.target.value)} placeholder="дней" style={{ width: 100 }} aria-label="Произвольное число суток" />}
          <div className="spacer" />
          <span className="muted small">{busy ? "Загрузка…" : data ? `Всего: ${num(data.total)}` : ""}</span>
        </div>
      </div>
      {err && <div className="alert error">{err}</div>}
      <div className="table-scroll"><table className="table compact">
        <thead><tr>{th("name", "Компьютер")}{th("ip", "IP-адрес")}{th("os", "ОС")}{th("group", "Группа")}{th("last_connected", "Последнее подключение (UTC)")}<th>Активность</th></tr></thead>
        <tbody>{(data?.items ?? []).map((h) => (
          <tr key={h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link>{h.fqdn && h.fqdn !== h.name && <div className="small muted">{h.fqdn}</div>}</td><td className="nowrap">{h.ip || "—"}</td><td>{h.os}{h.os_version ? <span className="muted small"> {h.os_version}</span> : null}</td><td className="small">{h.group}</td>
            <td className="nowrap">{fmt(h.last_connected)}</td><td><ActivityBadge days={h.days_since_connection} activityDays={(days || Number(customDays)) || data?.activity_days || 7} /></td></tr>))}
          {data && !data.items.length && !busy && <tr><td colSpan={6} className="empty">Компьютеров по этим условиям нет.</td></tr>}
        </tbody>
      </table></div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
    </section>
  );
}

export function HostPage({ ctx }: { ctx: Ctx }) {
  const { hostId } = useParams();
  const [d, setD] = useState<Awaited<ReturnType<typeof api.hosts.one>> | null>(null);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("");
  useEffect(() => { if (!ctx.current || !hostId) return; api.hosts.one(Number(hostId)).then((r) => { setD(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [ctx.current, hostId]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  if (err) return <section><h1>Компьютер</h1><div className="alert error">{err}</div></section>;
  if (!d) return <div className="muted">Загрузка…</div>;
  const h = d.host;
  const sw = d.software.filter((s) => !filter || `${s.name} ${s.version} ${s.publisher}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <section>
      <div className="row"><h1>{h.name}</h1><ActivityBadge days={h.days_since_connection} activityDays={d.activity_days} /><div className="spacer" /><Fetched at={d.fetched_at} /><Link className="btn" to="/hosts">← К списку</Link></div>
      <div className="grid">
        <div className="card"><h2>Устройство</h2>
          <table className="table compact" style={{ boxShadow: "none" }}><tbody>
            {([["FQDN", h.fqdn || "—"], ["IP-адрес", h.ip || "—"], ["ОС", `${h.os} ${h.os_version}`.trim()], ["Дистрибутив Linux", h.linux_release || "—"], ["Группа администрирования", h.group || "—"], ["Последнее подключение к KSC (UTC)", fmt(h.last_connected)], ["Последняя видимость (UTC)", fmt(h.last_visible)], ["Обновление антивирусных баз (UTC)", fmt(h.last_av_update)], ["Последняя полная проверка (UTC)", fmt(h.last_full_scan)], ["Постоянная защита", h.rtp_state_label || "—"], ["Идентификатор (nId)", String(h.host_id)]] as [string, string][]).map(([k, v]) => <tr key={k}><td className="muted">{k}</td><td>{v}</td></tr>)}
          </tbody></table>
          {h.ksc_status && <div className={`alert ${h.ksc_status.status === "OK" ? "ok" : h.ksc_status.status === "критический" ? "error" : "warn"}`}>Статус KSC: <b>{h.ksc_status.status}</b>{h.ksc_status.reasons.length > 0 && <ul style={{ margin: "4px 0 0" }}>{h.ksc_status.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}</div>}
        </div>
        <div className="card"><h2>Продукты Kaspersky</h2>
          {!d.kaspersky.length ? <p className="muted">Сведений о продуктах Kaspersky нет (или объект v_akpub_hst_prdstate недоступен).</p> : (
            <table className="table compact" style={{ boxShadow: "none" }}><thead><tr><th>Продукт</th><th>Версия</th><th>Состояние</th><th>Базы (UTC)</th></tr></thead>
              <tbody>{d.kaspersky.map((k, i) => <tr key={i}><td>{k.product}{k.has_rtp && <span className="badge accent" style={{ marginLeft: 6 }}>постоянная защита</span>}</td><td>{k.build}</td><td>{k.state}</td><td className="nowrap">{k.is_av ? fmt(k.av_bases_date) : "—"}</td></tr>)}</tbody></table>)}
        </div>
      </div>
      <div className="card">
        <div className="row"><h2>Установленное ПО ({num(d.software.length)})</h2><div className="spacer" /><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Фильтр по названию, версии, производителю" style={{ maxWidth: 360 }} aria-label="Фильтр" /></div>
        <div className="table-scroll"><table className="table compact">
          <thead><tr><th>Программа</th><th>Версия</th><th>Производитель</th><th>Установлена</th></tr></thead>
          <tbody>{sw.slice(0, 1000).map((s) => <tr key={s.install_id}><td><Link to={`/software?q=${encodeURIComponent(s.name)}`}>{s.name}</Link></td><td>{s.version}</td><td className="small">{s.publisher}</td><td className="nowrap">{fmtDate(s.install_date)}</td></tr>)}</tbody>
        </table></div>
        {sw.length > 1000 && <p className="muted small">Показаны первые 1000 записей — уточните фильтр.</p>}
      </div>
    </section>
  );
}
