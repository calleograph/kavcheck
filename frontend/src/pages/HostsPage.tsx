import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Host, type HostVuln } from "../api";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Fetched, Pager } from "../components/Common";
import { Icon } from "../components/Icons";
import { Empty, HiddenNote, PageHead, Segmented, SkelRows, SortTh, Tabs } from "../components/ui";
import { EventList, type EvFilter } from "./EventsPage";
import { ProblemBadges } from "./ProtectionPage";
import { HostVulns } from "./VulnsPage";
import { fmt, fmtDate, num } from "../util";

const DAYS = [1, 3, 7, 14, 30];
type Activity = "all" | "active" | "inactive";

export default function HostsPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState(sp.get("q") ?? ""); const [group, setGroup] = useState(""); const [os, setOs] = useState("");
  const [activity, setActivity] = useState<Activity>((sp.get("activity") as Activity) || "active");
  const [days, setDays] = useState<string>("");
  const [customDays, setCustomDays] = useState("");
  const [sort, setSort] = useState("name"); const [desc, setDesc] = useState(false);
  const [applied, setApplied] = useState({ q, group, os });
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ items: Host[]; total: number; hidden: number; activity_days: number; fetched_at: string } | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { const t = window.setTimeout(() => { setApplied({ q, group, os }); setOffset(0); }, 350); return () => window.clearTimeout(t); }, [q, group, os]);
  const threshold = days === "custom" ? (Number(customDays) || undefined) : days ? Number(days) : undefined;
  useEffect(() => {
    if (!ctx.current) return;
    setBusy(true);
    api.hosts.list({ ...applied, activity, days: threshold, sort, desc, offset, limit: 50 }).then((r) => { setData(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [ctx.current, applied, activity, threshold, sort, desc, offset]);
  useEffect(() => { setSp((p) => { if (activity === "active") p.delete("activity"); else p.set("activity", activity); return p; }, { replace: true }); }, [activity, setSp]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } setOffset(0); };
  const eff = threshold || data?.activity_days || 7;
  return (
    <section>
      <PageHead title="Компьютеры" lede={<>Управляемые устройства источника <b>{ctx.current.name}</b>. Связь — давность последнего подключения Агента администрирования к KSC, а не доступность компьютера прямо сейчас.</>}>
        {data && <Fetched at={data.fetched_at} />}
      </PageHead>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Имя компьютера или DNS-имя" aria-label="Поиск" /></div>
        <input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Группа администрирования" aria-label="Группа" style={{ width: 220 }} />
        <input value={os} onChange={(e) => setOs(e.target.value)} placeholder="ОС содержит" aria-label="ОС" style={{ width: 170 }} />
        <Segmented<Activity> label="Связь с KSC" value={activity} onChange={(v) => { setActivity(v); setOffset(0); }} options={[["active", "Активные"], ["inactive", "Без связи"], ["all", "Все"]]} />
        <label className="inline">Порог
          <select value={days} onChange={(e) => { setDays(e.target.value); setOffset(0); }}>
            <option value="">{data?.activity_days ?? "…"} сут (по настройке)</option>{DAYS.map((d) => <option key={d} value={d}>{d} сут</option>)}<option value="custom">другой…</option>
          </select>
        </label>
        {days === "custom" && <input type="number" min={1} max={3650} value={customDays} onChange={(e) => setCustomDays(e.target.value)} placeholder="суток" style={{ width: 96 }} aria-label="Произвольный порог в сутках" autoFocus />}
      </div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="table-scroll">
        {!data && busy ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr><SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><SortTh k="ip" label="IP-адрес" sort={sort} desc={desc} onSort={onSort} /><SortTh k="os" label="ОС" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="group" label="Группа" sort={sort} desc={desc} onSort={onSort} /><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} /><th>Связь</th></tr></thead>
            <tbody style={{ opacity: busy ? .55 : 1, transition: "opacity .15s" }}>
              {(data?.items ?? []).map((h) => (
                <tr key={h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link>{h.fqdn && h.fqdn !== h.name && <span className="sub">{h.fqdn}</span>}</td><td className="mono nowrap">{h.ip || "—"}</td><td>{h.os}{h.os_version && <span className="sub">{h.os_version}</span>}</td><td className="small">{h.group}</td>
                  <td className="nowrap">{fmt(h.last_connected)}</td><td><ActivityBadge days={h.days_since_connection} activityDays={eff} /></td></tr>))}
              {data && !data.items.length && <tr><td colSpan={6}><Empty icon="monitor" title="Компьютеров не найдено">Измените поиск или фильтр связи с KSC.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      {data && <Pager total={data.total} offset={offset} limit={50} onPage={setOffset} />}
      {data && (activity === "active" || activity === "all") && <HiddenNote hidden={data.hidden} days={eff} all={activity === "all"} onToggle={() => { setActivity(activity === "all" ? "active" : "all"); setOffset(0); }} />}
      <p className="muted small mt-sm">Всего по условиям: {num(data?.total)}. Записи кластеров и подчинённых серверов не считаются компьютерами.</p>
    </section>
  );
}

type HostTab = "software" | "vulns" | "events";

export function HostPage({ ctx }: { ctx: Ctx }) {
  const { hostId } = useParams();
  const [sp, setSp] = useSearchParams();
  const tab = (["software", "vulns", "events"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "software") as HostTab;
  const [vulns, setVulns] = useState<{ items: HostVuln[]; unsupported?: string[] } | null>(null);
  const [vErr, setVErr] = useState("");
  const [evGroup, setEvGroup] = useState<EvFilter>(""); const [evThreat, setEvThreat] = useState("");
  useEffect(() => { setVulns(null); setVErr(""); }, [ctx.current, hostId]);
  useEffect(() => { if (tab === "vulns" && !vulns && !vErr && ctx.current && hostId) api.vulns.host(Number(hostId)).then(setVulns).catch((e) => setVErr((e as ApiError).message)); }, [tab, vulns, vErr, ctx.current, hostId]);
  const [d, setD] = useState<Awaited<ReturnType<typeof api.hosts.one>> | null>(null);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("");
  useEffect(() => { if (!ctx.current || !hostId) return; api.hosts.one(Number(hostId)).then((r) => { setD(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [ctx.current, hostId]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const back = <Link className="back-link" to="/hosts"><Icon name="arrowL" size={15} />Компьютеры</Link>;
  if (err) return <section><PageHead title="Компьютер" back={back} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!d) return <section><PageHead title={<span className="skel" style={{ width: 260, height: 28 }} />} back={back} /><div className="split even"><div className="card"><SkelRows rows={6} cols={2} /></div><div className="card"><SkelRows rows={3} cols={3} /></div></div></section>;
  const h = d.host;
  const sw = d.software.filter((s) => !filter || `${s.name} ${s.version} ${s.publisher}`.toLowerCase().includes(filter.toLowerCase()));
  const facts: [string, React.ReactNode][] = [["FQDN", h.fqdn || "—"], ["IP-адрес", <span className="mono">{h.ip || "—"}</span>], ["Операционная система", `${h.os} ${h.os_version}`.trim() || "—"], ["Дистрибутив Linux", h.linux_release ? <span className="mono">{h.linux_release}</span> : "—"],
    ["Группа администрирования", h.group || "—"], ["Подключение к KSC", fmt(h.last_connected)], ["Последняя видимость", fmt(h.last_visible)], ["Обновление антивирусных баз", fmt(h.last_av_update)],
    ["Полная проверка", fmt(h.last_full_scan)], ["Постоянная защита", h.rtp_state_label || "—"], ["Идентификатор в KSC", <span className="mono">{h.host_id}</span>]];
  const st = h.ksc_status;
  return (
    <section>
      <PageHead title={h.name} back={back} lede={<span className="row tight" style={{ flexWrap: "wrap" }}><ActivityBadge days={h.days_since_connection} activityDays={d.activity_days} />{st && <span className={`badge ${st.status === "OK" ? "ok" : st.status === "критический" ? "err" : "warn"}`}>Статус KSC: {st.status}</span>}{h.protection && <ProblemBadges problems={h.protection.problems} />}<span className="muted small">Время — UTC</span></span>}>
        <Fetched at={d.fetched_at} />
      </PageHead>
      <div className="split even">
        <div className="card">
          <h2>Сведения</h2>
          <dl className="kv">{facts.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
        </div>
        <div className="stack">
          {st && st.reasons.length > 0 && (
            <div className={`alert ${st.status === "критический" ? "error" : "warn"}`} style={{ margin: 0 }}><Icon name="alert" />
              <div className="alert-body"><b>Причины статуса «{st.status}»</b><ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>{st.reasons.map((r) => <li key={r}>{r}</li>)}</ul></div></div>)}
          <div className="card flush">
            <div className="card-head"><h2>Продукты Kaspersky</h2></div>
            {!d.kaspersky.length ? <Empty icon="shieldPulse" title="Нет сведений о продуктах">Агент не передавал данные о защитных продуктах, или объект v_akpub_hst_prdstate недоступен.</Empty> : (
              <div className="table-scroll"><table className="table compact"><thead><tr><th>Продукт</th><th>Версия</th><th>Состояние</th><th>Базы</th></tr></thead>
                <tbody>{d.kaspersky.map((k, i) => <tr key={i}><td>{k.product}{k.has_rtp && <span className="sub">обеспечивает постоянную защиту</span>}</td><td className="mono nowrap">{k.build}</td><td>{k.state}</td><td className="nowrap">{k.is_av ? fmt(k.av_bases_date) : "—"}</td></tr>)}</tbody></table></div>)}
          </div>
        </div>
      </div>
      <div className="mt">
        <Tabs<HostTab> label="Сведения о компьютере" value={tab} onChange={(t) => setSp((p) => { if (t === "software") p.delete("tab"); else p.set("tab", t); return p; }, { replace: true })}
          items={[{ id: "software", label: "Установленное ПО", count: d.software.length }, { id: "vulns", label: "Уязвимости", count: vulns?.items.length }, { id: "events", label: "События безопасности" }]} />
      </div>
      {tab === "software" && <>
        <div className="section-head"><span className="muted small">Программ: {num(d.software.length)}</span><div className="spacer" />
          <div className="input-icon" style={{ width: 340, maxWidth: "100%" }}><Icon name="search" size={16} /><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Название, версия или производитель" aria-label="Фильтр программ" /></div></div>
        <div className="table-scroll">
          <table className="table compact">
            <thead><tr><th>Программа</th><th>Версия</th><th>Производитель</th><th>Установлена</th></tr></thead>
            <tbody>{sw.slice(0, 1000).map((s) => <tr key={s.install_id}><td><Link to={`/software?q=${encodeURIComponent(s.name)}`}>{s.name}</Link></td><td className="mono">{s.version}</td><td className="small">{s.publisher || "—"}</td><td className="nowrap">{fmtDate(s.install_date)}</td></tr>)}
              {!sw.length && <tr><td colSpan={4}><Empty icon="search" title={filter ? "Ничего не найдено" : "Программ нет"}>{filter ? "Измените текст фильтра." : "KSC не передавал сведений о программах этого компьютера."}</Empty></td></tr>}
            </tbody>
          </table>
        </div>
        {sw.length > 1000 && <p className="muted small" style={{ marginTop: 8 }}>Показаны первые 1000 записей — уточните фильтр.</p>}
      </>}
      {tab === "vulns" && (vErr ? <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{vErr}</div></div>
        : !vulns ? <div className="card"><SkelRows rows={4} cols={5} /></div>
          : vulns.unsupported ? <div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет объектов уязвимостей KSC.</div></div>
            : <><HostVulns items={vulns.items} /><p className="muted small mt-sm"><Link to={`/vulnerabilities/hosts/${h.host_id}`}>Сводка уязвимостей компьютера</Link> — счётчики по уровням опасности.</p></>)}
      {tab === "events" && <><p className="muted small">События обнаружения за 30 суток: новые сверху.</p><EventList days={30} hostId={h.host_id} group={evGroup} threat={evThreat} onGroup={setEvGroup} onThreat={setEvThreat} /></>}
    </section>
  );
}
