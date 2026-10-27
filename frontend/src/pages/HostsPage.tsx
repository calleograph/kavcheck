import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type ApiError, type Host, type HostVulnsAll } from "../api";
import { HostVulnsTable } from "../components/HostVulnsTable";
import { HardwareTab, HwProblems, useHardware } from "../components/HostHardware";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Fetched, OnlineBadge } from "../components/Common";
import { ListFoot, VirtualRows, staticList, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { Icon } from "../components/Icons";
import { FilterBar, ReportButton } from "../components/FilterBar";
import { CheckAll, QuickReportPanel, ReportDock, useRowSel } from "../components/QuickReport";
import { maskMatcher } from "../mask";
import { Empty, HiddenNote, PageHead, Segmented, SkelRows, SortTh, Tabs, MaskHint } from "../components/ui";
import { EventList, type EvFilter } from "./EventsPage";
import { ProblemBadges } from "./ProtectionPage";
import { fmt, fmtDate, num } from "../util";
import { HostZones, ZoneSelect } from "../components/ZoneBits";
import { HostEol } from "../components/EolBits";

const DAYS = [1, 3, 7, 14, 30];
type Activity = "all" | "active" | "inactive";

export default function HostsPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useKept("hosts.q", sp.get("q") ?? ""); const [group, setGroup] = useKept("hosts.group", ""); const [os, setOs] = useKept("hosts.os", "");
  const [activity, setActivity] = useState<Activity>((sp.get("activity") as Activity) || "active");
  const [days, setDays] = useKept<string>("hosts.days", "");
  const [customDays, setCustomDays] = useKept("hosts.customDays", "");
  const [sort, setSort] = useKept("hosts.sort", "name"); const [desc, setDesc] = useKept("hosts.desc", false);
  const [zone, setZone] = useKept("hosts.zone", sp.get("zone") ?? "");
  const [applied, setApplied] = useState({ q, group, os });
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, group, os }), 350); return () => window.clearTimeout(t); }, [q, group, os]);
  const threshold = days === "custom" ? (Number(customDays) || undefined) : days ? Number(days) : undefined;
  const list = useInfinite<Host>(`hosts:${ctx.current?.id}`, [applied, activity, threshold, sort, desc, zone],
    (offset, limit) => api.hosts.list({ ...applied, activity, days: threshold, sort, desc, zone, offset, limit }) as unknown as Promise<Chunk<Host>>);
  const extra = list.extra as { hidden?: number; activity_days?: number; fetched_at?: string } | null;
  const sel = useRowSel<number>(); const [report, setReport] = useState(false);
  const canReport = ctx.me.user.role !== "viewer";
  useEffect(() => { setSp((p) => { if (activity === "active") p.delete("activity"); else p.set("activity", activity); return p; }, { replace: true }); }, [activity, setSp]);
  // переход из поиска в верхней панели на уже открытую страницу: запрос и активность берутся из адреса
  const urlQ = sp.get("q"), urlActivity = sp.get("activity") as Activity | null;
  useEffect(() => { if (urlQ !== null) setQ(urlQ); }, [urlQ]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (urlActivity) setActivity(urlActivity); }, [urlActivity]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  const eff = threshold || extra?.activity_days || 7;
  return (
    <section>
      <PageHead title="Компьютеры" lede={<>Управляемые устройства источника <b>{ctx.current.name}</b>. «Связь» — давность подключения Агента к KSC, «Онлайн» — видит ли KSC устройство в сети сейчас.</>}>
        {extra?.fetched_at && <Fetched at={extra.fetched_at} />}
      </PageHead>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Имя компьютера или DNS-имя", label: "Поиск компьютера" }}
        primary={<>
          <Segmented<Activity> label="Связь с KSC" value={activity} onChange={setActivity} options={[["active", "Активные"], ["inactive", "Без связи"], ["all", "Все"]]} />
          <ZoneSelect value={zone} onChange={setZone} />
        </>}
        more={<>
          <label className="field">Группа администрирования<input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Например, *Серверы*" /></label>
          <label className="field">Операционная система<input value={os} onChange={(e) => setOs(e.target.value)} placeholder="Например, *Windows 11*" /></label>
          <label className="field">Порог активности
            <select value={days} onChange={(e) => setDays(e.target.value)}>
              <option value="">{extra?.activity_days ?? "…"} сут (по настройке)</option>{DAYS.map((d) => <option key={d} value={d}>{d} сут</option>)}<option value="custom">другой…</option>
            </select></label>
          {days === "custom" && <label className="field">Своё значение, суток<input type="number" min={1} max={3650} value={customDays} onChange={(e) => setCustomDays(e.target.value)} placeholder="суток" autoFocus /></label>}
        </>}
        moreActive={[group, os, days].filter(Boolean).length}
        chips={[...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []), ...(activity !== "active" ? [{ id: "act", label: `Связь: ${activity === "all" ? "все" : "без связи"}`, onRemove: () => setActivity("active") }] : []),
          ...(zone ? [{ id: "zone", label: "Зона ответственности", onRemove: () => setZone("") }] : []), ...(group ? [{ id: "grp", label: `Группа: ${group}`, onRemove: () => setGroup("") }] : []),
          ...(os ? [{ id: "os", label: `ОС: ${os}`, onRemove: () => setOs("") }] : []), ...(days ? [{ id: "days", label: `Порог: ${days === "custom" ? customDays || "?" : days} сут`, onRemove: () => setDays("") }] : [])]}
        onReset={() => { setQ(""); setActivity("active"); setZone(""); setGroup(""); setOs(""); setDays(""); }}
        count={{ n: list.initial ? null : list.total, noun: ["компьютер", "компьютера", "компьютеров"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
        report={canReport ? { onClick: () => setReport(true), title: sel.count ? `Отчёт по отмеченным компьютерам (${sel.count})` : "Отчёт по всем компьютерам, подходящим под текущие фильтры" } : null} />
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(list.items.map((h) => h.host_id))} some={sel.someOf(list.items.map((h) => h.host_id))} onToggle={() => sel.toggleMany(list.items.map((h) => h.host_id))} />
              <SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><SortTh k="ip" label="IP-адрес" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><SortTh k="os" label="ОС" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <SortTh k="group" label="Группа" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><th>Связь</th><th>Онлайн</th></tr></thead>
            <tbody>
              <VirtualRows list={list} colSpan={8} estimate={46} row={(h) => (
                <tr className={sel.has(h.host_id) ? "sel" : ""}><td className="check"><input type="checkbox" aria-label={`Выбрать ${h.name}`} checked={sel.has(h.host_id)} onChange={() => sel.toggle(h.host_id)} /></td><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link>{h.fqdn && h.fqdn !== h.name && <span className="sub">{h.fqdn}</span>}{h.zone && <span className="sub zone-sub" title="Зона ответственности">{h.zone}</span>}</td><td className="mono nowrap hide-sm">{h.ip || "—"}</td><td className="hide-sm">{h.os}{h.os_version && <span className="sub">{h.os_version}</span>}</td><td className="small hide-sm">{h.group}</td>
                  <td className="nowrap hide-sm">{fmt(h.last_connected)}</td><td><ActivityBadge days={h.days_since_connection} activityDays={eff} /></td><td><OnlineBadge online={h.online} seen={h.last_visible} /></td></tr>)} />
              {!list.items.length && !list.loading && <tr><td colSpan={8}><Empty icon="monitor" title="Компьютеров не найдено">Измените поиск или фильтр связи с KSC.</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      {extra && (activity === "active" || activity === "all") && <HiddenNote hidden={extra.hidden ?? 0} days={eff} all={activity === "all"} onToggle={() => setActivity(activity === "all" ? "active" : "all")} />}
      <ReportDock label="Выбранные компьютеры" count={sel.count} noun={["компьютер выбран", "компьютера выбрано", "компьютеров выбрано"]} canReport={canReport} onClear={sel.clear} onReport={() => setReport(true)} />
      {report && <QuickReportPanel kind="quick_hosts" title={sel.count ? `Отчёт по компьютерам (${sel.count})` : "Отчёт по компьютерам"} lede={sel.count ? "Состояние, защита, установленное ПО и уязвимости выбранных компьютеров" : "Все компьютеры, подходящие под фильтры страницы"} options={{ sections: true, scope: false }}
        params={sel.count ? { host_ids: sel.ids } : { q: applied.q || undefined, group_contains: applied.group || undefined, os_contains: applied.os || undefined, zone: zone || undefined, include_inactive: activity === "all" || undefined,
          inactive_only: activity === "inactive" || undefined, active_days: threshold }} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(false)} />}
      <p className="muted small mt-sm">Записи кластеров и подчинённых серверов не считаются компьютерами.</p>
    </section>
  );
}

type HostTab = "software" | "vulns" | "events" | "hardware";

export function HostPage({ ctx }: { ctx: Ctx }) {
  const { hostId } = useParams();
  const [sp, setSp] = useSearchParams();
  const rawTab = sp.get("tab") === "vdb" ? "vulns" : sp.get("tab");                     // прежняя вкладка «Внешние базы» объединена с «Уязвимостями»
  const tab = (["software", "vulns", "events", "hardware"].includes(rawTab ?? "") ? rawTab : "software") as HostTab;
  const [vulns, setVulns] = useState<HostVulnsAll | null>(null);
  const [vErr, setVErr] = useState("");
  const [evGroup, setEvGroup] = useState<EvFilter>(""); const [evThreat, setEvThreat] = useState(""); const [report, setReport] = useState(false);
  // все уязвимости (KSC и внешние базы) загружаются сразу при открытии карточки: счётчик на вкладке не зависит от того, открывали ли вкладку
  useEffect(() => {
    setVulns(null); setVErr("");
    if (!ctx.current || !hostId) return;
    let live = true;
    const id = Number(hostId);
    // сначала быстро — данные KSC, затем полный список с внешними базами (сопоставление может занять десятки секунд)
    api.hosts.vulns(id, false).then((r) => { if (live) setVulns((cur) => cur ?? r); }).catch((e) => { if (live) setVErr((e as ApiError).message); });
    api.hosts.vulns(id).then((r) => { if (live) { setVulns(r); setVErr(""); } }).catch((e) => { if (live) setVulns((cur) => (cur ? { ...cur, notes: [...cur.notes, `Проверка по внешним базам не выполнена: ${(e as ApiError).message}`], external_checked: true } : cur)); });
    return () => { live = false; };
  }, [ctx.current, hostId]);
  const hwq = useHardware(Number(hostId), !!ctx.current && !!hostId);      // одна выборка из KSC для строки «Сведения», предупреждений и вкладки
  const [d, setD] = useState<Awaited<ReturnType<typeof api.hosts.one>> | null>(null);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("");
  useEffect(() => { if (!ctx.current || !hostId) return; api.hosts.one(Number(hostId)).then((r) => { setD(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [ctx.current, hostId]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const back = <Link className="back-link" to="/hosts"><Icon name="arrowL" size={15} />Компьютеры</Link>;
  if (err) return <section><PageHead title="Компьютер" back={back} />
    {/не найден/i.test(err) ? <div className="card"><Empty icon="monitor" title="Компьютер не найден" action={<Link className="btn" to="/hosts">К списку компьютеров</Link>}>Он удалён из KSC или относится к другому источнику — проверьте источник в верхней панели.</Empty></div>
      : <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}</section>;
  if (!d) return <section><PageHead title={<span className="skel skel-title" />} back={back} /><div className="split even"><div className="card"><SkelRows rows={6} cols={2} /></div><div className="card"><SkelRows rows={3} cols={3} /></div></div></section>;
  const h = d.host;
  const hit = maskMatcher(filter);
  const sw = d.software.filter((s) => !hit || hit(s.name, s.version, s.publisher));
  const swList = staticList(`host-sw:${h.host_id}:${filter}`, sw);
  const facts: [string, React.ReactNode][] = [["FQDN", h.fqdn || "—"], ["IP-адрес", <span className="mono">{h.ip || "—"}</span>], ["Операционная система", `${h.os} ${h.os_version}`.trim() || "—"], ["Дистрибутив Linux", h.linux_release ? <span className="mono">{h.linux_release}</span> : "—"],
    ["Аппаратная часть", hwq.d ? (hwq.d.hw.known ? <span className={hwq.d.problems.length ? "warn-text" : ""}>{hwq.d.hw.line}{hwq.d.hw.virtual ? " (ВМ)" : ""}</span> : <span className="muted">Нет данных</span>) : hwq.err ? <span className="muted">Нет данных</span> : <span className="muted">…</span>],
    ["Группа администрирования", h.group || "—"], ["Подключение к KSC", fmt(h.last_connected)], ["Последняя видимость", fmt(h.last_visible)], ["Обновление антивирусных баз", fmt(h.last_av_update)],
    ["Полная проверка", fmt(h.last_full_scan)], ["Постоянная защита", h.rtp_state_label || "—"], ["Идентификатор в KSC", <span className="mono">{h.host_id}</span>]];
  const st = h.ksc_status;
  return (
    <section>
      <PageHead title={h.name} back={back} lede={<span className="row tight wrap"><OnlineBadge online={h.online} seen={h.last_visible} /><ActivityBadge days={h.days_since_connection} activityDays={d.activity_days} />{st && <span className={`badge ${st.status === "OK" ? "ok" : st.status === "критический" ? "err" : "warn"}`}>Статус KSC: {st.status}</span>}{h.protection && <ProblemBadges problems={h.protection.problems} />}<HostZones sourceId={ctx.current?.id} hostId={h.host_id} /></span>}>
        <Fetched at={d.fetched_at} />
        {ctx.me.user.role !== "viewer" && <ReportButton onClick={() => setReport(true)} title="Отчёт по этому компьютеру: состояние, защита, установленное ПО, уязвимости" />}
      </PageHead>
      {report && <QuickReportPanel kind="quick_hosts" title={`Отчёт: ${h.name}`} lede="Состояние, защита, установленное ПО и все уязвимости компьютера" options={{ sections: true, scope: false }}
        params={{ host_ids: [h.host_id] }} activityDays={ctx.me.activity_days} canReport onClose={() => setReport(false)} />}
      <div className="split even">
        <div className="card">
          <h2>Сведения</h2>
          <dl className="kv pairs">{facts.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
        </div>
        <div className="stack">
          {st && st.reasons.length > 0 && (
            <div className={`alert flat ${st.status === "критический" ? "error" : "warn"}`}><Icon name="alert" />
              <div className="alert-body"><b>Причины статуса «{st.status}»</b><ul className="reasons">{st.reasons.map((r) => <li key={r}>{r}</li>)}</ul></div></div>)}
          {hwq.d && <HwProblems d={hwq.d} />}
          {ctx.current && <HostEol sourceId={ctx.current.id} hostId={h.host_id} />}
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
          items={[{ id: "software", label: "Установленное ПО", count: d.software.length }, { id: "vulns", label: vulns && !vulns.external_checked ? "Уязвимости (идёт проверка по внешним базам)" : "Уязвимости", count: vulns?.counts.total }, { id: "events", label: "События безопасности" }, { id: "hardware", label: "Аппаратная часть", ...(hwq.d && hwq.d.problems.length ? { count: hwq.d.problems.length } : {}) }]} />
      </div>
      {tab === "software" && <>
        <div className="section-head"><span className="muted small">Программ: {num(d.software.length)}</span><div className="spacer" />
          <div className="input-icon w-search"><Icon name="search" size={16} /><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Название, версия или производитель" aria-label="Фильтр программ" /><MaskHint /></div></div>
        <div className="table-scroll">
          <table className="table compact virt">
            <thead><tr><th>Программа</th><th>Версия</th><th>Производитель</th><th>Установлена</th></tr></thead>
            <tbody><VirtualRows list={swList} colSpan={4} estimate={32} row={(s) => <tr><td><Link to={`/software?q=${encodeURIComponent(s.name)}`}>{s.name}</Link></td><td className="mono">{s.version}</td><td className="small">{s.publisher || "—"}</td><td className="nowrap">{fmtDate(s.install_date)}</td></tr>} />
              {!sw.length && <tr><td colSpan={4}><Empty icon="search" title={filter ? "Ничего не найдено" : "Программ нет"}>{filter ? "Измените текст фильтра." : "KSC не передавал сведений о программах этого компьютера."}</Empty></td></tr>}
            </tbody>
          </table>
        </div>
      </>}
      {tab === "vulns" && (vErr ? <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{vErr}</div></div>
        : !vulns ? <div className="card"><SkelRows rows={4} cols={5} /></div>
          : <><HostVulnsTable data={vulns} hostId={h.host_id} onMore={async (off) => (await api.hosts.vulns(h.host_id, vulns.external_checked, off)).groups} /><p className="muted small mt-sm"><Link to={`/vulnerabilities/hosts/${h.host_id}`}>Сводка уязвимостей KSC</Link> — счётчики по уровням опасности.</p></>)}
      {tab === "hardware" && <HardwareTab d={hwq.d} err={hwq.err} />}
      {tab === "events" && <><p className="muted small">События обнаружения за 30 суток: новые сверху.</p><EventList ctx={ctx} days={30} hostId={h.host_id} group={evGroup} threat={evThreat} onGroup={setEvGroup} onThreat={setEvThreat} /></>}
    </section>
  );
}
