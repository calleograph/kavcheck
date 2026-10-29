import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type ProblemKey, type ProtHost, type ProtSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Fetched, OnlineBadge } from "../components/Common";
import { FilterBar } from "../components/FilterBar";
import { ExpandCell, ExpandTh, ExpandedRow, XGrid, XItem, useExpanded } from "../components/ExpandRow";
import { ListFoot, VirtualRows, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { Icon } from "../components/Icons";
import { CheckAll, QuickReportPanel, ReportDock, useRowSel } from "../components/QuickReport";
import { Empty, HiddenNote, PageHead, Segmented, SkelRows, SortTh, Spectrum } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";
import { ZoneSelect } from "../components/ZoneBits";
import { OwnerSub } from "../components/OwnerBlock";

export const PROBLEM_TONE: Record<ProblemKey, "err" | "warn"> = { no_av: "err", rtp_off: "err", infected: "err", license: "err", bases_old: "warn", scan_old: "warn", reboot: "warn", hw_cpu: "warn", hw_ram: "warn" };
export const PROBLEM_SHORT: Record<ProblemKey, string> = { no_av: "нет антивируса", rtp_off: "защита не работает", infected: "невылеченные объекты", bases_old: "старые базы", license: "лицензия истекла", scan_old: "нет полной проверки", reboot: "нужна перезагрузка", hw_cpu: "мало ядер CPU", hw_ram: "мало ОЗУ" };
export const shortProduct = (s: string) => s.replace(/^Kaspersky\s+/, "").replace(" for ", " для ");
const daysAgo = (iso: string | null) => (iso ? Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86400000)) : null);

/** Проблемы защиты компьютера: красные — защиты фактически нет, жёлтые — требуют внимания. */
export function ProblemBadges({ problems }: { problems: ProblemKey[] }) {
  if (!problems.length) return <span className="badge ok">защита в порядке</span>;
  return <span className="badges">{problems.map((p) => <span key={p} className={`badge ${PROBLEM_TONE[p]}`}>{PROBLEM_SHORT[p]}</span>)}</span>;
}

/** Раздел «Состояние защиты»: где защиты нет или она не работает, какие версии KES и Агента развёрнуты, что говорит статус KSC. */

export default function ProtectionPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  const problem = sp.get("problem") ?? ""; const hwLevel = sp.get("hw_level") ?? ""; const product = sp.get("product") ?? ""; const build = sp.get("build") ?? "";
  const onlineOnly = sp.get("online") !== "0";   // по умолчанию — только устройства, которые KSC сейчас видит в сети
  const [basesDays, setBasesDays] = useKept("prot.bases", "3"); const [scanDays, setScanDays] = useKept("prot.scan", "30");
  const [q, setQ] = useKept("prot.q", ""); const [group, setGroup] = useKept("prot.group", ""); const [applied, setApplied] = useState({ q, group });
  const [all, setAll] = useKept("prot.all", false); const [sort, setSort] = useKept("prot.sort", "risk"); const [desc, setDesc] = useKept("prot.desc", true);
  const [zone, setZone] = useKept("prot.zone", sp.get("zone") ?? "");
  const force = useRef(false);
  useEffect(() => { const t = window.setTimeout(() => setApplied({ q, group }), 350); return () => window.clearTimeout(t); }, [q, group]);
  const list = useInfinite<ProtHost>(`protection:${ctx.current?.id}`, [problem, hwLevel, product, build, basesDays, scanDays, applied, all, onlineOnly, sort, desc, zone], (offset, limit) => {
    const refresh = (force.current && offset === 0) || undefined; force.current = false;
    return api.protection({ problem, hw_level: hwLevel, product, build, bases_days: basesDays, scan_days: scanDays, ...applied, all_hosts: all, online: onlineOnly, zone, sort, desc, offset, limit, refresh }) as unknown as Promise<Chunk<ProtHost>>;
  });
  const data = list.extra as { summary?: ProtSummary | null; unsupported?: string[] } | null;
  const busy = list.loading;
  const sel = useRowSel<number>(); const ex = useExpanded<number>(); const [report, setReport] = useState<"all" | "sel" | null>(null);
  const canReport = ctx.me.user.role !== "viewer";
  // результат щелчка — список компьютеров ниже сводки: прокручиваем к нему, чтобы изменение было видно сразу
  const reveal = () => window.requestAnimationFrame(() => document.getElementById("prot-hosts")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  const revealed = useRef(false);
  useEffect(() => {   // пришли с главной с фильтром (например, «Без антивируса») — сразу к списку; при возврате из карточки место восстанавливает список
    if (revealed.current || list.initial || list.restoreY != null) return;
    revealed.current = true;
    if (problem || product) reveal();
  }, [list.initial]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const setParams = (kv: Record<string, string>, show = false) => { setSp((p) => { for (const [k, v] of Object.entries(kv)) { if (v) p.set(k, v); else p.delete(k); } return p; }); if (show) reveal(); };
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(k !== "name"); } };
  const s = data?.summary;
  const count = (k: ProblemKey) => s?.problems.find((p) => p.key === k)?.hosts ?? 0;
  const pct = (n: number) => (s?.hosts ? Math.round((n / s.hosts) * 100) : 0);
  const pTitle = s?.problems.find((p) => p.key === problem)?.title ?? (problem === "ok" ? "Без проблем" : problem === "hw" ? "Недостаток аппаратных ресурсов" : problem);
  const vTitle = product ? `${shortProduct(s?.versions.find((v) => v.code === product)?.product ?? product)}${build ? ` ${build}` : ""}` : "";
  const filtered = !!(problem || hwLevel || product || applied.q || applied.group || zone);
  if (data?.unsupported) return <section><PageHead title="Состояние защиты" /><div className="alert warn"><Icon name="alert" /><div className="alert-body">В базе источника нет объектов состояния защиты ({data.unsupported.join(", ")}). Раздел недоступен для этого источника.</div></div></section>;
  return (
    <section>
      <PageHead title="Состояние защиты" lede="Где защиты Kaspersky нет или она не работает, насколько свежи базы и какие версии продуктов развёрнуты.">
        <label className="check inline-check" title={s && !s.online_data ? "KSC не передаёт сведения о присутствии устройств в сети" : "Только устройства, которые KSC сейчас видит в сети"}>
          <input type="checkbox" className="switch" checked={onlineOnly && s?.online_data !== false} disabled={s?.online_data === false} onChange={(e) => setParams({ online: e.target.checked ? "" : "0" })} />Только онлайн</label>
        {s && <Fetched at={s.fetched_at} />}
        <button className="btn" onClick={() => { force.current = true; list.reload(); }} aria-busy={busy && !!data}><Icon name="refresh" /><span>Обновить</span></button>
      </PageHead>
      {list.error && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      {s && <p className="scope-line">{s.online_only
        ? <><span className="dot ok" aria-hidden />Устройства в сети сейчас: <b>{num(s.hosts)}</b>. Ещё {num(s.offline_hosts)} {plural(s.offline_hosts, "активное устройство", "активных устройства", "активных устройств")} не в сети — их сведения о защите могут быть устаревшими. <button type="button" className="link-btn" onClick={() => setParams({ online: "0" })}>Показать все</button></>
        : s.online_data ? <><span className="dot off" aria-hidden />Все устройства, подключавшиеся к KSC за {s.activity_days} сут: <b>{num(s.hosts)}</b>; у тех, что не в сети, сведения — на время последнего подключения. <button type="button" className="link-btn" onClick={() => setParams({ online: "" })}>Только онлайн</button></>
          : <>KSC не передаёт сведения о присутствии устройств в сети: показаны устройства, подключавшиеся к KSC за {s.activity_days} сут.</>}</p>}
      <div className="meters">
        <div className="meter"><span className="l">Защищены</span><span className={`v ${s && pct(s.protected) < 90 ? "warn-text" : ""}`}>{s ? `${pct(s.protected)}%` : "…"}</span><span className="t">{s ? `${num(s.protected)} из ${num(s.hosts)}${s.online_only ? " в сети" : ""}: антивирус работает, базы свежее ${s.bases_days} сут` : ""}</span></div>
        {([["no_av", "Без антивируса", "нет продукта Kaspersky"], ["rtp_off", "Защита не работает", "остановлена, в сбое или не запущена"], ["bases_old", "Устаревшие базы", `старше ${s?.bases_days ?? "…"} сут`]] as [ProblemKey, string, string][]).map(([k, l, t]) => (
          <button key={k} type="button" className={`meter meter-btn ${problem === k ? "on" : ""}`} aria-pressed={problem === k} onClick={() => setParams({ problem: problem === k ? "" : k }, problem !== k)}>
            <span className="l">{l}</span><span className={`v ${s && count(k) ? (PROBLEM_TONE[k] === "err" ? "bad-text" : "warn-text") : ""}`}>{s ? num(count(k)) : "…"}</span><span className="t">{t}</span>
          </button>))}
      </div>

      <div className="split even mt">
        <div className="card flush">
          <div className="card-head"><h2>Проблемы защиты</h2><div className="spacer" />{s && <span className="muted small">из {num(s.hosts)} компьютеров</span>}</div>
          {!s ? <div className="pad"><SkelRows rows={5} cols={3} /></div> : (
            <ul className="ledger" aria-label="Проблемы защиты: выберите, чтобы показать компьютеры">
              {s.problems.map((p) => {
                const on = problem === p.key; const tone = p.hosts ? (PROBLEM_TONE[p.key] === "err" ? "bad" : "warn") : "ok";
                const hint = p.key === "bases_old" ? `базы старше ${s.bases_days} сут` : p.key === "scan_old" ? `полная проверка старше ${s.scan_days} сут или не выполнялась` : p.hint;
                return (
                  <li key={p.key}><button type="button" className={`ledger-row ${on ? "on" : ""}`} aria-pressed={on} onClick={() => setParams({ problem: on ? "" : p.key }, !on)}>
                    <span className={`dot ${tone}`} aria-hidden /><span className="lg-main"><b>{p.title}</b><span className="lg-sub">{hint}</span></span>
                    <span className="lg-bar" aria-hidden><i className={tone} style={{ width: `${p.hosts ? Math.max(2, pct(p.hosts)) : 0}%` }} /></span>
                    <span className="lg-n">{num(p.hosts)}<span className="lg-pct">{p.hosts ? `${pct(p.hosts)}%` : ""}</span></span>
                  </button></li>);
              })}
            </ul>)}
          {s && s.hw.linux > 0 && (
            <div className="card-foot hw-foot">
              <span className="small"><b>Аппаратные ресурсы Linux-серверов</b> (отдельно от уязвимостей и событий): критических {num(s.hw.critical)}, предупреждений {num(s.hw.warning)}
                {s.hw.with_data < s.hw.linux ? `; у ${num(s.hw.linux - s.hw.with_data)} из ${num(s.hw.linux)} Linux-устройств нет данных об оборудовании — оценка по ним не выполняется` : ""}.
                Пороги: ядер от {s.hw.thresholds.cpu_ok_cores} — норма, {s.hw.thresholds.cpu_critical_cores} — критично, ОЗУ меньше {s.hw.thresholds.ram_min_mb} МБ — предупреждение{ctx.me.user.is_admin ? <> (<Link to="/admin?tab=eolcfg">настроить</Link>)</> : ""}.</span>
              <span className="row tight"><Segmented label="Уровень проблемы ресурсов" value={problem === "hw" || problem.startsWith("hw_") ? hwLevel : "-"} onChange={(v) => setParams({ problem: problem.startsWith("hw") ? problem : "hw", hw_level: v === "-" ? "" : v }, true)}
                options={[["", "Все ресурсы"], ["critical", "Критические"], ["warning", "Предупреждения"]]} />{(problem === "hw" || hwLevel) && <button type="button" className="link-btn" onClick={() => setParams({ problem: "", hw_level: "" })}>Сбросить</button>}</span>
            </div>)}
          <div className="card-foot">
            <span className="muted small">Пороги:</span>
            <span className="row tight"><span className="small">базы старше</span><Segmented label="Порог актуальности баз, суток" value={basesDays} onChange={setBasesDays} options={[["1", "1"], ["3", "3"], ["7", "7"]]} /><span className="small">сут</span></span>
            <span className="row tight"><span className="small">проверка старше</span><Segmented label="Порог полной проверки, суток" value={scanDays} onChange={setScanDays} options={[["7", "7"], ["30", "30"], ["90", "90"]]} /><span className="small">сут</span></span>
          </div>
          {s && s.reasons.length > 0 && (
            <details className="disclosure pad-x">
              <summary>Причины статуса в KSC: критический {num(s.ksc_status["критический"] ?? 0)}, предупреждение {num(s.ksc_status["предупреждение"] ?? 0)}</summary>
              <ul className="rows">{s.reasons.map((r) => <li key={r.bit}><div className="r-main"><span>{r.title}</span></div><span className="num small">{num(r.hosts)}</span></li>)}</ul>
            </details>)}
        </div>
        <div className="card">
          <div className="card-head"><h2>Версии продуктов</h2><div className="spacer" /><span className="muted small">выберите версию, чтобы увидеть компьютеры</span></div>
          {!s ? <SkelRows rows={4} cols={2} /> : !s.versions.length ? <Empty icon="shieldPulse" title="Нет сведений о продуктах">KSC не получал от Агентов данных о продуктах Kaspersky.</Empty> : (
            <div className="stack">
              {s.versions.map((v) => (
                <div key={v.code} className="ver-block">
                  <div className="ver-head"><b>{shortProduct(v.product)}</b><span className="muted small">{v.versions.length > 1 ? `${num(v.on_latest)} из ${num(v.hosts)} на новейшей ${v.latest}` : `все ${num(v.hosts)} на ${v.latest}`}</span></div>
                  <Spectrum label={`Версии: ${v.product}`} unit=" комп." segs={v.versions.map((x) => ({ key: x.build, label: x.build, value: x.hosts }))}
                    selected={product === v.code ? new Set([build]) : undefined} onToggle={(b) => setParams(product === v.code && build === b ? { product: "", build: "" } : { product: v.code, build: b }, !(product === v.code && build === b))} />
                </div>))}
            </div>)}
        </div>
      </div>

      <div className="section-head" id="prot-hosts"><h2>Компьютеры</h2></div>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Компьютер или IP-адрес", label: "Компьютер" }}
        primary={<>
          <Segmented label="Показать" value={problem === "ok" ? "ok" : problem ? "problem" : ""} onChange={(v) => setParams({ problem: v === "ok" ? "ok" : "" })}
            options={[["", "Все"], ["ok", "Без проблем"], ...(problem && problem !== "ok" ? [["problem", pTitle] as [string, string]] : [])]} />
          <ZoneSelect value={zone} onChange={setZone} />
        </>}
        more={<label className="field">Группа администрирования<input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Например, *Серверы*" /></label>}
        moreActive={group ? 1 : 0}
        chips={[...(q ? [{ id: "q", label: `Компьютер: ${q}`, onRemove: () => setQ("") }] : []), ...(problem && problem !== "ok" ? [{ id: "prob", label: `Проблема: ${pTitle}`, onRemove: () => setParams({ problem: "" }) }] : []),
          ...(problem === "ok" ? [{ id: "ok", label: "Без проблем", onRemove: () => setParams({ problem: "" }) }] : []), ...(product ? [{ id: "ver", label: `Версия: ${vTitle}`, onRemove: () => setParams({ product: "", build: "" }) }] : []),
          ...(zone ? [{ id: "zone", label: "Зона ответственности", onRemove: () => setZone("") }] : []), ...(group ? [{ id: "grp", label: `Группа: ${group}`, onRemove: () => setGroup("") }] : [])]}
        onReset={() => { setQ(""); setGroup(""); setZone(""); setParams({ problem: "", product: "", build: "" }); }}
        count={{ n: list.initial ? null : list.total, noun: ["компьютер", "компьютера", "компьютеров"] }} onRefresh={() => list.reload()} refreshing={list.refreshing}
        report={canReport ? { onClick: () => setReport("all"), disabled: list.initial || !list.total, title: sel.count ? "Отчёт по отмеченным компьютерам — кнопка в панели выбора внизу" : "Отчёт по всем компьютерам списка с текущими фильтрами" } : null} />
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table virt">
            <thead><tr><CheckAll all={sel.allOf(list.items.map((h) => h.host_id))} some={sel.someOf(list.items.map((h) => h.host_id))} onToggle={() => sel.toggleMany(list.items.map((h) => h.host_id))} /><ExpandTh />
              <SortTh k="name" label="Компьютер" sort={sort} desc={desc} onSort={onSort} /><th>Онлайн</th><th>Защитный продукт</th><th className="hide-sm">Постоянная защита</th>
              <SortTh k="bases" label="Базы" sort={sort} desc={desc} onSort={onSort} /><SortTh k="scan" label="Полная проверка" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
              <SortTh k="risk" label="Проблемы" sort={sort} desc={desc} onSort={onSort} /><SortTh k="last_connected" label="Подключение к KSC" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /></tr></thead>
            <VirtualRows group list={list} colSpan={10} estimate={52} row={(h) => {
                const b = daysAgo(h.av?.bases ?? null); const old = h.problems.includes("bases_old");
                return (
                  <>
                  <tr className={`clickable ${sel.has(h.host_id) ? "sel" : ""}`} onClick={(e) => { if (!(e.target as HTMLElement).closest("a, input, button")) navigate(`/hosts/${h.host_id}`); }}>
                    <td className="check"><input type="checkbox" aria-label={`Выбрать ${h.name}`} checked={sel.has(h.host_id)} onChange={() => sel.toggle(h.host_id)} /></td>
                    <ExpandCell id={`p${h.host_id}`} open={ex.has(h.host_id)} onToggle={() => ex.toggle(h.host_id)} label={h.name} />
                    <td><Link to={`/hosts/${h.host_id}`} className="strong-link">{h.name}</Link><span className="sub mono">{h.ip}</span>{h.zone && <span className="sub zone-sub" title="Зона ответственности">{h.zone}</span>}<OwnerSub o={h.owner} /></td>
                    <td className="nowrap"><OnlineBadge online={h.online} seen={h.last_visible} />{h.online === false && h.last_info_update && <span className="sub">сведения от {fmtDate(h.last_info_update)}</span>}</td>
                    <td>{h.av ? <>{shortProduct(h.av.product)}<span className="sub mono">{h.av.build}</span></> : <span className="bad-text">нет</span>}{h.agent_build && <span className="sub nowrap">Агент <span className="mono">{h.agent_build}</span></span>}</td>
                    <td className="small hide-sm">{h.av ? (h.problems.includes("rtp_off") ? <span className="bad-text">{h.av.state_label && h.av.state_label !== "запущен" ? `продукт ${h.av.state_label}` : h.rtp_label || "не работает"}</span> : h.rtp_label || h.av.state_label || "—") : "—"}</td>
                    <td className="nowrap">{h.av ? (h.av.bases ? <span className={old ? "warn-text" : ""}>{fmtDate(h.av.bases)}<span className="sub">{b === 0 ? "сегодня" : `${b} сут назад`}</span></span> : <span className="warn-text">нет сведений</span>) : "—"}</td>
                    <td className="nowrap small hide-sm">{h.av ? (h.last_full_scan ? <span className={h.problems.includes("scan_old") ? "warn-text" : ""}>{fmtDate(h.last_full_scan)}</span> : <span className="muted">не выполнялась</span>) : "—"}</td>
                    <td><ProblemBadges problems={h.problems} />{h.hw?.problems.map((p) => <span key={p.key} className="sub small" title={p.level_ru}>{p.text}</span>)}</td>
                    <td className="nowrap small hide-sm">{fmt(h.last_connected)}</td>
                  </tr>
                  <ExpandedRow id={`p${h.host_id}`} open={ex.has(h.host_id)} colSpan={10}>
                    <XGrid>
                      <XItem label="Компьютер">{h.fqdn || h.name}</XItem><XItem label="ОС">{h.os}{h.platform ? ` · ${h.platform}` : ""}</XItem><XItem label="Группа KSC">{h.group}</XItem>
                      <XItem label="Защитный продукт">{h.av ? `${h.av.product} ${h.av.build}` : "не установлен или KSC не получал сведений"}</XItem>
                      <XItem label="Состояние продукта">{h.av ? `${h.av.state_label || "—"}${h.av.has_rtp ? "" : " · постоянная защита не предусмотрена"}` : ""}</XItem><XItem label="Постоянная защита (KSC)">{h.rtp_label}</XItem>
                      <XItem label="Базы">{h.av?.bases ? fmt(h.av.bases) : ""}</XItem><XItem label="Полная проверка">{h.av ? (h.last_full_scan ? fmt(h.last_full_scan) : "не выполнялась") : ""}</XItem>
                      <XItem label="Агент администрирования">{h.agent_build}</XItem><XItem label="Статус KSC">{h.ksc_status ?? ""}</XItem><XItem label="Невылеченных объектов">{h.uncured ? num(h.uncured) : ""}</XItem>
                      <XItem label="Подключение к KSC">{fmt(h.last_connected)} · {h.activity}</XItem><XItem label="Сведения об устройстве обновлены">{h.last_info_update ? fmt(h.last_info_update) : ""}</XItem>
                      <XItem label="Проблемы" wide>{h.problems.length ? <ul className="xlist">{h.problems.map((p) => <li key={p}>{(s?.problems.find((x) => x.key === p)?.title ?? PROBLEM_SHORT[p])}</li>)}</ul> : "проблем не найдено"}</XItem>
                      <XItem label="Ресурсы Linux-сервера" wide>{h.hw?.problems.length ? h.hw.problems.map((p) => p.text).join("; ") : ""}</XItem>
                    </XGrid>
                    <div><Link className="btn mini" to={`/hosts/${h.host_id}`}>Карточка компьютера</Link></div>
                  </ExpandedRow>
                  </>);
              }} />
            {!list.items.length && !list.loading && <tbody><tr><td colSpan={10}><Empty icon="checkCircle" title={filtered ? "Ничего не найдено" : "Компьютеров нет"}>{filtered ? "По выбранным условиям компьютеров нет." : s?.online_only ? "Сейчас KSC не видит в сети ни одного устройства. Выключите «Только онлайн», чтобы увидеть все." : "В источнике нет компьютеров, подключавшихся к KSC за порог активности."}</Empty></td></tr></tbody>}
          </table>)}
      </div>
      <ListFoot list={list} />
      {s && <HiddenNote hidden={s.hidden_hosts} days={s.activity_days} all={all} onToggle={() => setAll(!all)} />}
      <ReportDock label="Выбранные компьютеры" count={sel.count} noun={["компьютер выбран", "компьютера выбрано", "компьютеров выбрано"]} canReport={canReport} onClear={sel.clear} onReport={() => setReport("sel")} />
      {report && <QuickReportPanel kind="quick_protection" title={report === "sel" ? `Состояние защиты: выбранные компьютеры (${sel.count})` : `Состояние защиты: ${problem && problem !== "ok" ? pTitle : "все компьютеры списка"}`}
        lede={report === "all" ? "Условия берутся из текущих фильтров страницы" : undefined} options={{ scope: true, zoneFilter: true }} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(null)}
        params={{ problem, product, build, bases_days: Number(basesDays), scan_days: Number(scanDays), q: applied.q || null, group_contains: applied.group || null, include_inactive: all, zone: zone || undefined,
          online_only: onlineOnly && s?.online_data !== false, host_ids: report === "sel" ? sel.ids : [] }} />}
      <p className="muted small mt-sm">Сведения — из последних отчётов Агентов администрирования в KSC; время — UTC, показано в вашем часовом поясе. «Нет антивируса» означает, что KSC не получал от Агента сведений о защитном продукте Kaspersky.</p>
    </section>
  );
}
