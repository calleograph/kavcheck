import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type EolFinding, type EolMapping, type EolProductCard, type EolProductRow, type EolSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Modal } from "../components/Dialogs";
import { EOL_STATUS_TEXT, EolBadge, EolDates, EolSev } from "../components/EolBits";
import { Icon } from "../components/Icons";
import { ListFoot, useInfinite, useKept, type Chunk } from "../components/Infinite";
import { CountButton, FilterBar, type FilterChip } from "../components/FilterBar";
import { HostsDrawer, type DrawerHost } from "../components/HostsDrawer";
import { QuickReportPanel } from "../components/QuickReport";
import { useToast } from "../components/Toast";
import { ZoneField } from "../components/ZoneBits";
import { Empty, PageHead, Segmented, SkelRows, SortTh, Tabs } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";

type Tab = "infra" | "products" | "mappings";
type Kind = "" | "app" | "os";
type St = "" | "eol" | "extended" | "upcoming" | "undetermined";

/** Раздел «EOL»: жизненный цикл программ и ОС по данным endoflife.date и что из этого есть в инфраструктуре. */
export default function EolPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = (["infra", "products", "mappings"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "infra") as Tab;
  const [sum, setSum] = useState<EolSummary | null>(null);
  const [zone, setZone] = useKept("eol.zone", "");
  const [rev, setRev] = useState(0);
  useEffect(() => { if (ctx.current) api.eol.summary(zone).then(setSum).catch(() => setSum(null)); }, [ctx.current, ctx.all, zone, rev]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const f = sum?.findings;
  const states = sum ? Object.entries(sum.sources) : [];
  const noResult = states.length > 0 && states.every(([, s]) => !s.computed_at);      // ни по одному источнику нет результата: ноль находок не показываем как факт
  const running = states.filter(([, s]) => s.state === "running" || s.state === "retrying");
  const failed = states.filter(([, s]) => s.state === "error" || s.state === "deferred" || s.state === "retrying");
  const stale = states.filter(([, s]) => s.state === "stale");
  const none = states.filter(([, s]) => s.state === "none" || s.state === "waiting" || s.state === "interrupted");
  return (
    <section>
      <PageHead title="EOL: жизненный цикл ПО и ОС"
        lede="Когда производитель прекращает выпускать исправления безопасности. Сроки — из открытой базы endoflife.date; здесь видно, какие программы и операционные системы вашей инфраструктуры уже вышли из поддержки или выйдут в ближайшее время.">
      </PageHead>
      {sum && !sum.base.products && <div className="alert warn"><Icon name="alert" /><div className="alert-body">База endoflife.date ещё не загружена.{" "}
        {ctx.me.user.is_admin ? <>Включите источник «endoflife.date» в разделе <Link to="/admin?tab=vdb">Администрирование → База уязвимостей</Link> и запустите загрузку.</> : "Попросите администратора включить источник «endoflife.date»."}</div></div>}
      {sum?.base.error && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Последнее обновление базы EOL не удалось: {sum.base.error}. Используется прежняя копия{sum.base.last_ok_at ? ` от ${fmt(sum.base.last_ok_at)}` : ""}.</div></div>}
      {none.length > 0 && <div className="alert info"><Icon name="info" /><div className="alert-body"><b>{none.map(([, s]) => `${s.source}: ${s.state_ru.toLowerCase()}`).join("; ")}.</b> Расчёт запускается автоматически (если каталог программ ещё строится — по последнему готовому); нулевые значения ниже — не результат проверки.</div></div>}
      {running.length > 0 && <div className="alert info"><Icon name="info" /><div className="alert-body"><b>Выполняется:</b> {running.map(([k, s]) => <span key={k}>{s.source}{s.progress ? ` — ${s.progress}` : ""}{s.started_at ? ` (с ${fmt(s.started_at)})` : ""}. </span>)}{noResult ? "Результата пока нет." : "Показаны данные предыдущего расчёта."}</div></div>}
      {!noResult && sum && states.length > 1 && !sum.complete && sum.incomplete.length > 0 && <div className="alert warn"><Icon name="alert" /><div className="alert-body"><b>Данные неполные:</b> нет актуального результата по источникам {sum.incomplete.join(", ")}. Итоги ниже — по рассчитанным источникам (у источников с ошибкой — по последнему успешному расчёту, если он был); отсутствие находок не означает отсутствия EOL.</div></div>}
      {failed.length > 0 && <div className={`alert ${noResult ? "error" : "warn"}`}><Icon name="alert" /><div className="alert-body">{failed.map(([k, s]) => <p key={k}><b>{s.state_ru}</b> — источник «{s.source}»: {s.error}{s.error_at ? ` (${fmt(s.error_at)}${s.attempt_at && s.attempt_at !== s.error_at ? `, последняя попытка ${fmt(s.attempt_at)}` : ""})` : ""} {s.computed_at ? `Показаны данные последнего успешного расчёта от ${fmt(s.computed_at)}.` : "Результата нет: нули ниже не означают, что EOL нет."}{ctx.me.user.is_admin && s.error_detail && <span className="sub small mono">для администратора: {s.error_detail}</span>}</p>)}{ctx.me.user.is_admin && <p className="small">Повторная попытка выполняется автоматически через 15 минут; сразу — «Пересчитать» на вкладке «EOL в инфраструктуре».</p>}</div></div>}
      {stale.length > 0 && <div className="alert info"><Icon name="info" /><div className="alert-body"><b>Данные устарели:</b> {stale.map(([, s]) => `${s.source} (расчёт от ${fmt(s.computed_at)})`).join(", ")}. Исходные данные (база EOL, каталог, решения) изменились — пересчёт запустится автоматически.</div></div>}
      <div className="meters">
        <div className="meter"><span className="l">EOL: поддержка закончилась</span><span className={`v ${f?.eol ? "bad-text" : ""}`}>{noResult ? "—" : f ? num(f.eol) : "…"}</span><span className="t">{noResult ? "расчёта ещё нет" : sum ? `${num(sum.devices.eol)} ${plural(sum.devices.eol, "устройство", "устройства", "устройств")}` : ""}</span></div>
        <div className="meter"><span className="l">Только расширенная поддержка</span><span className={`v ${f?.extended ? "warn-text" : ""}`}>{noResult ? "—" : f ? num(f.extended) : "…"}</span><span className="t">платная или по договору — не подтверждена</span></div>
        <div className="meter"><span className="l">Скоро закончится</span><span className="v">{noResult ? "—" : f ? num(f.upcoming) : "…"}</span><span className="t">в ближайшие {sum?.base.soon_days ?? 180} сут</span></div>
        {!!sum?.os_undetermined?.items && <div className="meter"><span className="l">ОС: EOL не определён</span><span className="v warn-text">{num(sum.os_undetermined.devices)}</span><span className="t">{plural(sum.os_undetermined.devices, "устройство", "устройства", "устройств")} без сведений о выпуске ОС — <button type="button" className="link-btn" onClick={() => setSp((p) => { p.set("tab", "infra"); p.set("kind", "os"); p.set("status", "undetermined"); return p; })}>показать</button></span></div>}
        <div className="meter"><span className="l">База endoflife.date</span><span className="v">{sum ? num(sum.base.products) : "…"}</span><span className="t">продуктов{sum?.base.last_ok_at ? `, обновлена ${fmt(sum.base.last_ok_at)}` : ""}</span></div>
      </div>
      <Tabs label="Вид" value={tab} onChange={(t) => setSp((p) => { p.set("tab", t); p.delete("p"); return p; })}
        items={[{ id: "infra", label: "EOL в инфраструктуре", count: sum ? f!.eol + f!.extended + f!.upcoming || undefined : undefined }, { id: "products", label: "Все продукты" }, { id: "mappings", label: "Соответствия", count: sum?.ambiguous || undefined }]} />
      {tab === "infra" && <InfraView ctx={ctx} sum={sum} zone={zone} setZone={setZone} onRecalc={() => setRev((r) => r + 1)} />}
      {tab === "products" && <ProductsView ctx={ctx} />}
      {tab === "mappings" && <MappingsView ctx={ctx} onChanged={() => setRev((r) => r + 1)} />}
    </section>
  );
}

const KIND_RU: Record<string, string> = { app: "Программы", os: "Операционные системы" };
const STATUS_RU: Record<string, string> = { eol: "EOL", extended: "Расширенная поддержка", upcoming: "Скоро EOL", undetermined: "Не определён" };
const SEV_RU: Record<string, string> = { critical: "Критическая", high: "Высокая", warning: "Предупреждение" };

function InfraView({ ctx, sum, zone, setZone, onRecalc }: { ctx: Ctx; sum: EolSummary | null; zone: string; setZone: (z: string) => void; onRecalc: () => void }) {
  const [q, setQ] = useKept("eol.q", ""); const [applied, setApplied] = useState(q);
  const [kind, setKind] = useKept<Kind>("eol.kind", ""); const [status, setStatus] = useKept<St>("eol.status", "");
  const [sev, setSev] = useKept("eol.sev", ""); const [pub, setPub] = useKept("eol.pub", ""); const [prod, setProd] = useKept("eol.prod", "");
  const [srcId, setSrcId] = useKept("eol.src", ""); const [all, setAll] = useKept("eol.all", false);
  const [sort, setSort] = useKept("eol.sort", "severity"); const [desc, setDesc] = useKept("eol.desc", true);
  const [panel, setPanel] = useState<EolFinding | null>(null); const [toast, show] = useToast();
  const [sp, setSp] = useSearchParams();
  const [report, setReport] = useState<{ title: string; params: Record<string, unknown> } | null>(null);
  useEffect(() => {                                                    // переход из сводки («показать» у ОС с неопределённым EOL) задаёт тип и состояние
    const k = sp.get("kind"), st = sp.get("status");
    if (!k && !st) return;
    if (k === "app" || k === "os") setKind(k);
    if (st === "eol" || st === "extended" || st === "upcoming" || st === "undetermined") setStatus(st);
    setSp((p) => { p.delete("kind"); p.delete("status"); return p; }, { replace: true });
  }, [sp, setSp, setKind, setStatus]);
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const multi = ctx.all;                 // колонка «Источник» нужна, только когда показаны данные нескольких источников
  const list = useInfinite<EolFinding>(`eol:${ctx.current?.id}:${ctx.all}`, [applied, kind, status, sev, pub, prod, srcId, all, sort, desc, zone],
    (offset, limit) => api.eol.infra({ q: applied, kind, status, severity: sev, publisher: pub, product: prod, source_id: ctx.all ? srcId : "", all_hosts: all || undefined, zone, sort, desc, offset, limit }), 50);
  const extra = list.extra as { by_status?: Record<string, number>; computed_at?: string | null; publishers?: string[] } | null;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(true); } };
  const keyOf = (f: EolFinding) => `${f.source_id}|${f.kind}|${f.subject}|${f.version}`;
  const canRecalc = ctx.me.user.role !== "viewer"; const canReport = ctx.me.user.role !== "viewer";
  const recalc = async () => { try { await api.eol.recalc(); show("Пересчёт поставлен в очередь: результат появится в течение нескольких минут"); onRecalc(); } catch (e) { show((e as ApiError).message, "error"); } };
  const srcName = ctx.sources.find((s) => s.id === srcId)?.name ?? "";
  const chips: FilterChip[] = [
    ...(kind ? [{ id: "kind", label: `Тип: ${KIND_RU[kind]}`, onRemove: () => setKind("") }] : []), ...(status ? [{ id: "status", label: `Состояние: ${STATUS_RU[status]}`, onRemove: () => setStatus("") }] : []),
    ...(sev ? [{ id: "sev", label: `Критичность: ${SEV_RU[sev]}`, onRemove: () => setSev("") }] : []), ...(pub ? [{ id: "pub", label: `Производитель: ${pub}`, onRemove: () => setPub("") }] : []),
    ...(prod ? [{ id: "prod", label: `Продукт: ${prod}`, onRemove: () => setProd("") }] : []), ...(srcId && ctx.all ? [{ id: "src", label: `Источник: ${srcName}`, onRemove: () => setSrcId("") }] : []),
    ...(zone ? [{ id: "zone", label: "Зона ответственности", onRemove: () => setZone("") }] : []), ...(all ? [{ id: "all", label: "Включая неактивные устройства", onRemove: () => setAll(false) }] : []),
    ...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []),
  ];
  const reset = () => { setQ(""); setKind(""); setStatus(""); setSev(""); setPub(""); setProd(""); setSrcId(""); setAll(false); setZone(""); };
  const reportParams = (): Record<string, unknown> => ({ zone, q: applied || undefined, publisher: pub || undefined, severity: sev || undefined, include_inactive: all || undefined,
    kinds: kind ? [kind] : undefined, statuses: status ? [status] : undefined });
  const hostsOf = (f: EolFinding) => (all ? f.hosts : f.hosts_active);
  return (
    <>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Программа, производитель, продукт: Windows Server 2012*, *Java*", label: "Поиск по программам и ОС" }}
        primary={<>
          <Segmented<Kind> label="Тип" value={kind} onChange={setKind} options={[["", "Всё"], ["app", "Программы"], ["os", "Операционные системы"]]} />
          <select value={status} onChange={(e) => setStatus(e.target.value as St)} aria-label="Состояние поддержки">
            <option value="">Все состояния{extra?.by_status ? ` · ${Object.values(extra.by_status).reduce((a, b) => a + b, 0)}` : ""}</option>
            <option value="eol">EOL{extra?.by_status?.eol ? ` · ${extra.by_status.eol}` : ""}</option><option value="extended">Расширенная поддержка{extra?.by_status?.extended ? ` · ${extra.by_status.extended}` : ""}</option>
            <option value="upcoming">Скоро EOL{extra?.by_status?.upcoming ? ` · ${extra.by_status.upcoming}` : ""}</option>
            {(extra?.by_status?.undetermined || status === "undetermined") && <option value="undetermined">Не определён · {extra?.by_status?.undetermined ?? 0}</option>}
          </select>
        </>}
        more={<>
          <label className="field">Критичность<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">Любая</option><option value="critical">Критическая</option><option value="high">Высокая</option><option value="warning">Предупреждение</option></select></label>
          <label className="field">Производитель<select value={pub} onChange={(e) => setPub(e.target.value)}><option value="">Любой</option>{(extra?.publishers ?? []).map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
          <label className="field">Продукт endoflife.date<input value={prod} onChange={(e) => setProd(e.target.value.trim())} placeholder="например, windows-server" className="mono" /></label>
          {ctx.all && <label className="field">Источник KSC<select value={srcId} onChange={(e) => setSrcId(e.target.value)}><option value="">Все</option>{ctx.sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>}
          <ZoneField value={zone} onChange={setZone} />
          <label className="check"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />Включая давно не подключавшиеся устройства</label>
          {canRecalc && <div className="wide"><button type="button" className="link-btn" onClick={recalc}>Пересчитать сопоставление</button> <span className="muted small">— данные считает фоновая служба; страница не обращается к KSC</span></div>}
        </>}
        moreActive={[sev, pub, prod, srcId && ctx.all ? srcId : "", zone, all ? "1" : ""].filter(Boolean).length}
        chips={chips} onReset={reset} count={{ n: list.initial ? null : list.total, noun: ["запись", "записи", "записей"] }}
        report={canReport ? { onClick: () => setReport({ title: "EOL в инфраструктуре", params: reportParams() }) } : null} />
      <p className="muted small fbar-note">Данные посчитаны фоновой службой{extra?.computed_at ? ` ${fmt(extra.computed_at)}` : ""}; страница не обращается к KSC. {all ? "Учитываются все устройства." : "Учитываются устройства со связью с KSC за период активности."}</p>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr><SortTh k="severity" label="Критичность" sort={sort} desc={desc} onSort={onSort} /><SortTh k="title" label="Программа или ОС" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="release" label="Продукт EOL" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><SortTh k="eol_from" label="Поддержка" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="hosts" label="Устройств" sort={sort} desc={desc} onSort={onSort} className="num" />{multi && <th className="hide-sm">Источник</th>}</tr></thead>
            <tbody>
              {list.items.map((f) => {
                const k = keyOf(f);
                return (
                  <tr key={k} className={panel && keyOf(panel) === k ? "sel" : ""}>
                    <td><EolSev f={f} />{!f.confirmed && f.status !== "undetermined" && <span className="sub small" title={f.condition}>не подтверждено</span>}</td>
                    <td><strong>{f.title}</strong>{f.kind === "app" && <span className="sub mono small">{f.version}</span>}{f.publisher && <span className="sub small">{f.publisher}</span>}<span className="sub small">{f.kind_ru}</span></td>
                    <td className="hide-sm">{f.eol_product ? <><a href={`https://endoflife.date/${f.eol_product}`} target="_blank" rel="noopener noreferrer">{f.eol_label}</a>{f.eol_release && <span className="sub mono small">ветка {f.eol_release}</span>}</> : <span className="muted">нет в базе</span>}
                      {f.confidence !== "high" && f.status !== "undetermined" && <span className="sub small muted">{f.confidence_ru}</span>}</td>
                    <td><EolBadge s={f.status} /><EolDates f={f} />{f.condition && f.status !== "eol" && <span className="sub small">{f.condition}</span>}</td>
                    <td className="num"><CountButton n={hostsOf(f)} onClick={() => setPanel(f)} label="Показать устройства" />
                      {!all && f.hosts > f.hosts_active && <span className="sub small muted">всего {num(f.hosts)}</span>}</td>
                    {multi && <td className="hide-sm small">{f.source}</td>}
                  </tr>);
              })}
              {!list.items.length && !list.loading && <tr><td colSpan={6}><Empty icon="checkCircle" title="Ничего не найдено">{sum && !Object.values(sum.sources).some((s) => s.ready) ? "Сопоставление ещё не рассчитано." : chips.length ? "Измените запрос или фильтры." : "Программы и ОС с истёкшей или приближающейся датой окончания поддержки не найдены."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      {toast}
      {panel && <HostsDrawer title={panel.title} lede={<>{EOL_STATUS_TEXT[panel.status]}{panel.kind === "app" ? ` · версия ${panel.version}` : ""}{multi ? ` · ${panel.source}` : ""}. {panel.condition}</>}
        listKey={`eolhosts:${keyOf(panel)}`} deps={[zone, all]} search="Имя устройства" sortKeys={{ name: "name", os: "os", last_connected: "last_connected" }} activityDays={ctx.me.activity_days} multiSource={multi}
        fetchPage={async (offset, limit, qy) => {
          const r = await api.eol.hosts({ source_id: panel.source_id, kind: panel.kind, subject: panel.subject, version: panel.version, zone, all_hosts: all || undefined, q: qy.q, sort: qy.sort, desc: qy.desc || undefined, offset, limit });
          return { items: r.items.map((h) => ({ ...h, source_id: panel.source_id, source: panel.source, group: h.group ?? "", days_since_connection: undefined })), total: r.total } as unknown as Chunk<DrawerHost>;
        }}
        report={canReport ? { onClick: () => setReport({ title: `EOL: ${panel.title}`, params: { finding: { source_id: panel.source_id, kind: panel.kind, subject: panel.subject, version: panel.version }, statuses: [panel.status], include_inactive: all || undefined } }) } : null}
        onClose={() => setPanel(null)} />}
      {report && <QuickReportPanel kind="quick_eol" title={report.title} lede="Программы и ОС с закончившейся или приближающейся датой окончания поддержки и устройства, на которых они найдены" options={{ scope: false, eol: true, zoneFilter: true }}
        params={report.params} sourceIds={ctx.all ? ctx.sources.map((s) => s.id) : []} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(null)} />}
    </>
  );
}

function ProductsView({ ctx }: { ctx: Ctx }) {
  const [q, setQ] = useKept("eolp.q", ""); const [applied, setApplied] = useState(q);
  const [cat, setCat] = useKept("eolp.cat", ""); const [vendor, setVendor] = useKept("eolp.vendor", "");
  const [state, setState] = useKept("eolp.state", ""); const [sort, setSort] = useKept("eolp.sort", "name"); const [desc, setDesc] = useKept("eolp.desc", false);
  const [sp, setSp] = useSearchParams(); const open = sp.get("p");
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const list = useInfinite<EolProductRow>(`eolp:${ctx.all}`, [applied, cat, vendor, state, sort, desc], (offset, limit) => api.eol.products({ q: applied, category: cat, vendor, state, sort, desc, offset, limit }), 50);
  const cats = (list.extra as { categories?: string[] } | null)?.categories ?? [];
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(false); } };
  return (
    <>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Продукт: windows, ubuntu, *sql*", label: "Поиск продукта" }}
        primary={<Segmented<string> label="Состояние" value={state} onChange={setState} options={[["", "Все"], ["installed", "Есть у нас"], ["supported", "Поддерживаются"], ["eol", "Все ветки завершены"]]} />}
        more={<>
          <label className="field">Категория<select value={cat} onChange={(e) => setCat(e.target.value)}><option value="">Все</option>{cats.map((c) => <option key={c} value={c}>{c}</option>)}</select></label>
          <label className="field">Производитель<input value={vendor} onChange={(e) => setVendor(e.target.value.trim())} placeholder="microsoft, canonical…" /></label>
        </>}
        moreActive={[cat, vendor].filter(Boolean).length}
        chips={[...(q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []), ...(state ? [{ id: "st", label: `Состояние: ${{ installed: "есть у нас", supported: "поддерживаются", eol: "все ветки завершены" }[state] ?? state}`, onRemove: () => setState("") }] : []),
          ...(cat ? [{ id: "cat", label: `Категория: ${cat}`, onRemove: () => setCat("") }] : []), ...(vendor ? [{ id: "vnd", label: `Производитель: ${vendor}`, onRemove: () => setVendor("") }] : [])]}
        onReset={() => { setQ(""); setState(""); setCat(""); setVendor(""); }} count={{ n: list.initial ? null : list.total, noun: ["продукт", "продукта", "продуктов"] }} />
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={5} /> : (
          <table className="table"><thead><tr><SortTh k="name" label="Продукт" sort={sort} desc={desc} onSort={onSort} /><SortTh k="category" label="Категория" sort={sort} desc={desc} onSort={onSort} className="hide-sm" />
            <SortTh k="releases" label="Ветки" sort={sort} desc={desc} onSort={onSort} className="num" /><th className="num hide-sm">Поддерживается</th><SortTh k="installed" label="У нас" sort={sort} desc={desc} onSort={onSort} className="num" /></tr></thead>
            <tbody>{list.items.map((p) => (
              <tr key={p.name} className="clickable" onClick={() => setSp((s) => { s.set("p", p.name); return s; })}>
                <td><button type="button" className="link-btn strong-link" onClick={() => setSp((s) => { s.set("p", p.name); return s; })}>{p.label}</button><span className="sub mono small">{p.name}</span></td>
                <td className="hide-sm small">{p.category || "—"}</td><td className="num">{num(p.releases)}</td><td className="num hide-sm">{num(p.supported)}</td>
                <td className="num">{p.installed_hosts ? <><b>{num(p.installed_hosts)}</b><span className="sub small muted">устройств</span></> : <span className="muted">—</span>}</td></tr>))}
              {!list.items.length && !list.loading && <tr><td colSpan={5}><Empty icon="search" title="Продукты не найдены">Измените запрос или фильтры.</Empty></td></tr>}</tbody></table>)}
      </div>
      <ListFoot list={list} />
      {open && <ProductModal name={open} onClose={() => setSp((s) => { s.delete("p"); return s; })} />}
    </>
  );
}

function ProductModal({ name, onClose }: { name: string; onClose: () => void }) {
  const [d, setD] = useState<EolProductCard | null>(null); const [err, setErr] = useState("");
  useEffect(() => { api.eol.product(name).then(setD).catch((e) => setErr((e as ApiError).message)); }, [name]);
  return (
    <Modal side wide title={d?.label ?? name} onClose={onClose} lede={d ? `${d.category || "Продукт"} · обновлено ${fmt(d.updated_at)}` : undefined}>
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!d && !err && <span className="spin accent" role="status" aria-label="Загрузка" />}
      {d && <>
        <p className="small"><a href={d.links.html || `https://endoflife.date/${d.name}`} target="_blank" rel="noopener noreferrer">endoflife.date/{d.name}<Icon name="external" size={12} /></a>
          {d.links.releasePolicy && <> · <a href={d.links.releasePolicy} target="_blank" rel="noopener noreferrer">политика поддержки производителя<Icon name="external" size={12} /></a></>}</p>
        {Object.values(d.labels).some(Boolean) && <p className="muted small">Как производитель называет этапы: {Object.entries(d.labels).filter(([, v]) => v).map(([k, v]) => `${({ eoas: "конец активной поддержки", eol: "конец стандартной", eoes: "конец расширенной", discontinued: "снят с продажи" } as Record<string, string>)[k] ?? k} — «${v}»`).join("; ")}.</p>}
        <div className="table-scroll"><table className="table compact"><thead><tr><th>Ветка</th><th>Состояние</th><th>Стандартная поддержка до</th><th className="hide-sm">Расширенная до</th><th className="hide-sm">Последняя версия</th><th className="num">У нас</th></tr></thead>
          <tbody>{d.releases.map((r) => (
            <tr key={r.name}><td><b className="mono">{r.name}</b>{r.label && r.label !== r.name && <span className="sub small">{r.label}</span>}{r.lts && <span className="badge accent">LTS</span>}</td>
              <td>{r.status === "supported" ? <span className="badge ok">Поддерживается</span> : <EolBadge s={(r.status as "eol") || "unknown"} short />}{r.condition && r.status !== "eol" && r.status !== "supported" && <span className="sub small">{r.condition}</span>}</td>
              <td className="nowrap small">{r.eol_from ? fmtDate(r.eol_from) : "—"}</td><td className="nowrap small hide-sm">{r.eoes_from ? fmtDate(r.eoes_from) : "—"}</td><td className="small mono hide-sm">{r.latest ?? "—"}</td>
              <td className="num">{r.installed_hosts ? <b>{num(r.installed_hosts)}</b> : <span className="muted">—</span>}</td></tr>))}</tbody></table></div>
        <p className="muted small">«EOL» присваивается, только когда закончилась стандартная поддержка безопасности. Расширенная поддержка (платная или по договору) показывается отдельно и не считается подтверждённой.</p>
      </>}
    </Modal>
  );
}

function MappingsView({ ctx, onChanged }: { ctx: Ctx; onChanged: () => void }) {
  const [maps, setMaps] = useState<EolMapping[] | null>(null); const [un, setUn] = useState<Awaited<ReturnType<typeof api.eol.unmatched>> | null>(null);
  const [q, setQ] = useState(""); const [pick, setPick] = useState<{ key: string; name: string } | null>(null); const [toast, show] = useToast();
  const canEdit = ctx.me.user.role !== "viewer";
  const load = useCallback(() => { api.eol.mappings().then((r) => setMaps(r.items)).catch(() => setMaps([])); api.eol.unmatched(q).then(setUn).catch(() => setUn(null)); }, [q]);
  useEffect(() => { const t = window.setTimeout(load, 250); return () => window.clearTimeout(t); }, [load]);
  const del = async (m: EolMapping) => { try { await api.eol.delMapping(m.id); show("Решение удалено"); load(); onChanged(); } catch (e) { show((e as ApiError).message, "error"); } };
  const exclude = async (key: string) => { try { await api.eol.setMapping({ catalog_key: key, action: "exclude", note: "Исключено из проверки EOL" }); show("Программа исключена из проверки EOL"); load(); onChanged(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <>
      <p className="muted">Программы сопоставляются с базой endoflife.date автоматически: по идентификаторам (CPE, PURL), производителю и названию, ветка выбирается по установленной версии. Если соответствие неверное или не найдено — задайте его вручную: решение сохраняется при обновлении базы и каталога.</p>
      <h3 className="h3">Решения администратора</h3>
      <div className="table-scroll"><table className="table compact"><thead><tr><th>Программа каталога</th><th>Решение</th><th className="hide-sm">Кто и когда</th><th><span className="sr-only">Действия</span></th></tr></thead>
        <tbody>{(maps ?? []).map((m) => <tr key={m.id}><td><strong>{m.catalog_name}</strong><span className="sub mono small">{m.catalog_key}</span></td>
          <td>{m.action === "exclude" ? <span className="badge">Не проверять EOL</span> : <>соответствует <b>{m.eol_label || m.eol_product}</b></>}{m.note && <span className="sub small">{m.note}</span>}</td>
          <td className="small hide-sm">{m.created_by} · {fmtDate(m.created_at)}</td><td className="actions">{canEdit && <button type="button" className="btn mini ghost" onClick={() => del(m)}>Удалить</button>}</td></tr>)}
          {maps && !maps.length && <tr><td colSpan={4} className="muted">Решений пока нет.</td></tr>}</tbody></table></div>
      <h3 className="h3">Программы без соответствия</h3>
      <FilterBar search={{ value: q, onChange: setQ, placeholder: "Название или производитель", label: "Поиск программы" }} chips={q ? [{ id: "q", label: `Поиск: ${q}`, onRemove: () => setQ("") }] : []} onReset={() => setQ("")} />
      {un && un.ambiguous.length > 0 && <>
        <p className="muted small">Спорные — подходит несколько продуктов endoflife.date, EOL не присвоен до вашего решения:</p>
        <div className="table-scroll"><table className="table compact"><tbody>{un.ambiguous.map((a) => <tr key={a.catalog_key}><td><strong>{a.name}</strong><span className="sub small">{a.publisher}</span></td><td className="small">{a.reason}</td>
          <td className="num">{num(a.hosts)}</td><td className="actions">{canEdit && <button type="button" className="btn mini" onClick={() => setPick({ key: a.catalog_key, name: a.name })}>Выбрать продукт</button>}</td></tr>)}</tbody></table></div></>}
      <div className="table-scroll"><table className="table compact"><thead><tr><th>Программа</th><th className="hide-sm">Производитель</th><th className="num">Устройств</th><th className="hide-sm">Источник</th><th><span className="sr-only">Действия</span></th></tr></thead>
        <tbody>{(un?.items ?? []).map((u) => <tr key={`${u.source}:${u.catalog_key}`}><td><strong>{u.name}</strong><span className="sub mono small">{u.catalog_key}</span></td><td className="small hide-sm">{u.publisher || "—"}</td><td className="num">{num(u.hosts)}</td>
          <td className="small hide-sm">{u.source}</td>
          <td className="actions">{canEdit && <><button type="button" className="btn mini" onClick={() => setPick({ key: u.catalog_key, name: u.name })}>Сопоставить</button> <button type="button" className="btn mini ghost" onClick={() => exclude(u.catalog_key)}>Не проверять</button></>}</td></tr>)}
          {un && !un.items.length && <tr><td colSpan={5} className="muted">Все распространённые программы сопоставлены или исключены.</td></tr>}</tbody></table></div>
      {pick && <PickProduct item={pick} onClose={() => setPick(null)} onDone={() => { setPick(null); show("Соответствие сохранено, пересчёт запущен"); load(); onChanged(); }} />}
      {toast}
    </>
  );
}

function PickProduct({ item, onClose, onDone }: { item: { key: string; name: string }; onClose: () => void; onDone: () => void }) {
  const [q, setQ] = useState(item.name); const [rows, setRows] = useState<EolProductRow[]>([]); const [err, setErr] = useState("");
  useEffect(() => { const t = window.setTimeout(() => api.eol.products({ q, limit: 20 }).then((r) => setRows(r.items)).catch(() => setRows([])), 250); return () => window.clearTimeout(t); }, [q]);
  const save = async (name: string) => { try { await api.eol.setMapping({ catalog_key: item.key, eol_product: name, action: "map" }); onDone(); } catch (e) { setErr((e as ApiError).message); } };
  return (
    <Modal title={`Сопоставить: ${item.name}`} onClose={onClose} lede="Выберите продукт endoflife.date. Ветка определяется по установленной версии автоматически.">
      {err && <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      <div className="input-icon"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} aria-label="Поиск продукта endoflife.date" autoFocus /></div>
      <ul className="pick-list">{rows.map((p) => <li key={p.name}><button type="button" className="pick" onClick={() => save(p.name)}><b>{p.label}</b><span className="mono small muted">{p.name}</span><span className="small muted">{p.category}</span></button></li>)}
        {!rows.length && <li className="muted">Ничего не найдено.</li>}</ul>
    </Modal>
  );
}

