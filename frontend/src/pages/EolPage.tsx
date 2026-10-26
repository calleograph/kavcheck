import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ApiError, type EolFinding, type EolHostRow, type EolMapping, type EolProductCard, type EolProductRow, type EolSummary } from "../api";
import { NoSource, type Ctx } from "../App";
import { Modal } from "../components/Dialogs";
import { DeviceLink, EolBadge, EolDates, EolSev } from "../components/EolBits";
import { Icon } from "../components/Icons";
import { ListFoot, useInfinite, useKept } from "../components/Infinite";
import { QuickReportPanel } from "../components/QuickReport";
import { useToast } from "../components/Toast";
import { ZoneField } from "../components/ZoneBits";
import { Empty, MaskHint, PageHead, Segmented, SkelRows, SortTh, Tabs } from "../components/ui";
import { fmt, fmtDate, num, plural } from "../util";

type Tab = "infra" | "products" | "mappings";
type Kind = "" | "app" | "os";
type St = "" | "eol" | "extended" | "upcoming";

/** Раздел «EOL»: жизненный цикл программ и ОС по данным endoflife.date и что из этого есть в инфраструктуре. */
export default function EolPage({ ctx }: { ctx: Ctx }) {
  const [sp, setSp] = useSearchParams();
  const tab = (["infra", "products", "mappings"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "infra") as Tab;
  const [sum, setSum] = useState<EolSummary | null>(null);
  const [zone, setZone] = useKept("eol.zone", "");
  const [rev, setRev] = useState(0);
  const [report, setReport] = useState(false);
  useEffect(() => { if (ctx.current) api.eol.summary(zone).then(setSum).catch(() => setSum(null)); }, [ctx.current, ctx.all, zone, rev]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const canReport = ctx.me.user.role !== "viewer";
  const f = sum?.findings;
  const states = sum ? Object.entries(sum.sources) : [];
  const pending = states.filter(([, s]) => !s.ready && !s.error);
  const failed = states.filter(([, s]) => s.error);
  return (
    <section>
      <PageHead title="EOL: жизненный цикл ПО и ОС"
        lede="Когда производитель прекращает выпускать исправления безопасности. Сроки — из открытой базы endoflife.date; здесь видно, какие программы и операционные системы вашей инфраструктуры уже вышли из поддержки или выйдут в ближайшее время.">
        {canReport && <button className="btn" onClick={() => setReport(true)}><Icon name="download" />Выгрузить</button>}
      </PageHead>
      {sum && !sum.base.products && <div className="alert warn"><Icon name="alert" /><div className="alert-body">База endoflife.date ещё не загружена.{" "}
        {ctx.me.user.is_admin ? <>Включите источник «endoflife.date» в разделе <Link to="/admin?tab=vdb">Администрирование → База уязвимостей</Link> и запустите загрузку.</> : "Попросите администратора включить источник «endoflife.date»."}</div></div>}
      {sum?.base.error && <div className="alert warn"><Icon name="alert" /><div className="alert-body">Последнее обновление базы EOL не удалось: {sum.base.error}. Используется прежняя копия{sum.base.last_ok_at ? ` от ${fmt(sum.base.last_ok_at)}` : ""}.</div></div>}
      {pending.length > 0 && <div className="alert info"><Icon name="info" /><div className="alert-body">Сопоставление ещё не рассчитано для: {pending.map(([, s]) => s.source).join(", ")}. Расчёт выполняет фоновая служба после построения каталога программ.</div></div>}
      {failed.length > 0 && <div className="alert warn"><Icon name="alert" /><div className="alert-body">{failed.map(([k, s]) => <p key={k}>Источник «{s.source}»: расчёт не удался ({s.error}). Показаны данные последнего успешного расчёта{s.computed_at ? ` от ${fmt(s.computed_at)}` : ""}.</p>)}</div></div>}
      <div className="meters">
        <div className="meter"><span className="l">EOL: поддержка закончилась</span><span className={`v ${f?.eol ? "bad-text" : ""}`}>{f ? num(f.eol) : "…"}</span><span className="t">{sum ? `${num(sum.devices.eol)} ${plural(sum.devices.eol, "устройство", "устройства", "устройств")}` : ""}</span></div>
        <div className="meter"><span className="l">Только расширенная поддержка</span><span className={`v ${f?.extended ? "warn-text" : ""}`}>{f ? num(f.extended) : "…"}</span><span className="t">платная или по договору — не подтверждена</span></div>
        <div className="meter"><span className="l">Скоро закончится</span><span className="v">{f ? num(f.upcoming) : "…"}</span><span className="t">в ближайшие {sum?.base.soon_days ?? 180} сут</span></div>
        <div className="meter"><span className="l">База endoflife.date</span><span className="v">{sum ? num(sum.base.products) : "…"}</span><span className="t">продуктов{sum?.base.last_ok_at ? `, обновлена ${fmt(sum.base.last_ok_at)}` : ""}</span></div>
      </div>
      <Tabs label="Вид" value={tab} onChange={(t) => setSp((p) => { p.set("tab", t); p.delete("p"); return p; })}
        items={[{ id: "infra", label: "EOL в инфраструктуре", count: sum ? f!.eol + f!.extended + f!.upcoming || undefined : undefined }, { id: "products", label: "Все продукты" }, { id: "mappings", label: "Соответствия", count: sum?.ambiguous || undefined }]} />
      {tab === "infra" && <InfraView ctx={ctx} sum={sum} zone={zone} setZone={setZone} onRecalc={() => setRev((r) => r + 1)} />}
      {tab === "products" && <ProductsView ctx={ctx} />}
      {tab === "mappings" && <MappingsView ctx={ctx} onChanged={() => setRev((r) => r + 1)} />}
      {report && <QuickReportPanel kind="quick_eol" title="EOL в инфраструктуре" lede="Программы и ОС с закончившейся или приближающейся датой окончания поддержки и устройства, на которых они найдены"
        options={{ scope: false, eol: true, zoneFilter: true }} params={{ zone }} sourceIds={ctx.all ? ctx.sources.map((s) => s.id) : []} activityDays={ctx.me.activity_days} canReport={canReport} onClose={() => setReport(false)} />}
    </section>
  );
}

function InfraView({ ctx, sum, zone, setZone, onRecalc }: { ctx: Ctx; sum: EolSummary | null; zone: string; setZone: (z: string) => void; onRecalc: () => void }) {
  const [q, setQ] = useKept("eol.q", ""); const [applied, setApplied] = useState(q);
  const [kind, setKind] = useKept<Kind>("eol.kind", ""); const [status, setStatus] = useKept<St>("eol.status", "");
  const [sev, setSev] = useKept("eol.sev", ""); const [pub, setPub] = useKept("eol.pub", ""); const [prod, setProd] = useKept("eol.prod", "");
  const [srcId, setSrcId] = useKept("eol.src", ""); const [all, setAll] = useKept("eol.all", false);
  const [sort, setSort] = useKept("eol.sort", "severity"); const [desc, setDesc] = useKept("eol.desc", true);
  const [open, setOpen] = useState<string | null>(null); const [toast, show] = useToast();
  useEffect(() => { const t = window.setTimeout(() => setApplied(q), 350); return () => window.clearTimeout(t); }, [q]);
  const multi = ctx.all;                 // колонка «Источник» нужна, только когда показаны данные нескольких источников
  const list = useInfinite<EolFinding>(`eol:${ctx.current?.id}:${ctx.all}`, [applied, kind, status, sev, pub, prod, srcId, all, sort, desc, zone],
    (offset, limit) => api.eol.infra({ q: applied, kind, status, severity: sev, publisher: pub, product: prod, source_id: ctx.all ? srcId : "", all_hosts: all || undefined, zone, sort, desc, offset, limit }), 50);
  const extra = list.extra as { by_status?: Record<string, number>; computed_at?: string | null; publishers?: string[] } | null;
  const onSort = (k: string) => { if (sort === k) setDesc(!desc); else { setSort(k); setDesc(true); } };
  const keyOf = (f: EolFinding) => `${f.source_id}|${f.kind}|${f.subject}|${f.version}`;
  const canRecalc = ctx.me.user.role !== "viewer";
  const recalc = async () => { try { await api.eol.recalc(); show("Пересчёт поставлен в очередь: результат появится в течение нескольких минут"); onRecalc(); } catch (e) { show((e as ApiError).message, "error"); } };
  return (
    <>
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Программа, производитель, продукт: Windows Server 2012*, *Java*" aria-label="Поиск по программам и ОС" /><MaskHint /></div>
        <Segmented<Kind> label="Тип" value={kind} onChange={setKind} options={[["", "Всё"], ["app", "Программы"], ["os", "Операционные системы"]]} />
        <Segmented<St> label="Состояние поддержки" value={status} onChange={setStatus} options={[["", "Все"], ["eol", `EOL${extra?.by_status?.eol ? ` · ${extra.by_status.eol}` : ""}`], ["extended", "Расширенная"], ["upcoming", "Скоро"]]} />
        <details className="disclosure toolbar-more"><summary>Дополнительно</summary>
          <div className="toolbar-fields">
            <label className="field">Критичность<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">Любая</option><option value="critical">Критическая</option><option value="high">Высокая</option><option value="warning">Предупреждение</option></select></label>
            <label className="field">Производитель<select value={pub} onChange={(e) => setPub(e.target.value)}><option value="">Любой</option>{(extra?.publishers ?? []).map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
            <label className="field">Продукт endoflife.date<input value={prod} onChange={(e) => setProd(e.target.value.trim())} placeholder="например, windows-server" className="mono" /></label>
            {ctx.all && <label className="field">Источник KSC<select value={srcId} onChange={(e) => setSrcId(e.target.value)}><option value="">Все</option>{ctx.sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>}
            <ZoneField value={zone} onChange={setZone} />
          </div>
        </details>
        <div className="toolbar-foot"><span className="muted small">Данные посчитаны фоновой службой{extra?.computed_at ? ` ${fmt(extra.computed_at)}` : ""}; страница не обращается к KSC.</span>
          {canRecalc && <button type="button" className="link-btn" onClick={recalc}>Пересчитать сопоставление</button>}</div>
      </div>
      {list.error && list.initial && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{list.error}</div></div>}
      <div className={`table-scroll ${list.refreshing && !list.initial ? "is-busy" : ""}`}>
        {list.initial ? <SkelRows cols={6} /> : (
          <table className="table">
            <thead><tr><SortTh k="severity" label="Критичность" sort={sort} desc={desc} onSort={onSort} /><SortTh k="title" label="Программа или ОС" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="release" label="Продукт EOL" sort={sort} desc={desc} onSort={onSort} className="hide-sm" /><SortTh k="eol_from" label="Поддержка" sort={sort} desc={desc} onSort={onSort} />
              <SortTh k="hosts" label="Устройств" sort={sort} desc={desc} onSort={onSort} className="num" />{multi && <th className="hide-sm">Источник</th>}</tr></thead>
            <tbody>
              {list.items.flatMap((f) => {
                const k = keyOf(f); const isOpen = open === k;
                return [
                  <tr key={k} className={isOpen ? "sel" : ""}>
                    <td><EolSev f={f} />{!f.confirmed && <span className="sub small" title={f.condition}>не подтверждено</span>}</td>
                    <td><strong>{f.title}</strong>{f.kind === "app" && <span className="sub mono small">{f.version}</span>}{f.publisher && <span className="sub small">{f.publisher}</span>}<span className="sub small">{f.kind_ru}</span></td>
                    <td className="hide-sm"><a href={`https://endoflife.date/${f.eol_product}`} target="_blank" rel="noopener noreferrer">{f.eol_label}</a><span className="sub mono small">ветка {f.eol_release}</span>
                      {f.confidence !== "high" && <span className="sub small muted">{f.confidence_ru}</span>}</td>
                    <td><EolBadge s={f.status} /><EolDates f={f} />{f.condition && f.status !== "eol" && <span className="sub small">{f.condition}</span>}</td>
                    <td className="num"><button type="button" className="link-btn" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : k)}>{num(all ? f.hosts : f.hosts_active)}</button>
                      {!all && f.hosts > f.hosts_active && <span className="sub small muted">всего {num(f.hosts)}</span>}</td>
                    {multi && <td className="hide-sm small">{f.source}</td>}
                  </tr>,
                  isOpen && <tr key={`${k}:d`} className="expand"><td colSpan={multi ? 6 : 5}><FindingDevices f={f} zone={zone} all={all} /></td></tr>,
                ];
              })}
              {!list.items.length && !list.loading && <tr><td colSpan={6}><Empty icon="checkCircle" title="Ничего не найдено">{sum && !Object.values(sum.sources).some((s) => s.ready) ? "Сопоставление ещё не рассчитано." : applied || kind || status || sev || pub || prod || zone ? "Измените запрос или фильтры." : "Программы и ОС с истёкшей или приближающейся датой окончания поддержки не найдены."}</Empty></td></tr>}
            </tbody>
          </table>)}
      </div>
      <ListFoot list={list} />
      <p className="hidden-note"><Icon name={all ? "eye" : "eyeOff"} size={15} /><span>{all ? "Учитываются все устройства, включая не подключавшиеся к KSC дольше срока активности." : "Учитываются устройства со связью с KSC за период активности."}</span>
        <button type="button" className="link-btn" onClick={() => setAll(!all)}>{all ? "Скрыть неактивные" : "Показать все"}</button></p>
      {toast}
    </>
  );
}

/** Устройства находки: имя ведёт в карточку устройства. */
function FindingDevices({ f, zone, all }: { f: EolFinding; zone: string; all: boolean }) {
  const [rows, setRows] = useState<EolHostRow[]>([]); const [total, setTotal] = useState(0); const [busy, setBusy] = useState(true); const [err, setErr] = useState("");
  const load = useCallback((offset: number) => {
    setBusy(true);
    api.eol.hosts({ source_id: f.source_id, kind: f.kind, subject: f.subject, version: f.version, zone, all_hosts: all || undefined, offset, limit: 100 })
      .then((r) => { setRows((cur) => (offset ? [...cur, ...r.items] : r.items)); setTotal(r.total); }).catch((e) => setErr((e as ApiError).message)).finally(() => setBusy(false));
  }, [f.source_id, f.kind, f.subject, f.version, zone, all]);
  useEffect(() => { load(0); }, [load]);
  if (err) return <div className="alert error"><Icon name="alert" /><div className="alert-body">{err}</div></div>;
  return (
    <div className="eol-devices">
      <p className="muted small">{f.condition}</p>
      {busy && !rows.length ? <span className="spin accent" role="status" aria-label="Загрузка" /> : (
        <table className="table compact"><thead><tr><th>Устройство</th><th className="hide-sm">IP-адрес</th><th className="hide-md">ОС</th><th>Последнее подключение</th><th className="hide-sm">Зоны</th></tr></thead>
          <tbody>{rows.map((h) => <tr key={h.host_id}><td><DeviceLink sourceId={f.source_id} hostId={h.host_id} name={h.name} /></td><td className="mono small hide-sm">{h.ip || "—"}</td><td className="small hide-md">{h.os || "—"}</td>
            <td className="nowrap small">{fmt(h.last_connected)}</td><td className="small hide-sm">{h.zones.length ? h.zones.join(", ") : "—"}</td></tr>)}
            {!rows.length && <tr><td colSpan={5} className="muted">Подготовленных данных зон по этим устройствам ещё нет: список появится после первого расчёта данных зон.</td></tr>}</tbody></table>)}
      {rows.length < total && <button type="button" className="btn mini" disabled={busy} onClick={() => load(rows.length)}>Показать ещё ({num(total - rows.length)})</button>}
    </div>
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
      <div className="toolbar">
        <div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Продукт: windows, ubuntu, *sql*" aria-label="Поиск продукта" /><MaskHint /></div>
        <Segmented<string> label="Состояние" value={state} onChange={setState} options={[["", "Все"], ["installed", "Есть у нас"], ["supported", "Поддерживаются"], ["eol", "Все ветки завершены"]]} />
        <label className="field">Категория<select value={cat} onChange={(e) => setCat(e.target.value)}><option value="">Все</option>{cats.map((c) => <option key={c} value={c}>{c}</option>)}</select></label>
        <label className="field">Производитель<input value={vendor} onChange={(e) => setVendor(e.target.value.trim())} placeholder="microsoft, canonical…" className="w-md" /></label>
      </div>
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
      <div className="toolbar"><div className="input-icon grow"><Icon name="search" size={16} /><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Название или производитель" aria-label="Поиск программы" /><MaskHint /></div></div>
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

