import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type ApiError, type CatalogProductFull, type ProductHost } from "../api";
import { NoSource, type Ctx } from "../App";
import { ActivityBadge, Pager } from "../components/Common";
import { ConfirmDialog, Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { ProductPicker, type PickedProduct } from "../components/ProductPicker";
import { useToast } from "../components/Toast";
import { Empty, HiddenNote, PageHead, SkelRows, Spectrum } from "../components/ui";
import { fmt, fmtDate, num } from "../util";
import { CatalogStateLine } from "./CatalogPage";

const ORIGIN: Record<string, string> = { builtin: "встроенное описание продукта", auto: "автоматическая группа по названию", manual: "исправлено вручную" };
const KIND: Record<string, string> = { merge: "объединение", split: "выделение записей", rename: "переименование" };

/** Карточка продукта каталога: ветки и версии, компьютеры по выбору, записи реестра KSC, ручные корректировки. */
export default function ProductPage({ ctx }: { ctx: Ctx }) {
  const { key = "" } = useParams();
  const navigate = useNavigate();
  const [all, setAll] = useState(false);
  const [p, setP] = useState<CatalogProductFull | null>(null);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState<{ version?: string; branch?: string } | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [dialog, setDialog] = useState<"split" | "merge" | "rename" | null>(null);
  const [names, setNames] = useState<Set<string>>(new Set());
  const [del, setDel] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [toast, show] = useToast();
  useEffect(() => { if (!ctx.current) return; api.catalog.product(key, all).then((r) => { setP(r); setErr(""); }).catch((e) => setErr((e as ApiError).message)); }, [ctx.current, key, all, tick]);
  if (!ctx.current) return <NoSource ctx={ctx} />;
  const back = <Link className="back-link" to="/software"><Icon name="arrowL" size={15} />Программы</Link>;
  if (err) return <section><PageHead title="Продукт" back={back} /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!p) return <section><PageHead title={<span className="skel" style={{ width: 260, height: 28 }} />} back={back} /><div className="card"><SkelRows rows={5} cols={4} /></div></section>;
  const canEdit = ctx.me.user.role !== "viewer";
  const checkHref = (extra = "") => `/reports?product=${encodeURIComponent(p.key)}&name=${encodeURIComponent(p.name)}${extra}`;
  const hiddenTotal = p.hosts_all - p.hosts_active;
  const segs = p.branches.map((b) => ({ key: b.branch || "∅", label: b.branch || "не определена", value: b.hosts_shown, undef: !b.branch, note: `${num(b.versions.length)} верс.` })).filter((s) => s.value > 0);
  return (
    <section>
      <PageHead title={p.name} back={back}
        lede={<>{p.publisher ? <>{p.publisher} · </> : null}{p.platforms.join(", ")} · {ORIGIN[p.origin]}{p.note ? <span className="lede-note">{p.note}</span> : null}</>}>
        <CatalogStateLine state={p.state} canRebuild={canEdit} onRebuilt={() => setTick((x) => x + 1)} />
        {canEdit && <Link className="btn primary" to={checkHref()}><Icon name="target" />Проверить версии</Link>}
      </PageHead>
      <div className="meters">
        <div className="meter"><span className="l">Компьютеров</span><span className="v">{num(p.hosts)}</span><span className="t">{all ? "все устройства" : `активные за ${ctx.me.activity_days} сут`}</span></div>
        <div className="meter"><span className="l">Версий</span><span className="v">{num(p.versions.length)}</span><span className="t">новейшая <span className="mono">{p.latest_version || "—"}</span></span></div>
        <div className="meter"><span className="l">Веток</span><span className="v">{num(p.branches.filter((b) => b.branch).length)}</span><span className="t">{p.branches.some((b) => !b.branch) ? "есть записи без ветки" : "по основной версии"}</span></div>
        <div className="meter"><span className="l">Записей реестра KSC</span><span className="v">{num(p.versions.reduce((a, v) => a + v.records, 0))}</span><span className="t">{num(p.names.length)} вариант. названия</span></div>
      </div>
      {segs.length > 0 && (
        <div className="card spectrum-card">
          <div className="card-head"><h2>Ветки</h2><span className="muted small">ширина — доля компьютеров; щёлкните ветку, чтобы увидеть её компьютеры</span></div>
          <Spectrum label="Ветки продукта" size="lg" unit=" комп." segs={segs} hover={hover} onHover={setHover}
            selected={new Set(sel?.branch !== undefined ? [sel.branch || "∅"] : [])} onToggle={(k) => setSel((s) => (s?.branch === (k === "∅" ? "" : k) ? null : { branch: k === "∅" ? "" : k }))} />
        </div>
      )}
      <div className="section-head"><h2>Версии</h2><span className="count">{num(p.versions.length)}</span><div className="spacer" />
        {p.scheme === "dpkg" && <span className="muted small">Пакеты Linux: версия без эпохи и ревизии пакета</span>}
        {p.transform && <span className="muted small">Нумерация приведена к обычной ({p.transform === "java" ? "8.0.4010.7 → 8.0.401" : "3.12.3150.0 → 3.12.3"})</span>}</div>
      <div className="table-scroll">
        <table className="table">
          <thead><tr><th>Версия</th><th>Ветка</th><th>Платформа</th><th>Записи реестра</th><th className="num">Компьютеров</th><th><span className="sr-only">Действия</span></th></tr></thead>
          <tbody>
            {p.versions.map((v) => {
              const on = sel?.version === v.version;
              return (
                <tr key={`${v.version}|${v.scheme}`} className={`${on ? "sel" : ""} ${hover && (v.branch || "∅") === hover ? "hot" : ""}`}>
                  <td className="mono"><b>{v.version || "—"}</b>{v.raw[0] && v.raw[0] !== v.version && <span className="sub mono" title={v.raw.join(", ")}>{v.raw[0]}{v.raw.length > 1 ? ` и ещё ${v.raw.length - 1}` : ""}</span>}</td>
                  <td className="mono">{v.branch || <span className="muted">—</span>}</td>
                  <td className="small">{v.platform.join(", ")}</td>
                  <td className="small">{v.names.slice(0, 2).join("; ")}{v.names.length > 2 ? "…" : ""}</td>
                  <td className="num">{num(v.hosts)}{all && v.hosts_all !== v.hosts ? "" : ""}</td>
                  <td className="actions">
                    <button className={`btn mini ${on ? "primary" : ""}`} onClick={() => setSel(on ? null : { version: v.version })} aria-pressed={on}><Icon name="monitor" size={15} />Компьютеры</button>
                    {canEdit && <Link className="btn mini ghost" to={checkHref(`&value=${encodeURIComponent(v.version)}&op=le`)} title="Проверить эту и более ранние версии">≤ этой</Link>}
                  </td>
                </tr>);
            })}
            {!p.versions.length && <tr><td colSpan={6}><Empty icon="layers" title="Нет установок">На активных компьютерах продукт не найден. Включите показ всех устройств.</Empty></td></tr>}
          </tbody>
        </table>
      </div>
      <HiddenNote hidden={hiddenTotal} days={ctx.me.activity_days} all={all} onToggle={() => setAll(!all)} />
      {sel && <HostsPanel key={`${sel.version ?? ""}|${sel.branch ?? ""}|${all}`} productKey={p.key} sel={sel} all={all} activityDays={ctx.me.activity_days} onClose={() => setSel(null)} />}

      <div className="split even section-gap">
        <div className="card flush">
          <div className="card-head"><h2>Записи реестра KSC</h2><span className="muted small">варианты названия, вошедшие в продукт</span><div className="spacer" />
            {canEdit && names.size > 0 && <button className="btn mini primary" onClick={() => setDialog("split")}><Icon name="branch" size={15} />Выделить в отдельный продукт ({names.size})</button>}</div>
          <ul className="rows name-rows">
            {p.names.map(([n, c]) => (
              <li key={n}>{canEdit && <input type="checkbox" checked={names.has(n)} onChange={() => setNames((s) => { const x = new Set(s); if (x.has(n)) x.delete(n); else x.add(n); return x; })} aria-label={`Выбрать «${n}»`} />}
                <span className="grow">{n}</span><span className="muted small nowrap">{num(c)} уст.</span></li>))}
          </ul>
        </div>
        <div className="card">
          <div className="card-head"><h2>Исправления каталога</h2></div>
          <p className="muted small">Если продукт разделился на несколько (например, разные написания названия) или в него попало лишнее, исправьте это здесь. Исправления общие для всех источников, сохраняются при обновлении приложения; каталог перестраивается автоматически.</p>
          {canEdit && <div className="row wrap">
            <button className="btn" onClick={() => setDialog("merge")}><Icon name="layers" />Объединить с другим продуктом</button>
            <button className="btn ghost" onClick={() => setDialog("rename")}><Icon name="edit" />Переименовать</button>
          </div>}
          {p.overrides.length > 0 && (
            <ul className="rows">
              {p.overrides.map((o) => (
                <li key={o.id}><Icon name="branch" size={16} className="muted" />
                  <span className="grow small"><b>{KIND[o.kind]}</b>: {o.kind === "merge" ? `«${o.from_key}» → «${o.to_key}»` : o.kind === "split" ? `«${o.match_name}» → «${o.to_name}»` : `«${o.to_name ?? ""}»${o.to_publisher != null ? `, производитель «${o.to_publisher}»` : ""}`}
                    <span className="sub">{o.created_by} · {fmtDate(o.created_at)}</span></span>
                  {canEdit && <button className="btn mini ghost danger icon" onClick={() => setDel(o.id)} aria-label="Отменить исправление"><Icon name="trash" size={15} /></button>}</li>))}
            </ul>)}
        </div>
      </div>
      {dialog === "split" && <SplitDialog product={p} names={[...names]} onClose={() => setDialog(null)} onDone={() => { setDialog(null); setNames(new Set()); show("Записи будут выделены при ближайшем обновлении каталога"); setTick((x) => x + 1); }} />}
      {dialog === "merge" && <MergeDialog product={p} sourceId={ctx.current.id} onClose={() => setDialog(null)} onDone={(to) => { setDialog(null); show("Продукты будут объединены при ближайшем обновлении каталога"); navigate(`/software/p/${encodeURIComponent(to)}`); }} />}
      {dialog === "rename" && <RenameDialog product={p} onClose={() => setDialog(null)} onDone={() => { setDialog(null); show("Название изменится при ближайшем обновлении каталога"); setTick((x) => x + 1); }} />}
      {del && <ConfirmDialog title="Отменить исправление?" confirmLabel="Отменить исправление" body={<p>Каталог будет перестроен без этого исправления.</p>} onClose={() => setDel(null)}
        onConfirm={async () => { await api.catalog.deleteOverride(del); setTick((x) => x + 1); }} />}
      {toast}
    </section>
  );
}

function HostsPanel({ productKey, sel, all, activityDays, onClose }: { productKey: string; sel: { version?: string; branch?: string }; all: boolean; activityDays: number; onClose: () => void }) {
  const [offset, setOffset] = useState(0);
  const [d, setD] = useState<Awaited<ReturnType<typeof api.catalog.productHosts>> | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { setD(null); api.catalog.productHosts(productKey, { version: sel.version, branch: sel.branch, all_hosts: all, offset, limit: 50 }).then(setD).catch((e) => setErr((e as ApiError).message)); }, [productKey, sel.version, sel.branch, all, offset]);
  const title = sel.version !== undefined ? `Компьютеры с версией ${sel.version}` : `Компьютеры с веткой ${sel.branch || "«не определена»"}`;
  return (
    <div className="card flush hosts-panel" role="region" aria-label={title}>
      <div className="card-head"><h2>{title}</h2>{d && <span className="count">{num(d.total)}</span>}<div className="spacer" /><button className="btn mini ghost icon" onClick={onClose} aria-label="Закрыть список"><Icon name="close" size={15} /></button></div>
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
      {!d && !err && <SkelRows rows={4} cols={5} />}
      {d && (<>
        <div className="table-scroll flat">
          <table className="table compact">
            <thead><tr><th>Компьютер</th><th>IP-адрес</th><th>ОС</th><th>Группа</th><th>Подключение к KSC</th><th>Установленные версии</th></tr></thead>
            <tbody>{d.items.map((h: ProductHost) => (
              <tr key={h.host_id}><td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link></td><td className="mono nowrap">{h.ip || "—"}</td><td className="small">{h.os}</td><td className="small">{h.group}</td>
                <td className="nowrap">{fmt(h.last_connected)} <ActivityBadge days={h.days_since_connection} activityDays={activityDays} /></td>
                <td className="small mono">{h.versions.map((v) => `${v.app_name} ${v.app_version}`).join("; ")}</td></tr>))}
              {!d.items.length && <tr><td colSpan={6}><Empty icon="monitor" title="Компьютеров нет">{d.hidden_hosts ? `Все ${d.hidden_hosts} компьютеров с этой версией давно не подключались к KSC.` : "Установок не найдено."}</Empty></td></tr>}
            </tbody>
          </table>
        </div>
        <div className="panel-foot"><Pager total={d.total} offset={offset} limit={50} onPage={setOffset} />{!all && d.hidden_hosts > 0 && <span className="muted small">Ещё {num(d.hidden_hosts)} без связи с KSC дольше {activityDays} сут скрыто</span>}</div>
      </>)}
    </div>
  );
}

function SplitDialog({ product, names, onClose, onDone }: { product: CatalogProductFull; names: string[]; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(names[0] ?? ""); const [note, setNote] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); setBusy(true); try { await api.catalog.addOverride({ kind: "split", from_key: product.key, match_names: names, to_name: name, note: note || null }); onDone(); } catch (x) { setErr((x as ApiError).message); setBusy(false); } };
  return (
    <Modal title="Выделить в отдельный продукт" onClose={onClose}>
      <form onSubmit={submit}>
        <p className="muted small">Записи реестра с этими названиями перейдут в новый продукт во всех источниках:</p>
        <ul className="chips mb">{names.map((n) => <li key={n} className="chip">{n}</li>)}</ul>
        <label>Название нового продукта<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={300} autoFocus /></label>
        <label>Комментарий<input value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} placeholder="Почему разделено" /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={!name.trim()}><span>Выделить</span></button></div>
      </form>
    </Modal>
  );
}

function MergeDialog({ product, sourceId, onClose, onDone }: { product: CatalogProductFull; sourceId: string; onClose: () => void; onDone: (to: string) => void }) {
  const [target, setTarget] = useState<PickedProduct | null>(null); const [dir, setDir] = useState<"into" | "from">("into");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const ids = useMemo(() => [sourceId], [sourceId]);
  const submit = async (e: FormEvent) => {
    e.preventDefault(); if (!target) return; setBusy(true);
    const [from, to] = dir === "into" ? [product.key, target.key] : [target.key, product.key];
    try { await api.catalog.addOverride({ kind: "merge", from_key: from, to_key: to }); onDone(to); } catch (x) { setErr((x as ApiError).message); setBusy(false); }
  };
  return (
    <Modal title="Объединить продукты" onClose={onClose}>
      <form onSubmit={submit}>
        <label>Второй продукт<ProductPicker value={target} onChange={setTarget} sourceIds={ids} autoFocus /></label>
        <fieldset className="radio-list"><legend className="sr-only">Направление</legend>
          <label className="check"><input type="radio" name="dir" checked={dir === "into"} onChange={() => setDir("into")} /><span>«{product.name}» войдёт в выбранный продукт</span></label>
          <label className="check"><input type="radio" name="dir" checked={dir === "from"} onChange={() => setDir("from")} /><span>Выбранный продукт войдёт в «{product.name}»</span></label>
        </fieldset>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy} disabled={!target || target.key === product.key}><span>Объединить</span></button></div>
      </form>
    </Modal>
  );
}

function RenameDialog({ product, onClose, onDone }: { product: CatalogProductFull; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(product.name); const [pub, setPub] = useState(product.publisher);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); setBusy(true); try { await api.catalog.addOverride({ kind: "rename", to_key: product.key, to_name: name, to_publisher: pub }); onDone(); } catch (x) { setErr((x as ApiError).message); setBusy(false); } };
  return (
    <Modal title="Переименовать продукт" onClose={onClose}>
      <form onSubmit={submit}>
        <label>Название<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={300} autoFocus /></label>
        <label>Производитель<input value={pub} onChange={(e) => setPub(e.target.value)} maxLength={300} /></label>
        {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
        <div className="modal-foot"><button type="button" className="btn ghost" onClick={onClose}>Отмена</button><button className="btn primary" aria-busy={busy}><span>Сохранить</span></button></div>
      </form>
    </Modal>
  );
}
