import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as RKeyboardEvent, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { api, type ApiError, type HierData } from "../api";
import { Modal } from "../components/Dialogs";
import { Icon } from "../components/Icons";
import { useToast } from "../components/Toast";
import { Empty, PageHead, SkelRows, Tabs } from "../components/ui";
import { fmt, num, plural } from "../util";

/** «Иерархия. Предприятие»: структура организации по адресной книге почты. Данные отдаёт сервер после проверки роли; страница только показывает их и ничего не исправляет. */

interface Person { i: number; id: string; name: string; email: string; title: string; dept: number; mgr: number; mgrText: string; inh: boolean; self: boolean; reach: boolean; head: boolean; why: string; size: number; kids: number[]; sn: string }
interface GNode { id: string; kind: "root" | "p" | "grp" | "more"; p?: Person; label?: string; sub?: string; dept?: number; ch: GNode[]; parent?: GNode; rest?: number }
interface Pos { d: number; y: number }

const W = 224, H = 40, GX = 56, GY = 8, LIM = 14, MORE = 20, MAX_DEPTH = 200;
const shortName = (n: string) => { const t = n.split(/\s+/); return t.length < 2 ? n : `${t[0]} ${t.slice(1, 3).map((x) => `${x.charAt(0).toUpperCase()}.`).join(" ")}`; };
const initials = (n: string) => { const t = n.split(/\s+/); return (t[0].charAt(0) + (t[1] ?? "").charAt(0)).toUpperCase(); };
const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const reduceMotion = () => typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const byName = (a: Person, b: Person) => a.name.localeCompare(b.name, "ru");

function Avatar({ p, hue, lg }: { p: Person; hue: number; lg?: boolean }) { return <span className={`hier-av ${lg ? "lg" : ""}`} style={{ "--h": hue } as React.CSSProperties} aria-hidden>{initials(p.name)}</span>; }

function Hl({ text, q }: { text: string; q: string }) {
  const i = q ? text.toLowerCase().indexOf(q) : -1;
  return i < 0 ? <>{text}</> : <>{text.slice(0, i)}<mark>{text.slice(i, i + q.length)}</mark>{text.slice(i + q.length)}</>;
}

export default function HierarchyPage() {
  const [data, setData] = useState<HierData | null>(null);
  const [err, setErr] = useState("");
  const [asked, setAsked] = useState(false);
  const [toast, show] = useToast();
  const load = useCallback(() => api.hier.data().then((d) => { setData(d); setErr(""); return d; }).catch((e) => { setErr((e as ApiError).message); return null; }), []);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {                                                       // идёт сбор (или запрошен): страница сама подхватит готовый снимок
    if (!data || !(data.running || asked)) return;
    const first = data.snapshot?.id;
    const t = window.setInterval(() => void load().then((d) => { if (d && !d.running && d.snapshot?.id !== first) setAsked(false); }), 6000);
    const stop = window.setTimeout(() => setAsked(false), 180000);
    return () => { window.clearInterval(t); window.clearTimeout(stop); };
  }, [data?.running, data?.snapshot?.id, asked, load]); // eslint-disable-line react-hooks/exhaustive-deps
  const refresh = async () => { try { await api.hier.run(); setAsked(true); show("Сбор запрошен: обычно занимает до минуты, страница обновится сама"); } catch (e) { show((e as ApiError).message, "error"); } };
  if (err && !data) return <section><PageHead title="Иерархия. Предприятие" /><div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div></section>;
  if (!data) return <section><PageHead title="Иерархия. Предприятие" /><div className="card"><SkelRows rows={6} cols={3} /></div></section>;
  return (
    <section className="hier">
      <PageHead title="Иерархия. Предприятие" lede="Кто кому подчиняется и кто в каком подразделении — по адресной книге почты.">
        {data.can_admin && <div className="row">
          <button type="button" className="btn" onClick={() => void refresh()} disabled={data.running || asked} aria-busy={data.running || asked}><Icon name="refresh" size={15} />{data.running || asked ? "Идёт сбор…" : "Обновить сейчас"}</button>
          <Link className="btn ghost" to="/admin?tab=hier"><Icon name="sliders" size={15} />Настройки</Link></div>}
      </PageHead>
      <Source d={data} />
      {data.warning && <div className={`alert ${data.warning.status === "stale" ? "warn" : "error"}`} role="alert"><Icon name="alert" /><div className="alert-body">
        <b>{data.warning.status === "rejected" ? "Новый снимок не опубликован." : data.warning.status === "failed" ? "Последний сбор не удался." : "Данные могли устареть."}</b> {data.warning.message}
        {data.warning.last_ok_at && <> Показан последний успешный снимок от {fmt(data.warning.last_ok_at)}.</>}</div></div>}
      {data.state !== "ok" || !data.snapshot ? <NoData d={data} onRun={() => void refresh()} busy={data.running || asked} /> : <Chart d={data} />}
      {toast}
    </section>
  );
}

function Source({ d }: { d: HierData }) {
  const s = d.snapshot;
  return (
    <div className="hier-source" role="note">
      <Icon name="mail" size={22} />
      <div><b>Данные получены из почты.</b> Структура построена по адресной книге почты (Exchange): поля «Руководитель», «Должность», «Подразделение».
        {s ? <> Выгрузка от <span className="mono">{fmt(s.at)}</span>.</> : <> Выгрузки ещё не было.</>}
        {s && <span className="sub small">В адресной книге {num(s.raw_n)} {plural(s.raw_n, "запись", "записи", "записей")}. Показано {num(s.kept)} {plural(s.kept, "сотрудник", "сотрудника", "сотрудников")}: служебные ящики, внешние контакты и пустые карточки ({num(s.excluded)}) исключены.
          {s.source_name ? ` Источник: ${s.source_name}.` : s.source === "file" ? " Источник: загруженный файл." : ""}{d.next_run ? ` Следующее обновление: ${fmt(d.next_run)}.` : ""}</span>}</div>
    </div>
  );
}

function NoData({ d, onRun, busy }: { d: HierData; onRun: () => void; busy: boolean }) {
  return (
    <div className="card"><Empty icon="sitemap" title={d.state === "failed" ? "Снимок ещё не получен: сбор не удался" : "Структура ещё не загружена"}
      action={d.can_admin ? <><Link className="btn" to="/admin?tab=hier"><Icon name="sliders" size={15} />Настроить источник</Link>{d.source === "ldap" && <button type="button" className="btn primary" onClick={onRun} disabled={busy}>Обновить сейчас</button>}</> : undefined}>
      {d.state === "failed" && d.last_error ? d.last_error : d.can_admin ? "Выберите источник (подключение LDAPS), проверьте его и запустите сбор — либо загрузите файл выгрузки." : "Администратор ещё не настроил раздел."}</Empty></div>
  );
}

// ------------------------------------------------------------------------------------------------ граф, карточка, поиск
function Chart({ d }: { d: HierData }) {
  const loc = useLocation();
  const [tab, setTab] = useState<"g" | "d">("g");
  const [sel, setSel] = useState(-1);
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => ({ root: true, ...Object.fromEntries(d.people.map((r, i) => [r, i]).filter(([r]) => ((r as HierData["people"][number])[8] & 4) !== 0).slice(0, 3).map(([, i]) => [`p${i}`, true])) }));
  const [limit, setLimit] = useState<Record<string, number>>({});
  const [chain, setChain] = useState<Record<string, boolean>>({});
  const [zoom, setZoom] = useState(1);
  const [sheet, setSheet] = useState<{ dept: number; focus: number; mode: "team" | "all"; q: string; openAll: boolean } | null>(null);
  const [q, setQ] = useState("");
  const wrap = useRef<HTMLDivElement>(null);

  const model = useMemo(() => {
    const P: Person[] = d.people.map((r, i) => ({ i, id: r[0], name: r[1], email: r[2], title: r[3], dept: r[4], mgr: r[5], mgrText: r[6], inh: !!r[7], self: !!(r[8] & 1), reach: !!(r[8] & 2), head: !!(r[8] & 4), why: r[9], size: r[10], kids: [], sn: shortName(r[1]) }));
    P.forEach((p) => { if (p.mgr >= 0) P[p.mgr].kids.push(p.i); });
    P.forEach((p) => p.kids.sort((a, b) => (P[b].size || 1) - (P[a].size || 1) || byName(P[a], P[b])));
    const heads = P.filter((p) => p.head).sort((a, b) => b.size - a.size || byName(a, b));
    const lone = P.filter((p) => !p.reach);
    const N: Record<string, GNode> = {};
    const pnode = (i: number, leaf: boolean, depth: number): GNode => {
      const p = P[i];
      const n: GNode = { id: `p${i}`, kind: "p", p, ch: leaf || depth > MAX_DEPTH ? [] : p.kids.map((k) => pnode(k, false, depth + 1)) };
      N[n.id] = n;
      return n;
    };
    const root: GNode = { id: "root", kind: "root", label: "Предприятие", sub: `${heads.length} ${plural(heads.length, "верхний руководитель", "верхних руководителя", "верхних руководителей")}`, ch: [] };
    N.root = root;
    heads.forEach((h) => root.ch.push(pnode(h.i, false, 0)));
    const noMgr: GNode = { id: "gno", kind: "grp", label: "Руководитель в почте не указан", sub: `${lone.length} чел.`, ch: [] };
    N.gno = noMgr;
    const byDept = new Map<number, number[]>();
    lone.forEach((p) => byDept.set(p.dept, [...(byDept.get(p.dept) ?? []), p.i]));
    [...byDept.entries()].sort((a, b) => b[1].length - a[1].length).forEach(([dpt, ids]) => {
      const g: GNode = { id: `gd${dpt}`, kind: "grp", dept: dpt, label: d.depts[dpt]?.name ?? "", sub: `${ids.length} чел.`, ch: [] };
      N[g.id] = g;
      ids.sort((a, b) => byName(P[a], P[b])).forEach((i) => g.ch.push(pnode(i, true, 0)));
      noMgr.ch.push(g);
    });
    if (lone.length) root.ch.push(noMgr);
    const idx = new Map(P.map((p) => [p.id, p.i]));
    return { P, heads, lone, N, root, idx };
  }, [d]);
  const { P, heads, lone, N, root } = model;
  const hue = (dpt: number) => d.depts[dpt]?.hue ?? 200;

  const visible = useCallback((n: GNode): GNode[] => {
    if (!expanded[n.id]) return [];
    const l = limit[n.id] ?? LIM, out = n.ch.slice(0, l);
    if (n.ch.length > l) out.push({ id: `more:${n.id}`, kind: "more", parent: n, rest: n.ch.length - l, ch: [] });
    return out;
  }, [expanded, limit]);

  const L = useMemo(() => {
    const pos = new Map<string, Pos>(), items: GNode[] = [], links: [GNode, GNode][] = [];
    let cur = 0, maxd = 0;
    const go = (n: GNode, dd: number) => {                                  // обход в глубину; глубина ограничена MAX_DEPTH при построении дерева
      maxd = Math.max(maxd, dd);
      const k = visible(n);
      let y: number;
      if (!k.length) { y = cur; cur += H + GY; }
      else { k.forEach((c) => { go(c, dd + 1); links.push([n, c]); }); y = (pos.get(k[0].id)!.y + pos.get(k[k.length - 1].id)!.y) / 2; }
      pos.set(n.id, { d: dd, y });
      items.push(n);
    };
    go(root, 0);
    return { pos, items, links, w: (maxd + 1) * (W + GX) - GX + 24, h: Math.max(cur, H) + 8 };
  }, [root, visible]);

  const reveal = useCallback((p: Person) => {
    const ids: string[] = [];
    if (p.reach) { let c = p.i, g = 0; while (c >= 0 && g++ < 300) { ids.unshift(`p${c}`); c = P[c].mgr; } ids.unshift("root"); }
    else ids.push("root", "gno", `gd${p.dept}`, `p${p.i}`);
    const ch: Record<string, boolean> = {};
    ids.forEach((x) => { ch[x] = true; });
    setChain(ch);
    setExpanded((e) => { const n = { ...e }; ids.slice(0, -1).forEach((x) => { n[x] = true; }); return n; });
    setLimit((l) => {
      const n = { ...l };
      for (let k = 0; k < ids.length - 1; k++) { const par = N[ids[k]]; const ix = par.ch.findIndex((c) => c.id === ids[k + 1]); if (ix >= (n[par.id] ?? LIM)) n[par.id] = ix + 1; }
      return n;
    });
  }, [P, N]);

  const select = useCallback((i: number, opts: { quiet?: boolean } = {}) => {
    setSel(i);
    if (i >= 0) { reveal(P[i]); try { window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#p${P[i].id}`); } catch { /* адрес не обязателен */ } }
    else { setChain({}); try { window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`); } catch { /* адрес не обязателен */ } }
    if (i >= 0 && !opts.quiet && window.innerWidth <= 1180) window.setTimeout(() => document.getElementById("hier-panel")?.scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "start" }), 60);
  }, [P, reveal]);

  useEffect(() => {                                                       // ссылка на сотрудника: #p<идентификатор>
    const m = loc.hash.match(/^#p([0-9a-f]+)$/);
    if (m) { const i = model.idx.get(m[1]); if (i !== undefined && i !== sel) select(i, { quiet: true }); }
  }, [loc.hash, model.idx]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {                                                       // выбранный человек — в центре схемы
    if (sel < 0 || tab !== "g") return;
    const pos = L.pos.get(`p${sel}`), w = wrap.current;
    if (!pos || !w) return;
    const t = window.setTimeout(() => w.scrollTo({ left: Math.max(0, (pos.d * (W + GX) + 12) * zoom - w.clientWidth / 2 + (W * zoom) / 2), top: Math.max(0, (pos.y + 4) * zoom - w.clientHeight / 2 + (H * zoom) / 2), behavior: reduceMotion() ? "auto" : "smooth" }), 40);
    return () => window.clearTimeout(t);
  }, [sel, tab, L.pos]); // eslint-disable-line react-hooks/exhaustive-deps

  // перетаскивание схемы мышью (сдвиг больше 5 пикселей — перетаскивание, иначе клик) и масштаб Ctrl + колесо
  const zoomRef = useRef(zoom);
  zoomRef.current = zoom;
  const drag = useRef<{ x: number; y: number; l: number; t: number } | null>(null);
  const moved = useRef(false);
  const setZoomAt = useCallback((z: number, cx?: number, cy?: number) => {
    const w = wrap.current;
    z = Math.max(0.4, Math.min(2, z));
    setZoom((old) => {
      if (z === old || !w) return z;
      const x = cx ?? w.clientWidth / 2, y = cy ?? w.clientHeight / 2, px = (w.scrollLeft + x) / old, py = (w.scrollTop + y) / old;
      window.requestAnimationFrame(() => { w.scrollLeft = px * z - x; w.scrollTop = py * z - y; });
      return z;
    });
  }, []);
  useEffect(() => {
    const w = wrap.current;
    if (!w) return;
    const wheel = (e: WheelEvent) => { if (!e.ctrlKey) return; e.preventDefault(); const r = w.getBoundingClientRect(); setZoomAt(zoomRef.current * (e.deltaY < 0 ? 1.1 : 1 / 1.1), e.clientX - r.left, e.clientY - r.top); };
    const move = (e: PointerEvent) => {
      const s = drag.current;
      if (!s) return;
      const dx = e.clientX - s.x, dy = e.clientY - s.y;
      if (!moved.current && Math.abs(dx) + Math.abs(dy) < 5) return;
      moved.current = true; w.classList.add("drag"); w.scrollLeft = s.l - dx; w.scrollTop = s.t - dy;
    };
    const up = () => { drag.current = null; w.classList.remove("drag"); };
    w.addEventListener("wheel", wheel, { passive: false });
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    return () => { w.removeEventListener("wheel", wheel); window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
  }, [setZoomAt, tab]);

  const toggle = (id: string) => setExpanded((e) => ({ ...e, [id]: !e[id] }));
  const clickNode = (n: GNode) => {
    if (n.kind === "more") { const par = n.parent!.id; setLimit((l) => ({ ...l, [par]: (l[par] ?? LIM) + MORE })); return; }
    if (n.kind === "p") { if (n.ch.length && !expanded[n.id]) toggle(n.id); select(n.p!.i); return; }
    toggle(n.id);
  };
  const onKey = (e: RKeyboardEvent, n: GNode) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); clickNode(n); } };

  const personRow = (p: Person, extra?: ReactNode, cls = "") => (
    <button type="button" className={`hier-row ${cls}`} key={p.i} onClick={() => { setSheet(null); select(p.i); }}>
      <Avatar p={p} hue={hue(p.dept)} /><span className="t"><span className="n">{p.sn}</span><span className="s">{p.title || "должность не указана"}</span></span>{extra ? <span className="k">{extra}</span> : null}</button>);

  return (
    <div className="hier-grid">
      <aside className="hier-left"><Search P={P} q={q} setQ={setQ} onPick={(i) => select(i)} hue={hue} /><Note /></aside>
      <main className="card hier-main">
        <div className="hier-tabs"><Tabs value={tab} onChange={setTab} label="Вид структуры" items={[{ id: "g", label: "Граф" }, { id: "d", label: "Подразделения", count: d.depts.length }]} />
          {tab === "g" && <div className="hier-tools">
            <button type="button" className="btn mini" onClick={() => setZoomAt(zoom / 1.2)} aria-label="Уменьшить">−</button><button type="button" className="btn mini" onClick={() => setZoomAt(zoom * 1.2)} aria-label="Увеличить">+</button>
            <button type="button" className="btn mini" onClick={() => { setExpanded({ root: true }); setLimit({}); setChain({}); setSel(-1); }}>Свернуть всё</button>
            <button type="button" className="btn mini" onClick={() => setExpanded((e) => { const n = { ...e }; root.ch.forEach((c) => { if (c.ch.length) n[c.id] = true; }); return n; })}>Раскрыть 1 уровень</button></div>}</div>
        {tab === "g" ? (<>
          <p className="hier-hint">Схему можно двигать мышью, масштаб меняют кнопки «+» и «−» или Ctrl и колесо. Нажмите на человека — справа его карточка и цепочка руководителей. Кружок справа от карточки раскрывает и сворачивает подчинённых.</p>
          <div className="hier-gwrap" ref={wrap} onPointerDown={(e) => { if (e.pointerType !== "mouse" || e.button !== 0) return; const w = wrap.current!; drag.current = { x: e.clientX, y: e.clientY, l: w.scrollLeft, t: w.scrollTop }; moved.current = false; }}
            onClickCapture={(e) => { if (moved.current) { e.stopPropagation(); e.preventDefault(); moved.current = false; } }}>
            <svg className="hier-g" role="img" aria-label="Граф иерархии предприятия" width={Math.round(L.w * zoom)} height={Math.round(L.h * zoom)} viewBox={`0 0 ${L.w} ${L.h}`}>
              {L.links.map(([a, b]) => { const pa = L.pos.get(a.id)!, pb = L.pos.get(b.id)!, x1 = pa.d * (W + GX) + 12 + W, y1 = pa.y + 4 + H / 2, x2 = pb.d * (W + GX) + 12, y2 = pb.y + 4 + H / 2, mx = (x1 + x2) / 2;
                return <path key={`${a.id}>${b.id}`} className={`lnk${chain[a.id] && chain[b.id] ? " on" : ""}`} d={`M${x1} ${y1}C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`} />; })}
              {[...L.items].sort((a, b) => (chain[a.id] ? 1 : 0) - (chain[b.id] ? 1 : 0)).map((n) => {
                const pos = L.pos.get(n.id)!, p = n.p;
                let l1 = "", l2 = "", cls = "nd", hh: number | undefined, cnt: number | null = null;
                if (n.kind === "p" && p) { cls += sel === p.i ? " sel" : chain[n.id] ? " on" : ""; hh = hue(p.dept); l1 = p.sn; l2 = trunc(p.title || d.depts[p.dept]?.name || "", p.kids.length ? 24 : 34); if (n.ch.length) cnt = p.size - 1; }
                else if (n.kind === "root") { cls += ` grp${chain[n.id] ? " on" : ""}`; l1 = n.label!; l2 = n.sub!; }
                else if (n.kind === "grp") { cls += ` grp${chain[n.id] ? " on" : ""}`; hh = n.dept !== undefined ? hue(n.dept) : undefined; l1 = trunc(n.label!, 28); l2 = n.sub!; }
                else { cls += " more"; l1 = `ещё ${n.rest}`; l2 = "показать следующих"; }
                return (
                  <g key={n.id} className={cls} style={hh !== undefined ? ({ "--h": hh } as React.CSSProperties) : undefined} data-id={n.id} transform={`translate(${pos.d * (W + GX) + 12},${pos.y + 4})`} role="button" tabIndex={0} aria-label={`${l1}. ${l2}`}
                    onClick={() => clickNode(n)} onKeyDown={(e) => onKey(e, n)}>
                    <rect className="b" width={W} height={H} rx={10} />
                    {hh !== undefined && n.kind !== "more" && <rect className="strip" x={0} y={0} width={5} height={H} rx={2.5} />}
                    <text className="t1" x={16} y={17}>{l1}</text><text className="t2" x={16} y={31}>{l2}</text>
                    {cnt !== null && !expanded[n.id] && <text className="cnt" x={W - 30} y={24} textAnchor="end">+{cnt}</text>}
                    {n.ch.length > 0 && n.kind !== "more" && <g className="tg" transform={`translate(${W - 14},${H / 2})`} onClick={(e) => { e.stopPropagation(); toggle(n.id); }}><circle r={10} /><text y={4.5}>{expanded[n.id] ? "−" : "+"}</text></g>}
                  </g>);
              })}
            </svg>
          </div>
          <div className="hier-legend"><span><i className="lg-chain" />цепочка выбранного</span><span><i className="lg-sel" />выбранный сотрудник</span><span>цвет полоски слева — подразделение</span></div>
        </>) : (
          <div className="hier-tiles">{d.depts.map((dp, k) => {
            const members = P.filter((p) => p.dept === k);
            if (!members.length) return null;
            let best: Person | null = null;
            members.forEach((p) => { const out = p.mgr < 0 || P[p.mgr].dept !== k; if (out && (!best || (p.size || 1) > (best.size || 1))) best = p; });
            const lead = best as Person | null;
            const max = Math.max(...d.depts.map((x) => x.n));
            return <button type="button" key={dp.name} className="hier-tile" style={{ "--h": dp.hue } as React.CSSProperties} onClick={() => setSheet({ dept: k, focus: -1, mode: "all", q: "", openAll: false })}>
              <b>{dp.name}</b><span className="num">{num(members.length)}</span><span className="hd">{lead && lead.kids.length ? `Руководитель: ${lead.sn}` : "Руководитель не определён"}</span>
              <span className="bar"><i style={{ width: `${Math.max(4, Math.round((100 * members.length) / max))}%` }} /></span></button>;
          })}</div>)}
      </main>
      <aside className="card hier-right" id="hier-panel" aria-live="polite">
        {sel < 0 ? <Overview d={d} heads={heads} lone={lone.length} row={personRow} total={P.length} /> : <Card p={P[sel]} P={P} d={d} hue={hue} row={personRow} warnings={d.why ?? {}}
          onWho={() => setSheet({ dept: P[sel].dept, focus: sel, mode: P[sel].mgr >= 0 && P.some((x) => x.i !== sel && x.mgr === P[sel].mgr) ? "team" : "all", q: "", openAll: false })}
          onFocus={() => { setTab("g"); select(sel); }} onClose={() => select(-1)} />}
      </aside>
      {sheet && <Sheet st={sheet} setSt={setSheet} P={P} d={d} row={personRow} onClose={() => setSheet(null)} />}
    </div>
  );
}

function Note() {
  return (
    <details className="card hier-note"><summary>Откуда эти данные и что они не показывают</summary>
      <p>Раздел показывает то, что заполнено в почте, и сам эти данные не исправляет. У части людей руководитель не указан, подразделение пустое, названия подразделений написаны по-разному, а у разных людей одинаковая должность оказывается в разных ветках без общего начальника — такие случаи показаны как есть и помечены.</p>
      <p>Если подразделение у человека не заполнено, взято подразделение ближайшего вышестоящего руководителя (пометка «по руководителю»). Исправлять данные нужно в карточках пользователей почты.</p></details>
  );
}

function Search({ P, q, setQ, onPick, hue }: { P: Person[]; q: string; setQ: (v: string) => void; onPick: (i: number) => void; hue: (d: number) => number }) {
  const t = q.toLowerCase().trim();
  const res = useMemo(() => {
    if (t.length < 2) return null;
    const hit = P.filter((p) => `${p.name} ${p.title} ${p.email}`.toLowerCase().includes(t));
    hit.sort((a, b) => (a.name.toLowerCase().startsWith(t) ? 0 : 1) - (b.name.toLowerCase().startsWith(t) ? 0 : 1) || byName(a, b));
    return { list: hit.slice(0, 10), total: hit.length };
  }, [P, t]);
  return (
    <div className="card pad">
      <h2 className="hier-h">Найти сотрудника</h2>
      <div className="hier-search"><Icon name="search" size={16} />
        <input type="search" value={q} placeholder="Фамилия, должность или почта" autoComplete="off" aria-label="Поиск сотрудника" onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && res?.list[0]) onPick(res.list[0].i); }} /></div>
      <div className="hier-results" role="list">
        {!res ? <div className="hier-empty">Введите минимум 2 буквы.<br />Например, «Орлов» или «аналитик».</div>
          : !res.list.length ? <div className="hier-empty">Никого не найдено.</div>
          : <>{res.list.map((p) => <button type="button" role="listitem" className="hier-row" key={p.i} onClick={() => onPick(p.i)}><Avatar p={p} hue={hue(p.dept)} />
              <span className="t"><span className="n"><Hl text={p.sn} q={t} /></span><span className="s">{p.title || "должность не указана"}</span></span></button>)}
            {res.total > 10 && <div className="hier-empty">Показано 10 из {res.total}. Уточните запрос.</div>}</>}
      </div>
    </div>
  );
}

function Overview({ d, heads, lone, row, total }: { d: HierData; heads: Person[]; lone: number; row: (p: Person, extra?: ReactNode, cls?: string) => ReactNode; total: number }) {
  const depts = d.depts.filter((x) => x.name !== "Подразделение не указано").length;
  return (<>
    <div className="pad"><h2 className="hier-h">Предприятие в цифрах</h2><div className="hier-stats">
      <div className="hier-stat"><b>{num(total)}</b><span>сотрудников в структуре</span></div><div className="hier-stat"><b>{num(depts)}</b><span>подразделений</span></div>
      <div className="hier-stat"><b>{num(heads.length)}</b><span>руководителей верхнего уровня</span></div><div className="hier-stat"><b>{num(lone)}</b><span>без руководителя в почте</span></div></div></div>
    <div className="hier-sec"><h2 className="hier-h">Верхний уровень</h2><div>{heads.map((h) => row(h, `+${h.size - 1}`))}</div></div>
    <div className="hier-sec"><div className="hier-notebox">Выберите сотрудника в поиске или на графе: здесь появится его руководитель, вся цепочка выше и кнопка «Кто ещё в подразделении».</div></div>
  </>);
}

function Card({ p, P, d, hue, row, warnings, onWho, onFocus, onClose }: { p: Person; P: Person[]; d: HierData; hue: (d: number) => number; row: (p: Person, extra?: ReactNode, cls?: string) => ReactNode; warnings: Record<string, string>;
  onWho: () => void; onFocus: () => void; onClose: () => void }) {
  const [all, setAll] = useState(false);
  const [copied, setCopied] = useState("");
  useEffect(() => { setAll(false); setCopied(""); }, [p.i]);
  const steps: number[] = [];
  if (p.mgr >= 0) { let c = p.mgr, g = 0; while (c >= 0 && g++ < 300 && !steps.includes(c)) { steps.push(c); c = P[c].mgr; } }
  const top = steps.length ? P[steps[steps.length - 1]] : p;
  const copy = () => { try { void navigator.clipboard.writeText(p.email).then(() => setCopied("Скопировано"), () => setCopied("Выделите вручную")); } catch { setCopied("Выделите вручную"); } };
  return (<>
    <div className="pad"><Avatar p={p} hue={hue(p.dept)} lg /><div className="hier-pname">{p.name}</div><div className="muted">{p.title || "Должность не указана"}</div>
      <span className="hier-chip" style={{ "--h": hue(p.dept) } as React.CSSProperties}>{d.depts[p.dept]?.name}{p.inh ? " · по руководителю" : ""}</span>
      <div className="hier-mail"><span>{p.email}</span><button type="button" className="btn mini" onClick={copy}>{copied || "Копировать"}</button></div></div>
    <div className="hier-sec"><h2 className="hier-h">Кому подчиняется</h2>
      {steps.length > 0 ? <>
        <ul className="hier-chain">{steps.map((i, k) => <li key={i}>{k === 0 && <span className="hier-lab">Непосредственный руководитель</span>}{row(P[i], undefined, k === 0 ? "direct" : "")}</li>)}</ul>
        {steps.length > 1 && <div className="hier-notebox mt-sm">Цепочка: {steps.length} {steps.length < 5 ? "уровня" : "уровней"} до верхнего руководителя.</div>}
        {!top.head && !top.self && <div className="hier-notebox mt-sm">{warnings[top.why] || "Цепочка выше не продолжается."}</div>}</>
        : <div className="hier-notebox">{p.why === "text" && p.mgrText ? `В почте указан руководитель «${p.mgrText}», но найти его в выгрузке не удалось.` : warnings[p.why] || ""}</div>}</div>
    {p.kids.length > 0 && <div className="hier-sec"><h2 className="hier-h">Подчинённые · {p.kids.length}</h2><div className="hier-kids">{(all ? p.kids : p.kids.slice(0, 6)).map((k) => row(P[k]))}</div>
      {p.kids.length > 6 && !all && <button type="button" className="btn mt-sm" onClick={() => setAll(true)}>Показать всех {p.kids.length}</button>}</div>}
    <div className="hier-actions"><button type="button" className="btn primary" onClick={onWho}>Кто ещё в подразделении</button><button type="button" className="btn" onClick={onFocus}>Показать на графе</button><button type="button" className="btn" onClick={onClose}>Закрыть</button></div>
  </>);
}

function Sheet({ st, setSt, P, d, row, onClose }: { st: { dept: number; focus: number; mode: "team" | "all"; q: string; openAll: boolean }; setSt: (s: { dept: number; focus: number; mode: "team" | "all"; q: string; openAll: boolean }) => void;
  P: Person[]; d: HierData; row: (p: Person, extra?: ReactNode, cls?: string) => ReactNode; onClose: () => void }) {
  const members = useMemo(() => P.filter((x) => x.dept === st.dept), [P, st.dept]);
  const f = st.focus >= 0 ? P[st.focus] : null;
  const team = f && f.mgr >= 0 ? P.filter((x) => x.i !== f.i && x.mgr === f.mgr) : [];
  const showTeam = st.mode === "team" && !!f && team.length > 0;
  let list = showTeam ? [...team, f!] : members;
  const q = st.q.toLowerCase().trim();
  if (q) list = list.filter((x) => `${x.name} ${x.title}`.toLowerCase().includes(q));
  const groups = new Map<number, Person[]>();
  list.forEach((x) => groups.set(x.mgr, [...(groups.get(x.mgr) ?? []), x]));
  const keys = [...groups.keys()].sort((a, b) => groups.get(b)!.length - groups.get(a)!.length);
  const openAll = st.openAll || !!q || showTeam || keys.length <= 3;
  return (
    <Modal side title={d.depts[st.dept]?.name ?? "Подразделение"} onClose={onClose} guard={false} lede={f ? `Кто ещё рядом с сотрудником ${f.sn}` : `${num(members.length)} ${plural(members.length, "сотрудник", "сотрудника", "сотрудников")}`}>
      <div className="hier-sheet">
        {f && <div className="hier-seg" role="group" aria-label="Состав">
          <button type="button" aria-pressed={showTeam} onClick={() => setSt({ ...st, mode: "team" })}>Моя команда · {team.length}</button>
          <button type="button" aria-pressed={!showTeam} onClick={() => setSt({ ...st, mode: "all" })}>Всё подразделение · {members.length}</button></div>}
        <div className="row tight">
          <div className="hier-search grow"><Icon name="search" size={16} /><input type="search" value={st.q} placeholder="Фильтр по фамилии или должности" aria-label="Фильтр" onChange={(e) => setSt({ ...st, q: e.target.value })} /></div>
          <button type="button" className="btn mini" onClick={() => setSt({ ...st, openAll: !openAll })}>{openAll ? "Свернуть" : "Развернуть"} группы</button></div>
        {!list.length ? <div className="hier-empty">Никого не найдено.</div> : keys.map((k) => {
          const m = k >= 0 ? P[k] : null, arr = [...groups.get(k)!].sort(byName);
          const hasF = !!f && arr.some((x) => x.i === f.i);
          return <details className="hier-grp" key={`${k}:${openAll}`} open={openAll || hasF || (keys[0] === k && !f)}><summary><span>{m ? `Подчиняются: ${m.sn}` : "Без руководителя в почте"}</span><small>{arr.length}</small></summary>
            <div>{arr.map((x) => row(x, f && x.i === f.i ? "вы" : undefined, f && x.i === f.i ? "me" : ""))}</div></details>;
        })}
      </div>
    </Modal>
  );
}
