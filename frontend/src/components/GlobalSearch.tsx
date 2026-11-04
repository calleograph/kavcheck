import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, type Host } from "../api";
import { FUNCTIONS, QUICK_REPORTS, roleOk, type Fn, type Role } from "../navModel";
import { Icon, type IconName } from "./Icons";

type Product = Awaited<ReturnType<typeof api.catalog.search>>["items"][number];
type Cat = "hosts" | "software" | "users" | "vuln";
type Hit = { key: string; icon: IconName; title: string; sub?: string; to: string; strong?: boolean };
const CATS: Record<Cat, string> = { hosts: "Компьютеры", software: "Программы", users: "Пользователи", vuln: "Уязвимости и CVE" };
const SEARCH_EVENT = "kc:search";

/** Основа слова для поиска по функциям: пять первых букв — «лицензии» находит «лицензия», «владельцы» — «владелец». */
const norm = (s: string) => s.toLowerCase().replace(/ё/g, "е");
const stem = (t: string) => (t.length > 5 ? t.slice(0, 5) : t);
const matchFn = (f: Fn, tokens: string[]) => { const hay = norm(`${f.title} ${f.kw} ${f.group}`); return tokens.every((t) => hay.includes(stem(t))); };

/** Единый поиск и навигация в верхней панели: разделы, настройки и действия (по названию и ключевым словам), компьютеры, программы, пользователи, CVE, готовые отчёты.
 *  «/» или Ctrl+K — к полю (или кнопка «Найти…» на «Быстром доступе» с выбранной категорией); стрелки, Enter, Escape. На узком экране поле открывается кнопкой. */
export function GlobalSearch({ sourceId, role, hier, page = false }: { sourceId: string | null; role: string; hier: boolean; page?: boolean }) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [wide, setWide] = useState(false);
  const [cat, setCat] = useState<Cat | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [busy, setBusy] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const listId = useId();
  const term = q.trim();
  const tokens = norm(term).split(/\s+/).filter(Boolean);

  const focus = (c: Cat | null) => { setCat(c); setWide(true); setOpen(true); window.requestAnimationFrame(() => input.current?.focus()); };
  useEffect(() => { setOpen(false); setWide(false); setQ(""); setCat(null); }, [pathname, sourceId]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLElement && (e.target.matches("input, textarea, select") || e.target.isContentEditable);
      if (!page && document.querySelector(".gsearch.page")) return;                  // на «Быстром доступе» поиск встроен в страницу: он и отвечает
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing)) { e.preventDefault(); focus(null); }
    };
    const ev = (e: Event) => { if (!page && document.querySelector(".gsearch.page")) return; focus(((e as CustomEvent).detail?.cat as Cat | undefined) ?? null); };
    document.addEventListener("keydown", key); window.addEventListener(SEARCH_EVENT, ev);
    return () => { document.removeEventListener("keydown", key); window.removeEventListener(SEARCH_EVENT, ev); };
  }, []);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => { if (!box.current?.contains(e.target as Node)) { setOpen(false); setWide(false); } };
    document.addEventListener("mousedown", away); document.addEventListener("touchstart", away, { passive: true });
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("touchstart", away); };
  }, [open]);
  const wantData = !cat || cat === "hosts" || cat === "software";
  useEffect(() => {
    if (!sourceId || term.length < 2 || !wantData) { setHosts([]); setProducts([]); return; }
    let alive = true;
    const t = window.setTimeout(() => {
      setBusy(true);
      Promise.all([
        !cat || cat === "hosts" ? api.hosts.list({ q: term, activity: "all", limit: 5 }).then((r) => r.items).catch(() => []) : Promise.resolve([] as Host[]),
        !cat || cat === "software" ? api.catalog.search(term, [sourceId]).then((r) => r.items.slice(0, 5)).catch(() => []) : Promise.resolve([] as Product[]),
      ]).then(([h, p]) => { if (alive) { setHosts(h); setProducts(p); setActive(0); } }).finally(() => { if (alive) setBusy(false); });
    }, 220);
    return () => { alive = false; window.clearTimeout(t); };
  }, [term, sourceId, cat, wantData]);

  const enc = encodeURIComponent(term);
  const vulnId = /^(cve|bdu|ghsa|kla)[-:\d]/i.test(term);
  const groups = useMemo(() => {
    const g: { title: string; hits: Hit[] }[] = [];
    const fnHits = (): Hit[] => FUNCTIONS.filter((f) => roleOk(f.roles, role) && (!f.hier || hier) && (tokens.length ? matchFn(f, tokens) : false)).slice(0, 6)
      .map((f) => ({ key: `f${f.to}`, icon: f.icon, title: f.title, sub: f.group, to: f.to }));
    const repHits = (): Hit[] => QUICK_REPORTS.filter((r) => roleOk(r.roles, role) && tokens.length && tokens.every((t) => norm(`${r.title} ${r.hint} отчёт выгрузка`).includes(stem(t)))).slice(0, 4)
      .map((r) => ({ key: `r${r.id}`, icon: "file" as IconName, title: `Отчёт: ${r.title}`, sub: "Сформировать в разделе или на «Быстром доступе»", to: r.section }));
    if (term.length >= 2 || cat) {
      if (!cat) { const f = fnHits(); if (f.length) g.push({ title: "Разделы, настройки и действия", hits: f }); }
      if (!cat) { const r = repHits(); if (r.length) g.push({ title: "Отчёты", hits: r }); }
      if ((!cat || cat === "hosts") && sourceId && term.length >= 2) g.push({ title: CATS.hosts, hits: [...hosts.map((h) => ({ key: `h${h.host_id}`, icon: "monitor" as IconName, title: h.name, sub: [h.ip, h.os, h.group].filter(Boolean).join(" · "), to: `/hosts/${h.host_id}` })),
        { key: "hall", icon: "search", title: `Все компьютеры с «${term}»`, to: `/hosts?activity=all&q=${enc}`, strong: false }] });
      if ((!cat || cat === "software") && sourceId && term.length >= 2) g.push({ title: CATS.software, hits: [...products.map((p) => ({ key: `p${p.key}`, icon: "layers" as IconName, title: p.name, sub: [p.publisher, p.latest_version && `новейшая ${p.latest_version}`].filter(Boolean).join(" · "), to: `/software/p/${encodeURIComponent(p.key)}` })),
        { key: "pall", icon: "search", title: `Все программы с «${term}»`, to: `/software?q=${enc}` }] });
      if ((!cat || cat === "users") && term.length >= 2) g.push({ title: CATS.users, hits: [{ key: "uk", icon: "users", title: `Пользователь «${term}» среди пользователей KSC`, to: `/devices?tab=ksc&q=${enc}` },
        ...(role !== "viewer" ? [{ key: "ub", icon: "users" as IconName, title: `Сотрудник «${term}» по выгрузке BI`, to: `/devices?tab=bi&q=${enc}` }] : [])] });
      if ((!cat || cat === "vuln") && term.length >= 2) g.push({ title: CATS.vuln, hits: [{ key: "vdb", icon: "vault", title: `«${term}» в базе уязвимостей`, to: `/vdb?tab=search&q=${enc}` }, { key: "vk", icon: "bug", title: `«${term}» среди уязвимостей KSC`, to: `/vulnerabilities?q=${enc}` }] });
      if (vulnId) g.sort((a, b) => (a.title === CATS.vuln ? -1 : b.title === CATS.vuln ? 1 : 0));
    }
    return g;
  }, [term, cat, hosts, products, sourceId, role, hier, vulnId]); // eslint-disable-line react-hooks/exhaustive-deps
  const flat = groups.flatMap((g) => g.hits);
  const go = (h: Hit | undefined) => { if (!h) return; navigate(h.to); setOpen(false); setWide(false); setQ(""); setCat(null); input.current?.blur(); };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, flat.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(flat[active]); }
    else if (e.key === "Backspace" && !q && cat) setCat(null);
    else if (e.key === "Escape") { e.stopPropagation(); setOpen(false); setWide(false); setCat(null); input.current?.blur(); }
  };
  const showList = open && (term.length >= 2 || !!cat);
  let idx = -1;
  const empty = showList && !flat.length;
  return (
    <div className={`gsearch ${page ? "page" : ""} ${wide ? "wide" : ""} ${showList || (open && !term) ? "open" : ""}`} ref={box}>
      {page && <div className="gs-cats" role="group" aria-label="Что искать">{([[null, "Всё"], ["hosts", "Компьютеры"], ["software", "Программы"], ["users", "Пользователи"], ["vuln", "Уязвимости и CVE"]] as [Cat | null, string][]).map(([k, l]) =>
        <button key={l} type="button" className={`gs-cat ${cat === k ? "on" : ""}`} aria-pressed={cat === k} onClick={() => { setCat(k); setOpen(true); input.current?.focus(); }}>{l}</button>)}</div>}
      <button type="button" className="btn ghost icon gs-toggle" aria-label="Поиск по приложению" onClick={() => focus(null)}><Icon name="search" size={18} /></button>
      <div className="input-icon gs-field">
        <Icon name="search" size={16} />
        {cat && <button type="button" className="gs-chip" onClick={() => { setCat(null); input.current?.focus(); }} title="Искать везде">{CATS[cat]}<Icon name="close" size={12} /></button>}
        <input ref={input} value={q} role="combobox" aria-expanded={showList} aria-controls={listId} aria-autocomplete="list" aria-label="Поиск по приложению"
          aria-activedescendant={showList && flat[active] ? `${listId}-${active}` : undefined} placeholder={cat ? `${CATS[cat]}: введите запрос` : "Раздел, компьютер, программа или CVE"} spellCheck={false} autoComplete="off"
          onFocus={() => setOpen(true)} onChange={(e) => { setQ(e.target.value); setOpen(true); setActive(0); }} onKeyDown={onKey} />
        {busy ? <span className="spin sm gs-kbd" aria-hidden /> : !q && !cat && <kbd className="gs-kbd" aria-hidden>/</kbd>}
      </div>
      {open && !showList && !term && (
        <div className="gs-list gs-tips" role="note"><b>Что можно найти</b>
          <span>Компьютер, программу, пользователя или CVE; раздел или настройку по смыслу: <i>исключения</i>, <i>владелец</i>, <i>лицензия</i>, <i>импорт BI</i>, <i>отчёт по уязвимостям</i>.</span>
          <span>Звёздочка <span className="mono">*</span> заменяет любые символы: <span className="mono">SRV-*</span>, <span className="mono">*SQL*</span></span></div>)}
      {showList && (
        <ul className="gs-list" id={listId} role="listbox" aria-label="Найдено">
          {groups.map((g) => <li key={g.title} role="presentation"><ul role="group" aria-label={g.title} className="gs-grp"><li className="gs-group" role="presentation">{g.title}</li>
            {g.hits.map((h) => { idx += 1; const i = idx; return (
              <li key={h.key} id={`${listId}-${i}`} role="option" aria-selected={i === active} className={`gs-opt ${i === active ? "on" : ""} ${h.key.endsWith("all") ? "gs-all" : ""}`} onMouseEnter={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); go(h); }}>
                <Icon name={h.icon} size={16} /><span className="gs-main"><b>{h.title}</b>{h.sub && <span className="gs-sub">{h.sub}</span>}</span></li>); })}</ul></li>)}
          {empty && <li className="gs-empty" role="presentation">{busy ? "Поиск…" : sourceId ? "Ничего не найдено. Попробуйте другое слово: название раздела, настройки или часть имени." : "Выберите источник KSC, чтобы искать компьютеры и программы; разделы и настройки ищутся и без него."}</li>}
        </ul>)}
    </div>
  );
}

export type { Role };
