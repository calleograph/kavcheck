import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { num, plural } from "../util";
import { Icon, type IconName } from "./Icons";

/** Заголовок сортируемого столбца: щелчок или Enter меняет порядок. */
export function SortTh({ k, label, sort, desc, onSort, className = "" }: { k: string; label: string; sort: string; desc: boolean; onSort: (k: string) => void; className?: string }) {
  const on = sort === k;
  return <th className={`sortable ${className}`} aria-sort={on ? (desc ? "descending" : "ascending") : undefined} onClick={() => onSort(k)} tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSort(k); } }}>
    {label}<Icon name={on ? (desc ? "chevronD" : "chevronU") : "sort"} size={13} className="sort-ic" /></th>;
}


/** Заголовок страницы: название, пояснение и действия справа. */
export function PageHead({ title, lede, children, back }: { title: ReactNode; lede?: ReactNode; children?: ReactNode; back?: ReactNode }) {
  return (
    <header className="page-head">
      <div>{back}<h1>{title}</h1>{lede && <p className="lede">{lede}</p>}</div>
      {children && <div className="page-actions">{children}</div>}
    </header>
  );
}

/** Пустое состояние: что здесь будет и что сделать. */
export function Empty({ icon = "info", title, children, action }: { icon?: IconName; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-ic"><Icon name={icon} size={20} /></div>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action && <div className="row">{action}</div>}
    </div>
  );
}

/** Скелет таблицы на время загрузки (повторяет форму строк). */
export function SkelRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div aria-busy="true" aria-label="Загрузка">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="skel-row">{Array.from({ length: cols }, (_, c) => <span key={c} className="skel" style={{ height: 12, flex: c === 0 ? 2 : 1, opacity: 1 - r * 0.1 }} />)}</div>
      ))}
    </div>
  );
}

/** Подложка, скользящая к активному элементу (сегменты и вкладки): измеряем позицию активной кнопки и двигаем transform. */
function useGlide(dep: unknown) {
  const box = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ x: number; w: number } | null>(null);
  useLayoutEffect(() => {
    const measure = () => {
      const el = box.current?.querySelector<HTMLElement>("[data-on='true']");
      setPos(el ? { x: el.offsetLeft, w: el.offsetWidth } : null);
      edges();
    };
    // не поместившиеся варианты: затухание у края, где они скрыты (полоса прокрутки у .seg спрятана); выбранный вариант — в видимой части
    const edges = () => {
      const b = box.current;
      if (!b) return;
      b.dataset.more = `${b.scrollLeft > 2 ? "l" : ""}${b.scrollLeft + b.clientWidth < b.scrollWidth - 2 ? "r" : ""}`;
    };
    measure();
    const on = box.current?.querySelector<HTMLElement>("[data-on='true']");
    if (box.current && on && on.offsetLeft + on.offsetWidth > box.current.scrollLeft + box.current.clientWidth) box.current.scrollLeft = on.offsetLeft + on.offsetWidth - box.current.clientWidth + 24;   // только по горизонтали: страницу не прокручивать
    const ro = new ResizeObserver(measure);
    if (box.current) { ro.observe(box.current); box.current.addEventListener("scroll", edges, { passive: true }); }
    const b = box.current;
    return () => { ro.disconnect(); b?.removeEventListener("scroll", edges); };
  }, [dep]);
  return { box, pos };
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: ([T, ReactNode] | [T, ReactNode, string])[]; onChange: (v: T) => void; label: string }) {
  const { box, pos } = useGlide(value);
  return (
    <div className="seg" role="radiogroup" aria-label={label} ref={box}>
      {pos && <span className="seg-pill" style={{ width: pos.w, transform: `translateX(${pos.x}px)` }} aria-hidden />}
      {options.map(([v, l, name]) => <button key={v} type="button" role="radio" aria-checked={v === value} aria-label={name} title={name} data-on={v === value} onClick={() => onChange(v)}>{l}</button>)}
    </div>
  );
}

export function Tabs<T extends string>({ value, items, onChange, label }: { value: T; items: { id: T; label: ReactNode; count?: number }[]; onChange: (v: T) => void; label: string }) {
  const { box, pos } = useGlide(value);
  const onKey = (e: React.KeyboardEvent) => {
    const i = items.findIndex((x) => x.id === value);
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      e.preventDefault();
      const n = items[(i + (e.key === "ArrowRight" ? 1 : -1) + items.length) % items.length];
      onChange(n.id);
      window.requestAnimationFrame(() => box.current?.querySelector<HTMLElement>("[data-on='true']")?.focus());
    }
  };
  return (
    <div className="tabs" role="tablist" aria-label={label} ref={box} onKeyDown={onKey}>
      {items.map((t) => <button key={t.id} className="tab" role="tab" aria-selected={t.id === value} tabIndex={t.id === value ? 0 : -1} data-on={t.id === value} onClick={() => onChange(t.id)}>
        {t.label}{t.count !== undefined && <span className="count">{num(t.count)}</span>}</button>)}
      {pos && <span className="tab-line" style={{ width: pos.w, transform: `translateX(${pos.x}px)` }} aria-hidden />}
    </div>
  );
}

export interface SpectrumSeg { key: string; label: string; value: number; note?: string; tone?: "ok" | "warn" | "muted"; undef?: boolean }

/** Фирменный «спектр версий»: доли сегментов по значению, наведение приглушает остальные (и сообщает наружу ключ для подсветки строк),
 *  щелчок выбирает сегмент, если передан onToggle. Сегменты вырастают слева направо один раз при появлении данных. */
export function Spectrum({ segs, selected, onToggle, onHover, hover, size, label, legend = true, unit = "" }: {
  segs: SpectrumSeg[]; selected?: Set<string>; onToggle?: (key: string) => void; onHover?: (key: string | null) => void; hover?: string | null;
  size?: "lg"; label: string; legend?: boolean; unit?: string;
}) {
  const [own, setOwn] = useState<string | null>(null);
  const hot = hover !== undefined ? hover : own;
  const setHot = (k: string | null) => { setOwn(k); onHover?.(k); };
  const total = segs.reduce((a, s) => a + s.value, 0) || 1;
  let ci = 0;
  const colored = segs.map((s) => ({ ...s, color: s.undef || s.tone ? undefined : `var(--sp-${Math.min(ci++, 7)})` }));
  const Tag = onToggle ? "button" : "span";
  return (
    <div className={`spectrum intro ${size ?? ""} ${hot ? "has-hover" : ""}`} role="group" aria-label={label}>
      <div className="spectrum-track" onMouseLeave={() => setHot(null)}>
        {colored.map((s, i) => (
          <Tag key={s.key} type={onToggle ? "button" : undefined} className={`sp-seg ${s.undef ? "undef" : ""} ${s.tone ? `tone-${s.tone}` : ""} ${hot === s.key ? "hot" : ""} ${selected?.has(s.key) ? "sel" : ""}`}
            style={{ flexGrow: s.value, flexBasis: 0, ["--seg" as string]: s.color, ["--i" as string]: i }}
            onMouseEnter={() => setHot(s.key)} onFocus={() => setHot(s.key)} onBlur={() => setHot(null)}
            onClick={onToggle ? () => onToggle(s.key) : undefined}
            aria-pressed={onToggle ? !!selected?.has(s.key) : undefined}
            aria-label={`${s.label}: ${num(s.value)}${unit}${s.note ? `, ${s.note}` : ""}`}>
            <span className="sp-tip">{s.label} · {Math.round((s.value / total) * 100)}%</span>
          </Tag>
        ))}
      </div>
      {legend && (
        <ul className="sp-legend">
          {colored.map((s) => (
            <li key={s.key} className={hot === s.key ? "hot" : ""} onMouseEnter={() => setHot(s.key)} onMouseLeave={() => setHot(null)}>
              <span className={`sw ${s.undef ? "undef" : ""}`} style={{ ["--seg" as string]: s.color ?? (s.tone === "ok" ? "var(--ok)" : s.tone === "warn" ? "var(--warn)" : s.tone ? "var(--line-strong)" : undefined) }} />
              <b>{s.label}</b><span className="n">{num(s.value)}{unit}{s.note ? ` · ${s.note}` : ""}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Плавающая панель действий над выбранными строками. */
export function Dock({ children, label }: { children: ReactNode; label: string }) {
  return <div className="dock" role="toolbar" aria-label={label}>{children}</div>;
}

/** Строка о скрытых устройствах: глобальный фильтр активности прячет давно не подключавшиеся к KSC компьютеры.
 *  hidden = null — число уникальных скрытых компьютеров неизвестно (например, в каталоге счётчики по каждой программе). */
export function HiddenNote({ hidden, days, all, onToggle }: { hidden: number | null; days: number | null | undefined; all: boolean; onToggle: () => void }) {
  if (!all && hidden === 0) return null;
  return (
    <p className="hidden-note">
      <Icon name={all ? "eye" : "eyeOff"} size={15} />
      {all ? <span>Показаны все компьютеры, включая не подключавшиеся к KSC дольше {days ?? "…"} сут.</span>
        : hidden === null ? <span>Компьютеры без связи с KSC дольше {days ?? "…"} сут не учитываются.</span>
        : <span>Скрыто {num(hidden)} {plural(hidden, "компьютер", "компьютера", "компьютеров")} без связи с KSC дольше {days ?? "…"} сут.</span>}
      <button type="button" className="link-btn" onClick={onToggle}>{all ? "Скрыть неактивные" : "Показать все"}</button>
    </p>
  );
}

/** Счётчики уязвимостей по уровням опасности: нули приглушены, чтобы взгляд цеплялся за опасное. */
export function SevCounts({ critical, high, warning, compact }: { critical: number; high: number; warning: number; compact?: boolean }) {
  const cell = (n: number, cls: string, title: string) => <span className={`sev ${cls} ${n ? "" : "zero"}`} title={`${title}: ${n}`}>{compact ? num(n) : <><b>{num(n)}</b> {title.toLowerCase()}</>}</span>;
  return <span className="sev-row">{cell(critical, "crit", "Критические")}{cell(high, "high", "Высокие")}{cell(warning, "warn", "Предупреждения")}</span>;
}

/** Ввод списка значений (версии, ветки): Enter или запятая добавляют, Backspace в пустом поле убирает последнее. */
export function TagInput({ value, onChange, placeholder, label, mono = true }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string; label: string; mono?: boolean }) {
  const [text, setText] = useState("");
  const add = (raw: string) => { const parts = raw.split(/[,;\s]+/).map((x) => x.trim()).filter(Boolean); if (parts.length) onChange([...value, ...parts.filter((p) => !value.includes(p))]); setText(""); };
  return (
    <div className="tag-input" onClick={(e) => (e.currentTarget.querySelector("input") as HTMLInputElement | null)?.focus()}>
      {value.map((v) => <span key={v} className={`tag ${mono ? "mono" : ""}`}>{v}<button type="button" aria-label={`Убрать ${v}`} onClick={() => onChange(value.filter((x) => x !== v))}><Icon name="close" size={12} /></button></span>)}
      <input value={text} aria-label={label} placeholder={value.length ? "" : placeholder} onChange={(e) => { const t = e.target.value; if (/[,;]/.test(t)) add(t); else setText(t); }}
        onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(text); } else if (e.key === "Backspace" && !text && value.length) onChange(value.slice(0, -1)); }}
        onBlur={() => text && add(text)} />
    </div>
  );
}


const MASK_EXAMPLES: [string, string][] = [["SRV-*", "начинается с SRV-"], ["*-DB", "заканчивается на -DB"], ["*SQL*", "содержит SQL"], ["SRV-*-DB*", "несколько звёздочек"], ["CVE-2026-*", "все CVE за 2026 год"]];
/** Подсказка про поиск со звёздочкой: кнопка в поле поиска и короткая справка с примерами (Esc или щелчок снаружи закрывает). */
export function MaskHint() {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); (box.current?.querySelector("button") as HTMLElement | null)?.focus(); } };
    document.addEventListener("mousedown", away); document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return (
    <span className="mask-hint" ref={box}>
      <button type="button" className="mask-btn" aria-expanded={open} aria-label="Подсказка: поиск со звёздочкой" title="Поиск со звёздочкой: SRV-*, *-DB, *SQL*" onClick={() => setOpen(!open)}>*</button>
      {open && <div className="mask-pop" role="note">
        <p><b>*</b> заменяет любое число символов, в том числе ни одного. Регистр не важен.</p>
        <dl>{MASK_EXAMPLES.map(([m, t]) => <div key={m}><dt className="mono">{m}</dt><dd>{t}</dd></div>)}</dl>
        <p className="muted small">Без звёздочки ищется часть строки. Работает во всех полях поиска и фильтрах.</p>
      </div>}
    </span>
  );
}

/** «Назад» в карточке: к месту, откуда пришли (главная, панель, поиск — с фильтрами и открытой панелью); открытая по внешней ссылке карточка ведёт к списку раздела. */
export function BackLink({ to, label }: { to: string; label: string }) {
  const nav = useNavigate();
  const inApp = useLocation().key !== "default";
  return <Link className="back-link" to={to} title={inApp ? "Вернуться туда, откуда открыта карточка" : undefined}
    onClick={(e) => { if (inApp && e.button === 0 && !e.ctrlKey && !e.metaKey && !e.shiftKey) { e.preventDefault(); nav(-1); } }}><Icon name="arrowL" size={15} />{inApp ? "Назад" : label}</Link>;
}

/** Выбор нескольких значений метками-флажками (вместо select multiple: выбор без Ctrl, видны все варианты, удобно пальцем). */
export function MultiCheck({ label, options, value, onChange }: { label: string; options: { id: string; name: string }[]; value: string[]; onChange: (v: string[]) => void }) {
  const all = options.length > 1 && options.every((o) => value.includes(o.id));
  return (
    <fieldset className="mchk"><legend>{label}</legend>
      <div className="mchk-list">
        {options.length > 1 && <button type="button" className="link-btn small" onClick={() => onChange(all ? [] : options.map((o) => o.id))}>{all ? "снять все" : "все"}</button>}
        {options.map((o) => <label key={o.id} className={`mchk-i ${value.includes(o.id) ? "on" : ""}`}>
          <input type="checkbox" checked={value.includes(o.id)} onChange={(e) => onChange(e.target.checked ? [...value, o.id] : value.filter((x) => x !== o.id))} />{o.name}</label>)}
      </div>
    </fieldset>
  );
}

const reduceMotion = () => typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/** «Наверх»: появляется после глубокой прокрутки (страница или своя прокрутка панели — target), плавно возвращает в начало (без анимации при «уменьшить движение»);
 *  затем несколько секунд предлагает вернуться к прежнему месту. Не перекрывает панель выбора внизу; Home в списке работает как обычно. */
export function ToTop({ target, after = 900 }: { target?: RefObject<HTMLElement | null>; after?: number }) {
  const [y, setY] = useState(0);
  const [back, setBack] = useState<number | null>(null);
  useEffect(() => {
    const el: HTMLElement | Window = target?.current ?? window;
    const get = () => (target?.current ? target.current.scrollTop : window.scrollY);
    let raf = 0;
    const on = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => setY(get())); };
    el.addEventListener("scroll", on, { passive: true });
    on();
    return () => { el.removeEventListener("scroll", on); cancelAnimationFrame(raf); };
  }, [target]);
  useEffect(() => { if (back == null) return; const t = window.setTimeout(() => setBack(null), 8000); return () => window.clearTimeout(t); }, [back]);
  // «К прежнему месту» исчезает, если пользователь сам ушёл вниз — но не пока идёт плавная прокрутка наверх
  const arrived = useRef(false);
  useEffect(() => { if (back == null) arrived.current = false; else if (y < after) arrived.current = true; else if (arrived.current) setBack(null); }, [y, back, after]);
  const go = (top: number) => (target?.current ?? window).scrollTo({ top, behavior: reduceMotion() ? "auto" : "smooth" });
  if (y < after && back == null) return null;
  return (
    <div className={`to-top ${target ? "in-box" : ""}`}>
      {y >= after ? <button type="button" className="to-top-btn" aria-label="Наверх, к началу списка" title="Наверх" onClick={() => { setBack(y); go(0); }}><Icon name="chevronU" size={18} /></button>
        : back != null && <button type="button" className="to-top-back" onClick={() => { go(back); setBack(null); }}><Icon name="chevronD" size={15} />К прежнему месту</button>}
    </div>
  );
}
