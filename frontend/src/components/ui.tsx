import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
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
    };
    measure();
    const ro = new ResizeObserver(measure);
    if (box.current) ro.observe(box.current);
    return () => ro.disconnect();
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
