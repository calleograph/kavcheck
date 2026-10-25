import type { ReactNode } from "react";
import { num } from "../util";

/** Сегмент диаграммы: tone задаёт цвет через CSS-класс tone-<tone>, value — число компьютеров (или записей). */
export interface Seg { key: string; label: string; value: number; tone: string; hint?: string }

const R = 46, C = 2 * Math.PI * R;

/** Кольцевая диаграмма с подписями: щелчок по дуге или строке легенды выбирает сегмент (повторный щелчок снимает). Доступна с клавиатуры, цифры дублируются в легенде. */
export function Donut({ segs, selected, onSelect, center, label }: { segs: Seg[]; selected?: string; onSelect?: (key: string) => void; center: { value: ReactNode; label: string }; label: string }) {
  const total = segs.reduce((a, s) => a + s.value, 0);
  let off = 0;
  return (
    <div className="donut">
      <svg viewBox="0 0 120 120" role="img" aria-label={label} className="donut-svg">
        <circle cx="60" cy="60" r={R} className="donut-track" />
        {total > 0 && segs.filter((s) => s.value > 0).map((s) => {
          const len = (s.value / total) * C; const o = off; off += len;
          const on = selected === s.key;
          return <circle key={s.key} cx="60" cy="60" r={R} className={`donut-seg tone-${s.tone} ${on ? "on" : ""} ${selected && !on ? "dim" : ""}`} strokeDasharray={`${Math.max(len - 1, 0.5)} ${C - Math.max(len - 1, 0.5)}`} strokeDashoffset={-o}
            transform="rotate(-90 60 60)" tabIndex={onSelect ? 0 : undefined} role={onSelect ? "button" : undefined} aria-pressed={onSelect ? on : undefined} aria-label={`${s.label}: ${s.value}`}
            onClick={() => onSelect?.(s.key)} onKeyDown={(e) => { if (onSelect && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onSelect(s.key); } }}><title>{`${s.label}: ${num(s.value)}`}</title></circle>;
        })}
        <text x="60" y="58" textAnchor="middle" className="donut-v">{center.value}</text>
        <text x="60" y="73" textAnchor="middle" className="donut-l">{center.label}</text>
      </svg>
      <ul className="legend" aria-label={label}>
        {segs.map((s) => (
          <li key={s.key}>
            <button type="button" className={`legend-row ${selected === s.key ? "on" : ""} ${s.value === 0 ? "zero" : ""}`} aria-pressed={selected === s.key} disabled={!onSelect || s.value === 0} onClick={() => onSelect?.(s.key)} title={s.hint}>
              <i className={`sw tone-${s.tone}`} aria-hidden /><span className="lg-t">{s.label}</span><b className="num">{num(s.value)}</b><span className="lg-p">{total ? `${Math.round((s.value / total) * 100)}%` : ""}</span>
            </button>
          </li>))}
      </ul>
    </div>
  );
}

/** Горизонтальные столбцы: ширина — доля от наибольшего значения; строки выбираются щелчком. */
export function HBars({ rows, selected, onSelect, label, unit = "" }: { rows: Seg[]; selected?: string; onSelect?: (key: string) => void; label: string; unit?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="hbars" aria-label={label}>
      {rows.map((r) => (
        <li key={r.key}>
          <button type="button" className={`hbar ${selected === r.key ? "on" : ""} ${r.value === 0 ? "zero" : ""}`} aria-pressed={selected === r.key} disabled={!onSelect || r.value === 0} onClick={() => onSelect?.(r.key)} title={r.hint}>
            <span className="hb-l">{r.label}</span>
            <span className="hb-track" aria-hidden><i className={`tone-${r.tone}`} style={{ width: `${r.value ? Math.max(3, (r.value / max) * 100) : 0}%` }} /></span>
            <b className="num hb-v">{num(r.value)}{unit}</b>
          </button>
        </li>))}
    </ul>
  );
}
