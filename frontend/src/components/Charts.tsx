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

export interface TrendPoint { day: string; active: number; total: number }

/** График динамики: активные компьютеры (площадь) на фоне общего числа объектов (пунктир). Данные накапливаются по суткам, пока их мало — честная подпись вместо «линии из двух точек». */
export function Trend({ points, since, label }: { points: TrendPoint[]; since: string | null; label: string }) {
  if (points.length < 2) {
    return <p className="trend-empty">{points.length ? "Накоплен один срез." : "Срезов пока нет."} График строится по ежедневным срезам: он появится, когда их будет не меньше двух{since ? ` (первый — ${new Date(since).toLocaleDateString("ru-RU")})` : ""}.</p>;
  }
  const W = 320, H = 110, PX = 4, PY = 10;
  const maxV = Math.max(...points.map((p) => Math.max(p.total, p.active)), 1);
  const minV = Math.min(...points.map((p) => p.active));
  const lo = Math.max(0, minV - (maxV - minV) * 0.15 - 1);
  const x = (i: number) => PX + (i / (points.length - 1)) * (W - 2 * PX);
  const y = (v: number) => H - PY - ((v - lo) / Math.max(maxV - lo, 1)) * (H - 2 * PY);
  const line = (k: "active" | "total") => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p[k]).toFixed(1)}`).join(" ");
  const last = points[points.length - 1], first = points[0];
  const d = (iso: string) => new Date(iso).toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} preserveAspectRatio="none" className="trend-svg">
        <path d={`${line("active")} L${x(points.length - 1).toFixed(1)} ${H - PY} L${x(0).toFixed(1)} ${H - PY} Z`} className="trend-area" />
        <path d={line("total")} className="trend-total" vectorEffect="non-scaling-stroke" />
        <path d={line("active")} className="trend-line" vectorEffect="non-scaling-stroke" />
        <circle cx={x(points.length - 1)} cy={y(last.active)} r="3" className="trend-dot" vectorEffect="non-scaling-stroke" />
      </svg>
      <figcaption className="trend-cap"><span>{d(first.day)}: <b>{num(first.active)}</b></span><span>{d(last.day)}: <b>{num(last.active)}</b> из {num(last.total)}</span></figcaption>
      <table className="sr-only"><caption>{label}</caption><thead><tr><th>Дата</th><th>Активные</th><th>Всего</th></tr></thead><tbody>{points.map((p) => <tr key={p.day}><td>{p.day}</td><td>{p.active}</td><td>{p.total}</td></tr>)}</tbody></table>
    </figure>
  );
}
