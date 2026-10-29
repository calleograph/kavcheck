import { THEMES, type ThemeId } from "../theme";

/** Карточки тем с предпросмотром (навигация, карточка, акцент) — личный выбор и тема системы по умолчанию. none — пункт «Как в системе». */
export function ThemePicker({ value, onChange, none, label }: { value: ThemeId | null; onChange: (id: ThemeId | null) => void; none?: string; label: string }) {
  return (
    <div className="theme-grid" role="radiogroup" aria-label={label}>
      {none && <button type="button" role="radio" aria-checked={value === null} className={`theme-card ${value === null ? "on" : ""}`} onClick={() => onChange(null)}>
        <span className="theme-prev theme-prev-auto" aria-hidden><span>Аа</span></span>
        <span className="theme-name">Как в системе</span><span className="theme-desc">{none}</span></button>}
      {THEMES.map((t) => (
        <button key={t.id} type="button" role="radio" aria-checked={value === t.id} className={`theme-card ${value === t.id ? "on" : ""}`} onClick={() => onChange(t.id)}>
          <span className="theme-prev" style={{ background: t.preview.bg }} aria-hidden>
            <span className="tp-side" style={{ background: t.preview.side }}><i style={{ background: t.preview.accent }} /><i /><i /></span>
            <span className="tp-main"><span className="tp-card" style={{ background: t.preview.card, color: t.preview.text }}><b>Аа</b><i style={{ background: t.preview.accent }} /></span>
              <span className="tp-row" style={{ background: t.preview.card }} /><span className="tp-row" style={{ background: t.preview.card }} /></span>
          </span>
          <span className="theme-name">{t.name}</span><span className="theme-desc">{t.desc}</span>
        </button>))}
    </div>
  );
}
