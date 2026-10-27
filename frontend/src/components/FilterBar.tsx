import { useId, useState, type ReactNode } from "react";
import { num, plural } from "../util";
import { Icon } from "./Icons";
import { MaskHint } from "./ui";

export interface FilterChip { id: string; label: ReactNode; onRemove: () => void }

/** Кнопка «Сформировать отчёт»: одинаковая подпись и место во всех разделах (правый край панели фильтров или заголовка страницы). */
export function ReportButton({ onClick, disabled, title, count }: { onClick: () => void; disabled?: boolean; title?: string; count?: number }) {
  return (
    <button type="button" className="btn primary mini report-btn" onClick={onClick} disabled={disabled} title={title ?? "Открыть конструктор отчёта с текущими фильтрами страницы"}>
      <Icon name="file" size={15} />Сформировать отчёт{count ? <span className="report-btn-n">{num(count)}</span> : null}
    </button>
  );
}

/** Единая панель фильтрации: поиск и основные фильтры в одной строке, остальное — в «Все фильтры», активные условия — компактными чипами,
 *  справа — число найденных записей и предсказуемый набор кнопок (Сбросить, Обновить, Сформировать отчёт). На узком экране строка перестраивается, без горизонтальной прокрутки. */
export function FilterBar({ search, primary, more, moreActive = 0, chips = [], onReset, count, onRefresh, refreshing, report, extra }: {
  search?: { value: string; onChange: (v: string) => void; placeholder: string; label?: string; mask?: boolean };
  primary?: ReactNode;                                   // основные фильтры: выпадающие списки, переключатели
  more?: ReactNode;                                      // «Все фильтры»: дополнительные поля
  moreActive?: number;                                   // сколько условий внутри «Все фильтры» включено (число на кнопке)
  chips?: FilterChip[];                                  // применённые условия: у каждого свой крестик
  onReset?: () => void;
  count?: { n: number | null; noun: [string, string, string]; hint?: ReactNode };
  onRefresh?: () => void; refreshing?: boolean;
  report?: { onClick: () => void; disabled?: boolean; title?: string; count?: number } | null;
  extra?: ReactNode;                                     // дополнительные действия справа (например, «Пересчитать»)
}) {
  const [open, setOpen] = useState(false);
  const panel = useId();
  return (
    <div className="fbar" role="search">
      <div className="fbar-main">
        {search && (
          <div className="input-icon fbar-search"><Icon name="search" size={16} />
            <input value={search.value} onChange={(e) => search.onChange(e.target.value)} placeholder={search.placeholder} aria-label={search.label ?? "Поиск"} />
            {search.mask !== false && <MaskHint />}
          </div>)}
        {primary}
        {more && (
          <button type="button" className={`btn ghost mini fbar-more ${open ? "on" : ""}`} aria-expanded={open} aria-controls={panel} onClick={() => setOpen(!open)}>
            <Icon name="sliders" size={15} />Все фильтры{moreActive > 0 && <span className="fbar-badge" aria-label={`включено условий: ${moreActive}`}>{moreActive}</span>}
          </button>)}
        <div className="fbar-actions">
          {count && <span className="fbar-count" role="status" aria-live="polite">{count.n === null ? "…" : <><b>{num(count.n)}</b> <span className="muted">{plural(count.n, ...count.noun)}</span></>}{count.hint}</span>}
          {onReset && chips.length > 0 && <button type="button" className="btn ghost mini" onClick={onReset}>Сбросить</button>}
          {onRefresh && <button type="button" className="btn ghost mini icon" onClick={onRefresh} disabled={refreshing} aria-label="Обновить" title="Обновить данные">{refreshing ? <span className="spin" /> : <Icon name="refresh" size={15} />}</button>}
          {extra}
          {report && <ReportButton {...report} />}
        </div>
      </div>
      {more && open && <div id={panel} className="fbar-panel">{more}</div>}
      {chips.length > 0 && (
        <ul className="fbar-chips" aria-label="Применённые фильтры">
          {chips.map((c) => <li key={c.id}><span className="fchip">{c.label}<button type="button" onClick={c.onRemove} aria-label={`Убрать фильтр: ${typeof c.label === "string" ? c.label : c.id}`}><Icon name="close" size={12} /></button></span></li>)}
        </ul>)}
    </div>
  );
}

/** Число, которое раскрывается в боковую панель: подчёркнутая кнопка с понятной подсказкой. Нулевые значения — обычный текст, без обещания действия. */
export function CountButton({ n, onClick, label, muted }: { n: number; onClick: () => void; label: string; muted?: boolean }) {
  if (!n) return <span className="muted">0</span>;
  return <button type="button" className={`count-btn ${muted ? "muted" : ""}`} onClick={(e) => { e.stopPropagation(); onClick(); }} title={label} aria-label={`${num(n)}: ${label}`}>{num(n)}</button>;
}
