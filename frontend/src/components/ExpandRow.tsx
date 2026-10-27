import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { maskSecrets } from "../util";
import { Icon } from "./Icons";

/** Общее раскрытие строк таблиц: стрелка в первой ячейке раскрывает технические подробности самой записи (pentest, EOL, уязвимости, ПО, защита).
 *  Число устройств в строке по-прежнему открывает правую боковую панель — это другой сценарий, они не конфликтуют. Раскрытие доступно с клавиатуры (Enter, Пробел), состояние читается скринридером
 *  (`aria-expanded`, `aria-controls`), анимация отключается при `prefers-reduced-motion`. Содержимое монтируется при открытии: данные подробностей можно загружать лениво. */
export function useExpanded<K extends string | number = string>() {
  const [open, setOpen] = useState<Set<K>>(() => new Set());
  const toggle = useCallback((k: K) => setOpen((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; }), []);
  const clear = useCallback(() => setOpen(new Set()), []);
  return { has: (k: K) => open.has(k), toggle, clear, count: open.size };
}

export function ExpandTh({ allOpen, onToggleAll }: { allOpen?: boolean; onToggleAll?: () => void }) {
  return <th className="xcell">{onToggleAll
    ? <button type="button" className="xbtn" aria-pressed={allOpen} aria-label={allOpen ? "Свернуть все строки" : "Развернуть все строки"} title={allOpen ? "Свернуть все" : "Развернуть все"} onClick={onToggleAll}><Icon name="chevronD" size={15} className={allOpen ? "xrot" : ""} /></button>
    : <span className="sr-only">Подробности</span>}</th>;
}

export function ExpandCell({ id, open, onToggle, label }: { id: string; open: boolean; onToggle: () => void; label: string }) {
  return (
    <td className="xcell">
      <button type="button" className={`xbtn ${open ? "on" : ""}`} aria-expanded={open} aria-controls={`x-${id}`} aria-label={`${open ? "Свернуть" : "Развернуть"} подробности: ${label}`} onClick={onToggle}>
        <Icon name="chevronR" size={15} />
      </button>
    </td>
  );
}

/** Строка подробностей под записью. Плавное раскрытие (высота через grid), содержимое монтируется при открытии и убирается после закрытия. */
export function ExpandedRow({ id, open, colSpan, children }: { id: string; open: boolean; colSpan: number; children: ReactNode }) {
  const [mounted, setMounted] = useState(open);
  const [on, setOn] = useState(false);
  const t = useRef<number>(0);
  useEffect(() => {
    window.clearTimeout(t.current);
    if (open) { setMounted(true); t.current = window.setTimeout(() => setOn(true), 16); } else { setOn(false); t.current = window.setTimeout(() => setMounted(false), 240); }
    return () => window.clearTimeout(t.current);
  }, [open]);
  if (!mounted) return null;
  return (
    <tr className="xrow" id={`x-${id}`}>
      <td colSpan={colSpan}><div className={`xwrap ${on ? "open" : ""}`}><div className="xin"><div className="xbody">{children}</div></div></div></td>
    </tr>
  );
}

/** Сетка «подпись — значение» для подробностей. */
export function XGrid({ children }: { children: ReactNode }) { return <dl className="xgrid">{children}</dl>; }
export function XItem({ label, children, wide }: { label: string; children: ReactNode; wide?: boolean }) {
  if (children === null || children === undefined || children === "" || children === false) return null;
  return <div className={wide ? "wide" : ""}><dt>{label}</dt><dd>{children}</dd></div>;
}

/** Технический текст: экранируется (React не вставляет HTML), вероятные секреты скрываются, длинный текст сворачивается. */
export function SafeText({ text, max = 1200, label }: { text: string; max?: number; label?: string }) {
  const [full, setFull] = useState(false);
  const masked = maskSecrets(text);
  if (!masked) return <span className="muted">—</span>;
  const cut = !full && masked.length > max;
  return (
    <div className="xsafe">
      <pre className="xpre" aria-label={label}>{cut ? masked.slice(0, max) + "…" : masked}</pre>
      {masked.length > max && <button type="button" className="link-btn small" onClick={() => setFull(!full)}>{full ? "Свернуть" : `Показать полностью (${masked.length.toLocaleString("ru-RU")} символов)`}</button>}
    </div>
  );
}

/** «Техническая детализация»: большие дампы скрыты по умолчанию. */
export function TechDetails({ title = "Техническая детализация", children }: { title?: string; children: ReactNode }) {
  return <details className="xtech"><summary>{title}</summary><div className="xtech-body">{children}</div></details>;
}
