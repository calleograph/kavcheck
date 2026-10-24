import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icons";

/** Модальное окно: фокус внутрь и возврат, Escape и щелчок по фону закрывают, Tab не уходит за пределы окна; появление и закрытие анимированы. */
/** side — боковая панель справа на всю высоту (списки по щелчку на числе или версии); scrollRef — её прокручиваемая область. */
export function Modal({ title, onClose, children, wide, footer, side, scrollRef, lede }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean; footer?: ReactNode;
  side?: boolean; scrollRef?: RefObject<HTMLDivElement | null>; lede?: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [closing, setClosing] = useState(false);
  const close = useCallback(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { onClose(); return; }
    setClosing(true); window.setTimeout(onClose, 150);
  }, [onClose]);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("[autofocus], input, select, textarea, button:not(.modal-x)");
    (first ?? ref.current)?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.stopPropagation(); close(); return; }
      if (e.key !== "Tab" || !ref.current) return;
      const els = Array.from(ref.current.querySelectorAll<HTMLElement>("a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])"));
      if (!els.length) return;
      const a = els[0], b = els[els.length - 1];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); b.focus(); } else if (!e.shiftKey && document.activeElement === b) { e.preventDefault(); a.focus(); }
    };
    document.addEventListener("keydown", key);
    const ov = document.body.style.overflow; document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", key); document.body.style.overflow = ov; prev?.focus?.(); };
  }, [close]);
  // портал в body: окно не зависит от того, где объявлено (вложенные формы, карточки с overflow, стек z-index)
  return createPortal(
    <div className={`modal-back ${side ? "side" : ""} ${closing ? "closing" : ""}`} onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}>
      <div className={`modal ${wide ? "wide" : ""} ${side ? "side" : ""}`} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}
        ref={(el) => { ref.current = el; if (scrollRef) scrollRef.current = el; }}>
        <div className="modal-head"><div className="grow"><h2>{title}</h2>{lede && <div className="modal-lede">{lede}</div>}</div><button className="btn ghost icon modal-x" onClick={close} aria-label="Закрыть"><Icon name="close" /></button></div>
        <div className="modal-body">{children}{footer && <div className="modal-foot">{footer}</div>}</div>
      </div>
    </div>, document.body);
}

/** Подтверждение необратимого действия; `typed` — слово для ввода при самых опасных операциях. */
export function ConfirmDialog({ title, body, confirmLabel, typed, danger = true, onConfirm, onClose }: {
  title: string; body: ReactNode; confirmLabel: string; typed?: string; danger?: boolean; onConfirm: () => Promise<void> | void; onClose: () => void;
}) {
  const [word, setWord] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const go = async () => { setBusy(true); setErr(""); try { await onConfirm(); onClose(); } catch (e) { setErr((e as Error).message || "Не удалось выполнить действие"); setBusy(false); } };
  return (
    <Modal title={title} onClose={busy ? () => undefined : onClose}
      footer={<><button className="btn ghost" onClick={onClose} disabled={busy}>Отмена</button>
        <button className={`btn ${danger ? "danger" : "primary"}`} onClick={go} aria-busy={busy} disabled={typed !== undefined && word.trim().toLowerCase() !== typed.toLowerCase()}><span>{confirmLabel}</span></button></>}>
      <div className="muted">{body}</div>
      {typed && <label>Для подтверждения введите «{typed}»<input value={word} onChange={(e) => setWord(e.target.value)} autoFocus autoComplete="off" /></label>}
      {err && <div className="alert error" role="alert"><Icon name="alert" /><div className="alert-body">{err}</div></div>}
    </Modal>
  );
}
