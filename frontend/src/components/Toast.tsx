import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Icon } from "./Icons";

/** Короткое подтверждение справа внизу: выезжает с плавным замедлением, уходит само с растворением, читается скринридерами. */
export function useToast(ms = 2800): [ReactNode, (text: string, tone?: "ok" | "error") => void] {
  const [t, setT] = useState<{ text: string; tone: "ok" | "error"; n: number; out?: boolean } | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const outTimer = useRef<number | undefined>(undefined);
  const show = useCallback((text: string, tone: "ok" | "error" = "ok") => {
    window.clearTimeout(timer.current); window.clearTimeout(outTimer.current);
    setT((cur) => ({ text, tone, n: (cur?.n ?? 0) + 1 }));
    outTimer.current = window.setTimeout(() => setT((cur) => (cur ? { ...cur, out: true } : cur)), ms - 180);
    timer.current = window.setTimeout(() => setT(null), ms);
  }, [ms]);
  useEffect(() => () => { window.clearTimeout(timer.current); window.clearTimeout(outTimer.current); }, []);
  // ключ сохраняет уведомление, когда страница переключается между ветками (загрузка → содержимое)
  return [<div key="toast-host" className="toast-host" role="status" aria-live="polite">{t && <div key={t.n} className={`toast ${t.tone} ${t.out ? "out" : ""}`}><Icon name={t.tone === "ok" ? "checkCircle" : "alert"} />{t.text}</div>}</div>, show];
}
