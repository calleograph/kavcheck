/** Последняя работа: открытые разделы и карточки запоминаются в браузере отдельно для каждого пользователя (не больше восьми, без повторов). */
import { FUNCTIONS } from "./navModel";

export interface Recent { to: string; label: string; at: number }
const key = (uid: string) => `kc:recent:${uid}`;

export function readRecent(uid: string): Recent[] {
  try { const v = JSON.parse(localStorage.getItem(key(uid)) ?? "[]"); return Array.isArray(v) ? v.filter((x) => x && typeof x.to === "string" && typeof x.label === "string").slice(0, 8) : []; } catch { return []; }
}

/** Название по адресу: разделы — из указателя функций, карточки — по шаблону маршрута. */
export function labelFor(pathname: string, search: string): string | null {
  const tab = new URLSearchParams(search).get("tab");
  const full = tab ? `${pathname}?tab=${tab}` : pathname;
  const hit = FUNCTIONS.find((f) => f.to === full) ?? FUNCTIONS.find((f) => f.to === pathname);
  if (hit) return hit.title;
  if (/^\/hosts\/\d+/.test(pathname)) return "Карточка компьютера";
  if (/^\/vulnerabilities\/hosts\//.test(pathname)) return "Уязвимости компьютера";
  if (pathname.startsWith("/software/p/")) return decodeURIComponent(pathname.slice(12)).split("|")[0] || "Карточка программы";
  if (pathname.startsWith("/zones/")) return "Карточка зоны";
  if (pathname.startsWith("/reports/")) return "Готовый отчёт";
  return null;
}

export function pushRecent(uid: string, pathname: string, search: string, label?: string) {
  if (pathname === "/") return;
  const text = label ?? labelFor(pathname, search);
  if (!text) return;
  const tab = new URLSearchParams(search).get("tab");
  const to = tab ? `${pathname}?tab=${tab}` : pathname;
  try {
    const list = readRecent(uid).filter((r) => r.to !== to);
    localStorage.setItem(key(uid), JSON.stringify([{ to, label: text, at: Date.now() }, ...list].slice(0, 8)));
  } catch { /* не запомнится */ }
}
