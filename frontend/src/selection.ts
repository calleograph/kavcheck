import { useCallback, useSyncExternalStore } from "react";

/** Выбранные в каталоге программы: отдельные продукты и целые семейства (основной продукт и его компоненты).
 *  Хранятся по источнику в браузере — выбор не теряется при переходе между разделами и после перезагрузки страницы. */
export interface SelProduct { key: string; name: string; latest_version?: string }
export interface SelEntry extends SelProduct { family?: SelProduct[] }   // family — весь набор: основной продукт и компоненты

const KEY = (source: string) => `kc:sel:${source}`;
const listeners = new Set<() => void>();
const cache = new Map<string, SelEntry[]>();
const EMPTY: SelEntry[] = [];

function read(source: string): SelEntry[] {
  if (!source) return EMPTY;
  if (!cache.has(source)) {
    let v: SelEntry[] = [];
    try { v = JSON.parse(localStorage.getItem(KEY(source)) || "[]"); } catch { v = []; }
    cache.set(source, Array.isArray(v) ? v : []);
  }
  return cache.get(source)!;
}

function write(source: string, v: SelEntry[]) {
  cache.set(source, v);
  try { localStorage.setItem(KEY(source), JSON.stringify(v)); } catch { /* выбор живёт до перезагрузки */ }
  listeners.forEach((l) => l());
}

export function useSelection(source: string) {
  const items = useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => read(source));
  const set = useCallback((f: (cur: SelEntry[]) => SelEntry[]) => write(source, f(read(source))), [source]);
  return {
    items,
    /** выбран ли продукт: отдельно или в составе выбранного семейства */
    has: (key: string) => items.some((e) => e.key === key && !e.family) || items.some((e) => e.family?.some((m) => m.key === key)),
    hasFamily: (key: string) => items.some((e) => e.key === key && !!e.family),
    toggle: (p: SelProduct) => set((cur) => {
      const fam = cur.find((e) => e.family?.some((m) => m.key === p.key));
      if (fam) {      // снимаем один компонент с выбранного семейства: остальные остаются выбранными по отдельности
        return [...cur.filter((e) => e !== fam), ...fam.family!.filter((m) => m.key !== p.key && !cur.some((e) => e.key === m.key && !e.family))];
      }
      return cur.some((e) => e.key === p.key && !e.family) ? cur.filter((e) => !(e.key === p.key && !e.family)) : [...cur, p];
    }),
    toggleFamily: (root: SelProduct, members: SelProduct[]) => set((cur) => {
      if (cur.some((e) => e.key === root.key && e.family)) return cur.filter((e) => !(e.key === root.key && e.family));
      const keys = new Set(members.map((m) => m.key));
      return [...cur.filter((e) => !keys.has(e.key)), { ...root, family: members }];
    }),
    remove: (key: string) => set((cur) => cur.filter((e) => e.key !== key)),
    clear: () => set(() => []),
    count: items.reduce((a, e) => a + (e.family?.length ?? 1), 0),
  };
}

/** Короткая подпись выбора: «PHP и 5 компонентов, Google Chrome». */
export const selLabel = (e: SelEntry) => (e.family && e.family.length > 1 ? `${e.name} + ${e.family.length - 1} компонент.` : e.name);

/** Текущий выбор без подписки (для разового чтения при открытии конструктора). */
export const getSelection = (source: string): SelEntry[] => read(source);
