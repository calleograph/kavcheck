import { cloneElement, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactElement, type RefObject } from "react";
import { useVirtualizer, useWindowVirtualizer, type VirtualItem } from "@tanstack/react-virtual";
import { useLocation } from "react-router-dom";
import type { ApiError } from "../api";
import { num } from "../util";

/** Порция с сервера: строки, общее число и любые дополнительные поля ответа (сводка, время получения…). */
export type Chunk<T> = { items: T[]; total: number } & Record<string, unknown>;

interface Saved { deps: string; items: unknown[]; total: number; extra: Record<string, unknown> | null; scrollY: number; measures?: unknown }
// состояние списков на время сеанса: при возврате из карточки — те же строки, фильтры и место прокрутки, без повторной загрузки
const memory = new Map<string, Saved>();
const sizes = new Map<string, VirtualItem[]>();
const boxScroll = new Map<string, number>();       // прокрутка списков в боковой панели   // измеренные высоты строк списка — чтобы после возврата видны были те же строки

export interface Infinite<T> {
  items: T[]; total: number; extra: Record<string, unknown> | null; loading: boolean; error: string; done: boolean;
  /** перезагрузка с начала (новые фильтры): старые строки ещё видны, над таблицей — полоса загрузки */
  refreshing: boolean;
  /** первая порция ещё не пришла */
  initial: boolean;
  loadMore: () => void; reload: () => void;
  /** для восстановления положения прокрутки и размеров строк */
  key: string; restoreY: number | null;
}

/** Бесконечный список с сервера: фильтры и сортировка — на сервере (deps), порции по pageSize, устаревшие ответы отбрасываются. */
export function useInfinite<T>(key: string, deps: unknown[], fetchPage: (offset: number, limit: number) => Promise<Chunk<T>>, pageSize = 100): Infinite<T> {
  const depsKey = JSON.stringify(deps);
  const saved = memory.get(key);
  const hit = saved && saved.deps === depsKey ? saved : null;
  const [items, setItems] = useState<T[]>(() => (hit?.items as T[]) ?? []);
  const [total, setTotal] = useState(hit?.total ?? 0);
  const [extra, setExtra] = useState<Record<string, unknown> | null>(hit?.extra ?? null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [initial, setInitial] = useState(!hit);
  const restoreY = useRef<number | null>(hit ? hit.scrollY : null);
  const req = useRef(0);
  const state = useRef({ items, total, loading });
  state.current = { items, total, loading };
  const fetcher = useRef(fetchPage);
  fetcher.current = fetchPage;
  const extraRef = useRef(extra);
  extraRef.current = extra;

  const load = useCallback((offset: number, reset: boolean) => {
    const id = ++req.current;
    setLoading(true); setError(""); if (reset) setRefreshing(true);
    fetcher.current(offset, pageSize).then((r) => {
      if (id !== req.current) return;
      const { items: got, total: t, ...rest } = r;
      setItems((cur) => (reset ? got : [...cur, ...got])); setTotal(t); setExtra(rest); setInitial(false);
    }).catch((e) => { if (id === req.current) { setError((e as ApiError).message); setInitial(false); } })
      .finally(() => { if (id === req.current) { setLoading(false); setRefreshing(false); } });
  }, [pageSize]);

  // для каких фильтров строки уже есть: при возврате к списку — из памяти; повторный вызов эффекта (StrictMode) не перезагружает
  const loadedFor = useRef<string | null>(hit ? depsKey : null);
  useEffect(() => {
    if (loadedFor.current === depsKey) return;
    loadedFor.current = depsKey;
    restoreY.current = null;
    setInitial(true);
    load(0, true);
  }, [depsKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // место прокрутки — по событиям прокрутки: к моменту ухода со страницы браузер уже укоротил документ под новую страницу
  const lastY = useRef(window.scrollY);
  const onPage = useRef(true);
  useLayoutEffect(() => { onPage.current = true; return () => { onPage.current = false; }; }, []);   // снимается синхронно при смене страницы
  useEffect(() => {
    const on = () => { if (onPage.current) lastY.current = window.scrollY; };
    window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);
  useEffect(() => () => {                                               // уходим со страницы: запоминаем строки и место прокрутки
    memory.set(key, { deps: depsKey, items: state.current.items, total: state.current.total, extra: extraRef.current, scrollY: lastY.current });
  }, [key, depsKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadMore = useCallback(() => {
    const s = state.current;
    if (!s.loading && s.items.length < s.total) load(s.items.length, false);
  }, [load]);
  const reload = useCallback(() => { restoreY.current = null; load(0, true); }, [load]);
  return { items, total, extra, loading, refreshing, error, done: !initial && items.length >= total, initial, loadMore, reload, key, restoreY: restoreY.current };
}

/** Строки таблицы с виртуализацией: в DOM только видимые строки; при подходе к концу — следующая порция.
 *  scrollEl — контейнер со своей прокруткой (боковая панель, окно); без него — прокрутка страницы. */
export function VirtualRows<T>({ list, colSpan, row, estimate = 44, scrollEl, group }: {
  list: Infinite<T>; colSpan: number; row: (item: T, index: number) => ReactElement; estimate?: number; scrollEl?: RefObject<HTMLElement | null>;
  /** каждая запись — свой `<tbody>` (строка записи и раскрывающаяся строка подробностей измеряются вместе); таблица не должна иметь внешнего `<tbody>` */
  group?: boolean;
}) {
  const anchor = useRef<HTMLTableRowElement>(null);
  const [margin, setMargin] = useState(0);
  const Pad = ({ h, a }: { h: number; a?: boolean }) => (group ? <tbody aria-hidden><tr ref={a ? anchor : undefined} className="v-pad"><td colSpan={colSpan} style={{ height: Math.max(0, h) }} /></tr></tbody>
    : <tr ref={a ? anchor : undefined} className="v-pad" aria-hidden><td colSpan={colSpan} style={{ height: Math.max(0, h) }} /></tr>);
  useLayoutEffect(() => {
    const el = anchor.current;
    if (!el) return;
    const measure = () => {
      const top = el.getBoundingClientRect().top;
      setMargin(scrollEl?.current ? top - scrollEl.current.getBoundingClientRect().top + scrollEl.current.scrollTop : top + window.scrollY);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(document.body);
    return () => ro.disconnect();
  }, [scrollEl]);
  const snapshot = useRef(list.restoreY != null ? sizes.get(list.key) : undefined).current;
  const opts = { count: list.items.length, estimateSize: () => estimate, overscan: 12, scrollMargin: margin, initialMeasurementsCache: snapshot };
  // хуки вызываются всегда в одном порядке: оба виртуализатора, используется нужный
  const win = useWindowVirtualizer({ ...opts, enabled: !scrollEl });
  const box = useVirtualizer({ ...opts, getScrollElement: () => scrollEl?.current ?? null, enabled: !!scrollEl });
  const v = scrollEl ? box : win;
  const vRef = useRef(v);
  vRef.current = v;
  useEffect(() => () => { sizes.set(list.key, vRef.current.takeSnapshot()); }, [list.key]);
  useEffect(() => {
    const el = scrollEl?.current;
    if (!el) return;
    const on = () => { boxScroll.set(list.key, el.scrollTop); };
    el.addEventListener("scroll", on, { passive: true });
    return () => el.removeEventListener("scroll", on);
  }, [scrollEl, list.key]);
  const vis: VirtualItem[] = v.getVirtualItems();
  const last = vis.length ? vis[vis.length - 1].index : -1;
  useEffect(() => { if (last >= list.items.length - 25) list.loadMore(); }, [last, list.items.length]); // eslint-disable-line react-hooks/exhaustive-deps
  // возврат к списку: та же позиция прокрутки (один раз, после первой отрисовки строк)
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current || list.restoreY == null || !list.items.length) return;
    restored.current = true;
    const el = scrollEl?.current;
    // мгновенно: плавную прокрутку (scroll-behavior: smooth у html) обрывают поправки виртуализатора после измерения строк
    window.requestAnimationFrame(() => { if (el) el.scrollTop = boxScroll.get(list.key) ?? 0; else window.scrollTo({ top: list.restoreY ?? 0, behavior: "instant" }); });
  }, [list.items.length, list.restoreY, scrollEl]); // eslint-disable-line react-hooks/exhaustive-deps
  const top = vis.length ? vis[0].start - margin : 0;
  const bottom = vis.length ? v.getTotalSize() - (vis[vis.length - 1].end - margin) : 0;
  return (
    <>
      {Pad({ h: top, a: true })}
      {group ? vis.map((vi) => <tbody key={vi.key} ref={v.measureElement} data-index={vi.index}>{row(list.items[vi.index], vi.index)}</tbody>)
        : vis.map((vi) => cloneElement(row(list.items[vi.index], vi.index) as ReactElement<{ ref?: unknown; "data-index"?: number }>, { key: vi.key, ref: v.measureElement, "data-index": vi.index }))}
      {Pad({ h: bottom })}
    </>
  );
}

/** Под списком: сколько показано из скольких, подгрузка, ошибка. Вместо постраничной навигации. */
export function ListFoot<T>({ list, scrollEl }: { list: Infinite<T>; scrollEl?: RefObject<HTMLElement | null> }) {
  if (list.initial && !list.error) return null;
  return (
    <div className="list-foot" role="status">
      {list.error ? <><span className="bad-text">{list.error}</span><button type="button" className="link-btn" onClick={list.loadMore}>Повторить</button></>
        : list.loading && list.items.length ? <><span className="spin sm" aria-hidden />Загрузка… {num(list.items.length)} из {num(list.total)}</>
          : list.total ? <>{list.done ? `Всего: ${num(list.total)}` : `Показано ${num(list.items.length)} из ${num(list.total)}`}
            {list.items.length > 60 && <button type="button" className="link-btn" onClick={() => (scrollEl?.current ?? window).scrollTo({ top: 0, behavior: "smooth" })}>Наверх</button>}</> : null}
    </div>
  );
}

const kept = new Map<string, unknown>();
/** useState, значение которого живёт весь сеанс: фильтры и сортировка списка сохраняются при уходе в карточку и возврате. */
export function useKept<T>(key: string, initial: T): [T, (v: T | ((p: T) => T)) => void] {
  const [v, setV] = useState<T>(() => (kept.has(key) ? (kept.get(key) as T) : initial));
  const set = useCallback((x: T | ((p: T) => T)) => setV((p) => {
    const n = typeof x === "function" ? (x as (p: T) => T)(p) : x;
    kept.set(key, n);
    return n;
  }), [key]);
  return [v, set];
}

/** Открытая боковая панель привязана к записи истории: «Назад» из карточки возвращает к ней, а переход из меню открывает страницу без панели. */
export function usePanel<T>(name: string): [T | null, (v: T | null) => void] {
  return useKept<T | null>(`panel:${name}:${useLocation().key}`, null);
}

/** Уже загруженный массив в том же интерфейсе, что и бесконечный список: для виртуализации строк, пришедших одним ответом. */
export const staticList = <T,>(key: string, items: T[]): Infinite<T> => ({ items, total: items.length, extra: null, loading: false, refreshing: false, error: "", done: true,
  initial: false, loadMore: () => undefined, reload: () => undefined, key, restoreY: null });

export function useStaticList<T>(key: string, items: T[]): Infinite<T> {
  return useMemo(() => staticList(key, items), [key, items]);
}
