/* Темы оформления (перенесены из ArkLock). Выбор хранится в профиле пользователя на сервере (следует за ним на другие устройства) и дублируется в localStorage,
   чтобы страница входа и первая отрисовка сразу получали нужные цвета (public/theme-boot.js). Пока пользователь не выбрал тему, действует тема системы — её задаёт администратор. */
import { api, type Me } from "./api";

export type ThemeId = "night" | "glass" | "grove" | "aurora";
export const DEFAULT_THEME: ThemeId = "night";

export const THEMES: { id: ThemeId; name: string; desc: string; preview: { bg: string; card: string; accent: string; text: string; side: string } }[] = [
  { id: "night", name: "Тёмный профессиональный", desc: "Тёмно-синяя основа и фиолетовые акценты для работы вечером", preview: { bg: "#0e1024", card: "#232650", accent: "#9d8ff7", text: "#e9ebfb", side: "#141633" } },
  { id: "glass", name: "Современный и лёгкий", desc: "Светлое голубое стекло, мягкие синие акценты и волны на фоне", preview: { bg: "#e9f1fc", card: "#ffffff", accent: "#2563c9", text: "#142a49", side: "#f6f9ff" } },
  { id: "grove", name: "Корпоративный минимализм", desc: "Нейтральная основа, зелёные акценты, строгие панели и лёгкий лес", preview: { bg: "#f4f6f3", card: "#ffffff", accent: "#1f7a46", text: "#1f2a1f", side: "#ffffff" } },
  { id: "aurora", name: "Современный градиентный", desc: "Глубокий синий фон, бирюзовые акценты и градиентные волны", preview: { bg: "#061326", card: "#0f2a4d", accent: "#2dd4ee", text: "#e1f4fb", side: "#0a1d38" } },
];

const KEY = "kc:theme";
const DEF_KEY = "kc:theme-default";
const LEGACY: Record<string, ThemeId> = { light: "glass", dark: "night" };
export const isTheme = (v: unknown): v is ThemeId => THEMES.some((t) => t.id === v);
const store = (k: string, v: string | null) => { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { /* без хранилища — до закрытия вкладки */ } };
const read = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };

export function applyTheme(id: ThemeId): void {
  document.documentElement.setAttribute("data-theme", id);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEMES.find((t) => t.id === id)!.preview.bg);
}

/** Тема системы, известная до входа (страница входа): применяется, если в браузере нет личного выбора. */
export function rememberDefault(def: string): void {
  if (!isTheme(def)) return;
  store(DEF_KEY, def);
  const mine = read(KEY);
  if (!isTheme(mine) && !LEGACY[mine ?? ""]) applyTheme(def);
}

/** После входа: личный выбор из профиля; прежний выбор этого браузера («светлая»/«тёмная») один раз переносится в профиль; иначе — тема системы. */
export function syncTheme(me: Me): void {
  rememberDefault(me.default_theme);
  let mine = isTheme(me.theme) ? me.theme : null;
  const local = read(KEY);
  if (!mine && local && LEGACY[local]) {
    mine = LEGACY[local];
    void api.setTheme(mine).catch(() => undefined);
  }
  store(KEY, mine);
  applyTheme(mine ?? (isTheme(me.default_theme) ? me.default_theme : DEFAULT_THEME));
}

/** Выбор пользователя: применяется сразу, сохраняется в профиле; null — вернуться к теме системы. */
export async function chooseTheme(id: ThemeId | null, def: string): Promise<void> {
  store(KEY, id);
  applyTheme(id ?? (isTheme(def) ? def : DEFAULT_THEME));
  await api.setTheme(id);
}
