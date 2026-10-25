/** Поиск со звёздочкой, как на сервере (backend/app/search.py): `*` — любое число символов, включая ноль. Без звёздочки — часть строки. Регистр не важен.
 *  Используется только для фильтров по уже загруженным данным; поиск по базам выполняет сервер. */
export function maskMatcher(text: string): ((...values: (string | number | null | undefined)[]) => boolean) | null {
  const t = text.trim().replace(/\*+/g, "*").toLowerCase();
  if (!t || t === "*") return null;
  if (!t.includes("*")) return (...v) => v.some((x) => x != null && String(x).toLowerCase().includes(t));
  const rx = new RegExp("^" + t.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "s");
  return (...v) => v.some((x) => x != null && rx.test(String(x).toLowerCase()));
}
