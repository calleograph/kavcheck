/** Схема «Иерархия. Предприятие» как файл: SVG или PNG ровно в том виде, как на экране (раскрытые ветки, выбранный человек). Стили элементов переносятся в сам файл,
 *  поэтому картинка выглядит одинаково в любой программе и в любой теме оформления; кнопки раскрытия в файл не попадают. */
const PROPS = ["fill", "stroke", "stroke-width", "stroke-dasharray", "opacity", "font-family", "font-size", "font-weight", "text-anchor"];
const HEAD = 34;
const MAX_SIDE = 16000;
const MAX_AREA = 120_000_000;

function inline(src: Element, dst: Element) {
  const cs = getComputedStyle(src);
  for (const p of PROPS) { const v = cs.getPropertyValue(p); if (v) (dst as SVGElement).style.setProperty(p, v); }
  for (let i = 0; i < src.children.length; i++) inline(src.children[i], dst.children[i]);
}

const NS = "http://www.w3.org/2000/svg";

export function graphSvg(svg: SVGSVGElement, title: string, bg: string): { text: string; w: number; h: number } {
  const vb = svg.viewBox.baseVal;
  const w = Math.max(320, Math.round(vb.width)), h = Math.round(vb.height) + HEAD;
  const copy = svg.cloneNode(true) as SVGSVGElement;
  inline(svg, copy);
  copy.querySelectorAll(".tg").forEach((e) => e.remove());
  copy.querySelectorAll("[data-id],[tabindex],[role]").forEach((e) => { e.removeAttribute("data-id"); e.removeAttribute("tabindex"); e.removeAttribute("role"); });
  for (const a of ["class", "role", "aria-label", "style", "width", "height", "viewBox"]) copy.removeAttribute(a);
  const body = document.createElementNS(NS, "g");
  body.setAttribute("transform", `translate(0,${HEAD})`);
  while (copy.firstChild) body.appendChild(copy.firstChild);
  const back = document.createElementNS(NS, "rect");
  for (const [k, v] of Object.entries({ width: w, height: h, fill: bg })) back.setAttribute(k, String(v));
  const head = document.createElementNS(NS, "text");
  for (const [k, v] of Object.entries({ x: 14, y: 22, "font-family": "sans-serif", "font-size": 14, "font-weight": 700, fill: getComputedStyle(svg).color || "#222" })) head.setAttribute(k, String(v));
  head.textContent = title;
  copy.append(back, head, body);
  for (const [k, v] of Object.entries({ xmlns: NS, width: w, height: h, viewBox: `0 0 ${w} ${h}` })) copy.setAttribute(k, String(v));
  return { text: `<?xml version="1.0" encoding="UTF-8"?>\n${new XMLSerializer().serializeToString(copy)}`, w, h };
}

function save(blob: Blob, name: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove();
  window.setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

/** Возвращает текст ошибки или пустую строку. */
export async function downloadGraph(svg: SVGSVGElement, fmt: "svg" | "png", name: string, title: string): Promise<string> {
  const bg = getComputedStyle(svg.closest(".card") ?? document.body).backgroundColor || "#fff";
  const { text, w, h } = graphSvg(svg, title, bg === "rgba(0, 0, 0, 0)" ? "#fff" : bg);
  if (fmt === "svg") { save(new Blob([text], { type: "image/svg+xml" }), `${name}.svg`); return ""; }
  const scale = Math.min(2, MAX_SIDE / Math.max(w, h), Math.sqrt(MAX_AREA / (w * h)));
  if (scale < 0.25) return "Схема слишком велика для PNG: выгрузите SVG или сверните ветки.";
  const img = new Image();
  const url = URL.createObjectURL(new Blob([text], { type: "image/svg+xml" }));
  try {
    img.src = url; await img.decode();
    const c = document.createElement("canvas"); c.width = Math.round(w * scale); c.height = Math.round(h * scale);
    const g = c.getContext("2d"); if (!g) return "Браузер не дал создать изображение.";
    g.drawImage(img, 0, 0, c.width, c.height);
    const blob: Blob | null = await new Promise((r) => c.toBlob(r, "image/png"));
    if (!blob) return "Не удалось создать PNG: выгрузите SVG.";
    save(blob, `${name}.png`); return "";
  } catch { return "Не удалось создать PNG: выгрузите SVG."; } finally { URL.revokeObjectURL(url); }
}
