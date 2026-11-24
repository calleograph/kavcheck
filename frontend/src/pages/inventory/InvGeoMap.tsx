import { useEffect, useRef, useState } from "react";
import { num } from "../../util";

export interface GeoGroup {
  country: string; region: string; city: string; site_id: number | null; site?: string; status: string;
  n: number; fresh_n: number; lat: number | null; lon: number | null; radius_km: number | null;
}
type Ring = [number, number][];
type Land = Ring[][];
const W = 1000, H = 500;

export const groupName = (g: GeoGroup) => g.site || [g.country, g.region, g.city].filter(Boolean).join(" / ");
const x = (lon: number) => (lon + 180) * W / 360;
const y = (lat: number) => (90 - lat) * H / 180;

export default function InvGeoMap({ groups, select }: { groups: GeoGroup[]; select: (g: GeoGroup) => void }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [land, setLand] = useState<Land>([]);
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/geo-land.json", { signal: controller.signal }).then((r) => {
      if (!r.ok) throw new Error("map");
      return r.json() as Promise<Land>;
    }).then(setLand).catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, []);
  const pins = groups.filter((g) => g.lat != null && g.lon != null);
  useEffect(() => {
    const el = canvas.current;
    const ctx = el?.getContext("2d");
    if (!ctx || !el) return;
    const draw = () => {
      const css = getComputedStyle(el);
      const token = (name: string) => css.getPropertyValue(name).trim();
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = token("--surface-2");
      ctx.strokeStyle = token("--line");
      ctx.lineWidth = 1.5;
      for (const polygon of land) {
        ctx.beginPath();
        for (const ring of polygon) {
          ring.forEach(([lon, lat], i) => i ? ctx.lineTo(x(lon), y(lat)) : ctx.moveTo(x(lon), y(lat)));
          ctx.closePath();
        }
        ctx.fill("evenodd");
        ctx.stroke();
      }
      ctx.strokeStyle = token("--accent");
      ctx.fillStyle = token("--accent");
      for (const group of groups) {
        if (group.lat == null || group.lon == null || !group.radius_km) continue;
        const kmPerDegree = 111.2;
        const dx = Math.min(W, group.radius_km / kmPerDegree / Math.max(.1, Math.cos(group.lat * Math.PI / 180)) * W / 360);
        const dy = Math.min(H, group.radius_km / kmPerDegree * H / 180);
        for (const wrap of [-W, 0, W]) {
          ctx.beginPath();
          ctx.ellipse(x(group.lon) + wrap, y(group.lat), dx, dy, 0, 0, 2 * Math.PI);
          ctx.globalAlpha = .15;
          ctx.fill();
          ctx.globalAlpha = .55;
          ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;
    };
    draw();
    const theme = new MutationObserver(draw);
    theme.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => theme.disconnect();
  }, [groups, land]);
  return <>
    <div className="inv-geo-map">
      <canvas ref={canvas} width={W} height={H} aria-hidden="true" />
      {pins.map((g, i) => <button type="button" key={i} className={`inv-geo-pin ${g.status === "approx" ? "approx" : ""} ${g.fresh_n ? "" : "old"}`}
        style={{ left: `${x(g.lon!) / W * 100}%`, top: `${y(g.lat!) / H * 100}%` }}
        title={`${groupName(g)} · ${num(g.n)}${g.radius_km ? ` · до ${g.radius_km} км` : ""}`}
        aria-label={`Оборудование · ${groupName(g)} · ${num(g.n)}`} onClick={() => select(g)}>{num(g.n)}</button>)}
    </div>
    {error && <p className="muted small">Подложка карты недоступна. Географические группы доступны в списке.</p>}
    {!pins.length && !error && <p className="muted small">В этой выборке пока нет наблюдений с координатами.</p>}
  </>;
}
