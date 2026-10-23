export const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" }) : "—");
export const fmtDate = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString("ru-RU") : "—");
export const fmtTs = (ts: number | null | undefined) => (ts ? new Date(ts * 1000).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" }) : "—");
export const num = (n: number | null | undefined) => (n === null || n === undefined ? "—" : n.toLocaleString("ru-RU"));
export const bytes = (n: number | null | undefined) => { if (n == null) return "—"; const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"]; let i = 0, v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return `${v.toFixed(i ? 1 : 0)} ${u[i]}`; };
export const ago = (sec: number | null | undefined) => (sec == null ? "—" : sec < 90 ? `${sec} с назад` : sec < 5400 ? `${Math.round(sec / 60)} мин назад` : `${Math.round(sec / 3600)} ч назад`);
export const plural = (n: number, one: string, few: string, many: string) => { const m10 = n % 10, m100 = n % 100; return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? few : many; };
export const versionLabel = (v: string, commit: string) => (commit && commit !== "unknown" ? `${v} · ${commit.slice(0, 7)}` : v);
