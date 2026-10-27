export const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" }) : "—");
export const fmtDate = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleDateString("ru-RU") : "—");
export const fmtTime = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) : "—");
export const fmtTs = (ts: number | null | undefined) => (ts ? new Date(ts * 1000).toLocaleString("ru-RU", { dateStyle: "short", timeStyle: "short" }) : "—");
export const num = (n: number | null | undefined) => (n === null || n === undefined ? "—" : n.toLocaleString("ru-RU"));
export const bytes = (n: number | null | undefined) => { if (n == null) return "—"; const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"]; let i = 0, v = n; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } return `${v.toFixed(i ? 1 : 0).replace(".", ",")} ${u[i]}`; };
export const ago = (sec: number | null | undefined) => (sec == null ? "—" : sec < 90 ? `${sec} с назад` : sec < 5400 ? `${Math.round(sec / 60)} мин назад` : sec < 172800 ? `${Math.round(sec / 3600)} ч назад` : `${Math.round(sec / 86400)} сут назад`);
export const plural = (n: number, one: string, few: string, many: string) => { const m10 = n % 10, m100 = n % 100; return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? few : many; };
export const versionLabel = (v: string, commit: string) => (commit && commit !== "unknown" ? `${v} (${commit.slice(0, 7)})` : v);

/** Скрывает вероятные секреты в техническом тексте перед показом (ответы сервисов, баннеры, вывод скриптов): пароли, токены, ключи API, заголовки авторизации, пароль в адресе. Исходный текст в базе не меняется. */
export function maskSecrets(text: string): string {
  return (text || "")
    .replace(/(authorization\s*:\s*)(basic|bearer|digest|negotiate)\s+\S+/gi, "$1$2 ••••")
    .replace(/((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|cookie|set-cookie)["']?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;,&]+)/gi, "$1••••")
    .replace(/(\/\/[^\s/:@]+:)[^\s/@]+(@)/g, "$1••••$2")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "-----BEGIN PRIVATE KEY----- •••• -----END PRIVATE KEY-----");
}
