import type { ReactNode, SVGProps } from "react";

/** Собственный набор линейных пиктограмм: сетка 24×24, штрих 1.75, скругления, цвет — currentColor. Без внешних библиотек. */
const PATHS: Record<string, ReactNode> = {
  home: <><path d="M4 10.8 12 4l8 6.8V19a1 1 0 0 1-1 1h-4.5v-5.5h-5V20H5a1 1 0 0 1-1-1Z" /></>,
  layers: <><path d="m12 4 8.5 4.3L12 12.6 3.5 8.3Z" /><path d="m3.5 12.2 8.5 4.3 8.5-4.3M3.5 16.1 12 20.4l8.5-4.3" /></>,
  monitor: <><rect x="3" y="4.5" width="18" height="12" rx="2" /><path d="M8.5 20h7M12 16.5V20" /></>,
  bug: <><path d="M8.5 9.5a3.5 3.5 0 0 1 7 0v4.5a3.5 3.5 0 0 1-7 0Z" /><path d="M12 13v4.5M4.5 12h4M15.5 12h4M5.5 17.5l3-1.5M18.5 17.5l-3-1.5M6 6.5l2.6 2M18 6.5l-2.6 2M10 6V4.5M14 6V4.5" /></>,
  shieldPulse: <><path d="M12 3.5 19 6v5.4c0 4.4-2.9 7.6-7 9.1-4.1-1.5-7-4.7-7-9.1V6Z" /><path d="M8 12.5h2l1-2.5 2 5 1-2.5h2" /></>,
  bell: <><path d="M6.2 15.5V11a5.8 5.8 0 0 1 11.6 0v4.5l1.5 2H4.7Z" /><path d="M10 20a2.2 2.2 0 0 0 4 0" /></>,
  file: <><path d="M14 3.5H7.5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V8Z" /><path d="M14 3.5V8h4.5M9 12.5h6M9 16h4" /></>,
  sliders: <><path d="M4 7h10M18 7h2M4 17h4M12 17h8" /><circle cx="16" cy="7" r="2" /><circle cx="10" cy="17" r="2" /></>,
  gauge: <><path d="M4.5 16a7.5 7.5 0 1 1 15 0" /><path d="m12 16 3.5-4.5" /><circle cx="12" cy="16" r="1.2" /></>,
  database: <><ellipse cx="12" cy="5.8" rx="7" ry="2.6" /><path d="M5 5.8v12.4c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V5.8" /><path d="M5 12c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6" /></>,
  users: <><circle cx="9" cy="8.5" r="3.2" /><path d="M3 19.5c.4-3.3 2.8-5.2 6-5.2s5.6 1.9 6 5.2" /><path d="M15.8 5.6a3.1 3.1 0 0 1 0 5.8M18 14.6c1.8.6 2.8 2.2 3 4.9" /></>,
  key: <><circle cx="8" cy="14.5" r="3.8" /><path d="m10.8 11.8 8.2-8.2M15.5 7.1l2.6 2.6M13.3 9.3l2 2" /></>,
  branch: <><circle cx="6.5" cy="6" r="2" /><circle cx="6.5" cy="18" r="2" /><circle cx="17.5" cy="8" r="2" /><path d="M6.5 8v8M17.5 10c0 3.5-3 4.3-6 4.8-2 .3-3.8 1-4.6 2.2" /></>,
  upload: <><path d="M12 15.5V4.5M7.5 9 12 4.5 16.5 9M5 19.5h14" /></>,
  journal: <><path d="M6 3.5h10.5a2 2 0 0 1 2 2v15H8a2 2 0 0 1-2-2Z" /><path d="M6 18.5a2 2 0 0 1 2-2h10.5M10 8h5M10 11h3.5" /></>,
  history: <><path d="M4.5 12a7.5 7.5 0 1 0 2.2-5.3L4.5 9" /><path d="M4.5 4.5V9H9M12 8v4.3l3 1.8" /></>,
  search: <><circle cx="10.8" cy="10.8" r="6" /><path d="m15.3 15.3 4.7 4.7" /></>,
  download: <><path d="M12 4.5v11M7.5 11 12 15.5 16.5 11M5 19.5h14" /></>,
  refresh: <><path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3l2.2 2.3" /><path d="M19.5 4.5V9H15" /></>,
  plus: <><path d="M12 5v14M5 12h14" /></>,
  close: <><path d="M6.5 6.5l11 11M17.5 6.5l-11 11" /></>,
  check: <><path d="m5 12.5 4.5 4.5L19 7.5" /></>,
  alert: <><path d="M12 4.2 21 19.5H3Z" /><path d="M12 10v4M12 17v.2" /></>,
  info: <><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5M12 7.8v.2" /></>,
  checkCircle: <><circle cx="12" cy="12" r="8.5" /><path d="m8.3 12.3 2.6 2.6 4.8-5.2" /></>,
  xCircle: <><circle cx="12" cy="12" r="8.5" /><path d="m9.2 9.2 5.6 5.6M14.8 9.2l-5.6 5.6" /></>,
  clock: <><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></>,
  chevronD: <><path d="m6.5 9.5 5.5 5.5 5.5-5.5" /></>,
  chevronU: <><path d="m6.5 14.5 5.5-5.5 5.5 5.5" /></>,
  chevronL: <><path d="m14.5 6.5-5.5 5.5 5.5 5.5" /></>,
  chevronR: <><path d="m9.5 6.5 5.5 5.5-5.5 5.5" /></>,
  chevronsL: <><path d="m12.5 6.5-5.5 5.5 5.5 5.5M18 6.5 12.5 12l5.5 5.5" /></>,
  arrowL: <><path d="M19 12H5M10.5 6.5 5 12l5.5 5.5" /></>,
  arrowR: <><path d="M5 12h14M13.5 6.5 19 12l-5.5 5.5" /></>,
  sort: <><path d="m8 9.5 4-4 4 4M8 14.5l4 4 4-4" /></>,
  eye: <><path d="M2.8 12S6.2 5.8 12 5.8 21.2 12 21.2 12 17.8 18.2 12 18.2 2.8 12 2.8 12Z" /><circle cx="12" cy="12" r="2.7" /></>,
  eyeOff: <><path d="M9.6 6.1c.8-.2 1.5-.3 2.4-.3 5.8 0 9.2 6.2 9.2 6.2s-.9 1.6-2.5 3.2M6.4 7.8C4 9.4 2.8 12 2.8 12S6.2 18.2 12 18.2c1.4 0 2.7-.4 3.8-.9" /><path d="M10.1 10.2a2.7 2.7 0 0 0 3.7 3.7M4 4l16 16" /></>,
  edit: <><path d="M14.5 5.5 18.5 9.5M4.5 19.5l1-4.5L15.8 4.7a1.5 1.5 0 0 1 2.1 0l1.4 1.4a1.5 1.5 0 0 1 0 2.1L9 18.5Z" /></>,
  trash: <><path d="M4.5 7h15M10 4h4M6.5 7l.8 12a1.6 1.6 0 0 0 1.6 1.5h6.2a1.6 1.6 0 0 0 1.6-1.5l.8-12M10 11v5.5M14 11v5.5" /></>,
  plug: <><path d="M9 3.5v4M15 3.5v4M6.5 7.5h11v3.5a5.5 5.5 0 0 1-11 0ZM12 16.5v4" /></>,
  server: <><rect x="3.5" y="4" width="17" height="7" rx="1.8" /><rect x="3.5" y="13" width="17" height="7" rx="1.8" /><path d="M7 7.5h.2M7 16.5h.2M11 7.5h6M11 16.5h6" /></>,
  logout: <><path d="M14 4.5h3.5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H14M10 16.5 5.5 12 10 7.5M5.5 12H15" /></>,
  sun: <><circle cx="12" cy="12" r="3.8" /><path d="M12 3v1.8M12 19.2V21M3 12h1.8M19.2 12H21M5.6 5.6l1.3 1.3M17.1 17.1l1.3 1.3M5.6 18.4l1.3-1.3M17.1 6.9l1.3-1.3" /></>,
  moon: <><path d="M19.5 14.6A7.6 7.6 0 0 1 9.4 4.5a7.6 7.6 0 1 0 10.1 10.1Z" /></>,
  system: <><rect x="3.5" y="4.5" width="17" height="11.5" rx="2" /><path d="M8.5 19.5h7" /></>,
  play: <><path d="M8 5.5v13l10-6.5Z" /></>,
  stop: <><rect x="6.5" y="6.5" width="11" height="11" rx="2" /></>,
  copy: <><rect x="8.5" y="8.5" width="11" height="11" rx="2" /><path d="M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" /></>,
  save: <><path d="M5 4.5h11l3 3V18a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 18Z" /><path d="M8.5 4.5V9h6V4.5M8.5 19.5V14h7v5.5" /></>,
  target: <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r=".9" /></>,
  menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
  external: <><path d="M14 4.5h5.5V10M19.5 4.5 11 13M17 14v4a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 5 18V8.5A1.5 1.5 0 0 1 6.5 7h4" /></>,
  filter: <><path d="M4 5.5h16l-6 7.2v5.8l-4 1.5v-7.3Z" /></>,
  activity: <><path d="M3.5 12h3.5l2.5-6 4 12 2.5-6h4.5" /></>,
  package: <><path d="M12 3.5 19.5 7.7v8.6L12 20.5l-7.5-4.2V7.7Z" /><path d="M4.5 7.7 12 12l7.5-4.3M12 12v8.5M8.2 5.6l7.5 4.3" /></>,
};
export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18, ...rest }: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, "name">) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden focusable="false" {...rest}>{PATHS[name]}</svg>;
}

/** Знак KAV Checker: три полосы разной длины — «спектр версий», фирменный мотив продукта. */
export function Mark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden focusable="false">
      <rect width="32" height="32" rx="8" fill="var(--chrome-3, #242e3a)" />
      <rect x="7" y="8.5" width="18" height="3.4" rx="1.7" fill="#6ccbe6" />
      <rect x="7" y="14.3" width="12.5" height="3.4" rx="1.7" fill="#3fa9c8" />
      <rect x="7" y="20.1" width="7" height="3.4" rx="1.7" fill="#c0e1e9" />
    </svg>
  );
}
