import type { ReactNode, SVGProps } from "react";

/** Линейные пиктограммы (24×24, штрих 1.8, currentColor). Без внешних библиотек. */
const PATHS: Record<string, ReactNode> = {
  home: <><path d="M4 11.5 12 4.5l8 7" /><path d="M6.5 10v9h11v-9" /><path d="M10 19v-5h4v5" /></>,
  box: <><path d="M12 3 20 7.5v9L12 21l-8-4.5v-9Z" /><path d="M12 12 20 7.5M12 12 4 7.5M12 12v9" /></>,
  monitor: <><rect x="3" y="4.5" width="18" height="12" rx="2.2" /><path d="M8 20.5h8M12 16.5v4" /></>,
  bug: <><path d="M8 9a4 4 0 0 1 8 0v5a4 4 0 0 1-8 0Z" /><path d="M12 14v4M4 11h4M16 11h4M5 17l3-2M19 17l-3-2M6 5l2.5 2.5M18 5l-2.5 2.5" /></>,
  shield: <><path d="M12 3.4 19.4 6v5.6c0 4.5-3 7.5-7.4 9-4.4-1.5-7.4-4.5-7.4-9V6Z" /><path d="m8.8 12.2 2.2 2.2 4.2-4.6" /></>,
  bell: <><path d="M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15Z" /><path d="M10 20a2 2 0 0 0 4 0" /></>,
  file: <><path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8Z" /><path d="M14 3v5h5M8.5 13h7M8.5 16.5h5" /></>,
  gear: <><circle cx="12" cy="12" r="3.1" /><path d="M19.4 14.5a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3h0a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9v0a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" /></>,
  users: <><circle cx="9" cy="8.5" r="3.2" /><path d="M2.8 19.6c.4-3.4 3-5.3 6.2-5.3s5.8 1.9 6.2 5.3" /><path d="M16 5.6a3.1 3.1 0 0 1 0 5.8M18.2 14.6c1.8.6 3 2.2 3.2 5" /></>,
  db: <><ellipse cx="12" cy="5.5" rx="7.5" ry="2.8" /><path d="M4.5 5.5v13c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8v-13" /><path d="M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8" /></>,
  search: <><circle cx="10.8" cy="10.8" r="6" /><path d="m15.4 15.4 5 5" /></>,
  download: <><path d="M12 4v11M7.5 10.8 12 15.3l4.5-4.5M5 19.5h14" /></>,
  refresh: <><path d="M20 12a8 8 0 1 1-2.6-5.9" /><path d="M20 4.5v4.3h-4.3" /></>,
  chevronD: <><path d="m6 9.5 6 6 6-6" /></>,
  chevronR: <><path d="m9.5 6 6 6-6 6" /></>,
  arrowR: <><path d="M5 12h14M13.5 6.5 19 12l-5.5 5.5" /></>,
  eye: <><path d="M2.6 12S6 5.6 12 5.6 21.4 12 21.4 12 18 18.4 12 18.4 2.6 12 2.6 12Z" /><circle cx="12" cy="12" r="2.8" /></>,
  eyeOff: <><path d="M9.4 6.1c.8-.3 1.6-.5 2.6-.5 6 0 9.4 6.4 9.4 6.4s-.9 1.7-2.6 3.3M6.3 7.8C3.9 9.4 2.6 12 2.6 12S6 18.4 12 18.4c1.5 0 2.8-.4 3.9-.9" /><path d="M10 10.2a2.8 2.8 0 0 0 3.8 3.8M3.5 3.5l17 17" /></>,
  key: <><circle cx="8" cy="14" r="4" /><path d="m11 11 9-9M16 6l3 3M13.5 8.5l3 3" /></>,
  journal: <><path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3Z" /><path d="M5 17a3 3 0 0 1 3-3h11M9 8h6M9 11h4" /></>,
  activity: <><path d="M3 12h4l2.5-6 4 12 2.5-6H21" /></>,
  up: <><path d="M12 19V5M6 11l6-6 6 6" /></>,
  close: <><path d="M6 6l12 12M18 6 6 18" /></>,
  logo: <><path d="M12 3.4 19.4 6v5.6c0 4.5-3 7.5-7.4 9-4.4-1.5-7.4-4.5-7.4-9V6Z" fill="var(--accent)" stroke="var(--accent)" /><path d="m8.8 12.2 2.2 2.2 4.2-4.6" stroke="#fff" strokeWidth="2.2" /></>,
};
export type IconName = keyof typeof PATHS;
export function Icon({ name, size = 20, ...rest }: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, "name">) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden focusable="false" {...rest}>{PATHS[name]}</svg>;
}
