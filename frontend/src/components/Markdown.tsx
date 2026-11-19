import { Fragment, type ReactNode } from "react";

/** Markdown заметок к выпуску (CHANGELOG): заголовки, маркированные и нумерованные списки (с вложенностью), абзацы, блоки кода, **жирный**, `код`, [ссылки](https://…).
 *  Только React-элементы, без вставки HTML: текст из внешнего источника (GitHub) не может внедрить разметку; ссылки — лишь http(s). */
export function Markdown({ text, className = "md" }: { text: string; className?: string }) {
  return <div className={className}>{blocks(text.replace(/\r\n?/g, "\n"))}</div>;
}

const LINK = /^https?:\/\//i;

function inline(s: string, key = ""): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[([^\]]+)\]\(([^)\s]+)\))|(\[([^\]]+)\])/g;
  let last = 0; let m: RegExpExecArray | null; let i = 0;
  while ((m = re.exec(s))) {
    if (m.index > last) out.push(s.slice(last, m.index));
    const k = `${key}.${i++}`;
    if (m[1]) out.push(<code key={k}>{m[1].slice(1, -1)}</code>);
    else if (m[2]) out.push(<strong key={k}>{inline(m[2].slice(2, -2), k)}</strong>);
    else if (m[3]) out.push(LINK.test(m[5]) ? <a key={k} href={m[5]} target="_blank" rel="noopener noreferrer">{inline(m[4], k)}</a> : <Fragment key={k}>{inline(m[4], k)}</Fragment>);
    else out.push(<Fragment key={k}>{m[7]}</Fragment>);                       // «[0.34.0]» без адреса — просто текст
    last = re.lastIndex;
  }
  if (last < s.length) out.push(s.slice(last));
  return out;
}

type Item = { text: string; kids: string[] };

function list(lines: string[], ordered: boolean, key: string): ReactNode {
  const items: Item[] = [];
  const base = lines[0].match(/^\s*/)![0].length;
  for (const l of lines) {
    const ind = l.match(/^\s*/)![0].length;
    const marker = /^\s*([-*+]|\d+[.)])\s+/.exec(l);
    if (marker && ind <= base + 1) items.push({ text: l.slice(marker[0].length), kids: [] });
    else if (items.length) {
      if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) items[items.length - 1].kids.push(l);
      else items[items.length - 1].text += " " + l.trim();
    }
  }
  const Tag = ordered ? "ol" : "ul";
  return <Tag key={key}>{items.map((it, j) => <li key={j}>{inline(it.text, `${key}.${j}`)}{it.kids.length > 0 && list(it.kids, /^\s*\d/.test(it.kids[0]), `${key}.${j}.k`)}</li>)}</Tag>;
}

function blocks(src: string): ReactNode[] {
  const lines = src.split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    const key = `b${i}`;
    if (!l.trim()) { i++; continue; }
    if (/^```/.test(l)) {
      const body: string[] = [];
      for (i++; i < lines.length && !/^```/.test(lines[i]); i++) body.push(lines[i]);
      i++;
      out.push(<pre key={key}><code>{body.join("\n")}</code></pre>);
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(l);
    if (h) {
      const lvl = Math.min(6, h[1].length + 2) as 3 | 4 | 5 | 6;           // внутри страницы: «##» — подзаголовок, а не заголовок страницы
      const H = `h${lvl}` as const;
      out.push(<H key={key}>{inline(h[2].replace(/\s*#+\s*$/, ""), key)}</H>);
      i++;
      continue;
    }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) {
      const chunk: string[] = [];
      while (i < lines.length && lines[i].trim() && (/^\s*([-*+]|\d+[.)])\s+/.test(lines[i]) || /^\s+\S/.test(lines[i]))) chunk.push(lines[i++]);
      out.push(list(chunk, /^\s*\d/.test(chunk[0]), key));
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,6}\s|```|\s*([-*+]|\d+[.)])\s+)/.test(lines[i])) para.push(lines[i++].trim());
    out.push(<p key={key}>{inline(para.join(" "), key)}</p>);
  }
  return out;
}
