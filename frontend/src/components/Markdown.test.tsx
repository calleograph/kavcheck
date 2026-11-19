import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Markdown } from "./Markdown";

const NOTES = `## [0.34.0] — 2026-11-19

Аудит домена: проверка учётных записей.

- **Раздел «Аудит домена»** — вкладки.
- Скрипт \`scripts/windows/Export.ps1\` и [документация](https://example.local/doc).
  - вложенный пункт
- <img src=x onerror=alert(1)> и [плохая ссылка](javascript:alert(1))`;

describe("Markdown заметок к выпуску", () => {
  const html = renderToStaticMarkup(<Markdown text={NOTES} />);
  it("строит заголовок, абзац, список с вложенностью, жирный, код и ссылку", () => {
    expect(html).toContain("<h4>0.34.0 — 2026-11-19</h4>");
    expect(html).toContain("<p>Аудит домена: проверка учётных записей.</p>");
    expect(html).toContain("<strong>Раздел «Аудит домена»</strong>");
    expect(html).toContain("<code>scripts/windows/Export.ps1</code>");
    expect(html).toContain('<a href="https://example.local/doc" target="_blank" rel="noopener noreferrer">документация</a>');
    expect(html).toMatch(/<li>[^<]*<code>.*<ul><li>вложенный пункт<\/li><\/ul><\/li>/);
    expect(html).not.toContain("**");
  });
  it("не вставляет разметку и не создаёт ссылок не http(s)", () => {
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    expect(html).not.toContain("javascript:");
  });
});
