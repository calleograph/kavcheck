"""Темы оформления интерфейса (frontend/src/styles.css): ровно четыре, «Тёмный профессиональный» по умолчанию (CSS, <html data-theme>, скрипт до первой отрисовки),
контраст основных пар токенов по WCAG: основной текст ≥ 7:1, приглушённый, текст состояний и кнопок ≥ 4.5:1 — в каждой теме."""
import re
from pathlib import Path

import pytest

FRONT = Path(__file__).resolve().parents[2] / "frontend"
THEMES = ("night", "glass", "grove", "aurora")
pytestmark = pytest.mark.skipif(not (FRONT / "src" / "styles.css").exists(), reason="нет исходников интерфейса")


def blocks() -> dict:
    css = (FRONT / "src" / "styles.css").read_text()
    out = {}
    for m in re.finditer(r':root(?:, :root\[data-theme="night"\]|\[data-theme="(\w+)"\]) \{(.*?)\n\}', css, re.S):
        toks = dict(re.findall(r"--([\w-]+):\s*([^;]+);", m.group(2)))
        if "canvas" in toks:
            out.setdefault(m.group(1) or "night", toks)
    return out


def rgb(v, toks, under=None):
    v = v.strip()
    if v.startswith("var("):
        return rgb(toks[v[6:-1].split(",")[0].strip()], toks, under)
    if v.startswith("#"):
        h = v[1:]
        h = "".join(c * 2 for c in h) if len(h) == 3 else h
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.match(r"rgb\((\d+) (\d+) (\d+)(?: / ([.\d]+))?\)", v)
    c, a = tuple(int(x) for x in m.groups()[:3]), float(m.group(4) or 1)
    u = under or (255, 255, 255)
    return tuple(round(c[i] * a + u[i] * (1 - a)) for i in range(3))


def lum(c):
    f = [x / 255 for x in c]
    f = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in f]
    return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


PAIRS = [("ink", "surface", 7), ("ink", "canvas", 7), ("ink-2", "surface", 4.5), ("muted", "surface", 4.5), ("muted", "canvas", 4.5), ("accent", "surface", 3), ("accent-ink", "accent", 4.5),
         ("ok-text", "ok-bg", 4.5), ("warn-text", "warn-bg", 4.5), ("danger-text", "danger-bg", 4.5), ("danger-ink", "danger", 4.5), ("danger-text", "surface", 4.5), ("warn-text", "surface", 4.5),
         ("chrome-ink", "chrome", 7), ("chrome-muted", "chrome", 4.5), ("chrome-ink-strong", "chrome-3", 4.5), ("float-ink", "float", 7), ("float-muted", "float", 4.5), ("float-accent-ink", "float-accent", 4.5)]


def test_four_themes_night_by_default_everywhere():
    assert set(blocks()) == set(THEMES)
    assert ':root, :root[data-theme="night"] {' in (FRONT / "src" / "styles.css").read_text()
    assert 'data-theme="night"' in (FRONT / "index.html").read_text()
    boot = (FRONT / "public" / "theme-boot.js").read_text()
    assert 't = "night"' in boot and all(t in boot for t in THEMES)
    assert all((FRONT / "public" / "bg" / f"{t}.svg").stat().st_size < 2048 for t in THEMES)          # рисунки фона лёгкие и лежат в сборке


@pytest.mark.parametrize("theme", THEMES)
def test_theme_contrast(theme):
    t = blocks()[theme]
    canvas = rgb(t["canvas"], t)
    low = []
    for fg, bg, need in PAIRS:
        b = rgb(t[bg], t, canvas)
        r = ratio(rgb(t[fg], t, b), b)
        if r < need:
            low.append(f"{fg} на {bg}: {r:.2f} < {need}")
    assert not low, low
