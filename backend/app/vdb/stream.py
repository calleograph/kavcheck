"""Потоковая обработка больших выгрузок без загрузки в память: элементы JSON-массива по одному, проверка контрольной суммы распакованного потока, свободное место."""
from __future__ import annotations

import codecs
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import BinaryIO, Iterator

CHUNK = 1 << 20
_DECODER = json.JSONDecoder()


def iter_array(fp: BinaryIO, key: str) -> Iterator[dict]:
    """Элементы массива `"key": [ … ]` верхнего уровня JSON по одному. Память — один элемент и буфер около 4 МБ, а не весь файл (ленты NVD — сотни мегабайт).
    Оборванный или повреждённый JSON — ValueError (загрузка отклоняется целиком)."""
    dec = codecs.getincrementaldecoder("utf-8")(errors="strict")
    buf, pos, eof = "", 0, False
    marker = re.compile(r'"%s"\s*:\s*\[' % re.escape(key))

    def more() -> bool:
        nonlocal buf, eof
        if eof:
            return False
        raw = fp.read(CHUNK)
        if not raw:
            eof = True
            buf += dec.decode(b"", final=True)
            return False
        buf += dec.decode(raw)
        return True

    while True:                                       # до начала массива
        m = marker.search(buf)
        if m:
            pos = m.end()
            break
        if len(buf) > 2 * CHUNK:
            buf = buf[-256:]
        if not more():
            raise ValueError(f"в файле нет массива «{key}»")
    while True:
        while True:                                   # пробелы и запятые между элементами
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos < len(buf) or not more():
                break
        if pos >= len(buf):
            raise ValueError("файл оборван внутри массива")
        if buf[pos] == "]":
            return
        while True:
            try:
                obj, end = _DECODER.raw_decode(buf, pos)
                break
            except ValueError:
                if not more():
                    raise ValueError("повреждённый или оборванный JSON") from None
        pos = end
        if pos > 4 * CHUNK:
            buf, pos = buf[pos:], 0
        yield obj


def sha256_stream(fp: BinaryIO) -> tuple[str, int]:
    """SHA-256 и размер потока (для распакованных лент NVD — сверяется с файлом .meta)."""
    h, n = hashlib.sha256(), 0
    while True:
        b = fp.read(CHUNK)
        if not b:
            return h.hexdigest().upper(), n
        h.update(b)
        n += len(b)


def free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free
