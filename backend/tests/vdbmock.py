"""Подставные ответы публичных источников для тестов загрузчика: ленты NVD (.meta и .json.gz), архивы и modified_id.csv OSV, KEV, БДУ."""
import gzip
import hashlib
import io
import json
import zipfile
from pathlib import Path

import httpx

FIX = Path(__file__).parent / "fixtures" / "vdb"
NVD, KEV, OSV = (json.loads((FIX / n).read_text()) for n in ("nvd.json", "kev.json", "osv.json"))


def bdu_zip() -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("export/export.xml", (FIX / "bdu.xml").read_bytes())
    return b.getvalue()


def nvd_feed(url: str, doc: dict | None = None, *, corrupt: bool = False) -> httpx.Response:
    """Ответ на запрос ленты NVD: `…/nvdcve-2.0-2025.meta` или `….json.gz` (sha256 в .meta — распакованного содержимого, как у NIST)."""
    raw = json.dumps(doc if doc is not None else NVD).encode()
    if url.endswith(".meta"):
        sha = hashlib.sha256(raw).hexdigest().upper()
        return httpx.Response(200, text=f"lastModifiedDate:2026-10-25T12:00:08-04:00\nsize:{len(raw)}\nzipSize:1\ngzSize:1\nsha256:{sha}\n")
    gz = gzip.compress(raw)
    return httpx.Response(200, content=gz[: len(gz) // 2] if corrupt else gz, headers={"content-length": str(len(gz))})


def osv_zip(docs: list[dict]) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for d in docs:
            z.writestr(f"{d['id']}.json", json.dumps(d))
    return b.getvalue()
