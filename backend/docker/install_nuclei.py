#!/usr/bin/env python3
"""Установка Nuclei и архива шаблонов в образ при сборке: версии и контрольные суммы SHA-256 заданы в Dockerfile (ARG); при несовпадении сборка останавливается.
Нужны только стандартная библиотека Python и доступ к github.com во время сборки; в готовом образе шаблоны лежат локально, и Nuclei работает без интернета."""
import hashlib
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path


def fetch(url: str, dest: Path, sha: str) -> None:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=300) as r, dest.open("wb") as fh:  # noqa: S310 — фиксированные https-адреса проекта ProjectDiscovery
        while chunk := r.read(1 << 20):
            h.update(chunk)
            fh.write(chunk)
    if h.hexdigest() != sha.lower():
        dest.unlink(missing_ok=True)
        sys.exit(f"Контрольная сумма {url} не совпала: получено {h.hexdigest()}, ожидалось {sha}")


def main() -> None:
    version, sha_amd, sha_arm, tver, tsha = sys.argv[1:6]
    arch = {"x86_64": ("amd64", sha_amd), "aarch64": ("arm64", sha_arm)}.get(platform.machine())
    if arch is None:
        sys.exit(f"Архитектура {platform.machine()} не поддерживается Nuclei в образе")
    tmp = Path("/tmp/nuclei.zip")
    fetch(f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_{arch[0]}.zip", tmp, arch[1])
    with zipfile.ZipFile(tmp) as z:
        z.extract("nuclei", "/usr/local/bin")
    Path("/usr/local/bin/nuclei").chmod(0o755)
    tmp.unlink()
    out = Path("/opt/kavcheck")
    out.mkdir(parents=True, exist_ok=True)
    fetch(f"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v{tver}.tar.gz", out / "nuclei-templates.tar.gz", tsha)
    (out / "nuclei-templates.tar.gz.sha256").write_text(tsha + "\n")
    (out / "nuclei-templates.version").write_text(tver + "\n")
    print(f"Nuclei {version} ({arch[0]}), шаблоны {tver}: установлено")


if __name__ == "__main__":
    main()
