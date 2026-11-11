"""Каталог готовых фидов OVAL официальных источников дистрибутивов: администратору не нужно искать адреса — он отмечает галочками, что загружать.

Адреса проверены на доступность (11.11.2026), размер — архива, как отдаёт сервер (в разобранном виде больше). `current` — поддерживаемые выпуски: их предлагает кнопка «Только актуальные».
Поддерживаются форматы XML, .bz2 и .gz (см. `pentest/oval.py`). Своих фидов администратор может добавить сколько угодно — каталог их не ограничивает."""
from __future__ import annotations

CANON = "https://security-metadata.canonical.com/oval/com.ubuntu.{}.usn.oval.xml.bz2"
DEBIAN = "https://www.debian.org/security/oval/oval-definitions-{}.xml.bz2"
REDHAT = "https://access.redhat.com/security/data/oval/v2/RHEL{0}/rhel-{0}.oval.xml.bz2"
ALMA = "https://security.almalinux.org/oval/org.almalinux.alsa-{}.xml.bz2"
ROCKY = "https://download.rockylinux.org/pub/oval/org.rockylinux.rlsa-{}.xml.bz2"
ORACLE = "https://linux.oracle.com/security/oval/com.oracle.elsa-ol{}.xml.bz2"
SUSE = "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.{}.xml.gz"

# (группа, название, адрес, размер архива в байтах, актуальный выпуск)
_ROWS: list[tuple[str, str, str, int, bool]] = [
    ("Ubuntu", "Ubuntu 24.04 noble", CANON.format("noble"), 1_344_531, True),
    ("Ubuntu", "Ubuntu 22.04 jammy", CANON.format("jammy"), 1_570_034, True),
    ("Ubuntu", "Ubuntu 20.04 focal", CANON.format("focal"), 1_322_447, True),
    ("Ubuntu", "Ubuntu 18.04 bionic", CANON.format("bionic"), 1_024_013, False),
    ("Ubuntu", "Ubuntu 16.04 xenial", CANON.format("xenial"), 1_001_279, False),
    ("Debian", "Debian 13 trixie", DEBIAN.format("trixie"), 9_887_602, True),
    ("Debian", "Debian 12 bookworm", DEBIAN.format("bookworm"), 9_892_464, True),
    ("Debian", "Debian 11 bullseye", DEBIAN.format("bullseye"), 385_423, True),
    ("Debian", "Debian 10 buster", DEBIAN.format("buster"), 245_390, False),
    ("Red Hat Enterprise Linux", "RHEL 9", REDHAT.format(9), 1_477_006, True),
    ("Red Hat Enterprise Linux", "RHEL 8", REDHAT.format(8), 2_030_966, True),
    ("Red Hat Enterprise Linux", "RHEL 7", REDHAT.format(7), 1_008_892, False),
    ("AlmaLinux", "AlmaLinux 10", ALMA.format(10), 480_497, True),
    ("AlmaLinux", "AlmaLinux 9", ALMA.format(9), 1_127_386, True),
    ("AlmaLinux", "AlmaLinux 8", ALMA.format(8), 1_751_583, True),
    ("Rocky Linux", "Rocky Linux 9", ROCKY.format(9), 269_142, True),
    ("Rocky Linux", "Rocky Linux 8", ROCKY.format(8), 827_814, True),
    ("Oracle Linux", "Oracle Linux 10", ORACLE.format(10), 1_347_521, True),
    ("Oracle Linux", "Oracle Linux 9", ORACLE.format(9), 3_730_992, True),
    ("Oracle Linux", "Oracle Linux 8", ORACLE.format(8), 5_963_142, True),
    ("Oracle Linux", "Oracle Linux 7", ORACLE.format(7), 3_444_158, False),
    ("SUSE", "SLES 16", SUSE.format("server.16"), 15_850_934, True),
    ("SUSE", "SLES 15", SUSE.format("server.15"), 51_361_798, True),
    ("SUSE", "SLES 12", SUSE.format("server.12"), 25_269_247, False),
    ("SUSE", "SLED 15", SUSE.format("desktop.15"), 26_861_716, True),
]

CATALOG: list[dict] = [{"id": f"{i:02d}", "group": g, "name": n, "url": u, "size": sz, "current": cur} for i, (g, n, u, sz, cur) in enumerate(_ROWS, 1)]
