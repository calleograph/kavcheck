"""Категория продукта каталога для аналитики уязвимостей: операционная система, системный компонент, прикладное ПО, не классифицировано.

Название производителя само по себе категорию не определяет (PostgreSQL и PHP бывают и серверным, и системным ПО), поэтому порядок источников признаков такой:
  1. решение администратора (`product_classes`) — всегда главнее;
  2. категория продукта в endoflife.date (os, lang, db, server-app, app…), если продукт сопоставлен с ним;
  3. правила по названию: ОС и ядро, среды выполнения и библиотеки, драйверы, распространяемые пакеты Windows (системные компоненты), известное прикладное ПО;
  4. платформа: пакет дистрибутива Linux — системный компонент, установленная программа Windows с указанным производителем — прикладное ПО;
  5. иначе — «не классифицировано» (специалист может назначить категорию вручную).
Результат — пара (категория, основание); основание показывается в интерфейсе, чтобы решение было проверяемым."""
from __future__ import annotations

import re

CATEGORIES = ("os", "system", "application", "unclassified")
CATEGORY_RU = {"os": "Операционные системы", "system": "Системные компоненты", "application": "Прикладное ПО", "unclassified": "Не классифицировано"}

# категории endoflife.date → наши
EOL_CATEGORY = {"os": "os", "lang": "system", "db": "application", "server-app": "application", "app": "application", "framework": "application", "cms": "application", "service": "application"}

_OS_NAME = re.compile(r"^(microsoft\s+)?windows(\s+server)?\s+(\d{4}|\d{1,2}(\.\d)?|xp|vista|r2)(\s|$)", re.I)
_OS_NOT = re.compile(r"\b(sdk|kit|driver|update|hotfix|installer|defender|live|media|embedded runtime)\b", re.I)
_KERNEL = re.compile(r"^(linux-(image|modules|headers|kbuild)|kernel(-core|-devel|-modules)?|linux-libc-dev|astra-kernel)\b", re.I)
_OS_DISTRO = re.compile(r"^(ubuntu|debian gnu/linux|astra linux|alt (linux|server|workstation)|red hat enterprise linux|centos|rocky linux|almalinux|oracle linux|suse linux enterprise|ред ос|роса)\b", re.I)

_SYSTEM_WIN = re.compile(r"(visual c\+\+.*(redistributable|runtime)|vcredist|microsoft \.net|\.net (runtime|framework|desktop runtime|sdk|core)|asp\.net core|windows (software development kit|sdk|driver kit)|"
                         r"webview2|update health tools|security update|hotfix|\bkb\d{6,}|directx|java(\(tm\))? (se )?(runtime|\d+ update)|jre|openjdk|microsoft visual studio.*(runtime|redistributable|shell|installer)|"
                         r"windows installer|msxml|microsoft (edge )?update|nvidia (graphics|driver|physx)|intel\(r\).*(driver|management engine)|realtek.*(driver|audio)|amd .*(driver|chipset)|driver package)", re.I)
_RUNTIME = re.compile(r"^(python|php|node\.?js|ruby|perl|golang|go|openjdk|java|dotnet|mono|lua|erlang)[\s\-_0-9.]*(cli|fpm|common|runtime|interpreter|core)?$", re.I)
_SYSTEM_LINUX = re.compile(r"^(lib[\w.+-]+|bash|dash|zsh|openssl|openssh(-server|-client|-sftp-server)?|ssh|glibc|libc6|systemd[\w-]*|udev|coreutils|util-linux|sudo|curl|gnupg\d?|gpg|zlib[\w-]*|gnutls[\w-]*|"
                           r"dpkg|apt|rpm|yum|dnf|dbus[\w-]*|polkit[\w-]*|login|passwd|shadow|tar|gzip|bzip2|xz(-utils)?|ncurses[\w-]*|readline[\w-]*|sqlite3|bind9[\w-]*|cups[\w-]*|"
                           r"samba[\w-]*|krb5[\w-]*|pam[\w-]*|grub[\w-]*|initramfs[\w-]*|network-manager|netplan[\w.-]*|iptables|nftables|firewalld|cron|rsyslog|logrotate|ca-certificates|tzdata|"
                           r"[\w.+-]+-(common|data|doc|dev|devel|headers|utils|tools|libs|lib))$", re.I)
_APP = re.compile(r"(chrom(e|ium)|firefox|mozilla|opera|yandex|vivaldi|brave|microsoft edge$|tor browser|libreoffice|openoffice|microsoft (office|word|excel|outlook|teams|onedrive|visio|project|access)|"
                  r"office\s?(20\d\d|365)|acrobat|adobe reader|foxit|pdf|7-?zip|winrar|winzip|vlc|skype|zoom|telegram|whatsapp|viber|slack|discord|anydesk|teamviewer|rustdesk|notepad\+\+|putty|winscp|filezilla|"
                  r"git\b|docker|visual studio( code)?|jetbrains|intellij|pycharm|webstorm|postman|gimp|inkscape|obs studio|1c|1с|кonsultant|консультант|гарант|кспд|kaspersky|касперск|dr\.web|eset|"
                  r"nginx|apache(2| http| tomcat)?|httpd|tomcat|jboss|wildfly|postgres(ql)?|mysql|mariadb|mongodb|redis|memcached|oracle (database|vm)|sql server|exchange|sharepoint|zabbix|grafana|elasticsearch|"
                  r"kibana|logstash|jenkins|gitlab|nextcloud|wordpress|rabbitmq|kafka|vmware|virtualbox|veeam|acronis|winbox|wireshark|nmap|openvpn|wireguard)", re.I)


def classify(name: str, publisher: str = "", key: str = "", platforms: int = 0, component: bool = False, eol_category: str | None = None, override: str | None = None) -> tuple[str, str]:
    """(категория, основание). platforms — маска каталога: 1 — Windows, 2 — Linux."""
    if override in CATEGORIES:
        return override, "решение администратора"
    n = (name or key or "").strip()
    low = n.lower()
    if _OS_NAME.search(n) and not _OS_NOT.search(n):
        return "os", "название: операционная система Windows"
    if _KERNEL.search(low) or _OS_DISTRO.search(low):
        return "os", "название: ядро или дистрибутив Linux"
    mapped = EOL_CATEGORY.get(eol_category or "")
    if mapped:
        return mapped, f"категория endoflife.date: {eol_category}"
    if _RUNTIME.search(low):
        return "system", "название: среда выполнения или интерпретатор"
    if _SYSTEM_WIN.search(n):
        return "system", "название: системный компонент или среда выполнения Windows"
    if _APP.search(n):
        return "application", "название: известное прикладное ПО"
    if component:
        return "system", "каталог: компонент другого продукта"
    if platforms == 2:
        return ("system", "системная библиотека или пакет Linux") if _SYSTEM_LINUX.search(low) else ("system", "пакет дистрибутива Linux")
    if platforms & 1 and (publisher or "").strip():
        return "application", "установленная программа Windows с известным производителем"
    return "unclassified", "признаков категории нет"
