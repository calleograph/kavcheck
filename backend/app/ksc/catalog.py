"""Каталог продуктов: как записи реестра ПО KSC (название, версия, производитель, платформа) объединяются в продукты и ветки.

Порядок определения продукта записи:
1. ручная корректировка администратора (разделение по точному названию) — см. services/catalog.py;
2. встроенное описание распространённого продукта (BUILTIN): регулярные выражения по названию, схема сравнения версий, правило ветки;
3. автоматическая группа: название без номеров версий, разрядности и языка («7-Zip 23.01 (x64)» → «7-Zip»), для пакетов Linux — имя пакета.
Затем применяются ручные объединения продуктов (merge). Ключ продукта детерминирован, поэтому один и тот же продукт в разных источниках KSC
получает один ключ — по нему строятся отчёты сразу по нескольким серверам."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from . import versions
from .grouping import PHP_BRANCH_REGEX, PHP_NAME_REGEX

LINUX, WINDOWS = 2, 1


@dataclass(frozen=True)
class ProductDef:
    key: str
    name: str
    publisher: str = ""
    match: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    scheme: str | None = None            # None — по платформе записи (Linux — dpkg, Windows — numeric)
    transform: str | None = None         # приведение нестандартной нумерации: java | python
    branch: str = "parts:1"              # parts:N | postgres | mssql | name:<regex с группой 1> | phpname
    version_from_name: str | None = None  # регулярное выражение: версия из названия, если версия записи непригодна (.NET)
    component: bool = False              # служебные компоненты (части пакета Office и т. п.): в каталоге скрыты по умолчанию
    note: str = ""

    def compiled(self):
        return tuple(re.compile(p, re.I) for p in self.match), tuple(re.compile(p, re.I) for p in self.exclude)


def P(key: str, name: str, publisher: str, *match: str, **kw) -> ProductDef:
    return ProductDef(key=key, name=name, publisher=publisher, match=tuple(match), **kw)


_ARCH = r"(?:\s*\((?:x64|x86|64-bit|32-bit|64 bit|32 bit)(?:[ ,]+[a-z]{2}(?:-[a-z]{2})?)?\))?"
BUILTIN: tuple[ProductDef, ...] = (
    # --- браузеры
    P("google-chrome", "Google Chrome", "Google", r"^google chrome" + _ARCH + r"$", r"^google-chrome-stable$", r"^google chrome for testing"),
    P("microsoft-edge", "Microsoft Edge", "Microsoft", r"^microsoft edge" + _ARCH + r"$", r"^microsoft-edge-stable$"),
    P("microsoft-edge-webview2", "Microsoft Edge WebView2 Runtime", "Microsoft", r"^microsoft edge webview2 runtime"),
    P("mozilla-firefox", "Mozilla Firefox", "Mozilla", r"^mozilla firefox\b(?! maintenance)", r"^firefox(-esr)?$", note="ESR и обычный выпуск — ветки одного продукта"),
    P("mozilla-thunderbird", "Mozilla Thunderbird", "Mozilla", r"^mozilla thunderbird\b", r"^thunderbird$"),
    P("yandex-browser", "Яндекс Браузер", "Яндекс", r"^yandex$", r"^yandex browser", r"^яндекс браузер", r"^yandex-browser(-stable)?$"),
    P("opera", "Opera", "Opera", r"^opera stable\b", r"^opera\s+\d", r"^opera-stable$"),
    # --- архиваторы и утилиты
    P("7-zip", "7-Zip", "Igor Pavlov", r"^7-zip\b", r"^p7zip(-full)?$", r"^7zip$"),
    P("winrar", "WinRAR", "win.rar GmbH", r"^winrar\b"),
    P("notepad-plus-plus", "Notepad++", "Notepad++ Team", r"^notepad\+\+"),
    P("putty", "PuTTY", "Simon Tatham", r"^putty\b"),
    P("winscp", "WinSCP", "Martin Prikryl", r"^winscp\b"),
    P("filezilla", "FileZilla", "Tim Kosse", r"^filezilla\b"),
    P("keepass", "KeePass", "Dominik Reichl", r"^keepass\b"),
    P("vlc", "VLC media player", "VideoLAN", r"^vlc media player", r"^vlc$"),
    P("zoom", "Zoom", "Zoom Video Communications", r"^zoom(?: workplace)?" + _ARCH + r"$", r"^zoom\b.*meetings"),
    P("anydesk", "AnyDesk", "AnyDesk Software", r"^anydesk\b"),
    P("teamviewer", "TeamViewer", "TeamViewer", r"^teamviewer\b"),
    P("telegram", "Telegram Desktop", "Telegram FZ-LLC", r"^telegram desktop\b"),
    P("wireshark", "Wireshark", "Wireshark Foundation", r"^wireshark\b"),
    P("vscode", "Visual Studio Code", "Microsoft", r"^microsoft visual studio code\b", r"^visual studio code\b", r"^code$"),
    # --- Java, Python, Node.js, Git
    P("java", "Java (Oracle)", "Oracle", r"^java\s*\d*(\s+update\s+\d+)?" + _ARCH + r"$", r"^java\(tm\)", r"^java se development kit", r"^java \d+ update \d+",
      r"^jdk \d+", r"^java se runtime", transform="java", note="Java для Windows записывает 8u401 как 8.0.4010.7 — сравнивается как 8.0.401"),
    P("openjdk", "OpenJDK", "", r"^openjdk-\d+-(jre|jdk)(-headless)?$", r"^java-[\d.]+-openjdk(-headless|-devel)?$", r"^eclipse temurin", r"^adoptopenjdk",
      r"^microsoft build of openjdk", r"^amazon corretto", r"^(bellsoft )?liberica (jdk|jre)", r"^openjdk\b", transform="java"),
    P("python", "Python", "Python Software Foundation", r"^python \d+\.\d+(\.\d+)?(?!.*launcher)\b", r"^python[23](\.\d+)?(-minimal)?$", r"^libpython[23]\.\d+(-minimal|-stdlib)?$",
      r"^python3\d*$", transform="python", branch="parts:2", note="Компоненты установщика Python для Windows (Core Interpreter, Standard Library и др.) объединены"),
    P("nodejs", "Node.js", "Node.js Foundation", r"^node\.js$", r"^nodejs$"),
    P("git", "Git", "The Git Development Community", r"^git(\s+version\s+[\d.]+)?$", r"^git" + _ARCH + r"$", branch="parts:2"),
    P("php", "PHP", "", PHP_NAME_REGEX, branch="phpname", note="Пакеты самого PHP: ядро, CLI, FPM, модуль Apache и расширения phpX.Y-*; ветка — из имени пакета"),
    P("perl", "Perl", "", r"^perl$", r"^strawberry perl\b", r"^activeperl\b", branch="parts:2"),
    # --- криптография и удалённый доступ
    P("openssl", "OpenSSL", "OpenSSL", r"^openssl$", r"^libssl\d+(\.\d+)*[a-z]?$", r"^openssl-libs$", r"^(win64 |win32 )?openssl\b.*light", r"^openssl \d", branch="parts:2"),
    P("openssh", "OpenSSH", "OpenBSD", r"^openssh(-server|-client|-clients|-sftp-server)?$", r"^openssh\b" + _ARCH + r"$", branch="parts:2"),
    P("cryptopro-csp", "КриптоПро CSP", "КРИПТО-ПРО", r"^криптопро csp\b", r"^cryptopro csp\b", r"^lsb-cprocsp-base$", branch="parts:2"),
    # --- СУБД
    P("postgresql", "PostgreSQL", "PostgreSQL Global Development Group", r"^postgresql[ -]?\d+(\.\d+)?$", r"^postgresql\d*-server$", r"^postgresql(-\d+)?$",
      r"^postgresql \d+" + _ARCH, exclude=(r"common", r"odbc", r"jdbc", r"pgadmin", r"libpq"), branch="postgres", note="Ветка — основная версия (16), для версий до 10 — две части (9.6)"),
    P("mssql-server", "Microsoft SQL Server", "Microsoft", r"^(microsoft )?sql server \d{4}( r2)? database engine services$", r"^mssql-server$", branch="mssql",
      note="Учитывается компонент Database Engine Services; ветка — год выпуска (2019, 2022)"),
    P("ssms", "SQL Server Management Studio", "Microsoft", r"^(microsoft )?sql server management studio\b"),
    P("mysql", "MySQL Server", "Oracle", r"^mysql server \d+\.\d+", r"^mysql-server(-\d+\.\d+)?$", r"^mysql-community-server$", branch="parts:2"),
    P("mariadb", "MariaDB Server", "MariaDB", r"^mariadb \d+\.\d+", r"^mariadb-server(-\d+\.\d+)?$", r"^mariadb-server$", branch="parts:2"),
    P("redis", "Redis", "", r"^redis(-server)?$", r"^redis-tools$", branch="parts:2"),
    P("mongodb", "MongoDB", "MongoDB", r"^mongodb(-org)?(-server)?$", r"^mongodb \d", branch="parts:2"),
    # --- веб и контейнеры
    P("apache-httpd", "Apache HTTP Server", "Apache Software Foundation", r"^apache2(-bin)?$", r"^httpd$", r"^apache http server\b", branch="parts:2"),
    P("apache-tomcat", "Apache Tomcat", "Apache Software Foundation", r"^apache tomcat\b", r"^tomcat\d*$"),
    P("nginx", "nginx", "", r"^nginx(-core|-full|-light|-extras)?$", branch="parts:2"),
    P("docker-engine", "Docker Engine", "Docker", r"^docker-ce$", r"^docker\.io$", r"^docker-engine$", r"^moby-engine$"),
    P("docker-desktop", "Docker Desktop", "Docker", r"^docker desktop\b"),
    P("containerd", "containerd", "", r"^containerd(\.io)?$", branch="parts:2"),
    # --- .NET и Visual C++
    P("dotnet-runtime", ".NET Runtime", "Microsoft", r"^microsoft \.net runtime\b", r"^microsoft windows desktop runtime\b", r"^microsoft asp\.net core [\d.]+ - shared framework",
      r"^microsoft \.net host\b", r"^dotnet-runtime-\d", r"^aspnetcore-runtime-\d", r"^dotnet-host$", branch="parts:2",
      version_from_name=r"(\d+\.\d+\.\d+)", note="Среда выполнения .NET (Core, 5+): версия берётся из названия компонента"),
    P("dotnet-sdk", ".NET SDK", "Microsoft", r"^microsoft \.net sdk\b", r"^dotnet-sdk-\d", branch="parts:2", version_from_name=r"(\d+\.\d+\.\d+)"),
    P("dotnet-framework", ".NET Framework", "Microsoft", r"^microsoft \.net framework [\d.]+\b(?!.*(sdk|targeting|multi-targeting|language|developer))", branch="parts:2"),
    # --- офис и PDF
    P("microsoft-office", "Microsoft Office", "Microsoft", r"^microsoft office (professional|standard|home|enterprise|профессиональный|стандартный|для дома|корпоративный)\b",
      r"^microsoft 365\b(?!.*(mui|proofing))", r"^microsoft office 365\b", r"^microsoft office ltsc", branch=r"name:(\d{4}|365)",
      note="Ветка — выпуск из названия (2016, 2019, 2021, 365)"),
    P("microsoft-office-components", "Компоненты Microsoft Office", "Microsoft", r"^microsoft office\b.*(mui|proofing|shared|components|single image|language pack|click-to-run|osm|ux|outlook mui)",
      r"^microsoft (excel|word|powerpoint|outlook|access|publisher|onenote) mui\b", r"^microsoft office\b.*\(\w{2}-\w{2}\)$", component=True, branch=r"name:(\d{4})"),
    P("libreoffice", "LibreOffice", "The Document Foundation", r"^libreoffice\b(?!.*help pack)", r"^libreoffice-core$", branch="parts:2"),
    P("adobe-acrobat-reader", "Adobe Acrobat Reader", "Adobe", r"^adobe acrobat reader\b", r"^adobe reader\b"),
    P("adobe-acrobat", "Adobe Acrobat", "Adobe", r"^adobe acrobat(?! reader)\b"),
    P("foxit-reader", "Foxit PDF Reader", "Foxit Software", r"^foxit (pdf )?reader\b"),
    P("1c-enterprise", "1С:Предприятие", "1С", r"^1с:предприятие\b", r"^1c:enterprise\b", r"^1c-enterprise[\d.-]*-(server|client|common)", branch="parts:2"),
    # --- Linux: ядро и базовые библиотеки
    P("linux-kernel", "Ядро Linux", "", r"^linux-image-\d", r"^linux-image-(amd64|generic)$", r"^kernel(-core)?$", branch="parts:2"),
    P("glibc", "GNU C Library (glibc)", "", r"^libc6$", r"^libc-bin$", r"^glibc$", branch="parts:2"),
    P("sudo", "sudo", "", r"^sudo$", branch="parts:2"),
    P("bash", "bash", "", r"^bash$", branch="parts:2"),
    P("curl", "curl", "", r"^curl$", r"^libcurl\d*(-gnutls|-openssl)?$", r"^libcurl$", branch="parts:2"),
    P("xz-utils", "XZ Utils", "", r"^xz-utils$", r"^liblzma\d*$", r"^xz(-libs)?$", branch="parts:2"),
    P("zlib", "zlib", "", r"^zlib1g$", r"^zlib$", branch="parts:2"),
    P("systemd", "systemd", "", r"^systemd$", r"^libsystemd0$"),
    P("polkit", "polkit", "", r"^policykit-1$", r"^polkit$", r"^libpolkit-gobject-1-0$", branch="parts:2"),
    P("samba", "Samba", "", r"^samba$", r"^samba-common-bin$", branch="parts:2"),
    P("bind", "BIND", "ISC", r"^bind9$", r"^bind$", branch="parts:2"),
    P("exim", "Exim", "", r"^exim4(-daemon-light|-daemon-heavy)?$", branch="parts:2"),
    P("postfix", "Postfix", "", r"^postfix$", branch="parts:2"),
    # --- Kaspersky (записи реестра ПО; состояние защиты — отдельный раздел)
    P("kaspersky-endpoint-security", "Kaspersky Endpoint Security", "Kaspersky", r"^kaspersky endpoint security\b", r"^kesl$", branch="parts:2"),
    P("kaspersky-network-agent", "Агент администрирования Kaspersky", "Kaspersky", r"^агент администрирования kaspersky", r"^kaspersky security center network agent",
      r"^klnagent(64)?$", branch="parts:2"),
)
BUILTIN_BY_KEY = {d.key: d for d in BUILTIN}


@lru_cache(maxsize=None)
def _compiled(key: str):
    return BUILTIN_BY_KEY[key].compiled()


# ------------------------------------------------------------------------------------------------ автоматическая группа
_ARCH_RX = re.compile(r"\s*[\(\[]\s*(?:x64|x86|x86_64|amd64|arm64|64-bit|32-bit|64 bit|32 bit|64-разрядная|32-разрядная|64-разрядный|32-разрядный)"
                      r"(?:[ ,]+[a-z]{2}(?:-[a-z]{2})?)?\s*[\)\]]", re.I)
_LANG_RX = re.compile(r"\s*\((?:[a-z]{2}(?:-[a-z]{2})?)\)|\s+-\s+(?:[a-z]{2}-[a-z]{2}|russian|english|русский|английский)\s*$", re.I)
_ARCH_WORD = re.compile(r"\b(?:x64|x86|x86_64|amd64|arm64|win64|win32|64-bit|32-bit)\b", re.I)
_VER_RX = re.compile(r"(?<![\w.])v?\d+(?:[.,_]\d+)+(?:[a-z]\d*)?(?:[-+~][\w.]*)?(?![\w])", re.I)
_TRAIL_NUM = re.compile(r"\s+(?:version|версия|build|сборка|release|выпуск)\s*$", re.I)
_PUB_SUFFIX = re.compile(r"[,.]?\s*\b(?:inc|llc|ltd|limited|corp|corporation|co|gmbh|s\.r\.o|a\.s|ag|sa|bv|b\.v|plc|ооо|зао|пао|ао|оао|ип)\b\.?", re.I)


def clean_publisher(publisher: str) -> str:
    """Производитель для показа: без адреса электронной почты (пакеты Linux пишут «Maintainers <list@…>»)."""
    p = re.sub(r"<[^>]*>", "", publisher or "").strip(" ,;")
    return re.sub(r"\s{2,}", " ", p)


def publisher_key(publisher: str) -> str:
    """Ключ производителя для группировки: «Google LLC» и «Google Inc.» — один производитель."""
    p = clean_publisher(publisher).lower()
    p = re.sub(r"[«»\"']", "", p)
    for _ in range(2):
        p = _PUB_SUFFIX.sub("", p).strip(" ,.-")
    return slug(p)


def normalize_name(name: str) -> str:
    """Название без версии, разрядности и языка: «7-Zip 23.01 (x64)» → «7-Zip», «Notepad++ (64-bit x64)» → «Notepad++»."""
    s = (name or "").strip()
    s = _ARCH_RX.sub(" ", s)
    s = _LANG_RX.sub(" ", s)
    s = _VER_RX.sub(" ", s)
    s = _ARCH_WORD.sub(" ", s)
    s = re.sub(r"\(\s*\)", " ", s)
    s = re.sub(r"\s{2,}", " ", s).strip(" -–—:,;/")
    s = _TRAIL_NUM.sub("", s).strip(" -–—:,;/")
    return s or (name or "").strip()


def slug(text: str) -> str:
    s = re.sub(r"[^0-9a-zа-яё+#]+", "-", (text or "").lower()).strip("-")
    return s[:120] or "unnamed"


def is_linux_package(name: str, platform_mask: int | None) -> bool:
    return bool(int(platform_mask or 0) & LINUX) and not int(platform_mask or 0) & WINDOWS and " " not in (name or "")


@dataclass(frozen=True)
class Classified:
    key: str
    name: str
    builtin: ProductDef | None


@lru_cache(maxsize=200_000)
def classify(name: str, platform_mask: int | None = None) -> Classified:
    """Продукт записи реестра по встроенным описаниям, иначе — автоматическая группа по названию."""
    n = (name or "").strip()
    for d in BUILTIN:
        inc, exc = _compiled(d.key)
        if any(r.search(n) for r in inc) and not any(r.search(n) for r in exc):
            return Classified(d.key, d.name, d)
    if is_linux_package(n, platform_mask):
        return Classified("pkg:" + slug(n), n, None)
    base = normalize_name(n)
    return Classified(slug(base), base, None)


# ------------------------------------------------------------------------------------------------ версии и ветки записи
def record_version(d: ProductDef | None, name: str, version: str) -> str:
    """Версия записи для каталога (до схемы сравнения): у некоторых продуктов (.NET) точная версия — в названии."""
    if d and d.version_from_name:
        m = re.search(d.version_from_name, name or "")
        if m:
            return m.group(1)
    return (version or "").strip()


_MSSQL_YEARS = {"16": "2022", "15": "2019", "14": "2017", "13": "2016", "12": "2014", "11": "2012", "10": "2008"}


def branch(d: ProductDef | None, name: str, version: str, scheme: str) -> str:
    """Ветка продукта. Пустая строка — не определена достоверно (метапакет с эпохой, нечисловая версия)."""
    mode = d.branch if d else "parts:1"
    eff = versions.effective(record_version(d, name, version), scheme, d.transform if d else None)
    if mode == "phpname":
        cv = versions.compared_version(name, version, re.compile(PHP_BRANCH_REGEX, re.I))
        return versions.branch_of(cv, 2)
    if mode.startswith("name:"):
        m = re.search(mode[5:], name or "", re.I)
        return m.group(1) if m else ""
    if mode == "mssql":
        m = re.search(r"\b(20\d\d)\b", name or "")
        if m:
            return m.group(1)
        return _MSSQL_YEARS.get(eff.split(".")[0], "")
    if mode == "postgres":
        m = re.match(r"^(\d+)(?:\.(\d+))?", eff)
        if not m:
            return ""
        return m.group(1) if int(m.group(1)) >= 10 or not m.group(2) else f"{m.group(1)}.{m.group(2)}"
    parts = int(mode.split(":")[1]) if mode.startswith("parts:") else 1
    if scheme == "dpkg" and re.match(r"^\d+:", version or "") and parts > 1:
        # метапакеты Debian с эпохой (php-common 2:76+…) — ветка недостоверна
        if not re.match(r"^\d+\.\d+", eff):
            return ""
    m = re.match(r"(\d+(?:\.\d+){0,%d})" % (parts - 1), eff)
    if not m:
        return ""
    b = m.group(1)
    return b if b.count(".") >= parts - 1 else ""


def compared_version(d: ProductDef | None, name: str, version: str, scheme: str) -> str:
    """Версия для показа и сравнения: без эпохи/ревизии (dpkg), с приведением нумерации; у PHP-расширений — ветка из имени."""
    if d and d.branch == "phpname":
        return versions.compared_version(name, version, re.compile(PHP_BRANCH_REGEX, re.I))
    return versions.effective(record_version(d, name, version), scheme, d.transform if d else None)
