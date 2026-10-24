"""Соответствие идентификаторов CPE (производитель, продукт) встроенным продуктам каталога там, где названия не совпадают по словам (Java: jre/jdk/java_se).
Это данные, а не код: таблицу можно дополнять; для остального действуют общие правила по названиям (match.py) и решения администратора (vdb_mappings)."""
from __future__ import annotations

ALIASES: dict[tuple[str, str], str] = {
    ("google", "chrome"): "google-chrome", ("microsoft", "edge"): "microsoft-edge", ("microsoft", "edge_chromium"): "microsoft-edge",
    ("microsoft", "edge_chromium_based"): "microsoft-edge", ("mozilla", "firefox"): "mozilla-firefox", ("mozilla", "firefox_esr"): "mozilla-firefox",
    ("mozilla", "thunderbird"): "mozilla-thunderbird", ("yandex", "yandex_browser"): "yandex-browser", ("yandex", "browser"): "yandex-browser", ("opera", "opera_browser"): "opera",
    ("7-zip", "7-zip"): "7-zip", ("igor_pavlov", "7-zip"): "7-zip", ("rarlab", "winrar"): "winrar", ("notepad-plus-plus", "notepad_"): "notepad-plus-plus",
    ("notepad-plus-plus", "notepad++"): "notepad-plus-plus", ("don_ho", "notepad_"): "notepad-plus-plus", ("simon_tatham", "putty"): "putty", ("putty", "putty"): "putty",
    ("winscp", "winscp"): "winscp", ("filezilla-project", "filezilla_client"): "filezilla", ("filezilla-project", "filezilla"): "filezilla", ("videolan", "vlc_media_player"): "vlc",
    ("zoom", "zoom"): "zoom", ("zoom", "meetings"): "zoom", ("zoom", "zoom_client_for_meetings"): "zoom", ("teamviewer", "teamviewer"): "teamviewer", ("anydesk", "anydesk"): "anydesk",
    ("wireshark", "wireshark"): "wireshark", ("microsoft", "visual_studio_code"): "vscode", ("oracle", "jre"): "java", ("oracle", "jdk"): "java", ("oracle", "java_se"): "java",
    ("sun", "jre"): "java", ("sun", "jdk"): "java", ("oracle", "graalvm_for_jdk"): "java", ("openjdk", "openjdk"): "openjdk", ("python", "python"): "python",
    ("nodejs", "node.js"): "nodejs", ("nodejs", "node_js"): "nodejs", ("git-scm", "git"): "git", ("php", "php"): "php", ("perl", "perl"): "perl", ("openssl", "openssl"): "openssl",
    ("openbsd", "openssh"): "openssh", ("postgresql", "postgresql"): "postgresql", ("microsoft", "sql_server"): "mssql-server", ("oracle", "mysql"): "mysql",
    ("oracle", "mysql_server"): "mysql", ("mariadb", "mariadb"): "mariadb", ("redis", "redis"): "redis", ("mongodb", "mongodb"): "mongodb", ("apache", "http_server"): "apache-httpd",
    ("apache", "tomcat"): "apache-tomcat", ("f5", "nginx"): "nginx", ("nginx", "nginx"): "nginx", ("docker", "docker"): "docker-engine", ("mobyproject", "moby"): "docker-engine",
    ("docker", "desktop"): "docker-desktop", ("microsoft", ".net_framework"): "dotnet-framework", ("microsoft", "_net_framework"): "dotnet-framework",
    ("microsoft", ".net"): "dotnet-runtime", ("microsoft", "_net"): "dotnet-runtime", ("adobe", "acrobat_reader"): "adobe-acrobat-reader", ("adobe", "acrobat_reader_dc"): "adobe-acrobat-reader",
    ("adobe", "acrobat"): "adobe-acrobat", ("adobe", "acrobat_dc"): "adobe-acrobat", ("foxitsoftware", "foxit_reader"): "foxit-reader", ("foxit", "pdf_reader"): "foxit-reader",
    ("libreoffice", "libreoffice"): "libreoffice", ("documentfoundation", "libreoffice"): "libreoffice", ("linux", "linux_kernel"): "linux-kernel", ("gnu", "glibc"): "glibc",
    ("sudo_project", "sudo"): "sudo", ("todd_miller", "sudo"): "sudo", ("gnu", "bash"): "bash", ("haxx", "curl"): "curl", ("haxx", "libcurl"): "curl", ("tukaani", "xz"): "xz-utils",
    ("zlib", "zlib"): "zlib", ("systemd_project", "systemd"): "systemd", ("freedesktop", "systemd"): "systemd", ("polkit_project", "polkit"): "polkit", ("freedesktop", "polkit"): "polkit",
    ("samba", "samba"): "samba", ("isc", "bind"): "bind", ("exim", "exim"): "exim", ("postfix", "postfix"): "postfix", ("kaspersky", "endpoint_security"): "kaspersky-endpoint-security",
    ("microsoft", "office"): "microsoft-office", ("microsoft", "365_apps"): "microsoft-office", ("1c", "1c_enterprise"): "1c-enterprise", ("1c", "enterprise"): "1c-enterprise",
    ("crypto-pro", "cryptopro_csp"): "cryptopro-csp", ("cryptopro", "csp"): "cryptopro-csp",
}
