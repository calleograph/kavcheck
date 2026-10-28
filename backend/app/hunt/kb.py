"""Знания CVE Hunt о продуктах: названия, CPE, обычные порты, шаблоны названий в каталоге программ KSC, признаки версии в ответах сервисов.
Это не вторая база программ: продукты берутся из каталога KAV Checker и базы уязвимостей, здесь только подсказки по сетевому поиску (порты, как узнать версию)."""
from __future__ import annotations

import re

WEB = [80, 443, 8080, 8443]
KB: dict[str, dict] = {
    "php": {"title": "PHP", "aliases": ["php"], "cpe": [("php", "php")], "ports": WEB, "catalog": ["php"], "rx": [r"PHP/([0-9][\w.+~-]*)"], "presence": [r"X-Powered-By:\s*PHP\b", r"PHPSESSID="],
            "note": "PHP обычно работает за Apache или nginx и может не раскрывать версию в ответах сервера: сетевая проверка не даёт полного охвата, используйте и данные KSC."},
    "apache": {"title": "Apache HTTP Server", "aliases": ["apache httpd", "apache http server", "httpd"], "cpe": [("apache", "http_server")], "ports": WEB, "catalog": ["apache http server", "apache httpd"],
               "rx": [r"Apache/([0-9][\w.+~-]*)"], "note": "Версию может скрывать настройка ServerTokens."},
    "nginx": {"title": "nginx", "aliases": ["nginx"], "cpe": [("nginx", "nginx"), ("f5", "nginx")], "ports": WEB, "catalog": ["nginx"], "rx": [r"nginx/([0-9][\w.+~-]*)"],
              "note": "Версию может скрывать server_tokens off."},
    "openssh": {"title": "OpenSSH", "aliases": ["openssh"], "cpe": [("openbsd", "openssh")], "ports": [22], "catalog": ["openssh"], "rx": [r"OpenSSH[_ ]([0-9][\w.+~-]*)"],
                "note": "Часть CVE OpenSSH относится к клиенту (ssh, scp) и по сети на сервере не проверяется: у таких CVE результат — «Требует проверки» или совпадений нет."},
    "redis": {"title": "Redis", "aliases": ["redis key-value store", "redis"], "cpe": [("redislabs", "redis"), ("redis", "redis")], "ports": [6379], "catalog": ["redis"], "rx": [],
              "note": "Версия сообщается только при доступе к серверу без аутентификации."},
    "mssql": {"title": "Microsoft SQL Server", "aliases": ["microsoft sql server", "ms-sql"], "cpe": [("microsoft", "sql_server")], "ports": [1433], "catalog": ["microsoft sql server"], "rx": [],
              "note": "Версия определяется по ответу службы SQL Server; порт может быть нестандартным (динамические порты экземпляров)."},
    "bitrix": {"title": "1С-Битрикс", "aliases": ["bitrix", "1c-bitrix", "1с-битрикс"], "cpe": [("1c-bitrix", "1c-bitrix")], "ports": WEB, "catalog": ["1с-битрикс", "1c-bitrix", "bitrix"],
               "rx": [r"X-Powered-CMS:\s*Bitrix Site Manager(?:\s*\(\s*([0-9][\w.]*))?"], "note": "Версия платформы часто не раскрывается; признак присутствия — заголовок ответа."},
    "tomcat": {"title": "Apache Tomcat", "aliases": ["apache tomcat", "tomcat"], "cpe": [("apache", "tomcat")], "ports": [8080, 8443, 8009], "catalog": ["apache tomcat"], "rx": [r"Apache Tomcat/([0-9][\w.+~-]*)"], "note": ""},
    "mysql": {"title": "MySQL", "aliases": ["mysql"], "cpe": [("oracle", "mysql")], "ports": [3306], "catalog": ["mysql"], "rx": [], "note": ""},
    "postgresql": {"title": "PostgreSQL", "aliases": ["postgresql"], "cpe": [("postgresql", "postgresql")], "ports": [5432], "catalog": ["postgresql"], "rx": [], "note": ""},
}


def norm(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (t or "").lower()).strip("_")


def kb_for_text(text: str) -> str | None:
    """Ключ записи KB по названию продукта (каталог, название CPE): слово целиком, чтобы «php» не находилось в «phpmyadmin»."""
    t = (text or "").lower()
    for k, v in KB.items():
        for a in [k, *v["aliases"]]:
            if re.search(rf"(?<![a-z0-9]){re.escape(a)}(?![a-z0-9])", t):
                return k
    return None


def kb_for_cpe(vendor: str, product: str) -> str | None:
    for k, v in KB.items():
        if (norm(vendor), norm(product)) in [(norm(a), norm(b)) for a, b in v["cpe"]]:
            return k
    return None


def version_from_text(key: str, text: str) -> tuple[bool, str]:
    """(признак найден, версия) по ответам сервиса: баннер, заголовки, вывод скриптов."""
    for rx in KB.get(key, {}).get("rx", []):
        m = re.search(rx, text or "", re.I)
        if m:
            return True, (m.group(1) or "") if m.groups() else ""
    if any(re.search(rx, text or "", re.I) for rx in KB.get(key, {}).get("presence", [])):
        return True, ""                                                  # признак есть, версии нет
    return False, ""
