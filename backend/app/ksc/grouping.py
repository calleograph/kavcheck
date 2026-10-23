"""Правила логической группировки программ: один продукт = множество пакетов (PHP: php, php-common, php7.4-cli, php7.4-fpm …).
Встроенное правило PHP проверено на реальной базе KSC 15.1; пользовательские правила добавляются в административной панели."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import versions

PHP_NAME_LIKE = "%php%"
PHP_NAME_REGEX = r"^(php[0-9]+\.[0-9]+(-.+)?|php(-(cli|common|fpm|cgi))?|libapache2-mod-php[0-9.]*|php[0-9]+-php(-.+)?|rh-php[0-9]+(-php(-.+)?)?|PHP [0-9].*)$"
PHP_BRANCH_REGEX = r"^(?:php|libapache2-mod-php)(\d+\.\d+)(?:-|$)|^(?:rh-php|php)(\d)(\d)(?:-|$)"
PHP_DESCRIPTION = ("Пакеты самого PHP: ядро, CLI, FPM, CGI, модуль Apache и расширения веток phpX.Y-*. Ветка определяется по имени пакета (php7.4-xdebug → 7.4) "
                   "или по версии пакета (php7.1-cli 7.1.33 → 7.1). Метапакеты Debian с эпохой (php-common 2:70+…) ветки не имеют и показываются отдельно. "
                   "PhpStorm, Composer, WinCache, php-pecl-* и библиотеки в группу не входят.")

BUILTIN_RULES = [
    {"key": "php", "name": "PHP", "name_like": PHP_NAME_LIKE, "name_regex": PHP_NAME_REGEX, "branch_regex": PHP_BRANCH_REGEX, "branch_parts": 2,
     "exclude_regex": None, "description": PHP_DESCRIPTION},
]


@dataclass
class Rule:
    key: str
    name: str
    name_like: str
    name_regex: str
    branch_regex: str | None = None
    branch_parts: int = 2
    exclude_regex: str | None = None

    def __post_init__(self):
        self._name = re.compile(self.name_regex, re.I)
        self._branch = re.compile(self.branch_regex, re.I) if self.branch_regex else None
        self._exclude = re.compile(self.exclude_regex, re.I) if self.exclude_regex else None

    def matches(self, name: str) -> bool:
        return bool(self._name.search(name or "")) and not (self._exclude and self._exclude.search(name or ""))

    def compared_version(self, name: str, version: str) -> str:
        return versions.compared_version(name, version, self._branch)

    def branch(self, name: str, version: str) -> str:
        """Ветка продукта (major.minor): пусто — не определена достоверно (метапакет, нечисловая версия)."""
        cv = self.compared_version(name, version)
        return versions.branch_of(cv, self.branch_parts)


def validate_rule(name_regex: str, branch_regex: str | None, exclude_regex: str | None) -> None:
    for label, rx in (("name_regex", name_regex), ("branch_regex", branch_regex), ("exclude_regex", exclude_regex)):
        if rx:
            try:
                re.compile(rx, re.I)
            except re.error as exc:
                raise ValueError(f"{label}: некорректное регулярное выражение ({exc})") from None
