import re

from app.ksc import versions
from app.ksc.grouping import PHP_BRANCH_REGEX, PHP_NAME_REGEX, Rule


def test_compare_pairs():
    for a, b in (("8.9", "8.10"), ("1.0~rc1", "1.0"), ("2.0", "1:0.1"), ("7.1.33-2+0~2019", "7.1.33-14+0~2020"), ("120.0.6099.130", "120.0.6099.200")):
        assert versions.compare(a, b) < 0, (a, b)
        assert versions.compare(b, a) > 0
    assert versions.compare("8.1", "8.1") == 0


def test_upstream_and_branch():
    assert versions.upstream("2:8.1+92ubuntu1") == "8.1+92ubuntu1"
    assert versions.upstream("7.1.33-14+0~20200320.35+debian9~1.gbpb15fae") == "7.1.33"
    assert versions.branch_of("7.1.33") == "7.1"
    assert versions.branch_of("2:70+debian") == ""          # метапакет: ветка не определена
    assert versions.branch_of("8") == ""


def test_range_7x():
    ok = lambda v: versions.in_range(versions.upstream(v), "7", None, "8")
    assert ok("7.4.33-1") and ok("7.100") and not ok("8.0.1") and not ok("6.9")


def test_php_rule():
    rule = Rule("php", "PHP", "%php%", PHP_NAME_REGEX, PHP_BRANCH_REGEX)
    assert rule.matches("php7.1-cli") and rule.matches("php") and rule.matches("libapache2-mod-php8.1") and rule.matches("php74-php-cli") and rule.matches("PHP 7.4.33")
    assert not rule.matches("PhpStorm 2023.2") and not rule.matches("php-pecl-redis") and not rule.matches("Composer")
    assert rule.compared_version("php7.4-xdebug", "3.2.1-1") == "7.4"       # версия расширения → ветка из имени
    assert rule.compared_version("php7.1-cli", "7.1.33-14+0~2020") == "7.1.33"
    assert rule.branch("php7.1-cli", "7.1.33-14") == "7.1"
    assert rule.branch("php8.1-redis", "6.0.2") == "8.1"
    assert rule.branch("php-common", "2:70+debian") == ""
    assert rule.branch("php", "2:8.3+93ubuntu2") == "8.3"
    assert re.compile(PHP_NAME_REGEX, re.I).match("rh-php73-php-cli")


def test_numeric_scheme():
    cn = versions.compare_numeric
    assert cn("130", "130.0.0.0") == 0 and cn("124.0.6367.60", "130") < 0 and cn("130.0.1", "130") > 0
    assert cn("1.1.1w", "1.1.1") > 0 and cn("1.0rc1", "1.0") < 0 and cn("9.6p1", "9.7") < 0
    assert cn("24.002.20736", "24.2.20736") == 0             # Adobe: 002 = 2


def test_transforms_and_conditions():
    assert versions.transform("8.0.4010.7", "java") == "8.0.401" and versions.transform("1.8.0.392", "java") == "8.0.392"
    assert versions.transform("3.12.3150.0", "python") == "3.12.3"
    assert versions.matches("124.0.6367.60", "lt", "130") and not versions.matches("130.0.6723.58", "lt", "130")
    assert versions.matches("130.0.6723.58", "le", "131") and versions.matches("130", "eq", "130.0") and versions.matches("131.1", "gt", "131")
    assert versions.matches("120.5", "range", vmin="100", vmax="125") and not versions.matches("126", "range", vmin="100", vmax="125")
    # dpkg: без ревизии сравнивается upstream, граница с ревизией — полная версия
    assert not versions.matches("7.4.33-1+deb11u4", "lt", "7.4.33", scheme="dpkg")
    assert versions.matches("7.4.33-1+deb11u4", "lt", "7.4.33-1+deb11u5", scheme="dpkg")
    assert versions.matches("1:9.2p1-2", "lt", "9.3", scheme="dpkg")
    assert versions.excluded("115.10.0", ["115"]) and not versions.excluded("1150.1", ["115"]) and versions.excluded("7.4.33", ["7.4.*"])
    assert versions.condition_text("lt", "130") == "ниже 130" and versions.condition_text("range", vmin="1", vmax="2") == "от 1 до 2 включительно"


def test_catalog_classification():
    from app.ksc import catalog as C

    k = lambda n, m=1: C.classify(n, m).key  # noqa: E731
    assert k("Google Chrome") == k("google-chrome-stable", 2) == "google-chrome"
    assert k("Mozilla Firefox (x64 ru)") == k("Mozilla Firefox ESR (x64 ru)") == "mozilla-firefox" and k("Mozilla Maintenance Service") != "mozilla-firefox"
    assert k("7-Zip 23.01 (x64)") == k("7-Zip 9.20") == "7-zip"
    assert k("Python 3.12.3 Core Interpreter (64-bit)") == k("python3.11-minimal", 2) == "python" and k("Python Launcher") != "python"
    assert k("libssl3", 2) == k("openssl", 2) == "openssl" and k("openssh-server", 2) == "openssh"
    assert k("PhpStorm 2024.1") != "php" and k("php7.4-cli", 2) == "php"
    assert k("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135") == k("Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33135")
    assert k("base-files", 2) == "pkg:base-files"
    d = C.BUILTIN_BY_KEY
    assert C.branch(d["postgresql"], "PostgreSQL 9.6", "9.6.24", "numeric") == "9.6" and C.branch(d["postgresql"], "postgresql-14", "14.11-1", "dpkg") == "14"
    assert C.branch(d["mssql-server"], "SQL Server 2019 Database Engine Services", "15.0.4345.5", "numeric") == "2019"
    assert C.compared_version(d["dotnet-runtime"], "Microsoft .NET Runtime - 8.0.4 (x64)", "64.16.31012", "numeric") == "8.0.4"
    assert C.publisher_key("Google LLC") == C.publisher_key("Google Inc.") == "google"
    assert C.clean_publisher("Debian PHP Maintainers <team@example.org>") == "Debian PHP Maintainers"
