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
