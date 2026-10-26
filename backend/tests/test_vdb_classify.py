"""Категории продуктов для аналитики уязвимостей: порядок признаков, роль вместо производителя, решение администратора, неоднозначные случаи."""
import pytest

from app.vdb.classify import CATEGORIES, classify


@pytest.mark.parametrize("name,pub,plat,eol,want", [
    ("Microsoft Windows 11 Pro", "Microsoft", 1, None, "os"),
    ("Windows Server 2019 Standard", "Microsoft", 1, None, "os"),
    ("Windows Software Development Kit", "Microsoft", 1, None, "system"),                 # не ОС
    ("linux-image-5.15.0-91-generic", "", 2, None, "os"),
    ("Microsoft Visual C++ 2015-2022 Redistributable (x64)", "Microsoft", 1, None, "system"),
    ("Microsoft .NET Runtime - 8.0.1 (x64)", "Microsoft", 1, None, "system"),
    ("Google Chrome", "Google LLC", 1, None, "application"),
    ("7-Zip 23.01", "Igor Pavlov", 1, None, "application"),
    ("openssl", "", 2, None, "system"),
    ("bash", "", 2, None, "system"),
    ("libssl3", "", 2, None, "system"),
    ("nginx", "", 2, None, "application"),                                                # серверное ПО на Linux — прикладное, а не пакет ОС
    ("PostgreSQL 15", "PostgreSQL Global Development Group", 1, "db", "application"),
    ("php8.1-cli", "", 2, "lang", "system"),                                              # среда выполнения
    ("Contoso Assistant", "Contoso", 1, None, "application"),
    ("Mystery", "", 0, None, "unclassified"),
])
def test_classification_by_role_not_by_vendor(name, pub, plat, eol, want):
    cat, basis = classify(name, pub, "", plat, False, eol)
    assert cat == want and basis, (name, cat, basis)


def test_admin_override_wins_and_has_explicit_basis():
    assert classify("PostgreSQL 15", "PG", "", 1, False, "db", override="system") == ("system", "решение администратора")
    assert classify("PostgreSQL 15", "PG", "", 1, False, "db", override="bogus")[0] == "application"      # неизвестная категория решения игнорируется


def test_every_result_is_one_of_four_categories():
    for n in ("", "x", "Linux", "Windows", "kernel", "lib", "Adobe Acrobat"):
        assert classify(n)[0] in CATEGORIES
