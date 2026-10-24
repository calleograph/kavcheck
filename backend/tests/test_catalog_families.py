"""Семейства каталога: основной продукт и связанные компоненты — универсально по названию, без правил под конкретные программы;
выдача «только основные» и состав семейства; пункт проверки из нескольких продуктов каталога."""
import uuid

from app.ksc.catalog_build import families, name_tokens
from app.models import CatalogProduct, KscSource
from app.services import catalog as svc


def _p(key: str, name: str) -> dict:
    return {"key": key, "name": name}


def test_name_tokens():
    assert name_tokens("php8.3-xml") == ("php", "xml")
    assert name_tokens("Microsoft Office Proofing Tools 2016 (x64)") == ("microsoft", "office", "proofing", "tools")
    assert name_tokens("7-Zip 24.08 (x64)") == ("7", "zip")                        # число в начале — часть названия
    assert name_tokens("1С:Предприятие 8 (8.3.22.2283)") == ("1с", "предприятие")


def test_families_universal():
    ps = [_p("php", "PHP"), _p("php-xml", "php-xml"), _p("php-pear", "php-pear"), _p("php8-3-gd", "php8.3-gd"), _p("phpstorm", "PhpStorm 2024.1"),
          _p("microsoft-office", "Microsoft Office"), _p("office-proofing", "Microsoft Office Proofing Tools 2016 - Русский"),
          _p("microsoft-edge", "Microsoft Edge"), _p("microsoft-visual-c", "Microsoft Visual C++ 2015-2022 Redistributable (x64)"),
          _p("google-chrome", "Google Chrome"), _p("google-update", "Google Update Helper"), _p("java", "Java (Oracle)"), _p("java-auto-updater", "Java Auto Updater"),
          _p("1c-enterprise", "1С:Предприятие 8"), _p("1c-thin", "1С:Предприятие 8 Тонкий клиент"), _p("7-zip", "7-Zip"), _p("zip-archiver", "Zip Archiver"),
          _p("trueconf-client", "TrueConf Client")]
    families(ps)
    fam = {p["key"]: p["family_key"] for p in ps}
    assert {k for k, f in fam.items() if f == "php"} == {"php", "php-xml", "php-pear", "php8-3-gd"}          # PhpStorm — не компонент PHP
    assert fam["office-proofing"] == "microsoft-office" and fam["java-auto-updater"] == "java" and fam["1c-thin"] == "1c-enterprise"
    assert fam["microsoft-edge"] == "microsoft-edge" and fam["microsoft-visual-c"] == "microsoft-visual-c" and fam["google-update"] == "google-update"
    assert fam["zip-archiver"] == "zip-archiver" and fam["trueconf-client"] == "trueconf-client"
    size = {p["key"]: p["family_size"] for p in ps}
    assert size["php"] == 4 and size["php-xml"] == 1 and size["microsoft-office"] == 2 and size["google-chrome"] == 1


async def test_roots_family_and_multi_product_items(app):
    sid = uuid.uuid4()
    ver = lambda pid: [{"version": "1", "branch": "1", "scheme": "dpkg", "platform": 2, "installs": 1, "installs_active": 1, "hosts": 1, "hosts_active": 1,  # noqa: E731
                        "product_ids": [pid], "raw": ["1"], "names": ["x"]}]
    async with app.state.session_maker() as db:
        db.add(KscSource(id=sid, name="Тест", host="sql.example.local", port=1433, database="KAV", auth_type="sql", username="ro", tls_mode="require"))
        await db.flush()
        for i, (key, name, fam, size, hosts) in enumerate((("php", "PHP", "php", 3, 50), ("php-xml", "php-xml", "php", 1, 40), ("php-gd", "php-gd", "php", 1, 30),
                                                           ("google-chrome", "Google Chrome", "google-chrome", 1, 90))):
            db.add(CatalogProduct(source_id=sid, key=key, name=name, publisher="", publisher_key="", origin="auto", component=False, family_key=fam, family_size=size,
                                  platforms=2, names=[[name, 1]], versions=ver(100 + i), branches=[], versions_count=1, latest_version="1", scheme="dpkg",
                                  hosts_all=hosts, hosts_active=hosts, installs_all=hosts, installs_active=hosts, search=name.lower()))
        await db.commit()
        roots = await svc.query(db, sid, roots=True)
        assert [i["key"] for i in roots["items"]] == ["google-chrome", "php"] and roots["items"][1]["family_size"] == 3
        members = await svc.query(db, sid, family="php")
        assert [i["key"] for i in members["items"]] == ["php-xml", "php-gd"]
        found = await svc.query(db, sid, q="xml")
        assert found["items"][0]["family_name"] == "PHP"                           # компонент в поиске — с названием семейства
        items, missing = await svc.resolve_items(db, sid, [{"kind": "product", "product_keys": ["php", "php-xml", "php-gd"]}, {"kind": "product", "product_key": "nope"}])
    assert items[0]["product_ids"] == [100, 101, 102] and items[0]["pid_product"][101] == "php-xml" and items[0]["product_name"] == "PHP и ещё 2"
    assert missing == ["nope"]


def test_numbered_names_are_not_families():
    """Разные программы, названия которых отличаются только номером, — не семейство (ключ разбирается так же, как название)."""
    ps = [_p("служебная-программа-1", "Служебная программа 1 1.0"), _p("служебная-программа-106", "Служебная программа 106 2.6"),
          _p("visual-c-2010", "Microsoft Visual C++ 2010 Redistributable"), _p("visual-c-2015-2022", "Microsoft Visual C++ 2015-2022 Redistributable")]
    families(ps)
    assert all(p["family_key"] == p["key"] and p["family_size"] == 1 for p in ps)
