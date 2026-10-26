"""Правила жизненного цикла на настоящих данных endoflife.date (срез API v1 от 26.10.2026, tests/fixtures/eol_sample.json): EOL только при окончании всей применимой поддержки,
ветка по версии (PHP 7.4.16 → 7.4), ОС — по сборке и редакции, нет данных — нет EOL."""
import json
from datetime import date
from pathlib import Path
from types import SimpleNamespace

from app.eol.classify import classify, pick_release, version_forms
from app.eol.osmatch import os_release

TODAY = date(2026, 10, 26)
DOC = json.loads((Path(__file__).parent / "fixtures" / "eol_sample.json").read_text(encoding="utf-8"))
PROD = {p["name"]: p for p in DOC["result"]}


def rel(product: str, name: str) -> SimpleNamespace:
    r = next(x for x in PROD[product]["releases"] if x["name"] == name)
    d = lambda k: date.fromisoformat(r[k]) if r.get(k) else None  # noqa: E731
    return SimpleNamespace(eol_from=d("eolFrom"), eoas_from=d("eoasFrom"), eoes_from=d("eoesFrom"), eol_flag=r.get("isEol"), eoes_flag=r.get("isEoes"), latest_name=(r.get("latest") or {}).get("name"), name=name)


def status(product: str, name: str) -> str:
    return classify(rel(product, name), PROD[product]["labels"], TODAY).status


def test_php_branch_is_selected_by_version_not_by_latest():
    names = [r["name"] for r in PROD["php"]["releases"]]
    assert pick_release(names, "7.4.16") == "7.4" and pick_release(names, "8.3.2") == "8.3" and pick_release(names, "5.6.40") == "5.6"
    assert pick_release(names, "7.40.1") is None and pick_release(names, "") is None and pick_release(names, "nonsense") is None
    assert status("php", "7.4") == "eol" and status("php", "8.3") == "supported" and status("php", "8.5") == "supported"


def test_eol_needs_all_support_ended_and_extended_support_is_not_unconditional_eol():
    assert status("ubuntu", "22.04") == "supported"                 # LTS: стандартная поддержка до 2027
    cl = classify(rel("ubuntu", "20.04"), PROD["ubuntu"]["labels"], TODAY)
    assert cl.status == "extended" and cl.severity == "high" and not cl.confirmed and "Expanded Security Maintenance" in cl.condition and "2030" in cl.condition
    assert status("ubuntu", "22.10") == "eol" and classify(rel("ubuntu", "22.10"), PROD["ubuntu"]["labels"], TODAY).severity == "critical"
    assert status("windows-server", "2012") == "eol"                 # ESU закончился 13.10.2026
    assert status("windows-server", "2016") == "upcoming" and status("windows-server", "2019") == "supported"          # 2016: 12.01.2027 — менее 180 суток
    assert status("debian", "10") == "extended" and status("debian", "8") == "eol"
    assert status("windows", "10-22h2") == "extended"                # Windows 10 22H2: ESU до 2028 — платная программа
    assert status("postgresql", "13") == "eol" and status("postgresql", "17") == "supported"
    assert status("nodejs", "21") == "eol" and status("nodejs", "22") == "supported"


def test_upcoming_and_unknown_dates_never_become_eol():
    soon = classify(rel("postgresql", "14"), PROD["postgresql"]["labels"], TODAY)             # 12.11.2026 — через 17 суток
    assert soon.status == "upcoming" and soon.severity == "warning" and "17" in soon.condition
    none_date = SimpleNamespace(eol_from=None, eoas_from=None, eoes_from=None, eol_flag=None, eoes_flag=None)
    assert classify(none_date, {}, TODAY).status == "unknown" and classify(none_date, {}, TODAY).severity == ""
    no_end = SimpleNamespace(eol_from=None, eoas_from=None, eoes_from=None, eol_flag=False, eoes_flag=None)
    assert classify(no_end, {}, TODAY).status == "supported"
    flag_only = SimpleNamespace(eol_from=None, eoas_from=None, eoes_from=None, eol_flag=True, eoes_flag=None)
    assert classify(flag_only, {}, TODAY).status == "eol"            # API сообщает «закончилось» без даты — это известный факт, а не отсутствие данных


def test_version_forms_and_java_branches():
    assert version_forms("1.8.0_391") == ["1.8.0_391", "8"] and version_forms("8u391") == ["8u391", "8"] and version_forms("v2.1")[0] == "2.1" and version_forms("1:7.4.3-4")[0] == "7.4.3-4"
    names = [r["name"] for r in PROD["oracle-jdk"]["releases"]]
    assert pick_release(names, "1.8.0_391") == "8" and pick_release(names, "17.0.9") == "17"


def test_windows_server_ubuntu_debian_rhel_by_name():
    win = [{"name": r["name"], "latest_name": (r.get("latest") or {}).get("name")} for r in PROD["windows"]["releases"]]
    h = os_release("Microsoft Windows Server 2012 R2 Standard")
    assert (h.product, h.release) == ("windows-server", "2012-r2") and os_release("Microsoft Windows Server 2019 Datacenter").release == "2019"
    assert os_release("Ubuntu 24.04 LTS").release == "24.04" and os_release("Ubuntu 20.04.6 LTS").release == "20.04"
    assert os_release("Debian GNU/Linux 12 (bookworm)").release == "12" and os_release("Debian 11").release == "11"
    assert os_release("Red Hat Enterprise Linux 8.9 (Ootpa)").release == "8" and os_release("CentOS Linux 7 (Core)").product == "centos"
    assert os_release("CentOS Stream 9").product == "centos-stream" and os_release("AlmaLinux 9.3").release == "9" and os_release("Rocky Linux 8.8").product == "rocky-linux"
    for unknown in ("Linux", "", "Astra Linux (Smolensk) 1.7", "Microsoft Windows Server", "Windows"):
        assert os_release(unknown, 6, 8, 0, windows_releases=win) is None, unknown


def test_windows_client_release_by_build_and_edition():
    win = [{"name": r["name"], "latest_name": (r.get("latest") or {}).get("name")} for r in PROD["windows"]["releases"]]
    pro = os_release("Microsoft Windows 11 Pro", 10, 0, 22631, windows_releases=win)
    assert (pro.product, pro.release, pro.confidence) == ("windows", "11-23h2-w", "high")
    ent = os_release("Microsoft Windows 11 Enterprise", 10, 0, 22631, windows_releases=win)
    assert ent.release == "11-23h2-e"
    assert os_release("Microsoft Windows 10 Pro", 10, 0, 19045, windows_releases=win).release == "10-22h2"
    unk = os_release("Microsoft Windows 11", 10, 0, 22631, windows_releases=win)
    assert unk.release == "11-23h2-w" and unk.confidence == "name"           # редакция не названа — выбор помечен как неуверенный
    assert os_release("Microsoft Windows 11 Pro", 10, 0, 0, windows_releases=win) is None and os_release("Microsoft Windows 11 Pro", 10, 0, 99999, windows_releases=win) is None
    # 23H2 для Pro закончилась 11.11.2025; для Enterprise — 10.11.2026 (ещё действует)
    assert status("windows", "11-23h2-w") == "eol" and status("windows", "11-23h2-e") == "upcoming"
