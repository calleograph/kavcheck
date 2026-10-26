"""Столбцы «Уязвимостей» и «Из них в каталоге CISA KEV» в таблице «Компьютеры» отчёта по внешним базам: единица подсчёта — уникальная уязвимость, KEV — подмножество."""
from app.reports.quick_ext import summarize_hosts


def row(host, vuln, install, kev=False, status="confirmed"):
    return {"host_id": host, "name": f"srv{host}.example.local", "ip": "192.0.2.1", "os": "Linux", "group": "g", "last_connected": None, "active": True, "online": True, "rank": 4 if kev else 3,
            "vuln_key": vuln, "kev": "да" if kev else "", "status": status, "program": "linux-image", "installed_version": "5.15", "product_id": install}


def test_kev_is_subset_of_unique_vulns_when_one_vuln_hits_many_installs():
    # Linux-сервер: 4 уязвимости, каждая на 4 установленных пакетах (ядро, заголовки, модули, инструменты) → 16 строк обнаружений; в KEV две из четырёх
    out = [row(1, f"CVE-2099-{n}", pid, kev=n <= 2) for n in range(1, 5) for pid in range(100, 104)]
    (h,) = summarize_hosts(out)
    assert h["vulns"] == 4 and h["kev_n"] == 2 and h["confirmed"] == 4 and h["rows"] == 16
    assert h["kev_n"] <= h["vulns"] and h["confirmed"] <= h["vulns"]
    assert h["kev_list"] == "CVE-2099-1, CVE-2099-2" and h["vuln_list"] == "CVE-2099-1, CVE-2099-2, CVE-2099-3, CVE-2099-4"
    assert "kev" not in h                                    # множества в строку отчёта не попадают (она сериализуется в JSON)


def test_host_without_kev_and_long_lists_are_capped():
    out = [row(2, f"CVE-2099-{n:03d}", 1, kev=True) for n in range(30)]
    (h,) = summarize_hosts(out)
    assert h["kev_n"] == 30 and h["kev_list"].endswith("и ещё 18") and h["vuln_list"].endswith("и ещё 10")
    (z,) = summarize_hosts([row(3, "CVE-2099-1", 1)])
    assert z["kev_n"] == 0 and z["kev_list"] == ""
