"""Правила раздела «Состояние защиты» и разбор событий безопасности (без базы KSC)."""
from datetime import datetime, timedelta, timezone

from app.ksc import events, protection

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def rec(**kw):
    base = {"av": {"code": "KES", "product": "Kaspersky Endpoint Security for Windows", "build": "12.6.0.438", "state": 3, "state_label": "запущен",
                   "bases": NOW - timedelta(hours=5), "has_rtp": True}, "rtp_state": 4, "mask": 0, "uncured": 0, "last_full_scan": NOW - timedelta(days=2)}
    return {**base, **kw}


def test_problems():
    p = lambda r: protection.problems(r, NOW, bases_days=3, scan_days=30)   # noqa: E731
    assert p(rec()) == []
    assert p(rec(av=None, last_full_scan=None)) == ["no_av"]                  # без антивируса не проверяем базы и проверку
    assert p(rec(rtp_state=9)) == ["rtp_off"] and p(rec(mask=4)) == ["rtp_off"]
    assert p(rec(av={**rec()["av"], "state": 0, "bases": NOW - timedelta(days=4)})) == ["rtp_off", "bases_old"]
    assert p(rec(av={**rec()["av"], "bases": None})) == ["bases_old"]
    assert p(rec(mask=512 | 2048 | 1024, last_full_scan=None)) == ["infected", "license", "scan_old", "reboot"]   # порядок — по важности
    assert protection.problems(rec(av={**rec()["av"], "bases": NOW - timedelta(days=4)}), NOW, bases_days=7, scan_days=30) == []


def test_versions_newest_first():
    recs = [rec(av={**rec()["av"], "build": b}, agent_build="15.1.0.20748") for b in ("12.4.0.467", "12.10.0.1001", "12.4.0.467")]
    v = protection.versions(recs)
    assert v[0]["latest"] == "12.10.0.1001" and v[0]["versions"] == [{"build": "12.10.0.1001", "hosts": 1}, {"build": "12.4.0.467", "hosts": 2}]
    assert v[-1]["code"] == "1103" and v[-1]["hosts"] == 3


def test_event_row_and_where():
    a = events.event_row({"event_id": 1, "type": "GNRL_EV_ATTACK_DETECTED", "par1": "Scan.Generic.PortScan.TCP", "par2": "TCP", "par3": "3325256824", "par4": "22"})
    assert (a["type"], a["threat"], a["attacker"], a["port"]) == ("attack", "Scan.Generic.PortScan.TCP", "198.51.100.120", "22")
    d = events.event_row({"event_id": 2, "type": "GNRL_EV_VIRUS_FOUND", "par2": r"C:\x.exe", "par5": "EICAR-Test-File", "par7": r"EXAMPLE\user", "par8": "61"})
    assert (d["type_title"], d["object"], d["threat_kind"]) == ("Обнаружена угроза", r"C:\x.exe", "троянская программа")
    w, p = events.where(days=7, types=["bogus'; DROP"], host_id=5, qtext="x", threat="")
    assert "DROP" not in w and "GNRL_EV_VIRUS_FOUND" in w and p == {"hours": 168, "host": 5, "q": "%x%"}   # неизвестный тип — все типы, строки только параметрами
