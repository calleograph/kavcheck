from datetime import datetime, timedelta, timezone

from app.ksc import hosts as H


def test_activity_thresholds():
    now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    assert H.activity(None, now) == (None, "нет подключений Агента")
    assert H.activity(now - timedelta(hours=5), now)[1] == "≤1 сут"
    assert H.activity(now - timedelta(days=6), now)[1] == "≤7 сут"
    assert H.activity(now - timedelta(days=45), now)[1] == ">30 сут"
    days, _ = H.activity(now - timedelta(days=6), now)
    assert days == 6.0


def test_ip_and_group_path():
    assert H.ip_str(0xAC1E0A21) == "172.30.10.33"     # первый октет в старшем байте
    assert H.ip_str(0) == ""
    groups = {0: {"name": "Управляемые устройства", "parent_id": 2}, 5: {"name": "Серверы", "parent_id": 0}, 7: {"name": "Web", "parent_id": 5}}
    assert H.group_path(groups, 7) == "Управляемые устройства / Серверы / Web"
    assert H.group_path(groups, 99) == ""


def test_hosts_where_filters():
    where, params = H.hosts_where(qtext="web", active_days=7)
    assert "h.bIsSlaveServer = 0" in where and "DATEADD(day, -%(days)s" in where and params == {"q0": "%web%", "days": 7}
    where, params = H.hosts_where(active_days=7, inactive_only=True)
    assert "IS NULL OR" in where
