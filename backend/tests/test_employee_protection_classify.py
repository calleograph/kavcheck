from datetime import datetime, timedelta, timezone

import pytest

from app.employee_protection.classify import DEVICE_LABELS, EMPLOYEE_LABELS, REASON_LABELS, device_status, employee_status
from app.ksc import protection as P

NOW = datetime(2026, 11, 24, 15, tzinfo=timezone.utc)


def device(*, state=3, bases=NOW, has_rtp=True, **fields):
    record = {"last_connected": NOW, "rtp_state": 7, "online": True,
              "av": {"state": state, "has_rtp": has_rtp, "bases": bases}, **fields}
    return device_status(record, NOW, activity_days=14)


@pytest.mark.parametrize(("fields", "status", "reason", "installed"), [
    ({}, "protected", "running", True),
    ({"av": None, "mask": 32}, "no_av", "no_av_reported", False),
    ({"av": None}, "unknown", "av_unknown", None),
    ({"mask": 32}, "unknown", "conflicting_product", None),
    ({"rtp_state": 9, "online": False}, "problems", "rtp_off", True),
    ({"state": 4, "online": False}, "problems", "rtp_off", True),
    ({"rtp_state": 1, "online": True}, "problems", "rtp_off", True),
    ({"rtp_state": 1, "online": False}, "unknown", "offline_stop", True),
    ({"mask": 16}, "problems", "rtp_policy", True),
    ({"mask": 512}, "problems", "license", True),
    ({"uncured": 3}, "problems", "infected", True),
    ({"mask": 128}, "problems", "bases_old", True),
    ({"bases": NOW - timedelta(days=4)}, "problems", "bases_old", True),
    ({"mask": 2048}, "problems", "reboot", True),
    ({"state": 2}, "unknown", "rtp_unknown", True),
    ({"rtp_state": 0}, "unknown", "rtp_unknown", True),
    ({"has_rtp": False}, "unknown", "rtp_unknown", True),
    ({"bases": None}, "unknown", "bases_unknown", True),
    ({"bases": NOW + timedelta(days=1)}, "unknown", "bases_unknown", True),
])
def test_current_ksc_evidence(fields, status, reason, installed):
    result = device(**fields)
    assert result == {"status": status, "reason": reason, "installed": installed, "freshness": "fresh"}
    assert status in DEVICE_LABELS and reason in REASON_LABELS


def test_old_or_missing_data_does_not_confirm_av_status():
    assert device(last_connected=None, av=None, mask=32) == {
        "status": "unknown", "reason": "no_contact", "installed": None, "freshness": "unknown",
    }
    for fields in ({"av": None, "mask": 32}, {}):
        assert device(last_connected=NOW - timedelta(days=15), **fields) == {
            "status": "stale", "reason": "old_contact", "installed": None, "freshness": "stale",
        }
    assert device(last_connected=NOW - timedelta(days=14, seconds=1))["status"] == "stale"
    assert device(last_connected=NOW - timedelta(days=14))["status"] == "protected"
    assert device(last_connected=NOW + timedelta(seconds=1))["status"] == "unknown"
    assert device_status({}, NOW, activity_days=14, snapshot_at=NOW - timedelta(days=15))["reason"] == "old_snapshot"
    assert device_status(None, NOW, activity_days=14)["status"] == "outside_ksc"
    assert device_status(None, NOW, activity_days=14, matched_ksc=True)["reason"] == "ksc_data_missing"


def test_product_record_uses_shared_ksc_mapping():
    record = P.record({"host_id": 1, "last_connected": NOW, "rtp_state": 4},
                      [{"code": "1103"}, {"code": "KES", "is_av": True, "has_rtp": True, "state": 3, "bases": NOW}], None, NOW)
    assert device_status(record, NOW, activity_days=14)["status"] == "protected"
    assert record["av"]["code"] == "KES"


def test_employee_groups_devices_without_conflating_sources_or_coverage():
    good = {"key": ("source-a", 1), **device()}
    bad = {"key": ("source-b", 1), **device(state=4)}
    no_av = {"key": ("source-b", 2), **device(av=None, mask=32)}
    insufficient = {"key": "inventory:1", **device_status(None, NOW, activity_days=14)}
    old = {"key": ("source-a", 2), **device(last_connected=NOW - timedelta(days=40))}
    both = employee_status([good, dict(good), bad, insufficient, old])
    assert both == {"status": "partial", "reason": "some_protected", "device_count": 4,
                    "installed_devices": 2, "protected_devices": 1, "uses_av": True, "freshness": "stale"}
    cases = [([good], "protected"), ([bad, insufficient], "problems"), ([no_av], "no_av"),
             ([insufficient], "outside_ksc"), ([old, insufficient], "stale"), ([no_av, insufficient], "unknown"),
             ([good, {**bad, "key": good["key"]}], "unknown"), ([], "no_devices")]
    for devices, expected in cases:
        result = employee_status(iter(devices))
        assert result["status"] == expected
        assert result["reason"] in REASON_LABELS and expected in EMPLOYEE_LABELS
    assert employee_status([insufficient])["freshness"] == "unknown"
    assert not employee_status([old])["uses_av"]
    assert employee_status([device(rtp_state=0)])["uses_av"]
