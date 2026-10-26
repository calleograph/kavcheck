"""Параметры отчётов: null в необязательных полях — значение по умолчанию (регрессия «Input should be a valid string» для params.zone)."""
import pytest

from app.api import schemas as S

ITEM = {"kind": "pattern", "name_like": "Telegram*", "op": "lt", "value": "7.3.3"}


REQUIRED = {"quick_zone": {"zone_ids": ["none"]}, "quick_vulns": {"cves": ["CVE-2024-0001"]}, "quick_extvulns": {"vuln_keys": ["CVE-2024-0001"]}, "quick_hosts": {"host_ids": [1]}}


def test_audit_params_zone_null_means_all_hosts():
    p = S.AuditParams.model_validate({"items": [ITEM], "zone": None, "active_days": None, "group_contains": None, "include_inactive": None, "online_only": None})
    assert p.zone == "" and p.include_inactive is False and p.online_only is False and p.active_days is None


@pytest.mark.parametrize("name", [n for n in S.QUICK_PARAMS])
def test_every_quick_report_accepts_null_for_every_optional_field(name):
    cls = S.QUICK_PARAMS[name]
    body = {k: None for k, f in cls.model_fields.items() if not f.is_required()}
    body.update(REQUIRED.get(name, {}))
    got = cls.model_validate(body)
    assert got is not None


def test_null_in_a_required_field_is_still_an_error():
    with pytest.raises(Exception):
        S.AuditParams.model_validate({"items": None})
