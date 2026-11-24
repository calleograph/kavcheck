from ipaddress import IPv4Address, ip_address
from uuid import uuid4

import pytest

from app.inventory import geography as G


@pytest.mark.parametrize(("ip", "scope"), [
    ("192.168.0.0", "private"),
    ("fc00::19", "private"),
    ("100.64.0.2", "shared"),  # private-data: ignore — пример RFC 6598
    ("192.0.2.19", "special"),
    ("2001:db8::19", "special"),
    ("224.0.0.1", "special"),
    ("ff02::19", "special"),
    ("fe80::19", "special"),
    ("fec0::19", "special"),
])
def test_special_and_nonpublic_connections_are_explained_but_not_used(ip, scope):
    evidence = {"addresses": [{"kind": "connection", "ip": ip}]}
    assert G.connection_observation(evidence)["scope"] == scope
    assert G.public_connection(evidence) == ""
    assert G.locate(evidence, uuid4(), None, [], lambda _: pytest.fail("Unexpected GeoIP lookup"))["status"] == "unknown"


def test_connection_is_deduplicated_and_keeps_provenance():
    at = "2026-11-24T12:00:00+00:00"
    evidence = {"addresses": [
        {"kind": "connection", "ip": "::ffff:192.168.0.0", "source": "v_akpub_host.nConnectionIp", "observed_at": at},
        {"kind": "connection", "ip": "192.168.0.0", "source": "Hosts.nIpPeer"},
    ]}
    assert G.connection_observation(evidence) == {
        "scope": "private", "ip": "192.168.0.0", "source": "v_akpub_host.nConnectionIp", "observed_at": at,
    }


def test_only_unambiguous_public_connection_can_be_used(monkeypatch):
    class PublicExample(IPv4Address):
        @property
        def is_global(self):
            return True

    monkeypatch.setattr(G, "ip_address", lambda ip: PublicExample(ip) if ip == "192.0.2.19" else ip_address(ip))
    evidence = {"addresses": [{"kind": kind, "ip": "192.0.2.19"} for kind in ("reported", "device", "discovered")]}
    assert G.connection_observation(evidence) == {"scope": "missing"}
    assert G.public_connection(evidence) == ""

    evidence["addresses"].append({"kind": "connection", "ip": "192.0.2.19"})
    assert G.connection_observation(evidence)["scope"] == "public"
    assert G.public_connection(evidence) == "192.0.2.19"

    evidence["addresses"].append({"kind": "connection", "ip": "192.168.0.0"})
    assert G.connection_observation(evidence) == {"scope": "ambiguous"}
    assert G.public_connection(evidence) == ""
