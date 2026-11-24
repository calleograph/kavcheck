import re

from app.ksc import guard, network


async def test_network_read_keeps_queries_bounded_and_optional_columns_out():
    class PublicOnly:
        sizes: list[int] = []

        async def run(self, sql, *, max_rows):
            guard.check(sql)
            assert "dbo.Hosts" not in sql and "nConnectionIp" not in sql
            ids = [int(i) for i in re.search(r"h\.nId IN \(([^)]+)\)", sql).group(1).split(",")]
            self.sizes.append(len(ids))
            assert len(ids) == max_rows
            return [{"host_id": i, "name": f"ws-{i}", "dns_domain": "example.local", "win_domain": None, "group_id": 1,
                     "connection": None, "peer": None, "reported": -1073741211, "device": None, "discovered": None,
                     "last_connected": None, "last_info_update": None, "last_visible": None} for i in ids]

    client = PublicOnly()
    result = await network.read(client, [*range(1, 1602), 5], frozenset())
    assert client.sizes == [500, 500, 500, 101] and len(result) == 1601
    assert result[5]["addresses"] == [{"kind": "reported", "ip": "192.0.2.101", "source": "v_akpub_host.nIp", "observed_at": None}]
    assert result[5]["network_id"] is None and result[5]["interfaces"] == []
