import re

import pytest

from app.ksc import guard, queries


def test_templates_pass_guard():
    for name in dir(queries):
        v = getattr(queries, name)
        if isinstance(v, str) and name.isupper() and v.strip().upper().startswith(("SELECT", "WITH")):   # фрагменты условий (… _EXISTS, _FROM) — не запросы
            sql = v.replace("{where}", "1 = 1").replace("{order}", "p.nId").replace("{ids}", "1").replace("{names}", "N'x'")
            guard.check(re.sub(r"\{[a-z_]+\}", "", sql))


@pytest.mark.parametrize("sql", ["DELETE FROM dbo.Hosts", "SELECT 1; DROP TABLE x", "UPDATE dbo.Hosts SET a = 1", "SELECT * INTO t FROM dbo.Hosts", "EXEC sp_who",
                                 "SELECT 1 -- comment\nWAITFOR DELAY '0:0:5'", "with x as (select 1) select * from x; select 2"])
def test_guard_rejects(sql):
    with pytest.raises(guard.UnsafeQuery):
        guard.check(sql)


def test_ids_list_only_ints():
    assert queries.ids_list([1, "2", 3]) == "1, 2, 3"
    with pytest.raises(ValueError):
        queries.ids_list(["1 OR 1=1"])
    with pytest.raises(ValueError):
        queries.ids_list([])
