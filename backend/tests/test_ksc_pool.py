"""Пул простаивающих соединений SourceClient: соединение переиспользуется, разорванное из пула заменяется повтором, ошибки не повторяются зря."""
import pytest

from app.ksc import driver
from app.ksc.driver import ConnParams, KscError, SourceClient

P = ConnParams(host="ksc.example.local", port=1433, database="KAV", username="u", password="p")


class Conn:
    def __init__(self, n):
        self.n, self.closed = n, False

    def close(self):
        self.closed = True


@pytest.fixture
def pool(monkeypatch):
    made: list[Conn] = []
    calls: list[int] = []
    behaviour = {"fail": set()}                       # номера соединений, на которых запрос падает

    def fake_connect(_p):
        made.append(Conn(len(made)))
        return made[-1]

    def fake_query(conn, sql, params=None, *, max_rows):
        calls.append(conn.n)
        if conn.n in behaviour["fail"]:
            raise RuntimeError("Connection reset")
        return [{"n": conn.n}] * (max_rows + 1 if "BIG" in sql else 1)

    monkeypatch.setattr(driver, "connect", fake_connect)
    monkeypatch.setattr(driver, "query", fake_query)
    return SourceClient(P, concurrency=2, name="t"), made, calls, behaviour


def test_connection_is_reused_between_queries(pool):
    cl, made, calls, _ = pool
    for _ in range(5):
        assert cl.run_sync("SELECT 1", max_rows=10) == [{"n": 0}]
    assert len(made) == 1 and calls == [0] * 5                                  # одно подключение на пять запросов


def test_broken_pooled_connection_is_replaced_once(pool):
    cl, made, calls, beh = pool
    cl.run_sync("SELECT 1", max_rows=10)
    beh["fail"] = {0}                                                           # сервер закрыл соединение, пока оно простаивало
    assert cl.run_sync("SELECT 1", max_rows=10) == [{"n": 1}]
    assert made[0].closed and len(made) == 2 and calls == [0, 0, 1]


def test_error_on_fresh_connection_is_not_retried_and_not_pooled(pool):
    cl, made, calls, beh = pool
    beh["fail"] = {0}
    with pytest.raises(KscError) as e:
        cl.run_sync("SELECT 1", max_rows=10)
    assert e.value.code == "query" and calls == [0] and made[0].closed          # настоящая ошибка запроса — без повторов
    assert cl.run_sync("SELECT 1", max_rows=10) == [{"n": 1}]                  # следующий запрос — на новом соединении


def test_truncated_result_does_not_return_connection_to_pool(pool):
    cl, made, _calls, _ = pool
    with pytest.raises(KscError) as e:
        cl.run_sync("SELECT BIG", max_rows=3)
    assert e.value.code == "too_many_rows" and made[0].closed
    cl.run_sync("SELECT 1", max_rows=10)
    assert len(made) == 2


def test_idle_connection_expires(pool, monkeypatch):
    cl, made, _calls, _ = pool
    cl.run_sync("SELECT 1", max_rows=10)
    t = driver.time.monotonic()
    monkeypatch.setattr(driver.time, "monotonic", lambda: t + driver.IDLE_TTL_S + 1)
    cl.run_sync("SELECT 1", max_rows=10)
    assert len(made) == 2 and made[0].closed


def test_forbidden_query_never_connects(pool):
    cl, made, _calls, _ = pool
    with pytest.raises(Exception):
        cl.run_sync("DELETE FROM dbo.x", max_rows=10)
    assert made == []


def test_pool_size_is_bounded(pool):
    cl, made, _calls, _ = pool
    conns = [Conn(i) for i in range(5)]
    for c in conns:
        cl._give(c)
    assert len(cl._idle) == 2 and sum(c.closed for c in conns) == 3
    cl.close()
    assert not cl._idle and all(c.closed for c in conns)
