"""Доменный вход по LDAPS: короткое имя учётной записи, поиск во всех доменах с выбором домена, коды результата поиска,
отключённые переходы по ссылкам, причины отказа для администратора, одинаковые имена в разных доменах, локальный вход без каталога."""
import uuid

import pytest
from sqlalchemy import select

from app.auth import ldap as L
from app.auth.ldap import LdapConfig, LdapError, LdapIdentity, parse_login, user_filter
from app.models import AccessRule, AuditLog, LdapConnection, User
from tests.conftest import login

H = {"Origin": "http://testserver"}
GROUP = "cn=kav-analysts,ou=groups,dc=example,dc=local"


def test_login_names_and_filter():
    for ok in ("ivan.petrov", "anna-maria.k", "ivan_petrov2", "ivan.petrov-2", "EXAMPLE\\ivan.petrov", "ivan.petrov@example.local"):
        parse_login(ok)
    for bad in ("", "a*b", "(x)", "x\\y\\z", ".lead", "a@b@c", "a b"):
        with pytest.raises(LdapError):
            parse_login(bad)
    cfg = LdapConfig(user_filter="(&(objectCategory=person)(objectClass=user))", domain_dns="example.local")
    assert user_filter(cfg, "ivan.petrov") == "(&(&(objectCategory=person)(objectClass=user))(sAMAccountName=ivan.petrov))"
    assert "(sAMAccountName=ivan.petrov)" in user_filter(cfg, "ivan.petrov@example.local")           # логин@домен этого подключения
    assert user_filter(LdapConfig(user_filter="(&(objectClass=user)(sAMAccountName={login}))"), "EXAMPLE\\ivan.petrov") == "(&(objectClass=user)(sAMAccountName=ivan.petrov))"


class _Svc:
    def __init__(self, code: int, n: int, referrals=None):
        self.result = {"result": code, "description": "x", "referrals": referrals}
        self.response = [{"type": "searchResEntry", "dn": f"CN=u{i},DC=example,DC=local", "attributes": {}} for i in range(n)]

    def search(self, *a, **k):
        return True


def test_search_result_codes():
    cfg = LdapConfig(base_dn="DC=example,DC=local")
    assert L._find(_Svc(0, 1), cfg, "ivan.petrov")["dn"].startswith("CN=u0")
    for svc, code in ((_Svc(0, 0), "user_not_found"), (_Svc(4, 2), "ambiguous_user"), (_Svc(10, 0, ["ldap://other.example.local/DC=other"]), "search_error"),
                      (_Svc(32, 0), "search_error"), (_Svc(50, 0), "search_error")):
        with pytest.raises(LdapError) as e:
            L._find(svc, cfg, "ivan.petrov")
        assert e.value.code == code
    with pytest.raises(LdapError) as e:
        L._find(_Svc(10, 0, ["ldap://other.example.local/DC=other"]), cfg, "ivan.petrov")
    assert "другой сервер" in e.value.message


def test_referrals_disabled(monkeypatch):
    import ldap3

    seen = {}

    class Conn:
        def __init__(self, server, **kw):
            seen.update(kw)
            self.result = {"result": 0}

        def bind(self):
            return True

    monkeypatch.setattr(ldap3, "Connection", Conn)
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: object())
    L._connection(LdapConfig(host="dc1.example.local"), "svc", "pw")
    assert seen["auto_referrals"] is False and seen["read_only"] is True


@pytest.fixture
def two_domains(monkeypatch):
    """Два домена: ivan.petrov есть в обоих, olga.s — только во втором, в домене A с заданным именем — сбой поиска или неоднозначность."""
    a = LdapConfig(id="a", name="Домен A", host="dc.a.example.local", domain_dns="a.example.local", netbios="A", base_dn="DC=a")
    b = LdapConfig(id="b", name="Домен B", host="dc.b.example.local", domain_dns="b.example.local", netbios="B", base_dn="DC=b")
    users = {"a": {"ivan.petrov"}, "b": {"ivan.petrov", "olga.s"}}
    state = {"a_error": None}

    class Svc:
        def unbind(self):
            pass

    def service(cfg):
        if cfg.id == "a" and state["a_error"] == "server_unavailable":
            raise LdapError("server_unavailable")
        return Svc()

    def find(svc, cfg, login):
        name = parse_login(login)[0].split("@")[0]
        if cfg.id == "a" and state["a_error"] == "ambiguous_user":
            raise LdapError("ambiguous_user")
        if name not in users[cfg.id]:
            raise LdapError("user_not_found")
        return {"dn": f"CN={name},{cfg.base_dn}", "attributes": {"sAMAccountName": name}, "raw_attributes": {}}

    def connection(cfg, user, password):
        if password != f"pw-{cfg.id}":
            raise LdapError("invalid_credentials")
        return Svc()

    monkeypatch.setattr(L, "_service", service)
    monkeypatch.setattr(L, "_find", find)
    monkeypatch.setattr(L, "_connection", connection)
    monkeypatch.setattr(L, "_groups", lambda svc, cfg, dn, mo: frozenset({GROUP}))
    return L.Directory([a, b]), state


def test_directory_short_name_and_domain_choice(two_domains):
    d, state = two_domains
    with pytest.raises(LdapError) as e:                       # одно имя в двух доменах — без выбора домена входа нет
        d.authenticate("ivan.petrov", "pw-a")
    assert e.value.code == "choose_domain" and "Домен A" in e.value.detail and "Домен B" in e.value.detail
    assert d.authenticate("ivan.petrov", "pw-b", "b").connection == "Домен B"
    with pytest.raises(LdapError) as e:                       # пароль домена A в домене B не подходит: «чужой» домен не выбирается сам
        d.authenticate("ivan.petrov", "pw-a", "b")
    assert e.value.code == "invalid_credentials" and e.value.connection == "Домен B"
    assert d.authenticate("A\\ivan.petrov", "pw-a").connection == "Домен A"           # прежние формы входа по-прежнему выбирают домен
    assert d.authenticate("ivan.petrov@a.example.local", "pw-a").domain == "a.example.local"
    assert d.authenticate("olga.s", "pw-b").connection == "Домен B"                   # короткое имя есть только в одном домене
    with pytest.raises(LdapError) as e:
        d.authenticate("nobody", "pw-a")
    assert e.value.code == "user_not_found"
    with pytest.raises(LdapError) as e:
        d.authenticate("ivan.petrov", "pw-b", "zzz")
    assert e.value.code == "unknown_domain"
    state["a_error"] = "ambiguous_user"                       # неоднозначно в домене A — вход в домене B не выполняется
    with pytest.raises(LdapError) as e:
        d.authenticate("olga.s", "pw-b")
    assert e.value.code == "ambiguous_user"
    state["a_error"] = "server_unavailable"
    assert d.authenticate("olga.s", "pw-b").connection == "Домен B"
    with pytest.raises(LdapError) as e:
        d.authenticate("nobody", "pw-b")
    assert e.value.code == "server_unavailable"               # не найден в B, A недоступен — «не найден» утверждать нельзя


def test_diagnose_login_stages(two_domains):
    d, _ = two_domains
    stages, ident = d.diagnose_login("ivan.petrov", "pw-a")
    assert ident is None and [s["stage"] for s in stages] == ["parse", "search", "search", "choose"] and stages[-1]["ok"] is False
    stages, ident = d.diagnose_login("ivan.petrov", "wrong", "a")
    assert ident is None and stages[-1]["stage"] == "auth" and stages[-1]["ok"] is False and "отклонил пароль" in stages[-1]["message"]
    stages, ident = d.diagnose_login("olga.s", "pw-b")
    assert ident is not None and GROUP in ident.groups and all(s["ok"] is not False for s in stages)
    stages, ident = d.diagnose_login("olga.s")                # без пароля — поиск и группы
    assert ident is not None and [s["stage"] for s in stages][-2:] == ["auth", "groups"] and stages[-2]["ok"] is None
    stages, _ = d.diagnose_login("bad name")
    assert stages[0]["ok"] is False


class _Dir:
    """Каталог с двумя доменами для проверок через API: ivan.petrov есть в обоих."""

    def __init__(self, idents: dict[str, LdapIdentity], fail: str = ""):
        self.configs = [object(), object()]
        self.idents, self.fail = idents, fail

    def authenticate(self, login, password, domain=""):
        if self.fail:
            raise LdapError(self.fail, "фильтр (&(objectClass=user)(sAMAccountName=x))", "Домен A")
        if not domain:
            raise LdapError("choose_domain", "Домен A, Домен B")
        if password != "Pass-1":
            raise LdapError("invalid_credentials", connection="Домен A")
        return self.idents[domain]


def _ident(cid: uuid.UUID, guid: str, domain: str, name: str = "ivan.petrov") -> LdapIdentity:
    return LdapIdentity(guid=guid, dn=f"CN={name},DC=x", username=name, upn=None, display_name=name, email=None, groups=frozenset({GROUP}),
                        connection_id=str(cid), connection=domain, domain=domain)


async def test_login_domain_choice_names_and_reasons(client, app, monkeypatch):
    ca, cb = uuid.uuid4(), uuid.uuid4()
    idents = {str(ca): _ident(ca, "guid-a", "a.example.local"), str(cb): _ident(cb, "guid-b", "b.example.local"),
              "admin-dom": _ident(ca, "guid-adm", "a.example.local", "admin")}
    fake = _Dir(idents)

    async def directory(db):
        return fake

    monkeypatch.setattr(app.state.ldap, "directory", directory)
    async with app.state.session_maker() as db:
        db.add(AccessRule(group_dn=GROUP, role="analyst", all_sources=True))
        await db.commit()
    r = await client.post("/api/v1/auth/login", json={"login": "ivan.petrov", "password": "Pass-1"}, headers=H)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "choose_domain"
    r = await client.post("/api/v1/auth/login", json={"login": "ivan.petrov", "password": "Pass-1", "domain": str(ca)}, headers=H)
    assert r.status_code == 200 and r.json()["user"]["role"] == "analyst"
    client.cookies.clear()
    r = await client.post("/api/v1/auth/login", json={"login": "ivan.petrov", "password": "Pass-1", "domain": str(cb)}, headers=H)
    assert r.status_code == 200, r.text
    client.cookies.clear()
    # одноимённые учётные записи разных доменов — разные пользователи KAV Checker; локальный admin не затрагивается выбранным доменом
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Pass-1", "domain": "admin-dom"}, headers=H)
    assert r.status_code == 200, r.text
    async with app.state.session_maker() as db:
        rows = {u.ldap_guid: u.username for u in (await db.execute(select(User).where(User.auth_source == "ldap"))).scalars()}
        local_admin = (await db.execute(select(User).where(User.username == "admin"))).scalar_one()
    assert rows == {"guid-a": "ivan.petrov", "guid-b": "ivan.petrov@b.example.local", "guid-adm": "admin@a.example.local"}
    assert local_admin.auth_source == "local"
    # пользователю — общее сообщение, администратору в журнале — точная причина
    client.cookies.clear()
    fake.fail = "user_not_found"
    r = await client.post("/api/v1/auth/login", json={"login": "olga.s", "password": "x"}, headers=H)
    assert r.status_code == 401 and r.json()["detail"]["message"] == "Неверный логин или пароль."
    async with app.state.session_maker() as db:
        rec = (await db.execute(select(AuditLog).where(AuditLog.action == "auth.login_failed").order_by(AuditLog.id.desc()))).scalars().first()
    assert rec.details["reason"] == "user_not_found" and "Домен A" in rec.details["detail"] and "x" != rec.details.get("password")


async def test_local_login_when_directory_down(client, app, monkeypatch):
    async def directory(db):
        return _Dir({}, fail="server_unavailable")

    monkeypatch.setattr(app.state.ldap, "directory", directory)
    await login(client, "admin", "Admin-Passw0rd-123")                         # локальный администратор входит независимо от LDAPS
    client.cookies.clear()
    r = await client.post("/api/v1/auth/login", json={"login": "ivan.petrov", "password": "x"}, headers=H)
    assert r.status_code == 503 and r.json()["detail"]["code"] == "directory_unavailable"


async def test_login_options(client, app):
    assert (await client.get("/api/v1/auth/login-options")).json() == {"domains": [], "default_theme": "night"}
    async with app.state.session_maker() as db:
        for i, name in enumerate(("Домен A", "Домен B")):
            db.add(LdapConnection(id=uuid.uuid4(), name=name, enabled=True, is_primary=i == 0, protocol="ldaps", host=f"dc{i}.example.local", port=636, ldap_version=3,
                                  timeout_s=5, base_dn="DC=example,DC=local", domain_dns="", netbios="", bind_dn="svc", login_attribute="sAMAccountName",
                                  display_name_attribute="displayName", email_attribute="mail", user_filter="(objectClass=user)", nested_groups=True, position=i))
        await db.commit()
    assert [d["name"] for d in (await client.get("/api/v1/auth/login-options")).json()["domains"]] == ["Домен A", "Домен B"]
