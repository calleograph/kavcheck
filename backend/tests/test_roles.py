"""Роли: аналитик видит результаты проверок, запускает их только специалист по ИБ; правила доступа для отдельных доменных пользователей; «Иерархия» доступна всем ролям."""
import uuid

from app.auth.ldap import LdapIdentity
from app.models import AccessRule
from app.services.ldap_store import LdapStore
from tests.conftest import login

H = {"Origin": "http://testserver"}
PW = "Role-Test-Pass-12345"


async def make_user(client, name, role):
    r = await client.post("/api/v1/admin/users", json={"username": name, "password": PW, "role": role, "must_change_password": False})
    assert r.status_code == 201, r.text


def ident(username="ivanov", email="ivanov@example.local", upn="ivanov@example.local", groups=(), conn=""):
    return LdapIdentity(guid="g", dn=f"cn={username}", username=username, upn=upn, display_name="Иван", email=email, groups=frozenset(groups), connection_id=conn)


def rule(value, role, kind="user", conn=None):
    return AccessRule(id=uuid.uuid4(), group_dn=value, kind=kind, role=role, all_sources=True, connection_id=conn)


def test_user_rules_match_full_account_names_only():
    decide = LdapStore.decide
    me = ident()
    assert decide([rule("IVANOV", "analyst")], me).role == "analyst"                                 # логин без учёта регистра
    assert decide([rule("ivanov@example.local", "security")], me).role == "security"                 # UPN или почта
    assert decide([rule("ivan", "analyst")], me).role is None and decide([rule("ivanov@example.net", "analyst")], me).role is None   # часть имени и чужой домен не подходят
    assert decide([rule("EXAMPLE\\ivanov", "analyst")], me).role is None                              # NetBIOS подключения неизвестен — не подходит
    assert decide([rule("EXAMPLE\\ivanov", "analyst")], me, netbios="example").role == "analyst"
    assert decide([rule("EXAMPLE\\ivanov", "analyst")], me, netbios="other").role is None
    # группа и учётная запись вместе: старшая роль, источники объединяются
    both = decide([rule("cn=g1", "viewer", "group"), rule("ivanov", "security")], ident(groups=["cn=g1"]))
    assert both.role == "security"
    # правило другого подключения не действует
    assert decide([rule("ivanov", "analyst", conn=uuid.uuid4())], ident(conn=str(uuid.uuid4()))).role is None


async def test_user_rule_validation_and_listing(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    base = {"role": "security", "all_sources": True, "source_ids": []}
    post = lambda **kw: client.post("/api/v1/admin/ldap/rules", json={**base, **kw})                  # noqa: E731
    assert (await post(kind="user", group_dn="ivanov")).status_code == 422                            # логин без домена и без подключения — однофамильцы
    assert (await post(kind="user", group_dn="iva*")).status_code == 422
    assert (await post(kind="user", group_dn="CN=Group,DC=x")).status_code == 422                     # это DN, а не учётная запись
    assert (await post(kind="group", group_dn="ivanov")).status_code == 422
    ok = await post(kind="user", group_dn="ivanov@example.local")
    assert ok.status_code == 201 and ok.json()["kind"] == "user" and ok.json()["role"] == "security"
    assert any(r["kind"] == "user" for r in (await client.get("/api/v1/admin/ldap/rules")).json()["items"])


async def test_domain_user_logs_in_by_personal_rule(client, app, monkeypatch):
    me = ident("petrov", "petrov@example.local", "petrov@example.local")

    class FakeDir:
        configs = [object()]

        def authenticate(self, login, password, domain=""):
            return me

    async def fake_directory(db):
        return FakeDir()

    monkeypatch.setattr(app.state.ldap, "directory", fake_directory)
    body = {"login": "petrov", "password": "x"}
    assert (await client.post("/api/v1/auth/login", json=body, headers=H)).json()["detail"]["code"] == "no_role"
    async with app.state.session_maker() as db:
        db.add(rule("petrov@example.local", "security"))
        await db.commit()
    r = await client.post("/api/v1/auth/login", json=body, headers=H)
    assert r.status_code == 200 and r.json()["user"]["role"] == "security"


async def test_security_role_runs_scans_analyst_only_views(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    await make_user(client, "analyst1", "analyst")
    await make_user(client, "security1", "security")
    await client.post("/api/v1/auth/logout")
    new = {"title": "t", "targets": "192.0.2.10", "profile": "fast", "discovery": "off", "confirm_scope": True}
    await login(client, "analyst1", PW)
    assert (await client.get("/api/v1/pentest/jobs")).status_code == 200                                # результаты — аналитику
    assert (await client.post("/api/v1/pentest/jobs", json=new)).status_code == 403                     # запуск — нет
    assert (await client.post("/api/v1/pentest/targets/preview", json={"targets": "192.0.2.10"})).status_code == 403
    assert (await client.post("/api/v1/hunt/jobs", json={"cves": ["CVE-2024-0001"]})).status_code == 403
    await client.post("/api/v1/auth/logout")
    await login(client, "security1", PW)
    assert (await client.post("/api/v1/pentest/jobs", json=new)).status_code == 201
    assert (await client.get("/api/v1/auth/me")).json()["user"]["role"] == "security"
    assert (await client.get("/api/v1/admin/users")).status_code == 403                                 # администрирования у роли нет
    assert (await client.post("/api/v1/reports", json={"kind": "quick_pentest", "title": "t", "params": {"view": "jobs"}})).status_code in (200, 201)   # аналитические права включены


async def test_hierarchy_is_open_to_every_role_by_default(client, app):
    await login(client, "viewer", "Viewer-Passw0rd-123")
    assert (await client.get("/api/v1/hier/access")).json()["allowed"] is True
    await client.post("/api/v1/auth/logout")
    await login(client, "admin", "Admin-Passw0rd-123")
    await make_user(client, "security2", "security")
    await client.post("/api/v1/auth/logout")
    await login(client, "security2", PW)
    assert (await client.get("/api/v1/hier/access")).json()["allowed"] is True
