"""Второй фактор, подключения каталога, сертификаты CA, правила доступа, перенос настройки LDAP 0.1.0, режим cookie Secure."""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.auth.ldap import LdapIdentity, parse_login
from app.config import Settings
from app.models import AccessRule, AppSetting, LdapConnection, User
from app.security import totp
from app.services.ldap_store import LdapStore, clean
from tests.conftest import login


def _ca(cn="Example Root CA", ca=True) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(4242)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    keypem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return pem, keypem


async def test_totp_full_flow(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    st = (await client.get("/api/v1/auth/totp/status")).json()
    assert st["available"] and not st["enabled"] and st["policy"] == "optional"
    assert (await client.post("/api/v1/auth/totp/setup", json={"password": "wrong-password"})).status_code == 403
    setup = (await client.post("/api/v1/auth/totp/setup", json={"password": "Admin-Passw0rd-123"})).json()
    secret = setup["secret"].replace(" ", "")
    assert setup["qr_svg"].startswith("<svg") and setup["uri"].startswith("otpauth://totp/KAV%20Checker")
    assert (await client.post("/api/v1/auth/totp/enable", json={"code": "000000"})).status_code == 422
    r = await client.post("/api/v1/auth/totp/enable", json={"code": totp.code_at(secret)})
    codes = r.json()["backup_codes"]
    assert r.status_code == 200 and len(codes) == 10
    async with app.state.session_maker() as db:
        from sqlalchemy import select

        u = (await db.execute(select(User).where(User.username == "admin"))).scalar_one()
        assert u.totp_enabled and u.totp_secret_enc and secret not in u.totp_secret_enc   # секрет хранится зашифрованным
    await client.post("/api/v1/auth/logout")
    client.headers.pop("X-CSRF-Token", None)
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Admin-Passw0rd-123"}, headers={"Origin": "http://testserver"})
    body = r.json()
    assert r.status_code == 200 and body["totp_required"] and "kavcheck_session" not in r.cookies          # без кода сессии нет
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    bad = await client.post("/api/v1/auth/login/totp", json={"challenge": body["challenge"], "code": "123456"}, headers={"Origin": "http://testserver"})
    assert bad.status_code == 401
    ok = await client.post("/api/v1/auth/login/totp", json={"challenge": body["challenge"], "code": codes[0]}, headers={"Origin": "http://testserver"})
    assert ok.status_code == 200 and ok.json()["second_factor"] == "backup_code" and ok.json()["totp_enabled"]
    # резервный код действует один раз
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Admin-Passw0rd-123"}, headers={"Origin": "http://testserver"})
    again = await client.post("/api/v1/auth/login/totp", json={"challenge": r.json()["challenge"], "code": codes[0]}, headers={"Origin": "http://testserver"})
    assert again.status_code == 401


async def test_totp_policy_requires_enrollment_and_admin_reset(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.put("/api/v1/admin/settings/auth_security", json={"totp_policy": "all"})
    assert r.status_code == 200
    await client.post("/api/v1/auth/logout")
    client.headers.pop("X-CSRF-Token", None)
    me = await login(client, "viewer", "Viewer-Passw0rd-123")
    assert me["must_enroll_totp"]
    blocked = await client.get("/api/v1/auth/sources")
    assert blocked.status_code == 403 and blocked.json()["detail"]["code"] == "totp_enrollment_required"
    setup = (await client.post("/api/v1/auth/totp/setup", json={"password": "Viewer-Passw0rd-123"})).json()
    await client.post("/api/v1/auth/totp/enable", json={"code": totp.code_at(setup["secret"].replace(" ", ""))})
    assert (await client.get("/api/v1/auth/sources")).status_code == 200                # после настройки доступ открыт
    dis = await client.post("/api/v1/auth/totp/disable", json={"password": "Viewer-Passw0rd-123", "code": "000000"})
    assert dis.status_code == 403                                                        # политика не даёт отключить
    await client.post("/api/v1/auth/logout")
    client.headers.pop("X-CSRF-Token", None)
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Admin-Passw0rd-123"}, headers={"Origin": "http://testserver"})
    assert r.json().get("must_enroll_totp") is True or "totp_required" not in r.json()
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    client.headers["Origin"] = "http://testserver"
    # администратор под политикой «all» тоже обязан настроить 2FA: до настройки админские функции закрыты
    assert (await client.get("/api/v1/admin/users")).status_code == 403


async def test_admin_resets_totp(client, app):
    await login(client, "viewer", "Viewer-Passw0rd-123")
    setup = (await client.post("/api/v1/auth/totp/setup", json={"password": "Viewer-Passw0rd-123"})).json()
    await client.post("/api/v1/auth/totp/enable", json={"code": totp.code_at(setup["secret"].replace(" ", ""))})
    await client.post("/api/v1/auth/logout")
    client.headers.pop("X-CSRF-Token", None)
    await login(client, "admin", "Admin-Passw0rd-123")
    users = (await client.get("/api/v1/admin/users")).json()["items"]
    v = next(u for u in users if u["username"] == "viewer")
    assert v["totp_enabled"]
    assert (await client.post(f"/api/v1/admin/users/{v['id']}/totp/reset", json={"password": "bad"})).status_code == 403
    assert (await client.post(f"/api/v1/admin/users/{v['id']}/totp/reset", json={"password": "Admin-Passw0rd-123"})).status_code == 204
    assert not next(u for u in (await client.get("/api/v1/admin/users")).json()["items"] if u["username"] == "viewer")["totp_enabled"]


async def test_certificates(client):
    await login(client, "admin", "Admin-Passw0rd-123")
    pem, keypem = _ca()
    p = (await client.post("/api/v1/admin/ldap/certs/preview", json={"pem": pem})).json()
    assert p["new"][0]["subject"] == "CN=Example Root CA" and p["new"][0]["type"].startswith("корневой") and p["new"][0]["serial"] == "1092"
    assert (await client.get("/api/v1/admin/ldap/certs")).json()["items"] == []                          # предпросмотр не сохраняет
    bad = await client.post("/api/v1/admin/ldap/certs", json={"pem": pem + keypem})
    assert bad.status_code == 422 and "Закрытые ключи" in bad.json()["detail"]
    leaf, _ = _ca("dc1.example.local", ca=False)
    assert (await client.post("/api/v1/admin/ldap/certs", json={"pem": leaf})).status_code == 422          # не CA без подтверждения
    import base64

    der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    r = await client.post("/api/v1/admin/ldap/certs", json={"data_base64": base64.b64encode(der).decode(), "label": "Корневой"})
    assert r.status_code == 201 and len(r.json()["added"]) == 1
    again = (await client.post("/api/v1/admin/ldap/certs", json={"pem": pem})).json()
    assert again["added"] == [] and len(again["existing"]) == 1
    items = (await client.get("/api/v1/admin/ldap/certs")).json()["items"]
    assert items[0]["label"] == "Корневой" and len(items[0]["sha256"]) == 64
    assert (await client.delete(f"/api/v1/admin/ldap/certs/{items[0]['id']}")).status_code == 204


async def test_connections_rules_and_secret(client, app):
    await login(client, "admin", "Admin-Passw0rd-123")
    body = {"name": "Основной домен", "url": "ldaps://dc1.example.local:636", "base_dn": "DC=example,DC=local", "domain_dns": "example.local", "netbios": "example",
            "bind_dn": "svc-kavcheck@example.local", "bind_password": "s3cret-bind", "is_primary": True, "timeout_s": 7, "ldap_version": 3}
    r = await client.post("/api/v1/admin/ldap/connections", json=body)
    c = r.json()
    assert r.status_code == 201 and c["host"] == "dc1.example.local" and c["port"] == 636 and c["netbios"] == "EXAMPLE" and c["bind_password_set"]
    assert "s3cret-bind" not in r.text                                                                     # пароль не возвращается
    assert (await client.post("/api/v1/admin/ldap/connections", json={**body, "name": "Без пароля", "bind_password": ""})).status_code == 422
    assert (await client.post("/api/v1/admin/ldap/connections", json={**body, "name": "LDAP", "url": "ldap://dc1.example.local"})).json()["protocol"] == "starttls"
    up = await client.put(f"/api/v1/admin/ldap/connections/{c['id']}", json={**body, "bind_password": None, "timeout_s": 9})
    assert up.status_code == 200 and up.json()["timeout_s"] == 9 and up.json()["bind_password_set"]       # пустой пароль — не менять
    gone = (await client.delete(f"/api/v1/admin/ldap/connections/{c['id']}/secret")).json()
    assert not gone["bind_password_set"] and not gone["enabled"]
    t = (await client.post(f"/api/v1/admin/ldap/connections/{c['id']}/test", json={})).json()
    assert not t["ok"] and "Пароль сервисной учётной записи не задан" in t["stages"][0]["message"]
    rule = await client.post("/api/v1/admin/ldap/rules", json={"group_dn": "CN=KAV-Admins,OU=Groups,DC=example,DC=local", "role": "admin"})
    assert rule.status_code == 201 and rule.json()["connection"] == "любое"
    assert (await client.post("/api/v1/admin/ldap/rules", json={"group_dn": "KAV-Admins", "role": "admin"})).status_code == 422


def test_clean_and_decide():
    assert clean({"name": "D", "url": "ldaps://dc.example.local", "base_dn": "DC=x", "bind_dn": "u@x"})["port"] == 636
    assert parse_login("EXAMPLE\\ivanov") == ("ivanov", False, "EXAMPLE") and parse_login("ivanov@example.local")[1]
    rules = [AccessRule(group_dn="CN=View,DC=x", role="viewer", all_sources=False, source_ids=["s1"]), AccessRule(group_dn="CN=An,DC=x", role="analyst", all_sources=False, source_ids=["s2"])]
    ident = LdapIdentity(guid="g", dn="d", username="u", upn=None, display_name="U", email=None, groups=frozenset({"cn=view,dc=x", "cn=an,dc=x"}), connection_id="c1")
    d = LdapStore.decide(rules, ident)
    assert d.role == "analyst" and not d.all_sources and d.source_ids == {"s1", "s2"}
    assert LdapStore.decide(rules, LdapIdentity(guid="g", dn="d", username="u", upn=None, display_name="U", email=None, groups=frozenset())).role is None


async def test_legacy_ldap_migrated(app):
    async with app.state.session_maker() as db:
        enc = app.state.settings_svc.encrypt("old-pass", "ldap.bind_password")
        db.add(AppSetting(group="ldap", value={"enabled": True, "host": "dc.example.local", "port": 636, "protocol": "ldaps", "base_dn": "DC=example,DC=local",
                                               "bind_dn": "CN=svc,DC=example,DC=local", "bind_password_enc": enc, "admin_group_dn": "CN=Adm,DC=example,DC=local"}))
        await db.commit()
        assert await app.state.ldap.migrate_legacy(db)
        from sqlalchemy import select

        c = (await db.execute(select(LdapConnection))).scalar_one()
        assert c.is_primary and app.state.ldap.decrypt(c) == "old-pass"
        r = (await db.execute(select(AccessRule))).scalar_one()
        assert r.role == "admin" and r.all_sources
        assert not await app.state.ldap.migrate_legacy(db)                     # повторно не переносится


def test_secure_cookie_modes():
    assert Settings(app_public_url="https://kav.example.org").secure_cookie() is True
    assert Settings(app_public_url="http://kav.example.org").secure_cookie() is False
    assert Settings(app_public_url="http://kav.example.org").secure_cookie("https") is True          # за прокси с TLS
    assert Settings(app_public_url="https://kav.example.org", cookie_secure="false").secure_cookie() is False


async def test_directory_login_with_rules(client, app, monkeypatch):
    """Вход доменного пользователя: роль и источники — из правил групп; без подходящего правила вход отклоняется."""
    from app.auth import ldap as L

    ident = LdapIdentity(guid="g-1", dn="uid=ivanov,ou=People,dc=example,dc=local", username="ivanov", upn=None, display_name="Иван Иванов", email="ivanov@example.local",
                         groups=frozenset({"cn=kav-analysts,ou=groups,dc=example,dc=local"}), connection_id="")

    class FakeDir:
        configs = [object()]

        def authenticate(self, login, password):
            if password != "User-Test-Pass-1":
                raise L.LdapError("invalid_credentials")
            return ident

    async def fake_directory(db):
        return FakeDir()

    monkeypatch.setattr(app.state.ldap, "directory", fake_directory)
    h = {"Origin": "http://testserver"}
    r = await client.post("/api/v1/auth/login", json={"login": "EXAMPLE\\ivanov", "password": "User-Test-Pass-1"}, headers=h)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "no_role"                    # правил нет — входа нет
    async with app.state.session_maker() as db:
        db.add(AccessRule(group_dn="CN=KAV-Analysts,OU=Groups,DC=example,DC=local", role="analyst", all_sources=True))
        await db.commit()
    r = await client.post("/api/v1/auth/login", json={"login": "EXAMPLE\\ivanov", "password": "User-Test-Pass-1"}, headers=h)
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["user"]["role"] == "analyst" and not me["user"]["local"] and me["user"]["display_name"] == "Иван Иванов"
    assert (await client.post("/api/v1/auth/login", json={"login": "EXAMPLE\\ivanov", "password": "wrong"}, headers=h)).status_code == 401


async def test_sessions_expiry_proxy_and_password_change(client, app):
    from datetime import timedelta

    from sqlalchemy import update

    from app.models import Session as Sess
    from app.models import utcnow

    # за обратным прокси с TLS: X-Forwarded-Proto: https → cookie с флагом Secure (режим auto, APP_PUBLIC_URL по http)
    app.state.settings.cookie_secure = "auto"
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Admin-Passw0rd-123"},
                          headers={"Origin": "http://testserver", "X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"})
    assert r.status_code == 200 and "secure" in r.headers["set-cookie"].lower() and r.json()["secure_cookie"]
    r = await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Admin-Passw0rd-123"}, headers={"Origin": "http://testserver"})
    assert "secure" not in r.headers["set-cookie"].lower()                     # прямой HTTP — без Secure
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    client.headers["Origin"] = "http://testserver"
    assert (await client.get("/api/v1/auth/me")).status_code == 200
    # истечение по бездействию: сессия удаляется, нужен повторный вход
    async with app.state.session_maker() as db:
        await db.execute(update(Sess).values(last_seen=utcnow() - timedelta(seconds=app.state.settings.session_idle_timeout_seconds + 5)))
        await db.commit()
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    me = await login(client, "admin", "Admin-Passw0rd-123")
    assert me["user"]["username"] == "admin"
    # смена пароля завершает другие сеансы, текущий остаётся
    r2 = await client.post("/api/v1/auth/change-password", json={"current_password": "Admin-Passw0rd-123", "new_password": "Strong-Secret-2026-x"})
    assert r2.status_code == 204 and (await client.get("/api/v1/auth/me")).status_code == 200
    await client.post("/api/v1/auth/logout")
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    assert (await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Admin-Passw0rd-123"}, headers={"Origin": "http://testserver"})).status_code == 401
    assert (await client.post("/api/v1/auth/login", json={"login": "admin", "password": "Strong-Secret-2026-x"}, headers={"Origin": "http://testserver"})).status_code == 200
