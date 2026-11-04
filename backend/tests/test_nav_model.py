"""Контрольный перечень функций: любой маршрут интерфейса и любая вкладка администрирования имеют место в модели навигации (frontend/src/navModel.ts),
поэтому при перестройке меню ничего не теряется; личные настройки панели «Быстрый доступ» хранятся отдельно для каждого пользователя."""
import re
from pathlib import Path

from tests.conftest import login
from tests.test_hier import users

SRC = Path(__file__).resolve().parents[2] / "frontend" / "src"
MODEL = (SRC / "navModel.ts").read_text(encoding="utf-8")
APP = (SRC / "App.tsx").read_text(encoding="utf-8")
ADMIN = (SRC / "pages" / "AdminPage.tsx").read_text(encoding="utf-8")


def block(name: str) -> str:
    i = MODEL.index(name)
    return MODEL[i:MODEL.index("\n];", i)]


def test_every_route_is_in_the_menu_or_explained():
    routes = set(re.findall(r'<Route path="([^"]+)"', APP)) - {"*"}
    nav = set(re.findall(r'to: "(/[^"?]*)"', block("export const NAV_TOP") + block("export const NAV_GROUPS") + MODEL[MODEL.index("export const NAV_REPORTS"):MODEL.index("\n", MODEL.index("export const NAV_REPORTS"))]))
    hidden = set(re.findall(r'^\s*"(/[^"]+)":', MODEL[MODEL.index("export const NAV_HIDDEN"):MODEL.index("};", MODEL.index("export const NAV_HIDDEN"))], re.M)) | set(re.findall(r', "(/[a-z/:A-Z]+)": "', MODEL[MODEL.index("export const NAV_HIDDEN"):MODEL.index("};", MODEL.index("export const NAV_HIDDEN"))]))
    assert routes <= nav | hidden, f"маршруты без места в навигации: {sorted(routes - nav - hidden)}"
    assert {"/", "/overview", "/hosts", "/software", "/devices", "/protection", "/vulnerabilities", "/vdb", "/eol", "/events", "/hunt", "/pentest", "/zones", "/hierarchy", "/reports"} <= nav


def test_every_admin_tab_is_grouped_once_and_rendered():
    tabs = re.findall(r'\{ id: "([a-z]+)", label: "', block("export const ADMIN_TABS"))
    grouped = [t for g in re.findall(r'tabs: \[([^\]]*)\]', block("export const ADMIN_GROUPS")) for t in re.findall(r'"([a-z]+)"', g)]
    assert sorted(tabs) == sorted(grouped) and len(tabs) == 21, "каждая вкладка администрирования — ровно в одной группе"
    for t in tabs:
        assert f'tab === "{t}"' in ADMIN, f"вкладка {t} не отображается на странице администрирования"
    for t in tabs:
        assert f'{t}: "' in MODEL[MODEL.index("export const ADMIN_ICONS"):], f"нет значка {t}"


def test_every_quick_report_kind_exists_on_the_server():
    from app.reports.quick import QUICK_KINDS

    kinds = set(re.findall(r'kind: "(quick_[a-z]+)"', MODEL))
    assert kinds <= set(QUICK_KINDS) | {"quick_zone"}, kinds - set(QUICK_KINDS)


async def test_quick_prefs_are_per_user_validated_and_resettable(client, app):
    await users(app)
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.get("/api/v1/auth/me")).json()["quick"] is None                                        # новый пользователь — стартовая конфигурация
    r = await client.put("/api/v1/auth/me/quick", json={"items": ["find-host", "protection", "find-host"], "reports": ["r-rtp"], "hidden": ["rtp"]})
    assert r.status_code == 200 and r.json()["quick"] == {"items": ["find-host", "protection"], "reports": ["r-rtp"], "hidden": ["rtp"]}
    assert (await client.get("/api/v1/auth/me")).json()["quick"]["reports"] == ["r-rtp"]
    for bad in ({"items": "x"}, {"items": [1]}, {"items": ["a" * 61]}, {"items": [str(i) for i in range(61)]}):
        assert (await client.put("/api/v1/auth/me/quick", json=bad)).status_code == 422
    await login(client, "analyst1", "Analyst-Passw0rd-123")
    assert (await client.get("/api/v1/auth/me")).json()["quick"] is None                                        # чужие настройки не видны
    assert (await client.put("/api/v1/auth/me/quick", json={"items": ["zones"]})).status_code == 200
    await login(client, "admin", "Admin-Passw0rd-123")
    assert (await client.get("/api/v1/auth/me")).json()["quick"]["items"] == ["find-host", "protection"]
    assert (await client.put("/api/v1/auth/me/quick", json={})).json()["quick"] is None                        # восстановление исходного набора
