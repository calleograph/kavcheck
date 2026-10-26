from app.validation_text import explain


def test_explain_is_russian_and_names_the_field():
    got = explain([{"type": "string_type", "loc": ("body", "params", "zone"), "msg": "Input should be a valid string", "input": None}])
    assert got == "Зона ответственности: значение не заполнено или имеет неверный тип"
    assert "Input" not in got and "[{" not in got
    got = explain([{"type": "value_error", "loc": ("body",), "msg": "Value error, Выберите программу из каталога", "ctx": {}}])
    assert got == "Выберите программу из каталога"
    assert explain([{"type": "string_too_long", "loc": ("body", "title"), "msg": "x", "ctx": {"max_length": 300}}]) == "Название: не длиннее 300 символов"


async def test_validation_error_response_is_human_readable(client):
    from tests.conftest import login

    await login(client, "admin", "Admin-Passw0rd-123")
    r = await client.post("/api/v1/reports", json={"kind": "version_audit", "params": {}, "title": "x" * 400})
    assert r.status_code == 422 and r.json()["detail"].startswith("Проверьте параметры:") and "Название" in r.json()["detail"]
