"""Условия проверки версий: каждый оператор с граничными значениями, сложные версии (8.9 и 8.10, суффиксы), исключения, диапазоны,
неизменность условия при передаче (схема → задание → выполнение), текст условия и сверка с независимым эталоном."""
import itertools

import pytest
from pydantic import ValidationError

from app.api.schemas import AuditItem, AuditParams
from app.ksc import versions as V
from app.reports import audit

# --------------------------------------------------------------------------------------------- эталон: числовые версии без букв
def _t(v: str) -> tuple[int, ...]:
    p = [int(x) for x in v.split(".")]
    while len(p) > 1 and p[-1] == 0:      # 130 = 130.0.0
        p.pop()
    return tuple(p)


ORACLE = {"lt": lambda a, b: a < b, "le": lambda a, b: a <= b, "eq": lambda a, b: a == b, "ge": lambda a, b: a >= b, "gt": lambda a, b: a > b}
VERSIONS = ["8.9", "8.10", "8.9.9", "8.10.0", "8.4.14", "8.4.15", "8.4.16", "8.4.151", "8.4.150", "130", "130.0.0.0", "130.0.6723.70", "129.99.9", "9", "10", "1.0", "1.00"]


@pytest.mark.parametrize("scheme", ["numeric", "dpkg"])
def test_every_operator_against_oracle(scheme):
    """Все операторы × все пары версий: результат совпадает с независимым эталоном (кортежи чисел)."""
    for op, (a, b) in itertools.product(ORACLE, itertools.product(VERSIONS, VERSIONS)):
        if scheme == "dpkg" and _t(a) == _t(b) and a != b:
            continue            # в dpkg «8.10» и «8.10.0» — разные версии (8.10 < 8.10.0), в числовой схеме — одинаковые
        assert V.matches(a, op, b, scheme=scheme) is ORACLE[op](_t(a), _t(b)), (scheme, a, op, b)


def test_documented_boundaries():
    m = V.matches
    # ниже: граница не входит
    assert m("8.4.14", "lt", "8.4.15") and not m("8.4.15", "lt", "8.4.15") and not m("8.4.16", "lt", "8.4.15")
    # ниже или равна: граница входит
    assert m("8.4.15", "le", "8.4.15") and m("8.4.14", "le", "8.4.15") and not m("8.4.16", "le", "8.4.15")
    # равна: только граница (130 = 130.0.0.0)
    assert m("8.4.15", "eq", "8.4.15") and not m("8.4.14", "eq", "8.4.15") and m("130.0.0.0", "eq", "130")
    # выше или равна / выше
    assert m("8.4.15", "ge", "8.4.15") and not m("8.4.14", "ge", "8.4.15") and m("8.4.16", "ge", "8.4.15")
    assert m("8.4.16", "gt", "8.4.15") and not m("8.4.15", "gt", "8.4.15")
    # диапазон включает обе границы; одна граница — открытый диапазон
    assert m("8.4.10", "range", vmin="8.4.10", vmax="8.4.15") and m("8.4.15", "range", vmin="8.4.10", vmax="8.4.15")
    assert not m("8.4.9", "range", vmin="8.4.10", vmax="8.4.15") and not m("8.4.16", "range", vmin="8.4.10", vmax="8.4.15")
    assert m("99", "range", vmin="8.4.10") and not m("8.4.9", "range", vmin="8.4.10") and m("1", "range", vmax="8.4.10") and not m("8.4.11", "range", vmax="8.4.10")
    assert m("0.1", "any") and not V.matches("", "lt", "8.4.15")


def test_complex_versions():
    m = V.matches
    assert m("8.9", "lt", "8.10") and not m("8.10", "lt", "8.9") and m("8.10", "gt", "8.9")               # числа, а не строки
    assert m("8.9.12", "lt", "8.10.1") and m("8.4.9", "lt", "8.4.10") and not m("8.4.100", "lt", "8.4.20")
    assert m("1.1.1v", "lt", "1.1.1w") and m("1.1.1w", "ge", "1.1.1") and not m("1.1.1w", "lt", "1.1.1")     # буква после чисел — исправление
    assert m("9.6p1", "gt", "9.6") and m("9.6p1", "lt", "9.7")
    assert m("5.0.0-rc1", "lt", "5.0.0") and m("5.0.0-beta", "lt", "5.0") and not m("5.0.1", "lt", "5.0.0-rc1")   # предварительная версия меньше выпуска
    assert m("130.0.6723.70", "lt", "130.1") and m("130.0.6723.70", "gt", "130") and m("130.0.1", "gt", "130")
    # dpkg: эпоха, ревизия, тильда
    assert m("2:8.1+92ubuntu1", "lt", "8.3", scheme="dpkg") and m("7.4.33-1+deb11u4", "eq", "7.4.33", scheme="dpkg")
    assert m("1.0~rc1", "lt", "1.0", scheme="dpkg") and not m("1.0", "lt", "1.0~rc1", scheme="dpkg") and m("8.10", "lt", "8.10.0", scheme="dpkg")
    assert m("7.4.33-1+deb11u4", "lt", "7.4.33-1+deb11u5", scheme="dpkg") and m("7.4.33-1+deb11u5", "le", "7.4.33-1+deb11u5", scheme="dpkg")
    # Java и Python для Windows: нумерация приводится к обычной
    assert m("8.0.4010.7", "lt", "8.0.402", kind="java") and not m("8.0.4010.7", "lt", "8.0.401", kind="java") and m("8.0.4010.7", "eq", "8.0.401", kind="java")
    assert m("3.12.3150.0", "lt", "3.12.4", kind="python") and m("3.12.3150.0", "ge", "3.12.3", kind="python")


def test_excludes():
    assert V.excluded("115.10.0", ["115"]) and V.excluded("7.4.33", ["7.4"]) and V.excluded("7.4.33", ["7.4.33"]) and V.excluded("7.4.33", ["7.4.*"])
    assert not V.excluded("1150.1", ["115"]) and not V.excluded("7.40.1", ["7.4"]) and not V.excluded("7.4.34", ["7.4.33"]) and not V.excluded("1.0", [])
    assert V.excluded("8.10.2", ["8.10"]) and not V.excluded("8.1.2", ["8.10"]) and not V.excluded("8.100", ["8.10"])


def test_condition_text_is_exact():
    t = V.condition_text
    assert t("lt", "8.4.15") == "Установленная версия ниже 8.4.15"
    assert t("le", "8.4.15") == "Установленная версия ниже или равна 8.4.15"
    assert t("eq", "8.4.15") == "Установленная версия равна 8.4.15"
    assert t("ge", "8.4.15") == "Установленная версия выше или равна 8.4.15"
    assert t("gt", "8.4.15") == "Установленная версия выше 8.4.15"
    assert t("range", vmin="8.4.10", vmax="8.4.15") == "Установленная версия от 8.4.10 до 8.4.15 включительно"
    assert t("range", vmin="8.4.10") == "Установленная версия не ниже 8.4.10" and t("range", vmax="8.4.15") == "Установленная версия не выше 8.4.15"
    assert t("any") == "Любая установленная версия"
    item = {"op": "lt", "value": "8.4.15", "exclude": ["8.4"], "branches": ["8.3"]}
    assert audit.item_condition(item) == "Установленная версия ниже 8.4.15; ветки 8.3; кроме 8.4"
    # целевая версия — отдельное понятие («куда обновить»), а не условие: для «ниже 8.4.15» это «8.4.15 или выше»
    assert audit.target_text(item) == "8.4.15 или выше" and audit.item_condition({"op": "lt", "value": "8.4.15"}) == "Установленная версия ниже 8.4.15"


@pytest.mark.parametrize("op", ["lt", "le", "eq", "ge", "gt"])
def test_item_keeps_operator_through_schema(op):
    """Схема не меняет оператор и границу; поля чужого оператора отбрасываются, а не перепутываются."""
    it = AuditParams.model_validate({"items": [{"kind": "product", "product_key": "x", "op": op, "value": " 8.4.15 ", "min": "1", "max": "2"}]}).model_dump()["items"][0]
    assert it["op"] == op and it["value"] == "8.4.15" and it["min"] is None and it["max"] is None
    assert it["op"] == op and audit.item_condition(it) == f"Установленная версия {V.OP_TITLES[op]} 8.4.15"


def test_range_and_validation():
    ok = AuditItem(kind="product", product_key="x", op="range", value="9", min="8.4.10", max="8.4.15")
    assert (ok.op, ok.value, ok.min, ok.max) == ("range", None, "8.4.10", "8.4.15")
    with pytest.raises(ValidationError, match="нижняя граница"):
        AuditItem(kind="product", product_key="x", op="range", min="8.10", max="8.9")        # пустой результат из-за перепутанных границ
    with pytest.raises(ValidationError):
        AuditItem(kind="product", product_key="x", op="lt")                                    # нет версии
    with pytest.raises(ValidationError):
        AuditItem(kind="product", product_key="x", op="range")
    assert AuditItem(kind="product", product_key="x", op="any", value="5").value is None


def test_condition_guard_rejects_changed_condition():
    a = [{"kind": "product", "product_key": "x", "op": "lt", "value": "8.4.15", "exclude": [], "branches": []}]
    audit.check_conditions(a, [{**a[0], "product_ids": [1], "product_name": "X"}])          # служебные поля не в счёт
    for field, val in (("op", "ge"), ("value", "8.4.16"), ("exclude", ["8.4"]), ("branches", ["8.4"]), ("platform", "linux")):
        with pytest.raises(audit.KscError, match="Расхождение условий"):
            audit.check_conditions(a, [{**a[0], field: val}])
    with pytest.raises(audit.KscError):
        audit.check_conditions(a, [])


def test_empty_result_is_explained():
    found = [{"name": "App", "version": "8.4.16", "compared_version": "8.4.16", "matched": False}, {"name": "App", "version": "8.5", "compared_version": "8.5", "matched": False}]
    txt = audit.explain_empty(found, "Установленная версия ниже 8.4.15")
    assert "ниже 8.4.15" in txt and "от 8.4.16 до 8.5" in txt and "подходящих нет" in txt
    assert "не найдено ни одной записи" in audit.explain_empty([], "x")
