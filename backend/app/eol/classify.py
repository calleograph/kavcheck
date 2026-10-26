"""Правила жизненного цикла: что считать EOL, выбор ветки продукта по установленной версии.

Принципы (по требованиям безопасности):
* **EOL** — закончилась вся применимая поддержка, включая исправления безопасности: срок окончания (`eol_from`) наступил и расширенной поддержки (`eoes_from`) нет или она тоже закончилась.
  Это критическая проблема; идентификатора CVE у неё нет и быть не должно.
* **Расширенная поддержка** — стандартная закончилась, но исправления безопасности продолжают выходить по платной подписке или договору (Windows ESU, Ubuntu Pro, ELTS, RHEL ELS…).
  Это не безусловный EOL: статус «extended», подтверждения подписки в KSC нет, поэтому результат помечается неподтверждённым и условие показывается пользователю.
* Нет данных о датах — статус «unknown»: EOL автоматически не присваивается. Бессрочная поддержка без объявленного срока — «supported».
* Ветка выбирается по реальным названиям веток производителя (PHP 7.4.16 → «7.4», PostgreSQL 16.4 → «16»), а не по сравнению с «последней версией»."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

SOON_DAYS = 180                       # «приближающееся окончание поддержки»
STATUS_RU = {"eol": "Поддержка закончилась (EOL)", "extended": "Только расширенная поддержка", "upcoming": "Окончание поддержки приближается", "supported": "Поддерживается", "unknown": "Нет данных о сроках"}
SEVERITY = {"eol": "critical", "extended": "high", "upcoming": "warning", "supported": "", "unknown": ""}


@dataclass(frozen=True)
class Lifecycle:
    status: str                       # eol | extended | upcoming | supported | unknown
    severity: str                     # critical | high | warning | ""
    confirmed: bool                   # False — результат зависит от подписки или договора
    condition: str
    eol_from: date | None
    eoas_from: date | None
    eoes_from: date | None


def _fmt(d: date | None) -> str:
    return d.strftime("%d.%m.%Y") if d else "дата не указана"


def classify(rel, labels: dict | None, today: date, *, soon_days: int = SOON_DAYS) -> Lifecycle:
    """Состояние ветки на дату `today` по её датам (rel: eol_from, eoas_from, eoes_from, eol_flag, eoes_flag; labels — подписи этапов у производителя)."""
    labels = labels or {}
    eol, eoas, eoes = rel.eol_from, rel.eoas_from, rel.eoes_from
    eol_name = labels.get("eol") or "поддержка исправлений безопасности"
    eoes_name = labels.get("eoes") or "расширенная поддержка"
    if eol is None and rel.eol_flag is None:
        return Lifecycle("unknown", "", True, "Срок окончания поддержки производитель не объявил или сведений нет: EOL не присваивается", None, eoas, eoes)
    ended = (eol is not None and eol <= today) or (eol is None and rel.eol_flag is True)
    if ended:
        ext_active = eoes is not None and eoes > today
        if ext_active:
            cond = (f"Стандартная поддержка («{eol_name}») закончилась {_fmt(eol)}. Исправления безопасности выходят только по расширенной поддержке («{eoes_name}») до {_fmt(eoes)} — "
                    f"по платной подписке или договору. Наличие подписки по данным KSC подтвердить нельзя: если её нет, устройство фактически без исправлений.")
            return Lifecycle("extended", SEVERITY["extended"], False, cond, eol, eoas, eoes)
        extra = f" Расширенная поддержка («{eoes_name}») закончилась {_fmt(eoes)}." if eoes is not None else ""
        return Lifecycle("eol", SEVERITY["eol"], True, f"Поддержка («{eol_name}») закончилась {_fmt(eol)}: исправления безопасности больше не выходят.{extra}", eol, eoas, eoes)
    if eol is not None and (eol - today).days <= soon_days:
        return Lifecycle("upcoming", SEVERITY["upcoming"], True, f"Поддержка («{eol_name}») закончится {_fmt(eol)}: осталось {(eol - today).days} дн.", eol, eoas, eoes)
    cond = f"Поддерживается до {_fmt(eol)} («{eol_name}»)" if eol else "Срок окончания поддержки не объявлен"
    return Lifecycle("supported", "", True, cond, eol, eoas, eoes)


# ------------------------------------------------------------------------------------------------ выбор ветки по версии
_SEP = ".-_+~:"
_JAVA_OLD = re.compile(r"^1\.(\d+)(?:\.\d+)?(?:[_.-]\d+)?")
_JAVA_U = re.compile(r"^(\d+)u\d+$", re.I)


def version_forms(version: str) -> list[str]:
    """Написания версии, по которым ищется ветка: исходная, без приставки «v», Java 1.8.0_391 и 8u391 → 8."""
    v = (version or "").strip().lstrip("vV")
    if ":" in v and v.split(":", 1)[0].isdigit():         # эпоха пакета (dpkg): «1:7.4.3» → «7.4.3»
        v = v.split(":", 1)[1]
    out = [v] if v else []
    m = _JAVA_OLD.match(v)
    if m and int(m.group(1)) >= 5:
        out.append(m.group(1))
    m = _JAVA_U.match(v)
    if m:
        out.append(m.group(1))
    return out


def pick_release(names: list[str], version: str) -> str | None:
    """Самая длинная ветка из `names`, с которой начинается версия по границе компонента: «7.4.16» → «7.4» (но не «7»), «16.4» → «16», «2019» → «2019». Нет подходящей — None."""
    best = None
    for v in version_forms(version):
        for n in names:
            low, vl = n.lower(), v.lower()
            if vl == low or (vl.startswith(low) and vl[len(low)] in _SEP):
                if best is None or len(n) > len(best):
                    best = n
        if best:
            return best
    return None
