from __future__ import annotations

import re
import uuid
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, field_validator, model_validator

from ..search import clean

MaskText = Annotated[str | None, Field(max_length=200), AfterValidator(lambda v: v if v is None else clean(v))]     # текст поиска со звёздочкой: число звёздочек проверяется при приёме запроса


class Params(BaseModel):
    """Основа параметров отчётов: необязательное поле, переданное как null, получает значение по умолчанию (зона не выбрана — «все компьютеры»), а не ошибку «Input should be a valid string».
    Поля, для которых null — допустимое значение (`int | None = None`), остаются как есть.

    Общие для всех отчётов настройки конструктора: `detail` — «summary» (краткий: показатели и сводные таблицы) или «full» (подробный: все записи, полные перечни CVE, устройств, пользователей);
    `columns` — какие столбцы основной таблицы включить и в каком порядке (пусто — все)."""
    detail: Literal["summary", "full"] = "full"
    columns: list[str] = Field(default_factory=list, max_length=60)
    sort: str = Field(default="", max_length=60)                 # ключ столбца основной таблицы, по которому сортировать (пусто — порядок отчёта)
    desc: bool = False
    group: str = Field(default="", max_length=60)                # ключ столбца: строки группируются по значению, добавляется сводка «число по группам»

    @model_validator(mode="before")
    @classmethod
    def _null_means_default(cls, data):
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v is not None or (k in cls.model_fields and cls.model_fields[k].default is None)}
        return data


class LoginIn(BaseModel):
    login: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=512)
    domain: str = Field(default="", max_length=64)        # подключение LDAPS, выбранное на странице входа; пусто — определить по имени


class TotpLoginIn(BaseModel):
    challenge: str = Field(min_length=10, max_length=200)
    code: str = Field(min_length=6, max_length=32)


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    role: str
    is_admin: bool
    local: bool


class MeOut(BaseModel):
    user: UserOut
    csrf_token: str
    must_change_password: bool
    current_source_id: str | None
    site_name: str
    activity_days: int = 30
    must_enroll_totp: bool = False
    totp_enabled: bool = False
    second_factor: str | None = None
    secure_cookie: bool = False
    theme: str | None = None                                            # личный выбор; None — действует default_theme
    default_theme: str = "night"


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9._-]+$")
    port: int = Field(default=1433, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=128, pattern=r"^[\w.$-]+$")
    auth_type: str = Field(default="sql", pattern=r"^(sql|windows)$")
    username: str = Field(min_length=1, max_length=256)
    password: str | None = None            # None — не менять; "" — очистить
    tls_mode: str = Field(default="require", pattern=r"^(require|request|off)$")
    trust_server_cert: bool = True
    connect_timeout_s: int = Field(default=10, ge=1, le=120)
    query_timeout_s: int = Field(default=60, ge=5, le=3600)
    is_active: bool = True


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(default="", max_length=300)
    email: str | None = Field(default=None, max_length=320)
    role: str = Field(default="viewer", pattern=r"^(admin|analyst|viewer)$")
    password: str | None = None
    is_active: bool = True
    all_sources: bool = True
    source_ids: list[str] = []
    must_change_password: bool = True


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=300)
    email: str | None = Field(default=None, max_length=320)
    role: str | None = Field(default=None, pattern=r"^(admin|analyst|viewer)$")
    password: str | None = None
    is_active: bool | None = None
    all_sources: bool | None = None
    source_ids: list[str] | None = None
    must_change_password: bool | None = None


class RuleIn(BaseModel):
    key: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=120)
    name_like: str = Field(min_length=1, max_length=200)
    name_regex: str = Field(min_length=1, max_length=2000)
    branch_regex: str | None = Field(default=None, max_length=2000)
    branch_parts: int = Field(default=2, ge=1, le=4)
    exclude_regex: str | None = Field(default=None, max_length=2000)
    description: str | None = Field(default=None, max_length=4000)
    enabled: bool = True


class ReportParams(Params):
    """Параметры отчёта: выбор программ (идентификаторы, правило + ветки, шаблон названия), диапазон версий, активность, платформа, группа."""
    product_ids: list[int] = []
    rule: str | None = Field(default=None, max_length=64)
    branches: list[str] = []
    name_like: str | None = Field(default=None, max_length=200)
    name_regex: str | None = Field(default=None, max_length=2000)
    min_version: str | None = Field(default=None, max_length=100)
    max_version: str | None = Field(default=None, max_length=100)
    below_version: str | None = Field(default=None, max_length=100)
    platform: str | None = Field(default=None, pattern=r"^(windows|linux)?$")
    group_contains: MaskText = None
    active_days: int | None = Field(default=None, ge=1, le=3650)
    include_inactive: bool = False
    inactive_only: bool = False
    q: MaskText = None
    os_contains: MaskText = None


class AuditItem(Params):
    """Пункт проверки версий: программа (ключ каталога) или, в дополнительных настройках, шаблон названия / правило группировки."""
    kind: Literal["product", "pattern", "rule"] = "product"
    product_key: str | None = Field(default=None, max_length=160)
    product_keys: list[str] = Field(default_factory=list, max_length=100)    # несколько продуктов каталога (семейство, компоненты) с одним условием
    product_name: str | None = Field(default=None, max_length=300)
    op: Literal["lt", "le", "eq", "ge", "gt", "range", "any"] = "lt"
    value: str | None = Field(default=None, max_length=100)
    min: str | None = Field(default=None, max_length=100)
    max: str | None = Field(default=None, max_length=100)
    exclude: list[str] = Field(default_factory=list, max_length=50)
    branches: list[str] = Field(default_factory=list, max_length=100)
    target_version: str | None = Field(default=None, max_length=100)
    platform: Literal["windows", "linux", ""] | None = None
    name_like: str | None = Field(default=None, max_length=200)
    name_regex: str | None = Field(default=None, max_length=2000)
    publisher_like: str | None = Field(default=None, max_length=200)
    rule: str | None = Field(default=None, max_length=64)

    @field_validator("exclude", "branches")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        out = [x.strip()[:100] for x in v if isinstance(x, str)]
        return [x for x in out if x] if v is not None else []

    @model_validator(mode="after")
    def _check(self):
        for f in ("value", "min", "max", "target_version"):
            v = getattr(self, f)
            if v is not None:
                setattr(self, f, v.strip() or None)
        # поля, не относящиеся к выбранному оператору, отбрасываются: условие хранится ровно в том виде, в каком его выполняют
        if self.op == "range":
            self.value = None
        elif self.op == "any":
            self.value = self.min = self.max = None
        else:
            self.min = self.max = None
        if self.op == "range" and self.min and self.max:
            from ..ksc.versions import compare_numeric  # noqa: PLC0415

            if compare_numeric(self.min, self.max) > 0:
                raise ValueError(f"Диапазон задан неверно: нижняя граница {self.min} выше верхней {self.max}")
        if self.kind == "product" and not self.product_key:
            raise ValueError("Выберите программу из каталога")
        if self.kind == "pattern" and not (self.name_like or self.name_regex):
            raise ValueError("Укажите шаблон названия (SQL LIKE) или регулярное выражение")
        if self.kind == "rule" and not self.rule:
            raise ValueError("Укажите правило группировки")
        if self.op == "range" and not (self.min or self.max):
            raise ValueError("Для диапазона укажите хотя бы одну границу")
        if self.op not in ("range", "any") and not self.value:
            raise ValueError("Укажите версию для сравнения")
        if self.name_regex:
            try:
                re.compile(self.name_regex, re.I)
            except re.error as exc:
                raise ValueError(f"Регулярное выражение некорректно: {exc}") from None
        return self


class AuditParams(Params):
    """Параметры проверки версий (вид отчёта version_audit)."""
    items: list[AuditItem] = Field(min_length=1, max_length=50)
    active_days: int | None = Field(default=None, ge=1, le=3650)
    include_inactive: bool = False
    online_only: bool = False                  # только устройства, которые KSC сейчас видит в сети (отдельно от «связывались за N суток»)
    group_contains: MaskText = None
    zone: str = Field(default="", max_length=40)   # зона ответственности («none» — без ответственного); пусто — все компьютеры


class QuickScope(Params):
    """Общая область быстрых отчётов: давность связи с KSC, отдельно — «в сети сейчас», группа и поиск по компьютеру."""
    active_days: int | None = Field(default=None, ge=1, le=3650)
    include_inactive: bool = False
    online_only: bool = False
    group_contains: MaskText = None
    q: MaskText = None
    zone: str = Field(default="", max_length=40)          # зона ответственности («none» — без ответственного); пусто — все компьютеры


class QuickVulns(QuickScope):
    """Уязвимости, подтверждённые KSC: выбранные уязвимости (идентификаторы KSC или CVE), уязвимые программы и/или компьютеры."""
    descr_ids: list[int] = Field(default_factory=list, max_length=5000)
    cves: list[str] = Field(default_factory=list, max_length=200)
    vp_ids: list[int] = Field(default_factory=list, max_length=5000)
    product_names: list[str] = Field(default_factory=list, max_length=50)
    product_like: MaskText = None                          # поиск по названию программы (условие страницы «Компьютеры» раздела «Уязвимости»)
    host_ids: list[int] = Field(default_factory=list, max_length=500)
    severity: Literal["", "critical", "high", "warning"] = ""
    patchable: bool = False

    @model_validator(mode="after")
    def _normalise(self):
        # без выбора — отчёт по условиям страницы (все действующие обнаружения с учётом опасности, поиска, группы, зоны); объём ограничен пределом отчёта
        self.cves = [c.strip().upper() for c in self.cves if c.strip()]
        return self


class QuickHosts(QuickScope):
    """Отчёт по компьютерам: по выбранным (до 500) либо — без выбора — по условиям страницы «Компьютеры» (поиск, группа, ОС, давность связи, зона)."""
    host_ids: list[int] = Field(default_factory=list, max_length=500)
    os_contains: MaskText = None
    inactive_only: bool = False
    sections: list[Literal["software", "vulns", "protection"]] = Field(default_factory=list)     # пусто: по выбранным — все разделы, по условиям страницы — только защита
    bases_days: int = Field(default=3, ge=1, le=90)
    scan_days: int = Field(default=30, ge=1, le=365)


class QuickProtection(QuickScope):
    problem: str = Field(default="", pattern=r"^(|ok|no_av|rtp_off|infected|bases_old|license|scan_old|reboot|hw_cpu|hw_ram)$")
    product: str = Field(default="", max_length=64)
    build: str = Field(default="", max_length=64)
    bases_days: int = Field(default=3, ge=1, le=90)
    scan_days: int = Field(default=30, ge=1, le=365)
    host_ids: list[int] = Field(default_factory=list, max_length=500)


class QuickEvents(Params):
    days: Literal[1, 7, 30] = 7
    group: Literal["", "detections", "notcured", "resolved", "attacks"] = ""
    types: list[str] = Field(default_factory=list, max_length=10)
    threat: str = Field(default="", max_length=300)
    q: MaskText = ""
    host_id: int | None = None
    event_ids: list[int] = Field(default_factory=list, max_length=5000)


class QuickExtVulns(QuickScope):
    """Уязвимости из внешних баз (локальная база NVD, KEV, OSV, БДУ): выбранные уязвимости (CVE, БДУ…) и/или продукты каталога → компьютеры с потенциально затронутым ПО."""
    vuln_keys: list[str] = Field(default_factory=list, max_length=300)
    product_keys: list[str] = Field(default_factory=list, max_length=50)
    statuses: list[Literal["confirmed", "potential", "clarify", "fixed", "insufficient"]] = Field(default_factory=lambda: ["confirmed", "potential", "clarify", "insufficient"])
    min_severity: Literal["", "critical", "high", "medium", "low"] = ""
    exploited_only: bool = False

    @model_validator(mode="after")
    def _need_selection(self):
        if not (self.vuln_keys or self.product_keys):
            raise ValueError("Выберите уязвимости или программы")
        self.vuln_keys = [v.strip().upper() for v in self.vuln_keys if v.strip()]
        if not self.statuses:
            raise ValueError("Выберите хотя бы один статус сопоставления")
        return self


class QuickEol(Params):
    """EOL в инфраструктуре: какие состояния поддержки, типы и производитель; список устройств включается отдельной таблицей (полный, без сокращений)."""
    statuses: list[Literal["eol", "extended", "upcoming", "undetermined"]] = Field(default_factory=lambda: ["eol", "extended", "upcoming"], min_length=1)
    finding: dict | None = None                           # одна находка: {source_id, kind, subject, version} — отчёт по устройствам из боковой панели
    kinds: list[Literal["app", "os"]] = Field(default_factory=lambda: ["app", "os"], min_length=1)
    severity: Literal["", "critical", "high", "warning"] = ""
    publisher: MaskText = None
    q: MaskText = None
    include_inactive: bool = False
    devices: bool = True
    active_days: int | None = Field(default=None, ge=1, le=3650)
    zone: str = Field(default="", max_length=40)


class QuickZone(Params):
    """Состояние безопасности зон ответственности: зоны (или «none» — без ответственного), категории проблем, подробность, критичность и пороги."""
    zone_ids: list[str] = Field(min_length=1, max_length=100)
    categories: list[Literal["ksc_vulns", "ksc_critical", "ext_vulns", "no_av", "rtp_off", "bases_old", "infected", "license", "scan_old", "hw_cpu", "hw_ram", "reboot", "inactive"]] = Field(
        default_factory=lambda: ["ksc_vulns", "ext_vulns", "no_av", "rtp_off", "bases_old", "infected", "inactive"], min_length=1)
    level: Literal["management", "technical"] = "management"
    severity: Literal["", "critical", "high"] = ""
    include_inactive: bool = False
    online_only: bool = False
    show_excluded: bool = False
    bases_days: int = Field(default=3, ge=1, le=90)
    scan_days: int = Field(default=30, ge=1, le=365)
    refresh_data: bool = False                                             # обновить данные зоны из KSC перед формированием (иначе — подготовленные, с датой среза в отчёте)
    hosts: list[str] = Field(default_factory=list, max_length=500)          # выбранные компьютеры «источник:идентификатор» — отчёт только по ним

    @model_validator(mode="after")
    def _ids(self):
        for z in self.zone_ids:
            if z != "none":
                try:
                    uuid.UUID(z)
                except ValueError:
                    raise ValueError("Некорректный идентификатор зоны") from None
        return self


class QuickDevices(Params):
    """Устройства и пользователи: условия страницы «Устройства и пользователи» (поиск по имени, IP, сети CIDR и логину, зона, ОС, пользователь, состояние EOL, источник)."""
    q: str = Field(default="", max_length=400)
    zone: str = Field(default="", max_length=40)
    os: str = Field(default="", max_length=120)
    user: str = Field(default="", max_length=120)
    eol: Literal["", "any", "eol", "none"] = ""
    include_inactive: bool = False
    show_service: bool = False
    source_id: str = Field(default="", max_length=40)
    view: Literal["devices", "users"] = "devices"                       # users — вкладка «Пользователи KSC»
    all_os: bool = False
    pd: bool = True                                                     # сотрудник по BI в отчёте; для роли «Просмотр» сервер выставляет False


class QuickBi(Params):
    """BI: вид отчёта и фильтры страницы (поиск, источник BI, отбор, ОС, личные, сотрудник, устройство)."""
    view: str = Field(default="owners", pattern=r"^(owners|history|unknown|discrepancies|problems)$")
    q: str = Field(default="", max_length=200)
    source_id: str = Field(default="", max_length=40)
    filter: str = Field(default="", pattern=r"^(|unknown_owner|multi|no_ksc|candidates|issues|linked)$")
    os: str = Field(default="", pattern=r"^(|windows|linux|mac|unknown)$")
    personal: str = Field(default="", pattern=r"^(|yes|no)$")
    person_id: int | None = None
    device_id: int | None = None


class QuickHier(Params):
    """Иерархия: вид отчёта и условия страницы (поиск, подразделение, ветка выбранного сотрудника — его идентификатор из ссылки #p…)."""
    view: str = Field(default="people", pattern=r"^(people|tree|chain|depts|managers|roles|crossdept|dups|service|quality|changes|problems|pack)$")
    q: str = Field(default="", max_length=200)
    dept: str = Field(default="", max_length=300)
    branch: str = Field(default="", pattern=r"^[0-9a-f]{0,10}$")
    direct: bool = False                                          # с руководителем (branch): только непосредственные подчинённые
    include_reviewed: bool = False                                # в отчёте «Подразделения и подчинённость» показать и проверенные исключения
    base: str = Field(default="", max_length=40)                  # выгрузка для сравнения (по умолчанию — предыдущая)


class QuickAdmin(Params):
    """Таблицы администрирования: вид и фильтры страницы (журнал событий — текст, уровень, компонент, период; журнал действий — текст, действие, период; компоненты — статус; импорт BI — источник)."""
    view: str = Field(default="journal", pattern=r"^(licenses|journal|audit|users|components|bi_imports)$")
    q: str = Field(default="", max_length=200)
    level: str = Field(default="", pattern=r"^(|debug|info|warn|error)$")
    category: str = Field(default="", max_length=24)
    range: str = Field(default="", pattern=r"^(|1h|24h|7d|30d)$")
    action: str = Field(default="", max_length=80)
    status: str = Field(default="", max_length=24)
    source_id: str = Field(default="", max_length=40)
    since: str = Field(default="", max_length=40)                       # произвольный период журнала событий (ISO 8601)
    until: str = Field(default="", max_length=40)


class QuickHunt(Params):
    """Целевой поиск (CVE Hunt): задание, статусы (по умолчанию подтверждено и вероятно), поиск и зона; coverage — добавить журнал охвата."""
    job_id: str = Field(default="", max_length=40)
    view: Literal["results", "jobs"] = "results"                        # jobs — история заданий
    status: str = Field(default="", max_length=120)
    statuses: list[str] = Field(default_factory=lambda: ["confirmed", "probable"], max_length=3)
    q: str = Field(default="", max_length=200)
    zone: str = Field(default="", max_length=120)
    coverage: bool = False

    @field_validator("statuses")
    @classmethod
    def _st(cls, v: list[str]) -> list[str]:
        return [x for x in dict.fromkeys(v) if x in ("confirmed", "probable", "needs_check")] or ["confirmed", "probable"]


class QuickPentest(Params):
    """Результаты Pentest: задание и условия страницы результатов (выбранные адреса, поиск, адрес, порт, сервис, опасность, уверенность, CVE); view=jobs — список заданий."""
    job_id: str = Field(default="", max_length=40)
    view: Literal["results", "jobs"] = "results"
    status: str = Field(default="", max_length=120)
    ips: list[str] = Field(default_factory=list, max_length=2000)
    q: str = Field(default="", max_length=200)
    ip: str = Field(default="", max_length=200)
    port: int | None = Field(default=None, ge=1, le=65535)
    service: str = Field(default="", max_length=100)
    severity: str = Field(default="", max_length=60)
    confidence: str = Field(default="", max_length=80)
    cve: str = Field(default="", max_length=100)
    exploited: bool = False
    hide_not_confirmed: bool = False
    category: str = Field(default="", max_length=80)
    engine: str = Field(default="", max_length=60)
    levels: list[str] = Field(default_factory=lambda: ["critical"], max_length=5)         # уровни критичности отчёта; по умолчанию только критические

    @field_validator("levels")
    @classmethod
    def _levels(cls, v: list[str]) -> list[str]:
        ok = [x for x in dict.fromkeys(v) if x in ("critical", "high", "medium", "low", "info")]
        return ok or ["critical"]


class QuickOverview(Params):
    """Сводка инфраструктуры: условия главной страницы (период активности, показатель, источник)."""
    days: int = Field(default=30, ge=1, le=365)
    metric: str = Field(default="", max_length=20, pattern=r"^[a-z_]*$")
    source_id: str = Field(default="", max_length=40)


QUICK_PARAMS = {"quick_admin": QuickAdmin, "quick_pentest": QuickPentest, "quick_hunt": QuickHunt, "quick_bi": QuickBi, "quick_hier": QuickHier, "quick_overview": QuickOverview, "quick_zone": QuickZone, "quick_vulns": QuickVulns, "quick_hosts": QuickHosts, "quick_protection": QuickProtection, "quick_events": QuickEvents, "quick_extvulns": QuickExtVulns, "quick_eol": QuickEol, "quick_devices": QuickDevices}


class ReportIn(BaseModel):
    kind: str = Field(pattern=r"^(software_hosts|hosts|version_audit|quick_zone|quick_vulns|quick_hosts|quick_protection|quick_events|quick_extvulns|quick_eol|quick_devices|quick_overview|quick_pentest|quick_hunt|quick_bi|quick_hier|quick_admin)$")
    title: str = Field(default="", max_length=300)
    params: dict
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class PreviewIn(BaseModel):
    params: AuditParams
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    limit: int = Field(default=300, ge=1, le=20_000)     # интерфейс запрашивает все строки (в пределах max_rows) и показывает их непрерывным списком


class SavedCheckIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    params: AuditParams
    source_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    shared: bool = True


class OverrideIn(BaseModel):
    kind: Literal["merge", "split", "rename"]
    from_key: str | None = Field(default=None, max_length=160)
    match_names: list[str] = Field(default_factory=list, max_length=200)
    to_key: str | None = Field(default=None, max_length=160)
    to_name: str | None = Field(default=None, max_length=300)
    to_publisher: str | None = Field(default=None, max_length=300)
    note: str | None = Field(default=None, max_length=1000)


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern=r"^(software_hosts|hosts|version_audit|quick_zone|quick_vulns|quick_hosts|quick_protection|quick_events|quick_extvulns|quick_eol|quick_devices|quick_overview|quick_pentest|quick_hunt|quick_bi|quick_hier|quick_admin)$")
    params: dict
    shared: bool = True


class CheckIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    selection: ReportParams
    cve: str | None = Field(default=None, max_length=300)
    severity: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    description: str | None = Field(default=None, max_length=4000)
    comment: str | None = Field(default=None, max_length=4000)
