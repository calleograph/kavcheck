"""Настройки приложения из административной панели (таблица app_settings). Группы типизированы pydantic-моделями;
секретные поля хранятся зашифрованными (SecretBox) и наружу не отдаются — только флаг «задано». Пустая строка в PUT очищает секрет, отсутствие поля — не меняет."""
from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AppSetting, utcnow
from ..security.secretbox import SecretBox, SecretBoxError


class SettingsError(Exception):
    pass


class _Group(BaseModel):
    SECRETS: ClassVar[tuple[str, ...]] = ()
    model_config = {"extra": "forbid"}


class GeneralSettings(_Group):
    """Общие параметры: порог активности устройств, часовой пояс, название установки."""
    site_name: str = Field(default="KAV Checker", max_length=80)
    activity_days: int = Field(default=30, ge=1, le=3650)            # «Показывать компьютеры, активные за последние N суток»: остальные скрыты в рабочих разделах
    timezone: str = Field(default="UTC", max_length=64)
    report_keep_days: int = Field(default=90, ge=1, le=3650)         # сколько хранить сформированные отчёты
    journal_keep_days: int = Field(default=90, ge=1, le=3650)         # устарело: срок хранения журнала событий задаётся в «Журналы и хранение»
    components_check: bool = True                                    # фоновая проверка доступных версий компонентов (GitHub, PyPI, npm, endoflife.date); без доступа в интернет кэш остаётся пустым

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("timezone: неизвестный часовой пояс (пример: Europe/Moscow)") from None
        return v


class LdapSettings(_Group):
    """Настройка LDAP версии 0.1.0 (одно подключение). С 0.2.0 подключения хранятся в таблице ldap_connections; группа читается только для переноса."""
    SECRETS: ClassVar[tuple[str, ...]] = ("bind_password",)
    enabled: bool = False
    host: str = Field(default="", max_length=253)
    port: int = Field(default=636, ge=1, le=65535)
    protocol: Literal["ldaps", "starttls", "ldap"] = "ldaps"
    base_dn: str = Field(default="", max_length=1000)
    bind_dn: str = Field(default="", max_length=1000)
    bind_password: str = ""
    user_filter: str = Field(default="(&(objectClass=user)(sAMAccountName={login}))", max_length=1000)
    group_filter: str = Field(default="(objectClass=group)", max_length=1000)
    login_attribute: str = Field(default="sAMAccountName", max_length=64)
    display_name_attribute: str = Field(default="displayName", max_length=64)
    email_attribute: str = Field(default="mail", max_length=64)
    guid_attribute: str = Field(default="objectGUID", max_length=64)
    admin_group_dn: str = Field(default="", max_length=1000)
    analyst_group_dn: str = Field(default="", max_length=1000)
    viewer_group_dn: str = Field(default="", max_length=1000)
    verify_cert: bool = True
    ca_pem: str = Field(default="", max_length=200_000)
    timeout_s: int = Field(default=5, ge=1, le=60)
    nested_groups: bool = True
    migrated: bool = False

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if v and not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", v):
            raise ValueError("host: имя сервера или IP без схемы и слэшей")
        return v

    @field_validator("user_filter")
    @classmethod
    def _flt(cls, v: str) -> str:
        if "{login}" not in v:
            raise ValueError("user_filter должен содержать {login}")
        return v


class ReportsSettings(_Group):
    """Ограничения отчётов и запросов к SQL Server."""
    max_rows: int = Field(default=100_000, ge=1000, le=5_000_000)
    include_inactive_default: bool = False
    exclude_slave_servers: bool = True          # bIsSlaveServer = 1 — кластеры и подчинённые серверы, не компьютеры


class AuthSecuritySettings(_Group):
    """Второй фактор (TOTP). Политика: off — не предлагается; optional — каждый включает сам; admins — обязателен администраторам;
    all — всем; groups — участникам указанных групп каталога. Локальные администраторы подчиняются той же политике."""
    totp_policy: Literal["off", "optional", "admins", "all", "groups"] = "optional"
    totp_groups: str = Field(default="", max_length=8000)          # DN групп через «;» или с новой строки
    totp_issuer: str = Field(default="KAV Checker", max_length=60)

    def group_set(self) -> set[str]:
        return {g.strip().lower() for g in re.split(r"[;\n]", self.totp_groups) if g.strip()}


class SmtpSettings(_Group):
    """Отправка отчётов по электронной почте. Пароль хранится зашифрованным и наружу не отдаётся."""
    SECRETS: ClassVar[tuple[str, ...]] = ("password",)
    enabled: bool = False
    host: str = Field(default="", max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str = Field(default="", max_length=254)
    password: str = ""
    from_addr: str = Field(default="", max_length=254)
    from_name: str = Field(default="KAV Checker", max_length=80)
    verify_cert: bool = True
    timeout_s: int = Field(default=20, ge=3, le=120)
    max_attach_mb: int = Field(default=8, ge=1, le=50)              # вложения больше предела не отправляются, письмо содержит сводку и ссылку на интерфейс
    retry_max: int = Field(default=5, ge=1, le=20)                  # попыток отправки одного письма
    retry_minutes: int = Field(default=10, ge=1, le=1440)           # пауза перед первой повторной попыткой (дальше удваивается)
    alert_email: str = Field(default="", max_length=254)            # куда сообщить администратору о недоставленных отчётах
    base_url: str = Field(default="", max_length=300)               # адрес KAV Checker для ссылок в письмах (https://…); пусто — без ссылок

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if v and not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", v):
            raise ValueError("host: имя сервера или IP без схемы и слэшей")
        return v

    @field_validator("from_addr", "alert_email")
    @classmethod
    def _mail(cls, v: str) -> str:
        v = v.strip()
        if v and not re.fullmatch(r"[^\s@<>()\[\],;:\\\"]+@[^\s@<>()\[\],;:\\\"]+\.[^\s@<>()\[\],;:\\\"]{2,}", v):
            raise ValueError("адрес электронной почты записан неверно")
        return v

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if v and not re.fullmatch(r"https?://[A-Za-z0-9._:\-\[\]]+(/[A-Za-z0-9._~/%\-]*)?", v):
            raise ValueError("base_url: адрес вида https://kav.example.local")
        return v


class OrganizationSettings(_Group):
    """Данные организации для шапок и подвалов отчётов (HTML, Excel, печать, письма). Всё необязательно: пустые поля в отчёты не попадают."""
    full_name: str = Field(default="", max_length=300)
    short_name: str = Field(default="", max_length=120)
    unit: str = Field(default="", max_length=200)                   # подразделение или служба, формирующая отчёты
    contact_email: str = Field(default="", max_length=254)
    contacts: str = Field(default="", max_length=500)               # телефон, кабинет, часы работы — произвольным текстом
    classification: str = Field(default="", max_length=80)          # «Для служебного пользования», «Внутренний документ»…
    footnote: str = Field(default="", max_length=600)               # стандартное примечание в конце отчёта
    signature: str = Field(default="", max_length=200)              # «Составил: …»
    logo: str = Field(default="", max_length=400_000)                # data:image/png|jpeg|webp;base64,… (загружается через интерфейс)
    show_logo: bool = True

    @field_validator("logo")
    @classmethod
    def _logo(cls, v: str) -> str:
        if v and not re.fullmatch(r"data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+", v):
            raise ValueError("logo: допустимы PNG, JPEG и WebP")
        return v


class ZonecacheSettings(_Group):
    """Ночной расчёт данных зон ответственности и ограничения фоновой обработки. Страницы зон читают готовые данные; тяжёлые вычисления выполняет worker по одному."""
    enabled: bool = True
    at: str = Field(default="03:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")             # время начала ночного расчёта (по часовому поясу ниже)
    timezone: str = Field(default="", max_length=64)                   # пусто — часовой пояс организации (Общие настройки)
    parallel: int = Field(default=1, ge=1, le=2)                       # сколько тяжёлых фоновых задач (расчёт зон, анализ уязвимостей, каталог) одновременно
    intensity: Literal["low", "normal", "high"] = "normal"             # размер порции и паузы между порциями: low — медленнее и мягче для KSC и сервера
    max_detections: int = Field(default=3_000_000, ge=10_000, le=20_000_000)    # больше обнаружений на источник — сохраняются только счётчики по компьютерам
    ext_per_host: int = Field(default=60, ge=10, le=1000)             # потенциальных совпадений с внешними базами в списке на компьютер (итоги учитывают все)
    stale_hours: int = Field(default=36, ge=1, le=720)                 # отчёты по расписанию обновляют данные зоны, если им больше этого возраста

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        if v:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415
            try:
                ZoneInfo(v)
            except (ZoneInfoNotFoundError, ValueError):
                raise ValueError("timezone: неизвестный часовой пояс (пример: Europe/Moscow)") from None
        return v


class EolSettings(_Group):
    """Жизненный цикл ПО и ОС (EOL): как учитывается в аналитике и когда окончание поддержки считается приближающимся."""
    include_in_analytics: bool = True          # EOL в общем списке проблем, дашбордах зон и сводках; выключено — остаётся отдельный раздел «EOL»
    soon_days: int = Field(default=180, ge=30, le=730)          # за сколько суток до окончания стандартной поддержки показывать «приближается»


class DevicesSettings(_Group):
    """Пользователи устройств: KSC хранит списки «вошли сейчас» и «входили ранее» без дат, поэтому KAV Checker опрашивает их по расписанию и накапливает наблюдения."""
    enabled: bool = True
    interval_minutes: int = Field(default=60, ge=10, le=1440)         # как часто опрашивать списки пользователей в KSC (опрос лёгкий: одна выборка порциями)
    retention_days: int = Field(default=90, ge=8, le=730)              # сколько хранить наблюдения за пользователями, которых KSC больше не показывает
    hide_service: bool = True                                           # в таблицах не показывать служебные и системные учётные записи
    service_masks: list[str] = Field(default_factory=lambda: ["svc*", "*_svc", "*-svc", "service*", "krbtgt", "iusr*", "iwam*"], max_length=100)   # маски служебных записей (звёздочка — любое число символов)


class HardwareSettings(_Group):
    """Контроль аппаратных ресурсов Linux-серверов для Kaspersky Endpoint Security for Linux (по инвентаризации оборудования KSC). Нет данных об оборудовании — оценка не выполняется."""
    enabled: bool = True
    cpu_ok_cores: int = Field(default=3, ge=1, le=64)            # столько ядер и больше — норма; меньше — «Мало ядер CPU» (предупреждение)
    cpu_critical_cores: int = Field(default=1, ge=1, le=64)      # столько ядер и меньше — «Недостаточно ядер CPU» (критическая)
    ram_min_mb: int = Field(default=1792, ge=256, le=1_048_576)  # меньше — «Недостаточно ОЗУ» (предупреждение); 1792 МБ, а не 2048: сервер «с 2 ГБ» часто сообщает 1,9 ГБ (часть памяти занята системой) и должен проходить; требования зависят от версии KESL и нагрузки: уточните для своих серверов
    exclude_masks: list[str] = Field(default_factory=list, max_length=100)   # имена устройств (маски `*`), которые не проверяются: рабочие станции под Linux, тестовые стенды


class PentestSettings(_Group):
    """Сетевое сканирование (модуль Pentest): область разрешённых адресов, пределы нагрузки, хранение. Сканер работает в отдельном контейнере; эти значения читает он."""
    enabled: bool = True
    # Область разрешений: оператор может сканировать только адреса внутри неё. По умолчанию — частные сети (RFC 1918, ULA) и документационный 192.0.2.0/24; публичные адреса — только если добавлены сюда.
    allowed_networks: list[str] = Field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "192.0.2.0/24"], max_length=200)
    denied_networks: list[str] = Field(default_factory=list, max_length=200)               # исключения из области разрешений (всегда не сканируются)
    hunt_networks: list[str] = Field(default_factory=list, max_length=200)                 # «вся инфраструктура» для CVE Hunt: сети, которые просматривает целевой поиск (в пределах области разрешений); плюс активные компьютеры KSC
    allow_loopback: bool = False                                                            # сканирование самого сервера (127.0.0.0/8, ::1) — только для проверки установки
    max_targets: int = Field(default=4096, ge=1, le=262_144)                              # адресов в одном задании
    large_threshold: int = Field(default=256, ge=1, le=262_144)                           # с этого числа адресов запуск требует отдельного подтверждения
    full_ports_max_targets: int = Field(default=64, ge=1, le=4096)                        # полный профиль (65 535 портов) не запускается на большем числе адресов
    max_concurrent_jobs: int = Field(default=1, ge=1, le=4)
    max_concurrent_hosts: int = Field(default=4, ge=1, le=32)                             # одновременно определяются сервисы на стольких адресах
    batch_size: int = Field(default=32, ge=1, le=256)                                       # адресов в одном запуске Nmap на этапе портов
    max_rate: int = Field(default=300, ge=10, le=10_000)                                   # предел скорости проб (пакетов в секунду) на запуск Nmap
    max_parallelism: int = Field(default=100, ge=1, le=1000)                               # одновременных проб (соединений) на запуск Nmap: --max-parallelism
    nmap_memory_mb: int = Field(default=1500, ge=256, le=16384)                            # предел памяти одного процесса Nmap (RLIMIT_AS)
    nmap_nice: int = Field(default=10, ge=0, le=19)                                        # приоритет процесса Nmap ниже обычного: сканирование не отнимает CPU у сервера
    host_timeout_s: int = Field(default=300, ge=30, le=3600)                                # на адрес на этапе портов
    service_timeout_s: int = Field(default=180, ge=30, le=1800)                             # на адрес на этапе определения сервисов
    job_timeout_h: int = Field(default=12, ge=1, le=168)
    scan_type: Literal["auto", "connect", "syn"] = "auto"                                   # auto — SYN, если у процесса есть CAP_NET_RAW, иначе обычное соединение
    safe_scripts_enabled: bool = False                                                       # разрешить профиль «расширенная безопасная проверка» (заранее заданные скрипты Nmap категории safe)
    retention_days: int = Field(default=180, ge=7, le=3650)                                 # сколько хранить завершённые задания
    evidence_max_kb: int = Field(default=8, ge=1, le=256)                                   # предел размера технических доказательств одного порта
    custom_profiles: list[dict] = Field(default_factory=list, max_length=20)                # профили портов, добавленные администратором: {key, name, ports, intensity}
    # Nuclei и расширенные проверки (шаблоны выполняются только из каталога разрешённых проверок: «Pentest → Шаблоны и проверки»)
    nuclei_enabled: bool = True                                                              # Nuclei можно выключить целиком: задания остаются на Nmap
    nuclei_rate: int = Field(default=50, ge=1, le=1000)                                      # запросов в секунду на запуск Nuclei (-rl)
    nuclei_concurrency: int = Field(default=10, ge=1, le=100)                               # одновременных шаблонов (-c)
    nuclei_bulk: int = Field(default=10, ge=1, le=100)                                       # одновременных целей на шаблон (-bs)
    nuclei_timeout_s: int = Field(default=10, ge=2, le=120)                                  # время ожидания ответа одного запроса
    nuclei_batch_hosts: int = Field(default=8, ge=1, le=64)                                  # хостов в одном запуске Nuclei (результаты готовых пачек сохраняются сразу)
    nuclei_run_timeout_s: int = Field(default=900, ge=5, le=14400)                          # предельное время одного запуска Nuclei
    nuclei_memory_mb: int = Field(default=1024, ge=256, le=16384)                            # предел памяти процесса Nuclei (GOMEMLIMIT и контроль размера процесса)
    nuclei_nice: int = Field(default=10, ge=0, le=19)
    nuclei_max_requests: int = Field(default=20_000, ge=100, le=1_000_000)                  # бюджет запросов на задание: при превышении проверки останавливаются, результаты сохраняются
    nse_ssl_enum: bool = False                                                               # разрешить ssl-enum-ciphers (десятки TLS-рукопожатий на порт) в профиле «расширенное»
    hit_retention_days: int = Field(default=60, ge=1, le=3650)                               # сырые результаты Nuclei хранятся не дольше (находки — по сроку хранения заданий)

    @field_validator("allowed_networks", "denied_networks", "hunt_networks")
    @classmethod
    def _nets(cls, v: list[str]) -> list[str]:
        import ipaddress  # noqa: PLC0415

        out = []
        for x in v:
            try:
                out.append(str(ipaddress.ip_network(x.strip(), strict=False)))
            except ValueError:
                raise ValueError(f"«{x}» — не сеть (пример: 10.0.0.0/8 или 192.0.2.0/24)") from None
        return out


class LogsSettings(_Group):
    """Хранение журналов (Администрирование → «Журналы и хранение»). Операционные журналы чистятся по сроку и объёму; журнал действий (аудит) — отдельная политика: по умолчанию не удаляется,
    а при заданном сроке записи сначала переносятся в сжатый архив. Результаты сканирований этими настройками не затрагиваются."""
    journal_days: int = Field(default=30, ge=1, le=3650)             # журнал событий приложения (ошибки, источники KSC, каталог, EOL, базы уязвимостей, отчёты, система)
    journal_max_mb: int = Field(default=500, ge=0, le=102_400)       # 0 — без предела объёма
    journal_archive: bool = False                                    # перед удалением переносить записи в сжатый архив
    journal_by_category: dict[str, int] = Field(default_factory=dict, max_length=20)   # срок по категориям события (auth, ksc, report, catalog, worker, admin, system), суток; остальные — journal_days
    audit_days: int = Field(default=0, ge=0, le=3650)                # журнал действий: 0 — не удалять; иначе не меньше 90 суток, записи удаляются только после переноса в архив
    audit_max_mb: int = Field(default=0, ge=0, le=102_400)           # для аудита предел объёма только предупреждает: записи по объёму не удаляются
    pt_events_days: int = Field(default=90, ge=1, le=3650)           # журналы выполнения заданий Pentest (находки и результаты не затрагиваются)
    pt_events_max_mb: int = Field(default=200, ge=0, le=102_400)
    pt_events_archive: bool = False
    archive_days: int = Field(default=180, ge=1, le=3650)            # срок хранения архивов
    archive_max_files: int = Field(default=200, ge=1, le=10_000)     # предел числа архивных файлов
    archive_file_mb: int = Field(default=50, ge=1, le=1024)          # ротация по размеру: файл архива закрывается и начинается следующий
    compress: bool = True                                            # архивы сжимаются gzip
    quota_mb: int = Field(default=1024, ge=0, le=1_048_576)          # общий предел журналов в базе и архивов; 0 — без предела
    auto_clean: bool = True                                          # автоматическая очистка по сроку и объёму
    rotate_hours: int = Field(default=24, ge=1, le=168)              # как часто запускается ротация
    disk_warn_free_mb: int = Field(default=2048, ge=100, le=1_048_576)   # предупреждать, когда на диске данных свободно меньше

    @field_validator("audit_days")
    @classmethod
    def _audit(cls, v: int) -> int:
        if 0 < v < 90:
            raise ValueError("журнал действий нельзя хранить меньше 90 суток (0 — не удалять)")
        return v

    @field_validator("journal_by_category")
    @classmethod
    def _cats(cls, v: dict[str, int]) -> dict[str, int]:
        for k, d in v.items():
            if not (isinstance(k, str) and k.isalnum() and len(k) <= 24 and isinstance(d, int) and 1 <= d <= 3650):
                raise ValueError("сроки по категориям: имя категории и число суток от 1 до 3650")
        return v


class BiSettings(_Group):
    """BI-выгрузки (Excel через SMB): общие ограничения для всех BI-источников."""
    allowed_hosts: list[str] = Field(default_factory=list, max_length=100)   # разрешённые SMB-серверы: имя (маска со звёздочкой) или сеть CIDR; пусто — любой, кроме петлевых и link-local


THEMES = ("night", "glass", "grove", "aurora")                        # «Тёмный профессиональный» (по умолчанию), «Современный и лёгкий», «Корпоративный минимализм», «Современный градиентный»


class AppearanceSettings(_Group):
    """Внешний вид: тема по умолчанию для всех, кто не выбрал свою (личный выбор в профиле важнее)."""
    default_theme: Literal["night", "glass", "grove", "aurora"] = "night"


GROUPS: dict[str, type[_Group]] = {"appearance": AppearanceSettings, "bi": BiSettings, "pentest": PentestSettings, "general": GeneralSettings, "ldap": LdapSettings, "reports": ReportsSettings, "auth_security": AuthSecuritySettings, "smtp": SmtpSettings,
                                   "organization": OrganizationSettings, "zonecache": ZonecacheSettings, "eol": EolSettings, "devices": DevicesSettings, "hardware": HardwareSettings, "logs": LogsSettings}


class SettingsService:
    def __init__(self, box: SecretBox | None):
        self.box = box

    async def _row(self, db: AsyncSession, group: str) -> AppSetting | None:
        return await db.get(AppSetting, group)

    async def raw(self, db: AsyncSession, group: str) -> dict:
        row = await self._row(db, group)
        return dict(row.value or {}) if row else {}

    async def get(self, db: AsyncSession, group: str) -> _Group:
        """Модель группы: секреты расшифрованы (для использования внутри приложения)."""
        model = GROUPS[group]
        data = await self.raw(db, group)
        for s in model.SECRETS:
            enc = data.pop(f"{s}_enc", None)
            data[s] = self.decrypt(enc, f"{group}.{s}") if enc else ""
        try:
            return model(**{k: v for k, v in data.items() if k in model.model_fields})
        except ValidationError:
            return model()

    async def public(self, db: AsyncSession, group: str) -> dict:
        """Для интерфейса: вместо секрета — флаг <имя>_set."""
        model = GROUPS[group]
        cfg = await self.get(db, group)
        out = cfg.model_dump()
        for s in model.SECRETS:
            out[f"{s}_set"] = bool(out.pop(s))
        return out

    async def update(self, db: AsyncSession, group: str, patch: dict[str, Any], *, actor: str) -> list[str]:
        model = GROUPS[group]
        cur = await self.raw(db, group)
        merged = {k: v for k, v in cur.items() if not k.endswith("_enc")}
        changed = []
        for k, v in patch.items():
            if k in model.SECRETS:
                continue
            if k not in model.model_fields:
                raise SettingsError(f"Неизвестное поле: {k}")
            if merged.get(k) != v:
                changed.append(k)
            merged[k] = v
        try:
            validated = model(**{**{s: "" for s in model.SECRETS}, **merged})
        except ValidationError as exc:
            raise SettingsError("; ".join(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors())) from None
        data = validated.model_dump()
        for s in model.SECRETS:
            data.pop(s, None)
            if s in patch and patch[s] is not None:
                if patch[s] == "":
                    data.pop(f"{s}_enc", None)
                else:
                    data[f"{s}_enc"] = self.encrypt(str(patch[s]), f"{group}.{s}")
                changed.append(s)
            elif cur.get(f"{s}_enc"):
                data[f"{s}_enc"] = cur[f"{s}_enc"]
        row = await self._row(db, group)
        if row is None:
            row = AppSetting(group=group, value=data)
            db.add(row)
        else:
            row.value = data
        row.updated_at, row.updated_by = utcnow(), actor
        await db.flush()
        return changed

    def encrypt(self, value: str, aad: str) -> str:
        if self.box is None:
            raise SettingsError("APP_MASTER_KEY не задан: секреты сохранить нельзя")
        return self.box.encrypt(value, aad=aad.encode())

    def decrypt(self, token: str | None, aad: str) -> str:
        if not token or self.box is None:
            return ""
        try:
            return self.box.decrypt(token, aad=aad.encode())
        except SecretBoxError:
            return ""
