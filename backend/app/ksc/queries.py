"""Проверенные SQL-шаблоны для базы Kaspersky Security Center (поддерживаются KSC 14–15.1, Microsoft SQL Server).
Параметры — только через плейсхолдеры pymssql (%s / %(name)s); строки в запрос не подставляются, кроме проверенных целых чисел (списки идентификаторов).
Все даты в базе KSC — UTC. Источник знаний о структуре — docs/ksc/."""
from __future__ import annotations

IP_EXPR = ("CAST((h.nIp / 16777216) % 256 AS varchar(3)) + '.' + CAST((h.nIp / 65536) % 256 AS varchar(3)) + '.' + "
           "CAST((h.nIp / 256) % 256 AS varchar(3)) + '.' + CAST(h.nIp % 256 AS varchar(3))")

HOST_COLS = ("h.nId AS host_id, h.wstrDisplayName AS name, h.wstrDnsName AS dns_name, h.wstrDnsDomain AS dns_domain, h.nIp AS ip_int, h.wstrOSName AS os_name, "
             "h.nPlatformType AS platform_type, h.nVersionMajor AS os_major, h.nVersionMinor AS os_minor, h.nOsBuildNumber AS os_build, h.nGroup AS group_id, "
             "h.tmLastNagentConnected AS last_connected, h.tmLastVisible AS last_visible, h.tmLastInfoUpdate AS last_info_update, h.tmLastUpdate AS last_av_update, "
             "h.tmLastFullScan AS last_full_scan, h.nStatus AS status_bits, h.nLastRtpState AS rtp_state, h.bIsSlaveServer AS is_slave, h.nPkgMgrType AS pkg_mgr, "
             "h.nComputerType AS computer_type, h.nProcType AS proc_type, h.tmCreated AS created")

SERVER_INFO = "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS version, CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition, DB_NAME() AS db_name, CAST(SERVERPROPERTY('Collation') AS nvarchar(128)) AS collation"
OBJECTS_EXIST = "SELECT o.name AS name, o.type AS type FROM sys.objects o WHERE o.schema_id = SCHEMA_ID('dbo') AND o.type IN ('U','V') AND o.name IN ({names})"
DB_ROLES = ("SELECT IS_MEMBER('db_datareader') AS datareader, IS_MEMBER('db_datawriter') AS datawriter, IS_MEMBER('db_owner') AS owner, "
            "IS_MEMBER('db_ddladmin') AS ddladmin, USER_NAME() AS db_user")
KSC_VERSION = "SELECT TOP (1) p.wstrProductBuildNumber AS build FROM dbo.v_akpub_hst_prdstate p WHERE p.wstrProductNameId = '1093' ORDER BY p.nHost"

# --- сводка главной страницы
SERVER_IDENTITY = "SELECT CAST(@@SERVERNAME AS nvarchar(256)) AS server, DB_NAME() AS db"
COUNT_HOSTS = "SELECT COUNT(*) AS n FROM dbo.v_akpub_host h WHERE h.bIsSlaveServer = 0"
COUNT_HOSTS_ACTIVE = "SELECT COUNT(*) AS n FROM dbo.v_akpub_host h WHERE h.bIsSlaveServer = 0 AND h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE())"
# EOL: компьютеры (ОС) порциями по nId и устройства с заданными записями реестра ПО; признак активности считается в SQL (даты KSC — UTC)
_ACTIVE = "CASE WHEN h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE()) THEN 1 ELSE 0 END"
EOL_OS_HOSTS = ("SELECT TOP (%(n)s) h.nId AS host_id, h.wstrOSName AS os_name, h.nVersionMajor AS os_major, h.nVersionMinor AS os_minor, h.nOsBuildNumber AS os_build, " + _ACTIVE + " AS active "
                "FROM dbo.v_akpub_host h WHERE h.nId > %(after)s AND {where} ORDER BY h.nId")
EOL_APP_HOSTS = ("SELECT i.nHostId AS host_id, i.nProduct AS product_id, " + _ACTIVE + " AS active FROM dbo.hst_inventory_hstprds i JOIN dbo.v_akpub_host h ON h.nId = i.nHostId "
                 "WHERE i.bDeleted = 0 AND {where} AND i.nProduct IN ({ids})")
# пользователи устройств: hst_user_visited — вошедшие сейчас (bActual = 1) и входившие ранее (0); дат во внутренних списках KSC нет. Порциями по nId.
USERS_VISITED = ("SELECT TOP (%(n)s) v.nId AS row_id, v.nHost AS host_id, v.nUser AS user_id, v.bActual AS actual, CONVERT(varchar(34), v.binSidHash, 1) AS sid_hash, "
                 "u.wstrSamAccountName AS login, u.wstrUserPrincipalName AS upn, u.wstrDisplayName AS display_name, u.nHostId AS local_host "
                 "FROM dbo.hst_user_visited v LEFT JOIN dbo.ak_users u ON u.nId = v.nUser WHERE v.nId > %(after)s ORDER BY v.nId")
# оборудование (инвентаризация Агента): hst_hwinv_dev — по строке на компонент; типы nDevType: 0 плата, 1 процессор, 2 модуль ОЗУ, 3 накопитель, 4 видео, 5 звук, 6 сеть, 7 монитор, 8 привод.
# XPar1 — серийный номер (накопитель, монитор) или MAC (сеть); XPar2 — объём накопителя в байтах / скорость сети; XPar3 — объём модуля ОЗУ в байтах / свободное место накопителя в байтах
HW_HOST = ("SELECT d.nId AS id, d.nDevType AS dev_type, n.wstrName AS name, ds.wstrDescr AS descr, m.wstrManuf AS manuf, d.wstrDevId AS dev_id, d.wstrSerialNum AS serial, d.XPar1 AS x1, "
           "d.XPar2 AS x2, d.XPar3 AS x3, d.nCpuSpeed AS cpu_mhz, d.nCpuCores AS cpu_cores, d.nCpuThreads AS cpu_threads, d.strBiosManuf AS bios_manuf, d.strBiosVersion AS bios_version, "
           "d.dtBiosRelease AS bios_date FROM dbo.hst_hwinv_dev d LEFT JOIN dbo.hwinv_dev_name n ON n.nId = d.nNameId LEFT JOIN dbo.hwinv_dev_descr ds ON ds.nId = d.nDescrId "
           "LEFT JOIN dbo.hwinv_dev_manuf m ON m.nId = d.nManufId WHERE d.bDeleted = 0 AND d.nHostId = %(id)s ORDER BY d.nDevType, d.nId")
_HW_AGG = ("SELECT d.nHostId AS host_id, SUM(CASE WHEN d.nDevType = 1 THEN 1 ELSE 0 END) AS cpus, SUM(CASE WHEN d.nDevType = 1 AND d.nCpuCores IS NOT NULL THEN 1 ELSE 0 END) AS cpus_known, "
           "SUM(CASE WHEN d.nDevType = 1 THEN ISNULL(d.nCpuCores, 0) ELSE 0 END) AS cores, SUM(CASE WHEN d.nDevType = 1 THEN ISNULL(d.nCpuThreads, 0) ELSE 0 END) AS threads, "
           "SUM(CASE WHEN d.nDevType = 2 THEN 1 ELSE 0 END) AS ram_modules, SUM(CASE WHEN d.nDevType = 2 THEN ISNULL(d.XPar3, 0) ELSE 0 END) AS ram_bytes "
           "FROM dbo.hst_hwinv_dev d {join} WHERE d.bDeleted = 0 AND d.nDevType IN (1, 2) AND {where} GROUP BY d.nHostId")
HW_AGG_LINUX = _HW_AGG.format(join="JOIN dbo.v_akpub_host h ON h.nId = d.nHostId", where="h.nPlatformType = 6")
HW_AGG_FOR = _HW_AGG.format(join="", where="d.nHostId IN ({ids})")
COUNT_PRODUCTS = "SELECT COUNT(*) AS n FROM dbo.hst_inventory_products p WHERE EXISTS (SELECT 1 FROM dbo.hst_inventory_hstprds i WHERE i.nProduct = p.nId AND i.bDeleted = 0)"
COUNT_INSTALLS = "SELECT COUNT(*) AS n FROM dbo.hst_inventory_hstprds i WHERE i.bDeleted = 0"

# --- реестр ПО: страница продуктов и счётчики установок по продуктам страницы
PRODUCTS_PAGE = """SELECT p.nId AS product_id, p.wstrDisplayName AS name, p.wstrDisplayVersion AS version, p.wstrPublisher AS publisher,
       p.nPlatformTypeMask AS platform_mask, p.tmFirstAppear AS first_seen, p.bIsMsi AS is_msi
FROM dbo.hst_inventory_products p
WHERE {where}
ORDER BY {order}
OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY"""
PRODUCTS_COUNT = "SELECT COUNT(*) AS n FROM dbo.hst_inventory_products p WHERE {where}"
PRODUCTS_BY_IDS = ("SELECT p.nId AS product_id, p.wstrDisplayName AS name, p.wstrDisplayVersion AS version, p.wstrPublisher AS publisher, p.nPlatformTypeMask AS platform_mask "
                   "FROM dbo.hst_inventory_products p WHERE p.nId IN ({ids})")
PRODUCTS_BY_LIKE = ("SELECT p.nId AS product_id, p.wstrDisplayName AS name, p.wstrDisplayVersion AS version, p.wstrPublisher AS publisher, p.nPlatformTypeMask AS platform_mask "
                    "FROM dbo.hst_inventory_products p WHERE p.wstrDisplayName LIKE %(like)s {extra} ORDER BY p.nId OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY")
INSTALL_COUNTS_ACTIVE = ("SELECT i.nProduct AS product_id, COUNT(*) AS installs, COUNT(DISTINCT i.nHostId) AS hosts FROM dbo.hst_inventory_hstprds i "
                         "JOIN dbo.v_akpub_host h ON h.nId = i.nHostId AND h.bIsSlaveServer = 0 AND h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE()) "
                         "WHERE i.bDeleted = 0 AND i.nProduct IN ({ids}) GROUP BY i.nProduct")
INSTALL_COUNTS = ("SELECT i.nProduct AS product_id, COUNT(*) AS installs, COUNT(DISTINCT i.nHostId) AS hosts FROM dbo.hst_inventory_hstprds i "
                  "WHERE i.bDeleted = 0 AND i.nProduct IN ({ids}) GROUP BY i.nProduct")
INSTALLS_BY_PRODUCTS = ("SELECT i.nId AS install_id, i.nHostId AS host_id, i.nProduct AS product_id, i.tmInstallDate AS install_date FROM dbo.hst_inventory_hstprds i "
                        "WHERE i.bDeleted = 0 AND i.nProduct IN ({ids}) ORDER BY i.nId OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY")
# установленное ПО выбранных компьютеров (действующие установки) вместе с записью реестра: версия, название, производитель
INSTALLS_FOR_HOSTS = ("SELECT i.nHostId AS host_id, i.nProduct AS product_id, p.wstrDisplayName AS name, p.wstrDisplayVersion AS version, p.wstrPublisher AS publisher, i.tmInstallDate AS install_date "
                      "FROM dbo.hst_inventory_hstprds i JOIN dbo.hst_inventory_products p ON p.nId = i.nProduct WHERE i.bDeleted = 0 AND i.nHostId IN ({ids})")
HOSTS_BY_IDS = f"SELECT {HOST_COLS} FROM dbo.v_akpub_host h WHERE h.nId IN ({{ids}})"
GROUPS_ALL = "SELECT g.nId AS group_id, g.wstrName AS name, g.nParentId AS parent_id FROM dbo.v_akpub_adm_group g"
RELEASE_PACKAGES = ("SELECT i.nHostId AS host_id, p.wstrDisplayName AS name, p.wstrDisplayVersion AS version FROM dbo.hst_inventory_products p "
                    "JOIN dbo.hst_inventory_hstprds i ON i.nProduct = p.nId AND i.bDeleted = 0 "
                    "WHERE p.wstrDisplayName IN (N'base-files', N'redhat-release', N'centos-release', N'almalinux-release', N'rocky-release', N'oraclelinux-release', N'astra-version') "
                    "AND i.nHostId IN ({ids})")

# --- компьютеры
HOSTS_PAGE = f"""SELECT {HOST_COLS}, g.wstrName AS group_name
FROM dbo.v_akpub_host h LEFT JOIN dbo.v_akpub_adm_group g ON g.nId = h.nGroup
WHERE {{where}}
ORDER BY {{order}}
OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY"""
HOSTS_COUNT = "SELECT COUNT(*) AS n FROM dbo.v_akpub_host h LEFT JOIN dbo.v_akpub_adm_group g ON g.nId = h.nGroup WHERE {where}"
HOST_ONE = f"SELECT {HOST_COLS}, g.wstrName AS group_name FROM dbo.v_akpub_host h LEFT JOIN dbo.v_akpub_adm_group g ON g.nId = h.nGroup WHERE h.nId = %(id)s"
SOFTWARE_ON_HOST = ("SELECT a.nId AS install_id, a.nProductId AS product_id, a.wstrDisplayName AS name, a.wstrBuild AS version, a.wstrPublisher AS publisher, "
                    "a.tmInstallDate AS install_date, a.bMsiInstaller AS is_msi FROM dbo.v_akpub_application a WHERE a.nHostId = %(id)s ORDER BY a.wstrDisplayName")
KASPERSKY_ON_HOST = ("SELECT p.wstrProductNameId AS product_code, p.wstrProductDisplayName AS product, p.wstrProductBuildNumber AS build, p.nState AS state, "
                     "p.tmAvbasesDate AS av_bases_date, p.bAvProduct AS is_av, p.bHasRtp AS has_rtp FROM dbo.v_akpub_hst_prdstate p WHERE p.nHost = %(id)s")
HOST_STATUS = "SELECT s.nStatus AS status, s.nStatusMask AS mask FROM dbo.v_akpub_host_status s WHERE s.nId = %(id)s"

# --- уязвимости, подтверждённые KSC (действующие: не исправлены и не игнорируются)
VULNS_WHERE = "o.tmDisappearanceTime IS NULL AND o.bIgnore = 0 AND pv.bIgnore = 0 AND d.bIgnore = 0"
VULNS_PAGE = """SELECT o.nId AS occurrence_id, h.nId AS host_id, h.wstrDisplayName AS host, o.tmDetectTime AS detected, d.wstrPrimaryName AS kla_id, d.nKlSeverity AS severity,
       n.wstrName AS cve, vp.wstrName AS product, ev.strProductDisplVersion AS product_version, p.wstrDisplayName AS app_name, p.wstrDisplayVersion AS app_version,
       o.bPatchesAvailable AS patches_available, d.wstrDescriptionURL AS url
FROM dbo.vapm_vulnerability_occurence o
JOIN dbo.vapm_product_vulnerability pv ON pv.nId = o.nProductVulnerabilityId
JOIN dbo.vapm_vulnerability_descr d ON d.nId = COALESCE(pv.nVulnerabilityDescrId, o.nVulnerabilityDescrId)
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
LEFT JOIN dbo.vapm_product_exact_version ev ON ev.nId = pv.nProductExactVersionId
LEFT JOIN dbo.v_vapm_product vp ON vp.nId = ev.nProductId
LEFT JOIN dbo.vapm_vulnerability_names n ON n.nVulnerabilityDescrId = d.nId AND n.nSense = 3
LEFT JOIN dbo.hst_inventory_products p ON p.strID = o.strSoftwareInventoryProductId
WHERE {where}
ORDER BY o.tmDetectTime DESC, o.nId
OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY"""
VULNS_COUNT = """SELECT COUNT(*) AS n FROM dbo.vapm_vulnerability_occurence o
JOIN dbo.vapm_product_vulnerability pv ON pv.nId = o.nProductVulnerabilityId
JOIN dbo.vapm_vulnerability_descr d ON d.nId = COALESCE(pv.nVulnerabilityDescrId, o.nVulnerabilityDescrId)
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
LEFT JOIN dbo.vapm_vulnerability_names n ON n.nVulnerabilityDescrId = d.nId AND n.nSense = 3
WHERE {where}"""

# --- уязвимости: сводки по компьютерам и программам, список на компьютере
VULN_FROM_BASE = """FROM dbo.vapm_vulnerability_occurence o
JOIN dbo.vapm_product_vulnerability pv ON pv.nId = o.nProductVulnerabilityId
JOIN dbo.vapm_vulnerability_descr d ON d.nId = COALESCE(pv.nVulnerabilityDescrId, o.nVulnerabilityDescrId)
LEFT JOIN dbo.vapm_product_exact_version ev ON ev.nId = pv.nProductExactVersionId
LEFT JOIN dbo.v_vapm_product vp ON vp.nId = ev.nProductId"""
VULN_JOIN_INVENTORY = "LEFT JOIN dbo.hst_inventory_products p ON p.strID = o.strSoftwareInventoryProductId"
VULN_FROM = VULN_FROM_BASE + "\n" + VULN_JOIN_INVENTORY
VULN_SEV_SUMS = ("SUM(CASE WHEN d.nKlSeverity = 4 THEN 1 ELSE 0 END) AS critical, SUM(CASE WHEN d.nKlSeverity = 2 THEN 1 ELSE 0 END) AS high, "
                 "SUM(CASE WHEN d.nKlSeverity = 1 THEN 1 ELSE 0 END) AS warning, COUNT(*) AS total, SUM(CASE WHEN o.bPatchesAvailable = 1 THEN 1 ELSE 0 END) AS patchable")
# реестр ПО присоединяется только для фильтра по названию программы ({{join_inventory}}): на крупной базе соединение по strID — заметная часть времени
VULN_HOSTS_AGG = f"""WITH a AS (SELECT o.nHostId AS host_id, {VULN_SEV_SUMS}, COUNT(DISTINCT ev.nProductId) AS products, MAX(o.tmDetectTime) AS last_detected
{VULN_FROM_BASE}
{{join_inventory}}
WHERE {{where}}
GROUP BY o.nHostId)
SELECT {HOST_COLS}, a.critical, a.high, a.warning, a.total, a.patchable, a.products, a.last_detected
FROM a JOIN dbo.v_akpub_host h ON h.nId = a.host_id"""
VULN_PRODUCTS_AGG = f"""SELECT COALESCE(vp.nId, 0) AS vp_id, COALESCE(vp.wstrName, p.wstrDisplayName, N'') AS name, COUNT(DISTINCT o.nHostId) AS hosts,
       COUNT(DISTINCT d.nId) AS vulns, {VULN_SEV_SUMS}, MAX(o.tmDetectTime) AS last_detected
{VULN_FROM}
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
WHERE {{where}}
GROUP BY COALESCE(vp.nId, 0), COALESCE(vp.wstrName, p.wstrDisplayName, N'')"""
VULNS_ON_HOST = f"""SELECT TOP (5000) o.nId AS occurrence_id, d.nId AS descr_id, d.wstrPrimaryName AS kla_id, d.nKlSeverity AS severity, d.wstrDescriptionURL AS url,
       vp.nId AS vp_id, vp.wstrName AS product, ev.strProductDisplVersion AS product_version, p.wstrDisplayName AS app_name, p.wstrDisplayVersion AS app_version,
       p.wstrPublisher AS publisher, o.tmDetectTime AS detected, o.bPatchesAvailable AS patches_available
{VULN_FROM}
WHERE {VULNS_WHERE} AND o.nHostId = %(host)s
ORDER BY d.nKlSeverity DESC, o.tmDetectTime DESC"""
# Быстрые отчёты: действующие обнаружения целиком (уязвимость × компьютер × программа) с данными компьютера; keyset по o.nId, выбор — в {extra}
VULN_DETAIL = f"""SELECT TOP ({{top}}) o.nId AS occurrence_id, d.nId AS descr_id, d.wstrPrimaryName AS kla_id, d.nKlSeverity AS severity, d.wstrDescriptionURL AS url,
       vp.nId AS vp_id, vp.wstrName AS product, ev.strProductDisplVersion AS product_version, p.wstrDisplayName AS app_name, p.wstrDisplayVersion AS app_version,
       p.nId AS inv_id, p.wstrPublisher AS publisher, o.tmDetectTime AS detected, o.bPatchesAvailable AS patches_available, {HOST_COLS}
{VULN_FROM}
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
WHERE {VULNS_WHERE} AND o.nId > %(after)s {{extra}}
ORDER BY o.nId"""
# Список уязвимостей: одна строка на уязвимость KSC (KLA) с числом затронутых компьютеров
# Группировка только по идентификатору уязвимости (текстовые поля в GROUP BY замедляли запрос в пять раз); имена и ссылки — отдельным небольшим запросом
VULN_DESCR_AGG = f"""SELECT d.nId AS descr_id, COUNT(DISTINCT o.nHostId) AS hosts, COUNT(*) AS total,
       SUM(CASE WHEN o.bPatchesAvailable = 1 THEN 1 ELSE 0 END) AS patchable, MAX(o.tmDetectTime) AS last_detected
{VULN_FROM_BASE}
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
WHERE {{where}}
GROUP BY d.nId"""
VULN_DESCR_INFO = "SELECT d.nId AS descr_id, d.wstrPrimaryName AS kla_id, d.nKlSeverity AS severity, d.wstrDescriptionURL AS url FROM dbo.vapm_vulnerability_descr d WHERE d.nId IN ({ids})"
VULN_DESCR_PRODUCTS = f"""SELECT d.nId AS descr_id, COALESCE(vp.wstrName, N'') AS product, COUNT(DISTINCT o.nHostId) AS hosts
{VULN_FROM_BASE}
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
WHERE {{where}}
GROUP BY d.nId, COALESCE(vp.wstrName, N'')"""
VULN_DESCR_BY_CVE = "SELECT n.nVulnerabilityDescrId AS descr_id, n.wstrName AS name FROM dbo.vapm_vulnerability_names n WHERE n.nSense = 3 AND n.wstrName IN ({names})"
VULN_NAMES = "SELECT n.nVulnerabilityDescrId AS descr_id, n.nSense AS sense, n.wstrName AS name FROM dbo.vapm_vulnerability_names n WHERE n.nSense IN (3, 5, 6) AND n.nVulnerabilityDescrId IN ({ids})"
VULN_CVE_EXISTS = "EXISTS (SELECT 1 FROM dbo.vapm_vulnerability_names n WHERE n.nVulnerabilityDescrId = d.nId AND n.nSense = 3 AND n.wstrName LIKE %(cve)s)"

# Состояние защиты: компьютеры со статусом KSC (1:1) и защитные продукты на них — два чтения небольших таблиц, проверки — в приложении (ksc/protection.py)
PROTECTION_HOSTS = (f"SELECT {HOST_COLS}, s.nStatus AS ksc_status, s.nStatusMask AS status_mask, h.nUncured AS uncured, h.nVirusCount AS virus_count "
                    "FROM dbo.v_akpub_host h LEFT JOIN dbo.v_akpub_host_status s ON s.nId = h.nId WHERE {where}")
HOST_IDS = "SELECT h.nId AS host_id FROM dbo.v_akpub_host h WHERE {where} ORDER BY h.nId"
KSC_STAMP = ("SELECT (SELECT COUNT_BIG(*) FROM dbo.v_akpub_host h WHERE h.bIsSlaveServer = 0) AS hosts, (SELECT MAX(h.nId) FROM dbo.v_akpub_host h) AS max_host, "
             "(SELECT COUNT_BIG(*) FROM dbo.vapm_vulnerability_occurence o WHERE o.tmDisappearanceTime IS NULL) AS vulns, (SELECT MAX(o.nId) FROM dbo.vapm_vulnerability_occurence o) AS max_occ")
PROTECTION_PRODUCTS_FOR = ("SELECT p.nHost AS host_id, p.wstrProductNameId AS code, p.wstrProductDisplayName AS name, p.wstrProductBuildNumber AS build, p.nState AS state, "
                           "p.tmAvbasesDate AS bases, p.bAvProduct AS is_av, p.bHasRtp AS has_rtp FROM dbo.v_akpub_hst_prdstate p "
                           "WHERE (p.bAvProduct = 1 OR p.wstrProductNameId = '1103') AND p.nHost IN ({ids})")
PROTECTION_PRODUCTS = ("SELECT p.nHost AS host_id, p.wstrProductNameId AS code, p.wstrProductDisplayName AS name, p.wstrProductBuildNumber AS build, p.nState AS state, "
                       "p.tmAvbasesDate AS bases, p.bAvProduct AS is_av, p.bHasRtp AS has_rtp FROM dbo.v_akpub_hst_prdstate p WHERE p.bAvProduct = 1 OR p.wstrProductNameId = '1103'")

# События безопасности: всегда ограничены периодом по tmRiseTime (индекс) и типами обнаружений; время задаёт устройство — значения из будущего отсекаются
EV_SECURITY = ("'GNRL_EV_VIRUS_FOUND', 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND', 'GNRL_EV_OBJECT_NOTCURED', 'GNRL_EV_OBJECT_DELETED', 'GNRL_EV_OBJECT_CURED', "
               "'GNRL_EV_OBJECT_QUARANTINED', 'GNRL_EV_ATTACK_DETECTED'")
EV_PERIOD = "e.tmRiseTime >= DATEADD(hour, -%(hours)s, GETUTCDATE()) AND e.tmRiseTime < DATEADD(hour, 1, GETUTCDATE())"
EV_WHERE = f"{EV_PERIOD} AND e.strEventType IN ({EV_SECURITY})"
EVENTS_BY_TYPE = f"SELECT e.strEventType AS type, COUNT(*) AS n, COUNT(DISTINCT e.nHostId) AS hosts FROM dbo.v_akpub_ev_event e WHERE {EV_WHERE} GROUP BY e.strEventType"
EVENTS_HOSTS = f"""SELECT COUNT(DISTINCT e.nHostId) AS any_hosts,
  COUNT(DISTINCT CASE WHEN e.strEventType IN ('GNRL_EV_VIRUS_FOUND', 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND') THEN e.nHostId END) AS detections,
  COUNT(DISTINCT CASE WHEN e.strEventType = 'GNRL_EV_OBJECT_NOTCURED' THEN e.nHostId END) AS notcured,
  COUNT(DISTINCT CASE WHEN e.strEventType IN ('GNRL_EV_OBJECT_DELETED', 'GNRL_EV_OBJECT_CURED', 'GNRL_EV_OBJECT_QUARANTINED') THEN e.nHostId END) AS resolved,
  COUNT(DISTINCT CASE WHEN e.strEventType = 'GNRL_EV_ATTACK_DETECTED' THEN e.nHostId END) AS attacks
FROM dbo.v_akpub_ev_event e WHERE {EV_WHERE}"""
EVENTS_TREND = ("SELECT DATEADD({unit}, DATEDIFF({unit}, 0, e.tmRiseTime), 0) AS bucket, e.strEventType AS type, COUNT(*) AS n FROM dbo.v_akpub_ev_event e "
                f"WHERE {EV_WHERE} GROUP BY DATEADD({{unit}}, DATEDIFF({{unit}}, 0, e.tmRiseTime), 0), e.strEventType")
EVENTS_TOP_HOSTS = f"""SELECT TOP (15) e.nHostId AS host_id, MAX(h.wstrDisplayName) AS name, MAX(h.nIp) AS ip_int, COUNT(*) AS n,
  SUM(CASE WHEN e.strEventType IN ('GNRL_EV_VIRUS_FOUND', 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND') THEN 1 ELSE 0 END) AS detections,
  SUM(CASE WHEN e.strEventType = 'GNRL_EV_OBJECT_NOTCURED' THEN 1 ELSE 0 END) AS notcured,
  SUM(CASE WHEN e.strEventType = 'GNRL_EV_ATTACK_DETECTED' THEN 1 ELSE 0 END) AS attacks, MAX(e.tmRiseTime) AS last
FROM dbo.v_akpub_ev_event e LEFT JOIN dbo.v_akpub_host h ON h.nId = e.nHostId
WHERE {EV_WHERE} GROUP BY e.nHostId ORDER BY COUNT(*) DESC"""
EV_THREAT_KIND = "CASE WHEN e.strEventType = 'GNRL_EV_ATTACK_DETECTED' THEN 'attack' ELSE 'threat' END"
EV_THREAT_NAME = "CASE WHEN e.strEventType = 'GNRL_EV_ATTACK_DETECTED' THEN e.wstrPar1 ELSE e.wstrPar5 END"
EVENTS_TOP_THREATS = f"""SELECT TOP (15) {EV_THREAT_KIND} AS kind, {EV_THREAT_NAME} AS name, COUNT(*) AS n, COUNT(DISTINCT e.nHostId) AS hosts, MAX(e.tmRiseTime) AS last
FROM dbo.v_akpub_ev_event e WHERE {EV_PERIOD} AND e.strEventType IN ('GNRL_EV_VIRUS_FOUND', 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND', 'GNRL_EV_ATTACK_DETECTED')
GROUP BY {EV_THREAT_KIND}, {EV_THREAT_NAME} ORDER BY COUNT(DISTINCT e.nHostId) DESC, COUNT(*) DESC"""
EVENTS_PAGE = """SELECT e.nId AS event_id, e.tmRiseTime AS at, e.strEventType AS type, e.wstrEventTypeDisplayName AS type_name, e.nSeverity AS severity, e.nHostId AS host_id,
  h.wstrDisplayName AS host, h.nIp AS ip_int, e.wstrProductNameId AS product, e.wstrPar1 AS par1, e.wstrPar2 AS par2, e.wstrPar3 AS par3, e.wstrPar4 AS par4,
  e.wstrPar5 AS par5, e.wstrPar7 AS par7, e.wstrPar8 AS par8
FROM dbo.v_akpub_ev_event e LEFT JOIN dbo.v_akpub_host h ON h.nId = e.nHostId
WHERE {where} ORDER BY e.tmRiseTime DESC, e.nId DESC OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY"""
# Все события выборки одним запросом (отчёты): без OFFSET и повторного COUNT на каждой порции; TOP ограничивает чтение пределом отчёта
EVENTS_ALL = EVENTS_PAGE.replace("SELECT e.nId AS event_id", "SELECT TOP (%(cap)s) e.nId AS event_id", 1).split(" OFFSET ")[0]
EVENTS_COUNT = "SELECT COUNT(*) AS n FROM dbo.v_akpub_ev_event e LEFT JOIN dbo.v_akpub_host h ON h.nId = e.nHostId WHERE {where}"

# Объекты, необходимые функциям: по ним проверяется совместимость источника при добавлении
FEATURE_OBJECTS = {
    "hosts": ("v_akpub_host", "v_akpub_adm_group"),
    "software": ("hst_inventory_products", "hst_inventory_hstprds", "v_akpub_application", "v_akpub_host", "v_akpub_adm_group"),
    "protection": ("v_akpub_hst_prdstate", "v_akpub_host_status", "v_akpub_host"),
    "vulnerabilities": ("vapm_vulnerability_occurence", "vapm_product_vulnerability", "vapm_vulnerability_descr", "vapm_vulnerability_names",
                        "vapm_product_exact_version", "v_vapm_product", "hst_inventory_products", "v_akpub_host"),
    "events": ("v_akpub_ev_event", "v_akpub_host"),
    "users": ("hst_user_visited", "ak_users", "v_akpub_host"),
    "hardware": ("hst_hwinv_dev", "hwinv_dev_name", "hwinv_dev_descr", "hwinv_dev_manuf", "v_akpub_host"),
}


def ids_list(ids) -> str:
    """Список целых идентификаторов для IN (…): только int, иначе ValueError — строки в SQL не подставляются."""
    out = [str(int(i)) for i in ids]
    if not out:
        raise ValueError("пустой список идентификаторов")
    return ", ".join(out)
