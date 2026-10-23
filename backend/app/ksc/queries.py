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
COUNT_HOSTS = "SELECT COUNT(*) AS n FROM dbo.v_akpub_host h WHERE h.bIsSlaveServer = 0"
COUNT_HOSTS_ACTIVE = "SELECT COUNT(*) AS n FROM dbo.v_akpub_host h WHERE h.bIsSlaveServer = 0 AND h.tmLastNagentConnected >= DATEADD(day, -%(days)s, GETUTCDATE())"
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
INSTALL_COUNTS = ("SELECT i.nProduct AS product_id, COUNT(*) AS installs, COUNT(DISTINCT i.nHostId) AS hosts FROM dbo.hst_inventory_hstprds i "
                  "WHERE i.bDeleted = 0 AND i.nProduct IN ({ids}) GROUP BY i.nProduct")
INSTALLS_BY_PRODUCTS = ("SELECT i.nId AS install_id, i.nHostId AS host_id, i.nProduct AS product_id, i.tmInstallDate AS install_date FROM dbo.hst_inventory_hstprds i "
                        "WHERE i.bDeleted = 0 AND i.nProduct IN ({ids}) ORDER BY i.nId OFFSET %(offset)s ROWS FETCH NEXT %(limit)s ROWS ONLY")
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

# Объекты, необходимые функциям: по ним проверяется совместимость источника при добавлении
FEATURE_OBJECTS = {
    "hosts": ("v_akpub_host", "v_akpub_adm_group"),
    "software": ("hst_inventory_products", "hst_inventory_hstprds", "v_akpub_application", "v_akpub_host", "v_akpub_adm_group"),
    "protection": ("v_akpub_hst_prdstate", "v_akpub_host_status", "v_akpub_host"),
    "vulnerabilities": ("vapm_vulnerability_occurence", "vapm_product_vulnerability", "vapm_vulnerability_descr", "vapm_vulnerability_names",
                        "vapm_product_exact_version", "v_vapm_product", "hst_inventory_products", "v_akpub_host"),
    "events": ("v_akpub_ev_event", "v_akpub_host"),
}


def ids_list(ids) -> str:
    """Список целых идентификаторов для IN (…): только int, иначе ValueError — строки в SQL не подставляются."""
    out = [str(int(i)) for i in ids]
    if not out:
        raise ValueError("пустой список идентификаторов")
    return ", ".join(out)
