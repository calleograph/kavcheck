# Проверенные запросы

Шаблоны приложения — `backend/app/ksc/queries.py`; поддерживаемые версии KSC — 14.x и 15.1 (проверено на 15.1.0.22239). Ниже — те же запросы в виде, пригодном для ручной проверки в SQL Server Management Studio (ограничение `TOP (1000)` — чтобы не нагружать производственную базу).

## Компьютеры с программой по части названия

```sql
SELECT TOP (1000) h.wstrDisplayName AS ComputerName, h.wstrDnsName, h.wstrDnsDomain,
  CAST((h.nIp / 16777216) % 256 AS varchar(3)) + '.' + CAST((h.nIp / 65536) % 256 AS varchar(3)) + '.' + CAST((h.nIp / 256) % 256 AS varchar(3)) + '.' + CAST(h.nIp % 256 AS varchar(3)) AS IPAddress,
  h.wstrOSName AS OperatingSystem, p.wstrDisplayName AS ApplicationName, p.wstrDisplayVersion AS ApplicationVersion, p.wstrPublisher AS Publisher,
  i.tmInstallDate, h.tmLastNagentConnected AS LastConnectionUtc, g.wstrName AS AdministrationGroup, h.nId AS HostId, p.nId AS ProductId, i.nId AS InstallId
FROM dbo.hst_inventory_products p
JOIN dbo.hst_inventory_hstprds i ON i.nProduct = p.nId AND i.bDeleted = 0
JOIN dbo.v_akpub_host h ON h.nId = i.nHostId
LEFT JOIN dbo.v_akpub_adm_group g ON g.nId = h.nGroup
WHERE p.wstrDisplayName LIKE N'%php%' AND h.bIsSlaveServer = 0
```

Для пакетов самого PHP вместо `%php%`: `p.wstrDisplayName LIKE N'php[0-9]%' OR p.wstrDisplayName IN (N'php', N'php-cli', N'php-common', N'php-fpm', N'php-cgi') OR p.wstrDisplayName LIKE N'libapache2-mod-php%' OR p.wstrDisplayName LIKE N'rh-php%' OR p.wstrDisplayName LIKE N'PHP [0-9]%'`.

## Устройства с датами активности

```sql
SELECT TOP (1000) h.nId, h.wstrDisplayName, h.wstrOSName, g.wstrName AS AdministrationGroup, h.tmLastNagentConnected, h.tmLastVisible, h.tmLastInfoUpdate,
  CASE WHEN h.tmLastNagentConnected IS NULL THEN N'нет подключений Агента'
       WHEN h.tmLastNagentConnected >= DATEADD(day, -1, GETUTCDATE()) THEN N'≤1 сут'
       WHEN h.tmLastNagentConnected >= DATEADD(day, -7, GETUTCDATE()) THEN N'≤7 сут'
       WHEN h.tmLastNagentConnected >= DATEADD(day, -30, GETUTCDATE()) THEN N'≤30 сут' ELSE N'>30 сут' END AS ActivityStatus
FROM dbo.v_akpub_host h LEFT JOIN dbo.v_akpub_adm_group g ON g.nId = h.nGroup
WHERE h.bIsSlaveServer = 0
```

Без связи дольше 30 суток: `WHERE h.bIsSlaveServer = 0 AND (h.tmLastNagentConnected IS NULL OR h.tmLastNagentConnected < DATEADD(day, -30, GETUTCDATE()))`.

## Всё ПО одного устройства

```sql
SELECT TOP (1000) a.wstrDisplayName, a.wstrBuild AS Version, a.wstrPublisher, a.tmInstallDate, a.bMsiInstaller
FROM dbo.v_akpub_application a WHERE a.nHostId = 1   -- 1 — сам Сервер администрирования
```

## Дерево групп

```sql
SELECT TOP (1000) g.nId, g.wstrName, g.nParentId, p.wstrName AS ParentName
FROM dbo.v_akpub_adm_group g LEFT JOIN dbo.v_akpub_adm_group p ON p.nId = g.nParentId
```

## Дистрибутив Linux

```sql
SELECT TOP (1000) h.wstrDisplayName, h.nPkgMgrType, p.wstrDisplayName AS ReleasePackage, p.wstrDisplayVersion AS ReleaseVersion
FROM dbo.hst_inventory_products p JOIN dbo.hst_inventory_hstprds i ON i.nProduct = p.nId AND i.bDeleted = 0 JOIN dbo.v_akpub_host h ON h.nId = i.nHostId
WHERE p.wstrDisplayName IN (N'base-files', N'redhat-release', N'centos-release', N'almalinux-release', N'rocky-release', N'oraclelinux-release', N'astra-version')
```

## Продукты Kaspersky, версии Агента, базы

```sql
SELECT TOP (1000) h.wstrDisplayName, p.wstrProductNameId, p.wstrProductDisplayName, p.wstrProductBuildNumber, p.nState, p.tmAvbasesDate, p.bHasRtp, h.nLastRtpState
FROM dbo.v_akpub_hst_prdstate p JOIN dbo.v_akpub_host h ON h.nId = p.nHost WHERE p.bAvProduct = 1
-- версии Агента: WHERE p.wstrProductNameId = '1103'; версия KSC: WHERE p.wstrProductNameId = '1093'
-- устаревшие базы: WHERE p.bAvProduct = 1 AND p.tmAvbasesDate < DATEADD(day, -7, GETUTCDATE()) AND h.tmLastNagentConnected >= DATEADD(day, -1, GETUTCDATE())
```

## Статусы с проблемами

```sql
SELECT TOP (1000) h.wstrDisplayName, s.nStatus, s.nStatusMask FROM dbo.v_akpub_host_status s JOIN dbo.v_akpub_host h ON h.nId = s.nId WHERE s.nStatus <> 0
```

## Действующие уязвимости

```sql
SELECT TOP (1000) h.wstrDisplayName, o.tmDetectTime, d.wstrPrimaryName AS KlaId, d.nKlSeverity, n.wstrName AS Cve, vp.wstrName AS VulnerableProduct,
  ev.strProductDisplVersion AS VulnerableVersion, p.wstrDisplayName AS InventoryApplication, p.wstrDisplayVersion AS InventoryVersion, o.bPatchesAvailable, d.wstrDescriptionURL
FROM dbo.vapm_vulnerability_occurence o
JOIN dbo.vapm_product_vulnerability pv ON pv.nId = o.nProductVulnerabilityId
JOIN dbo.vapm_vulnerability_descr d ON d.nId = COALESCE(pv.nVulnerabilityDescrId, o.nVulnerabilityDescrId)
JOIN dbo.v_akpub_host h ON h.nId = o.nHostId
LEFT JOIN dbo.vapm_product_exact_version ev ON ev.nId = pv.nProductExactVersionId
LEFT JOIN dbo.v_vapm_product vp ON vp.nId = ev.nProductId
LEFT JOIN dbo.vapm_vulnerability_names n ON n.nVulnerabilityDescrId = d.nId AND n.nSense = 3
LEFT JOIN dbo.hst_inventory_products p ON p.strID = o.strSoftwareInventoryProductId
WHERE o.tmDisappearanceTime IS NULL AND o.bIgnore = 0 AND pv.bIgnore = 0 AND d.bIgnore = 0
```

## Обнаружения угроз за 7 суток

```sql
SELECT TOP (1000) e.nId, e.tmRiseTime, e.strEventType, e.nSeverity, e.nHostId, h.wstrDisplayName, e.wstrProductNameId, e.wstrPar5 AS ThreatName, e.wstrPar2 AS ObjectName, e.wstrPar8 AS DangerType
FROM dbo.v_akpub_ev_event e LEFT JOIN dbo.v_akpub_host h ON h.nId = e.nHostId
WHERE e.tmRiseTime >= DATEADD(day, -7, GETUTCDATE()) AND e.strEventType = 'GNRL_EV_VIRUS_FOUND'
```

## Правила ручной проверки на производственной базе

Только SELECT, всегда `TOP (n)`, без тяжёлых агрегатов по всей таблице событий, отдельная учётная запись `db_datareader`. Персональные данные (пути, имена пользователей) в отчёты и документы не переносить.
