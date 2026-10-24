-- Синтетическая база «как KSC» для проверки SQL-шаблонов KAV Checker. Структура повторяет имена объектов и столбцов KSC 15.1,
-- которые использует приложение; данные вымышленные (имена example.local, адреса из диапазона документации 192.0.2.0/24).
-- Это НЕ копия производственной базы и не полная схема KSC.
IF DB_ID('KAVTEST') IS NULL CREATE DATABASE KAVTEST;
GO
USE KAVTEST;
GO
CREATE TABLE dbo.v_akpub_adm_group (nId int PRIMARY KEY, wstrName nvarchar(256) NOT NULL, nParentId int NULL, nVServer int NOT NULL DEFAULT 0);
CREATE TABLE dbo.v_akpub_host (
  nId bigint PRIMARY KEY, strName varchar(64) NOT NULL, wstrDisplayName nvarchar(256) NOT NULL, wstrDnsName nvarchar(256) NULL, wstrDnsDomain nvarchar(256) NULL,
  wstrWinName nvarchar(256) NULL, wstrWinDomain nvarchar(256) NULL, nIp bigint NULL, wstrOSName nvarchar(256) NULL, nPlatformType int NULL, nVersionMajor int NULL, nVersionMinor int NULL,
  nOsBuildNumber int NULL, nGroup int NOT NULL, tmLastNagentConnected datetime NULL, tmLastVisible datetime NULL, tmLastInfoUpdate datetime NULL, tmLastUpdate datetime NULL,
  tmLastFullScan datetime NULL, tmSystemLastStarted datetime NULL, tmCreated datetime NULL, nStatus int NOT NULL DEFAULT 0, nLastRtpState int NULL, nLastRtpErrorCode int NULL,
  bIsSlaveServer bit NOT NULL DEFAULT 0, nPkgMgrType int NULL, nComputerType int NULL, nProcType int NULL, nVirusCount int NULL, nUncured int NULL);
CREATE TABLE dbo.hst_inventory_products (
  nId bigint PRIMARY KEY, strID char(32) NOT NULL, wstrDisplayName nvarchar(256) NOT NULL, wstrDisplayVersion nvarchar(256) NULL, wstrPublisher nvarchar(256) NULL,
  nPlatformTypeMask int NOT NULL DEFAULT 1, bIsMsi bit NOT NULL DEFAULT 0, tmFirstAppear datetime NULL, wstrARPRegKey nvarchar(256) NULL, wstrComments nvarchar(1024) NULL, bFakeApp bit NOT NULL DEFAULT 0);
CREATE TABLE dbo.hst_inventory_hstprds (
  nId bigint IDENTITY PRIMARY KEY, nHostId bigint NOT NULL, nProduct bigint NOT NULL REFERENCES dbo.hst_inventory_products(nId), binInstId varbinary(16) NOT NULL DEFAULT 0x00,
  tmInstallDate datetime NULL, bDeleted bit NOT NULL DEFAULT 0, nInstallDir int NULL);
CREATE INDEX IX_hst_inventory_hstprds_nProduct_FindHosts ON dbo.hst_inventory_hstprds (nProduct, bDeleted, nHostId);
GO
CREATE VIEW dbo.v_akpub_application AS
  SELECT i.nId, i.nHostId, p.nId AS nProductId, p.strID AS strProductID, p.wstrDisplayName, p.wstrDisplayVersion AS wstrBuild, p.wstrPublisher, p.bIsMsi AS bMsiInstaller,
         i.tmInstallDate, CAST(NULL AS nvarchar(256)) AS wstrPackageCode, CAST(NULL AS nvarchar(256)) AS wstrInstallDir, CAST(NULL AS nvarchar(256)) AS wstrQuietUninstallString
  FROM dbo.hst_inventory_hstprds i JOIN dbo.hst_inventory_products p ON p.nId = i.nProduct WHERE i.bDeleted = 0;
GO
CREATE TABLE dbo.v_akpub_hst_prdstate (nHost bigint NOT NULL, wstrProductNameId nvarchar(64) NOT NULL, wstrProductVersionId nvarchar(64) NULL, wstrProductDisplayName nvarchar(256) NULL,
  wstrProductBuildNumber nvarchar(64) NULL, nState int NULL, tmAvbasesDate datetime NULL, bAvProduct bit NOT NULL DEFAULT 0, bHasRtp bit NOT NULL DEFAULT 0);
CREATE TABLE dbo.v_akpub_host_status (nId bigint PRIMARY KEY, nStatus int NOT NULL, nStatusMask int NOT NULL);
CREATE TABLE dbo.vapm_vulnerability_descr (nId bigint PRIMARY KEY, wstrPrimaryName nvarchar(64), nKlSeverity int, wstrDescriptionURL nvarchar(512), bIgnore bit NOT NULL DEFAULT 0);
CREATE TABLE dbo.vapm_vulnerability_names (nVulnerabilityDescrId bigint, nSense int, wstrName nvarchar(256));
CREATE TABLE dbo.v_vapm_product (nId bigint PRIMARY KEY, wstrName nvarchar(256));
CREATE TABLE dbo.vapm_product_exact_version (nId bigint PRIMARY KEY, nProductId bigint, strProductDisplVersion nvarchar(64));
CREATE TABLE dbo.vapm_product_vulnerability (nId bigint PRIMARY KEY, nVulnerabilityDescrId bigint NULL, nProductExactVersionId bigint NULL, bIgnore bit NOT NULL DEFAULT 0);
CREATE TABLE dbo.vapm_vulnerability_occurence (nId bigint PRIMARY KEY, nHostId bigint, nProductVulnerabilityId bigint, nVulnerabilityDescrId bigint NULL, strSoftwareInventoryProductId char(32) NULL,
  tmDetectTime datetime, tmDisappearanceTime datetime NULL, bIgnore bit NOT NULL DEFAULT 0, bPatchesAvailable bit NOT NULL DEFAULT 0);
CREATE TABLE dbo.v_akpub_ev_event (nId bigint PRIMARY KEY, nHostId bigint, tmRiseTime datetime, tmRegistrationTime datetime NULL, strEventType varchar(64), wstrEventTypeDisplayName nvarchar(256) NULL,
  nSeverity int, wstrProductNameId nvarchar(64) NULL, wstrProductVersionId nvarchar(64) NULL, wstrDescription nvarchar(1000) NULL, wstrPar1 nvarchar(256) NULL, wstrPar2 nvarchar(256),
  wstrPar3 nvarchar(256) NULL, wstrPar4 nvarchar(256) NULL, wstrPar5 nvarchar(256), wstrPar7 nvarchar(256) NULL, wstrPar8 nvarchar(64), wstrTaskDisplayName nvarchar(256) NULL);
CREATE INDEX IX_ev_rise ON dbo.v_akpub_ev_event (tmRiseTime);
-- индексы как в KSC 15.1 (UK_hst_inventory_products__strID, IX_vapm_vulnerability_occurence__complex*)
CREATE UNIQUE INDEX UK_hst_inventory_products__strID ON dbo.hst_inventory_products (strID);
CREATE INDEX IX_vapm_occ_host ON dbo.vapm_vulnerability_occurence (nHostId, nProductVulnerabilityId, tmDisappearanceTime, bIgnore);
CREATE INDEX IX_vapm_occ_pv ON dbo.vapm_vulnerability_occurence (nProductVulnerabilityId, tmDisappearanceTime, bIgnore) INCLUDE (nHostId, bPatchesAvailable, strSoftwareInventoryProductId);
CREATE INDEX IX_ev_host ON dbo.v_akpub_ev_event (nHostId, tmRiseTime);
GO
-- Группы: 0 — корень управляемых, 1 — нераспределённые, 10 — Серверы, 11 — Web (внутри Серверов), 12 — Рабочие станции
INSERT INTO dbo.v_akpub_adm_group VALUES (0, N'Управляемые устройства', 2, 0), (1, N'Нераспределенные устройства', NULL, 0), (10, N'Серверы', 0, 0), (11, N'Web', 10, 0), (12, N'Рабочие станции', 0, 0);
-- Устройства: nIp — первый октет в старшем байте (192.0.2.x = 3221225984 + x)
INSERT INTO dbo.v_akpub_host (nId, strName, wstrDisplayName, wstrDnsName, wstrDnsDomain, nIp, wstrOSName, nPlatformType, nVersionMajor, nVersionMinor, nOsBuildNumber, nGroup, tmLastNagentConnected, tmLastVisible, tmLastInfoUpdate, tmLastUpdate, tmLastFullScan, tmCreated, nStatus, nLastRtpState, bIsSlaveServer, nPkgMgrType, nComputerType, nProcType) VALUES
 (1,  'guid-0001', N'ksc-server', N'ksc-server', N'example.local', 3221225984+10, N'Microsoft Windows Server 2022', 2, 10, 0, 20348, 0, DATEADD(hour,-1,GETUTCDATE()), DATEADD(hour,-1,GETUTCDATE()), DATEADD(hour,-1,GETUTCDATE()), DATEADD(hour,-2,GETUTCDATE()), DATEADD(day,-3,GETUTCDATE()), DATEADD(day,-400,GETUTCDATE()), 29, 4, 0, 0, 2, 2),
 (2,  'guid-0002', N'web-01.example.local', N'web-01', N'example.local', 3221225984+21, N'Linux', 6, 5, 10, 0, 11, DATEADD(hour,-3,GETUTCDATE()), DATEADD(hour,-3,GETUTCDATE()), DATEADD(hour,-3,GETUTCDATE()), DATEADD(hour,-5,GETUTCDATE()), NULL, DATEADD(day,-300,GETUTCDATE()), 29, 4, 0, 2, 2, 2),
 (3,  'guid-0003', N'web-02.example.local', N'web-02', N'example.local', 3221225984+22, N'Linux', 6, 5, 10, 0, 11, DATEADD(day,-2,GETUTCDATE()), DATEADD(day,-2,GETUTCDATE()), DATEADD(day,-2,GETUTCDATE()), DATEADD(day,-2,GETUTCDATE()), NULL, DATEADD(day,-300,GETUTCDATE()), 29, 8, 0, 2, 2, 2),
 (4,  'guid-0004', N'app-01.example.local', N'app-01', N'example.local', 3221225984+23, N'Linux', 6, 5, 15, 0, 10, DATEADD(day,-10,GETUTCDATE()), DATEADD(day,-10,GETUTCDATE()), DATEADD(day,-10,GETUTCDATE()), NULL, NULL, DATEADD(day,-200,GETUTCDATE()), 5, 0, 0, 1, 2, 2),
 (5,  'guid-0005', N'old-srv.example.local', N'old-srv', N'example.local', 3221225984+24, N'Linux', 6, 4, 19, 0, 10, DATEADD(day,-45,GETUTCDATE()), DATEADD(day,-45,GETUTCDATE()), DATEADD(day,-45,GETUTCDATE()), NULL, NULL, DATEADD(day,-500,GETUTCDATE()), 4, 0, 0, 2, 2, 2),
 (6,  'guid-0006', N'ws-001', N'ws-001', N'example.local', 3221225984+101, N'Microsoft Windows 11', 2, 10, 0, 22631, 12, DATEADD(minute,-20,GETUTCDATE()), DATEADD(minute,-20,GETUTCDATE()), DATEADD(minute,-20,GETUTCDATE()), DATEADD(hour,-1,GETUTCDATE()), DATEADD(day,-1,GETUTCDATE()), DATEADD(day,-100,GETUTCDATE()), 29, 4, 0, 0, 1, 2),
 (7,  'guid-0007', N'ws-002', N'ws-002', N'example.local', 3221225984+102, N'Microsoft Windows 10', 2, 10, 0, 19045, 12, DATEADD(day,-20,GETUTCDATE()), DATEADD(day,-20,GETUTCDATE()), DATEADD(day,-20,GETUTCDATE()), DATEADD(day,-21,GETUTCDATE()), DATEADD(day,-40,GETUTCDATE()), DATEADD(day,-100,GETUTCDATE()), 4, 1, 0, 0, 1, 2),
 (8,  'guid-0008', N'ws-003', N'ws-003', N'example.local', 3221225984+103, N'Microsoft Windows 11', 2, 10, 0, 22631, 12, NULL, NULL, DATEADD(day,-90,GETUTCDATE()), NULL, NULL, DATEADD(day,-90,GETUTCDATE()), 0, 0, 0, 0, 1, 2),
 (9,  'guid-0009', N'SQL-CL-01', N'SQL-CL-01', N'example.local', 3221225984+30, N'Microsoft Windows Server 2019', 2, 10, 0, 17763, 10, NULL, NULL, NULL, NULL, NULL, DATEADD(day,-300,GETUTCDATE()), 64, 0, 1, 0, 2, 2);
-- Продукты: PHP-пакеты, ОС-пакеты, Windows-приложения, «ложные» PHP (PhpStorm, Composer)
INSERT INTO dbo.hst_inventory_products (nId, strID, wstrDisplayName, wstrDisplayVersion, wstrPublisher, nPlatformTypeMask, bIsMsi, tmFirstAppear) VALUES
 (101, REPLICATE('a',31)+'1', N'php7.4-cli', N'7.4.33-1+0~20221121.75+debian11~1.gbp5ad3b6', N'Debian PHP Maintainers <team@example.org>', 2, 0, DATEADD(day,-200,GETUTCDATE())),
 (102, REPLICATE('a',31)+'2', N'php7.4-fpm', N'7.4.33-1+0~20221121.75+debian11~1.gbp5ad3b6', N'Debian PHP Maintainers <team@example.org>', 2, 0, DATEADD(day,-200,GETUTCDATE())),
 (103, REPLICATE('a',31)+'3', N'php7.4-xdebug', N'3.1.6+2.9.8+2.8.1+2.5.5-1', N'Debian PHP Maintainers <team@example.org>', 2, 0, DATEADD(day,-200,GETUTCDATE())),
 (104, REPLICATE('a',31)+'4', N'php-common', N'2:76+0~20221121.47+debian11~1.gbp2bf9c2', N'Debian PHP Maintainers <team@example.org>', 2, 0, DATEADD(day,-200,GETUTCDATE())),
 (105, REPLICATE('a',31)+'5', N'php8.1-cli', N'8.1.27-1+0~20231221.46+debian11~1.gbp8e7a4e', N'Debian PHP Maintainers <team@example.org>', 2, 0, DATEADD(day,-100,GETUTCDATE())),
 (106, REPLICATE('a',31)+'6', N'php8.1-redis', N'6.0.2-1', N'Debian PHP Maintainers <team@example.org>', 2, 0, DATEADD(day,-100,GETUTCDATE())),
 (107, REPLICATE('a',31)+'7', N'php', N'2:8.3+93ubuntu2', N'Ubuntu Developers <team@example.org>', 2, 0, DATEADD(day,-50,GETUTCDATE())),
 (108, REPLICATE('a',31)+'8', N'php8.3-fpm', N'8.3.6-0ubuntu0.24.04.2', N'Ubuntu Developers <team@example.org>', 2, 0, DATEADD(day,-50,GETUTCDATE())),
 (109, REPLICATE('a',31)+'9', N'php5.6', N'5.6.40-1', N'', 2, 0, DATEADD(day,-500,GETUTCDATE())),
 (110, REPLICATE('b',31)+'0', N'php-cli', N'8.0.30-1.el8', N'', 2, 0, DATEADD(day,-150,GETUTCDATE())),
 (111, REPLICATE('b',31)+'1', N'php-pecl-redis', N'5.3.7-1.el8', N'', 2, 0, DATEADD(day,-150,GETUTCDATE())),
 (120, REPLICATE('b',31)+'2', N'base-files', N'11.1+deb11u9', N'Santiago Vila <sv@example.org>', 2, 0, DATEADD(day,-300,GETUTCDATE())),
 (121, REPLICATE('b',31)+'3', N'base-files', N'13ubuntu10.1', N'Ubuntu Developers <team@example.org>', 2, 0, DATEADD(day,-50,GETUTCDATE())),
 (122, REPLICATE('b',31)+'4', N'almalinux-release', N'8.9-1.el8', N'', 2, 0, DATEADD(day,-150,GETUTCDATE())),
 (130, REPLICATE('b',31)+'5', N'PhpStorm 2024.1', N'241.14494.237', N'JetBrains s.r.o.', 1, 0, DATEADD(day,-60,GETUTCDATE())),
 (131, REPLICATE('b',31)+'6', N'Composer', N'2.7.1', N'', 1, 0, DATEADD(day,-60,GETUTCDATE())),
 (132, REPLICATE('b',31)+'7', N'Google Chrome', N'124.0.6367.60', N'Google LLC', 1, 1, DATEADD(day,-60,GETUTCDATE())),
 (133, REPLICATE('b',31)+'8', N'Google Chrome', N'120.0.6099.130', N'Google LLC', 1, 1, DATEADD(day,-200,GETUTCDATE())),
 (134, REPLICATE('b',31)+'9', N'7-Zip 23.01 (x64)', N'23.01', N'Igor Pavlov', 1, 0, DATEADD(day,-200,GETUTCDATE())),
 (135, REPLICATE('c',31)+'0', N'Kaspersky Endpoint Security для Windows', N'12.6.0.438', N'AO Kaspersky Lab', 1, 1, DATEADD(day,-200,GETUTCDATE())),
 (140, REPLICATE('c',31)+'1', N'nginx', N'1.22.1-9', N'Debian Nginx Maintainers <team@example.org>', 2, 0, DATEADD(day,-200,GETUTCDATE()));
INSERT INTO dbo.hst_inventory_hstprds (nHostId, nProduct, tmInstallDate, bDeleted) VALUES
 (2,101,DATEADD(day,-180,GETUTCDATE()),0),(2,102,DATEADD(day,-180,GETUTCDATE()),0),(2,103,DATEADD(day,-180,GETUTCDATE()),0),(2,104,DATEADD(day,-180,GETUTCDATE()),0),(2,120,DATEADD(day,-300,GETUTCDATE()),0),(2,140,DATEADD(day,-180,GETUTCDATE()),0),
 (3,105,DATEADD(day,-90,GETUTCDATE()),0),(3,106,DATEADD(day,-90,GETUTCDATE()),0),(3,104,DATEADD(day,-90,GETUTCDATE()),0),(3,120,DATEADD(day,-300,GETUTCDATE()),0),(3,140,DATEADD(day,-90,GETUTCDATE()),0),(3,101,DATEADD(day,-400,GETUTCDATE()),1),
 (4,110,DATEADD(day,-140,GETUTCDATE()),0),(4,111,DATEADD(day,-140,GETUTCDATE()),0),(4,122,DATEADD(day,-150,GETUTCDATE()),0),
 (5,109,DATEADD(day,-490,GETUTCDATE()),0),(5,104,DATEADD(day,-490,GETUTCDATE()),0),
 (6,130,DATEADD(day,-30,GETUTCDATE()),0),(6,131,DATEADD(day,-30,GETUTCDATE()),0),(6,132,DATEADD(day,-10,GETUTCDATE()),0),(6,134,DATEADD(day,-100,GETUTCDATE()),0),(6,135,DATEADD(day,-100,GETUTCDATE()),0),
 (7,133,DATEADD(day,-150,GETUTCDATE()),0),(7,134,DATEADD(day,-150,GETUTCDATE()),0),(7,135,DATEADD(day,-150,GETUTCDATE()),0),
 (8,133,DATEADD(day,-90,GETUTCDATE()),0),
 (1,135,DATEADD(day,-200,GETUTCDATE()),0),(1,134,DATEADD(day,-200,GETUTCDATE()),0),
 (9,107,DATEADD(day,-40,GETUTCDATE()),0),(9,108,DATEADD(day,-40,GETUTCDATE()),0),
 (6,107,DATEADD(day,-40,GETUTCDATE()),0),(6,108,DATEADD(day,-40,GETUTCDATE()),0),(6,121,DATEADD(day,-40,GETUTCDATE()),0);
INSERT INTO dbo.v_akpub_hst_prdstate VALUES
 (1,'1093','1.0.0.0',N'Kaspersky Security Center Administration Server','15.1.0.22239',3,NULL,0,0),(1,'1103','1.0.0.0',N'Kaspersky Security Center Network Agent','15.1.0.22239',3,NULL,0,0),
 (2,'1103','1.0.0.0',N'Kaspersky Security Center Network Agent','15.1.0.22239',3,NULL,0,0),(2,'kesl','12.0.0.0',N'Kaspersky Endpoint Security for Linux','12.3.0.1162',3,DATEADD(hour,-5,GETUTCDATE()),1,1),
 (3,'1103','1.0.0.0',N'Kaspersky Security Center Network Agent','14.2.0.26967',3,NULL,0,0),(3,'kesl','12.0.0.0',N'Kaspersky Endpoint Security for Linux','12.3.0.1162',3,DATEADD(day,-2,GETUTCDATE()),1,1),
 (6,'1103','1.0.0.0',N'Kaspersky Security Center Network Agent','15.1.0.22239',3,NULL,0,0),(6,'KES','11.0.0.0',N'Kaspersky Endpoint Security for Windows','12.6.0.438',3,DATEADD(hour,-1,GETUTCDATE()),1,1),
 (7,'1103','1.0.0.0',N'Kaspersky Security Center Network Agent','14.0.0.10902',0,NULL,0,0),(7,'KES','11.0.0.0',N'Kaspersky Endpoint Security for Windows','12.4.0.467',0,DATEADD(day,-21,GETUTCDATE()),1,1);
INSERT INTO dbo.v_akpub_host_status VALUES (1,0,0),(2,0,0),(3,0,0),(4,2,256),(5,1,256+128),(6,0,0),(7,1,2+128+16384),(8,1,32);
INSERT INTO dbo.vapm_vulnerability_descr VALUES (5001,N'KLA10001',4,N'https://threats.kaspersky.com/en/vulnerability/KLA10001',0),(5002,N'KLA10002',2,N'https://threats.kaspersky.com/en/vulnerability/KLA10002',0);
INSERT INTO dbo.vapm_vulnerability_names VALUES (5001,3,N'CVE-2024-0001'),(5001,3,N'CVE-2024-0002'),(5002,3,N'CVE-2023-9999'),(5001,4,N'KLA10001');
INSERT INTO dbo.v_vapm_product VALUES (7001,N'Google Chrome');
INSERT INTO dbo.vapm_product_exact_version VALUES (7101,7001,N'120.0.6099.130');
INSERT INTO dbo.vapm_product_vulnerability VALUES (8001,5001,7101,0),(8002,5002,7101,0);
INSERT INTO dbo.vapm_vulnerability_occurence VALUES (9001,7,8001,NULL,REPLICATE('b',31)+'8',DATEADD(day,-30,GETUTCDATE()),NULL,0,1),(9002,8,8001,NULL,NULL,DATEADD(day,-20,GETUTCDATE()),NULL,0,1),(9003,7,8002,5002,REPLICATE('b',31)+'8',DATEADD(day,-30,GETUTCDATE()),DATEADD(day,-5,GETUTCDATE()),0,0);
-- 0.2.0: продукты для каталога и проверки версий (нестандартная нумерация Java и Python для Windows, компоненты, пакеты Linux)
INSERT INTO dbo.hst_inventory_products (nId, strID, wstrDisplayName, wstrDisplayVersion, wstrPublisher, nPlatformTypeMask, bIsMsi, tmFirstAppear) VALUES
 (150, REPLICATE('d',31)+'0', N'Mozilla Firefox (x64 ru)', N'125.0.3', N'Mozilla', 1, 0, DATEADD(day,-20,GETUTCDATE())),
 (151, REPLICATE('d',31)+'1', N'Mozilla Firefox ESR (x64 ru)', N'115.10.0', N'Mozilla', 1, 0, DATEADD(day,-120,GETUTCDATE())),
 (152, REPLICATE('d',31)+'2', N'Java 8 Update 401 (64-bit)', N'8.0.4010.7', N'Oracle Corporation', 1, 1, DATEADD(day,-40,GETUTCDATE())),
 (153, REPLICATE('d',31)+'3', N'Java 8 Update 391 (64-bit)', N'8.0.3910.13', N'Oracle Corporation', 1, 1, DATEADD(day,-200,GETUTCDATE())),
 (154, REPLICATE('d',31)+'4', N'Python 3.12.3 Core Interpreter (64-bit)', N'3.12.3150.0', N'Python Software Foundation', 1, 1, DATEADD(day,-30,GETUTCDATE())),
 (155, REPLICATE('d',31)+'5', N'Python 3.12.3 Standard Library (64-bit)', N'3.12.3150.0', N'Python Software Foundation', 1, 1, DATEADD(day,-30,GETUTCDATE())),
 (156, REPLICATE('d',31)+'6', N'libssl1.1', N'1.1.1w-0+deb11u1', N'Debian OpenSSL Team <team@example.org>', 2, 0, DATEADD(day,-300,GETUTCDATE())),
 (157, REPLICATE('d',31)+'7', N'openssl', N'3.0.13-0ubuntu3.1', N'Ubuntu Developers <team@example.org>', 2, 0, DATEADD(day,-50,GETUTCDATE())),
 (158, REPLICATE('d',31)+'8', N'openssh-server', N'1:8.4p1-5+deb11u3', N'Debian OpenSSH Maintainers <team@example.org>', 2, 0, DATEADD(day,-300,GETUTCDATE())),
 (159, REPLICATE('d',31)+'9', N'Microsoft Edge', N'124.0.2478.80', N'Microsoft Corporation', 1, 0, DATEADD(day,-15,GETUTCDATE())),
 (160, REPLICATE('e',31)+'0', N'Notepad++ (64-bit x64)', N'8.6.4', N'Notepad++ Team', 1, 0, DATEADD(day,-60,GETUTCDATE())),
 (161, REPLICATE('e',31)+'1', N'Mozilla Maintenance Service', N'125.0.3', N'Mozilla', 1, 0, DATEADD(day,-20,GETUTCDATE()));
INSERT INTO dbo.hst_inventory_hstprds (nHostId, nProduct, tmInstallDate, bDeleted) VALUES
 (6,150,DATEADD(day,-20,GETUTCDATE()),0),(6,161,DATEADD(day,-20,GETUTCDATE()),0),(6,159,DATEADD(day,-15,GETUTCDATE()),0),(6,154,DATEADD(day,-30,GETUTCDATE()),0),
 (6,155,DATEADD(day,-30,GETUTCDATE()),0),(6,160,DATEADD(day,-60,GETUTCDATE()),0),(6,152,DATEADD(day,-40,GETUTCDATE()),0),
 (7,151,DATEADD(day,-120,GETUTCDATE()),0),(7,153,DATEADD(day,-200,GETUTCDATE()),0),
 (1,159,DATEADD(day,-15,GETUTCDATE()),0),(1,153,DATEADD(day,-200,GETUTCDATE()),0),
 (2,156,DATEADD(day,-300,GETUTCDATE()),0),(2,158,DATEADD(day,-300,GETUTCDATE()),0),(3,156,DATEADD(day,-300,GETUTCDATE()),0),(6,157,DATEADD(day,-40,GETUTCDATE()),0);
-- уязвимости 0.2.0: Firefox на ws-001 (высокая), Java 8u391 на ksc-server (критическая и предупреждение), исправление доступно не везде
INSERT INTO dbo.vapm_vulnerability_descr VALUES (5003,N'KLA10003',2,N'https://threats.kaspersky.com/en/vulnerability/KLA10003',0),(5004,N'KLA10004',4,N'https://threats.kaspersky.com/en/vulnerability/KLA10004',0),
 (5005,N'KLA10005',1,N'https://threats.kaspersky.com/en/vulnerability/KLA10005',0);
INSERT INTO dbo.vapm_vulnerability_names VALUES (5003,3,N'CVE-2024-1111'),(5004,3,N'CVE-2024-2222'),(5004,6,N'5034441'),(5005,5,N'MS24-001');
INSERT INTO dbo.v_vapm_product VALUES (7002,N'Mozilla Firefox'),(7003,N'Oracle Java');
INSERT INTO dbo.vapm_product_exact_version VALUES (7102,7002,N'125.0.3'),(7103,7003,N'8.0.391');
INSERT INTO dbo.vapm_product_vulnerability VALUES (8003,5003,7102,0),(8004,5004,7103,0),(8005,5005,7103,0);
INSERT INTO dbo.vapm_vulnerability_occurence VALUES (9004,6,8003,NULL,REPLICATE('d',31)+'0',DATEADD(day,-3,GETUTCDATE()),NULL,0,1),
 (9005,1,8004,NULL,REPLICATE('d',31)+'3',DATEADD(day,-60,GETUTCDATE()),NULL,0,0),(9006,1,8005,NULL,REPLICATE('d',31)+'3',DATEADD(day,-60,GETUTCDATE()),NULL,0,1);
INSERT INTO dbo.v_akpub_ev_event (nId, nHostId, tmRiseTime, tmRegistrationTime, strEventType, wstrEventTypeDisplayName, nSeverity, wstrProductNameId, wstrDescription, wstrPar1, wstrPar2, wstrPar3, wstrPar4, wstrPar5, wstrPar7, wstrPar8) VALUES
 (1,7,DATEADD(day,-1,GETUTCDATE()),DATEADD(day,-1,GETUTCDATE()),'GNRL_EV_VIRUS_FOUND',N'Обнаружен вредоносный объект',4,N'KES',N'Обнаружен объект',NULL,N'C:\Users\user\Downloads\sample.bin',NULL,NULL,N'EICAR-Test-File',N'EXAMPLE\user',N'60'),
 (2,6,DATEADD(hour,-5,GETUTCDATE()),DATEADD(hour,-5,GETUTCDATE()),'GNRL_EV_VIRUS_FOUND',N'Обнаружен вредоносный объект',4,N'KES',N'Обнаружен объект',NULL,N'C:\Users\user\AppData\Local\Temp\tool.exe',NULL,NULL,N'HEUR:Trojan.Win32.Generic',N'EXAMPLE\user',N'61'),
 (3,6,DATEADD(hour,-5,GETUTCDATE()),DATEADD(hour,-5,GETUTCDATE()),'GNRL_EV_OBJECT_DELETED',N'Объект удалён',2,N'KES',N'Объект удалён',NULL,N'C:\Users\user\AppData\Local\Temp\tool.exe',NULL,NULL,NULL,NULL,NULL),
 (4,2,DATEADD(hour,-30,GETUTCDATE()),DATEADD(hour,-30,GETUTCDATE()),'GNRL_EV_ATTACK_DETECTED',N'Обнаружена сетевая атака',4,N'kesl',N'Сетевая атака',N'Scan.Generic.PortScan.TCP',N'TCP',N'3325256824',N'22',NULL,NULL,NULL),
 (5,7,DATEADD(day,-2,GETUTCDATE()),DATEADD(day,-2,GETUTCDATE()),'GNRL_EV_OBJECT_NOTCURED',N'Объект не вылечен',3,N'KES',N'Объект не вылечен',NULL,N'C:\Users\user\Downloads\sample.bin',NULL,NULL,N'EICAR-Test-File',NULL,NULL),
 (6,1,DATEADD(hour,-2,GETUTCDATE()),DATEADD(hour,-2,GETUTCDATE()),'KLEVP_GroupTaskSyncState',N'Синхронизация задачи',1,N'1103',N'Служебное',NULL,NULL,NULL,NULL,NULL,NULL,NULL),
 (7,6,DATEADD(day,-40,GETUTCDATE()),DATEADD(day,-40,GETUTCDATE()),'GNRL_EV_VIRUS_FOUND',N'Обнаружен вредоносный объект',4,N'KES',N'Обнаружен объект',NULL,N'D:\old\setup.exe',NULL,NULL,N'not-a-virus:RiskTool.Win32.Example',NULL,N'65');
GO
-- Проверка условий версий: «Contoso Agent» с заранее известными версиями и компьютерами (tests/test_ksc_live.py::test_version_conditions_end_to_end).
-- Активные за 30 суток: 1, 2, 3, 4, 6, 7; без связи: 5 (45 суток), 8 (никогда); 9 — кластер (подчинённая запись). Версии 8.9 и 8.10 — проверка числового сравнения.
INSERT INTO dbo.hst_inventory_products (nId, strID, wstrDisplayName, wstrDisplayVersion, wstrPublisher, nPlatformTypeMask, bIsMsi, tmFirstAppear) VALUES
 (9101, REPLICATE('9',28)+'9101', N'Contoso Agent', N'8.4.14', N'Contoso Ltd', 1, 0, DATEADD(day,-300,GETUTCDATE())),
 (9102, REPLICATE('9',28)+'9102', N'Contoso Agent', N'8.4.15', N'Contoso Ltd', 1, 0, DATEADD(day,-200,GETUTCDATE())),
 (9103, REPLICATE('9',28)+'9103', N'Contoso Agent', N'8.4.16', N'Contoso Ltd', 1, 0, DATEADD(day,-100,GETUTCDATE())),
 (9104, REPLICATE('9',28)+'9104', N'Contoso Agent', N'8.9', N'Contoso Ltd', 1, 0, DATEADD(day,-90,GETUTCDATE())),
 (9105, REPLICATE('9',28)+'9105', N'Contoso Agent', N'8.10', N'Contoso Ltd', 1, 0, DATEADD(day,-30,GETUTCDATE()));
INSERT INTO dbo.hst_inventory_hstprds (nHostId, nProduct, tmInstallDate, bDeleted) VALUES
 (1,9101,DATEADD(day,-100,GETUTCDATE()),0),(5,9101,DATEADD(day,-100,GETUTCDATE()),0),(9,9101,DATEADD(day,-100,GETUTCDATE()),0),
 (2,9102,DATEADD(day,-50,GETUTCDATE()),0),(3,9102,DATEADD(day,-50,GETUTCDATE()),0),
 (4,9103,DATEADD(day,-20,GETUTCDATE()),0),(6,9103,DATEADD(day,-20,GETUTCDATE()),0),
 (7,9104,DATEADD(day,-10,GETUTCDATE()),0),
 (6,9105,DATEADD(day,-5,GETUTCDATE()),0),(8,9105,DATEADD(day,-5,GETUTCDATE()),0),(1,9105,DATEADD(day,-5,GETUTCDATE()),1);

-- Учётная запись только для чтения (так же, как рекомендуется для реальной базы KSC)
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'kavcheck_ro') CREATE LOGIN kavcheck_ro WITH PASSWORD = 'KavCheck-Test-Pass-1', CHECK_POLICY = OFF; -- private-data: ignore (тестовый пароль синтетической базы)
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'kavcheck_ro') CREATE USER kavcheck_ro FOR LOGIN kavcheck_ro;
ALTER ROLE db_datareader ADD MEMBER kavcheck_ro;
GO
