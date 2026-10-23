# Словарь данных: объекты, которые использует KAV Checker

Типы и назначение столбцов; достоверность: doc / verified. Все даты — `datetime` в UTC.

## `dbo.v_akpub_host` (представление над `Hosts`)

| Столбец | Тип | Назначение | Дост. |
|---|---|---|---|
| nId | bigint | ключ устройства (= Hosts.nId) | verified |
| strName | varchar(64) | GUID устройства (не имя) | verified |
| wstrDisplayName | nvarchar(256) | отображаемое имя | doc |
| wstrDnsName, wstrDnsDomain | nvarchar | DNS-имя и суффикс | doc |
| wstrWinName, wstrWinDomain | nvarchar | NetBIOS-имя и домен/рабочая группа | doc |
| nIp | bigint | IP, первый октет в старшем байте | verified |
| wstrOSName | nvarchar | ОС (у Linux — «Linux») | doc |
| nPlatformType | int | 2 Windows NT+, 6 Linux | verified |
| nVersionMajor, nVersionMinor, nOsBuildNumber | int | версия ОС | doc |
| nGroup | int | группа администрирования → v_akpub_adm_group.nId | verified (FK) |
| tmLastNagentConnected | datetime | последнее подключение Агента | doc/verified |
| tmLastVisible, tmLastInfoUpdate, tmLastUpdate, tmLastFullScan, tmSystemLastStarted, tmCreated | datetime | см. DEVICES.md | doc |
| nStatus | int | биты: 0 видимо, 2 Агент установлен, 3 Агент жив, 4 постоянная защита; 6 — запись кластера | doc/verified |
| nLastRtpState, nLastRtpErrorCode | int | постоянная защита | doc |
| bIsSlaveServer | bit | 1 — подчинённый Сервер или кластер | verified |
| nPkgMgrType | int | 0 нет, 1 RPM, 2 dpkg | doc |
| nComputerType | int | битовая маска типа | doc |
| nProcType | int | 1 x86, 2 AMD64 | doc |
| nVirusCount, nUncured | int | обнаружено / не вылечено | doc |

## `dbo.v_akpub_adm_group` (над `AdmGroups`, без `bInvisible = 1`)

| Столбец | Тип | Назначение |
|---|---|---|
| nId | int | ключ; 0 — «Управляемые устройства», 1 — «Нераспределённые устройства» |
| wstrName | nvarchar | название |
| nParentId | int | родитель (у корня — скрытая группа) |
| nVServer | int | виртуальный Сервер |

## `dbo.hst_inventory_products`

| Столбец | Тип | Назначение |
|---|---|---|
| nId | bigint | ключ записи продукта |
| strID | char(32) | уникальный строковый идентификатор (ссылка из уязвимостей) |
| wstrDisplayName | nvarchar | название программы / пакета |
| wstrDisplayVersion | nvarchar | версия (строка) |
| wstrPublisher | nvarchar | издатель / сопровождающий |
| nPlatformTypeMask | int | 1 Windows, 2 Linux |
| bIsMsi | bit | установщик MSI |
| tmFirstAppear | datetime | впервые обнаружен на Сервере |
| wstrARPRegKey | nvarchar | ключ реестра «Программы и компоненты» |
| wstrComments | nvarchar | комментарий / описание пакета |
| bFakeApp | bit | служебная запись |

## `dbo.hst_inventory_hstprds`

| Столбец | Тип | Назначение |
|---|---|---|
| nId | bigint | ключ установки (= v_akpub_application.nId) |
| nHostId | bigint | устройство |
| nProduct | bigint | → hst_inventory_products.nId (FK) |
| binInstId | varbinary | различает несколько установок одного продукта |
| tmInstallDate | datetime | дата установки |
| bDeleted | bit | 1 — удалена (история) |
| nInstallDir | int | → invprod_installdir |

Уникальный ключ `(nHostId, nProduct, binInstId)`; индекс `(nProduct, bDeleted, nHostId)`.

## `dbo.v_akpub_application`

`nId` (установка), `nHostId`, `nProductId`, `strProductID`, `wstrDisplayName`, `wstrBuild` (версия), `wstrPublisher`, `bMsiInstaller`, `tmInstallDate`; `wstrPackageCode`, `wstrInstallDir`, `wstrQuietUninstallString` — NULL в 15.1. Только `bDeleted = 0`.

## `dbo.v_akpub_hst_prdstate`

| Столбец | Тип | Назначение |
|---|---|---|
| nHost | bigint | устройство |
| wstrProductNameId | nvarchar | код продукта (`1093`, `1103`, `KES`, `kesl`, `WSEE`) |
| wstrProductVersionId | nvarchar | линейка (не версия) |
| wstrProductDisplayName | nvarchar | название |
| wstrProductBuildNumber | nvarchar | версия (сборка) |
| nState | int | состояние продукта (см. PROTECTION.md) |
| tmAvbasesDate | datetime | дата антивирусных баз |
| bAvProduct, bHasRtp | bit | антивирусный продукт; обеспечивает постоянную защиту |

## `dbo.v_akpub_host_status`

`nId` (устройство, 1:1), `nStatus` (0 OK, 1 критический, 2 предупреждение), `nStatusMask` (биты причин, PROTECTION.md).

## Уязвимости

- `vapm_vulnerability_occurence`: `nId`, `nHostId`, `nProductVulnerabilityId`, `nVulnerabilityDescrId` (редко заполнен), `strSoftwareInventoryProductId` (→ hst_inventory_products.strID), `tmDetectTime`, `tmRegistrationTime`, `tmPatchTime` (не заполняется), `tmDisappearanceTime`, `bIgnore`, `bPatchesAvailable`.
- `vapm_product_vulnerability`: `nId`, `nVulnerabilityDescrId`, `nProductExactVersionId`, `bIgnore`.
- `vapm_vulnerability_descr`: `nId`, `wstrPrimaryName` (KLA…), `nKlSeverity` (1/2/4), `wstrDescriptionURL`, `bIgnore`, `nVapmBuild`, `tmRecordCreationTime`.
- `vapm_vulnerability_names`: `nVulnerabilityDescrId`, `nSense` (3 CVE, 5 MSSB, 6 KB), `wstrName`.
- `vapm_product_exact_version`: `nId`, `nProductId` (→ v_vapm_product.nId), `strProductDisplVersion`.
- `v_vapm_product`: `nId`, `wstrName`.

## События: `dbo.v_akpub_ev_event`

`nId`, `tmRiseTime`, `tmRegistrationTime`, `strEventType`, `wstrEventTypeDisplayName`, `nSeverity`, `nHostId`, `strHostname` (GUID), `wstrProductNameId`, `wstrProductVersionId`, `wstrProductBuildNumber`, `wstrDescription`, `wstrPar1`…`wstrPar9`, `nGroup`, `wstrGroupName`, `wstrTaskDisplayName`, `nTaskState`.

## Прочие полезные объекты

| Объект | Назначение |
|---|---|
| `grp_subgroups2` | пары «предок — потомок» для всех групп (устройства группы с подгруппами) |
| `hst_glued_hosts`, `hst_old_dnsnames` | слияния дубликатов, прежние DNS-имена |
| `v_akpub_prod_comp` | компоненты защитных продуктов (`nStatus`: 0 неизвестно, 1 остановлен, 2 приостановлен, 3 запускается, 4 выполняется, 9 сбой, 10 не установлен, 11 нет лицензии) |
| `v_akpub_hwinv` | оборудование (`nType`, `wstrName`, `strMAC`, `nCpuCores`) |
| `v_akpub_tsk_task`, `tsk_host_state` | задачи и их выполнение (`state_code`: 1 ожидает, 2 выполняется, 4 успешно, 8 с предупреждением, 16 ошибка, 32 запланирована, 64 приостановлена) |
| `pol_policy` | политики (активна при `sync_id IS NOT NULL AND type = 0`) |
| `keys`, `keys_installed` | лицензионные ключи (`tmExpirationLimit` UTC) |
| `appctrl_exefile*` | исполняемые файлы (Контроль программ); содержат персональные данные в путях |
