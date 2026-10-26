# Устройства, группы, активность

## Источники

| Нужно | Объект |
|---|---|
| Управляемые устройства | `v_akpub_host` — документированное представление над `Hosts` с `nRecordType IN (0,1,2,3,6,9)` |
| Поля, которых нет в представлении (`tmLastHeartbeat`, `nRecordType` …) | `Hosts` (внутренняя таблица; состав меняется между версиями) |
| Группы | `v_akpub_adm_group` (`AdmGroups` без `bInvisible = 1`) |
| Расширенный статус | `v_akpub_host_status` |

## Идентификаторы

- `Hosts.nId` (bigint) = `v_akpub_host.nId` — ключ устройства; в других таблицах `nHostId`, `nHost`. `nId = 1` — сам Сервер администрирования.
- `Hosts.strName` — строковый GUID (уникальный), **не имя компьютера**; по нему связаны `tsk_host_state.hostname` и `v_akpub_ev_event.strHostname`.

## Имя, адрес, ОС (поля `v_akpub_host`)

| Что | Поле | Примечание |
|---|---|---|
| Отображаемое имя | `wstrDisplayName` | уникально в пределах виртуального сервера; у Linux часто FQDN |
| DNS-имя | `wstrDnsName` + `.` + `wstrDnsDomain` | суффикс бывает пустым |
| NetBIOS | `wstrWinName`, `wstrWinDomain` | |
| IP | `nIp` | `ISNULL(NULLIF(nIpPeer,0), ISNULL(NULLIF(nNsaIp,0), NULLIF(nIpAddress,0)))`; **первый октет в старшем байте** (verified; klakdb ошибочно называет little-endian) |
| ОС | `wstrOSName`, `nPlatformType` (2 — Windows NT+, 6 — Linux), `nVersionMajor`/`nVersionMinor`, `nOsBuildNumber` | у Linux `wstrOSName = 'Linux'`, дистрибутив — по пакету `base-files` (`11.1+deb11u…` — Debian 11, `12.4+deb12u…` — Debian 12, `11ubuntu…` — Ubuntu 20.04, `12ubuntu…` — 22.04, `13ubuntu…` — 24.04, `*astra*` — Astra) или `centos-release`, `almalinux-release` и т. п. |
| Менеджер пакетов | `nPkgMgrType` | 0 нет, 1 RPM, 2 dpkg |
| Тип, разрядность, ВМ | `nComputerType` (битовая маска), `nProcType` (1 x86, 2 AMD64), `nVmType`, `bVmVdi` | doc |

IP в SQL: `CAST((nIp / 16777216) % 256 AS varchar) + '.' + CAST((nIp / 65536) % 256 AS varchar) + '.' + CAST((nIp / 256) % 256 AS varchar) + '.' + CAST(nIp % 256 AS varchar)`.

## Отметки активности (UTC)

| Поле | Смысл | Примечание |
|---|---|---|
| `tmLastNagentConnected` | последнее подключение Агента администрирования | **главный признак активности**; ставится процедурой подключения вместе с `tmLastVisible` и `tmLastInfoUpdate` (verified по коду) |
| `tmLastVisible` | последняя видимость (включая опрос сети) | обычно = или чуть позже |
| `tmLastInfoUpdate` | последнее обновление сведений об устройстве | отдельной отметки инвентаризации ПО нет |
| `tmLastUpdate` | последнее обновление антивирусных баз | |
| `tmLastFullScan` | последняя полная проверка | |
| `tmSystemLastStarted` | последний запуск ОС | |
| `tmCreated` | добавлено в базу | |
| `Hosts.tmLastHeartbeat` | сигнал heartbeat Агента | нет в представлении |
| `Hosts.tmLastStart` | начало текущего сеанса Агента | **не** отметка активности |

Правила KAV Checker: активность — порог по `tmLastNagentConnected` (1/3/7/14/30 суток или произвольно); NULL — Агент не подключался. Это актуальность связи с KSC, не доступность компьютера сейчас. Статус самого KSC — биты `nStatus` (бит 0 — видимо, 2 — Агент установлен, 3 — Агент «жив», 4 — есть постоянная защита; KSC снимает биты по `nVisibilityTimeout`).

## Типы записей и особые устройства

`Hosts.nRecordType`: 0 — обычное устройство; 1 — подчинённый Сервер; 2, 9 — мобильные; 3 — кластер (`bIsSlaveServer = 1`, без подключений Агента); 4 — псевдоустройство установки (нет в представлении); 5 — виртуальный Сервер; 7 — источник событий.

- Подсчёт компьютеров: `v_akpub_host WHERE bIsSlaveServer = 0`.
- Удаление физическое (`DELETE FROM Hosts`): возможны «сироты» в событиях. KSC сам удаляет неактивные устройства через `AdmGroups.nRemovePrd` суток — давно неактивных устройств в базе может уже не быть.
- Дубликаты сливаются процедурами `nsa_glue_*`; журнал — `hst_glued_hosts`; прежние DNS-имена — `hst_old_dnsnames`.

## Группы

`v_akpub_adm_group`: `nId`, `wstrName`, `nParentId`, `nVServer`. `nId = 0` — «Управляемые устройства» (его родитель скрыт), `nId = 1` — «Нераспределённые устройства». Полный путь собирается в коде по `nParentId` (KAV Checker: `hosts.group_path`). Устройства группы со всеми подгруппами — `grp_subgroups2` (пары «предок — потомок»).

## Пользователи устройств

| Объект | Что хранит |
|---|---|
| `hst_user_visited` (`nId`, `nHost`, `nUser`, `bActual`, `binId`, `binSidHash`, `binDomainSamHash`) | пользователи устройства: `bActual = 1` — в текущем списке вошедших, `bActual = 0` — входившие ранее. **Дат нет.** `nUser` может быть `NULL` (учётная запись не сопоставлена, остаётся только хэш SID) |
| `v_akpub_hst_loggedin_users` | представление: `hst_user_visited` где `bActual <> 0 AND nUser IS NOT NULL` |
| `ak_users` (`nId`, `binId`, `wstrSamAccountName`, `wstrUserPrincipalName`, `wstrDisplayName`, `nHostId`, `nDomain`) | учётные записи: доменные (`nDomain` задан) и локальные устройства (`nHostId` задан) |

Запрос KAV Checker (`USERS_VISITED`): `hst_user_visited v LEFT JOIN ak_users u ON u.nId = v.nUser`, порциями по `v.nId`. Что из этого следует и чего в KSC нет («последний пользователь», время входа) — [docs/DEVICES.md](../DEVICES.md). На выборке настоящей базы KSC 15.1 в текущем списке было около 7 % записей, у ~28 % записей `nUser` пуст. Объекты, которых нет в базе (старые версии KSC, ограниченные права), — функция «Пользователи устройств» отключается без ошибок (`FEATURE_OBJECTS["users"]`).

## Несколько Серверов администрирования

На одном SQL Server могут быть несколько баз KSC с одинаковой структурой — по базе на Сервер администрирования. KAV Checker подключает каждую отдельным источником.
