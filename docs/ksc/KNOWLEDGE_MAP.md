# Техническая карта знаний Kaspersky Security Center (база на Microsoft SQL Server)

Универсальные сведения о структуре базы Сервера администрирования KSC: объекты, назначение столбцов, связи и алгоритмы, на которых построен KAV Checker. Проверено на KSC для Windows **15.1.0.22239** (SQL Server 2019); большинство объектов существует и в 14.x. Сведения о конкретных организациях, именах устройств и адресах здесь отсутствуют: все примеры вымышленные.

Уровни достоверности: **doc** — документация Kaspersky (klakdb); **verified** — проверено на реальной базе или по коду процедур KSC; **assumed** — предположение.

## Задача → документ → объекты → запрос KAV Checker

| Задача | Документ | Объекты и поля | Связь | Шаблон (`backend/app/ksc/queries.py`) |
|---|---|---|---|---|
| Компьютеры с программой нужной версии (например PHP) | [SOFTWARE.md](SOFTWARE.md), [ALGORITHMS.md](ALGORITHMS.md) | `hst_inventory_products` (`wstrDisplayName`, `wstrDisplayVersion`, `wstrPublisher`, `nPlatformTypeMask`), `hst_inventory_hstprds` (`nHostId`, `nProduct`, `bDeleted`, `tmInstallDate`), `v_akpub_host` | `i.nProduct = p.nId AND i.bDeleted = 0`; `h.nId = i.nHostId` | `PRODUCTS_*`, `INSTALLS_BY_PRODUCTS`, `HOSTS_BY_IDS` |
| Реестр приложений как в консоли | [SOFTWARE.md](SOFTWARE.md) | `hst_inventory_products`; «Количество» = число установок с `bDeleted = 0` | — | `PRODUCTS_PAGE`, `INSTALL_COUNTS` |
| Всё ПО одного компьютера | [SOFTWARE.md](SOFTWARE.md) | `v_akpub_application` (`wstrBuild` — версия) | `a.nHostId = h.nId` | `SOFTWARE_ON_HOST` |
| Список компьютеров, последняя активность | [DEVICES.md](DEVICES.md) | `v_akpub_host`: `tmLastNagentConnected`, `tmLastVisible`, `tmLastInfoUpdate`, `nStatus`, `bIsSlaveServer`, `nIp` | `g.nId = h.nGroup` | `HOSTS_PAGE`, `HOST_ONE` |
| Группы администрирования, путь группы | [DEVICES.md](DEVICES.md) | `v_akpub_adm_group` (`nId`, `wstrName`, `nParentId`) | рекурсия по `nParentId` в коде | `GROUPS_ALL` |
| Дистрибутив Linux | [DEVICES.md](DEVICES.md) | пакеты `base-files`, `*-release` в реестре ПО | как для ПО | `RELEASE_PACKAGES` |
| Продукты Kaspersky, версии KES и Агента, базы | [PROTECTION.md](PROTECTION.md) | `v_akpub_hst_prdstate` (`wstrProductNameId`, `wstrProductBuildNumber`, `tmAvbasesDate`, `nState`) | `p.nHost = h.nId` | `KASPERSKY_ON_HOST`, `KSC_VERSION` |
| Статус устройства и причины | [PROTECTION.md](PROTECTION.md) | `v_akpub_host_status` (`nStatus`, `nStatusMask`), `v_akpub_host.nLastRtpState` | `s.nId = h.nId` | `HOST_STATUS` |
| Уязвимости и CVE | [VULNERABILITIES.md](VULNERABILITIES.md) | `vapm_vulnerability_occurence` → `vapm_product_vulnerability` → `vapm_vulnerability_descr` → `vapm_vulnerability_names (nSense = 3)` | см. документ | `VULNS_PAGE` |
| События и обнаружения угроз | [EVENTS.md](EVENTS.md) | `v_akpub_ev_event` (`tmRiseTime`, `strEventType`, `nSeverity`, `wstrPar2/5/8`) | `LEFT JOIN v_akpub_host` | (следующий выпуск) |
| Сравнение версий, диапазоны, ветка PHP, IP, активность | [ALGORITHMS.md](ALGORITHMS.md) | — | — | `versions.py`, `grouping.py`, `hosts.py` |
| Описания столбцов | [DICTIONARY.md](DICTIONARY.md) | все объекты, которые использует приложение | — | — |

## Главные связи (verified)

```
v_akpub_adm_group.nId <── v_akpub_host.nGroup                  (Hosts.nGroup → AdmGroups.nId, FK)
v_akpub_host.nId  (= Hosts.nId — ключ устройства; в других таблицах nHostId / nHost)
   ├── hst_inventory_hstprds.nHostId ── nProduct ──> hst_inventory_products.nId   [bDeleted = 0]
   ├── v_akpub_hst_prdstate.nHost         (продукты Kaspersky, базы)
   ├── v_akpub_host_status.nId            (расширенный статус, 1:1)
   ├── vapm_vulnerability_occurence.nHostId ──> vapm_product_vulnerability ──> vapm_vulnerability_descr ──> vapm_vulnerability_names
   │        └── strSoftwareInventoryProductId ──> hst_inventory_products.strID
   └── v_akpub_ev_event.nHostId           (события; LEFT JOIN — есть события удалённых устройств)
Hosts.strName (GUID) <── v_akpub_ev_event.strHostname, tsk_host_state.hostname
```

## Частые ошибки

- Версия программы — `hst_inventory_products.wstrDisplayVersion` (= `v_akpub_application.wstrBuild`). Сравнивать версии строками нельзя.
- Действующие установки — только `bDeleted = 0`.
- `v_akpub_host.nIp`: первый октет в старшем байте (документация ошибается).
- Все даты в UTC; сравнивать с `GETUTCDATE()`.
- `strHostname` и `Hosts.strName` — GUID, не имя компьютера.
- `bIsSlaveServer = 1` — подчинённые серверы и кластеры, не компьютеры.
- Удаление устройства физическое: ссылки из событий на отсутствующие `nId` нормальны.
