# Реестр установленного ПО

## Модель данных (verified)

```
hst_inventory_products                      hst_inventory_hstprds                        v_akpub_host
  nId  PK  ───────────────────────────<     nProduct (FK)                  >──────────── nId
  strID char(32) уникальный id записи       nHostId
  wstrDisplayName  название                 tmInstallDate (дата без времени)
  wstrDisplayVersion версия                 binInstId (несколько установок одного продукта)
  wstrPublisher издатель                    bDeleted (1 — удалена, история)
  nPlatformTypeMask 1 = Windows, 2 = Linux
  bIsMsi, tmFirstAppear, wstrARPRegKey, wstrComments, bFakeApp
```

- `hst_inventory_products` — справочник уникальных сочетаний «название + версия + издатель». Каждая версия пакета — отдельная запись.
- `hst_inventory_hstprds` — факты установки. Уникальный ключ `(nHostId, nProduct, binInstId)`. Действующие установки — **`bDeleted = 0`**; это условие стоит в определении `v_akpub_application`.
- Индекс `IX_hst_inventory_hstprds_nProduct_FindHosts (nProduct, bDeleted, nHostId)` — тот же путь использует консоль «Найти устройства с программой»; KAV Checker идёт от продуктов к установкам пачками `nProduct IN (…)`.

## Экран консоли «Реестр приложений» → поля базы

| Поле консоли | Поле базы |
|---|---|
| Название | `wstrDisplayName` |
| Количество (устройств) | число строк `hst_inventory_hstprds` с `nProduct = p.nId AND bDeleted = 0` (хранимого поля нет; сверено с консолью) |
| Версия | `wstrDisplayVersion` |
| Поставщик | `wstrPublisher` (пуст у RPM без поля Vendor) |
| Комментарии | `wstrComments` (у Linux — описание пакета) |
| Первая установка в сети | `tmFirstAppear` (UTC) |
| Устройства | `hst_inventory_hstprds (bDeleted = 0)` → `v_akpub_host` |

Режим «с группировкой по названию» — представление `v_invprod_dispname_grouping` (только `bFakeApp = 0`).

## `v_akpub_application` (публичное представление)

`hst_inventory_hstprds JOIN hst_inventory_products WHERE bDeleted = 0`. Поля: `nId` — установка, `nHostId`, `nProductId`, `strProductID`, `wstrDisplayName`, **`wstrBuild` = версия**, `wstrPublisher`, `bMsiInstaller`, `tmInstallDate`; `wstrPackageCode`, `wstrInstallDir`, `wstrQuietUninstallString` в 15.1 всегда NULL.

## Windows и Linux

| | Windows | Linux |
|---|---|---|
| `nPlatformTypeMask` | 1 | 2 |
| Название | «Программы и компоненты», `wstrARPRegKey` — ключ реестра/GUID MSI | имя пакета (`php7.4-cli`, `libidn2-0`) |
| Версия | `14.2.0.26967` | версия пакета dpkg/RPM: `2.2.27-2+deb11u2`, `2:8.1+92ubuntu1` (эпоха `2:`, ревизия после последнего `-`) |
| Издатель | производитель | сопровождающий пакета |
| Менеджер пакетов | — | `v_akpub_host.nPkgMgrType`: 1 — RPM, 2 — dpkg |

Один продукт в Linux — множество пакетов. Версия пакета не равна версии работающей программы; ближе всего версии пакетов `phpX.Y-*`. Метапакеты (`php-common 2:7x+…`) отражают ветку дистрибутива. Программы Windows без установщика (распакованные из архива) в реестр не попадают; их признаки — только косвенные (например, Windows Cache Extension «for PHP x.y»).

## Актуальность

Отдельной отметки «последняя инвентаризация ПО» на уровне устройства нет; свежесть оценивается по `v_akpub_host.tmLastInfoUpdate` и `tmLastNagentConnected`. Список ПО устройства без связи дольше 30 суток считайте потенциально устаревшим.

## Исполняемые файлы — отдельный реестр

`appctrl_exefile*` (Контроль программ): запускаемые файлы, а не установленные программы. Пути содержат имена пользователей (персональные данные).
