# Уязвимости (VAPM)

## Модель данных

```
vapm_vulnerability_occurence — обнаружение уязвимости на устройстве
  nHostId ─> v_akpub_host.nId
  nProductVulnerabilityId ─> vapm_product_vulnerability.nId      [заполнено всегда]
        ├── nVulnerabilityDescrId ─> vapm_vulnerability_descr.nId  [основной путь — так соединяет сама KSC]
        └── nProductExactVersionId ─> vapm_product_exact_version ─> v_vapm_product (уязвимый продукт и версия по справочнику Kaspersky)
  nVulnerabilityDescrId ─> vapm_vulnerability_descr.nId            [заполнено редко — запасной путь через COALESCE]
  strSoftwareInventoryProductId ─> hst_inventory_products.strID    [заполнено не всегда]
  tmDetectTime, tmRegistrationTime, tmPatchTime, tmDisappearanceTime, bIgnore, bPatchesAvailable
vapm_vulnerability_descr — описание: wstrPrimaryName (KLA…), nKlSeverity (1 предупреждение, 2 высокая, 4 критическая), wstrDescriptionURL, bIgnore
vapm_vulnerability_names — имена: nVulnerabilityDescrId, nSense (3 — CVE, 5 — бюллетень MSSB, 6 — номер статьи KB), wstrName
```

## Ответы на типовые вопросы

| Вопрос | Ответ |
|---|---|
| Где CVE | `vapm_vulnerability_names.wstrName` при `nSense = 3`; у одной уязвимости бывает несколько CVE — строка на каждый |
| Где CVSS | нигде: только `nKlSeverity` (шкала Kaspersky) и `nMsrcSeverity` для обновлений Windows |
| Связь с программой на устройстве | `strSoftwareInventoryProductId = hst_inventory_products.strID` (название и версия из реестра ПО); второй путь — справочник `vapm_product_*` |
| Действующая уязвимость | `tmDisappearanceTime IS NULL AND o.bIgnore = 0 AND pv.bIgnore = 0 AND d.bIgnore = 0` (так считают счётчики KSC). Закрытые записи KSC удаляет по сроку — история устранения неполная |
| Linux | KSC не находит уязвимости на устройствах Linux (`nPlatformType = 6`): для пакетов Linux сопоставляйте версии из реестра ПО с внешними источниками |
| Программы вне справочника (например PHP) | в `v_vapm_product` их нет — KSC их не оценивает ни на Windows, ни на Linux; используйте пользовательские критерии KAV Checker |
| Доступные обновления | `bPatchesAvailable`; подробности — `v_akpub_vapm_update_vuln`, `v_akpub_vapm_vulnerability_patch_avail_vuln` |
| Обновления Windows | `wus_upd_revision` (`wstrSecurityBulletinID`, `nMsrcSeverity`), `v_akpub_wus_upd_host_state_vuln` |

## Ограничения

- Соединять описание через `vapm_product_vulnerability.nVulnerabilityDescrId`, как делает представление KSC `v_vapm_vulnerability_occurence`; прямое `o.nVulnerabilityDescrId` теряет большинство записей. `COALESCE(pv.…, o.…)` — подстраховка KAV Checker.
- `nKlSeverity` — битовая шкала (1, 2, 4), значения 3 нет.
- Числовые версии (`nToVersion` и т. п.) упакованы по 16 бит на часть версии.
- Связь из документации `v_akpub_klupd_update_host_state_vuln.nProductId → v_akpub_vapm_product_vuln.nProductId` в 15.1 неверна: соединять с `nId`.
