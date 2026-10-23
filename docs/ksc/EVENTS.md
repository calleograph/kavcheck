# События безопасности

## Где хранятся

- `ev_event` — все события; обычно самая крупная таблица базы.
- `v_akpub_ev_event` — публичное представление над ней (verified):

| Поле | Смысл |
|---|---|
| `nId` | идентификатор события |
| `tmRiseTime` | время возникновения на устройстве (UTC; задаёт устройство — бывают значения из будущего) |
| `tmRegistrationTime` | время регистрации на Сервере (UTC) |
| `strEventType`, `wstrEventTypeDisplayName` | тип: `GNRL_EV_VIRUS_FOUND`, `GNRL_EV_ATTACK_DETECTED`, `KLEVP_GroupTaskSyncState` … |
| `nSeverity` | 1 информационное, 2 предупреждение, 3 ошибка, 4 критическое |
| `nHostId` | устройство → `v_akpub_host.nId` (**LEFT JOIN**: есть события удалённых устройств); имя на момент события — `ev_event.host_display_name` |
| `strHostname` | GUID устройства, не имя |
| `wstrProductNameId`, `wstrProductVersionId`, `wstrProductBuildNumber` | продукт-источник (`KES`, `kesl`, `1093`, `1103`) |
| `wstrDescription` | текст (содержит пути и имена пользователей — персональные данные) |
| `wstrPar1` … `wstrPar9` | параметры по типу события |
| `nGroup`, `wstrGroupName`, `wstrTaskDisplayName`, `nTaskState` | группа и задача |

## Параметры обнаружений (doc)

| Событие | Параметры |
|---|---|
| `GNRL_EV_VIRUS_FOUND` | `wstrPar2` объект, `wstrPar5` имя угрозы, `wstrPar7` пользователь, `wstrPar8` тип опасности (60 вирус, 61 троян, 62 вредоносная программа, 63 бэкдор, 64 червь, 65 riskware, 0 неизвестно); по коду также `par1` — SHA256 |
| `GNRL_EV_OBJECT_CURED/_DELETED/_QUARANTINED/_NOTCURED`, `GNRL_EV_PASSWD_ARCHIVE_FOUND` | `wstrPar2` объект |
| `GNRL_EV_SUSPICIOUS_OBJECT_FOUND` | `wstrPar2` объект, `wstrPar5` угроза |
| `GNRL_EV_ATTACK_DETECTED` | `wstrPar1` атака, `wstrPar2` протокол, `wstrPar3` IP атакующего (число), `wstrPar4` порт |

История обнаружений с результатом — `v_akpub_virus_activity` (`wstrVirusName`, `wstrObject`, `wstrAction`, `result_ev`); карантин и резервное хранилище — `v_akpub_infected_item`.

## Хранение и нагрузка

- Срок хранения — по типу и важности (`nf_rule.day_count_to_store`), плюс предел по количеству; старые события удаляются процедурами KSC.
- Индексы: `rise_time`, `event_type`, `nHostId`, `severity`. Фильтр по периоду и типу дёшев; распределения за весь период (`GROUP BY` по большой таблице) выполняйте с осторожностью и ограничением периода.
- Пример запроса (обнаружения за 7 суток): `SELECT TOP (1000) … FROM dbo.v_akpub_ev_event e LEFT JOIN dbo.v_akpub_host h ON h.nId = e.nHostId WHERE e.tmRiseTime >= DATEADD(day, -7, GETUTCDATE()) AND e.strEventType = 'GNRL_EV_VIRUS_FOUND'`.
