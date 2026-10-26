# Инструкции для ИИ-агентов и новых разработчиков

KAV Checker — самостоятельный продукт. Для работы с ним не нужны никакие внешние проекты: всё, что требуется знать о структуре Kaspersky Security Center, собрано в `docs/ksc/`.

## Устройство (кратко)

- `backend/app` — FastAPI. `ksc/` — адаптер базы KSC (драйвер pymssql, защита запросов, SQL-шаблоны, диагностика, версии, группировка); `reports/` — построитель отчётов и воркер; `api/` — маршруты; `auth/` — сессии, роли, LDAP; `services/` — настройки, аудит, обновления.
- `frontend/src` — React + TypeScript, без UI-библиотек; стили в `styles.css`.
- `deployment/compose.yml` — postgres, backend, worker, web. `scripts/` — установка, обновление, откат, резервные копии, помощник обновлений.
- `docs/` — для администраторов и разработчиков; `docs/ksc/` — карта знаний KSC.

Подробно: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEVELOPER.md](docs/DEVELOPER.md).

## Правила работы с базами KSC (обязательно)

1. **Только чтение.** Никаких INSERT/UPDATE/DELETE/DDL/EXEC. Каждый SQL проходит `app/ksc/guard.py`; новые запросы — только шаблонами в `app/ksc/queries.py` с параметрами pymssql (`%(name)s`). Строки от пользователя в SQL не подставляются; списки идентификаторов — через `queries.ids_list` (только int). Текстовый поиск (`LIKE`) — только через `app/search.py`: `mssql_like(текст, mode)` для KSC, `column_like`/`any_of` для внутренней базы, `matcher`/`any_field` для списков в памяти; `*` — любое число символов (правила и пределы — там же).
2. **Ограничения:** постраничная выдача (`OFFSET … FETCH`), `max_rows`, тайм-аут запроса, семафор одновременных запросов на источник. Тяжёлое — только фоновым отчётом.
3. **Не изменять структуру базы KSC** и не «чинить» её. Если объекта нет — функция сообщает о несовместимости (`app/ksc/schema.py`, `FEATURE_OBJECTS`).
4. **Даты KSC — UTC.** Активность считается по `tmLastNagentConnected`. `nIp`: первый октет в старшем байте. Действующие установки — `bDeleted = 0`. Версии сравниваются алгоритмом dpkg (`app/ksc/versions.py`), не строками.
5. **Миграции** (Alembic) относятся только к внутренней базе KAV Checker.

## Конфиденциальность

- В репозиторий не попадают имена организаций, компьютеров, домены, IP-адреса, учётные записи, дампы и отчёты. Примеры — `example.local`, адреса из 192.0.2.0/24. Проверка: `python3 scripts/check_private_data.py` (в CI обязательна; `--history` — по всей истории git).
- Секреты только в `.env` (вне git) и в базе в зашифрованном виде (`APP_MASTER_KEY`). Пароли не возвращаются через API и не пишутся в журналы (`logging_setup.scrub`).

## Как добавить

- **Новый отчёт:** вид в `reports/builder.py` (функция `build_<kind>` → `(rows, summary)`), колонки в `builder.*_COLUMNS`, ветка в `reports/runner.py`, схема параметров в `api/schemas.py`, тип в `frontend/src/api.ts` и форма в `pages/ReportsPage.tsx`.
- **Новый модуль аудита** (лицензии, сравнение периодов…): SQL-шаблоны в `ksc/queries.py` + объекты в `FEATURE_OBJECTS`, сервис в `ksc/<module>.py`, маршрут в `api/` (образец — `api/protection.py`: кэш, глобальный фильтр активности, `unsupported`), страница в `pages/` и пункт в `NAV`. Используйте общие компоненты: `current_source`, роли (`require_user/analyst/admin`), `write_audit`, `Journal`, `Pager`, `Fetched`, `HiddenNote`.
- **Зоны ответственности, рассылки, решения по уязвимостям:** `backend/app/zones/` (`match.py` — принадлежность компьютеров, `csv_io.py`, `dataset.py` — запись «компьютер × проблемы», `snapshot.py` — потоковый расчёт подготовленных данных зон (worker), `zread.py` — чтение их агрегатами SQL, `zjobs.py` — очередь заданий и ночное расписание, `report.py` — отчёт зоны, `triage.py`, `mailer.py` — очередь и расписания), `api/zones.py`, страницы `ZonesPage` и `admin/{Zones,Mail,Org}Admin`; порядок таблиц во всех отчётах — `reports/layout.py`. Подробно: [docs/ZONES.md](docs/ZONES.md), [docs/ZONE_CACHE.md](docs/ZONE_CACHE.md). **Память и конкуренция фоновых задач:** страницы и API не читают KSC и не грузят в память целые источники; тяжёлое — только в worker, порциями, под `services/resources.py` (`RES.heavy`, `RES.breathe`); новые тяжёлые операции без порционной обработки и ограничителя не добавляются. Замеры — `python -m app.tools.perf`, `tests/perf/`. SQLite в тестах не проверяет длину строк — длины столбцов сверяет `test_enum_values_fit_postgres_column_lengths`.
- **Продукт в каталоге:** встроенное описание `P(...)` в `ksc/catalog.py BUILTIN` (шаблон имени, схема версий, правило ветки) с тестом в `tests/test_versions.py`; ошибки группировки на конкретной установке исправляются в интерфейсе (Администрирование → Каталог программ).

## Проверка перед изменениями

```bash
cd backend && .venv/bin/python -m pytest -q            # модульные тесты (SQLite, подставной KSC)
tests/ksc_synthetic/run.sh up && KSC_TEST_HOST=127.0.0.1 backend/.venv/bin/python -m pytest -q backend/tests/test_ksc_live.py   # SQL-шаблоны на SQL Server
cd frontend && npm run build
python3 scripts/check_private_data.py
```

Не выполняйте массовые проверки и нагрузочные тесты на производственных SQL Server.
