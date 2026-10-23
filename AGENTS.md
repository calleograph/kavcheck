# Инструкции для ИИ-агентов и новых разработчиков

KAV Checker — самостоятельный продукт. Для работы с ним не нужны никакие внешние проекты: всё, что требуется знать о структуре Kaspersky Security Center, собрано в `docs/ksc/`.

## Устройство (кратко)

- `backend/app` — FastAPI. `ksc/` — адаптер базы KSC (драйвер pymssql, защита запросов, SQL-шаблоны, диагностика, версии, группировка); `reports/` — построитель отчётов и воркер; `api/` — маршруты; `auth/` — сессии, роли, LDAP; `services/` — настройки, аудит, обновления.
- `frontend/src` — React + TypeScript, без UI-библиотек; стили в `styles.css`.
- `deployment/compose.yml` — postgres, backend, worker, web. `scripts/` — установка, обновление, откат, резервные копии, помощник обновлений.
- `docs/` — для администраторов и разработчиков; `docs/ksc/` — карта знаний KSC.

Подробно: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DEVELOPER.md](docs/DEVELOPER.md).

## Правила работы с базами KSC (обязательно)

1. **Только чтение.** Никаких INSERT/UPDATE/DELETE/DDL/EXEC. Каждый SQL проходит `app/ksc/guard.py`; новые запросы — только шаблонами в `app/ksc/queries.py` с параметрами pymssql (`%(name)s`). Строки от пользователя в SQL не подставляются; списки идентификаторов — через `queries.ids_list` (только int).
2. **Ограничения:** постраничная выдача (`OFFSET … FETCH`), `max_rows`, тайм-аут запроса, семафор одновременных запросов на источник. Тяжёлое — только фоновым отчётом.
3. **Не изменять структуру базы KSC** и не «чинить» её. Если объекта нет — функция сообщает о несовместимости (`app/ksc/schema.py`, `FEATURE_OBJECTS`).
4. **Даты KSC — UTC.** Активность считается по `tmLastNagentConnected`. `nIp`: первый октет в старшем байте. Действующие установки — `bDeleted = 0`. Версии сравниваются алгоритмом dpkg (`app/ksc/versions.py`), не строками.
5. **Миграции** (Alembic) относятся только к внутренней базе KAV Checker.

## Конфиденциальность

- В репозиторий не попадают имена организаций, компьютеров, домены, IP-адреса, учётные записи, дампы и отчёты. Примеры — `example.local`, адреса из 192.0.2.0/24. Проверка: `python3 scripts/check_private_data.py` (в CI обязательна; `--history` — по всей истории git).
- Секреты только в `.env` (вне git) и в базе в зашифрованном виде (`APP_MASTER_KEY`). Пароли не возвращаются через API и не пишутся в журналы (`logging_setup.scrub`).

## Как добавить

- **Новый отчёт:** вид в `reports/builder.py` (функция `build_<kind>` → `(rows, summary)`), колонки в `builder.*_COLUMNS`, ветка в `reports/runner.py`, схема параметров в `api/schemas.py`, тип в `frontend/src/api.ts` и форма в `pages/ReportsPage.tsx`.
- **Новый модуль аудита** (защита, события…): SQL-шаблоны в `ksc/queries.py` + объекты в `FEATURE_OBJECTS`, сервис в `ksc/<module>.py`, маршрут в `api/`, страница во frontend вместо заглушки из `pages/PlannedPages.tsx`. Используйте общие компоненты: `current_source`, роли (`require_user/analyst/admin`), `write_audit`, `Journal`, `Pager`, `Fetched`.
- **Правило группировки продукта:** через интерфейс (Администрирование → Правила группировки) или встроенное в `ksc/grouping.py BUILTIN_RULES` (с тестом в `tests/test_versions.py`).

## Проверка перед изменениями

```bash
cd backend && .venv/bin/python -m pytest -q            # модульные тесты (SQLite, подставной KSC)
tests/ksc_synthetic/run.sh up && KSC_TEST_HOST=127.0.0.1 backend/.venv/bin/python -m pytest -q backend/tests/test_ksc_live.py   # SQL-шаблоны на SQL Server
cd frontend && npm run build
python3 scripts/check_private_data.py
```

Не выполняйте массовые проверки и нагрузочные тесты на производственных SQL Server.
