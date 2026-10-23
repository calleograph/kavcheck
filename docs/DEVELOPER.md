# Для разработчиков

## Локальная разработка

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q                       # модульные тесты на SQLite и подставном KSC
cd ../frontend && npm install && npm run dev        # http://localhost:5173, прокси /api → 127.0.0.1:8000
```

Backend локально: `DATABASE_URL=postgresql+asyncpg://… APP_MASTER_KEY=… COOKIE_SECURE=false APP_PUBLIC_URL=http://localhost:5173 .venv/bin/uvicorn app.main:app_factory --factory --reload`.

Полная среда в Docker: `cp .env.example .env`, заполнить, `./scripts/install.sh --build`.

Синтетическая база «как KSC» для проверки SQL-шаблонов (SQL Server 2022 в Docker, вымышленные данные): `tests/ksc_synthetic/run.sh up`, затем `KSC_TEST_HOST=127.0.0.1 backend/.venv/bin/python -m pytest -q backend/tests/test_ksc_live.py`. Схема — `tests/ksc_synthetic/schema.sql`; при добавлении шаблонов, использующих новые объекты, дополните её.

## Архитектура SQL-запросов

- Все шаблоны — в `backend/app/ksc/queries.py`. Параметры только через `%(name)s` (pymssql). Динамические части — заранее собранные фрагменты из белых списков (`hosts_where`, `products_where`, `_SORT`) и списки целых (`ids_list`).
- Каждый запрос проходит `guard.check` (одна инструкция SELECT/WITH, запрещённые слова) до подключения.
- Соединение: `ksc/driver.py` — `SourceClient` (семафор, поток на запрос) для интерактивных запросов, `Session` (одно соединение на серию запросов) для отчётов. На соединении: `READ UNCOMMITTED`, `LOCK_TIMEOUT 5000`, тайм-аут запроса из настроек источника.
- Большие выборки читаются пачками (`OFFSET … FETCH`, `IN (…)` по 300–500 идентификаторов) с проверкой `max_rows` и флага отмены.
- Совместимость: `FEATURE_OBJECTS` → `schema.diagnose` проверяет объекты; API возвращает «функция недоступна для источника», если объектов нет.

## Адаптер KSC: алгоритмы

- `versions.py`: сравнение dpkg (`compare`), `upstream` (без эпохи и ревизии), `branch_of`, `compared_version(name, version, branch_regex)`, `in_range`.
- `grouping.py`: `Rule` (LIKE → regex → ветка из имени или из версии), встроенные правила.
- `hosts.py`: активность по `tmLastNagentConnected`, IP из `nIp` (первый октет в старшем байте), путь группы, дистрибутив Linux по `base-files`/`*-release`.
- `software.py`: страницы реестра со счётчиками, группировка по ветке, отбор по версиям.

Знания о структуре KSC — `docs/ksc/`.

## Добавить отчёт

1. `reports/builder.py`: `build_<kind>(conn, params, …) -> (rows, summary)`; колонки `<KIND>_COLUMNS`.
2. `reports/runner.py`: ветка по `job.kind`; `reports/export.py`: лист XLSX, если нужен особый.
3. `api/schemas.py` (`ReportIn.kind`, параметры), `api/reports.py` (`KIND_TITLE`).
4. Frontend: `api.ts` (`Job["kind"]`), `pages/ReportsPage.tsx` (форма, `KINDS`, колонки просмотра).
5. Тест на подставной сессии в `tests/test_reports.py` и, при новых SQL, в `tests/test_ksc_live.py`.

## Добавить модуль (раздел)

Сервис в `ksc/<module>.py` (шаблоны в `queries.py`, объекты в `FEATURE_OBJECTS`), маршрут в `api/` с зависимостями `require_user`/`current_source`, аудит важных действий (`write_audit`) и события (`Journal.emit`), страница во frontend вместо заглушки из `PlannedPages.tsx`, пункт в `NAV` (`App.tsx`).

## Настройки

Группы — pydantic-модели в `services/settings.py` (`GROUPS`); секреты в `SECRETS` шифруются и наружу отдаются флагом `<имя>_set`. Новая группа: модель + форма во frontend (`GeneralAdmin.tsx` — образец).

## Миграции

```bash
cd backend && .venv/bin/alembic revision -m "описание"    # заполнить upgrade/downgrade вручную
```

Только внутренняя база. Перед миграцией `update.sh` создаёт резервную копию; `rollback.sh` проверяет совместимость ревизии.

## Выпуск

`VERSION` → `CHANGELOG.md` (раздел `## [X.Y.Z]`) → `frontend/package.json` совпадают (`scripts/release.sh check`). `scripts/release.sh patch|minor` создаёт коммит и тег; `git push --tags` запускает `release.yml`: образы в GHCR и страница релиза. CI (`ci.yml`): тесты backend, сборка frontend, синтаксис скриптов, `compose config`, проверка частных данных, согласованность версии, сборка образов.

## Конфиденциальность

`python3 scripts/check_private_data.py [--history]` — домены, адреса и IP только из `scripts/private-data.allow`; свои запрещённые шаблоны — `PRIVATE_DENY_FILE`. Тестовые данные — вымышленные (`example.local`, 192.0.2.0/24).
