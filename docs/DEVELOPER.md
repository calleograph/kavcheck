# Для разработчиков

## Локальная разработка

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q                       # модульные тесты на SQLite и подставном KSC
cd ../frontend && npm install && npm run dev        # http://localhost:5173, прокси /api → 127.0.0.1:8000
```

Прокси можно направить на запущенный контейнер `web`: `DEV_BACKEND_URL=http://127.0.0.1:18080 npm run dev` (добавьте `http://127.0.0.1:5173` в `ALLOWED_ORIGINS` локального `.env`).

### Интерфейс

Стили — только `frontend/src/styles.css`: сначала токены (цвета обеих тем, радиусы, тени, движение), затем компоненты. Новые цвета и отступы берите из токенов, тёмную тему задавайте в обоих блоках (`[data-theme=dark]` и `prefers-color-scheme`). Общие элементы страниц — `components/ui.tsx` (заголовок страницы, пустое состояние, скелет, сегменты, вкладки, спектр, плавающая панель), пиктограммы — `components/Icons.tsx`. Моноширинный шрифт (`.mono`) — только для версий, адресов, CVE и команд. Анимации — через `transform`/`opacity`, с правилом в блоке `prefers-reduced-motion`. Правила экранов (одно основное действие, технические параметры в «Дополнительно», состояния загрузки, таблицы, движение, адаптивность) и итоги аудита интерфейса — [docs/UI.md](UI.md). Встроенные стили (`style={{…}}`) — только для вычисляемых значений (ширины полос, положения подложек).

Списки: `components/Infinite.tsx` — `useInfinite` (порции с сервера, фильтры в `deps`, память списка и места прокрутки на сеанс), `VirtualRows` (виртуализация строк таблицы, `@tanstack/react-virtual`; `scrollEl` — для боковой панели), `ListFoot` (подвал), `useKept` (фильтры на сеанс), `staticList`/`useStaticList` (уже загруженный массив). Постраничных кнопок нет. Списки по щелчку на числе или версии — `components/HostsDrawer.tsx` (боковая панель; её состояние — в параметрах адреса, чтобы «Назад» из карточки возвращал к ней). Выбор программ каталога — `selection.ts` (localStorage по источнику). Тяжёлые наборы (компьютеры продукта, выбранных записей реестра, защиты, уязвимостей) строятся одним запросом к KSC и кэшируются, порции берутся из кэша.

Backend локально: `DATABASE_URL=postgresql+asyncpg://… APP_MASTER_KEY=… COOKIE_SECURE=false APP_PUBLIC_URL=http://localhost:5173 .venv/bin/uvicorn app.main:app_factory --factory --reload`.

Полная среда в Docker: `cp .env.example .env`, заполнить, `./scripts/install.sh --build`.

Синтетическая база «как KSC» для проверки SQL-шаблонов (SQL Server 2022 в Docker, вымышленные данные): `tests/ksc_synthetic/run.sh up`, затем `KSC_TEST_HOST=127.0.0.1 backend/.venv/bin/python -m pytest -q backend/tests/test_ksc_live.py`. Схема — `tests/ksc_synthetic/schema.sql` (с индексами как в KSC 15.1); при добавлении шаблонов, использующих новые объекты, дополните её. Крупная база для проверки производительности: `tests/ksc_synthetic/run.sh bulk [число компьютеров]` создаёт KAVBIG (`gen_bulk.py`: 20 тыс. компьютеров, 600 тыс. установок, уязвимости, состояние защиты, 300 тыс. событий за 90 суток; адреса из 198.18.0.0/15).

Тестовый каталог для LDAP: `tests/ldap_test/run.sh up [сеть docker]` — OpenLDAP с LDAPS (ldap.example.local:636 в сети compose, 127.0.0.1:10636 снаружи), сгенерированная цепочка корневой → промежуточный CA → сервер (`run.sh ca` печатает корневой сертификат), пользователи `ivanov` (группа KAV-Analysts) и `petrova`. Пароли тестовых записей — в `seed.ldif`, только для стенда.

## Архитектура SQL-запросов

- Все шаблоны — в `backend/app/ksc/queries.py`. Параметры только через `%(name)s` (pymssql). Динамические части — заранее собранные фрагменты из белых списков (`hosts_where`, `products_where`, `_SORT`) и списки целых (`ids_list`).
- Каждый запрос проходит `guard.check` (одна инструкция SELECT/WITH, запрещённые слова) до подключения.
- Соединение: `ksc/driver.py` — `SourceClient` (семафор, поток на запрос) для интерактивных запросов, `Session` (одно соединение на серию запросов) для отчётов. На соединении: `READ UNCOMMITTED`, `LOCK_TIMEOUT 5000`, тайм-аут запроса из настроек источника.
- Большие выборки читаются пачками (`OFFSET … FETCH`, `IN (…)` по 300–500 идентификаторов) с проверкой `max_rows` и флага отмены.
- Совместимость: `FEATURE_OBJECTS` → `schema.diagnose` проверяет объекты; API возвращает «функция недоступна для источника», если объектов нет.

## Адаптер KSC: алгоритмы

- `versions.py`: сравнение dpkg (`compare`) и числовое для Windows (`compare_numeric`: 130 = 130.0.0.0, rc/beta ниже выпуска, буквенный суффикс 1.1.1w выше 1.1.1), приведение нумерации (`transform`: java 8.0.4010.7 → 8.0.401, python 3.12.3150.0 → 3.12.3), `scheme_for`, условия `matches` (lt/le/eq/ge/gt/range/any) и исключения `excluded` (сборка или префикс ветки).
- `catalog.py`: встроенные описания продуктов (`BUILTIN`, около 70: имя, шаблон, схема версий, правило ветки), `classify` записи реестра, нормализация имени и производителя, `branch` (`parts:N`, `postgres`, `mssql`, `name:<regex>`, `phpname`). `catalog_build.py`: построение каталога keyset-чтением компьютеров, продуктов и установок; ручные правки (`Overrides`: объединение, выделение, переименование).
- `grouping.py`: правила группировки по LIKE и регулярному выражению (отбор по названию в проверке версий).
- `protection.py`: основной защитный продукт компьютера, проблемы защиты с порогами (`problems`), спектр версий (`versions`). `events.py`: типы обнаружений, параметры событий (`event_row`), сводка и страница журнала.
- `hosts.py`: активность по `tmLastNagentConnected`, IP из `nIp` (первый октет в старшем байте), путь группы, дистрибутив Linux по `base-files`/`*-release`.
- `software.py`: страницы реестра со счётчиками. `vulns.py`: агрегаты уязвимостей по компьютерам и программам.

Знания о структуре KSC — `docs/ksc/`.

## Добавить отчёт

1. `reports/builder.py`: `build_<kind>(conn, params, …) -> (rows, summary)`; колонки `<KIND>_COLUMNS`.
2. `reports/runner.py`: ветка по `job.kind`; `reports/export.py`: лист XLSX, если нужен особый.
3. `api/schemas.py` (`ReportIn.kind`, параметры), `api/reports.py` (`KIND_TITLE`).
4. Frontend: `api.ts` (`Job["kind"]`), `pages/ReportsPage.tsx` (форма, `KINDS`, колонки просмотра).
5. Тест на подставной сессии в `tests/test_reports.py` и, при новых SQL, в `tests/test_ksc_live.py`.

## Быстрые отчёты

Быстрый отчёт — вид `quick_vulns | quick_hosts | quick_protection | quick_events` (и `version_audit` в панели). Один документ (`reports/quick.py`: `build(kind, client, params, ctx)` → title, conditions, metrics, severity, notes, tables) — единственный источник правды для предпросмотра (`POST /quick/preview`, `api/quick.py`, кэш по источнику, виду и параметрам), фонового отчёта (`runner._execute_quick`) и выгрузок (`reports/quick_export.py`: XLSX, самодостаточный HTML, CSV). Строки подсчитываются один раз: уникальные компьютеры, установки (компьютер × программа), обнаружения; новые правила подсчёта добавляйте в построителе, а не в выгрузке.

Новый быстрый отчёт: SQL-шаблон в `ksc/queries.py` (если нужен) → построитель в `reports/quick.py` + ветка в `build()` → схема параметров в `api/schemas.py` (`Quick*`, `QUICK_PARAMS`, `ReportIn.kind`) → `KIND_TITLE` в `api/reports.py` → в интерфейсе `useRowSel` + `ReportDock` + `QuickReportPanel` (`components/QuickReport.tsx`) на нужной странице. Тесты — `tests/test_quick_reports.py` (синтетический SQL Server): совпадение просмотра и отчёта, отсутствие двойного подсчёта, содержимое XLSX/HTML.

## Добавить модуль (раздел)

Сервис в `ksc/<module>.py` (шаблоны в `queries.py`, объекты в `FEATURE_OBJECTS`), маршрут в `api/` с зависимостями `require_user`/`current_source` и проверкой `unsupported(src, "<функция>")`, тяжёлые агрегаты — через `request.app.state.cache` (как `api/protection.py`), глобальный фильтр активности — из `settings_svc.get(db, "general").activity_days` со счётчиком скрытых, аудит важных действий (`write_audit`) и события (`Journal.emit`), страница в `pages/` и пункт в `NAV` (`App.tsx`). Тесты: правила без базы — `tests/test_<module>.py`, SQL — `tests/test_ksc_live.py`.

## Настройки

Группы — pydantic-модели в `services/settings.py` (`GROUPS`); секреты в `SECRETS` шифруются и наружу отдаются флагом `<имя>_set`. Новая группа: модель + форма во frontend (`GeneralAdmin.tsx` — образец).

## Миграции

```bash
cd backend && .venv/bin/alembic revision -m "описание"    # заполнить upgrade/downgrade вручную
```

Только внутренняя база. Перед миграцией `update.sh` создаёт резервную копию; `rollback.sh` проверяет совместимость ревизии. Миграции выполняет отдельная команда (`./scripts/ctl.sh migrate`, `install.sh`, `update.sh`), не сервер при запуске. `0004_catalog_families` — семейства каталога (`family_key`, `family_size`) и запрос на перестроение каталогов.

## Выпуск

`VERSION` → `CHANGELOG.md` (раздел `## [X.Y.Z]`) → `frontend/package.json` совпадают (`scripts/release.sh check`). `scripts/release.sh patch|minor` создаёт коммит и тег; `git push --tags` запускает `release.yml`: образы в GHCR и страница релиза. CI (`ci.yml`): тесты backend, сборка frontend, синтаксис скриптов, `compose config`, проверка частных данных, согласованность версии, сборка образов.

## Конфиденциальность

`python3 scripts/check_private_data.py [--history]` — домены, адреса и IP только из `scripts/private-data.allow`; свои запрещённые шаблоны — `PRIVATE_DENY_FILE`. Тестовые данные — вымышленные (`example.local`, 192.0.2.0/24).
