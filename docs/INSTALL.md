# Установка

## Требования

- Linux-сервер (Ubuntu 22.04/24.04, Debian 12 или другой с systemd), Docker Engine 24+ и Docker Compose v2, git, curl, openssl.
- 2 ГБ ОЗУ, 5 ГБ на диске для образов и данных.
- Доступ по TCP к SQL Server базы KSC (обычно порт 1433) и учётная запись **только для чтения** (роль `db_datareader` в базе KSC). Не используйте учётную запись самого Сервера администрирования.
- Внешний reverse proxy с TLS (nginx, Caddy, Traefik): приложение публикует порт только на loopback и не привязано к домену.

## Шаги

```bash
sudo mkdir -p /opt/kavcheck && sudo chown "$USER" /opt/kavcheck
git clone https://github.com/<владелец>/kavcheck.git /opt/kavcheck && cd /opt/kavcheck
git checkout "$(git tag --list 'v*' --sort=-v:refname | head -1)"    # последний релиз (или оставьте main для разработки)
./scripts/install.sh
```

Первый запуск создаёт `.env` с случайными секретами (`POSTGRES_PASSWORD`, `APP_MASTER_KEY`) и останавливается. Откройте `.env` и проверьте:

| Переменная | Что указать |
|---|---|
| `APP_PUBLIC_URL` | адрес, по которому пользователи открывают приложение через ваш прокси, например `https://kavcheck.example.org` |
| `DATA_ROOT` | каталог постоянных данных вне репозитория, например `/srv/kavcheck-data` |
| `WEB_BIND_ADDR`, `WEB_PORT` | куда контейнер web слушает для прокси, по умолчанию `127.0.0.1:18080` |
| `IMAGE_REPO`, `IMAGE_TAG` | готовые образы релиза `ghcr.io/<владелец>/kavcheck` и `vX.Y.Z`; без доступа к реестру оставьте `kavcheck`/`dev` и ставьте с `--build` |
| `GITHUB_REPO` | `<владелец>/kavcheck` — для проверки релизов |
| `NPM_REGISTRY`, `PIP_INDEX_URL` | зеркала для локальной сборки, если registry.npmjs.org или pypi.org недоступны; пусто — официальные реестры |

Затем:

```bash
./scripts/install.sh            # или ./scripts/install.sh --build — собрать образы локально
```

Без доступа к registry.npmjs.org (ошибка `ETIMEDOUT` при сборке интерфейса) укажите зеркало: `./scripts/install.sh --build --npm-registry https://npm-mirror.gitverse.ru` (или `NPM_REGISTRY` в `.env`); аналогично `--pip-index` для pip. Установщик проверяет доступность реестров до сборки. Контрольные суммы пакетов проверяются в любом случае.

Установщик создаёт каталоги данных, получает или собирает образы, применяет миграции внутренней базы, запускает сервисы и создаёт локального администратора `admin` — пароль печатается один раз, при первом входе его нужно сменить.

Помощник обновлений (нужен только для кнопок «Обновить», «Откатить», «Резервная копия» в браузере):

```bash
sudo ./scripts/updater.sh install --yes
```

## Reverse proxy

Пример для nginx (TLS завершается на прокси, приложение получает `X-Forwarded-Proto`):

```nginx
server {
    listen 443 ssl;
    server_name kavcheck.example.org;
    # ssl_certificate …; ssl_certificate_key …;
    client_max_body_size 8m;
    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

`APP_PUBLIC_URL` должен совпадать с адресом в браузере: по нему проверяется Origin для защиты от CSRF. Несколько адресов — через `ALLOWED_ORIGINS`.

### HTTP и HTTPS

Приложение работает за прокси и по HTTP (например, на время ввода в эксплуатацию), и по HTTPS. При `COOKIE_SECURE=auto` (по умолчанию) cookie сессии получает флаг Secure, если `APP_PUBLIC_URL` начинается с `https://` или прокси передаёт `X-Forwarded-Proto: https`. При переходе с HTTP на HTTPS достаточно поменять `APP_PUBLIC_URL` и пересоздать контейнеры с новыми настройками (`./scripts/ctl.sh up`). Пока приложение открывается по HTTP, «Состояние системы» показывает предупреждение. `true` или `false` задают флаг принудительно.

## Проверка

- `./scripts/ctl.sh status` — состояние контейнеров.
- `curl -s http://127.0.0.1:18080/api/v1/health/ready` — готовность backend и внутренней базы.
- В браузере: Администрирование → Состояние системы.

## Полезные команды

```bash
./scripts/ctl.sh logs backend        # журналы
./scripts/ctl.sh admin               # создать ещё одного локального администратора
./scripts/ctl.sh reset-password admin
./scripts/backup.sh                  # резервная копия внутренней базы и .env
./scripts/update.sh                  # обновление до последнего релиза
./scripts/rollback.sh                # откат на предыдущую версию
```

## Переменные .env

Полный список с пояснениями — в [.env.example](../.env.example). Секреты (`POSTGRES_PASSWORD`, `APP_MASTER_KEY`) никогда не попадают в git. Потеря `APP_MASTER_KEY` означает потерю сохранённых паролей источников и LDAP и настроек второго фактора пользователей: храните копию `.env` в защищённом месте.
