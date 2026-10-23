#!/usr/bin/env bash
# install.sh — первая установка KAV Checker на сервере с Docker Engine и Docker Compose.
#   scripts/install.sh [--env FILE] [--build] [--yes]
# Что делает: проверяет docker; создаёт .env из .env.example (генерирует секреты) если его нет; создаёт каталоги данных; получает образы релиза
# (или собирает локально при --build / без доступа к реестру); применяет миграции внутренней базы; запускает сервисы; создаёт локального администратора.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
BUILD=0; YES=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --build) BUILD=1; shift ;; --yes|-y) YES=1; shift ;; -h|--help) sed -n '2,6p' "$0"; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
command -v docker >/dev/null || die "Docker не найден. Установите Docker Engine и Docker Compose (docs/INSTALL.md)."
docker compose version >/dev/null 2>&1 || die "Docker Compose (plugin) не найден."
if [ ! -f "$ENV_FILE" ]; then
  cp "$REPO_ROOT/.env.example" "$ENV_FILE"; chmod 600 "$ENV_FILE"
  sed -i "s#^POSTGRES_PASSWORD=.*#POSTGRES_PASSWORD=$(openssl rand -hex 24)#; s#^APP_MASTER_KEY=.*#APP_MASTER_KEY=$(openssl rand -base64 32)#" "$ENV_FILE"
  warn "Создан $ENV_FILE с новыми секретами. Проверьте APP_PUBLIC_URL, DATA_ROOT, WEB_PORT, GITHUB_REPO и IMAGE_REPO/IMAGE_TAG, затем запустите установку снова."
  exit 2
fi
load_env; validate_project_name; require_vars DATA_ROOT APP_PUBLIC_URL APP_MASTER_KEY POSTGRES_PASSWORD; check_placeholders
mkdir -p "$DATA_ROOT"/{postgres,reports,backups,updater,state} || die "Не удалось создать каталоги в $DATA_ROOT"
chmod 1777 "$DATA_ROOT/updater"; chown 10001 "$DATA_ROOT/reports" 2>/dev/null || chmod 777 "$DATA_ROOT/reports"
host_version_info
if [ "$BUILD" -eq 1 ] || [ "${IMAGE_REPO:-kavcheck}" = kavcheck ]; then
  export IMAGE_TAG="${APP_GIT_COMMIT}"; export IMAGE_REPO=kavcheck
  sed -i "s#^IMAGE_TAG=.*#IMAGE_TAG=$IMAGE_TAG#; s#^IMAGE_REPO=.*#IMAGE_REPO=kavcheck#" "$ENV_FILE"
  info "Сборка образов локально (тег $IMAGE_TAG)…"; dc build || die "Сборка образов не удалась"
else
  info "Получение образов ${IMAGE_REPO}:${IMAGE_TAG}…"; dc pull backend web || die "Не удалось получить образы: проверьте доступ к реестру или установите с --build"
fi
dc up -d postgres || die "PostgreSQL не запустился"; wait_healthy 120 postgres || die "PostgreSQL не стал работоспособным"
info "Миграции внутренней базы…"; dc run --rm --no-deps backend alembic upgrade head || die "Миграции не применены"
dc up -d || die "Сервисы не запустились"; wait_healthy 120 backend web || die "Сервисы не стали работоспособными (scripts/logs: docker compose logs)"
if ! dc exec -T backend python -m app.cli status 2>/dev/null | grep -qE 'Пользователей: [1-9]'; then
  info "Создание локального администратора…"; dc exec -T backend python -m app.cli create-admin || warn "Администратор не создан: создайте вручную: ./scripts/ctl.sh admin"
fi
printf '%s version=%s commit=%s image_tag=%s\n' "$(date -Is)" "$APP_VERSION" "$APP_GIT_COMMIT" "$IMAGE_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$APP_VERSION"; state_set current_commit "$APP_GIT_COMMIT"; state_set current_tag "$IMAGE_TAG"
ok "KAV Checker запущен: http://${WEB_BIND_ADDR}:${WEB_PORT} (публичный адрес ${APP_PUBLIC_URL} — через ваш reverse proxy)."
info "Обновления из браузера: sudo ./scripts/updater.sh install --yes"
