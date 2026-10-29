#!/usr/bin/env bash
# install.sh — первая установка KAV Checker на сервере с Docker Engine и Docker Compose.
#   scripts/install.sh [--env FILE] [--build] [--yes] [--npm-registry URL] [--pip-index URL]
# Что делает: проверяет docker; создаёт .env из .env.example (генерирует секреты) если его нет; создаёт каталоги данных; получает образы релиза
# (или собирает локально при --build / без доступа к реестру); устанавливает и включает помощника обновлений (служба systemd); применяет миграции внутренней базы; запускает сервисы; создаёт локального администратора.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
BUILD=0; YES=0; NPM_OPT=""; PIP_OPT=""
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --build) BUILD=1; shift ;; --yes|-y) YES=1; shift ;; --npm-registry) NPM_OPT="$2"; shift 2 ;;
  --pip-index) PIP_OPT="$2"; shift 2 ;; -h|--help) sed -n '2,6p' "$0"; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
env_set() { env_put "$1" "$2"; }
command -v docker >/dev/null || die "Docker не найден. Установите Docker Engine и Docker Compose (docs/INSTALL.md)."
docker compose version >/dev/null 2>&1 || die "Docker Compose (plugin) не найден."
if [ ! -f "$ENV_FILE" ]; then
  cp "$REPO_ROOT/.env.example" "$ENV_FILE"; chmod 600 "$ENV_FILE"
  sed -i "s#^POSTGRES_PASSWORD=.*#POSTGRES_PASSWORD=$(openssl rand -hex 24)#; s#^APP_MASTER_KEY=.*#APP_MASTER_KEY=$(openssl rand -base64 32)#" "$ENV_FILE"
  warn "Создан $ENV_FILE с новыми секретами. Проверьте APP_PUBLIC_URL, DATA_ROOT, WEB_PORT, GITHUB_REPO и IMAGE_REPO/IMAGE_TAG, затем запустите установку снова."
  exit 2
fi
load_env; validate_project_name; require_vars DATA_ROOT APP_PUBLIC_URL APP_MASTER_KEY POSTGRES_PASSWORD; check_placeholders
mkdir -p "$DATA_ROOT"/{postgres,reports,bi,backups,updater,state,pentest-import} || die "Не удалось создать каталоги в $DATA_ROOT"
chmod 1777 "$DATA_ROOT/updater"; for d in reports bi; do chown 10001 "$DATA_ROOT/$d" 2>/dev/null || chmod 777 "$DATA_ROOT/$d"; done
host_version_info
[ -n "$NPM_OPT" ] && env_set NPM_REGISTRY "${NPM_OPT%/}" && ok "Зеркало npm: $NPM_REGISTRY (сохранено в .env)"
[ -n "$PIP_OPT" ] && env_set PIP_INDEX_URL "$PIP_OPT" && ok "Зеркало pip: $PIP_INDEX_URL (сохранено в .env)"
# Готовые образы релиза — основной способ (ghcr.io, без Docker Hub, npm и pip). Условие: код на теге релиза vX.Y.Z и образы опубликованы.
# Иначе (код из ветки, нет доступа к реестру, явный --build) — локальная сборка; при установке прежней версии нет, поэтому переход на сборку допустим, но с сообщением.
dc_base
T_PULL="${UPD_TIMEOUT_PULL:-1800}"; S_PULL="${UPD_STALL_PULL:-300}"; T_BUILD="${UPD_TIMEOUT_BUILD:-2400}"; S_BUILD="${UPD_STALL_BUILD:-900}"
TAG_AT_HEAD="$(git -C "$REPO_ROOT" describe --tags --exact-match HEAD 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
GOT=0; REG=""
if [ "$BUILD" -eq 0 ] && [ -n "$TAG_AT_HEAD" ] && pick_registry "$TAG_AT_HEAD"; then
  REG="$REGISTRY_PICKED"; export IMAGE_REPO="$REG" IMAGE_TAG="$TAG_AT_HEAD"; info "Получение готовых образов ${IMAGE_REPO}-*:${IMAGE_TAG}…"
  if run_guarded "загрузка образов" "$T_PULL" "$S_PULL" "${DCB[@]}" pull backend web; then GOT=1
  else warn "Готовые образы получить не удалось ($(diag_advice "$(guard_fail_code registry)"))"; fi
fi
if [ "$GOT" -eq 0 ] && [ "$BUILD" -eq 0 ]; then
  die "Готовые образы получить не удалось (код на теге релиза: ${TAG_AT_HEAD:-нет}). Установка без сборки: git checkout vX.Y.Z && scripts/install.sh. Локальная сборка (нужны Docker Hub, npm и pip или их зеркала) — только явно: scripts/install.sh --build"
fi
if [ "$GOT" -eq 0 ]; then
  adopt_mirrors
  pick_npm_registries; pick_pip_indexes; export NPM_REGISTRIES PIP_INDEX_URLS
  REG_NPM="${NPM_REGISTRY:-https://registry.npmjs.org}"
  if ! curl -fsS -m 20 -o /dev/null "${REG_NPM%/}/typescript"; then
    warn "Реестр npm $REG_NPM не ответил за 20 с: сборка интерфейса может не пройти."
    if [ -t 0 ] && [ "$YES" -ne 1 ]; then
      read -r -p "Адрес зеркала npm (например https://npm-mirror.gitverse.ru), Enter — продолжить без зеркала: " M
      [ -n "$M" ] && env_set NPM_REGISTRY "${M%/}" && ok "Зеркало npm сохранено в .env: $NPM_REGISTRY"
    else warn "Укажите зеркало: scripts/install.sh --npm-registry URL (или NPM_REGISTRY в .env)"; fi
  fi
  export IMAGE_TAG="${APP_GIT_COMMIT}"; export IMAGE_REPO="$(local_build_repo)"
  info "Сборка образов локально (тег $IMAGE_TAG)…"; run_guarded "сборка образов" "$T_BUILD" "$S_BUILD" "${DCB[@]}" build || { kill_oneoff; die "Сборка образов не удалась: $(diag_advice "$(guard_fail_code build)")"; }
fi
env_set IMAGE_TAG "$IMAGE_TAG"; env_set IMAGE_REPO "$IMAGE_REPO"
[ -n "$REG" ] && ! grep -q '^IMAGE_REGISTRY=' "$ENV_FILE" && env_set IMAGE_REGISTRY "$REG"
dc up -d postgres || die "PostgreSQL не запустился"; wait_healthy 120 postgres || die "PostgreSQL не стал работоспособным"
info "Миграции внутренней базы…"; dc run --rm --no-deps backend alembic upgrade head || die "Миграции не применены"
dc up -d || die "Сервисы не запустились"; wait_healthy 120 backend web || die "Сервисы не стали работоспособными (scripts/logs: docker compose logs)"
if ! dc exec -T backend python -m app.cli status 2>/dev/null | grep -qE 'Пользователей: [1-9]'; then
  info "Создание локального администратора…"; dc exec -T backend python -m app.cli create-admin || warn "Администратор не создан: создайте вручную: ./scripts/ctl.sh admin"
fi
printf '%s version=%s commit=%s image_tag=%s\n' "$(date -Is)" "$APP_VERSION" "$APP_GIT_COMMIT" "$IMAGE_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$APP_VERSION"; state_set current_commit "$APP_GIT_COMMIT"; state_set current_tag "$IMAGE_TAG"
ok "KAV Checker запущен: http://${WEB_BIND_ADDR}:${WEB_PORT} (публичный адрес ${APP_PUBLIC_URL} — через ваш reverse proxy)."
# Помощник обновлений: служба systemd (автозапуск, перезапуск при сбоях) устанавливается и включается сразу — кнопка «Обновить» в браузере работает без дополнительных действий
if [ "$(id -u)" -eq 0 ]; then "$SCRIPTS_DIR/updater.sh" ensure --env "$ENV_FILE" || warn "Помощник обновлений не установлен: sudo ./scripts/updater.sh install --yes"
elif sudo -n true 2>/dev/null; then sudo -n "$SCRIPTS_DIR/updater.sh" ensure --env "$ENV_FILE" || warn "Помощник обновлений не установлен: sudo ./scripts/updater.sh install --yes"
elif [ -t 0 ] && command -v sudo >/dev/null; then sudo "$SCRIPTS_DIR/updater.sh" ensure --env "$ENV_FILE" || warn "Помощник обновлений не установлен: sudo ./scripts/updater.sh install --yes"
else warn "Помощник обновлений не установлен (нужны права root): sudo ./scripts/updater.sh install --yes — без него кнопка «Обновить» в браузере недоступна"; fi
