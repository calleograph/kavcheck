#!/usr/bin/env bash
# update.sh — штатное обновление установленного KAV Checker до релиза из GitHub (или локальной сборки).
#   scripts/update.sh [--env FILE] [--to vX.Y.Z] [--build] [--yes] [--dry-run]
# По порядку: git fetch → выбор целевого релиза (последний тег vX.Y.Z или --to) → checkout тега → образы релиза (pull из IMAGE_REPO либо локальная сборка)
# → резервная копия внутренней базы и .env → миграции Alembic → перезапуск → ожидание healthcheck → при ошибке автоматический откат (rollback.sh).
# Сохраняются текущая и одна предыдущая версия образов; старые образы этого проекта удаляются. Данные, отчёты и настройки не затрагиваются.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
TO=""; BUILD=0; YES=0; WAIT=180
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --to) TO="$2"; shift 2 ;; --build) BUILD=1; shift ;; --yes|-y) YES=1; shift ;; --dry-run) DRY_RUN=1; shift ;; --wait) WAIT="$2"; shift 2 ;; -h|--help) sed -n '2,7p' "$0"; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
STEP=0; STEPS=9; CUR="init"
step() { STEP=$((STEP + 1)); CUR="$1"; log; log "[$STEP/$STEPS] $1"; }
OLD_VER="$(version_file_read)"; OLD_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"; OLD_TAG="${IMAGE_TAG:-}"
DEPLOYED=0
stop_update() {
  fail "$*"; history_append update failed "$OLD_VER" "${NEW_VER:-?}" "$CUR"; state_set result "failed_at_${CUR}"
  if [ "$DEPLOYED" -eq 1 ]; then warn "Сервисы новой версии не заработали — откат на предыдущую"; "$REPO_ROOT/scripts/rollback.sh" --yes --env "$ENV_FILE" || warn "Откат не выполнен: см. docs/UPDATE_AND_BACKUP.md"
  elif [ -n "${PREV_HEAD:-}" ] && [ "$(git -C "$REPO_ROOT" rev-parse HEAD)" != "$PREV_HEAD" ]; then git -C "$REPO_ROOT" checkout -q --detach "$PREV_HEAD" && warn "Код возвращён на прежнюю версию; работающие сервисы не трогались"; fi
  exit 1
}
step "Текущая версия и репозиторий"
command -v git >/dev/null || die "git не найден"; git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 || die "$REPO_ROOT не git-репозиторий"
log "Проект $COMPOSE_PROJECT_NAME · версия $OLD_VER · commit $OLD_COMMIT · образы ${IMAGE_REPO:-kavcheck}:${OLD_TAG}"
step "Проверка релизов в GitHub (git fetch --tags)"
git -C "$REPO_ROOT" fetch --tags --prune -q origin 2>/dev/null || warn "git fetch не удался (нет доступа к GitHub?) — используются уже полученные теги"
if [ -n "$TO" ]; then TARGET_TAG="$TO"; else TARGET_TAG="$(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"; fi
[ -n "$TARGET_TAG" ] || stop_update "Релизных тегов vX.Y.Z нет: обновляться не на что"
git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$TARGET_TAG" >/dev/null || stop_update "Тег $TARGET_TAG не найден"
NEW_VER="${TARGET_TAG#v}"
log "Целевой релиз: $TARGET_TAG"
if [ "$DRY_RUN" = 1 ]; then info "[dry-run] дальше: checkout $TARGET_TAG → образы → резервная копия → миграции → перезапуск → проверка"; exit 0; fi
if [ "$YES" -ne 1 ]; then if [ -t 0 ]; then read -r -p "Обновить $OLD_VER → $NEW_VER? [y/N] " a; [ "$a" = y ] || die "Отменено."; else die "Нет терминала: добавьте --yes"; fi; fi
step "Переход кода на $TARGET_TAG"
PREV_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)"
if [ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]; then git -C "$REPO_ROOT" stash push -q -m "update-$(date +%s)" && warn "Локальные изменения файлов проекта сохранены в git stash"; fi
git -C "$REPO_ROOT" checkout -q --detach "$TARGET_TAG" || stop_update "git checkout $TARGET_TAG не удался"
host_version_info
state_set previous_version "$OLD_VER"; state_set previous_commit "$OLD_COMMIT"; state_set previous_tag "$OLD_TAG"; state_set previous_head "$PREV_HEAD"
step "Образы релиза"
if [ "$BUILD" -eq 1 ] || [ "${IMAGE_REPO:-kavcheck}" = kavcheck ]; then
  export IMAGE_REPO=kavcheck IMAGE_TAG="$APP_GIT_COMMIT"; dc build || stop_update "Сборка образов не удалась"
else
  export IMAGE_TAG="$TARGET_TAG"; dc pull backend web || stop_update "Не удалось получить образы ${IMAGE_REPO}:${IMAGE_TAG} — проверьте доступ к реестру или используйте --build"
fi
sed -i "s#^IMAGE_TAG=.*#IMAGE_TAG=$IMAGE_TAG#; s#^IMAGE_REPO=.*#IMAGE_REPO=$IMAGE_REPO#" "$ENV_FILE"
step "Резервная копия внутренней базы и .env"
cp -p "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)" && chmod 600 "$ENV_FILE".backup-* 2>/dev/null
dc up -d postgres >/dev/null && wait_healthy 120 postgres || stop_update "PostgreSQL не запустился"
"$REPO_ROOT/scripts/backup.sh" --env "$ENV_FILE" --label "pre-${OLD_VER}" || stop_update "Резервная копия не создана — миграции без неё не выполняются"
step "Миграции внутренней базы (Alembic)"
dc stop backend worker >/dev/null 2>&1 || true
dc run --rm --no-deps backend alembic upgrade head || stop_update "alembic upgrade head не выполнен (PostgreSQL откатил миграцию; схема прежняя). Восстановите код: scripts/rollback.sh"
step "Перезапуск сервисов и ожидание healthcheck"
DEPLOYED=1
dc up -d || stop_update "docker compose up не выполнен"
wait_healthy "$WAIT" backend web || stop_update "Сервисы не стали работоспособными"
step "Проверка доступности приложения"
curl -fsS "http://${WEB_BIND_ADDR}:${WEB_PORT}/api/v1/health/ready" >/dev/null || stop_update "Приложение не отвечает на /api/v1/health/ready"
RUN_VER="$(curl -fsS "http://${WEB_BIND_ADDR}:${WEB_PORT}/api/v1/version" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ "$RUN_VER" = "$NEW_VER" ] || warn "Работающая версия ($RUN_VER) отличается от целевой ($NEW_VER)"
step "Очистка старых образов проекта"
for svc in backend web; do
  docker images --format '{{.Repository}}:{{.Tag}}' "${IMAGE_REPO}-${svc}" 2>/dev/null | grep -vE ":(${IMAGE_TAG}|${OLD_TAG:-__none__})$" | xargs -r docker rmi >/dev/null 2>&1 || true
done
printf '%s old=%s new=%s image_tag=%s\n' "$(date -Is)" "$OLD_VER" "$NEW_VER" "$IMAGE_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$NEW_VER"; state_set current_commit "$APP_GIT_COMMIT"; state_set current_tag "$IMAGE_TAG"; state_set result ok
history_append update ok "$OLD_VER" "$NEW_VER"
ok "Обновление выполнено: $OLD_VER → $NEW_VER (образы ${IMAGE_REPO}:${IMAGE_TAG}). Откат: scripts/rollback.sh"
