#!/usr/bin/env bash
# update.sh — штатное обновление установленного KAV Checker до релиза из GitHub (или локальной сборки).
#   scripts/update.sh [--env FILE] [--to vX.Y.Z] [--build] [--yes] [--dry-run] [--skip-preflight]
# По порядку: проверки перед обновлением (место, GitHub, реестр образов или npm/pip, база, возможность отката) → git fetch и выбор релиза →
# перенос локальных правок зеркала в .env → checkout тега → образы → остановка приложения → резервная копия базы и .env → миграции →
# запуск и проверка работоспособности → очистка старых образов проекта → отчёт $DATA_ROOT/updater/report.json.
# Восстановление при ошибке: неудачная миграция — база возвращается к копии (прежняя сохраняется под другим именем), код и контейнеры — к прежней версии;
# новая версия не заработала — база к копии и откат образов (rollback.sh). Хранятся образы текущей и одной предыдущей версии. Данные, отчёты, настройки
# и секреты не затрагиваются.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
TO=""; BUILD=0; YES=0; WAIT=180; SKIP_PF=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --to) TO="$2"; shift 2 ;; --build) BUILD=1; shift ;; --yes|-y) YES=1; shift ;; --dry-run) DRY_RUN=1; shift ;;
  --wait) WAIT="$2"; shift 2 ;; --skip-preflight) SKIP_PF=1; shift ;; -h|--help) sed -n '2,10p' "$0"; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
STEP=0; STEPS=10; CUR="init"
step() { STEP=$((STEP + 1)); CUR="$1"; log; log "[$STEP/$STEPS] $1"; }
OLD_VER="$(version_file_read)"; OLD_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"; OLD_TAG="${IMAGE_TAG:-}"
DEPLOYED=0; MIGRATED=0; BACKUP=""; NEW_VER="?"
action_reset
stop_update() {
  fail "$*"; history_append update failed "$OLD_VER" "${NEW_VER:-?}" "$CUR"; state_set result "failed_at_${CUR}"
  local advice="См. журнал обновления и docs/UPDATE_AND_BACKUP.md"
  if [ "$DEPLOYED" -eq 1 ] || [ "$MIGRATED" -eq 1 ]; then
    warn "Новая версия не заработала — возвращаю базу к резервной копии и прежнюю версию"
    if [ -n "$BACKUP" ] && restore_db_exact "$BACKUP"; then
      if "$REPO_ROOT/scripts/rollback.sh" --yes --env "$ENV_FILE" --skip-schema-check; then action_log "выполнен откат кода и образов на $OLD_VER"; advice="Работает прежняя версия $OLD_VER. Причину смотрите в журнале обновления."
      else advice="Откат не выполнен автоматически: выполните на сервере sudo ./scripts/rollback.sh"; fi
    else advice="База не восстановлена автоматически: восстановите копию вручную (scripts/restore.sh $BACKUP) и выполните scripts/rollback.sh"; fi
  elif [ -n "${PREV_HEAD:-}" ] && [ "$(git -C "$REPO_ROOT" rev-parse HEAD)" != "$PREV_HEAD" ]; then
    git -C "$REPO_ROOT" checkout -q --detach "$PREV_HEAD" && action_log "код возвращён на прежнюю версию $OLD_VER; работающие сервисы не останавливались"
    if [ "$(svc_state backend)" = missing ] || [ "$(docker inspect -f '{{.State.Running}}' "$(dc ps -q backend 2>/dev/null | head -1)" 2>/dev/null)" != true ]; then
      export IMAGE_TAG="$OLD_TAG" IMAGE_REPO="${OLD_REPO:-$IMAGE_REPO}"; sed -i "s#^IMAGE_TAG=.*#IMAGE_TAG=$OLD_TAG#; s#^IMAGE_REPO=.*#IMAGE_REPO=$IMAGE_REPO#" "$ENV_FILE"
      dc up -d >/dev/null 2>&1 && action_log "прежние контейнеры запущены снова"
    fi
    advice="Работает прежняя версия $OLD_VER. Устраните причину и повторите обновление."
  fi
  report_write failed "$CUR" "$OLD_VER" "${NEW_VER:-?}" "$advice"
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
step "Проверки перед обновлением"
if [ "$SKIP_PF" -eq 1 ]; then warn "Проверки пропущены (--skip-preflight)"; else PF_BUILD=$BUILD preflight "$TARGET_TAG" || stop_update "Проверки перед обновлением не пройдены — ничего не изменено"; fi
if [ "$DRY_RUN" = 1 ]; then info "[dry-run] дальше: checkout $TARGET_TAG → образы → остановка → резервная копия → миграции → запуск → проверка → очистка"; exit 0; fi
if [ "$YES" -ne 1 ]; then if [ -t 0 ]; then read -r -p "Обновить $OLD_VER → $NEW_VER? [y/N] " a; [ "$a" = y ] || die "Отменено."; else die "Нет терминала: добавьте --yes"; fi; fi
step "Переход кода на $TARGET_TAG"
PREV_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)"
mirror_local_fix
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then git -C "$REPO_ROOT" stash push -q -m "update-$(date +%s)" && action_log "прочие локальные изменения файлов проекта сохранены в git stash"; fi
git -C "$REPO_ROOT" checkout -q --detach "$TARGET_TAG" || stop_update "git checkout $TARGET_TAG не удался"
host_version_info
OLD_REPO="${IMAGE_REPO:-kavcheck}"
state_set previous_version "$OLD_VER"; state_set previous_commit "$OLD_COMMIT"; state_set previous_tag "$OLD_TAG"; state_set previous_head "$PREV_HEAD"; state_set previous_repo "$OLD_REPO"
step "Образы релиза"
if [ "$BUILD" -eq 1 ] || is_local_repo; then
  [ -n "${NPM_REGISTRY:-}" ] && info "Сборка интерфейса через зеркало npm: $NPM_REGISTRY"
  export IMAGE_REPO="$(local_build_repo)" IMAGE_TAG="$APP_GIT_COMMIT"; dc build || stop_update "Сборка образов не удалась (при недоступности реестров укажите NPM_REGISTRY и PIP_INDEX_URL в .env)"
else
  export IMAGE_TAG="$TARGET_TAG"; dc pull backend web || stop_update "Не удалось получить образы ${IMAGE_REPO}:${IMAGE_TAG} — проверьте доступ к реестру или используйте --build"
fi
sed -i "s#^IMAGE_TAG=.*#IMAGE_TAG=$IMAGE_TAG#; s#^IMAGE_REPO=.*#IMAGE_REPO=$IMAGE_REPO#" "$ENV_FILE"
step "Остановка приложения и резервная копия базы и .env"
dc up -d postgres >/dev/null && wait_healthy 120 postgres || stop_update "PostgreSQL не запустился"
dc stop backend worker >/dev/null 2>&1 || true            # после копии в базу никто не пишет: восстановление при ошибке — без потери данных
action_log "приложение остановлено на время резервной копии и миграций"
cp -p "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)" && chmod 600 "$ENV_FILE".backup-* 2>/dev/null
"$REPO_ROOT/scripts/backup.sh" --env "$ENV_FILE" --label "pre-${OLD_VER}" || stop_update "Резервная копия не создана — миграции без неё не выполняются"
BACKUP="$(ls -1t "${BACKUP_DIR:-$DATA_ROOT/backups}"/*-db-*-pre-"${OLD_VER}".dump 2>/dev/null | head -1)"
action_log "резервная копия базы: $(basename "${BACKUP:-?}")"
step "Миграции внутренней базы (Alembic)"
REV_BEFORE="$(dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '[:space:]')"
if ! dc run --rm --no-deps backend alembic upgrade head; then
  # приложение остановлено с момента копии — возврат базы к копии безопасен и не теряет данных, даже если миграция успела что-то изменить
  MIGRATED=1
  stop_update "Миграция не выполнена (ревизия до попытки: ${REV_BEFORE:-?})"
fi
MIGRATED=1
step "Запуск и проверка работоспособности"
DEPLOYED=1
dc up -d || stop_update "docker compose up не выполнен"
wait_healthy "$WAIT" backend web || stop_update "Сервисы не стали работоспособными"
curl -fsS "http://${WEB_BIND_ADDR}:${WEB_PORT}/api/v1/health/ready" >/dev/null || stop_update "Приложение не отвечает на /api/v1/health/ready"
RUN_VER="$(curl -fsS "http://${WEB_BIND_ADDR}:${WEB_PORT}/api/v1/version" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ "$RUN_VER" = "$NEW_VER" ] || warn "Работающая версия ($RUN_VER) отличается от целевой ($NEW_VER)"
step "Очистка старых образов проекта"
cleanup_images "$IMAGE_TAG" "$OLD_TAG"
step "Отчёт"
printf '%s old=%s new=%s image_tag=%s\n' "$(date -Is)" "$OLD_VER" "$NEW_VER" "$IMAGE_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$NEW_VER"; state_set current_commit "$APP_GIT_COMMIT"; state_set current_tag "$IMAGE_TAG"; state_set result ok
history_append update ok "$OLD_VER" "$NEW_VER"
report_write ok "готово" "$OLD_VER" "$NEW_VER" "Откат на $OLD_VER: Администрирование → Обновления или sudo ./scripts/rollback.sh"
ok "Обновление выполнено: $OLD_VER → $NEW_VER (образы ${IMAGE_REPO}:${IMAGE_TAG}). Откат: scripts/rollback.sh"
