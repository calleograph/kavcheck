#!/usr/bin/env bash
# update.sh — штатное обновление установленного KAV Checker до релиза из GitHub.
#   scripts/update.sh [--env FILE] [--to vX.Y.Z] [--build] [--yes] [--dry-run] [--skip-preflight]
# Основной способ — готовые образы релиза из реестра (ghcr.io): Docker Hub, npm и pip не нужны. Локальная сборка — только с --build, UPDATE_MODE=build
# или UPDATE_ALLOW_BUILD=1 в .env (тогда при недоступности реестра сборка запускается с предупреждением в журнале).
# По порядку: проверки → git fetch и выбор релиза → код на тег → образы → остановка и резервная копия базы и .env → миграции → запуск и проверка → очистка старых образов
# → помощник обновлений → отчёт $DATA_ROOT/updater/report.json. У каждой сетевой операции и сборки свой тайм-аут и контроль прогресса (UPD_TIMEOUT_*, UPD_STALL_*).
# Ошибка на любом этапе: возвращается прежняя версия (при необходимости база — из копии); причина с советом — в report.json и журнале. Прерванное обновление
# (перезагрузка, остановка помощника) обрабатывает scripts/recover.sh по метке $DATA_ROOT/state/update.inprogress. Данные, отчёты, настройки и секреты не затрагиваются.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
TO=""; BUILD=0; YES=0; WAIT="${UPD_WAIT_HEALTH:-180}"; SKIP_PF=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --to) TO="$2"; shift 2 ;; --build) BUILD=1; shift ;; --yes|-y) YES=1; shift ;; --dry-run) DRY_RUN=1; shift ;;
  --wait) WAIT="$2"; shift 2 ;; --skip-preflight) SKIP_PF=1; shift ;; -h|--help) sed -n '2,10p' "$0"; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
T_NET="${UPD_TIMEOUT_NET:-60}"; T_PULL="${UPD_TIMEOUT_PULL:-1800}"; S_PULL="${UPD_STALL_PULL:-300}"; T_BUILD="${UPD_TIMEOUT_BUILD:-2400}"; S_BUILD="${UPD_STALL_BUILD:-900}"
T_MIG="${UPD_TIMEOUT_MIGRATE:-600}"; T_BACKUP="${UPD_TIMEOUT_BACKUP:-900}"; T_UP="${UPD_TIMEOUT_UP:-300}"
STEP=0; STEPS=11; CUR="init"; STAGE_CODE=generic
step() { STEP=$((STEP + 1)); CUR="$1"; log; log "[$STEP/$STEPS] $1"; }
OLD_VER="$(version_file_read)"; OLD_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"; OLD_TAG="${IMAGE_TAG:-}"; OLD_REPO="${IMAGE_REPO:-kavcheck}"
NEW_VER="?"; MARKED=0; UPD_MODE_USED=""
if [ "$DRY_RUN" != 1 ]; then
  # прерванное прежнее обновление (перезагрузка, Ctrl-C) обрабатывается до нового: сначала возвращается работоспособное состояние
  [ -e "$(marker_file)" ] && { warn "Найдено прерванное обновление — сначала проверяю и восстанавливаю состояние"; "$REPO_ROOT/scripts/recover.sh" --env "$ENV_FILE" || die "Восстановление не завершено: устраните причину и повторите (scripts/recover.sh)"; }
  take_lock; action_reset
fi

# stop_update КОД СООБЩЕНИЕ — завершить с ошибкой: вернуть прежнюю версию по этапу из метки, записать отчёт с причиной и советом
stop_update() {
  local code="$1"; shift
  fail "$*"
  local advice; advice="$(diag_advice "$code")"
  history_append update failed "$OLD_VER" "${NEW_VER:-?}" "$CUR"; state_set result "failed_at_${CUR}"
  if [ "$MARKED" -eq 1 ]; then
    recover_update
    case "$RECOVER_RESULT" in
      rolled_back) advice="$advice $RECOVER_ADVICE" ;;
      finalized) advice="$RECOVER_ADVICE" ;;
      *) advice="$advice $RECOVER_ADVICE" ;;
    esac
    marker_clear
  fi
  report_write failed "$CUR" "$OLD_VER" "${NEW_VER:-?}" "$advice" "$code"
  exit 1
}
step "Текущая версия и репозиторий"
command -v git >/dev/null || die "git не найден"; git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 || die "$REPO_ROOT не git-репозиторий"
log "Проект $COMPOSE_PROJECT_NAME · версия $OLD_VER · commit $OLD_COMMIT · образы ${OLD_REPO}:${OLD_TAG}"
if [ "$BUILD" -eq 1 ] || [ "$(update_mode)" = build ]; then UPD_MODE_USED=build; else UPD_MODE_USED=pull; fi
if [ "$UPD_MODE_USED" = pull ]; then log "Способ: готовые образы из реестра $(registry_repo) (локальная сборка не используется$(build_allowed && echo ', кроме резервного варианта UPDATE_ALLOW_BUILD=1'))"
else log "Способ: локальная сборка образов (запрошена явно)"; fi
step "Проверка релизов в GitHub (git fetch --tags)"
GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30 timeout "$T_NET" git -C "$REPO_ROOT" fetch --tags --prune -q origin 2>/dev/null || warn "git fetch не удался (нет доступа к GitHub?) — используются уже полученные теги"
if [ -n "$TO" ]; then TARGET_TAG="$TO"; else TARGET_TAG="$(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"; fi
[ -n "$TARGET_TAG" ] || stop_update generic "Релизных тегов vX.Y.Z нет: обновляться не на что"
git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$TARGET_TAG" >/dev/null || stop_update generic "Тег $TARGET_TAG не найден"
NEW_VER="${TARGET_TAG#v}"
log "Целевой релиз: $TARGET_TAG"
step "Проверки перед обновлением"
if [ "$SKIP_PF" -eq 1 ]; then warn "Проверки пропущены (--skip-preflight)"; else
  PF_MODE=$UPD_MODE_USED preflight "$TARGET_TAG" || {
    code=generic
    pf_failed registry && { [[ "$PF_ITEMS" == *'"key":"registry","status":"fail","message":"Образов'* ]] && code=image_missing || code=registry; }
    pf_failed docker_hub && code=docker_hub; pf_failed npm && code=npm; { pf_failed disk_docker || pf_failed disk_data; } && code=disk
    if [ "$UPD_MODE_USED" = pull ] && { [ "$code" = registry ] || [ "$code" = image_missing ]; } && build_allowed; then
      warn "Готовые образы недоступны; UPDATE_ALLOW_BUILD=1 — переход на локальную сборку (долго, нужны npm, pip и Docker Hub)"; action_log "готовые образы недоступны ($code): включена резервная локальная сборка (UPDATE_ALLOW_BUILD=1)"
      UPD_MODE_USED=build; PF_MODE=build preflight "$TARGET_TAG" || stop_update "$code" "Проверки перед обновлением не пройдены — ничего не изменено"
    else stop_update "$code" "Проверки перед обновлением не пройдены — ничего не изменено"; fi
  }
fi
if [ "$DRY_RUN" = 1 ]; then info "[dry-run] дальше: checkout $TARGET_TAG → образы ($UPD_MODE_USED) → остановка → резервная копия → миграции → запуск → проверка → очистка"; exit 0; fi
if [ "$YES" -ne 1 ]; then if [ -t 0 ]; then read -r -p "Обновить $OLD_VER → $NEW_VER? [y/N] " a; [ "$a" = y ] || die "Отменено."; else die "Нет терминала: добавьте --yes"; fi; fi
PREV_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)"
for kv in "pid=$$" "started=$(date +%s)" "old_ver=$OLD_VER" "new_ver=$NEW_VER" "old_tag=$OLD_TAG" "old_repo=$OLD_REPO" "prev_head=$PREV_HEAD" "stage=prepare" "mode=$UPD_MODE_USED" "target=$TARGET_TAG"; do marker_set "${kv%%=*}" "${kv#*=}"; done
MARKED=1
step "Переход кода на $TARGET_TAG"
marker_set stage code
mirror_local_fix
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then git -C "$REPO_ROOT" stash push -q -m "update-$(date +%s)" && action_log "прочие локальные изменения файлов проекта сохранены в git stash"; fi
git -C "$REPO_ROOT" checkout -q --detach "$TARGET_TAG" || stop_update generic "git checkout $TARGET_TAG не удался"
host_version_info
state_set previous_version "$OLD_VER"; state_set previous_commit "$OLD_COMMIT"; state_set previous_tag "$OLD_TAG"; state_set previous_head "$PREV_HEAD"; state_set previous_repo "$OLD_REPO"
step "Образы релиза"
marker_set stage images
dc_base
get_images() { # готовые образы; ненулевой код — получить не удалось (причина в STAGE_CODE)
  local reg="$REGISTRY_PICKED"; [ -n "$reg" ] || { pick_registry "$TARGET_TAG" || true; reg="$REGISTRY_PICKED"; }
  [ -n "$reg" ] || { STAGE_CODE=image_missing; return 1; }
  export IMAGE_REPO="$reg" IMAGE_TAG="$TARGET_TAG"
  run_guarded "загрузка образов" "$T_PULL" "$S_PULL" "${DCB[@]}" pull backend web && return 0
  STAGE_CODE="$(guard_fail_code registry)"; return 1
}
build_images() {
  adopt_mirrors
  [ -n "${NPM_REGISTRY:-}" ] && info "Сборка интерфейса через зеркало npm: $NPM_REGISTRY"; [ -n "${PIP_INDEX_URL:-}" ] && info "Сборка backend через зеркало pip: $PIP_INDEX_URL"
  export IMAGE_REPO="$(local_build_repo)" IMAGE_TAG="$APP_GIT_COMMIT"
  run_guarded "сборка образов" "$T_BUILD" "$S_BUILD" "${DCB[@]}" build && return 0
  kill_oneoff; STAGE_CODE="$(guard_fail_code build)"; return 1
}
if [ "$UPD_MODE_USED" = pull ]; then
  if ! get_images; then
    if build_allowed; then
      warn "Готовые образы получить не удалось (${STAGE_CODE}); UPDATE_ALLOW_BUILD=1 — перехожу на локальную сборку. Это долго и требует npm, pip и Docker Hub."
      action_log "готовые образы не получены (${STAGE_CODE}); выполняется резервная локальная сборка по настройке UPDATE_ALLOW_BUILD=1"; UPD_MODE_USED=build
      build_images || stop_update "$STAGE_CODE" "Сборка образов не удалась"
    else stop_update "$STAGE_CODE" "Не удалось получить образы ${IMAGE_REPO}-*:${IMAGE_TAG}"; fi
  fi
else build_images || stop_update "$STAGE_CODE" "Сборка образов не удалась"; fi
for svc in backend web; do docker image inspect "${IMAGE_REPO}-${svc}:${IMAGE_TAG}" >/dev/null 2>&1 || stop_update image_missing "Образ ${IMAGE_REPO}-${svc}:${IMAGE_TAG} не найден после загрузки"; done
action_log "образы получены: ${IMAGE_REPO}-*:${IMAGE_TAG} ($UPD_MODE_USED)"
env_put IMAGE_TAG "$IMAGE_TAG"; env_put IMAGE_REPO "$IMAGE_REPO"
step "Остановка приложения и резервная копия базы и .env"
marker_set stage stopped
dc up -d postgres >/dev/null && wait_healthy 120 postgres || stop_update generic "PostgreSQL не запустился"
dc stop backend worker >/dev/null 2>&1 || true            # после копии в базу никто не пишет: восстановление при ошибке — без потери данных
action_log "приложение остановлено на время резервной копии и миграций"
cp -p "$ENV_FILE" "$ENV_FILE.backup-$(date +%Y%m%d-%H%M%S)" && chmod 600 "$ENV_FILE".backup-* 2>/dev/null
run_guarded "резервная копия" "$T_BACKUP" "$T_BACKUP" "$REPO_ROOT/scripts/backup.sh" --env "$ENV_FILE" --label "pre-${OLD_VER}" || stop_update "$(guard_fail_code generic)" "Резервная копия не создана — миграции без неё не выполняются"
BACKUP="$(ls -1t "${BACKUP_DIR:-$DATA_ROOT/backups}"/*-db-*-pre-"${OLD_VER}".dump 2>/dev/null | head -1)"
[ -s "$BACKUP" ] || stop_update generic "Файл резервной копии не найден после backup.sh"
marker_set backup "$BACKUP"; marker_set stage backup_done
action_log "резервная копия базы: $(basename "$BACKUP")"
step "Миграции внутренней базы (Alembic)"
marker_set stage migrating
REV_BEFORE="$(dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '[:space:]')"
if ! run_guarded "миграции" "$T_MIG" "$T_MIG" "${DCB[@]}" run --rm --no-deps backend alembic upgrade head; then
  kill_oneoff
  stop_update "$([ "$GUARD_REASON" = ok ] && echo migration || guard_fail_code migration)" "Миграция не выполнена (ревизия до попытки: ${REV_BEFORE:-?})"
fi
step "Запуск и проверка работоспособности"
marker_set stage deploying
run_guarded "запуск сервисов" "$T_UP" "$T_UP" "${DCB[@]}" up -d || stop_update "$(guard_fail_code health)" "docker compose up не выполнен"
wait_healthy "$WAIT" backend web || stop_update health "Сервисы не стали работоспособными"
curl -fsS -m 15 "http://${WEB_BIND_ADDR}:${WEB_PORT}/api/v1/health/ready" >/dev/null || stop_update health "Приложение не отвечает на /api/v1/health/ready"
RUN_VER="$(curl -fsS -m 15 "http://${WEB_BIND_ADDR}:${WEB_PORT}/api/v1/version" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ "$RUN_VER" = "$NEW_VER" ] || warn "Работающая версия ($RUN_VER) отличается от целевой ($NEW_VER)"
marker_set healthy_seen 1; marker_set stage verified
step "Очистка старых образов проекта"
marker_set stage cleanup
cleanup_images "${IMAGE_REPO}:${IMAGE_TAG}" "${OLD_REPO}:${OLD_TAG}"
step "Помощник обновлений"
"$REPO_ROOT/scripts/updater.sh" sync-unit --env "$ENV_FILE" 2>&1 | sed 's/^/  /' || true
step "Отчёт"
printf '%s old=%s new=%s image_tag=%s\n' "$(date -Is)" "$OLD_VER" "$NEW_VER" "$IMAGE_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$NEW_VER"; state_set current_commit "$APP_GIT_COMMIT"; state_set current_tag "$IMAGE_TAG"; state_set result ok
history_append update ok "$OLD_VER" "$NEW_VER"
report_write ok "готово" "$OLD_VER" "$NEW_VER" "Откат на $OLD_VER: Администрирование → Обновления или sudo ./scripts/rollback.sh" ""
marker_clear
ok "Обновление выполнено: $OLD_VER → $NEW_VER (образы ${IMAGE_REPO}:${IMAGE_TAG}, $UPD_MODE_USED). Откат: scripts/rollback.sh"
