#!/usr/bin/env bash
# update-core.sh — выполнение обновления. Не запускается напрямую: scripts/update.sh (стабильная «пусковая» часть) получает теги, распаковывает каталог scripts/ ЦЕЛЕВОГО релиза
# из git и запускает его update-core.sh, поэтому обновление всегда исполняет логику нового релиза, а не установленной (возможно, старой или с дефектами) версии.
#   update-core.sh --target-tag vX.Y.Z [--env FILE] [--build] [--yes] [--dry-run] [--skip-preflight]
# Основной способ — готовые образы релиза из реестра (ghcr.io): Docker Hub, npm и pip не нужны. Локальная сборка — ТОЛЬКО по явному выбору: --build, UPDATE_MODE=build или кнопка
# «Собрать локально»; скрытого перехода на сборку при недоступном реестре нет.
# По порядку: проверки → код на тег → образы → остановка и резервная копия базы и .env → миграции → запуск и проверка → очистка старых образов → помощник обновлений → отчёт
# $DATA_ROOT/updater/report.json. У каждой сетевой операции и сборки свой тайм-аут и контроль прогресса (UPD_TIMEOUT_*, UPD_STALL_*).
# Ошибка на любом этапе: возвращается прежняя версия (при необходимости база — из копии, если схема несовместима); причина с советом — в report.json и журнале. Прерванное обновление
# (перезагрузка, остановка помощника) обрабатывает scripts/recover.sh по метке $DATA_ROOT/state/update.inprogress. Данные, отчёты, настройки и секреты не затрагиваются.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
TARGET_TAG=""; BUILD=0; YES=0; WAIT="${UPD_WAIT_HEALTH:-180}"; SKIP_PF=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --target-tag) TARGET_TAG="$2"; shift 2 ;; --build) BUILD=1; shift ;; --yes|-y) YES=1; shift ;; --dry-run) DRY_RUN=1; shift ;;
  --wait) WAIT="$2"; shift 2 ;; --skip-preflight) SKIP_PF=1; shift ;; -h|--help) sed -n '2,10p' "$0"; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
T_NET="${UPD_TIMEOUT_NET:-60}"; T_PULL="${UPD_TIMEOUT_PULL:-1800}"; S_PULL="${UPD_STALL_PULL:-300}"; T_BUILD="${UPD_TIMEOUT_BUILD:-2400}"; S_BUILD="${UPD_STALL_BUILD:-900}"
T_MIG="${UPD_TIMEOUT_MIGRATE:-600}"; T_BACKUP="${UPD_TIMEOUT_BACKUP:-900}"; T_UP="${UPD_TIMEOUT_UP:-300}"
STEP=0; STEPS=11; CUR="init"; STAGE_CODE=generic
step() { STEP=$((STEP + 1)); CUR="$1"; log; log "[$STEP/$STEPS] $1"; }
OLD_VER="$(installed_version)"; PREV_HEAD="$(installed_head "$OLD_VER")"; START_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)"; OLD_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=12 "$PREV_HEAD" 2>/dev/null || echo unknown)"; OLD_TAG="${IMAGE_TAG:-}"; OLD_REPO="${IMAGE_REPO:-kavcheck}"
NEW_VER="?"; MARKED=0; UPD_MODE_USED=""
if [ "$DRY_RUN" != 1 ]; then
  # прерванное прежнее обновление (перезагрузка, Ctrl-C) обрабатывается до нового: сначала возвращается работоспособное состояние
  [ -e "$(marker_file)" ] && { warn "Найдено прерванное обновление — сначала проверяю и восстанавливаю состояние"; "$SCRIPTS_DIR/recover.sh" --env "$ENV_FILE" || die "Восстановление не завершено: устраните причину и повторите (scripts/recover.sh)"; }
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
log "Проект $COMPOSE_PROJECT_NAME · работает версия $OLD_VER (commit $OLD_COMMIT; извлечённый код: $(version_file_read)) · образы ${OLD_REPO}:${OLD_TAG}"
log "Скрипты обновления: $SCRIPTS_DIR (версия целевого релиза)"
if [ "$BUILD" -eq 1 ] || [ "$(update_mode)" = build ]; then UPD_MODE_USED=build; else UPD_MODE_USED=pull; fi
if [ "$UPD_MODE_USED" = pull ]; then log "Способ: готовые образы из реестра $(registry_repo) (локальная сборка не используется)"
else log "Способ: локальная сборка образов (запрошена явно)"; fi
step "Целевой релиз"
[ -n "$TARGET_TAG" ] || stop_update generic "Не указан целевой релиз"
git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$TARGET_TAG" >/dev/null || stop_update generic "Тег $TARGET_TAG не найден"
NEW_VER="${TARGET_TAG#v}"
log "Целевой релиз: $TARGET_TAG"
step "Проверки перед обновлением"
if [ "$SKIP_PF" -eq 1 ]; then warn "Проверки пропущены (--skip-preflight)"; else
  PF_MODE=$UPD_MODE_USED preflight "$TARGET_TAG" || {
    code=generic
    pf_failed registry && { [[ "$PF_ITEMS" == *'"key":"registry","status":"fail","message":"Образов'* ]] && code=image_missing || code=registry; }
    pf_failed docker_hub && code=docker_hub; pf_failed npm && code=npm; { pf_failed disk_docker || pf_failed disk_data; } && code=disk
    stop_update "$code" "Проверки перед обновлением не пройдены — ничего не изменено"
  }
fi
if [ "$DRY_RUN" = 1 ]; then info "[dry-run] дальше: checkout $TARGET_TAG → образы ($UPD_MODE_USED) → остановка → резервная копия → миграции → запуск → проверка → очистка"; exit 0; fi
if [ "$YES" -ne 1 ]; then if [ -t 0 ]; then read -r -p "Обновить $OLD_VER → $NEW_VER? [y/N] " a; [ "$a" = y ] || die "Отменено."; else die "Нет терминала: добавьте --yes"; fi; fi
for kv in "pid=$$" "started=$(date +%s)" "old_ver=$OLD_VER" "new_ver=$NEW_VER" "old_tag=$OLD_TAG" "old_repo=$OLD_REPO" "prev_head=$PREV_HEAD" "start_head=$START_HEAD" "stage=prepare" "mode=$UPD_MODE_USED" "target=$TARGET_TAG"; do marker_set "${kv%%=*}" "${kv#*=}"; done
MARKED=1
step "Переход кода на $TARGET_TAG"
marker_set stage code
mirror_local_fix
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then git -C "$REPO_ROOT" stash push -q -m "update-$(date +%s)" && action_log "прочие локальные изменения файлов проекта сохранены в git stash"; fi
git -C "$REPO_ROOT" checkout -q --detach "$TARGET_TAG" || stop_update generic "git checkout $TARGET_TAG не удался"
host_version_info
state_set previous_version "$OLD_VER"; state_set previous_commit "$OLD_COMMIT"; state_set previous_tag "$OLD_TAG"; state_set previous_head "$PREV_HEAD"; state_set previous_start "$START_HEAD"; state_set previous_repo "$OLD_REPO"
step "Образы релиза: $([ "$UPD_MODE_USED" = pull ] && echo "загрузка готовых образов" || echo "локальная сборка")"
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
  pick_npm_registries; pick_pip_indexes          # реальная проверка источников зависимостей: порядок — исправные первыми; всё ограничено по времени и числу попыток
  export NPM_REGISTRIES PIP_INDEX_URLS
  export IMAGE_REPO="$(local_build_repo)" IMAGE_TAG="$APP_GIT_COMMIT"
  run_guarded "сборка образов" "$T_BUILD" "$S_BUILD" "${DCB[@]}" build && return 0
  kill_oneoff; STAGE_CODE="$(guard_fail_code build)"; return 1
}
if [ "$UPD_MODE_USED" = pull ]; then get_images || stop_update "$STAGE_CODE" "Не удалось получить образы ${IMAGE_REPO}-*:${IMAGE_TAG}"
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
run_guarded "резервная копия" "$T_BACKUP" "$T_BACKUP" "$SCRIPTS_DIR/backup.sh" --env "$ENV_FILE" --label "pre-${OLD_VER}" || stop_update "$(guard_fail_code generic)" "Резервная копия не создана — миграции без неё не выполняются"
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
"$SCRIPTS_DIR/updater.sh" sync-unit --env "$ENV_FILE" 2>&1 | sed 's/^/  /' || true
"$SCRIPTS_DIR/updater.sh" refresh --env "$ENV_FILE" 2>&1 | sed 's/^/  /' || true      # служба помощника перезапускается на новом коде после завершения обновления
step "Отчёт"
printf '%s old=%s new=%s image_tag=%s\n' "$(date -Is)" "$OLD_VER" "$NEW_VER" "$IMAGE_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$NEW_VER"; state_set current_commit "$APP_GIT_COMMIT"; state_set current_tag "$IMAGE_TAG"; state_set result ok
history_append update ok "$OLD_VER" "$NEW_VER"
report_write ok "готово" "$OLD_VER" "$NEW_VER" "Откат на $OLD_VER: Администрирование → Обновления или sudo ./scripts/rollback.sh" ""
marker_clear
ok "Обновление выполнено: $OLD_VER → $NEW_VER (образы ${IMAGE_REPO}:${IMAGE_TAG}, $UPD_MODE_USED). Откат: scripts/rollback.sh"
