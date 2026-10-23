#!/usr/bin/env bash
# rollback.sh — возврат кода и образов к предыдущей рабочей версии (после scripts/update.sh), без пересборки.
#   scripts/rollback.sh [--env FILE] [--yes]
# Откат кода ≠ откат базы: если схема внутренней базы изменилась новой миграцией, скрипт останавливается и предлагает восстановить резервную копию (scripts/restore.sh).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
YES=0; SKIP_SCHEMA=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --yes|-y) YES=1; shift ;; --skip-schema-check) SKIP_SCHEMA=1; shift ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
PREV_HEAD="$(state_get previous_head)"; PREV_TAG="$(state_get previous_tag)"; PREV_VER="$(state_get previous_version)"; CUR_VER="$(version_file_read)"
[ -n "$PREV_HEAD" ] && [ -n "$PREV_TAG" ] || die "Нет сведений о предыдущей версии (обновление ещё не выполнялось)"
log "Откат: $CUR_VER → ${PREV_VER:-?} (образы ${IMAGE_REPO}:${PREV_TAG})"
for svc in backend web; do docker image inspect "${IMAGE_REPO}-${svc}:${PREV_TAG}" >/dev/null 2>&1 || die "Образ ${IMAGE_REPO}-${svc}:${PREV_TAG} не найден — откат без пересборки невозможен; обновитесь до исправленной версии"; done
# совместимость схемы: ревизия базы должна быть известна коду предыдущей версии
DBREV="$(dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '[:space:]')"
if [ "$SKIP_SCHEMA" -eq 0 ] && [ -n "$DBREV" ] && ! git -C "$REPO_ROOT" grep -q "revision = \"$DBREV\"" "$PREV_HEAD" -- backend/migrations/versions 2>/dev/null; then
  fail "База на ревизии $DBREV, неизвестной предыдущей версии. Сначала восстановите резервную копию, снятую перед обновлением: scripts/restore.sh $(ls -1t "${BACKUP_DIR:-$DATA_ROOT/backups}"/*pre-*.dump 2>/dev/null | head -1), затем повторите откат."
  history_append rollback failed "$CUR_VER" "$PREV_VER" "schema"; exit 3
fi
if [ "$YES" -ne 1 ]; then read -r -p "Откатить код и образы? [y/N] " a; [ "$a" = y ] || die "Отменено."; fi
git -C "$REPO_ROOT" checkout -q --detach "$PREV_HEAD" || die "git checkout не удался"
export IMAGE_TAG="$PREV_TAG"
sed -i "s#^IMAGE_TAG=.*#IMAGE_TAG=$PREV_TAG#" "$ENV_FILE"
dc up -d || die "docker compose up не выполнен"
wait_healthy 180 backend web || { history_append rollback failed "$CUR_VER" "$PREV_VER" "health"; die "После отката сервисы не работоспособны"; }
printf '%s ROLLBACK from=%s to=%s image_tag=%s\n' "$(date -Is)" "$CUR_VER" "$PREV_VER" "$PREV_TAG" >> "$DATA_ROOT/state/deploy-history.log"
state_set current_version "$PREV_VER"; state_set current_tag "$PREV_TAG"; state_set result "rolled_back"
history_append rollback ok "$CUR_VER" "$PREV_VER"
ok "Откат выполнен: работает версия ${PREV_VER}."
