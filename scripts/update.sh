#!/usr/bin/env bash
# update.sh — обновление установленного KAV Checker до релиза из GitHub (пусковая часть; логика — scripts/update-core.sh ЦЕЛЕВОГО релиза).
#   scripts/update.sh [--env FILE] [--to vX.Y.Z] [--build] [--yes] [--dry-run] [--skip-preflight]
# Почему так: если бы обновление исполняло скрипты установленной версии, то любой дефект старой версии (выбор сборки вместо готовых образов, замирающий пульс помощника)
# повторялся бы при каждом обновлении и исправления нового релиза до него не доходили. Поэтому эта часть минимальна и стабильна: получает теги, распаковывает scripts/ выбранного
# тега из git в $DATA_ROOT/state/run/ (копия не меняется при переходе кода на тег) и передаёт управление update-core.sh из этой копии. Подробности — update-core.sh и docs/UPDATE_AND_BACKUP.md.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
TO=""; ARGS=(); EARLY=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; ARGS+=("$1" "$2"); shift 2 ;; --to) TO="$2"; shift 2 ;; -h|--help) sed -n '2,7p' "$0"; exit 0 ;; *) ARGS+=("$1"); shift ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT POSTGRES_USER POSTGRES_DB
command -v git >/dev/null || die "git не найден"; git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 || die "$REPO_ROOT не git-репозиторий"
log; log "[0/11] Получение списка релизов"
GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30 timeout "${UPD_TIMEOUT_NET:-60}" git -C "$REPO_ROOT" fetch --tags --prune -q origin 2>/dev/null || warn "git fetch не удался (нет доступа к GitHub?) — используются уже полученные теги"
[ -n "$TO" ] || TO="$(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"
[ -n "$TO" ] || die "Релизных тегов vX.Y.Z нет: обновляться не на что"
git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$TO" >/dev/null || die "Тег $TO не найден"
RUN="$DATA_ROOT/state/run/$(date +%Y%m%d-%H%M%S)-$TO"
mkdir -p "$RUN" && git -C "$REPO_ROOT" archive "$TO" scripts | tar -x -C "$RUN" 2>/dev/null
if [ -x "$RUN/scripts/update-core.sh" ]; then
  log "Выполняю логику релиза $TO (скрипты распакованы в $RUN/scripts)"
  ls -1dt "$DATA_ROOT"/state/run/*/ 2>/dev/null | tail -n +4 | xargs -r rm -rf          # хранятся копии трёх последних запусков
  KC_REPO_ROOT="$REPO_ROOT" exec "$RUN/scripts/update-core.sh" --target-tag "$TO" "${ARGS[@]}"
fi
die "Релиз $TO не содержит update-core.sh (он старше схемы обновления): обновление до него этим помощником не поддерживается"
