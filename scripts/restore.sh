#!/usr/bin/env bash
# restore.sh — восстановление внутренней базы из резервной копии (pg_restore) в ЧИСТУЮ базу. Приложение останавливается на время восстановления.
#   scripts/restore.sh <файл.dump> [--env FILE] [--yes]
# Порядок: копия текущей базы (метка pre-restore) → текущая база переименовывается в <имя>_before_restore_<время> (сохраняется для разбора) →
# создаётся пустая база, в неё восстанавливается копия → при ошибке всё возвращается как было. Хранятся две последние отложенные базы.
# Восстановление поверх существующей базы (pg_restore --clean) не используется: таблицы более новой версии мешают удалить старые, и база получается смешанной.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
FILE=""; YES=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --yes|-y) YES=1; shift ;; *) FILE="$1"; shift ;; esac; done
[ -f "$FILE" ] || die "Укажите файл резервной копии (.dump)"
load_env; validate_project_name; require_vars POSTGRES_USER POSTGRES_DB DATA_ROOT
take_lock
if [ "$YES" -ne 1 ]; then read -r -p "Восстановить базу из $FILE? Текущие данные будут ЗАМЕНЕНЫ (прежняя база сохранится под другим именем). [y/N] " a; [ "$a" = y ] || die "Отменено."; fi
action_reset
dc up -d postgres >/dev/null; wait_healthy 60 postgres
"$SCRIPTS_DIR/backup.sh" --env "$ENV_FILE" --label pre-restore >/dev/null && ok "Перед восстановлением снята копия текущей базы (метка pre-restore)" || die "Не удалось снять копию текущей базы — восстановление не начато"
restore_db_exact "$FILE" before_restore || { dc up -d >/dev/null; die "Восстановление не выполнено; база оставлена как была, сервисы запущены"; }
# старые отложенные базы: оставить две последние каждого вида
for kind in before_restore failed; do
  dc exec -T postgres psql -U "$POSTGRES_USER" -d postgres -tAc "SELECT datname FROM pg_database WHERE datname LIKE '${POSTGRES_DB}\\_${kind}\\_%' ORDER BY datname DESC OFFSET 2" 2>/dev/null \
    | tr -d '\r' | while read -r old; do [ -n "$old" ] && dc exec -T postgres psql -U "$POSTGRES_USER" -d postgres -tAc "DROP DATABASE \"$old\"" >/dev/null 2>&1 && info "Удалена старая отложенная база $old"; done
done
dc up -d >/dev/null
ok "База восстановлена из $FILE; сервисы запущены. Прежняя база сохранена (см. журнал выше)."
