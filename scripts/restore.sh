#!/usr/bin/env bash
# restore.sh — восстановление внутренней базы из резервной копии (pg_restore). Приложение останавливается на время восстановления.
#   scripts/restore.sh <файл.dump> [--env FILE] [--yes]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
FILE=""; YES=0
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --yes|-y) YES=1; shift ;; *) FILE="$1"; shift ;; esac; done
[ -f "$FILE" ] || die "Укажите файл резервной копии (.dump)"
load_env; validate_project_name; require_vars POSTGRES_USER POSTGRES_DB
if [ "$YES" -ne 1 ]; then read -r -p "Восстановить базу из $FILE? Текущие данные будут ЗАМЕНЕНЫ. [y/N] " a; [ "$a" = y ] || die "Отменено."; fi
dc stop backend worker >/dev/null
dc up -d postgres >/dev/null; wait_healthy 60 postgres
dc exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --no-privileges < "$FILE" || warn "pg_restore сообщил об ошибках (часто безобидны при --clean)"
dc up -d >/dev/null
ok "База восстановлена из $FILE; сервисы запущены."
