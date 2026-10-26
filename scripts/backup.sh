#!/usr/bin/env bash
# backup.sh — резервная копия внутренней базы KAV Checker (pg_dump, custom format) и .env. Подготовленные данные зон (таблицы zc_*, сотни мегабайт на крупных источниках) в копию не входят:
# они производные от KSC и восстанавливаются расчётом (worker запускает его сам, если данных нет).
#   scripts/backup.sh [--env FILE] [--keep N] [--label ТЕКСТ]
# Результат: ${BACKUP_DIR:-$DATA_ROOT/backups}/<проект>-db-<время>[-label].dump и <проект>-env-<время>.bak (600). Хранятся N последних (по умолчанию 14).
# Базы KSC не затрагиваются.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
KEEP=14; LABEL=""
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --keep) KEEP="$2"; shift 2 ;; --label) LABEL="-$2"; shift 2 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT POSTGRES_USER POSTGRES_DB
BACKUP_DIR="${BACKUP_DIR:-$DATA_ROOT/backups}"; mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR" 2>/dev/null || true
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/${COMPOSE_PROJECT_NAME}-db-${TS}${LABEL}.dump"
[ "$(svc_state postgres)" != missing ] || die "Контейнер postgres не запущен"
dc exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --exclude-table-data='zc_*' > "$OUT.tmp" && mv "$OUT.tmp" "$OUT" && chmod 600 "$OUT"
cp -p "$ENV_FILE" "$BACKUP_DIR/${COMPOSE_PROJECT_NAME}-env-${TS}.bak" && chmod 600 "$BACKUP_DIR/${COMPOSE_PROJECT_NAME}-env-${TS}.bak"
ok "Резервная копия: $OUT ($(du -h "$OUT" | cut -f1)); копия .env рядом (содержит секреты, права 600)"
ls -1t "$BACKUP_DIR"/${COMPOSE_PROJECT_NAME}-db-*.dump 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
ls -1t "$BACKUP_DIR"/${COMPOSE_PROJECT_NAME}-env-*.bak 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
backups_json 2>/dev/null || true
