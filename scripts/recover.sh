#!/usr/bin/env bash
# recover.sh — проверка и восстановление после прерванного обновления (перезагрузка сервера, остановка помощника, зависший и остановленный update.sh).
#   scripts/recover.sh [--env FILE]
# Читает метку $DATA_ROOT/state/update.inprogress, проверяет фактическое состояние (версия, образы, контейнеры, база) и безопасно возвращает работоспособную версию:
# прежнюю — если новая не успела заработать, новую — если она уже работала. Повторное обновление автоматически не запускается. Помощник вызывает скрипт при каждом старте.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT POSTGRES_USER POSTGRES_DB
[ -f "$(marker_file)" ] || { info "Незавершённых обновлений нет"; exit 0; }
pid="$(marker_get pid)"
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q 'update\.sh'; then info "Обновление ещё выполняется (pid $pid)"; exit 0; fi
mkdir -p "$DATA_ROOT/state"; exec 8>"$DATA_ROOT/state/update.lock"; flock -w 60 8 || { info "Идёт другая операция обновления"; exit 0; }       # ждём, пока завершится только что остановленный процесс
OLD_VER="$(marker_get old_ver)"; NEW_VER="$(marker_get new_ver)"; STAGE="$(marker_get stage)"; UPD_MODE_USED="$(marker_get mode)"
warn "Найдено прерванное обновление $OLD_VER → $NEW_VER (этап «$STAGE»): проверяю фактическое состояние"
recover_update
case "$RECOVER_RESULT" in
  finalized)
    run_ver="$(curl -fsS -m 15 "http://${WEB_BIND_ADDR:-127.0.0.1}:${WEB_PORT:-8080}/api/v1/version" 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
    state_set current_version "${run_ver:-$NEW_VER}"; state_set current_tag "$(marker_get target)"; state_set result recovered_ok
    history_append update recovered "$OLD_VER" "$NEW_VER" "$STAGE"
    report_write recovered "восстановление после прерывания" "$OLD_VER" "$NEW_VER" "$RECOVER_ADVICE" "${KC_RECOVER_CODE:-interrupted}"
    marker_clear; ok "$RECOVER_ADVICE" ;;
  rolled_back)
    state_set current_version "$OLD_VER"; state_set result recovered_rolled_back
    history_append update recovered "$OLD_VER" "$NEW_VER" "$STAGE"
    report_write recovered "восстановление после прерывания" "$OLD_VER" "$NEW_VER" "$RECOVER_ADVICE $(diag_advice "${KC_RECOVER_CODE:-interrupted}")" "${KC_RECOVER_CODE:-interrupted}"
    marker_clear; ok "$RECOVER_ADVICE" ;;
  *)
    state_set result recovery_manual
    history_append update failed "$OLD_VER" "$NEW_VER" "$STAGE"
    report_write failed "восстановление после прерывания" "$OLD_VER" "$NEW_VER" "$RECOVER_ADVICE" "${KC_RECOVER_CODE:-interrupted}"
    marker_clear; fail "$RECOVER_ADVICE"; exit 2 ;;
esac
