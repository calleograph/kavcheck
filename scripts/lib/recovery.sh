#!/usr/bin/env bash
# Восстановление после неудачного или прерванного обновления. Решение принимается по этапу из метки $DATA_ROOT/state/update.inprogress (её ведёт update.sh):
#   prepare|code|images   контейнеры не трогали → вернуть код и .env, прежняя версия работает;
#   stopped|backup_done   приложение остановлено, база не менялась → вернуть код и запустить прежнюю версию;
#   migrating             миграция могла частично выполниться, но после копии в базу никто не писал → база из копии, затем прежняя версия;
#   deploying             новая версия запускалась: если она уже работала (healthy_seen) — оставить и завершить; если нет — база из копии и прежняя версия;
#   verified|cleanup      новая версия проверена → считать обновление выполненным.
# Результат в RECOVER_RESULT: rolled_back | finalized | manual (нужно вмешательство; автоматически ничего опасного не делается).
RECOVER_RESULT=""; RECOVER_ADVICE=""; RECOVER_SCHEMA=""
recover_start_old() { # вернуть код, .env и запустить контейнеры прежней версии
  local old_tag old_repo prev_head code_head
  old_tag="$(marker_get old_tag)"; old_repo="$(marker_get old_repo)"; prev_head="$(marker_get prev_head)"; code_head="$(marker_get start_head)"; code_head="${code_head:-$prev_head}"
  [ -n "$old_tag" ] && [ -n "$prev_head" ] || return 1
  # прежняя версия не должна запускаться на несовместимой схеме базы: ревизия базы должна быть известна её миграциям
  dc up -d postgres >/dev/null 2>&1 && wait_healthy 90 postgres
  local dbrev; dbrev="$(dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '[:space:]')"
  if [ -n "$dbrev" ] && ! git -C "$REPO_ROOT" grep -q "revision = \"$dbrev\"" "$prev_head" -- backend/migrations/versions 2>/dev/null; then
    RECOVER_SCHEMA="$dbrev"; return 3
  fi
  # код возвращается к тому состоянию, в котором был до обновления (в нём могут быть свежие скрипты), а не к тегу прежней версии: иначе следующее обновление запустит устаревшие скрипты
  [ "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" = "$code_head" ] || git -C "$REPO_ROOT" checkout -q --detach "$code_head" || return 1
  export IMAGE_TAG="$old_tag" IMAGE_REPO="$old_repo"
  env_put IMAGE_TAG "$old_tag"; env_put IMAGE_REPO "$old_repo"
  dc up -d >/dev/null 2>&1 && wait_healthy 180 backend web
}
recover_update() { # recover_update — после неудачи или прерывания обновления
  local stage backup; stage="$(marker_get stage)"; backup="$(marker_get backup)"; stage="${stage:-prepare}"
  local old_ver new_ver; old_ver="$(marker_get old_ver)"; new_ver="$(marker_get new_ver)"
  action_log "восстановление после сбоя: этап «$stage»"
  case "$stage" in
    verified|cleanup)
      RECOVER_RESULT=finalized; RECOVER_ADVICE="Новая версия $new_ver проверена и работает; прерван был только заключительный этап (очистка)." ;;
    deploying)
      if [ "$(marker_get healthy_seen)" = 1 ]; then
        dc up -d >/dev/null 2>&1; wait_healthy 120 backend web
        RECOVER_RESULT=finalized; RECOVER_ADVICE="Новая версия $new_ver уже работала до прерывания; данные не откатывались."
      else
        if [ -n "$backup" ] && restore_db_exact "$backup" && recover_start_old; then RECOVER_RESULT=rolled_back; RECOVER_ADVICE="Новая версия не успела заработать: база возвращена к копии, работает прежняя версия $old_ver."
        else RECOVER_RESULT=manual; RECOVER_ADVICE="Автоматический возврат не удался: восстановите копию (scripts/restore.sh ${backup:-<копия>}) и выполните scripts/rollback.sh. Повторное обновление автоматически не запускается."; fi
      fi ;;
    migrating)
      if [ -n "$backup" ] && restore_db_exact "$backup" && recover_start_old; then RECOVER_RESULT=rolled_back; RECOVER_ADVICE="Миграция была прервана: база возвращена к копии перед обновлением, работает прежняя версия $old_ver."
      else RECOVER_RESULT=manual; RECOVER_ADVICE="Миграция прервана, а база не восстановлена автоматически: выполните scripts/restore.sh ${backup:-<копия>}, затем scripts/rollback.sh. Повторное обновление автоматически не запускается."; fi ;;
    *)
      recover_start_old; local rc=$?
      if [ "$rc" -eq 0 ]; then RECOVER_RESULT=rolled_back; RECOVER_ADVICE="Работает прежняя версия $old_ver; данные не менялись."
      elif [ "$rc" -eq 3 ]; then RECOVER_RESULT=manual; RECOVER_ADVICE="База данных уже на ревизии $RECOVER_SCHEMA, которой не знает прежняя версия $old_ver: запускать её небезопасно. Восстановите копию, снятую перед обновлением (${backup:-см. DATA_ROOT/backups}): scripts/restore.sh, затем scripts/rollback.sh."
      else RECOVER_RESULT=manual; RECOVER_ADVICE="Прежняя версия не запущена автоматически: выполните sudo ./scripts/rollback.sh или ./scripts/ctl.sh up."; fi ;;
  esac
}
