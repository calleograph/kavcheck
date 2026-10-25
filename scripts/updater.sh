#!/usr/bin/env bash
# updater.sh — «помощник» обновлений для веб-интерфейса (Администрирование → Обновления).
#   scripts/updater.sh run [--env FILE]           # работает постоянно (служба systemd от root)
#   scripts/updater.sh check [--env FILE]         # разовая проверка релизов GitHub → remote.json
#   scripts/updater.sh install [--env FILE] [--yes] | uninstall | status | print-unit
# Контейнер backend не имеет доступа к Docker и git хоста. Веб-интерфейс кладёт запрос в $DATA_ROOT/updater/request.txt (простые строки key=value),
# помощник выполняет ТОЛЬКО фиксированный набор: check | preflight | update [target=vX.Y.Z] | rollback | backup | restore [target=имя копии]. Произвольные команды выполнить нельзя.
# Файлы обмена: request.txt (из веб-интерфейса), status.json, remote.json, backups.json, update.log (последнее обновление/откат/восстановление; предыдущее —
# update.prev.log), backup.log, history.ndjson, preflight.json, report.json, system.json (образы проекта, место на дисках, размер резервных копий — раз в 5 минут).
# Надёжность: служба systemd с Restart=always без предела перезапусков; при старте обрабатывается прерванное обновление (scripts/recover.sh); зависшее действие
# (общий тайм-аут UPD_TIMEOUT_TOTAL или нет вывода UPD_STALL_TOTAL) останавливается вместе с дочерними процессами, затем выполняется восстановление; после обновления
# помощник сам перезапускается на новом коде, а файл службы обновляется (sync-unit).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
CMD="${1:-run}"; [ $# -gt 0 ] && shift
UPDATER_API=3
YES=0; INTERVAL=3; CHECK_EVERY="${UPDATER_CHECK_EVERY:-3600}"
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --yes|-y) YES=1; shift ;; --interval) INTERVAL="$2"; shift 2 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
CH="$DATA_ROOT/updater"; LOG="$CH/update.log"; UNIT="kavcheck-updater-${COMPOSE_PROJECT_NAME}"; UNIT_FILE="/etc/systemd/system/$UNIT.service"
[ "$(id -u)" -eq 0 ] && export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$REPO_ROOT"
mkdir -p "$CH" && chmod 1777 "$CH" 2>/dev/null
jesc() { printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\t\r' '  ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
atomic() { local tmp; tmp="$(mktemp "$CH/.w.XXXXXX")" && cat > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1"; }
STATE=idle; ACTION=""; REQ=""; STEP_NO=0; STEP_TOTAL=11; STEP_NAME=""; STARTED=0; FINISHED=0; EXIT=null; RESULT=""; BY=""; TARGET=""; LAST_OUT=0; MODE=""; OP_ID=""; OP_PID=0
BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"; SELF_SHA="$(sha256sum "$SCRIPTS_DIR/updater.sh" 2>/dev/null | cut -d' ' -f1)"; UP_SINCE="$(date +%s)"; HB_PID=0
# Три независимые сведения (интерфейс не должен смешивать их):
#  1) heartbeat.json — «помощник жив»: пишет отдельный фоновый цикл раз в 4 с, не зависит от того, чем занят основной цикл (долгая сборка, сетевой вызов, ожидание);
#  2) operation.json — что делает помощник: идентификатор операции, этап, фаза, время последнего вывода, результат (status.json — та же запись для совместимости);
#  3) состояние процесса операции — op_alive в heartbeat.json (kill -0 по pid из .op.pid), а не наличие файла блокировки.
phase_of() { # фаза по названию этапа — для интерфейса
  case "$1" in *"загрузка готовых образов"*) echo pulling ;; *"локальная сборка"*) echo building ;; *"езервн"*) echo backup ;; *"игра"*) echo migrating ;; *"апуск и проверка"*) echo restarting ;; *"роверки"*) echo preflight ;; *"Очистка"*) echo cleanup ;; *"Помощник"*) echo helper ;; *"Отчёт"*) echo report ;; *"Переход кода"*) echo code ;; *) echo "" ;; esac
}
write_status() { printf '{"ts":%s,"pid":%s,"updater_api":%s,"op_id":"%s","state":"%s","action":"%s","request_id":"%s","step_no":%s,"step_total":%s,"step_name":"%s","phase":"%s","started_at":%s,"finished_at":%s,"last_output_at":%s,"exit_code":%s,"result":"%s","by":"%s","target":"%s","mode":"%s","op_pid":%s}\n' \
  "$(date +%s)" "$$" "$UPDATER_API" "$OP_ID" "$STATE" "$ACTION" "$REQ" "$STEP_NO" "$STEP_TOTAL" "$(jesc "$STEP_NAME")" "$(phase_of "$STEP_NAME")" "$STARTED" "$FINISHED" "$LAST_OUT" "$EXIT" "$RESULT" "$(jesc "$BY")" "$(jesc "$TARGET")" "$MODE" "$OP_PID" > "$CH/.op.tmp"
  atomic "$CH/operation.json" < "$CH/.op.tmp"; atomic "$CH/status.json" < "$CH/.op.tmp"; }
write_heartbeat() { # write_heartbeat [остановлена] — пульс помощника
  local alive=false; [ "$(cat "$CH/.op.pid" 2>/dev/null || echo 0)" -gt 0 ] 2>/dev/null && kill -0 "$(cat "$CH/.op.pid")" 2>/dev/null && alive=true
  printf '{"ts":%s,"pid":%s,"updater_api":%s,"boot_id":"%s","started_at":%s,"script_sha":"%s","op_alive":%s,"stopped":%s,"unit":"%s"}\n' "$(date +%s)" "$$" "$UPDATER_API" "$BOOT_ID" "$UP_SINCE" "$SELF_SHA" "$alive" "${1:-false}" "$UNIT" | atomic "$CH/heartbeat.json"; }
hb_loop() { # отдельный процесс-«пульс»: завершается вместе с основным процессом и не держит его блокировку
  local parent="$1"
  while kill -0 "$parent" 2>/dev/null; do write_heartbeat; sleep 4; done
}

do_check() { # релизы GitHub: последний тег vX.Y.Z и описание релиза (через API, если доступен)
  local prev="$STATE" ok=true err="" cur latest notes="" published="" behind=false
  STATE=checking; write_status
  git -C "$REPO_ROOT" fetch --tags --prune -q origin 2>/tmp/kc-fetch.err || { ok=false; err="$(head -c 200 /tmp/kc-fetch.err | tr '\n' ' ')"; }
  cur="$(version_file_read)"; latest="$(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"
  [ -n "$latest" ] || { ok=false; err="${err:-в репозитории нет релизных тегов}"; }
  if [ -n "$latest" ] && [ "$(printf '%s\n%s\n' "${latest#v}" "$cur" | sort -V | tail -1)" != "$cur" ]; then behind=true; fi
  if [ -n "${GITHUB_REPO:-}" ] && [ "$GITHUB_REPO" != "CHANGE_ME_owner/kavcheck" ] && [ -n "$latest" ]; then
    local json; json="$(curl -fsS --max-time 15 -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${latest}" 2>/dev/null || true)"
    [ -n "$json" ] && notes="$(printf '%s' "$json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("body") or "")' 2>/dev/null | head -c 20000)" && published="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("published_at") or "")' 2>/dev/null)"
  fi
  [ -z "$notes" ] && [ -n "$latest" ] && notes="$(git -C "$REPO_ROOT" show "$latest:CHANGELOG.md" 2>/dev/null | awk -v v="${latest#v}" '$0 ~ "^## " && found {exit} $0 ~ "^## .*"v {found=1} found' | head -c 20000)"
  printf '{"checked_at":%s,"ok":%s,"error":"%s","current_version":"%s","latest_version":"%s","latest_tag":"%s","behind":%s,"notes":"%s","published_at":"%s"}\n' \
    "$(date +%s)" "$ok" "$(jesc "$err")" "$cur" "${latest#v}" "$latest" "$behind" "$(jesc "$notes" | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')" "$published" | atomic "$CH/remote.json"
  STATE="$prev"; [ "$STATE" = checking ] && STATE=idle; write_status; [ "$ok" = true ]
}
do_system() { # сведения о сервере для раздела «Состояние системы»: образы этого проекта, место на дисках, резервные копии
  local imgs="" total=0 line name size bytes bdir="${BACKUP_DIR:-$DATA_ROOT/backups}"
  while read -r name size; do
    [ -n "$name" ] || continue
    bytes="$(docker image inspect -f '{{.Size}}' "$name" 2>/dev/null || echo 0)"; total=$((total + bytes))
    imgs="${imgs:+$imgs,}{\"name\":\"$(jesc "$name")\",\"bytes\":$bytes}"
  done < <(docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' 2>/dev/null | grep -E "^${IMAGE_REPO:-kavcheck}-(backend|web):")
  printf '{"checked_at":%s,"images":[%s],"images_bytes":%s,"backups_bytes":%s,"docker_free_bytes":%s,"data_free_bytes":%s,"update_mode":"%s","registry":"%s","allow_build":%s,"npm_mirror":%s,"pip_mirror":%s,"helper_unit":"%s"}\n' "$(date +%s)" "$imgs" "$total" \
    "$(du -sb "$bdir" 2>/dev/null | cut -f1 || echo null)" "$(df -PB1 "$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /)" 2>/dev/null | awk 'NR==2{print $4}')" \
    "$(df -PB1 "$DATA_ROOT" 2>/dev/null | awk 'NR==2{print $4}')" "$(update_mode)" "$(jesc "$(registry_repo)")" "false" "$([ -n "${NPM_REGISTRY:-}" ] && echo true || echo false)" \
    "$([ -n "${PIP_INDEX_URL:-}" ] && echo true || echo false)" "$(if have_systemd; then unit_verify >/dev/null 2>&1 && echo ok || echo incomplete; else echo none; fi)" | atomic "$CH/system.json"
}
# run_action СОСТОЯНИЕ ФАЙЛ_ЖУРНАЛА СКРИПТ АРГУМЕНТЫ… — запуск скрипта в собственной группе процессов с наблюдением: ход этапов из строк «[N/M] …», пульс, общий тайм-аут
# и отсутствие вывода. Зависшее действие останавливается целиком (TERM, затем KILL), после чего scripts/recover.sh проверяет состояние и возвращает рабочую версию.
run_action() {
  local st="$1" logf="$2" script="$3"; shift 3
  local pid rc pos=0 size line t0 now reason="" total="${UPD_TIMEOUT_TOTAL:-5400}" stall="${UPD_STALL_TOTAL:-1500}" v
  local -a pass=()
  # скрипты запускаются в чистом окружении; пробрасываются только настройки прокси и сертификатов и переменные из UPD_PASS_ENV (проверки и нестандартные среды)
  for v in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy SSL_CERT_FILE KC_NO_SYSTEMD $UPD_PASS_ENV; do [ -n "${!v:-}" ] && pass+=("$v=${!v}"); done
  LOG="$logf"; STATE="$st"; STARTED="$(date +%s)"; OP_ID="$STARTED-$REQ"; OP_PID=0; FINISHED=0; EXIT=null; RESULT=""; STEP_NO=0; STEP_NAME="запуск"; LAST_OUT="$STARTED"; write_status
  [ "$logf" = "$CH/update.log" ] && [ -s "$logf" ] && mv -f "$logf" "$CH/update.prev.log"
  : > "$logf"; chmod 644 "$logf"; printf '=== %s запущен %s (запросил: %s) ===\n' "$ACTION" "$(date '+%F %T')" "${BY:-?}" >> "$logf"
  (cd "$REPO_ROOT" && exec setsid env -i PATH="$PATH" HOME="${HOME:-/root}" LANG="${LANG:-C.UTF-8}" ENV_FILE="$ENV_FILE" UPDATE_BY="$BY" GIT_CONFIG_COUNT="${GIT_CONFIG_COUNT:-0}" GIT_CONFIG_KEY_0="${GIT_CONFIG_KEY_0:-}" GIT_CONFIG_VALUE_0="${GIT_CONFIG_VALUE_0:-}" "${pass[@]}" "$REPO_ROOT/scripts/$script" "$@" >>"$logf" 2>&1 9>&- </dev/null) &
  pid=$!; t0="$(date +%s)"; OP_PID="$pid"; echo "$pid" > "$CH/.op.pid"; write_status; write_heartbeat
  while kill -0 "$pid" 2>/dev/null; do
    sleep 2; now="$(date +%s)"; size="$(stat -c %s "$logf" 2>/dev/null || echo 0)"
    if [ "$size" -gt "$pos" ]; then
      while IFS= read -r line; do
        if [[ "$line" =~ ^\[([0-9]+)/([0-9]+)\][[:space:]]+(.*)$ ]]; then STEP_NO="${BASH_REMATCH[1]}"; STEP_TOTAL="${BASH_REMATCH[2]}"; STEP_NAME="${BASH_REMATCH[3]}"; fi
      done < <(tail -c +$((pos + 1)) "$logf" | head -c $((size - pos)))
      pos="$size"; LAST_OUT="$now"
    fi
    write_status
    if [ $((now - t0)) -gt "$total" ]; then reason=timeout_total; break; fi
    if [ $((now - LAST_OUT)) -gt "$stall" ]; then reason=timeout_stall; break; fi
  done
  if [ -n "$reason" ]; then
    printf '=== %s: %s — останавливаю процессы обновления ===\n' "$(date '+%F %T')" "$reason" >> "$logf"
    kill -TERM -- "-$pid" 2>/dev/null; sleep 8; kill -KILL -- "-$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    STEP_NAME="восстановление после остановки"; write_status
    (cd "$REPO_ROOT" && KC_RECOVER_CODE="$reason" timeout 1200 env "${pass[@]}" "$REPO_ROOT/scripts/recover.sh" --env "$ENV_FILE" >>"$logf" 2>&1 9>&-)
    rc=124
  else wait "$pid"; rc=$?; fi
  rm -f "$CH/.op.pid"; OP_PID=0; FINISHED="$(date +%s)"; EXIT="$rc"; STATE=idle; [ "$rc" -eq 0 ] && RESULT=ok || RESULT=failed
  printf '=== %s завершён %s: %s (код %s) ===\n' "$ACTION" "$(date '+%F %T')" "$([ "$rc" -eq 0 ] && echo успешно || echo 'С ОШИБКОЙ')" "$rc" >> "$logf"
  write_status; backups_json 2>/dev/null || true
  return "$rc"
}
handle_request() {
  local f="$CH/request.txt" owner rid action target by at mode
  [ -f "$f" ] || return 0
  owner="$(stat -c %u "$f" 2>/dev/null || echo -1)"
  if [ -L "$f" ] || ! [[ "$owner" =~ ^(0|$(id -u)|10001)$ ]]; then warn "Запрос отклонён: символьная ссылка или посторонний владелец (uid $owner)"; rm -f "$f"; return 0; fi
  mode="$(sed -n 's/^mode=//p' "$f" | head -1)"; rid="$(sed -n 's/^id=//p' "$f" | head -1)"; action="$(sed -n 's/^action=//p' "$f" | head -1)"; target="$(sed -n 's/^target=//p' "$f" | head -1)"; by="$(sed -n 's/^by=//p' "$f" | head -1)"; at="$(sed -n 's/^at=//p' "$f" | head -1)"
  rm -f "$f"
  [[ "$rid" =~ ^[a-f0-9]{8,32}$ ]] && [[ "$at" =~ ^[0-9]+$ ]] || { warn "Запрос отклонён: некорректный формат"; return 0; }
  [ $(( $(date +%s) - at )) -le 600 ] || { warn "Запрос $rid устарел"; return 0; }
  [[ "$by" =~ ^[A-Za-z0-9._-]{0,60}$ ]] || by="?"
  [[ "$mode" =~ ^(pull|build)?$ ]] || { warn "Запрос отклонён: некорректный способ получения образов"; return 0; }
  if [ "$action" = restore ]; then [[ "$target" =~ ^[A-Za-z0-9._-]{1,120}\.dump$ ]] || { warn "Запрос отклонён: некорректное имя резервной копии"; return 0; }
  else [[ "$target" =~ ^(v?[0-9]+\.[0-9]+\.[0-9]+)?$ ]] || { warn "Запрос отклонён: некорректная версия"; return 0; }; fi
  REQ="$rid"; BY="$by"; ACTION="$action"; TARGET="$target"; MODE="$mode"
  case "$action" in
    ping) write_status ;;
    check) do_check || true ;;
    update) run_action updating "$CH/update.log" update.sh --yes --env "$ENV_FILE" ${target:+--to "$target"} $([ "$mode" = build ] && echo --build) || true; do_check || true ;;
    rollback) run_action rolling_back "$CH/update.log" rollback.sh --yes --env "$ENV_FILE" || true ;;
    backup) run_action backing_up "$CH/backup.log" backup.sh --env "$ENV_FILE" || true ;;
    preflight) STATE=checking; write_status; ( PF_MODE="$([ "$mode" = build ] && echo build || update_mode)"; preflight "" ) >/dev/null 2>&1; STATE=idle; write_status ;;
    restore) [ -f "${BACKUP_DIR:-$DATA_ROOT/backups}/$target" ] || { warn "Резервная копия $target не найдена"; return 0; }
             run_action restoring "$CH/update.log" restore.sh "${BACKUP_DIR:-$DATA_ROOT/backups}/$target" --yes --env "$ENV_FILE" || true ;;
    *) warn "Неизвестное действие: $action" ;;
  esac
}
cmd_run() {
  mkdir -p "$DATA_ROOT/state"; exec 9>"$DATA_ROOT/state/updater.lock"; flock -n 9 || die "Помощник уже запущен для проекта $COMPOSE_PROJECT_NAME"
  info "Помощник обновлений запущен: проект $COMPOSE_PROJECT_NAME, каталог $CH, uid $(id -u), API $UPDATER_API"
  hb_loop "$$" 9>&- & HB_PID=$!
  trap 'STATE=stopped; write_status; kill "$HB_PID" 2>/dev/null; write_heartbeat true; exit 0' INT TERM
  # статус «Выполняется» от прежнего процесса недействителен: сначала проверяем прерванное обновление и только потом принимаем запросы
  STATE=recovering; ACTION=recover; STEP_NAME="проверка после запуска"; write_status
  if [ -f "$(marker_file)" ]; then
    : >> "$CH/update.log"; printf '=== %s: найдено прерванное обновление, помощник проверяет состояние ===\n' "$(date '+%F %T')" >> "$CH/update.log"
    timeout 1200 "$REPO_ROOT/scripts/recover.sh" --env "$ENV_FILE" >>"$CH/update.log" 2>&1 9>&-
  fi
  STATE=idle; ACTION=""; STEP_NAME=""; write_status; backups_json 2>/dev/null || true
  local last_check=0 last_system=0 now self; self="$(sha256sum "$REPO_ROOT/scripts/updater.sh" 2>/dev/null | cut -d' ' -f1)"
  while :; do
    now="$(date +%s)"
    if [ -f "$CH/request.txt" ]; then handle_request; elif [ $((now - last_check)) -ge "$CHECK_EVERY" ]; then do_check || true; last_check="$now"
    elif [ $((now - last_system)) -ge 300 ]; then do_system || true; do_doctor >/dev/null 2>&1 || true; last_system="$now"; write_status; else write_status; fi
    # после обновления на диске новая версия помощника: перезапускаемся на ней в паузе между действиями
    if [ "$STATE" = idle ] && [ ! -f "$CH/request.txt" ] && [ "$(sha256sum "$REPO_ROOT/scripts/updater.sh" 2>/dev/null | cut -d' ' -f1)" != "$self" ]; then
      info "Файл помощника изменился (обновление) — перезапуск на новой версии"; kill "$HB_PID" 2>/dev/null; exec 9>&-; exec "$REPO_ROOT/scripts/updater.sh" run --env "$ENV_FILE"
    fi
    sleep "$INTERVAL"
  done
}
# do_doctor — самодиагностика службы: каждая проверка даёт конкретную причину; результат — $CH/doctor.json (читает интерфейс), код 0 — всё исправно.
DOC_ITEMS=""; DOC_BAD=0
doc_add() { DOC_ITEMS="${DOC_ITEMS:+$DOC_ITEMS,}{\"key\":\"$1\",\"ok\":$2,\"message\":\"$(jesc "$3")\"}"; [ "$2" = true ] || DOC_BAD=$((DOC_BAD + 1)); }
do_doctor() {
  DOC_ITEMS=""; DOC_BAD=0
  local en act rs ep wd us hb age
  if have_systemd; then
    if [ ! -f "$UNIT_FILE" ]; then doc_add unit_file false "Файл службы $UNIT_FILE не найден: sudo ./scripts/updater.sh install --yes"
    else
      en="$(systemctl is-enabled "$UNIT.service" 2>/dev/null)"; act="$(systemctl is-active "$UNIT.service" 2>/dev/null)"; rs="$(systemctl show -p Restart --value "$UNIT.service" 2>/dev/null)"
      [ "$en" = enabled ] && doc_add autostart true "Автозапуск включён" || doc_add autostart false "Служба не включена в автозапуск (${en:-?}): после перезагрузки помощник не запустится. sudo systemctl enable $UNIT"
      [ "$act" = active ] && doc_add active true "Служба активна" || doc_add active false "Служба не активна (${act:-?}): sudo systemctl restart $UNIT; причина — journalctl -u $UNIT -n 50"
      [ "$rs" = always ] && doc_add restart true "Перезапуск при сбоях: always" || doc_add restart false "Перезапуск при сбоях не always (${rs:-?}): sudo ./scripts/updater.sh install --yes"
      unit_current && doc_add unit_current true "Файл службы соответствует релизу" || doc_add unit_current false "Файл службы устарел: sudo ./scripts/updater.sh install --yes"
      ep="$(systemctl show -p ExecStart --value "$UNIT.service" 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p')"; wd="$(systemctl show -p WorkingDirectory --value "$UNIT.service" 2>/dev/null)"; us="$(systemctl show -p User --value "$UNIT.service" 2>/dev/null)"
      [ -x "${ep:-/nonexistent}" ] && doc_add exec true "Запускаемый файл на месте: $ep" || doc_add exec false "Файл ${ep:-?} из ExecStart не найден или не исполняемый (каталог проекта перемещён?): sudo ./scripts/updater.sh install --yes из нового каталога"
      [ -d "${wd:-/nonexistent}" ] && doc_add workdir true "Рабочий каталог на месте" || doc_add workdir false "Рабочий каталог ${wd:-?} отсутствует"
      [ "${us:-root}" = root ] || [ -z "$us" ] && doc_add user true "Служба работает от root (нужно для Docker и git)" || doc_add user false "Служба работает от $us: для Docker и git нужен root"
    fi
  else doc_add systemd true "systemd не используется: помощник запускается средствами вашей init-системы"; fi
  [ -w "$CH" ] && doc_add data_dir true "Каталог обмена $CH доступен для записи" || doc_add data_dir false "Каталог обмена $CH недоступен для записи"
  [ "$(stat -c %a "$CH" 2>/dev/null)" = 1777 ] && doc_add data_perm true "Права каталога обмена позволяют приложению передавать запросы" || doc_add data_perm false "У каталога $CH не права 1777: приложение не сможет передавать запросы (chmod 1777 $CH)"
  docker info >/dev/null 2>&1 && doc_add docker true "Docker доступен" || doc_add docker false "Docker недоступен для службы: sudo systemctl status docker"
  hb="$CH/heartbeat.json"; age=$(( $(date +%s) - $(stat -c %Y "$hb" 2>/dev/null || echo 0) ))
  [ "$age" -le 30 ] && doc_add heartbeat true "Пульс свежий (${age} с)" || doc_add heartbeat false "Пульс не обновлялся ${age} с: процесс помощника не работает или завис"
  [ -e "$(marker_file)" ] && doc_add pending false "Есть незавершённое обновление: помощник обработает его при запуске (scripts/recover.sh)" || doc_add pending true "Незавершённых обновлений нет"
  printf '{"checked_at":%s,"ok":%s,"items":[%s]}\n' "$(date +%s)" "$([ "$DOC_BAD" -eq 0 ] && echo true || echo false)" "$DOC_ITEMS" | atomic "$CH/doctor.json"
  [ "$DOC_BAD" -eq 0 ]
}
# refresh — после обновления перезапустить службу на новом коде, если работает старый процесс помощника (в старых версиях помощник не перезапускался сам). Перезапуск — отложенный
# (systemd-run, вне службы), чтобы не оборвать обновление, из которого вызван refresh.
do_refresh() {
  have_systemd || return 0; [ "$(id -u)" -eq 0 ] || return 0
  systemctl is-active --quiet "$UNIT.service" || return 0
  local run_sha; run_sha="$(sed -n 's/.*"script_sha":"\([0-9a-f]*\)".*/\1/p' "$CH/heartbeat.json" 2>/dev/null)"
  [ "$run_sha" = "$SELF_SHA" ] && { log "Помощник работает на актуальном коде"; return 0; }
  if command -v systemd-run >/dev/null; then systemd-run --quiet --on-active=20 --unit="$UNIT-refresh" systemctl restart "$UNIT.service" && log "Помощник будет перезапущен на новом коде через 20 секунд"
  else warn "systemd-run недоступен: перезапустите помощника вручную: sudo systemctl restart $UNIT"; fi
}
unit_text() { cat <<U
[Unit]
Description=KAV Checker updater (${COMPOSE_PROJECT_NAME})
After=network-online.target docker.service
Wants=network-online.target docker.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=$REPO_ROOT
ExecStart=$REPO_ROOT/scripts/updater.sh run --env $ENV_FILE
Restart=always
RestartSec=10
KillMode=control-group
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
U
}
have_systemd() { [ -z "${KC_NO_SYSTEMD:-}" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }
unit_current() { [ -f "$UNIT_FILE" ] && [ "$(unit_text)" = "$(cat "$UNIT_FILE")" ]; }
# unit_verify — служба установлена, включена в автозапуск, работает и перезапускается при сбоях (проверяется фактически, а не по файлу)
unit_verify() {
  local en act rs
  have_systemd || { warn "systemd не найден: помощник нужно запускать вручную или средствами вашей init-системы"; return 2; }
  en="$(systemctl is-enabled "$UNIT.service" 2>/dev/null)"; act="$(systemctl is-active "$UNIT.service" 2>/dev/null)"; rs="$(systemctl show -p Restart --value "$UNIT.service" 2>/dev/null)"
  log "Служба $UNIT: автозапуск=${en:-нет} · состояние=${act:-нет} · перезапуск при сбоях=${rs:-?} · файл службы актуален: $(unit_current && echo да || echo нет)"
  [ "$en" = enabled ] && [ "$act" = active ] && [ "$rs" = always ] && unit_current
}
unit_install() { # установить или обновить службу (root)
  have_systemd || die "systemd не найден: запустите вручную: nohup $REPO_ROOT/scripts/updater.sh run &"
  [ "$(id -u)" -eq 0 ] || die "Нужны права root: sudo ./scripts/updater.sh install --yes"
  unit_text > "$UNIT_FILE"; chmod 644 "$UNIT_FILE"; systemctl daemon-reload; systemctl enable "$UNIT.service" >/dev/null 2>&1
  systemctl restart "$UNIT.service"; sleep 3
  unit_verify && ok "Служба $UNIT установлена, включена и запущена: кнопки «Обновить», «Откатить», «Резервная копия» доступны в веб-интерфейсе." || die "Служба не заработала как нужно: journalctl -u $UNIT"
}
case "$CMD" in
  run) cmd_run ;;
  check) do_check && ok "Проверка выполнена: $CH/remote.json" || { warn "Проверка не удалась (нет доступа к GitHub?)"; exit 1; } ;;
  system) do_system && cat "$CH/system.json" ;;
  preflight) preflight "" ;;
  status) cat "$CH/status.json" 2>/dev/null || die "Помощник не запускался" ;;
  print-unit) unit_text ;;
  install)
    if [ "$YES" -ne 1 ]; then read -r -p "Установить службу $UNIT (работает от root, выполняет только check/update/rollback/backup)? [y/N] " a; [ "$a" = y ] || die "Отменено."; fi
    unit_install ;;
  ensure) # идемпотентно: установить, если службы нет, она выключена, остановлена или устарела (вызывается установщиком)
    have_systemd || { warn "systemd не найден: помощник нужно запускать вручную"; exit 0; }
    unit_verify >/dev/null 2>&1 && { ok "Помощник обновлений уже установлен и работает"; exit 0; }
    [ "$(id -u)" -eq 0 ] || { warn "Для установки помощника нужны права root: sudo ./scripts/updater.sh install --yes"; exit 1; }
    unit_install ;;
  sync-unit) # после обновления: файл службы приводится к версии релиза (перезапуск службы не нужен — помощник перезапускается сам)
    have_systemd || exit 0
    [ "$(id -u)" -eq 0 ] || exit 0
    if [ -f "$UNIT_FILE" ] && ! unit_current; then unit_text > "$UNIT_FILE"; chmod 644 "$UNIT_FILE"; systemctl daemon-reload; log "Файл службы $UNIT обновлён до версии релиза"; fi
    [ -f "$UNIT_FILE" ] && [ "$(systemctl is-enabled "$UNIT.service" 2>/dev/null)" != enabled ] && { systemctl enable "$UNIT.service" >/dev/null 2>&1; log "Служба $UNIT снова включена в автозапуск"; }
    exit 0 ;;
  doctor) do_doctor && ok "Помощник исправен" || { cat "$CH/doctor.json" | python3 -c 'import json,sys; [print(("  ✓ " if i["ok"] else "  ✗ ")+i["message"]) for i in json.load(sys.stdin)["items"]]' 2>/dev/null; fail "Найдены проблемы (подробности выше)"; if [ "$YES" -eq 1 ] && [ "$(id -u)" -eq 0 ] && have_systemd; then info "Автоматическое восстановление службы"; systemctl daemon-reload; systemctl enable "$UNIT.service" >/dev/null 2>&1; systemctl restart "$UNIT.service"; fi; exit 1; } ;;
  refresh) do_refresh ;;
  verify) unit_verify && ok "Помощник обновлений работает и защищён от сбоев" || { fail "Помощник установлен не полностью: sudo ./scripts/updater.sh install --yes"; exit 1; } ;;
  uninstall) systemctl disable --now "$UNIT.service" 2>/dev/null; rm -f "$UNIT_FILE"; systemctl daemon-reload; ok "Служба удалена" ;;
  *) die "Команды: run | check | status | print-unit | install | ensure | verify | doctor [--yes] | refresh | sync-unit | uninstall" ;;
esac
