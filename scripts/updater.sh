#!/usr/bin/env bash
# updater.sh — «помощник» обновлений для веб-интерфейса (Администрирование → Обновления).
#   scripts/updater.sh run [--env FILE]           # работает постоянно (служба systemd от root)
#   scripts/updater.sh check [--env FILE]         # разовая проверка релизов GitHub → remote.json
#   scripts/updater.sh install [--env FILE] [--yes] | uninstall | status | print-unit
# Контейнер backend не имеет доступа к Docker и git хоста. Веб-интерфейс кладёт запрос в $DATA_ROOT/updater/request.txt (простые строки key=value),
# помощник выполняет ТОЛЬКО фиксированный набор: check | update [target=vX.Y.Z] | rollback | backup. Произвольные команды выполнить нельзя.
# Файлы обмена: request.txt (из веб-интерфейса), status.json, remote.json, backups.json, update.log, history.ndjson.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
CMD="${1:-run}"; [ $# -gt 0 ] && shift
YES=0; INTERVAL=3; CHECK_EVERY="${UPDATER_CHECK_EVERY:-3600}"
while [ $# -gt 0 ]; do case "$1" in --env) ENV_FILE="$2"; shift 2 ;; --yes|-y) YES=1; shift ;; --interval) INTERVAL="$2"; shift 2 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
load_env; validate_project_name; require_vars DATA_ROOT
CH="$DATA_ROOT/updater"; LOG="$CH/update.log"; UNIT="kavcheck-updater-${COMPOSE_PROJECT_NAME}"; UNIT_FILE="/etc/systemd/system/$UNIT.service"
[ "$(id -u)" -eq 0 ] && export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$REPO_ROOT"
mkdir -p "$CH" && chmod 1777 "$CH" 2>/dev/null
jesc() { printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\t\r' '  ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
atomic() { local tmp; tmp="$(mktemp "$CH/.w.XXXXXX")" && cat > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1"; }
STATE=idle; ACTION=""; REQ=""; STEP_NO=0; STEP_TOTAL=9; STEP_NAME=""; STARTED=0; FINISHED=0; EXIT=null; RESULT=""; BY=""; TARGET=""
write_status() { printf '{"ts":%s,"pid":%s,"state":"%s","action":"%s","request_id":"%s","step_no":%s,"step_total":%s,"step_name":"%s","started_at":%s,"finished_at":%s,"exit_code":%s,"result":"%s","by":"%s","target":"%s"}\n' \
  "$(date +%s)" "$$" "$STATE" "$ACTION" "$REQ" "$STEP_NO" "$STEP_TOTAL" "$(jesc "$STEP_NAME")" "$STARTED" "$FINISHED" "$EXIT" "$RESULT" "$(jesc "$BY")" "$(jesc "$TARGET")" | atomic "$CH/status.json"; }

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
pump() { local line; while IFS= read -r line; do printf '%s\n' "$line" | sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' >> "$LOG"; if [[ "$line" =~ ^\[([0-9]+)/([0-9]+)\][[:space:]]+(.*)$ ]]; then STEP_NO="${BASH_REMATCH[1]}"; STEP_TOTAL="${BASH_REMATCH[2]}"; STEP_NAME="${BASH_REMATCH[3]}"; write_status; fi; done; }
run_action() { # run_action СОСТОЯНИЕ СКРИПТ АРГУМЕНТЫ…
  local st="$1" script="$2"; shift 2; local rc
  STATE="$st"; STARTED="$(date +%s)"; FINISHED=0; EXIT=null; RESULT=""; STEP_NO=0; STEP_NAME="запуск"; write_status
  : > "$LOG"; printf '=== %s запущен %s (запросил: %s) ===\n' "$ACTION" "$(date '+%F %T')" "${BY:-?}" >> "$LOG"
  (cd "$REPO_ROOT" && env -i PATH="$PATH" HOME="${HOME:-/root}" LANG="${LANG:-C.UTF-8}" ENV_FILE="$ENV_FILE" UPDATE_BY="$BY" GIT_CONFIG_COUNT="${GIT_CONFIG_COUNT:-0}" GIT_CONFIG_KEY_0="${GIT_CONFIG_KEY_0:-}" GIT_CONFIG_VALUE_0="${GIT_CONFIG_VALUE_0:-}" "$REPO_ROOT/scripts/$script" "$@" 2>&1) | pump
  rc="${PIPESTATUS[0]}"
  FINISHED="$(date +%s)"; EXIT="$rc"; STATE=idle; [ "$rc" -eq 0 ] && RESULT=ok || RESULT=failed
  printf '=== %s завершён %s: %s (код %s) ===\n' "$ACTION" "$(date '+%F %T')" "$([ "$rc" -eq 0 ] && echo успешно || echo 'С ОШИБКОЙ')" "$rc" >> "$LOG"
  write_status; backups_json 2>/dev/null || true
  return "$rc"
}
handle_request() {
  local f="$CH/request.txt" owner rid action target by at
  [ -f "$f" ] || return 0
  owner="$(stat -c %u "$f" 2>/dev/null || echo -1)"
  if [ -L "$f" ] || ! [[ "$owner" =~ ^(0|$(id -u)|10001)$ ]]; then warn "Запрос отклонён: символьная ссылка или посторонний владелец (uid $owner)"; rm -f "$f"; return 0; fi
  rid="$(sed -n 's/^id=//p' "$f" | head -1)"; action="$(sed -n 's/^action=//p' "$f" | head -1)"; target="$(sed -n 's/^target=//p' "$f" | head -1)"; by="$(sed -n 's/^by=//p' "$f" | head -1)"; at="$(sed -n 's/^at=//p' "$f" | head -1)"
  rm -f "$f"
  [[ "$rid" =~ ^[a-f0-9]{8,32}$ ]] && [[ "$at" =~ ^[0-9]+$ ]] || { warn "Запрос отклонён: некорректный формат"; return 0; }
  [ $(( $(date +%s) - at )) -le 600 ] || { warn "Запрос $rid устарел"; return 0; }
  [[ "$by" =~ ^[A-Za-z0-9._-]{0,60}$ ]] || by="?"; [[ "$target" =~ ^(v?[0-9]+\.[0-9]+\.[0-9]+)?$ ]] || { warn "Запрос отклонён: некорректная версия"; return 0; }
  REQ="$rid"; BY="$by"; ACTION="$action"; TARGET="$target"
  case "$action" in
    ping) write_status ;;
    check) do_check || true ;;
    update) run_action updating update.sh --yes --env "$ENV_FILE" ${target:+--to "$target"} || true; do_check || true ;;
    rollback) run_action rolling_back rollback.sh --yes --env "$ENV_FILE" || true ;;
    backup) run_action backing_up backup.sh --env "$ENV_FILE" || true ;;
    *) warn "Неизвестное действие: $action" ;;
  esac
}
cmd_run() {
  mkdir -p "$DATA_ROOT/state"; exec 9>"$DATA_ROOT/state/updater.lock"; flock -n 9 || die "Помощник уже запущен для проекта $COMPOSE_PROJECT_NAME"
  info "Помощник обновлений запущен: проект $COMPOSE_PROJECT_NAME, каталог $CH, uid $(id -u)"
  trap 'STATE=stopped; write_status; exit 0' INT TERM
  STATE=idle; write_status; backups_json 2>/dev/null || true
  local last_check=0 now
  while :; do
    now="$(date +%s)"
    if [ -f "$CH/request.txt" ]; then handle_request; elif [ $((now - last_check)) -ge "$CHECK_EVERY" ]; then do_check || true; last_check="$now"; else write_status; fi
    sleep "$INTERVAL"
  done
}
unit_text() { cat <<U
[Unit]
Description=KAV Checker updater (${COMPOSE_PROJECT_NAME})
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$REPO_ROOT
ExecStart=$REPO_ROOT/scripts/updater.sh run --env $ENV_FILE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
U
}
case "$CMD" in
  run) cmd_run ;;
  check) do_check && ok "Проверка выполнена: $CH/remote.json" || { warn "Проверка не удалась (нет доступа к GitHub?)"; exit 1; } ;;
  status) cat "$CH/status.json" 2>/dev/null || die "Помощник не запускался" ;;
  print-unit) unit_text ;;
  install)
    command -v systemctl >/dev/null || die "systemd не найден: запустите вручную: nohup $REPO_ROOT/scripts/updater.sh run &"
    [ "$(id -u)" -eq 0 ] || die "Нужны права root: sudo ./scripts/updater.sh install --yes"
    if [ "$YES" -ne 1 ]; then read -r -p "Установить службу $UNIT (работает от root, выполняет только check/update/rollback/backup)? [y/N] " a; [ "$a" = y ] || die "Отменено."; fi
    unit_text > "$UNIT_FILE"; systemctl daemon-reload; systemctl enable "$UNIT.service" >/dev/null 2>&1; systemctl restart "$UNIT.service"
    sleep 3; systemctl is-active --quiet "$UNIT.service" && ok "Служба $UNIT запущена: кнопки «Обновить», «Откатить», «Резервная копия» доступны в веб-интерфейсе." || die "Служба не запустилась: journalctl -u $UNIT" ;;
  uninstall) systemctl disable --now "$UNIT.service" 2>/dev/null; rm -f "$UNIT_FILE"; systemctl daemon-reload; ok "Служба удалена" ;;
  *) die "Команды: run | check | status | print-unit | install | uninstall" ;;
esac
