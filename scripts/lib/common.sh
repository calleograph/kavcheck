#!/usr/bin/env bash
# Общие функции скриптов KAV Checker: загрузка .env, обёртка docker compose, вывод, состояние обновления.
set -o pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
DRY_RUN="${DRY_RUN:-0}"

log()  { printf '%s\n' "$*"; }
info() { printf '\033[36m•\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; }
die()  { fail "$*"; exit 1; }

load_env() { # load_env ФАЙЛ — переменные .env в окружение (только строки KEY=VALUE)
  local f="${1:-$ENV_FILE}"
  [ -f "$f" ] || die "Файл настроек $f не найден. Создайте его: cp .env.example .env (или scripts/install.sh)"
  set -a; # shellcheck disable=SC1090
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$f" | sed 's/\r$//'); set +a
}
validate_project_name() { [[ "${COMPOSE_PROJECT_NAME:-}" =~ ^[a-z][a-z0-9_-]{0,40}$ ]] || die "COMPOSE_PROJECT_NAME: только a-z, 0-9, '-', '_' (сейчас: '${COMPOSE_PROJECT_NAME:-}')"; }
require_vars() { local v; for v in "$@"; do [ -n "${!v:-}" ] || die "В .env не задано: $v"; done; }
check_placeholders() { grep -nE '^[A-Z_]+=CHANGE_ME' "$ENV_FILE" && die "В .env остались заглушки CHANGE_ME — заполните их"; return 0; }

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$REPO_ROOT/deployment" --env-file "$ENV_FILE" -f "$REPO_ROOT/deployment/compose.yml" "$@"; }

version_file_read() { tr -d '[:space:]' < "$REPO_ROOT/VERSION" 2>/dev/null; }
host_version_info() { # APP_VERSION/APP_GIT_COMMIT/APP_BUILT_AT для сборки образов
  export APP_VERSION="$(version_file_read)"
  export APP_GIT_COMMIT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  export APP_BUILT_AT="$(date -u +%FT%TZ)"
}

svc_state() { docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q "$1" 2>/dev/null | head -1)" 2>/dev/null || echo missing; }
wait_healthy() { # wait_healthy СЕК СЕРВИСЫ…
  local t="$1"; shift; local i s st bad
  for ((i = 0; i < t; i += 3)); do
    bad=""; for s in "$@"; do st="$(svc_state "$s")"; [ "$st" = healthy ] || [ "$st" = "" ] && [ "$(docker inspect -f '{{.State.Running}}' "$(dc ps -q "$s" 2>/dev/null | head -1)" 2>/dev/null)" = true ] || bad="$bad $s"; done
    [ -z "$bad" ] && return 0
    sleep 3
  done
  warn "Не стали работоспособными:$bad"; return 1
}

# Состояние обновления: $DATA_ROOT/state/last-update.state (key=value)
state_file() { echo "$DATA_ROOT/state/last-update.state"; }
state_get() { sed -n "s/^$1=//p" "$(state_file)" 2>/dev/null | tail -1; }
state_set() { mkdir -p "$DATA_ROOT/state"; local f; f="$(state_file)"; touch "$f"; grep -v "^$1=" "$f" > "$f.tmp" 2>/dev/null || true; printf '%s=%s\n' "$1" "$2" >> "$f.tmp"; mv "$f.tmp" "$f"; }
history_append() { # history_append ДЕЙСТВИЕ РЕЗУЛЬТАТ ОТ ДО [ЭТАП]
  mkdir -p "$DATA_ROOT/updater"
  printf '{"at":%s,"action":"%s","result":"%s","from_version":"%s","to_version":"%s","by":"%s","stage":"%s"}\n' "$(date +%s)" "$1" "$2" "$3" "$4" "${UPDATE_BY:-terminal}" "${5:-}" >> "$DATA_ROOT/updater/history.ndjson"
}
backups_json() { # список резервных копий для веб-интерфейса
  local d="${BACKUP_DIR:-$DATA_ROOT/backups}" f first=1 out="{\"items\":["
  for f in $(ls -1t "$d"/*.dump 2>/dev/null | head -30); do
    [ "$first" = 1 ] || out+=","; first=0
    out+="{\"name\":\"$(basename "$f")\",\"size\":$(stat -c %s "$f"),\"at\":$(stat -c %Y "$f")}"
  done
  printf '%s]}\n' "$out" > "$DATA_ROOT/updater/backups.json.tmp" && mv "$DATA_ROOT/updater/backups.json.tmp" "$DATA_ROOT/updater/backups.json"
}
