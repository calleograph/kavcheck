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

# Образы: из реестра релизов (IMAGE_REPO с «/», например ghcr.io/владелец/kavcheck) или локальная сборка. Локально собранные образы называются по имени
# compose-проекта (<проект>-backend:<commit>), чтобы очистка одного экземпляра не задевала образы другого на том же сервере.
is_local_repo() { [[ "${IMAGE_REPO:-kavcheck}" != */* ]]; }
local_build_repo() { echo "${COMPOSE_PROJECT_NAME:-kavcheck}"; }
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

# ------------------------------------------------------------------------------------------------ 0.2.0: обновление
jstr() { printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | tr '\t\r\n' '   ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
free_gb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print int($4/1048576)}'; }
docker_root() { local r; r="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)"; [ -d "$r" ] && echo "$r" || echo /; }

# preflight [ЦЕЛЕВОЙ_ТЕГ] — проверки перед обновлением; печатает итог и пишет $DATA_ROOT/updater/preflight.json. Код 0 — критичных проблем нет.
PF_ITEMS=""; PF_FAIL=0
pf_add() { # pf_add КЛЮЧ ok|warn|fail ТЕКСТ
  PF_ITEMS="${PF_ITEMS:+$PF_ITEMS,}{\"key\":\"$1\",\"status\":\"$2\",\"message\":\"$(jstr "$3")\"}"
  case "$2" in ok) ok "$3" ;; warn) warn "$3" ;; *) fail "$3"; PF_FAIL=$((PF_FAIL + 1)) ;; esac
}
preflight() {
  local target="${1:-}" g need="${UPD_MIN_FREE_GB:-3}" reg
  PF_ITEMS=""; PF_FAIL=0
  g="$(free_gb "$(docker_root)")"
  if [ -z "$g" ]; then pf_add disk_docker warn "Свободное место для Docker определить не удалось"
  elif [ "$g" -lt 1 ]; then pf_add disk_docker fail "Свободно $g ГБ на диске Docker ($(docker_root)): нужно не меньше $need ГБ для образов и сборки"
  elif [ "$g" -lt "$need" ]; then pf_add disk_docker warn "Свободно $g ГБ на диске Docker: меньше рекомендуемых $need ГБ — перед сборкой будет очищен устаревший кэш сборки"
  else pf_add disk_docker ok "Диск Docker: свободно $g ГБ"; fi
  g="$(free_gb "$DATA_ROOT")"
  if [ -n "$g" ] && [ "$g" -lt 1 ]; then pf_add disk_data fail "Свободно меньше 1 ГБ в $DATA_ROOT: резервная копия базы может не поместиться"; else pf_add disk_data ok "Каталог данных: свободно ${g:-?} ГБ"; fi
  if timeout 25 git -C "$REPO_ROOT" ls-remote --tags origin >/dev/null 2>&1; then pf_add github ok "GitHub доступен (git ls-remote)"; else pf_add github warn "GitHub недоступен: обновиться можно только до уже полученных тегов"; fi
  if [ "${PF_BUILD:-0}" != 1 ] && ! is_local_repo; then
    if timeout 30 docker manifest inspect "${IMAGE_REPO}-backend:${target:-$IMAGE_TAG}" >/dev/null 2>&1; then pf_add registry ok "Реестр образов доступен: ${IMAGE_REPO}"
    else pf_add registry fail "Реестр образов ${IMAGE_REPO} недоступен или нет образа ${target:-$IMAGE_TAG}: обновитесь с локальной сборкой (--build)"; fi
  else
    reg="${NPM_REGISTRY:-https://registry.npmjs.org}"
    if curl -fsS -m 20 -o /dev/null "${reg%/}/typescript"; then pf_add npm ok "Реестр npm доступен: ${reg}"
    else pf_add npm fail "Реестр npm ${reg} недоступен: сборка интерфейса не пройдёт. Укажите зеркало NPM_REGISTRY в .env (например https://npm-mirror.gitverse.ru)"; fi
    reg="${PIP_INDEX_URL:-https://pypi.org/simple}"
    if curl -fsS -m 20 -o /dev/null "${reg%/}/fastapi/"; then pf_add pip ok "Индекс pip доступен: ${reg}"
    else pf_add pip warn "Индекс pip ${reg} недоступен: сборка backend может не пройти. Укажите PIP_INDEX_URL в .env"; fi
  fi
  if dc exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 \
     && dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version" >/dev/null 2>&1; then
    pf_add database ok "Внутренняя база работает (ревизия $(dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '[:space:]'))"
  else pf_add database fail "Внутренняя база PostgreSQL не отвечает: обновление без резервной копии невозможно"; fi
  if docker image inspect "${IMAGE_REPO:-kavcheck}-backend:${IMAGE_TAG}" >/dev/null 2>&1 && docker image inspect "${IMAGE_REPO:-kavcheck}-web:${IMAGE_TAG}" >/dev/null 2>&1; then
    pf_add rollback ok "Откат возможен: образы текущей версии (${IMAGE_TAG}) сохраняются"
  else pf_add rollback warn "Образов текущей версии ${IMAGE_TAG} нет на сервере: автоматический откат будет невозможен"; fi
  mkdir -p "$DATA_ROOT/updater" 2>/dev/null
  printf '{"checked_at":%s,"target":"%s","ok":%s,"items":[%s]}\n' "$(date +%s)" "$(jstr "$target")" "$([ "$PF_FAIL" -eq 0 ] && echo true || echo false)" "$PF_ITEMS" \
    > "$DATA_ROOT/updater/preflight.json.tmp" && mv "$DATA_ROOT/updater/preflight.json.tmp" "$DATA_ROOT/updater/preflight.json"
  [ "$PF_FAIL" -eq 0 ]
}

# restore_db_exact ДАМП [ВИД] — точный возврат внутренней базы к копии: текущая база не удаляется, а переименовывается (<имя>_<вид>_<время>, вид по умолчанию failed),
# создаётся пустая база и в неё восстанавливается копия; при ошибке прежняя база возвращается на место.
restore_db_exact() {
  local bk="$1" db="$POSTGRES_DB" keep
  [ -s "$bk" ] || { warn "Резервная копия $bk не найдена — восстановление базы невозможно"; return 1; }
  keep="${db}_${2:-failed}_$(date +%Y%m%d%H%M%S)"
  dc stop backend worker >/dev/null 2>&1
  local q='psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -tAc'
  dc exec -T postgres sh -c "$q \"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = '$db' AND pid <> pg_backend_pid()\"" >/dev/null 2>&1
  dc exec -T postgres sh -c "$q 'ALTER DATABASE \"$db\" RENAME TO \"$keep\"'" >/dev/null || { warn "Не удалось отложить текущую базу — восстановление не начато"; return 1; }
  if dc exec -T postgres sh -c "$q 'CREATE DATABASE \"$db\" OWNER \"$POSTGRES_USER\"'" >/dev/null && dc exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$db" --no-owner --exit-on-error < "$bk"; then
    action_log "база восстановлена из копии $(basename "$bk"); прежняя база сохранена как $keep"
    return 0
  fi
  dc exec -T postgres sh -c "$q 'DROP DATABASE IF EXISTS \"$db\"'" >/dev/null 2>&1
  dc exec -T postgres sh -c "$q 'ALTER DATABASE \"$keep\" RENAME TO \"$db\"'" >/dev/null 2>&1
  action_log "восстановить базу из копии не удалось — база оставлена как была"
  return 1
}

# Журнал автоматических действий для отчёта об обновлении (report.json)
ACTIONS_FILE() { echo "$DATA_ROOT/state/update-actions.log"; }
action_reset() { mkdir -p "$DATA_ROOT/state"; : > "$(ACTIONS_FILE)"; }
action_log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >> "$(ACTIONS_FILE)" 2>/dev/null; info "$*"; }
report_write() { # report_write РЕЗУЛЬТАТ ЭТАП ОТ ДО СОВЕТ
  local items="" line
  while IFS= read -r line; do items="${items:+$items,}\"$(jstr "$line")\""; done < "$(ACTIONS_FILE)" 2>/dev/null
  mkdir -p "$DATA_ROOT/updater"
  printf '{"finished_at":%s,"result":"%s","stage":"%s","from_version":"%s","to_version":"%s","advice":"%s","actions":[%s]}\n' "$(date +%s)" "$1" "$(jstr "$2")" "$3" "$4" "$(jstr "$5")" "$items" \
    > "$DATA_ROOT/updater/report.json.tmp" && mv "$DATA_ROOT/updater/report.json.tmp" "$DATA_ROOT/updater/report.json"
}

# Локальные правки зеркала npm/pip на сервере (Dockerfile, package-lock.json, .npmrc) переносятся в .env, файлы возвращаются к версии из репозитория,
# правки сохраняются патчем в $DATA_ROOT/state — иначе git checkout нового релиза конфликтует с ними.
mirror_local_fix() {
  local files="frontend/Dockerfile frontend/package-lock.json frontend/.npmrc backend/Dockerfile backend/pip.conf" changed="" f url patch
  for f in $files; do
    [ -e "$REPO_ROOT/$f" ] || continue
    if [ -n "$(git -C "$REPO_ROOT" status --porcelain -- "$f" 2>/dev/null)" ]; then changed="$changed $f"; fi
  done
  [ -n "$changed" ] || return 0
  patch="$DATA_ROOT/state/local-changes-$(date +%Y%m%d-%H%M%S).patch"
  mkdir -p "$DATA_ROOT/state"; git -C "$REPO_ROOT" diff -- $changed > "$patch" 2>/dev/null
  git -C "$REPO_ROOT" ls-files --others --exclude-standard -- $changed | while read -r f; do printf '\n# новый файл %s\n' "$f" >> "$patch"; cat "$REPO_ROOT/$f" >> "$patch"; done
  if [ -z "${NPM_REGISTRY:-}" ]; then
    url="$(grep -hoE 'https?://[A-Za-z0-9._:/-]+' "$patch" | grep -viE 'registry\.npmjs\.org|pypi\.org|github\.com' | grep -iE 'npm' | head -1)"
    [ -z "$url" ] && url="$(grep -hoE '^registry *= *https?://[^ ]+' "$REPO_ROOT/frontend/.npmrc" 2>/dev/null | sed 's/^registry *= *//' | head -1)"
    if [ -n "$url" ]; then url="${url%/}"; grep -q '^NPM_REGISTRY=' "$ENV_FILE" && sed -i "s#^NPM_REGISTRY=.*#NPM_REGISTRY=$url#" "$ENV_FILE" || echo "NPM_REGISTRY=$url" >> "$ENV_FILE"
      export NPM_REGISTRY="$url"; action_log "зеркало npm из локальных правок перенесено в .env: NPM_REGISTRY=$url"; fi
  fi
  git -C "$REPO_ROOT" checkout -q -- $(for f in $changed; do git -C "$REPO_ROOT" ls-files --error-unmatch "$f" >/dev/null 2>&1 && echo "$f"; done) 2>/dev/null
  for f in $changed; do git -C "$REPO_ROOT" ls-files --error-unmatch "$f" >/dev/null 2>&1 || rm -f "$REPO_ROOT/$f"; done
  action_log "локальные правки файлов сборки ($changed) сохранены в $patch и заменены версией из репозитория"
}

# Очистка: образы этого проекта, кроме текущей и предыдущей версии; «висячие» слои только с меткой kavcheck.component; кэш сборки старше недели — только при нехватке места.
cleanup_images() { # cleanup_images ТЕКУЩИЙ_ТЕГ ПРЕДЫДУЩИЙ_ТЕГ
  local svc img
  for svc in backend web; do
    docker images --format '{{.Repository}}:{{.Tag}}' "${IMAGE_REPO}-${svc}" 2>/dev/null | grep -vE ":(${1}|${2:-__none__})$" | while read -r img; do
      docker rmi "$img" >/dev/null 2>&1 && action_log "удалён старый образ $img"; done
  done
  docker image prune -f --filter "label=kavcheck.component" >/dev/null 2>&1
  local g; g="$(free_gb "$(docker_root)")"
  if [ -n "$g" ] && [ "$g" -lt "${UPD_MIN_FREE_GB:-3}" ]; then docker builder prune -f --filter until=168h >/dev/null 2>&1 && action_log "очищен кэш сборки Docker старше 7 суток (мало места: $g ГБ)"; fi
}
