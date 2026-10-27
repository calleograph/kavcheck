#!/usr/bin/env bash
# Общие функции скриптов KAV Checker: загрузка .env, обёртка docker compose, вывод, состояние обновления.
set -o pipefail
# Скрипты могут выполняться из копии каталога scripts/ целевого релиза (update.sh распаковывает её из git и запускает): SCRIPTS_DIR — где лежат скрипты, REPO_ROOT — установленный
# репозиторий (код, compose, миграции), его переопределяет KC_REPO_ROOT. Так обновление всегда выполняет логику НОВОГО релиза, а не старой установленной версии.
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${KC_REPO_ROOT:-$(cd "$SCRIPTS_DIR/.." && pwd)}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
DRY_RUN="${DRY_RUN:-0}"
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
source "$(dirname "${BASH_SOURCE[0]}")/recovery.sh"

log()  { printf '%s\n' "$*"; }
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then C0=$'\033[0m'; C1=$'\033[36m'; C2=$'\033[32m'; C3=$'\033[33m'; C4=$'\033[31m'; else C0=""; C1=""; C2=""; C3=""; C4=""; fi   # цвета только в терминале: в журнале обновления их нет
info() { printf '%s•%s %s\n' "$C1" "$C0" "$*"; }
ok()   { printf '%s✓%s %s\n' "$C2" "$C0" "$*"; }
warn() { printf '%s!%s %s\n' "$C3" "$C0" "$*" >&2; }
fail() { printf '%s✗%s %s\n' "$C4" "$C0" "$*" >&2; }
die()  { fail "$*"; exit 1; }

load_env() { # load_env ФАЙЛ — переменные .env в окружение (только строки KEY=VALUE)
  local f="${1:-$ENV_FILE}"
  [ -f "$f" ] || die "Файл настроек $f не найден. Создайте его: cp .env.example .env (или scripts/install.sh)"
  set -a; # shellcheck disable=SC1090
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$f" | sed 's/\r$//'); set +a
  # необязательные настройки: не заданные в .env не должны давать «unbound variable» (set -u) ни в одном скрипте
  GITHUB_REPO="${GITHUB_REPO:-}"; APP_PUBLIC_URL="${APP_PUBLIC_URL:-}"; IMAGE_REPO="${IMAGE_REPO:-kavcheck}"; IMAGE_TAG="${IMAGE_TAG:-}"; WEB_BIND_ADDR="${WEB_BIND_ADDR:-127.0.0.1}"; WEB_PORT="${WEB_PORT:-}"
}
validate_project_name() { [[ "${COMPOSE_PROJECT_NAME:-}" =~ ^[a-z][a-z0-9_-]{0,40}$ ]] || die "COMPOSE_PROJECT_NAME: только a-z, 0-9, '-', '_' (сейчас: '${COMPOSE_PROJECT_NAME:-}')"; }
require_vars() { local v; for v in "$@"; do [ -n "${!v:-}" ] || die "В .env не задано: $v"; done; }
check_placeholders() { grep -nE '^[A-Z_]+=CHANGE_ME' "$ENV_FILE" && die "В .env остались заглушки CHANGE_ME — заполните их"; return 0; }

dc_base() { DCB=(docker compose --progress plain -p "$COMPOSE_PROJECT_NAME" --project-directory "$REPO_ROOT/deployment" --env-file "$ENV_FILE" -f "$REPO_ROOT/deployment/compose.yml"); }
dc() { dc_base; "${DCB[@]}" "$@"; }
kill_oneoff() { # разовые контейнеры `compose run`, оставшиеся после остановки зависшей команды
  docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" --filter "label=com.docker.compose.oneoff=True" 2>/dev/null | xargs -r docker rm -f >/dev/null 2>&1
}

# Образы: из реестра релизов (IMAGE_REPO с «/», например ghcr.io/владелец/kavcheck) или локальная сборка. Локально собранные образы называются по имени
# compose-проекта (<проект>-backend:<commit>), чтобы очистка одного экземпляра не задевала образы другого на том же сервере.
is_local_repo() { [[ "${IMAGE_REPO:-kavcheck}" != */* ]]; }
local_build_repo() { echo "${COMPOSE_PROJECT_NAME:-kavcheck}"; }
version_file_read() { tr -d '[:space:]' < "$REPO_ROOT/VERSION" 2>/dev/null; }
# Какая версия РАБОТАЕТ сейчас: ответ приложения, иначе запись о последнем обновлении, иначе файл VERSION. Файл VERSION показывает только извлечённый код и может расходиться
# с запущенными образами (например, код уже на новом теге, а контейнеры ещё старые).
installed_version() {
  local v; v="$(curl -fsS -m 8 "http://${WEB_BIND_ADDR:-127.0.0.1}:${WEB_PORT:-8080}/api/v1/version" 2>/dev/null | sed -n 's/.*"version":"\([0-9][^"]*\)".*/\1/p')"
  [ -n "$v" ] && [ "$v" != "0.0.0" ] && { echo "$v"; return; }
  v="$(state_get current_version)"; [ -n "$v" ] && { echo "$v"; return; }
  version_file_read
}
# Коммит запущенной версии: тег vX.Y.Z, если он есть, иначе текущий HEAD.
installed_head() { git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/v$1^{commit}" 2>/dev/null || git -C "$REPO_ROOT" rev-parse HEAD; }
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
pf_failed() { [[ "$PF_ITEMS" == *"\"key\":\"$1\",\"status\":\"fail\""* ]]; }
preflight() { # PF_MODE=pull|build — какой источник образов проверяется
  local target="${1:-}" g need="${UPD_MIN_FREE_GB:-3}" reg host code out img missing=0 mode="${PF_MODE:-pull}"
  PF_ITEMS=""; PF_FAIL=0
  g="$(free_gb "$(docker_root)")"
  if [ -z "$g" ]; then pf_add disk_docker warn "Свободное место для Docker определить не удалось"
  elif [ "$g" -lt 1 ]; then pf_add disk_docker fail "Свободно $g ГБ на диске Docker ($(docker_root)): нужно не меньше $need ГБ для образов и сборки"
  elif [ "$g" -lt "$need" ]; then pf_add disk_docker warn "Свободно $g ГБ на диске Docker: меньше рекомендуемых $need ГБ — перед сборкой будет очищен устаревший кэш сборки"
  else pf_add disk_docker ok "Диск Docker: свободно $g ГБ"; fi
  g="$(free_gb "$DATA_ROOT")"
  if [ -n "$g" ] && [ "$g" -lt 1 ]; then pf_add disk_data fail "Свободно меньше 1 ГБ в $DATA_ROOT: резервная копия базы может не поместиться"; else pf_add disk_data ok "Каталог данных: свободно ${g:-?} ГБ"; fi
  if timeout 25 git -C "$REPO_ROOT" ls-remote --tags origin >/dev/null 2>&1; then pf_add github ok "GitHub доступен (git ls-remote)"; else pf_add github warn "GitHub недоступен: обновиться можно только до уже полученных тегов"; fi
  if [ "$mode" = pull ]; then
    reg="$(registry_repo)"; host="${reg%%/*}"
    if [ -z "$reg" ]; then pf_add registry fail "Не определён репозиторий готовых образов: укажите IMAGE_REGISTRY (например ghcr.io/владелец/kavcheck) или GITHUB_REPO в .env"
    else
      code="$(http_code 20 "$(registry_scheme "$host")://$host/v2/")"
      if [ "$code" = 000 ]; then pf_add registry fail "Реестр образов $host недоступен с сервера (нет соединения за 20 с): проверьте сеть, DNS и прокси. Прежняя версия продолжает работать"
      elif pick_registry "${target:-$IMAGE_TAG}"; then pf_add registry ok "Готовые образы ${REGISTRY_PICKED}-*:${target:-$IMAGE_TAG} опубликованы и доступны"
      elif grep -qiE 'no such manifest|manifest unknown|not found|denied|unauthorized' <<<"$REGISTRY_ERR"; then pf_add registry fail "Образов релиза ${target:-$IMAGE_TAG} в реестре нет (${REGISTRY_ERR:0:200}): публикация релиза ещё не завершилась? Проверьте IMAGE_REGISTRY/GITHUB_REPO в .env; повторите позже или выберите локальную сборку"
      else pf_add registry fail "Не удалось проверить образы в реестре $host: ${REGISTRY_ERR:0:200}"; fi
    fi
  else
    adopt_mirrors
    reg="${NPM_REGISTRY:-https://registry.npmjs.org}"
    if curl -fsS -m 20 -o /dev/null "${reg%/}/typescript"; then pf_add npm ok "Реестр npm доступен: ${reg}"
    else pf_add npm fail "Реестр npm ${reg} недоступен: сборка интерфейса не пройдёт. Укажите зеркало NPM_REGISTRY в .env (например https://npm-mirror.gitverse.ru)"; fi
    reg="${PIP_INDEX_URL:-https://pypi.org/simple}"
    if curl -fsS -m 20 -o /dev/null "${reg%/}/fastapi/"; then pf_add pip ok "Индекс pip доступен: ${reg}"
    else pf_add pip warn "Индекс pip ${reg} недоступен: сборка backend может не пройти. Укажите PIP_INDEX_URL в .env"; fi
    for img in node:24-alpine python:3.12-slim nginxinc/nginx-unprivileged:1.27-alpine; do docker image inspect "$img" >/dev/null 2>&1 || missing=1; done
    if [ "$missing" = 1 ]; then
      code="$(http_code 20 "https://registry-1.docker.io/v2/")"; [ "$code" = 000 ] && out=bad || { code="$(http_code 20 "https://auth.docker.io/token?service=registry.docker.io")"; [ "$code" = 200 ] && out=ok || out=bad; }
      if [ "$out" = ok ]; then pf_add docker_hub ok "Docker Hub доступен (нужен для базовых образов сборки)"
      else pf_add docker_hub fail "Docker Hub (registry-1.docker.io, auth.docker.io) недоступен: локальная сборка не получит базовые образы. Используйте готовые образы или настройте зеркало Docker Hub (registry-mirrors)"; fi
    else pf_add docker_hub ok "Базовые образы сборки уже есть на сервере: Docker Hub не нужен"; fi
  fi
  if dc exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1 \
     && dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SELECT version_num FROM alembic_version" >/dev/null 2>&1; then
    pf_add database ok "Внутренняя база работает (ревизия $(dc exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '[:space:]'))"
  else pf_add database fail "Внутренняя база PostgreSQL не отвечает: обновление без резервной копии невозможно"; fi
  if docker image inspect "${IMAGE_REPO:-kavcheck}-backend:${IMAGE_TAG}" >/dev/null 2>&1 && docker image inspect "${IMAGE_REPO:-kavcheck}-web:${IMAGE_TAG}" >/dev/null 2>&1; then
    pf_add rollback ok "Откат возможен: образы текущей версии (${IMAGE_TAG}) сохраняются"
  else pf_add rollback warn "Образов текущей версии ${IMAGE_TAG} нет на сервере: автоматический откат будет невозможен"; fi
  mkdir -p "$DATA_ROOT/updater" 2>/dev/null
  printf '{"checked_at":%s,"target":"%s","mode":"%s","ok":%s,"items":[%s]}\n' "$(date +%s)" "$(jstr "$target")" "$mode" "$([ "$PF_FAIL" -eq 0 ] && echo true || echo false)" "$PF_ITEMS" \
    > "$DATA_ROOT/updater/preflight.json.tmp" && mv "$DATA_ROOT/updater/preflight.json.tmp" "$DATA_ROOT/updater/preflight.json"
  [ "$PF_FAIL" -eq 0 ]
}

# restore_db_exact ДАМП [ВИД] — точный возврат внутренней базы к копии: текущая база не удаляется, а переименовывается (<имя>_<вид>_<время>, вид по умолчанию failed),
# создаётся пустая база и в неё восстанавливается копия; при ошибке прежняя база возвращается на место.
restore_db_exact() {
  local bk="$1" db="$POSTGRES_DB" keep
  [ -s "$bk" ] || { warn "Резервная копия $bk не найдена — восстановление базы невозможно"; return 1; }
  keep="${db}_${2:-failed}_$(date +%Y%m%d%H%M%S)"
  dc stop backend worker pentest >/dev/null 2>&1
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
action_log() { mkdir -p "$DATA_ROOT/state" 2>/dev/null; printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >> "$(ACTIONS_FILE)" 2>/dev/null; info "$*"; }
report_write() { # report_write РЕЗУЛЬТАТ ЭТАП ОТ ДО СОВЕТ [КОД_ПРИЧИНЫ] — result: ok | failed | recovered
  local items="" line started
  while IFS= read -r line; do items="${items:+$items,}\"$(jstr "$line")\""; done < <(cat "$(ACTIONS_FILE)" 2>/dev/null)
  started="$(marker_get started)"; started="${started:-$(date +%s)}"
  mkdir -p "$DATA_ROOT/updater"
  printf '{"started_at":%s,"finished_at":%s,"result":"%s","stage":"%s","from_version":"%s","to_version":"%s","advice":"%s","reason_code":"%s","mode":"%s","actions":[%s]}\n' "$started" "$(date +%s)" "$1" "$(jstr "$2")" "$3" "$4" "$(jstr "$5")" "${6:-}" "${UPD_MODE_USED:-}" "$items" \
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

# Очистка после УСПЕШНОГО обновления: из образов этого проекта остаются только текущие и предыдущей версии (откат на один релиз); прочие удаляются; «висячие» слои
# только с меткой kavcheck.component; кэш сборки старше недели — только при нехватке места. До проверки новой версии ничего не удаляется.
cleanup_images() { # cleanup_images ТЕКУЩИЙ_РЕПО:ТЕГ ПРЕДЫДУЩИЙ_РЕПО:ТЕГ
  local svc img key keep=" $1 $2 " repo seen=""
  for repo in "${IMAGE_REPO:-kavcheck}" "${2%%:*}" "$(local_build_repo)"; do
    case " $seen " in *" $repo "*) continue ;; esac; seen="$seen $repo"
    for svc in backend web; do
      docker images --format '{{.Repository}}:{{.Tag}}' "${repo}-${svc}" 2>/dev/null | while read -r img; do
        key="${img%-${svc}:*}:${img##*:}"
        case "$keep" in *" $key "*) continue ;; esac
        docker rmi "$img" >/dev/null 2>&1 && action_log "удалён старый образ $img"
      done
    done
  done
  docker image prune -f --filter "label=kavcheck.component" >/dev/null 2>&1
  local g; g="$(free_gb "$(docker_root)")"      # общий кэш сборки Docker принадлежит всему серверу (другим проектам тоже): автоматически не чистится
  [ -n "$g" ] && [ "$g" -lt "${UPD_MIN_FREE_GB:-3}" ] && warn "На диске Docker мало места ($g ГБ). Освободите его вручную (docker system df); автоматическая очистка общего кэша сборки не выполняется"
  ls -1t "$ENV_FILE".backup-* 2>/dev/null | tail -n +6 | xargs -r rm -f
}
