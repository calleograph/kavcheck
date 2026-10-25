#!/usr/bin/env bash
# Надёжность обновления: источник образов, сторож зависаний (тайм-аут общий и «нет вывода»), диагностика причин сбоя, блокировка, метка незавершённого обновления,
# автоопределение зеркал npm/pip. Подключается из common.sh.

# ------------------------------------------------------------------------------------------------ источник образов
# Готовые образы релиза — основной способ обновления. Репозиторий образов: IMAGE_REGISTRY из .env, иначе IMAGE_REPO с «/», иначе ghcr.io/<владелец>/<репозиторий>
# по GITHUB_REPO или по адресу remote origin. Локальная сборка — ТОЛЬКО по явному выбору (--build, UPDATE_MODE=build, кнопка «Собрать локально»): скрытого перехода на сборку нет.
origin_slug() {
  local u; u="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null)"
  sed -nE 's#^(https?://([^/@]+@)?|git@|ssh://git@)github\.com[:/]([^/]+/[^/]+)$#\3#; s#\.git/?$##p' <<<"$u" | head -1
}
github_slug() {
  local s="${GITHUB_REPO:-}"
  if [[ "$s" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] && [ "$s" != "CHANGE_ME_owner/kavcheck" ]; then echo "$s"; return; fi
  origin_slug
}
# registry_candidates — возможные репозитории образов по порядку: явный IMAGE_REGISTRY (единственный), иначе по GITHUB_REPO и по адресу origin (если различаются)
registry_candidates() {
  local s
  [ -n "${IMAGE_REGISTRY:-}" ] && { echo "${IMAGE_REGISTRY%/}"; return; }
  [[ "${IMAGE_REPO:-}" == */* ]] && echo "$IMAGE_REPO"
  for s in "$(github_slug)" "$(origin_slug)"; do [ -n "$s" ] && echo "ghcr.io/$(printf '%s' "$s" | tr 'A-Z' 'a-z')"; done | awk '!seen[$0]++'
}
registry_repo() { registry_candidates | head -1; }
# pick_registry ТЕГ — первый репозиторий, где опубликован образ релиза (docker manifest inspect); результат в REGISTRY_PICKED, причина неудачи в REGISTRY_ERR
REGISTRY_PICKED=""; REGISTRY_ERR=""
pick_registry() {
  local r out; REGISTRY_PICKED=""; REGISTRY_ERR=""
  for r in $(registry_candidates); do
    if out="$(timeout "${UPD_TIMEOUT_NET:-60}" docker manifest inspect $(is_local_host "${r%%/*}" && echo --insecure) "${r}-backend:$1" 2>&1)"; then REGISTRY_PICKED="$r"; return 0; fi
    REGISTRY_ERR="${REGISTRY_ERR:+$REGISTRY_ERR; }$r: ${out:0:140}"
  done
  return 1
}
is_local_host() { [[ "$1" =~ ^(localhost|127\.[0-9.]+|\[::1\])(:[0-9]+)?$ ]]; }       # локальный реестр (отладка, закрытые контуры) допускается без TLS
registry_scheme() { is_local_host "$1" && echo http || echo https; }
registry_host() { local r; r="$(registry_repo)"; echo "${r%%/*}"; }
update_mode() { # pull | build — как получать образы нового релиза
  case "${UPDATE_MODE:-auto}" in build) echo build ;; *) echo pull ;; esac
}

# ------------------------------------------------------------------------------------------------ сторож
# run_guarded ЭТАП ВСЕГО_СЕК БЕЗ_ВЫВОДА_СЕК КОМАНДА… — команда выполняется в собственной группе процессов; вывод показывается сразу и сохраняется в $GUARD_OUT.
# Нет нового вывода дольше БЕЗ_ВЫВОДА_СЕК или команда идёт дольше ВСЕГО_СЕК — вся группа завершается (TERM, затем KILL). Код: 124 — общий тайм-аут, 125 — нет прогресса.
GUARD_OUT=""; GUARD_REASON=""; GUARD_PID=""
# При сигнале остановки (помощник останавливает зависшее обновление, Ctrl-C) команда, запущенная сторожем в своей группе процессов, завершается вместе со скриптом.
# Состояние (метка незавершённого обновления) остаётся: его обработает scripts/recover.sh — помощник вызывает его сам, при ручном запуске update.sh — перед следующим обновлением.
guard_term() {
  [ -n "$GUARD_PID" ] && { kill -TERM -- "-$GUARD_PID"; sleep 1; kill -KILL -- "-$GUARD_PID"; } 2>/dev/null
  warn "Операция прервана сигналом. Состояние проверит scripts/recover.sh (помощник запускает его сам)"; exit 143
}
trap guard_term TERM INT HUP
run_guarded() {
  local name="$1" total="$2" stall="$3" pid tpid start last size prev=-1 rc; shift 3
  GUARD_OUT="$(mktemp "${TMPDIR:-/tmp}/kc-guard.XXXXXX")"; GUARD_REASON=ok
  setsid "$@" >"$GUARD_OUT" 2>&1 8>&- 9>&- </dev/null &
  pid=$!; GUARD_PID=$pid
  { tail -n +1 -f --pid="$pid" "$GUARD_OUT" 2>/dev/null | { grep --line-buffered -v '^npm http fetch' || true; }; } 8>&- 9>&- &
  tpid=$!
  start=$SECONDS; last=$SECONDS
  while kill -0 "$pid" 2>/dev/null; do
    sleep 2
    size="$(stat -c %s "$GUARD_OUT" 2>/dev/null || echo 0)"
    [ "$size" != "$prev" ] && { prev="$size"; last=$SECONDS; }
    if [ $((SECONDS - start)) -gt "$total" ]; then GUARD_REASON=total; break; fi
    if [ $((SECONDS - last)) -gt "$stall" ]; then GUARD_REASON=stall; break; fi
  done
  if [ "$GUARD_REASON" != ok ]; then
    kill -TERM -- "-$pid" 2>/dev/null; sleep 5; kill -KILL -- "-$pid" 2>/dev/null
    wait "$pid" 2>/dev/null; wait "$tpid" 2>/dev/null; GUARD_PID=""
    if [ "$GUARD_REASON" = total ]; then fail "$name: превышено время ($total с) — операция остановлена"; return 124; fi
    fail "$name: нет вывода и прогресса $stall с — операция остановлена"; return 125
  fi
  wait "$pid"; rc=$?; wait "$tpid" 2>/dev/null; GUARD_PID=""
  return "$rc"
}

# ------------------------------------------------------------------------------------------------ диагностика
# diag_code ФАЙЛ [ЭТАП_ПО_УМОЛЧАНИЮ] — код причины по тексту вывода команд.
diag_code() {
  local f="$1" dflt="${2:-generic}"
  [ -s "$f" ] || { echo "$dflt"; return; }
  if grep -qiE 'no space left on device' "$f"; then echo disk
  elif grep -qiE '(auth\.docker\.io|registry-1\.docker\.io|production\.cloudflare\.docker\.com|failed to resolve source metadata for docker\.io)' "$f" && grep -qiE 'timeout|deadline|refused|no such host|EOF|TLS|unreachable|failed to' "$f"; then echo docker_hub
  elif grep -qiE 'manifest unknown|manifest for .* not found|not found: manifest|pull access denied|requested access to the resource is denied|name unknown' "$f"; then echo image_missing
  elif grep -qiE 'ETIMEDOUT|ENOTFOUND|EAI_AGAIN|ECONNRESET|npm (ERR!|error)|npm-mirror|registry\.npmjs' "$f"; then echo npm
  elif grep -qiE 'ReadTimeoutError|pypi|Could not find a version|No matching distribution|pip._vendor' "$f"; then echo pip
  elif grep -qiE 'ghcr\.io|dial tcp|i/o timeout|connection reset|TLS handshake|no such host|network is unreachable' "$f"; then
    if grep -qiE 'ghcr\.io' "$f"; then echo registry; else echo network; fi
  else echo "$dflt"; fi
}
diag_advice() { # КОД → понятный совет администратору
  case "$1" in
    docker_hub) echo "Недоступен Docker Hub (auth.docker.io / registry-1.docker.io): он нужен только для локальной сборки базовых образов. Обновление из готовых образов (ghcr.io) его не использует — повторите обновление без локальной сборки либо настройте зеркало Docker Hub (registry-mirrors в /etc/docker/daemon.json)." ;;
    registry) echo "Недоступен реестр готовых образов (ghcr.io). Проверьте сеть, прокси и DNS сервера; повторите позже. Локальная сборка — кнопка «Собрать локально» (потребуются npm, pip и Docker Hub)." ;;
    image_missing) echo "Образы этого релиза в реестре не найдены. Возможно, публикация образов ещё не завершилась (проверьте вкладку Actions релиза в GitHub); повторите позже или выберите «Собрать локально»." ;;
    npm) echo "Не удалось скачать пакеты npm. Укажите зеркало NPM_REGISTRY в .env (например https://npm-mirror.gitverse.ru) и повторите; обновление из готовых образов npm не требует." ;;
    pip) echo "Не удалось скачать пакеты Python. Укажите зеркало PIP_INDEX_URL в .env и повторите; обновление из готовых образов pip не требует." ;;
    network) echo "Обрыв или недоступность сети. Проверьте соединение сервера, DNS и прокси и повторите обновление; прежняя версия продолжает работать." ;;
    disk) echo "Не хватает места на диске. Освободите место (docker system df; удалите ненужные образы и кэш сборки) и повторите обновление." ;;
    build) echo "Сборка образов завершилась с ошибкой. Подробности — в журнале обновления (кнопка «Скачать журнал»)." ;;
    migration) echo "Миграция внутренней базы не выполнилась; база возвращена к резервной копии, работает прежняя версия. Передайте журнал обновления разработчикам." ;;
    health) echo "Новая версия не стала работоспособной (проверка здоровья не пройдена). Выполнен возврат к прежней версии; причину ищите в журнале обновления." ;;
    timeout_total) echo "Операция превысила допустимое время и была остановлена. Проверьте скорость сети и повторите; сроки задаются UPD_TIMEOUT_* в .env." ;;
    timeout_stall) echo "Операция перестала продвигаться (нет вывода) и была остановлена. Чаще всего это недоступность реестра или зеркала; проверьте сеть и повторите." ;;
    interrupted) echo "Обновление было прервано (перезагрузка сервера или остановка помощника). Состояние проверено автоматически; см. журнал." ;;
    *) echo "См. журнал обновления (кнопка «Скачать журнал») и docs/UPDATE_AND_BACKUP.md." ;;
  esac
}
# guard_fail_code РЕЗУЛЬТАТ_КОМАНДЫ ЭТАП — итоговый код причины после run_guarded
guard_fail_code() {
  case "$GUARD_REASON" in total) echo timeout_total; return ;; stall) echo timeout_stall; return ;; esac
  diag_code "$GUARD_OUT" "${1:-generic}"
}

# ------------------------------------------------------------------------------------------------ блокировка и метка
# Одновременно может идти только одно обновление, откат или восстановление: блокировка снимается ОС при завершении (в том числе аварийном) процесса.
take_lock() {
  mkdir -p "$DATA_ROOT/state"; exec 8>"$DATA_ROOT/state/update.lock"
  flock -n 8 || die "Уже выполняется другое обновление, откат или восстановление"
}
kv_file_set() { local f="$1"; mkdir -p "$(dirname "$f")"; touch "$f"; grep -v "^$2=" "$f" > "$f.tmp" 2>/dev/null || true; printf '%s=%s\n' "$2" "$3" >> "$f.tmp"; mv "$f.tmp" "$f"; }
kv_file_get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1; }
marker_file() { echo "$DATA_ROOT/state/update.inprogress"; }
marker_set() { kv_file_set "$(marker_file)" "$1" "$2"; }
marker_get() { kv_file_get "$(marker_file)" "$1"; }
marker_clear() { rm -f "$(marker_file)"; }

# ------------------------------------------------------------------------------------------------ зеркала
# Если NPM_REGISTRY / PIP_INDEX_URL не заданы в .env, но на сервере зеркало уже настроено (npm config, ~/.npmrc, pip.conf, переменные окружения),
# оно берётся оттуда и сохраняется в .env — иначе Docker о нём не знает и сборка идёт на недоступный стандартный реестр.
owner_home() { local u h; u="$(stat -c %U "$REPO_ROOT" 2>/dev/null)"; h="$(getent passwd "$u" 2>/dev/null | cut -d: -f6)"; echo "${h:-$HOME}"; }
detect_npm_mirror() {
  local h reg f; h="$(owner_home)"
  reg="${NPM_CONFIG_REGISTRY:-${npm_config_registry:-}}"
  for f in "$h/.npmrc" "$REPO_ROOT/frontend/.npmrc" /etc/npmrc /usr/etc/npmrc "$HOME/.npmrc"; do
    [ -n "$reg" ] && break; [ -r "$f" ] && reg="$(sed -nE 's/^[[:space:]]*registry[[:space:]]*=[[:space:]]*(https?:[^[:space:]]+).*/\1/p' "$f" | head -1)"
  done
  [ -z "$reg" ] && command -v npm >/dev/null && reg="$(timeout 10 npm config get registry 2>/dev/null)"
  reg="${reg%/}"; case "$reg" in ""|"https://registry.npmjs.org"|"http://registry.npmjs.org") return 1 ;; esac; echo "$reg"
}
detect_pip_mirror() {
  local h url f; h="$(owner_home)"
  url="${PIP_INDEX_URL:-}"
  for f in "$h/.config/pip/pip.conf" "$h/.pip/pip.conf" /etc/pip.conf "$HOME/.config/pip/pip.conf" "$REPO_ROOT/backend/pip.conf"; do
    [ -n "$url" ] && break; [ -r "$f" ] && url="$(sed -nE 's/^[[:space:]]*index-url[[:space:]]*=[[:space:]]*(https?:[^[:space:]]+).*/\1/p' "$f" | head -1)"
  done
  case "$url" in ""|"https://pypi.org/simple"|"https://pypi.org/simple/") return 1 ;; esac; echo "$url"
}
env_put() { # env_put КЛЮЧ ЗНАЧЕНИЕ — записать в .env и в окружение
  grep -q "^$1=" "$ENV_FILE" && sed -i "s#^$1=.*#$1=$2#" "$ENV_FILE" || echo "$1=$2" >> "$ENV_FILE"; export "$1=$2"
}
adopt_mirrors() {
  local m
  if [ -z "${NPM_REGISTRY:-}" ] && m="$(detect_npm_mirror)"; then env_put NPM_REGISTRY "$m"; action_log "зеркало npm найдено в настройках сервера и сохранено в .env: NPM_REGISTRY=$m"; fi
  if [ -z "${PIP_INDEX_URL:-}" ] && m="$(detect_pip_mirror)"; then env_put PIP_INDEX_URL "$m"; action_log "зеркало pip найдено в настройках сервера и сохранено в .env: PIP_INDEX_URL=$m"; fi
  return 0
}
http_code() { curl -sS -m "${1:-20}" -o /dev/null -w '%{http_code}' "$2" 2>/dev/null || echo 000; }

# ------------------------------------------------------------------------------------------------ источники зависимостей для локальной сборки
# Доступность одного адреса не означает, что реестр исправен (бывают HTTP 504 на части пакетов): проверяется реальное получение нескольких пакетов из package-lock.json.
# Реестры задаются списком (NPM_REGISTRIES или NPM_REGISTRY, затем официальный), исправные идут первыми; в Dockerfile каждый пробуется ограниченное число раз с тайм-аутом.
list_words() { tr ',;' '  ' <<<"$*" | xargs -n1 2>/dev/null | sed 's#/*$##' | awk 'NF && !seen[$0]++'; }
npm_probe() { # npm_probe РЕЕСТР — 0, если 4 разных пакета из package-lock.json скачиваются целиком
  local reg="$1" url n=0 total=0 lock="$REPO_ROOT/frontend/package-lock.json" urls
  urls="$(grep -o '"resolved": "https://registry.npmjs.org/[^"]*"' "$lock" 2>/dev/null | cut -d'"' -f4 | awk 'NR%97==1' | head -4)"
  [ -n "$urls" ] || urls="https://registry.npmjs.org/typescript/-/typescript-5.0.0.tgz"
  for url in $urls; do
    total=$((total + 1)); local u="${reg%/}/${url#https://registry.npmjs.org/}"
    local code; code="$(curl -sS -m 30 -o /dev/null -w '%{http_code}' -r 0-4095 "$u" 2>/dev/null)"
    case "$code" in 200|206) n=$((n + 1)) ;; esac
  done
  [ "$n" -eq "$total" ]
}
pick_npm_registries() {
  local cand good="" bad="" r
  cand="$(list_words "${NPM_REGISTRIES:-} ${NPM_REGISTRY:-}" https://registry.npmjs.org)"
  for r in $cand; do
    if npm_probe "$r"; then good="$good $r"; info "npm: $r — пакеты скачиваются"; else bad="$bad $r"; warn "npm: $r — часть пакетов недоступна (таймаут или ошибка сервера); будет пробоваться последним"; fi
  done
  NPM_REGISTRIES="$(echo $good $bad)"
}
pip_probe() { [ "$(curl -sS -m 30 -o /dev/null -w '%{http_code}' "${1%/}/fastapi/" 2>/dev/null)" = 200 ]; }
pick_pip_indexes() {
  local cand good="" bad="" r
  cand="$(list_words "${PIP_INDEX_URLS:-} ${PIP_INDEX_URL:-}" https://pypi.org/simple)"
  for r in $cand; do if pip_probe "$r"; then good="$good $r"; else bad="$bad $r"; warn "pip: $r недоступен; будет пробоваться последним"; fi; done
  PIP_INDEX_URLS="$(echo $good $bad)"
}
