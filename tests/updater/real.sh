#!/usr/bin/env bash
# real.sh — интеграционные испытания обновления на НАСТОЯЩЕМ Docker и systemd (служба пользователя): отдельный проект и порты, рабочая установка не затрагивается.
#   tests/updater/real.sh           (нужны docker, доступ к ghcr.io, systemd --user; код должен быть закоммичен — берётся из git HEAD)
# Что происходит: «новая версия» — реальные образы релиза v0.6.1 из ghcr.io (тег v0.6.1 в локальном origin песочницы указывает на текущий код); установка стартует на образах v0.5.0, помеченных как локально собранные
# (IMAGE_REPO=kavcheck — состояние, из-за которого раньше обновление запускало сборку); помощник работает службой systemd (Restart=always); обновления запускаются через API
# приложения, как кнопкой в интерфейсе. Сценарии: недоступный реестр, ошибка миграции, «перезагрузка» во время миграции, повтор без ручных действий, обновление, падение помощника,
# перезапуск backend, откат на несовместимую схему.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; P="kcreal$$"; PORT="${KC_REAL_PORT:-28090}"; W="$(mktemp -d /tmp/kcreal.XXXXXX)"
APP="$W/app"; ENVF="$APP/.env"; D="$W/data"; REG="ghcr.io/calleograph/kavcheck"; UNIT="$P-updater"; PASS=0; FAILS=0; CJ="$W/cj"
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$d"; else FAILS=$((FAILS + 1)); printf '  \033[31m✗\033[0m %s\n' "$d"; diag "$d"; fi; }
diag() { # при провале проверки: состояние, из-за которого она не прошла (в $W/diag.log и в конец вывода при DIAG=1)
  { printf '\n=== %s\n' "$1"; printf 'версия: %s; IMAGE_*: %s\n' "$(running_version)" "$(grep -E '^IMAGE_(REPO|TAG|REGISTRY)=' "$ENVF" | tr '\n' ' ')"; printf 'repo HEAD: %s (ROOT %s)\n' "$(git -C "$APP" rev-parse --short HEAD)" "$(git -C "$ROOT" rev-parse --short HEAD)"
    printf 'report: '; cat "$D/updater/report.json" 2>/dev/null | head -c 700; printf '\nметка: '; cat "$D/state/update.inprogress" 2>/dev/null | tr '\n' ' '; printf '\nov: '; ov | head -c 900
    printf '\n--- update.log (хвост)\n'; tail -n 25 "$D/updater/update.log" 2>/dev/null; printf -- '--- образы\n'; docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'kavcheck' | head -20; } >> "$W/diag.log" 2>&1
}
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
dc() { docker compose -p "$P" --project-directory "$APP/deployment" --env-file "$ENVF" -f "$APP/deployment/compose.yml" "$@"; }
cleanup() {
  systemctl --user stop "$UNIT" >/dev/null 2>&1; systemctl --user reset-failed "$UNIT" >/dev/null 2>&1
  [ -f "$ENVF" ] && dc down -v >/dev/null 2>&1;   docker run --rm -v "$W:/w" --entrypoint sh postgres:16-alpine -c 'rm -rf /w/data' >/dev/null 2>&1; rm -rf "$W"
  docker rmi kavcheck-backend:real5 kavcheck-web:real5 >/dev/null 2>&1
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT
api() { python3 - "$@" <<'PY'
import json, sys, urllib.request, http.cookiejar, os
m, path = sys.argv[1], sys.argv[2]; body = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
B = f"http://127.0.0.1:{os.environ['PORT']}/api/v1"; cj = http.cookiejar.MozillaCookieJar(os.environ['CJ'])
try: cj.load(ignore_discard=True)
except Exception: pass
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)); H = {"Origin": f"http://127.0.0.1:{os.environ['PORT']}", "Content-Type": "application/json"}
tok = open(os.environ['CJ'] + ".csrf").read().strip() if os.path.exists(os.environ['CJ'] + ".csrf") else ""
if tok: H["X-CSRF-Token"] = tok
try:
    r = op.open(urllib.request.Request(B + path, method=m, headers=H, data=json.dumps(body).encode() if body is not None else None), timeout=60); d = r.read()
except urllib.error.HTTPError as e:
    print(json.dumps({"_http": e.code, "detail": e.read().decode()[:300]})); sys.exit(0)
except Exception as e:
    print(json.dumps({"_err": str(e)})); sys.exit(0)
cj.save(ignore_discard=True); out = json.loads(d or b"null")
if path.endswith("/auth/login"): open(os.environ['CJ'] + ".csrf", "w").write(out["csrf_token"])
print(json.dumps(out))
PY
}
export PORT CJ
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split('.'): d=d.get(k) if isinstance(d,dict) else None
print('' if d is None else d)" "$1"; }
ov() { api GET /admin/updates; }
wait_idle() { # дождаться окончания операции (состояние idle и есть finished_at новее начала) — до $1 секунд
  local i s; for ((i = 0; i < ${1:-600}; i += 3)); do s="$(ov | jq_ updater.state)"; [ "$s" = idle ] || [ "$s" = interrupted ] && [ -n "$(ov | jq_ updater.finished_at)" ] && [ "$(ov | jq_ updater.finished_at)" != 0 ] && return 0; sleep 3; done; return 1; }
running_version() { curl -fsS -m 5 "http://127.0.0.1:$PORT/api/v1/version" | python3 -c "import json,sys;print(json.load(sys.stdin)['version'])" 2>/dev/null; }
psql_() { dc exec -T postgres psql -U kc -d kc -tAc "$1"; }
report() { python3 -c "import json;print(json.load(open('$D/updater/report.json')).get('$1',''))"; }
trigger() { api POST /admin/updates/run '{"confirm":true,"target":"v0.6.1"}' >/dev/null; sleep 4; }
dock_build_calls() { docker ps -a --format '{{.Names}}' | grep -c buildkit; }

say "Подготовка: реестр образов, образы, репозиторий, установка на «локальных» образах v0.5.0"
for s in backend web; do        # «установленные» образы v0.5.0 помечены как локально собранные (IMAGE_REPO=kavcheck); образы нового релиза на сервере отсутствуют — их скачивает обновление
  docker pull -q "ghcr.io/calleograph/kavcheck-$s:v0.5.0" >/dev/null && docker tag "ghcr.io/calleograph/kavcheck-$s:v0.5.0" "kavcheck-$s:real5"
  docker rmi "ghcr.io/calleograph/kavcheck-$s:v0.6.1" >/dev/null 2>&1
done
# Реальные образы релиза 0.6.1 лежат в ghcr.io, поэтому «новая версия» — тег v0.6.1 в ЛОКАЛЬНОМ origin песочницы, переставленный на текущий код (со скриптами обновления нового образца).
git clone -q --bare "$ROOT" "$W/origin.git" && git clone -q "$W/origin.git" "$APP" && git -C "$APP" checkout -q --detach "$(git -C "$ROOT" rev-parse HEAD)" && git -C "$APP" tag -d v0.6.1 >/dev/null
( cd "$W" && git clone -q "$W/origin.git" maker && cd maker && git -c user.name=t -c user.email=t@example.org checkout -q "$(git -C "$ROOT" rev-parse HEAD)" && echo 0.6.1 > VERSION && git -c user.name=t -c user.email=t@example.org commit -qam "release 0.6.1 (sandbox)" --allow-empty && git tag -f v0.6.1 >/dev/null && git push -q -f origin HEAD:refs/heads/rel v0.6.1 )
mkdir -p "$D"/{postgres,reports,backups,updater,state}; chmod 1777 "$D/updater"; chmod 777 "$D/reports"
cp "$ROOT/.env.example" "$ENVF"; sed -i "s#^COMPOSE_PROJECT_NAME=.*#COMPOSE_PROJECT_NAME=$P#; s#^DATA_ROOT=.*#DATA_ROOT=$D#; s#^WEB_PORT=.*#WEB_PORT=$PORT#; s#^POSTGRES_DB=.*#POSTGRES_DB=kc#; s#^POSTGRES_USER=.*#POSTGRES_USER=kc#; s#^POSTGRES_PASSWORD=.*#POSTGRES_PASSWORD=pw-$P#; s#^APP_MASTER_KEY=.*#APP_MASTER_KEY=$(openssl rand -base64 32)#; s#^APP_PUBLIC_URL=.*#APP_PUBLIC_URL=http://127.0.0.1:$PORT#; s#^IMAGE_REPO=.*#IMAGE_REPO=kavcheck#; s#^IMAGE_TAG=.*#IMAGE_TAG=real5#; s#^IMAGE_REGISTRY=.*#IMAGE_REGISTRY=$REG#; s#^GITHUB_REPO=.*#GITHUB_REPO=acme/kavcheck#; s#^COOKIE_SECURE=.*#COOKIE_SECURE=false#" "$ENVF"
dc up -d postgres >/dev/null; for _ in $(seq 1 40); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q postgres)" 2>/dev/null)" = healthy ] && break; sleep 2; done
dc run --rm --no-deps backend alembic upgrade head >/dev/null 2>&1; dc up -d >/dev/null 2>&1; for _ in $(seq 1 60); do [ "$(running_version)" = 0.5.0 ] && break; sleep 2; done
dc exec -T backend python -m app.cli create-admin --username admin --password 'Real-Test-Pass-2026' >/dev/null 2>&1; psql_ "UPDATE users SET must_change_password = false WHERE username = 'admin'" >/dev/null
api POST /auth/login '{"login":"admin","password":"Real-Test-Pass-2026"}' >/dev/null
t "установлена версия 0.5.0 на локальных образах (IMAGE_REPO=kavcheck)" bash -c "[ '$(running_version)' = 0.5.0 ] && grep -q '^IMAGE_REPO=kavcheck' '$ENVF'"
systemd-run --user --quiet --collect --unit="$UNIT" -p Restart=always -p RestartSec=3 -p KillMode=control-group -E KC_NO_SYSTEMD=1 -E "PATH=$PATH" "$APP/scripts/updater.sh" run --env "$ENVF"
for _ in $(seq 1 30); do [ -f "$D/updater/heartbeat.json" ] && break; sleep 1; done; sleep 5
t "служба помощника (systemd) запущена, приложение видит пульс" bash -c "[ \"\$(systemctl --user is-active $UNIT)\" = active ] && [ '$(ov | jq_ updater.available)' = True ]"

say "R1. Реестр образов недоступен (настоящая ошибка Docker): прежняя версия работает, сборка не запускается"
sed -i "s#^IMAGE_REGISTRY=.*#IMAGE_REGISTRY=127.0.0.1:1/kc/kavcheck#" "$ENVF"; trigger; wait_idle 300
t "обновление остановлено, причина — реестр" bash -c "[ '$(report result)' = failed ] && [[ '$(report reason_code)' == registry* || '$(report reason_code)' == image_missing || '$(report reason_code)' == network ]]"
t "работает 0.5.0, сборка не запускалась" bash -c "[ '$(running_version)' = 0.5.0 ] && ! grep -q 'docker compose.*build' '$D/updater/update.log'"
t "помощник доступен, блокировок и меток нет" bash -c "[ '$(ov | jq_ updater.available)' = True ] && [ ! -e '$D/state/update.inprogress' ] && flock -n '$D/state/update.lock' true"
sed -i "s#^IMAGE_REGISTRY=.*#IMAGE_REGISTRY=$REG#" "$ENVF"

say "R2. Ошибка миграции (настоящая): база возвращается к копии, прежняя версия работает, данные целы"
psql_ "ALTER TABLE vdb_sources ADD COLUMN channel text" >/dev/null; trigger; wait_idle 500
t "обновление остановлено, причина — миграция" bash -c "[ '$(report result)' = failed ] && [ '$(report reason_code)' = migration ]"
t "работает 0.5.0; образы нового релиза скачаны, но не запущены" bash -c "[ '$(running_version)' = 0.5.0 ] && grep -q '^IMAGE_TAG=real5' '$ENVF' && [ '$(git -C "$APP" rev-parse HEAD)' = '$(git -C "$ROOT" rev-parse HEAD)' ]"
t "база восстановлена из копии (лишнего столбца нет), пользователь admin на месте" bash -c "[ -z \"\$(docker exec \$(docker compose -p $P --project-directory $APP/deployment --env-file $ENVF -f $APP/deployment/compose.yml ps -q postgres) psql -U kc -d kc -tAc \"select 1 from information_schema.columns where table_name='vdb_sources' and column_name='channel'\")\" ] && [ '$(psql_ "select count(*) from users where username='admin'")' = 1 ]"
t "вход в приложение работает" bash -c "[ -n '$(api POST /auth/login '{"login":"admin","password":"Real-Test-Pass-2026"}' | jq_ csrf_token)' ]"

say "R3. «Перезагрузка» посреди миграции: все процессы убиты, служба поднимается сама и возвращает работоспособную версию"
( dc exec -T postgres psql -U kc -d kc -c "BEGIN; LOCK TABLE vdb_sources IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(600);" >/dev/null 2>&1 ) & LOCKER=$!
sleep 3; trigger
for _ in $(seq 1 120); do grep -q '^stage=migrating' "$D/state/update.inprogress" 2>/dev/null && break; sleep 2; done
t "обновление дошло до миграции и ждёт блокировку" grep -q '^stage=migrating' "$D/state/update.inprogress"
systemctl --user kill -s KILL "$UNIT"; docker ps -aq --filter "label=com.docker.compose.project=$P" --filter "label=com.docker.compose.oneoff=True" | xargs -r docker rm -f >/dev/null 2>&1; kill "$LOCKER" 2>/dev/null; docker exec "$(dc ps -q postgres)" pkill -f pg_sleep >/dev/null 2>&1; psql_ "select pg_terminate_backend(pid) from pg_stat_activity where query like '%pg_sleep%' and pid <> pg_backend_pid()" >/dev/null
for _ in $(seq 1 100); do [ "$(ov | jq_ updater.state)" = idle ] && [ ! -e "$D/state/update.inprogress" ] && [ "$(report result)" = recovered ] && break; sleep 3; done
t "служба перезапущена systemd сама, помощник доступен" bash -c "[ \"\$(systemctl --user is-active $UNIT)\" = active ] && [ '$(ov | jq_ updater.available)' = True ]"
t "прерванное обновление обработано: результат recovered, метки нет" bash -c "[ '$(report result)' = recovered ] && [ ! -e '$D/state/update.inprogress' ]"
t "работает 0.5.0, база на прежней схеме, данные целы" bash -c "[ '$(running_version)' = 0.5.0 ] && [ '$(psql_ "select version_num from alembic_version")' = 0006_cvss_scores ] && [ '$(psql_ "select count(*) from users where username='admin'")' = 1 ]"

say "R4. Повторное обновление сразу после сбоя — без ручного снятия блокировок и перезапуска служб; переход с IMAGE_REPO=kavcheck на релизные образы"
BEFORE_BUILD="$(docker images --format '{{.Repository}}' | grep -c '^kavcheck-real' )"; trigger; wait_idle 600
t "обновление выполнено" bash -c "[ '$(report result)' = ok ]"
t "работает новая версия 0.6.1 (образы из реестра), миграция применена" bash -c "[ '$(running_version)' = 0.6.1 ] && [ '$(psql_ "select version_num from alembic_version")' = 0007_vdb_channels ] && grep -q '^IMAGE_REPO=$REG' '$ENVF'"
t "локальная сборка не запускалась (журнал без build)" bash -c "! grep -qi 'docker compose.*build\|сборка образов' '$D/updater/update.log' || grep -q 'загрузка готовых образов' '$D/updater/update.log'"
t "данные и вход сохранены" bash -c "[ '$(psql_ "select count(*) from users where username='admin'")' = 1 ] && [ -n '$(api POST /auth/login '{"login":"admin","password":"Real-Test-Pass-2026"}' | jq_ csrf_token)' ]"
t "прежние (локальные) образы сохранены для отката, лишних нет" bash -c "docker image inspect kavcheck-backend:real5 >/dev/null && [ \$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -c '^kavcheck-backend:') -le 2 ]"
t "после обновления backend помощник на связи и операция завершена" bash -c "[ '$(ov | jq_ updater.available)' = True ] && [ '$(ov | jq_ updater.state)' = idle ] && [ '$(ov | jq_ report.result)' = ok ]"

say "R5. Падение помощника и перезапуск backend"
PID1="$(python3 -c "import json;print(json.load(open('$D/updater/heartbeat.json'))['pid'])")"; systemctl --user kill -s KILL "$UNIT"
for _ in $(seq 1 30); do P2="$(python3 -c "import json;print(json.load(open('$D/updater/heartbeat.json'))['pid'])" 2>/dev/null)"; [ "$P2" != "$PID1" ] && [ "$(ov | jq_ updater.available)" = True ] && break; sleep 1; done
t "помощник перезапущен systemd (новый pid) и снова доступен" bash -c "[ '$P2' != '$PID1' ] && [ '$(ov | jq_ updater.available)' = True ]"
dc restart backend >/dev/null 2>&1; for _ in $(seq 1 40); do [ -n "$(running_version)" ] && break; sleep 2; done; api POST /auth/login '{"login":"admin","password":"Real-Test-Pass-2026"}' >/dev/null
t "после перезапуска backend связь с помощником не потеряна" bash -c "[ '$(ov | jq_ updater.available)' = True ]"

say "R6. Откат на предыдущую версию при несовместимой схеме базы запрещён (схема 0007 неизвестна коду 0.5.0)"
api POST /admin/updates/rollback '{"confirm":true}' >/dev/null; sleep 5; wait_idle 120
t "откат остановлен проверкой схемы, версия 0.6.1 продолжает работать" bash -c "[ '$(running_version)' = 0.6.1 ] && grep -q 'неизвестной предыдущей версии' '$D/updater/update.log'"

say "R7. Системная проверка файла службы"
t "systemd-analyze разбирает файл службы без ошибок" bash -c "'$APP/scripts/updater.sh' print-unit --env '$ENVF' > '$W/unit.service' && systemd-analyze verify --user '$W/unit.service' 2>&1 | grep -viE 'ExecStart|not executable|Failed to|file' | grep -ci 'error' | grep -q '^0$'"

printf '\nИтого: %s проверок пройдено, %s не пройдено\n' "$PASS" "$FAILS"
[ -f "$W/diag.log" ] && { cp "$W/diag.log" "${DIAG_OUT:-/tmp/real-diag.log}"; echo "Диагностика провалов: ${DIAG_OUT:-/tmp/real-diag.log}"; }
[ "$FAILS" = 0 ]
[ "$FAILS" -eq 0 ]
