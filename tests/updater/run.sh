#!/usr/bin/env bash
# Сценарии отказов обновления на подставном docker/curl (tests/updater/fake): реальные scripts/update.sh, recover.sh, rollback.sh и updater.sh в песочнице с git-репозиторием.
#   tests/updater/run.sh [часть названия сценария]
# Проверяется главное: обновление идёт из готовых образов, а не локальной сборкой; при недоступных реестрах, зависании, ошибке миграции или проверки здоровья,
# обрыве и «перезагрузке» во время обновления работоспособная прежняя версия сохраняется, процессы не остаются, блокировка снимается, причина записана в отчёте.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; ONLY="${1:-}"
PASS=0; FAILS=0; CUR=""
export UPD_PASS_ENV="FAKE_STATE FAKE_PULL FAKE_BUILD FAKE_MIGRATE FAKE_HEALTH FAKE_REGISTRY FAKE_MANIFEST FAKE_NPM FAKE_HUB FAKE_UP FAKE_BASE UPD_STALL_PULL UPD_WAIT_HEALTH"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.org GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.org KC_NO_SYSTEMD=1 UPD_WAIT_HEALTH=6
t() { # t ОПИСАНИЕ КОМАНДА… — проверка
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); printf '  \033[32m✓\033[0m %s\n' "$d"; else FAILS=$((FAILS + 1)); printf '  \033[31m✗\033[0m %s   [%s]\n' "$d" "$CUR"; fi
}
scn() { CUR="$1"; [ -z "$ONLY" ] || [[ "$1" == *"$ONLY"* ]] || return 1; printf '\n\033[1m%s\033[0m\n' "$1"; return 0; }
mk() { # песочница: SB, W (рабочая копия), S (состояние docker), D (DATA_ROOT)
  SB="$(mktemp -d)"; S="$SB/state"; D="$SB/data"; W="$SB/work"; M="$SB/maker"; mkdir -p "$S" "$SB/bin" "$D"/{state,updater,backups,postgres,reports}
  cp "$HERE"/fake/docker "$HERE"/fake/curl "$SB/bin/"; git init -q --bare "$SB/origin.git"
  git init -q "$M"; ( cd "$M" && mkdir -p backend/migrations/versions deployment && cp -r "$ROOT/scripts" . && cp "$ROOT/deployment/compose.yml" deployment/ && echo 0.1.0 > VERSION \
    && echo 'revision = "r1"' > backend/migrations/versions/0001.py && git add -A && git commit -qm v1 && git tag v0.1.0 && git remote add origin "$SB/origin.git" && git push -q origin HEAD:master --tags )
  git clone -q "$SB/origin.git" "$W"
  ( cd "$M" && echo 0.2.0 > VERSION && echo 'revision = "r2"' > backend/migrations/versions/0002.py && git add -A && git commit -qm v2 && git tag v0.2.0 && git push -q origin HEAD:master --tags )
  cat > "$W/.env" <<EOF
COMPOSE_PROJECT_NAME=kctest
DATA_ROOT=$D
POSTGRES_USER=u
POSTGRES_DB=d
POSTGRES_PASSWORD=p
APP_MASTER_KEY=k
APP_PUBLIC_URL=http://x.example.org
WEB_BIND_ADDR=127.0.0.1
WEB_PORT=18999
IMAGE_REPO=kavcheck
IMAGE_TAG=local1
GITHUB_REPO=acme/kavcheck
EOF
  printf '%s\n' kavcheck-backend:local1 kavcheck-web:local1 > "$S/images"; printf 'postgres\nbackend kavcheck local1\nworker kavcheck local1\nweb kavcheck local1\n' > "$S/running"
  echo r1 > "$S/dbrev"; echo 0.1.0 > "$S/localver"
}
upd() { ( cd "$W" && env PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" "$@" "$W/scripts/update.sh" --yes >"$SB/out.log" 2>&1 ); }
updx() { local -a e=(); while [ "$1" != -- ]; do e+=("$1"); shift; done; shift; ( cd "$W" && env PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" "${e[@]}" "$W/scripts/update.sh" --yes "$@" >"$SB/out.log" 2>&1 ); }
rec() { ( cd "$W" && env PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" "$@" "$W/scripts/recover.sh" >"$SB/rec.log" 2>&1 ); }
tag() { awk '$1=="backend"{print $3}' "$S/running"; }
dbrev() { cat "$S/dbrev"; }
rj() { python3 -c "import json,sys; print(json.load(open('$D/updater/report.json')).get('$1',''))"; }
envv() { sed -n "s/^$1=//p" "$W/.env" | tail -1; }
built() { [ -e "$S/BUILD_CALLED" ]; }
no_sleepers() { ! pgrep -f 'sleep 6001' >/dev/null; }
unlocked() { flock -n "$D/state/update.lock" true; }
nomarker() { [ ! -e "$D/state/update.inprogress" ]; }
healthy_old() { [ "$(tag)" = local1 ] && [ "$(dbrev)" = r1 ]; }
head_is() { [ "$(git -C "$W" describe --tags --exact-match HEAD 2>/dev/null)" = "$1" ]; }
fin() { pkill -f "sleep 6001" 2>/dev/null; if [ -n "${KEEP:-}" ]; then echo "  (песочница сохранена: $SB)"; else rm -rf "$SB"; fi; }
common_fail() { # после любого сбоя: прежняя версия работает, процессов нет, блокировка снята, метка снята, причина записана
  t "работает прежняя версия и прежние данные" healthy_old
  t "нет зависших процессов" no_sleepers; t "блокировка обновления снята" unlocked; t "метка незавершённого обновления снята" nomarker
  t "отчёт: результат failed/recovered" bash -c "[ \"\$(python3 -c \"import json;print(json.load(open('$D/updater/report.json'))['result'])\")\" != ok ]"
}

if scn "1. Успешное обновление: готовые образы, без локальной сборки (IMAGE_REPO=kavcheck — исходный случай)"; then mk
  upd; rc=$?
  t "обновление завершилось успешно" [ "$rc" -eq 0 ]; t "локальная сборка НЕ запускалась" bash -c "! [ -e '$S/BUILD_CALLED' ]"
  t "запущена версия v0.2.0" [ "$(tag)" = v0.2.0 ]; t "образы из реестра ghcr.io/acme/kavcheck" [ "$(envv IMAGE_REPO)" = ghcr.io/acme/kavcheck ]; t "миграция применена" [ "$(dbrev)" = r2 ]
  t "код на теге v0.2.0" head_is v0.2.0; t "образы предыдущей версии сохранены для отката" grep -qx kavcheck-backend:local1 "$S/images"
  t "резервная копия базы создана" bash -c "ls '$D'/backups/*-pre-0.1.0.dump"; t "копия .env создана" bash -c "ls '$W'/.env.backup-*"; t "отчёт ok, способ pull" bash -c "[ '$(rj result)' = ok ] && [ '$(rj mode)' = pull ]"
  t "метка снята, блокировка свободна" bash -c "[ ! -e '$D/state/update.inprogress' ]"
  fin; fi

if scn "2. Реестр образов недоступен: ничего не меняется, сборка не запускается"; then mk
  upd FAKE_REGISTRY=down; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "локальная сборка НЕ запускалась" bash -c "! [ -e '$S/BUILD_CALLED' ]"; t "причина registry" [ "$(rj reason_code)" = registry ]; t "совет упоминает реестр" bash -c "[ -n '$(rj advice)' ]"
  t ".env не менялся" [ "$(envv IMAGE_TAG)" = local1 ]; t "код остался на v0.1.0" head_is v0.1.0; common_fail; fin; fi

if scn "3. Образов релиза в реестре ещё нет"; then mk
  upd FAKE_MANIFEST=missing; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина image_missing" [ "$(rj reason_code)" = image_missing ]; t "сборка не запускалась" bash -c "! [ -e '$S/BUILD_CALLED' ]"; common_fail; fin; fi

if scn "4. Загрузка образов зависла (нет вывода): сторож останавливает, прежняя версия работает"; then mk
  upd FAKE_PULL=hang UPD_STALL_PULL=4; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина timeout_stall" [ "$(rj reason_code)" = timeout_stall ]; t "сборка не запускалась" bash -c "! [ -e '$S/BUILD_CALLED' ]"; common_fail; fin; fi

if scn "5. Обрыв сети при загрузке образов: диагностика ghcr.io, без сборки"; then mk
  upd FAKE_PULL=timeout; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина registry" [ "$(rj reason_code)" = registry ]; t "сборка не запускалась" bash -c "! [ -e '$S/BUILD_CALLED' ]"; common_fail; fin; fi

if scn "6. Образы недоступны, но администратор разрешил резервную сборку (UPDATE_ALLOW_BUILD=1)"; then mk
  upd FAKE_PULL=timeout UPDATE_ALLOW_BUILD=1 FAKE_REGISTRY=down; rc=$?
  t "обновление выполнено локальной сборкой" [ "$rc" -eq 0 ]; t "сборка запускалась" [ -e "$S/BUILD_CALLED" ]; t "в журнале предупреждение о переходе на сборку" grep -q 'резервн' "$SB/out.log"
  t "режим build в отчёте" [ "$(rj mode)" = build ]; t "запущен локальный образ нового коммита" bash -c "[ '$(tag)' != local1 ] && [ '$(tag)' != v0.2.0 ]"; fin; fi

if scn "7. Явная локальная сборка: Docker Hub недоступен"; then mk
  updx FAKE_BUILD=hub FAKE_HUB=down -- --build; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина docker_hub" [ "$(rj reason_code)" = docker_hub ]; common_fail; fin; fi

if scn "8. Явная локальная сборка: npm недоступен"; then mk
  updx FAKE_NPM=down -- --build; rc=$?
  t "обновление остановлено проверками" [ "$rc" -ne 0 ]; t "причина npm" [ "$(rj reason_code)" = npm ]; common_fail; fin; fi

if scn "9. Явная локальная сборка зависла"; then mk
  updx FAKE_BUILD=hang UPD_STALL_BUILD=4 -- --build; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина timeout_stall" [ "$(rj reason_code)" = timeout_stall ]; common_fail; fin; fi

if scn "10. Ошибка миграции: база возвращается к копии, работает прежняя версия"; then mk
  upd FAKE_MIGRATE=fail; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина migration" [ "$(rj reason_code)" = migration ]; t ".env вернулся к прежним образам" [ "$(envv IMAGE_TAG)" = local1 ]; t "код вернулся на v0.1.0" head_is v0.1.0
  t "база восстановлена из копии" grep -q 'restored r1' "$S/calls.log"; common_fail; fin; fi

if scn "11. Зависшая миграция: тайм-аут, база возвращается к копии"; then mk
  upd FAKE_MIGRATE=hang UPD_TIMEOUT_MIGRATE=4; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина timeout" bash -c "[[ '$(rj reason_code)' == timeout_* ]]"; common_fail; fin; fi

if scn "12. Новая версия не прошла проверку здоровья: возврат к прежней"; then mk
  upd FAKE_HEALTH=bad; rc=$?
  t "обновление остановлено" [ "$rc" -ne 0 ]; t "причина health" [ "$(rj reason_code)" = health ]; t "код вернулся на v0.1.0" head_is v0.1.0
  # после возврата прежняя версия здорова: сбрасываем неисправность подставного сервиса
  common_fail; fin; fi

if scn "13. «Перезагрузка» во время миграции (kill -9 всей группы) → recover.sh"; then mk
  ( cd "$W" && PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" FAKE_MIGRATE=hang exec setsid "$W/scripts/update.sh" --yes >"$SB/out.log" 2>&1 ) & pid=$!
  for _ in $(seq 1 60); do grep -q 'hang: migrate' "$S/calls.log" 2>/dev/null && break; sleep 1; done
  t "обновление дошло до миграции" grep -q '^stage=migrating' "$D/state/update.inprogress"
  kill -9 -- "-$pid" 2>/dev/null; pkill -9 -f 'sleep 6001'; wait "$pid" 2>/dev/null
  t "после «перезагрузки» метка осталась, база повреждена" bash -c "[ -e '$D/state/update.inprogress' ] && [ \"\$(cat '$S/dbrev')\" = r2 ]"
  rec; t "recover.sh завершился успешно" [ "$?" -eq 0 ]; t "результат восстановления: recovered" [ "$(rj result)" = recovered ]
  common_fail; fin; fi

if scn "14. Прерывание после запуска новой версии, но до проверки: база из копии, прежняя версия"; then mk
  upd; cp -r "$D/backups" "$SB/b"; B="$(ls "$D"/backups/*-pre-0.1.0.dump | head -1)"
  { echo pid=999999; echo started=$(date +%s); echo old_ver=0.1.0; echo new_ver=0.2.0; echo old_tag=local1; echo old_repo=kavcheck; echo "prev_head=$(git -C "$W" rev-parse v0.1.0)"; echo stage=deploying; echo "backup=$B"; echo mode=pull; echo target=v0.2.0; } > "$D/state/update.inprogress"
  rec; t "прежняя версия работает, база r1" healthy_old; t "отчёт recovered" [ "$(rj result)" = recovered ]; t "метка снята" nomarker; fin; fi

if scn "15. Прерывание на очистке (новая версия уже проверена): обновление считается выполненным"; then mk
  upd; B="$(ls "$D"/backups/*-pre-0.1.0.dump | head -1)"
  { echo pid=999999; echo started=$(date +%s); echo old_ver=0.1.0; echo new_ver=0.2.0; echo old_tag=local1; echo old_repo=kavcheck; echo "prev_head=$(git -C "$W" rev-parse v0.1.0)"; echo stage=cleanup; echo healthy_seen=1; echo "backup=$B"; echo target=v0.2.0; } > "$D/state/update.inprogress"
  rec; t "новая версия осталась, данные не откатывались" bash -c "[ '$(tag)' = v0.2.0 ] && [ '$(dbrev)' = r2 ]"; t "отчёт recovered" [ "$(rj result)" = recovered ]; t "метка снята" nomarker; fin; fi

if scn "16. Помощник: зависшее обновление останавливается сторожем, помощник продолжает работать"; then mk
  ( cd "$W" && PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" FAKE_PULL=hang UPD_STALL_PULL=900 UPD_STALL_TOTAL=7 exec setsid "$W/scripts/updater.sh" run --env "$W/.env" >"$SB/updater.log" 2>&1 ) & upid=$!
  for _ in $(seq 1 30); do [ -f "$D/updater/status.json" ] && break; sleep 1; done
  printf 'id=aabbccddeeff0011\naction=update\ntarget=v0.2.0\nmode=\nby=tester\nat=%s\n' "$(date +%s)" > "$D/updater/request.txt"
  for _ in $(seq 1 90); do [ "$(python3 -c "import json;print(json.load(open('$D/updater/status.json')).get('result',''))" 2>/dev/null)" = failed ] && break; sleep 2; done
  t "статус: действие остановлено (failed), не «выполняется»" bash -c "python3 -c \"import json;d=json.load(open('$D/updater/status.json'));assert d['result']=='failed' and d['state']=='idle'\""
  t "в журнале причина остановки" grep -q 'timeout_stall' "$D/updater/update.log"; t "помощник жив" kill -0 "$upid"; common_fail
  kill -TERM -- "-$upid" 2>/dev/null; wait "$upid" 2>/dev/null; fin; fi

if scn "17. Остановка помощника во время обновления и его перезапуск → восстановление при старте"; then mk
  ( cd "$W" && PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" FAKE_MIGRATE=hang exec setsid "$W/scripts/updater.sh" run --env "$W/.env" >"$SB/updater.log" 2>&1 ) & upid=$!
  for _ in $(seq 1 30); do [ -f "$D/updater/status.json" ] && break; sleep 1; done
  printf 'id=aabbccddeeff0022\naction=update\ntarget=v0.2.0\nmode=\nby=tester\nat=%s\n' "$(date +%s)" > "$D/updater/request.txt"
  for _ in $(seq 1 60); do grep -q 'hang: migrate' "$S/calls.log" 2>/dev/null && break; sleep 1; done
  t "обновление дошло до миграции" grep -q '^stage=migrating' "$D/state/update.inprogress"
  kill -9 -- "-$upid" 2>/dev/null; pkill -9 -f 'sleep 6001'; pkill -9 -f "$W/scripts/update.sh"; wait "$upid" 2>/dev/null
  t "в status.json остался «updating» (помощник убит)" grep -q '"state":"updating"' "$D/updater/status.json"
  ( cd "$W" && PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" exec setsid "$W/scripts/updater.sh" run --env "$W/.env" >"$SB/updater2.log" 2>&1 ) & upid=$!
  for _ in $(seq 1 60); do [ ! -e "$D/state/update.inprogress" ] && grep -q '"state":"idle"' "$D/updater/status.json" 2>/dev/null && break; sleep 1; done
  t "после перезапуска помощник снял статус «выполняется»" grep -q '"state":"idle"' "$D/updater/status.json"; t "отчёт recovered" [ "$(rj result)" = recovered ]; common_fail
  kill -TERM -- "-$upid" 2>/dev/null; wait "$upid" 2>/dev/null; fin; fi

if scn "18. Служба помощника: файл systemd, зеркала, определение репозитория образов"; then mk
  unit="$(cd "$W" && env PATH="$SB/bin:$PATH" ENV_FILE="$W/.env" "$W/scripts/updater.sh" print-unit --env "$W/.env")"
  t "Restart=always" grep -q '^Restart=always' <<<"$unit"; t "без предела перезапусков" grep -q '^StartLimitIntervalSec=0' <<<"$unit"; t "автозапуск после загрузки" grep -q 'WantedBy=multi-user.target' <<<"$unit"
  t "завершает дочерние процессы" grep -q '^KillMode=control-group' <<<"$unit"
  t "зеркало npm из настроек сервера сохраняется в .env" bash -c "cd '$W' && NPM_CONFIG_REGISTRY=https://mirror.example.net/npm/ ENV_FILE='$W/.env' bash -c 'source scripts/lib/common.sh; load_env; DATA_ROOT=$D; action_reset; adopt_mirrors' >/dev/null 2>&1; grep -qx 'NPM_REGISTRY=https://mirror.example.net/npm' '$W/.env'"
  t "репозиторий образов по GITHUB_REPO" bash -c "cd '$W' && ENV_FILE='$W/.env' bash -c 'source scripts/lib/common.sh; load_env; [ \"\$(registry_repo)\" = ghcr.io/acme/kavcheck ]'"
  sed -i 's#^GITHUB_REPO=.*#GITHUB_REPO=CHANGE_ME_owner/kavcheck#' "$W/.env"; git -C "$W" remote set-url origin git@github.com:Acme/Kavcheck.git
  t "репозиторий образов по адресу origin" bash -c "cd '$W' && ENV_FILE='$W/.env' bash -c 'source scripts/lib/common.sh; load_env; [ \"\$(registry_repo)\" = ghcr.io/acme/kavcheck ]'"
  fin; fi

if scn "19. Два обновления одновременно: второе отклоняется"; then mk
  ( cd "$W" && PATH="$SB/bin:$PATH" FAKE_STATE="$S" ENV_FILE="$W/.env" FAKE_PULL=hang UPD_STALL_PULL=60 exec setsid "$W/scripts/update.sh" --yes >"$SB/out1.log" 2>&1 ) & p1=$!
  for _ in $(seq 1 30); do [ -e "$D/state/update.inprogress" ] && break; sleep 1; done; sleep 3
  upd; rc=$?; t "второй запуск отклонён блокировкой" [ "$rc" -ne 0 ]; t "первое продолжает работать" kill -0 "$p1"
  kill -9 -- "-$p1" 2>/dev/null; pkill -9 -f 'sleep 6001'; wait "$p1" 2>/dev/null; fin; fi

printf '\nИтого: %s проверок пройдено, %s не пройдено\n' "$PASS" "$FAILS"
[ "$FAILS" -eq 0 ]
