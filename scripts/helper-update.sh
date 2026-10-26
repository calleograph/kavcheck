#!/usr/bin/env bash
# helper-update.sh — безопасная доставка исправлений помощника обновлений БЕЗ обновления приложения (образы, база и данные не затрагиваются).
#   scripts/helper-update.sh [--to vX.Y.Z] [--env FILE] [--repo КАТАЛОГ] [--yes] [--no-restart] [--check]
# Нужен, когда сам помощник неисправен и обновить приложение через него нельзя. Работает и как отдельный файл, без остальных скриптов установки:
#   cd /opt/kavcheck && sudo git fetch --tags origin && git show vX.Y.Z:scripts/helper-update.sh | sudo bash -s -- --env /opt/kavcheck/.env --yes
# Порядок: получить теги → распаковать scripts/ выбранного релиза во временный каталог → проверить синтаксис и выполнить «updater.sh selftest» (строгий режим, чистое окружение,
# временные данные: те же пути запроса, что в работе) → сохранить текущие скрипты в архив → заменить файлы по одному атомарно → перезапустить службу и дождаться пульса новой версии.
# Не удалось на любом шаге после замены — прежние скрипты возвращаются из архива. Без перезапуска (--no-restart, так вызывает сам помощник из интерфейса) службу перезапускает
# отдельный «страж» (systemd-run): если за 90 секунд новая версия не отозвалась, он возвращает прежние скрипты.
# Во время обновления приложения (блокировка update.lock) команда отказывается работать. Рабочая база и контейнеры не затрагиваются.
set -uo pipefail
say() { printf '%s\n' "$*"; }
die() { printf '✗ %s\n' "$*" >&2; exit 1; }
TO=""; ENV_FILE=""; REPO=""; YES=0; NORESTART=0; CHECK=0; WATCH=""
while [ $# -gt 0 ]; do case "$1" in
  --to) TO="$2"; shift 2 ;; --env) ENV_FILE="$2"; shift 2 ;; --repo) REPO="$2"; shift 2 ;; --yes|-y) YES=1; shift ;; --no-restart) NORESTART=1; shift ;; --check) CHECK=1; shift ;;
  --watchdog) WATCH="$2"; shift 2 ;; -h|--help) sed -n '2,12p' "$0" 2>/dev/null; exit 0 ;; *) die "Неизвестный аргумент: $1" ;; esac; done
[ -n "$REPO" ] || REPO="${KC_REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || true)}"
[ -n "$REPO" ] || { [ -n "$ENV_FILE" ] && REPO="$(dirname "$ENV_FILE")"; }
[ -d "$REPO/.git" ] || die "Не найден каталог установки (git): укажите --repo /opt/kavcheck или запустите из него"
[ -n "$ENV_FILE" ] || ENV_FILE="$REPO/.env"
[ -f "$ENV_FILE" ] || die "Файл настроек $ENV_FILE не найден"
set -a; source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE" | sed 's/\r$//'); set +a
DATA_ROOT="${DATA_ROOT:-}"; PROJ="${COMPOSE_PROJECT_NAME:-}"
[ -n "$DATA_ROOT" ] && [[ "$PROJ" =~ ^[a-z][a-z0-9_-]{0,40}$ ]] || die "В .env должны быть заданы DATA_ROOT и COMPOSE_PROJECT_NAME"
UNIT="kavcheck-updater-$PROJ"; HD="$DATA_ROOT/state/helper"; CH="$DATA_ROOT/updater"; SC="$REPO/scripts"
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$REPO"
have_systemd() { [ -z "${KC_NO_SYSTEMD:-}" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
hb_field() { sed -n "s/.*\"$1\":\"\\{0,1\\}\\([^,\"}]*\\).*/\\1/p" "$CH/heartbeat.json" 2>/dev/null | head -1; }

# install_dir ИСТОЧНИК — заменить файлы scripts/ по одному: копия рядом и переименование (новый inode; работающий bash дочитывает прежний файл), updater.sh — последним
install_dir() {
  local src="$1" f rel
  while IFS= read -r f; do
    rel="${f#"$src"/}"; [ "$rel" = updater.sh ] && continue
    mkdir -p "$SC/$(dirname "$rel")"; cp -p "$f" "$SC/$rel.new" && mv -f "$SC/$rel.new" "$SC/$rel" || return 1
  done < <(find "$src" -type f | sort)
  cp -p "$src/updater.sh" "$SC/updater.sh.new" && mv -f "$SC/updater.sh.new" "$SC/updater.sh"
}
restore_backup() { # restore_backup АРХИВ — вернуть прежние скрипты
  local tmp; tmp="$(mktemp -d "$HD/restore.XXXXXX")" && tar -xzf "$1" -C "$tmp" && install_dir "$tmp/scripts"; local rc=$?; rm -rf "$tmp"; return $rc
}
restart_unit() { have_systemd && [ -f "/etc/systemd/system/$UNIT.service" ] && systemctl restart "$UNIT.service"; }
wait_new() { # wait_new ХЭШ СЕК — дождаться свежего пульса помощника с этим хэшем скрипта
  local i; for ((i = 0; i < $2; i += 2)); do
    [ "$(hb_field script_sha)" = "$1" ] && [ $(( $(date +%s) - $(stat -c %Y "$CH/heartbeat.json" 2>/dev/null || echo 0) )) -le 15 ] && return 0
    sleep 2
  done; return 1
}

# страж: запускается отдельно от службы и проверяет, что новая версия помощника ожила; иначе возвращает прежние скрипты
if [ -n "$WATCH" ]; then
  NEW_SHA="${WATCH%%:*}"; BK="${WATCH#*:}"
  wait_new "$NEW_SHA" "${KC_WATCH_WAIT:-90}" && { say "Страж: помощник новой версии работает"; rm -f "$HD/pending"; echo "$(date +%s) watchdog_ok ${NEW_SHA:0:12}" >> "$HD/history.log"; exit 0; }
  say "Страж: новая версия помощника не ответила за 90 секунд — возвращаю прежние скрипты"
  restore_backup "$BK" && restart_unit; rm -f "$HD/pending"; echo "$(date +%s) rolled_back_by_watchdog $BK" >> "$HD/history.log"; exit 1
fi

mkdir -p "$HD" "$CH"
exec 8>"$HD/helper-update.lock"; flock -n 8 || die "Другое обновление помощника уже выполняется"
if [ -e "$DATA_ROOT/state/update.lock" ] && ! flock -n 7 7>"$DATA_ROOT/state/update.lock"; then die "Идёт обновление приложения (блокировка update.lock): повторите позже"; fi
command -v git >/dev/null || die "git не найден"

say "• Получение списка релизов"
GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30 timeout 90 git -C "$REPO" fetch --tags --prune -q origin 2>/dev/null || say "! git fetch не удался (нет доступа к GitHub?): используются уже полученные теги"
[ -n "$TO" ] || TO="$(git -C "$REPO" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -1)"
[[ "$TO" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Не удалось определить релиз (тег $TO)"
git -C "$REPO" rev-parse -q --verify "refs/tags/$TO^{commit}" >/dev/null || die "Тег $TO не найден в репозитории"
git -C "$REPO" cat-file -e "$TO:scripts/updater.sh" 2>/dev/null || die "В релизе $TO нет scripts/updater.sh"
git -C "$REPO" cat-file -e "$TO:scripts/helper-update.sh" 2>/dev/null || say "! В релизе $TO нет helper-update.sh: после установки обновлять помощника отдельно будет нельзя"

STAGE="$HD/stage-$(date +%Y%m%d-%H%M%S)-$TO"; mkdir -p "$STAGE"
git -C "$REPO" archive "$TO" scripts | tar -x -C "$STAGE" || die "Не удалось распаковать scripts/ релиза $TO"
NEW_SHA="$(sha_of "$STAGE/scripts/updater.sh")"; OLD_SHA="$(sha_of "$SC/updater.sh")"
say "• Релиз $TO: помощник ${OLD_SHA:0:12} → ${NEW_SHA:0:12}"
if [ "$NEW_SHA" = "$OLD_SHA" ] && diff -rq "$STAGE/scripts" "$SC" >/dev/null 2>&1; then say "✓ Скрипты уже соответствуют релизу $TO — менять нечего"; rm -rf "$STAGE"; exit 0; fi
[ "$CHECK" = 1 ] && { say "Есть отличия (проверка: --check, ничего не меняю)"; rm -rf "$STAGE"; exit 0; }
if [ "$YES" != 1 ]; then read -r -p "Заменить скрипты помощника файлами релиза $TO (приложение и данные не затрагиваются)? [y/N] " a; [ "$a" = y ] || { rm -rf "$STAGE"; die "Отменено."; }; fi

say "• Проверка кода релиза"
for f in "$STAGE"/scripts/*.sh "$STAGE"/scripts/lib/*.sh; do bash -n "$f" 2>/dev/null || { rm -rf "$STAGE"; die "Синтаксическая ошибка в $(basename "$f") релиза $TO: установка отменена"; }; done
if grep -q 'cmd_selftest' "$STAGE/scripts/updater.sh"; then
  KC_REPO_ROOT="$REPO" env -i PATH="$PATH" HOME="${HOME:-/root}" LANG="${LANG:-C.UTF-8}" "$STAGE/scripts/updater.sh" selftest --env "$ENV_FILE" >"$HD/selftest.log" 2>&1 \
    || { tail -n 15 "$HD/selftest.log" >&2; rm -rf "$STAGE"; die "Самопроверка помощника релиза $TO не пройдена (журнал: $HD/selftest.log): установка отменена, прежние скрипты не тронуты"; }
  say "✓ Самопроверка помощника релиза $TO пройдена"
else say "! В помощнике релиза $TO нет самопроверки: проверен только синтаксис"; fi

BK="$HD/scripts-$(date +%Y%m%d-%H%M%S)-before-$TO.tgz"
tar -czf "$BK" -C "$REPO" scripts || die "Не удалось сохранить текущие скрипты"
ls -1t "$HD"/scripts-*.tgz 2>/dev/null | tail -n +6 | xargs -r rm -f; ls -1dt "$HD"/stage-* 2>/dev/null | tail -n +3 | xargs -r rm -rf
say "• Резервная копия прежних скриптов: $BK"
install_dir "$STAGE/scripts" || { restore_backup "$BK"; die "Замена файлов не удалась — прежние скрипты возвращены"; }
echo "$(date +%s) installed $TO ${OLD_SHA:0:12}->${NEW_SHA:0:12} backup=$BK" >> "$HD/history.log"
say "✓ Скрипты помощника заменены на версию релиза $TO"

if [ "$NORESTART" = 1 ]; then
  # вызвано самим помощником: он перезапустится сам, когда освободится; независимый страж вернёт прежнее, если новая версия не оживёт
  echo "$NEW_SHA:$BK" > "$HD/pending"
  if have_systemd && command -v systemd-run >/dev/null; then systemd-run --quiet --on-active="${KC_WATCH_DELAY:-100}" --unit="$UNIT-watch-$(date +%s)" "$STAGE/scripts/helper-update.sh" --env "$ENV_FILE" --repo "$REPO" --watchdog "$NEW_SHA:$BK" 2>/dev/null \
    || say "! systemd-run не запустил стража: проверьте помощника вручную (sudo ./scripts/updater.sh doctor)"
  else ( KC_WATCH_DELAY="${KC_WATCH_DELAY:-100}" setsid bash -c 'sleep "$KC_WATCH_DELAY"; exec "$@"' _ "$STAGE/scripts/helper-update.sh" --env "$ENV_FILE" --repo "$REPO" --watchdog "$NEW_SHA:$BK" >/dev/null 2>&1 9>&- 8>&- </dev/null & ); fi
  say "✓ Помощник перезапустится на новой версии сам; проверка — через ~100 секунд (страж вернёт прежнюю версию при сбое)"; exit 0
fi

if have_systemd && [ -f "/etc/systemd/system/$UNIT.service" ]; then
  say "• Перезапуск службы $UNIT"
  restart_unit; rc=$?
  if [ "$rc" -eq 0 ] && wait_new "$NEW_SHA" 60; then say "✓ Помощник работает на версии релиза $TO (хэш ${NEW_SHA:0:12}). Приложение и данные не затрагивались."; exit 0; fi
  say "✗ Помощник новой версии не ответил за 60 секунд — возвращаю прежние скрипты"
  restore_backup "$BK" && restart_unit
  die "Установка отменена, прежние скрипты возвращены (архив: $BK). Журнал службы: journalctl -u $UNIT -n 50"
fi
say "! Служба systemd не найдена: перезапустите помощника вручную (он перезапустится сам, когда освободится, если уже работает)"
