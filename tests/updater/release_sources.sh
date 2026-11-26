#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE"' EXIT
git init -q "$FIXTURE/publish"
git -C "$FIXTURE/publish" config user.name Fixture
git -C "$FIXTURE/publish" config user.email fixture@example.local
mkdir -p "$FIXTURE/publish/scripts/lib"
printf '0.1.0\n' >"$FIXTURE/publish/VERSION"
git -C "$FIXTURE/publish" add VERSION
git -C "$FIXTURE/publish" commit -qm 'Исходная версия'
git -C "$FIXTURE/publish" tag v0.1.0
git clone -q --bare "$FIXTURE/publish" "$FIXTURE/primary.git"
git clone -q "$FIXTURE/primary.git" "$FIXTURE/install"
cp "$ROOT/scripts/lib/releases.sh" "$FIXTURE/publish/scripts/lib/"
printf '#!/bin/sh\nprintf "Проверочный сценарий: %%s %%s\\n" "$1" "$2"\n' >"$FIXTURE/publish/scripts/update-core.sh"
chmod +x "$FIXTURE/publish/scripts/update-core.sh"
printf '#!/bin/sh\nexit 0\n' >"$FIXTURE/publish/scripts/updater.sh"
printf '## [0.2.0] — 2026-11-26\n\nОписание из зеркала.\n' >"$FIXTURE/publish/CHANGELOG.md"
git -C "$FIXTURE/publish" add CHANGELOG.md scripts
git -C "$FIXTURE/publish" commit -qm 'Следующий релиз'
git -C "$FIXTURE/publish" tag v0.2.0
git -C "$FIXTURE/publish" tag v0.99.0-preview
git clone -q --bare "$FIXTURE/publish" "$FIXTURE/mirror.git"

export REPO_ROOT="$FIXTURE/install" KC_REPO_ROOT="$FIXTURE/install"
export UPDATE_GIT_MIRRORS="ext::fixture https://fixture:secret@example.local/repo https://mirror.example.local/fixture.git"
git -C "$REPO_ROOT" config "url.file://$FIXTURE/mirror.git.insteadOf" "https://mirror.example.local/fixture.git"
source "$ROOT/scripts/lib/releases.sh"
test "$(release_git_sources)" = $'origin\nhttps://mirror.example.local/fixture.git'
release_transport fetch
test "$RELEASE_SOURCE" = origin
test "$(latest_release_tag)" = v0.1.0
release_transport probe v0.2.0
test "$RELEASE_SOURCE" = mirror

printf 'COMPOSE_PROJECT_NAME=fixture\nDATA_ROOT=%s\nPOSTGRES_USER=fixture\nPOSTGRES_DB=fixture\nWEB_PORT=1\n' "$FIXTURE/data" >"$FIXTURE/fixture.env"
"$ROOT/scripts/update.sh" --env "$FIXTURE/fixture.env" --to v0.2.0 --yes >"$FIXTURE/cli.log"
grep -q 'Теги получены через зеркало mirror.example.local' "$FIXTURE/cli.log"
grep -q 'Проверочный сценарий: --target-tag v0.2.0' "$FIXTURE/cli.log"
test "$(latest_release_tag)" = v0.2.0

git -C "$REPO_ROOT" remote set-url origin "$FIXTURE/unavailable.git"
"$ROOT/scripts/updater.sh" check --env "$FIXTURE/fixture.env" >/dev/null
python3 - "$FIXTURE/data/updater/remote.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    status = json.load(f)
assert status["ok"] and status["behind"]
assert status["latest_tag"] == "v0.2.0"
assert status["source"] == "mirror" and status["source_host"] == "mirror.example.local"
assert "Описание из зеркала." in status["notes"]
PY
bash -s -- --repo "$REPO_ROOT" --env "$FIXTURE/fixture.env" --to v0.2.0 --check \
  <"$ROOT/scripts/helper-update.sh" >"$FIXTURE/helper.log"
grep -q 'Теги получены через зеркало mirror.example.local' "$FIXTURE/helper.log"
grep -q 'ничего не меняю' "$FIXTURE/helper.log"

saved="$(git -C "$REPO_ROOT" rev-parse refs/tags/v0.2.0)"
git --git-dir "$FIXTURE/mirror.git" tag -f v0.2.0 refs/tags/v0.1.0 >/dev/null
if release_transport fetch v0.2.0; then exit 1; fi
test "$saved" = "$(git -C "$REPO_ROOT" rev-parse refs/tags/v0.2.0)"
echo 'Проверены приоритет origin, резервный Git, служба, CLI, помощник и защита существующего тега.'
