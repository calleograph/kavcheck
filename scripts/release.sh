#!/usr/bin/env bash
# release.sh — выпуск версии: check | patch | minor | notes
#   check — VERSION, CHANGELOG.md и frontend/package.json согласованы; patch|minor — поднять версию, добавить раздел в CHANGELOG, закоммитить и создать тег vX.Y.Z
#   (push тега выполняется вручную: git push origin HEAD --tags — после него CI соберёт и опубликует образы); notes — раздел CHANGELOG текущей версии (для описания релиза).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V="$(tr -d '[:space:]' < "$ROOT/VERSION")"
case "${1:-check}" in
  check)
    [[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION некорректна: $V"; exit 1; }
    # между выпусками (ALLOW_UNRELEASED=1, CI на обычных push) изменения копятся в разделе [Unreleased]; для тега нужен раздел версии
    grep -q "^## \[$V\]" "$ROOT/CHANGELOG.md" || { [ "${ALLOW_UNRELEASED:-}" = 1 ] && grep -q "^## \[Unreleased\]" "$ROOT/CHANGELOG.md"; } || { echo "В CHANGELOG.md нет раздела ## [$V]"; exit 1; }
    grep -q "\"version\": \"$V\"" "$ROOT/frontend/package.json" || { echo "frontend/package.json version != $V"; exit 1; }
    # реестр компонентов рассмотрен для этого выпуска (backend/app/components.json → reviewed_for); между выпусками не требуется
    if [ "${ALLOW_UNRELEASED:-}" != 1 ]; then
      R="$(python3 -c "import json,sys; print(json.load(open('$ROOT/backend/app/components.json'))['reviewed_for'])")"
      [ "$(printf '%s\n%s\n' "$R" "$V" | sort -V | head -1)" = "$V" ] || { echo "Реестр компонентов рассмотрен для $R, а выпуск — $V: проверьте компоненты (docs/RELEASE.md)"; exit 1; }
    fi
    echo "Версия $V согласована." ;;
  notes) awk -v v="$V" '$0 ~ "^## \\[" && found {exit} $0 ~ "^## \\["v"\\]" {found=1; next} found' "$ROOT/CHANGELOG.md" ;;
  patch|minor)
    [ -z "$(git -C "$ROOT" status --porcelain)" ] || { echo "Рабочее дерево не чистое"; exit 1; }
    IFS=. read -r a b c <<<"$V"; if [ "$1" = patch ]; then c=$((c + 1)); else b=$((b + 1)); c=0; fi; N="$a.$b.$c"
    R="$(python3 -c "import json; print(json.load(open('$ROOT/backend/app/components.json'))['reviewed_for'])")"
    [ "$R" = "$N" ] || { echo "Обязательная проверка компонентов: в backend/app/components.json поставьте reviewed_for = $N после рассмотрения зависимостей (docs/RELEASE.md). Сейчас: $R"; exit 1; }
    echo "$N" > "$ROOT/VERSION"; sed -i "s/\"version\": \"$V\"/\"version\": \"$N\"/" "$ROOT/frontend/package.json"
    sed -i "s/^## \[Unreleased\]/## [Unreleased]\n\n## [$N] — $(date +%F)/" "$ROOT/CHANGELOG.md"
    git -C "$ROOT" add VERSION CHANGELOG.md frontend/package.json && git -C "$ROOT" commit -q -m "release: $N" && git -C "$ROOT" tag "v$N"
    echo "Версия $N: коммит и тег v$N созданы. Опубликовать: git push origin HEAD --tags" ;;
  *) echo "release.sh check | patch | minor | notes"; exit 1 ;;
esac
