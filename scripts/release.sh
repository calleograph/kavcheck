#!/usr/bin/env bash
# release.sh — выпуск версии: check | patch | minor | notes
#   check — VERSION, CHANGELOG.md и frontend/package.json согласованы; patch|minor — поднять версию, добавить раздел в CHANGELOG, закоммитить и создать тег vX.Y.Z
#   (push тега выполняется вручную: git push origin main --tags — после него CI соберёт и опубликует образы); notes — раздел CHANGELOG текущей версии (для описания релиза).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
V="$(tr -d '[:space:]' < "$ROOT/VERSION")"
case "${1:-check}" in
  check)
    [[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION некорректна: $V"; exit 1; }
    grep -q "^## \[$V\]" "$ROOT/CHANGELOG.md" || { echo "В CHANGELOG.md нет раздела ## [$V]"; exit 1; }
    grep -q "\"version\": \"$V\"" "$ROOT/frontend/package.json" || { echo "frontend/package.json version != $V"; exit 1; }
    echo "Версия $V согласована." ;;
  notes) awk -v v="$V" '$0 ~ "^## \\[" && found {exit} $0 ~ "^## \\["v"\\]" {found=1; next} found' "$ROOT/CHANGELOG.md" ;;
  patch|minor)
    [ -z "$(git -C "$ROOT" status --porcelain)" ] || { echo "Рабочее дерево не чистое"; exit 1; }
    IFS=. read -r a b c <<<"$V"; if [ "$1" = patch ]; then c=$((c + 1)); else b=$((b + 1)); c=0; fi; N="$a.$b.$c"
    echo "$N" > "$ROOT/VERSION"; sed -i "s/\"version\": \"$V\"/\"version\": \"$N\"/" "$ROOT/frontend/package.json"
    sed -i "s/^## \[Unreleased\]/## [Unreleased]\n\n## [$N] — $(date +%F)/" "$ROOT/CHANGELOG.md"
    git -C "$ROOT" add VERSION CHANGELOG.md frontend/package.json && git -C "$ROOT" commit -q -m "release: $N" && git -C "$ROOT" tag "v$N"
    echo "Версия $N: коммит и тег v$N созданы. Опубликовать: git push origin HEAD --tags" ;;
  *) echo "release.sh check | patch | minor | notes"; exit 1 ;;
esac
