#!/usr/bin/env bash
# Получение тегов из основного репозитория и доверенных HTTPS-зеркал.
release_tag() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
latest_release_tag() {
  git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname |
    awk '/^v[0-9]+\.[0-9]+\.[0-9]+$/ && !seen++ { print }'
}
release_git_sources() {
  local url mirrors="${UPDATE_GIT_MIRRORS:-}" i=0
  local -a urls=()
  read -r -a urls <<< "${mirrors//,/ }"
  printf '%s\n' origin
  for url in "${urls[@]}"; do
    [[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)+/?$ ]] || continue
    printf '%s\n' "$url"
    i=$((i + 1))
    [ "$i" -lt 5 ] || break
  done
}
release_git_network() {
  local seconds="$1"; shift
  GIT_TERMINAL_PROMPT=0 GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30 \
    timeout "$seconds" git -C "$REPO_ROOT" "$@" </dev/null >/dev/null 2>&1
}
release_transport() { # fetch обновляет только теги; probe проверяет канал без изменения репозитория.
  local mode="$1" tag="${2:-}" remote seconds="${UPD_TIMEOUT_NET:-60}" refspec status
  RELEASE_SOURCE=""; RELEASE_HOST=""
  [ -z "$tag" ] || release_tag "$tag" || return 1
  refspec="refs/tags/${tag:-v*}:refs/tags/${tag:-v*}"
  while IFS= read -r remote; do
    status=0
    if [ "$mode" = probe ]; then
      release_git_network 25 ls-remote --tags --exit-code "$remote" "refs/tags/${tag:-v*}" || status=$?
    else
      release_git_network "$seconds" fetch --no-tags --atomic --no-write-fetch-head -q "$remote" "$refspec" || status=$?
    fi
    [ "$status" = 0 ] || continue
    if [ "$mode" = fetch ] && [ -z "$tag" ] && [ -z "$(latest_release_tag)" ]; then continue; fi
    if [ "$remote" = origin ]; then
      RELEASE_SOURCE=origin
    else
      RELEASE_SOURCE=mirror; RELEASE_HOST="${remote#https://}"; RELEASE_HOST="${RELEASE_HOST%%/*}"
    fi
    return 0
  done < <(release_git_sources)
  return 1
}
