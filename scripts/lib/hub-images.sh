#!/usr/bin/env bash
# Базовые образы привязаны к дайджесту оригинального манифеста на Docker Hub.
hub_sources() {
  local ref="$1" host
  printf '%s\n' "$ref"
  while IFS= read -r host; do
    if [[ "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]+)?$ ]] && [ "$host" != docker.io ]; then
      printf '%s/%s\n' "$host" "${ref#docker.io/}"
    fi
  done < <(list_words "${DOCKER_HUB_MIRRORS-mirror.gcr.io dockerhub.timeweb.cloud}")
}

hub_image_present() {
  docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$1" 2>/dev/null \
    | grep -E "@${1#*@}$" >/dev/null
}

# Сначала используем проверенный локальный образ. Иначе docker pull проверяет манифест и весь набор слоёв.
hub_image() {
  local ref="$1" total="${2:-${UPD_TIMEOUT_PULL:-1800}}" stall="${3:-${UPD_STALL_PULL:-300}}" source count i code
  HUB_IMAGE="" HUB_CODE=docker_hub
  if ! [[ "$ref" =~ ^docker\.io/[a-z0-9][a-z0-9_/.-]*@sha256:[a-f0-9]{64}$ ]]; then
    fail "Некорректная закреплённая ссылка на базовый образ: $ref"; return 1
  fi
  # Один медленный источник не должен исчерпать общий тайм-аут обновления до перехода на зеркало.
  if [ "$total" -gt 300 ]; then total=300; fi
  local -a sources
  mapfile -t sources < <(hub_sources "$ref")
  for source in "${sources[@]}"; do
    if hub_image_present "$source"; then
      info "Используется локальный базовый образ $source"
      HUB_IMAGE="$source"; return 0
    fi
  done
  for source in "${sources[@]}"; do
    count=1; [ "$source" != "$ref" ] || count=3
    for ((i = 1; i <= count; i++)); do
      info "Загрузка базового образа $source (попытка $i из $count)"
      if run_guarded "загрузка базового образа" "$total" "$stall" docker pull "$source"; then
        if hub_image_present "$source"; then HUB_IMAGE="$source"; return 0; fi
        warn "Дайджест загруженного образа не совпал с закреплённым: $source"
        break
      else
        code="$(guard_fail_code docker_hub)"
        if [ "$code" = disk ]; then HUB_CODE=disk; return 1; fi
        [ "$code" != image_missing ] || break
      fi
    done
  done
  return 1
}

postgres_prepare() {
  local ref compose
  HUB_CODE=docker_hub
  if [ -n "${1:-}" ]; then
    compose="$(git -C "$REPO_ROOT" show "$1:deployment/compose.yml")" || return 1
  else
    compose="$(cat "$REPO_ROOT/deployment/compose.yml")" || return 1
  fi
  ref="$(sed -nE 's|^[[:space:]]+image: \$\{KC_POSTGRES_IMAGE:-([^}]+)\}$|\1|p' <<<"$compose")"
  # При откате на старый релиз переменной в Compose ещё нет.
  if [ -z "$ref" ]; then unset KC_POSTGRES_IMAGE; return 0; fi
  hub_image "$ref" || return 1
  export KC_POSTGRES_IMAGE="$HUB_IMAGE"
}
