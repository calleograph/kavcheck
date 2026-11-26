#!/usr/bin/env bash

compose_build_images() {
  local total="$1" stall="$2" pins arg ref
  local -a base_args=()
  if ! pins="$(sed -nE 's/^ARG ([A-Z_]+_IMAGE)=(docker\.io\/[a-z0-9_.\/-]+@sha256:[0-9a-f]{64})$/\1=\2/p' \
    "$REPO_ROOT/backend/Dockerfile" "$REPO_ROOT/frontend/Dockerfile")" || [ -z "$pins" ]; then
    HUB_CODE=build
    warn "В Dockerfile не найдены ссылки на базовые образы с контрольными суммами"
    return 1
  fi
  while IFS='=' read -r arg ref; do
    hub_image "$ref" || return 1
    base_args+=(--build-arg "$arg=$HUB_IMAGE")
  done <<<"$pins"

  # Встроенный BuildKit использует хранилище Docker Engine с уже загруженными образами.
  if DOCKER_BUILDKIT=1 BUILDX_BUILDER=default run_guarded "сборка образов" "$total" "$stall" \
    "${DCB[@]}" build "${base_args[@]}"; then
    return 0
  fi
  HUB_CODE="$(guard_fail_code build)"
  return 1
}
