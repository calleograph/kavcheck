#!/usr/bin/env bash
# ctl.sh — повседневные команды: up | down | restart | status | logs [сервис] | admin (создать администратора) | reset-password ЛОГИН | migrate | shell
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
CMD="${1:-status}"; shift || true
load_env; validate_project_name
case "$CMD" in
  up) dc up -d ;;
  down) dc down ;;
  restart) dc restart ;;
  status) dc ps ;;
  logs) dc logs -f --tail=200 "$@" ;;
  admin) dc exec -T backend python -m app.cli create-admin "$@" ;;
  reset-password) dc exec -T backend python -m app.cli reset-password --username "${1:?логин}" ;;
  migrate) dc run --rm --no-deps backend alembic upgrade head ;;
  shell) dc exec backend sh ;;
  *) die "Команды: up | down | restart | status | logs [сервис] | admin | reset-password ЛОГИН | migrate | shell" ;;
esac
