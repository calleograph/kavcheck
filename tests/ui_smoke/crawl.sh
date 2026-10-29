#!/bin/bash
# Обход всех разделов в настоящем браузере (agent-browser): ширины от 1920 до 360 px (KC_VIEWPORTS, «ШxВ» через пробел), снимки экрана,
# горизонтальная прокрутка страницы, число мелких элементов управления, ошибки на экране.
# Использование: KC_URL=http://localhost:5173 KC_USER=admin KC_PASS=... tests/ui_smoke/crawl.sh <каталог снимков>
# Код возврата 1 — на какой-то странице появилась горизонтальная прокрутка или сообщение об ошибке.
set -u
URL=${KC_URL:-http://localhost:5173}; OUT=${1:-ui-smoke-out}; HERE=$(cd "$(dirname "$0")" && pwd)
export AGENT_BROWSER_SESSION=${AGENT_BROWSER_SESSION:-kc-ui-smoke}
mkdir -p "$OUT"; JS=$(cat "$HERE/probe.js"); bad=0
agent-browser set viewport 1366 768 >/dev/null; agent-browser open "$URL/" >/dev/null; sleep 1
if agent-browser eval "!document.querySelector('.sidenav')" | grep -q true; then
  [ -n "${KC_USER:-}" ] && [ -n "${KC_PASS:-}" ] || { echo "нужны KC_USER и KC_PASS"; exit 2; }
  agent-browser find label "Имя пользователя" fill "$KC_USER" >/dev/null; agent-browser find label "Пароль" fill "$KC_PASS" >/dev/null
  agent-browser find role button click --name "Войти" >/dev/null; sleep 2
fi
ROUTES="/ /pentest /pentest?tab=new /pentest?tab=jobs /pentest?tab=results /pentest?tab=profiles /pentest?tab=reports /software /hosts /devices /devices?tab=ksc /devices?tab=bi /devices?tab=match /hunt /eol /eol?tab=products /eol?tab=mappings /zones /vulnerabilities /vdb /vdb?tab=mine /protection /events /reports /security /appearance /admin?tab=system /admin?tab=sources /admin?tab=sources&kind=bi /admin?tab=licenses /admin?tab=pentest /admin?tab=users /admin?tab=ldap /admin?tab=general /admin?tab=eolcfg /admin?tab=zcache /admin?tab=catalog /admin?tab=vdb /admin?tab=updates /admin?tab=journal /admin?tab=audit /admin?tab=components /admin?tab=logs /admin?tab=mail /admin?tab=org /admin?tab=zones /admin?tab=ptchecks"
for vp in ${KC_VIEWPORTS:-1920x1080 1440x900 1366x768 1280x800 1024x768 768x1024 390x844 360x780}; do
  agent-browser set viewport ${vp%x*} ${vp#*x} >/dev/null; w=${vp%x*}
  for r in $ROUTES; do
    agent-browser open "$URL$r" >/dev/null 2>&1; sleep 1.8
    m=$(agent-browser eval "$JS" 2>&1 | tail -1 | sed 's/\\"/"/g; s/^"//; s/"$//')
    echo "$w $r $m"
    agent-browser screenshot "$OUT/${w}_$(echo "$r" | tr '/?=' '___').png" >/dev/null 2>&1
    case "$m" in *'"sx":0,'*) ;; *) bad=1;; esac
  done
done
agent-browser close >/dev/null 2>&1
exit $bad
