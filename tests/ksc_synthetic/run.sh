#!/usr/bin/env bash
# Поднимает SQL Server 2022 в Docker с синтетической базой KAVTEST (schema.sql) для проверки SQL-шаблонов. Только для разработки и тестов.
#   tests/ksc_synthetic/run.sh up | down
# Переменные для тестов: KSC_TEST_HOST=127.0.0.1 KSC_TEST_PORT=11433 KSC_TEST_DB=KAVTEST KSC_TEST_USER=kavcheck_ro KSC_TEST_PASSWORD=KavCheck-Test-Pass-1
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="${KSC_TEST_CONTAINER:-kavcheck-mssql-test}"; PORT="${KSC_TEST_PORT:-11433}"; SA_PW="${KSC_TEST_SA_PASSWORD:-Sa-Test-Passw0rd!}"
case "${1:-up}" in
  up)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=$SA_PW" -e MSSQL_PID=Express -p "127.0.0.1:${PORT}:1433" mcr.microsoft.com/mssql/server:2022-latest >/dev/null
    for i in $(seq 1 60); do docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -Q "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
    docker cp "$DIR/schema.sql" "$NAME:/tmp/schema.sql"
    docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -i /tmp/schema.sql
    echo "KAVTEST готова: 127.0.0.1:${PORT}, пользователь kavcheck_ro" ;;
  down) docker rm -f "$NAME" >/dev/null 2>&1 || true ;;
esac
