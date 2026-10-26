#!/usr/bin/env bash
# Поднимает SQL Server 2022 в Docker с синтетической базой KAVTEST (schema.sql) для проверки SQL-шаблонов. Только для разработки и тестов.
#   tests/ksc_synthetic/run.sh up | down
#   tests/ksc_synthetic/run.sh bulk-lean [ЧИСЛО] [БАЗА]       # крупная база без уязвимостей и событий (сотни тысяч компьютеров)
#   tests/ksc_synthetic/run.sh bulk [ЧИСЛО_КОМПЬЮТЕРОВ]   # крупная база KAVBIG для проверки производительности (gen_bulk.py), по умолчанию 20000 компьютеров
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
  bulk)
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    { echo "IF DB_ID('KAVBIG') IS NOT NULL BEGIN ALTER DATABASE KAVBIG SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE KAVBIG; END"; echo "GO";
      sed -n '1,/^-- Группы/p' "$DIR/schema.sql" | grep -v '^-- Группы' | sed 's/KAVTEST/KAVBIG/g';
      echo "CREATE USER kavcheck_ro FOR LOGIN kavcheck_ro; ALTER ROLE db_datareader ADD MEMBER kavcheck_ro;"; echo "GO"; } > "$TMP/ddl.sql"
    python3 "$DIR/gen_bulk.py" --hosts "${2:-20000}" > "$TMP/bulk.sql"
    docker cp "$TMP/ddl.sql" "$NAME:/tmp/ddl.sql"; docker cp "$TMP/bulk.sql" "$NAME:/tmp/bulk.sql"
    docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -b -i /tmp/ddl.sql
    time docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -b -i /tmp/bulk.sql
    docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -d KAVBIG -Q "SELECT (SELECT COUNT(*) FROM dbo.v_akpub_host) AS hosts, (SELECT COUNT(*) FROM dbo.hst_inventory_hstprds) AS installs, (SELECT COUNT(*) FROM dbo.vapm_vulnerability_occurence) AS vulns, (SELECT COUNT(*) FROM dbo.v_akpub_ev_event) AS events"
    echo "KAVBIG готова: 127.0.0.1:${PORT}, пользователь kavcheck_ro" ;;
  bulk-lean)   # tests/ksc_synthetic/run.sh bulk-lean ЧИСЛО_КОМПЬЮТЕРОВ [ИМЯ_БАЗЫ] — крупная база без уязвимостей, защиты и событий (EOL, устройства, пользователи, поиск)
    DB="${3:-KAVHUGE}"; TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    { echo "IF DB_ID('$DB') IS NOT NULL BEGIN ALTER DATABASE $DB SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE $DB; END"; echo "GO";
      sed -n '1,/^-- Группы/p' "$DIR/schema.sql" | grep -v '^-- Группы' | sed "s/KAVTEST/$DB/g";
      echo "CREATE USER kavcheck_ro FOR LOGIN kavcheck_ro; ALTER ROLE db_datareader ADD MEMBER kavcheck_ro;"; echo "GO"; } > "$TMP/ddl.sql"
    python3 "$DIR/gen_bulk.py" --hosts "${2:-100000}" --db "$DB" --lean > "$TMP/bulk.sql"
    docker cp "$TMP/ddl.sql" "$NAME:/tmp/ddl.sql"; docker cp "$TMP/bulk.sql" "$NAME:/tmp/bulk.sql"
    docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -b -i /tmp/ddl.sql
    time docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -b -i /tmp/bulk.sql
    docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -d "$DB" -Q "SELECT (SELECT COUNT(*) FROM dbo.v_akpub_host) AS hosts, (SELECT COUNT(*) FROM dbo.hst_inventory_hstprds) AS installs, (SELECT COUNT(*) FROM dbo.hst_user_visited) AS users"
    echo "$DB готова: 127.0.0.1:${PORT}, пользователь kavcheck_ro" ;;
  down) docker rm -f "$NAME" >/dev/null 2>&1 || true ;;
esac
