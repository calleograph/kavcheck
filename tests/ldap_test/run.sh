#!/usr/bin/env bash
# Тестовый каталог OpenLDAP с LDAPS (самоподписанный CA) для проверки входа через каталог. Только для разработки и тестового стенда.
#   tests/ldap_test/run.sh up [СЕТЬ_DOCKER] | down | ca
# Сервер: ldap.example.local:636 (в сети compose), 127.0.0.1:10636 снаружи. Base DN dc=example,dc=local; сервисная запись uid=svc-kavcheck,ou=People,…
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; NAME=kavcheck-ldap-test
case "${1:-up}" in
  up)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    # цепочка: корневой CA → промежуточный CA → сертификат сервера ldap.example.local (сервер отдаёт сертификат вместе с промежуточным)
    C="$DIR/certs"; rm -rf "$C"; mkdir -p "$C"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=Example Test Root CA/O=Example" -keyout "$C/root.key" -out "$C/root.crt" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Example Test Issuing CA/O=Example" -keyout "$C/int.key" -out "$C/int.csr" 2>/dev/null
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$C/int.ext"
    openssl x509 -req -in "$C/int.csr" -CA "$C/root.crt" -CAkey "$C/root.key" -CAcreateserial -days 1825 -extfile "$C/int.ext" -out "$C/int.crt" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=ldap.example.local" -keyout "$C/ldap.key" -out "$C/ldap.csr" 2>/dev/null
    printf 'subjectAltName=DNS:ldap.example.local\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n' > "$C/ldap.ext"
    openssl x509 -req -in "$C/ldap.csr" -CA "$C/int.crt" -CAkey "$C/int.key" -CAcreateserial -days 825 -extfile "$C/ldap.ext" -out "$C/leaf.crt" 2>/dev/null
    cat "$C/leaf.crt" "$C/int.crt" > "$C/ldap.crt"; cp "$C/root.crt" "$C/ca.crt"; chmod 644 "$C"/*
    docker run -d --name "$NAME" --hostname ldap.example.local -p 127.0.0.1:10636:636 -e LDAP_ORGANISATION="Example" -e LDAP_DOMAIN="example.local" \
      -e LDAP_ADMIN_PASSWORD="Ldap-Admin-Test-1" -e LDAP_TLS_VERIFY_CLIENT=never -e LDAP_TLS_CRT_FILENAME=ldap.crt -e LDAP_TLS_KEY_FILENAME=ldap.key -e LDAP_TLS_CA_CRT_FILENAME=ca.crt \
      -v "$C:/container/service/slapd/assets/certs" osixia/openldap:1.5.0 --copy-service >/dev/null
    [ -n "${2:-}" ] && docker network connect --alias ldap.example.local "$2" "$NAME"
    for i in $(seq 1 40); do docker exec "$NAME" ldapsearch -x -H ldap://localhost -b dc=example,dc=local -D cn=admin,dc=example,dc=local -w Ldap-Admin-Test-1 -s base >/dev/null 2>&1 && break; sleep 2; done
    docker cp "$DIR/seed.ldif" "$NAME:/tmp/seed.ldif"
    docker exec "$NAME" ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=local -w Ldap-Admin-Test-1 -f /tmp/seed.ldif >/dev/null
    docker cp "$DIR/acl.ldif" "$NAME:/tmp/acl.ldif"; docker exec "$NAME" ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/acl.ldif >/dev/null 2>&1
    echo "LDAPS готов: ldap.example.local:636; CA: tests/ldap_test/run.sh ca" ;;
  ca) cat "$DIR/certs/root.crt" ;;
  down) docker rm -f "$NAME" >/dev/null 2>&1 || true ;;
esac
