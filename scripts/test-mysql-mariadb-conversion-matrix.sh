#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for mysql_version in 8.0 8.4; do
  for mariadb_version in 10.11 11.4; do
    echo "=== MySQL ${mysql_version} <-> MariaDB ${mariadb_version} ==="
    ASKIO_MIGRATION_MYSQL_IMAGE="mysql:${mysql_version}" \
      ASKIO_MIGRATION_MARIADB_IMAGE="mariadb:${mariadb_version}" \
      "${repository_root}/scripts/test-mysql-mariadb-conversion-integration.sh"
  done
done
