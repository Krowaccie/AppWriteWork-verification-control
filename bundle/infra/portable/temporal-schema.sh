#!/bin/sh
set -eu
SQL_PASSWORD=$(cat /run/secrets/temporal-migrator.password)
export SQL_PASSWORD
for db in temporal temporal_visibility; do
  temporal-sql-tool --plugin postgres12 --ep temporal-postgres -u temporal_migrator -p 5432 --db "$db" setup-schema -v 0.0
  if [ "$db" = temporal ]; then folder=temporal; else folder=visibility; fi
  temporal-sql-tool --plugin postgres12 --ep temporal-postgres -u temporal_migrator -p 5432 --db "$db" update-schema -d "/etc/temporal/schema/postgresql/v12/$folder/versioned"
done
