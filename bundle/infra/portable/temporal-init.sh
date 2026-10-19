#!/bin/bash
set -euo pipefail
migrator=$(cat /run/secrets/temporal-migrator.password)
runtime=$(cat /run/secrets/temporal-runtime.password)
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d temporal --set=migrator="$migrator" --set=runtime="$runtime" <<'SQL'
CREATE ROLE temporal_migrator LOGIN PASSWORD :'migrator' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE temporal_runtime LOGIN PASSWORD :'runtime' NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER DATABASE temporal OWNER TO temporal_migrator;
ALTER SCHEMA public OWNER TO temporal_migrator;
ALTER DEFAULT PRIVILEGES FOR ROLE temporal_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO temporal_runtime;
GRANT USAGE ON SCHEMA public TO temporal_runtime;
CREATE DATABASE temporal_visibility OWNER temporal_migrator;
SQL
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d temporal_visibility <<'SQL'
ALTER SCHEMA public OWNER TO temporal_migrator;
ALTER DEFAULT PRIVILEGES FOR ROLE temporal_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO temporal_runtime;
GRANT USAGE ON SCHEMA public TO temporal_runtime;
SQL
