#!/bin/sh
set -eu
POSTGRES_PWD=$(cat /run/secrets/temporal-runtime.password)
export POSTGRES_PWD
printf '{}\n' > /tmp/portable-dynamic.yaml
export DYNAMIC_CONFIG_FILE_PATH=/tmp/portable-dynamic.yaml
exec "$@"
