#!/bin/bash
set -euo pipefail
if [ "$(id -u)" = 0 ]; then
  install -d -o postgres -g postgres -m 700 /var/lib/postgresql/tls
  install -o postgres -g postgres -m 600 /run/secrets/server.key /var/lib/postgresql/tls/server.key
  install -o postgres -g postgres -m 644 /run/secrets/server.crt /var/lib/postgresql/tls/server.crt
fi
exec /usr/local/bin/docker-entrypoint.sh "$@"
