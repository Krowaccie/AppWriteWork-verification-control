#!/bin/sh
set -eu
attempt=0
until temporal operator cluster health --address temporal:7233 >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo PORTABLE_TEMPORAL_HEALTH_TIMEOUT >&2
    exit 1
  fi
  sleep 2
done
if temporal operator namespace describe --address temporal:7233 --namespace salmora >/dev/null 2>&1; then
  echo PORTABLE_NAMESPACE_EXISTS
else
  temporal operator namespace create --address temporal:7233 --namespace salmora --retention 1d
fi
