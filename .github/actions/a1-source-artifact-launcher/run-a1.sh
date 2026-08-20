#!/usr/bin/env bash
set -euo pipefail

readonly image='ghcr.io/krowaccie/appwritework-verification-a1@sha256:1efd444383f6b807d54feb1822a9f5d40bb891d3d1d7f06234a5f2866acca63e'
readonly workspace="${GITHUB_WORKSPACE:-}"

require_nonempty() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'A1 launcher missing required GitHub runtime binding: %s\n' "$name" >&2
    exit 2
  fi
}

for name in GITHUB_WORKSPACE GITHUB_ACTIONS ACTIONS_RUNTIME_TOKEN ACTIONS_RESULTS_URL GITHUB_JOB GITHUB_RUN_ATTEMPT GITHUB_RUN_ID A1_HOSTED_REQUEST; do
  require_nonempty "$name"
done

if [[ "$GITHUB_ACTIONS" != 'true' || "$workspace" != /* || "$workspace" == *$'\n'* || "$workspace" == *,* || "$ACTIONS_RESULTS_URL" != https://* ]]; then
  printf 'A1 launcher rejected an invalid GitHub runtime binding.\n' >&2
  exit 2
fi

exec docker run --rm \
  --user 0 \
  --cap-drop ALL \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add SETUID \
  --cap-add SETGID \
  --mount "type=bind,src=$workspace,dst=/github/workspace,readonly" \
  --env GITHUB_ACTIONS \
  --env ACTIONS_RUNTIME_TOKEN \
  --env ACTIONS_RESULTS_URL \
  --env GITHUB_JOB \
  --env GITHUB_RUN_ATTEMPT \
  --env GITHUB_RUN_ID \
  "$image" "$A1_HOSTED_REQUEST"
