#!/usr/bin/env bash
set -euo pipefail

readonly image='ghcr.io/krowaccie/appwritework-verification-a1@sha256:ff23ed8834201d90e4c6e67b6f4c6ed66626c2b4bea897147b407647197f15e8'
readonly workspace="${GITHUB_WORKSPACE:-}"
readonly runner_temp="${RUNNER_TEMP:-}"

require_nonempty() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'A1 launcher missing required GitHub runtime binding: %s\n' "$name" >&2
    exit 2
  fi
}

for name in GITHUB_WORKSPACE GITHUB_ACTIONS GITHUB_OUTPUT GITHUB_RUN_ATTEMPT GITHUB_RUN_ID RUNNER_TEMP A1_HOSTED_REQUEST; do
  require_nonempty "$name"
done

if [[
  "$GITHUB_ACTIONS" != 'true'
  || "$workspace" != /*
  || "$workspace" == *$'\n'*
  || "$workspace" == *,*
  || "$runner_temp" != /*
  || "$runner_temp" == *$'\n'*
  || "$runner_temp" == *,*
  || ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$
  || ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$
]]; then
  printf 'A1 launcher rejected an invalid GitHub runtime binding.\n' >&2
  exit 2
fi

readonly request_pattern='^\{"repository":"Krowaccie/AppWriteWork","schemaVersion":"verification-a1-hosted-request.v1","sourceRef":"refs/heads/main","sourceRevision":"([0-9a-f]{40})","sourceTreeDigest":"sha256:[0-9a-f]{64}","workflow":"Verify Main","workflowRunAttempt":[1-9][0-9]*,"workflowRunId":"[1-9][0-9]*"\}$'
if [[ ! "$A1_HOSTED_REQUEST" =~ $request_pattern ]]; then
  printf 'A1 launcher rejected an invalid hosted request.\n' >&2
  exit 2
fi

readonly revision="${BASH_REMATCH[1]}"
readonly artifact_name="verification-artifacts-${revision}"
readonly artifact_path="${runner_temp}/verification-a1-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
readonly host_uid="$(id -u)"
readonly host_gid="$(id -g)"
if [[ ! "$host_uid" =~ ^[1-9][0-9]*$ || "$host_uid" == '1000' || ! "$host_gid" =~ ^[1-9][0-9]*$ ]]; then
  printf 'A1 launcher rejected an unsafe runner identity.\n' >&2
  exit 2
fi
if [[ -e "$artifact_path" ]]; then
  printf 'A1 launcher requires a new artifact staging directory.\n' >&2
  exit 2
fi
(umask 077 && mkdir -- "$artifact_path")
printf 'artifact-name=%s\nartifact-path=%s\n' "$artifact_name" "$artifact_path" >> "$GITHUB_OUTPUT"

docker run --rm \
  --user 0 \
  --cap-drop ALL \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add SETUID \
  --cap-add SETGID \
  --mount "type=bind,src=$workspace,dst=/github/workspace,readonly" \
  --mount "type=bind,src=$artifact_path,dst=/work/host-output" \
  --env GITHUB_ACTIONS \
  --env A1_VALIDATED_ARTIFACT_OUTPUT=/work/host-output \
  --env A1_VALIDATED_ARTIFACT_UID="$host_uid" \
  --env A1_VALIDATED_ARTIFACT_GID="$host_gid" \
  "$image" "$A1_HOSTED_REQUEST"
