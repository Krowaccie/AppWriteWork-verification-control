import { createHash } from 'node:crypto';

import {
  canonicalReleaseJson,
  digestReleaseRecord,
  validateProductionReleaseBinding,
  validateReleaseRecord,
} from './release-record-contract.mjs';

export { digestReleaseRecord };

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SHA = /^[0-9a-f]{40}$/;
const ID = /^[1-9][0-9]*$/;
const LOGICAL_TARGET = /^[a-z0-9][a-z0-9-]*$/;
const DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const ENVIRONMENT = 'production-release';
const DEFAULT_MAX_RECORD_AGE_MS = 24 * 60 * 60 * 1000;
const EXPECTED_TARGET_KEYS = Object.freeze([
  'site:web:production-site',
  'function:api-keys-py:api-keys-py',
  'function:api-router-py:api-router-py',
  'function:billing-cron-py:billing-cron-py',
  'function:billing-py:billing-py',
  'function:billing-webhook-py:billing-webhook-py',
  'function:branch-py:branch-py',
  'function:cache-cleanup-cron-py:cache-cleanup-cron-py',
  'function:catalog-py:catalog-py',
  'function:chat-py:chat-py',
  'function:cleanup-cron-py:cleanup-cron-py',
  'function:connections-py:connections-py',
  'function:finance-sync-sec-py:finance-sync-sec-py',
  'function:finance-sync-wb-py:finance-sync-wb-py',
  'function:flowise-runner-py:flowise-runner-py',
  'function:mcp-cleanup-cron-py:mcp-cleanup-cron-py',
  'function:mcp-gateway-py:mcp-gateway-py',
  'function:project-public-links-py:project-public-links-py',
  'function:project-public-read-py:project-public-read-py',
  'function:project-snapshots-py:project-snapshots-py',
  'function:runs-cancel-py:runs-cancel-py',
  'function:runs-clear-py:runs-clear-py',
  'function:runs-create-py:runs-create-py',
  'function:runs-detail-py:runs-detail-py',
  'function:runs-list-py:runs-list-py',
  'function:runs-status-py:runs-status-py',
  'function:runs-steps-py:runs-steps-py',
  'function:sec-cache-builder-py:sec-cache-builder-py',
  'function:sharing-py:sharing-py',
  'function:smtp-diagnostic-py:smtp-diagnostic-py',
  'function:telemetry-py:telemetry-py',
  'function:usage-cron-py:usage-cron-py',
  'function:usage-py:usage-py',
  'function:validate-py:validate-py',
  'function:verification-email-py:verification-email-py',
  'function:worker-cron-py:worker-cron-py',
]);

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function blocked(code) {
  return Object.freeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: Object.freeze([Object.freeze({
      code,
      safeMessage: 'Trusted production release record could not be established.',
      retryable: false,
    })]),
  });
}

function pass(value) {
  return Object.freeze({ status: 'PASS', value: deepFreeze(value), diagnostics: Object.freeze([]) });
}

function hasExactKeys(value, expected) {
  return (
    value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.getOwnPropertySymbols(value).length === 0
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
    && Object.values(Object.getOwnPropertyDescriptors(value))
      .every((descriptor) => Object.hasOwn(descriptor, 'value'))
  );
}

function validController(value) {
  return (
    hasExactKeys(value, [
      'bundleDigest',
      'repository',
      'sha',
      'trustedBundleDigest',
      'trustedControllerSha',
    ])
    && value.repository === REPOSITORY
    && SHA.test(value.sha)
    && value.sha === value.trustedControllerSha
    && DIGEST.test(value.bundleDigest)
    && value.bundleDigest === value.trustedBundleDigest
  );
}

function validCredential(value) {
  return (
    hasExactKeys(value, ['credentialClass', 'readSecret', 'scopes', 'variableName'])
    && Object.isFrozen(value)
    && value.credentialClass === 'github-deployments-read'
    && value.variableName === 'GITHUB_TOKEN'
    && Array.isArray(value.scopes)
    && Object.isFrozen(value.scopes)
    && JSON.stringify(value.scopes) === JSON.stringify(['actions:read', 'deployments:read'])
    && typeof value.readSecret === 'function'
  );
}

function validDeployment(value, artifactId) {
  try {
    if (!hasExactKeys(value, ['createdAt', 'id', 'payload', 'protected', 'state'])) return false;
    if (
      !ID.test(String(value.id))
      || value.state !== 'success'
      || value.protected !== true
      || !Number.isFinite(Date.parse(value.createdAt))
    ) return false;
    validateProductionReleaseBinding(value.payload);
    return value.payload.recordArtifactId === artifactId;
  } catch {
    return false;
  }
}

function validRecord(value, binding) {
  try {
    validateReleaseRecord(value);
    return value.recordDigest === binding.recordDigest
      && value.sourceRevision === binding.revision
      && value.artifactManifestDigest === binding.artifactManifestDigest
      && value.github.repository === binding.repository
      && value.github.workflow === binding.workflow
      && value.github.runId === binding.runId
      && value.github.runAttempt === binding.runAttempt
      && value.github.environment === binding.environment;
  } catch {
    return false;
  }
}

function parseCanonicalRecord(bytes) {
  if (!(bytes instanceof Uint8Array)) return null;
  try {
    const snapshot = Buffer.from(bytes);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(snapshot);
    const value = JSON.parse(text);
    const expectedBytes = Buffer.from(`${canonicalReleaseJson(value)}\n`, 'utf8');
    if (!snapshot.equals(expectedBytes)) return null;
    return value;
  } catch {
    return null;
  }
}

export function createGithubDeploymentReader({
  controller,
  credentialHandle,
  transport,
  now = Date.now,
  maxRecordAgeMs = DEFAULT_MAX_RECORD_AGE_MS,
} = {}) {
  const readTrustedReleaseRecord = async ({ artifactId } = {}) => {
    if (!validController(controller)) return blocked('CONTROLLER_ATTESTATION_MISMATCH');
    if (!validCredential(credentialHandle)) return blocked('GITHUB_CREDENTIAL_INVALID');
    if (
      typeof artifactId !== 'string'
      || !ID.test(artifactId)
      || typeof transport?.listDeployments !== 'function'
      || typeof transport?.downloadArtifact !== 'function'
      || typeof now !== 'function'
      || !Number.isSafeInteger(maxRecordAgeMs)
      || maxRecordAgeMs <= 0
    ) return blocked('RELEASE_RECORD_INPUT_INVALID');

    let secret;
    try {
      secret = credentialHandle.readSecret();
    } catch {
      return blocked('GITHUB_CREDENTIAL_UNAVAILABLE');
    }
    if (typeof secret !== 'string' || secret.length === 0) return blocked('GITHUB_CREDENTIAL_UNAVAILABLE');

    let deployments;
    try {
      deployments = await transport.listDeployments({
        repository: REPOSITORY,
        environment: ENVIRONMENT,
        artifactId,
        authorization: secret,
      });
    } catch {
      return blocked('RELEASE_DEPLOYMENT_READ_FAILED');
    }
    if (!Array.isArray(deployments)) return blocked('RELEASE_DEPLOYMENT_AMBIGUOUS');
    const matches = deployments.filter((deployment) => validDeployment(deployment, artifactId));
    if (matches.length === 0) return blocked('RELEASE_DEPLOYMENT_UNTRUSTED');
    if (matches.length !== 1) return blocked('RELEASE_DEPLOYMENT_AMBIGUOUS');
    const deployment = matches[0];

    let nowMs;
    try {
      nowMs = now();
    } catch {
      return blocked('RELEASE_RECORD_CLOCK_INVALID');
    }
    const createdAtMs = Date.parse(deployment.createdAt);
    if (
      !Number.isFinite(nowMs)
      || createdAtMs > nowMs
      || nowMs - createdAtMs > maxRecordAgeMs
    ) return blocked('RELEASE_RECORD_STALE');

    let bytes;
    try {
      bytes = await transport.downloadArtifact({
        repository: REPOSITORY,
        artifactId: deployment.payload.recordArtifactId,
        authorization: secret,
      });
    } catch {
      return blocked('RELEASE_RECORD_DOWNLOAD_FAILED');
    }
    if (!(bytes instanceof Uint8Array)) return blocked('RELEASE_RECORD_INVALID');
    const snapshot = Buffer.from(bytes);
    if (digestBytes(snapshot) !== deployment.payload.recordArtifactDigest) {
      return blocked('RELEASE_RECORD_ARTIFACT_DIGEST_MISMATCH');
    }
    const record = parseCanonicalRecord(snapshot);
    if (!validRecord(record, deployment.payload)) return blocked('RELEASE_RECORD_INVALID');

    return pass({
      record: structuredClone(record),
      recordArtifactDigest: deployment.payload.recordArtifactDigest,
      recordDigest: deployment.payload.recordDigest,
      releaseBinding: structuredClone(deployment.payload),
    });
  };
  return Object.freeze({ readTrustedReleaseRecord });
}
