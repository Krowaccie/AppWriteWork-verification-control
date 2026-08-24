import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { canonicalJson } from './canonical-json.mjs';

export const SOURCE_SHA = '1'.repeat(40);
export const CONTROLLER_SHA = '2'.repeat(40);
export const RUNNER_SHA = '3'.repeat(40);
export const NOW = 1_000_000;
export const TASK4A_EVALUATOR_PATHS = Object.freeze([
  'dev/verification/bootstrap/qualify-runner.mjs',
  'scripts/verification/canonical-json.mjs',
  'scripts/verification/controller-bundle.mjs',
  'scripts/verification/controller-trust-materials.mjs',
  'scripts/verification/test-cloud-bootstrap.mjs',
  'scripts/verification/test-cloud-provider-contract.mjs',
  'scripts/verification/test-cloud-setup-attestation.mjs',
]);

const corpus = JSON.parse(await readFile(
  new URL('../../dev/verification/fixtures/test-cloud-setup-readback.v1.corpus.json', import.meta.url),
  'utf8',
));
const positive = corpus.vectors.find(({ id }) => id === '01.setup.pass.canonical');

export const canonicalReadback = Object.freeze(JSON.parse(
  Buffer.from(positive.input.bytesBase64, 'base64').toString('utf8'),
));
export const canonicalReadbackDigest = positive.input.expectedDigest;

export function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function digestJson(value) {
  return digestBytes(Buffer.from(canonicalJson(value), 'utf8'));
}

export function setupAttestation({
  readback = canonicalReadback,
  nowEpochSeconds = NOW,
  retentionMaxSeconds = 3600,
  overrides = {},
} = {}) {
  return {
    credentialScopeReadbackDigest: `sha256:${'5'.repeat(64)}`,
    environmentDigest: readback.environmentDigest,
    executionObservationPolicyDigest: `sha256:${'6'.repeat(64)}`,
    expiresAtEpochSeconds: nowEpochSeconds + 100,
    fixedLeaseIdentityDigest: `sha256:${'7'.repeat(64)}`,
    functionConfigurationsDigest: `sha256:${'8'.repeat(64)}`,
    globalCleanupReadbackDigest: `sha256:${'9'.repeat(64)}`,
    identityBindingsDigest: readback.identityBindings.identityBindingsDigest,
    issuedAtEpochSeconds: nowEpochSeconds - 10,
    primaryExecutionRetentionMaxSeconds: retentionMaxSeconds,
    projectReadbackDigest: `sha256:${'a'.repeat(64)}`,
    providerContractDigest: readback.providerContractDigest,
    providerSetupReadbackDigest: canonicalReadbackDigest,
    runnerVariableReadbackDigest: `sha256:${'b'.repeat(64)}`,
    schemaVersion: 'test-cloud-setup-attestation.v1',
    siteConfigurationDigest: `sha256:${'c'.repeat(64)}`,
    ...overrides,
  };
}

export function setupBindings(options = {}) {
  const attestation = setupAttestation(options);
  return {
    readback: structuredClone(options.readback ?? canonicalReadback),
    readbackDigest: canonicalReadbackDigest,
    attestation,
    attestationDigest: digestJson(attestation),
  };
}

export function validationClock(nowEpochSeconds = NOW) {
  return Object.freeze({ nowEpochSeconds: () => nowEpochSeconds });
}

export function qualificationContext({
  nowEpochSeconds = NOW,
  retentionMaxSeconds = 3600,
} = {}) {
  return Object.freeze({
    clock: validationClock(nowEpochSeconds),
    primaryExecutionRetentionMaxSeconds: retentionMaxSeconds,
  });
}

export function qualificationArgs({
  bindings = setupBindings(),
  sourceSha = SOURCE_SHA,
  controllerSha = CONTROLLER_SHA,
  runnerSha = RUNNER_SHA,
} = {}) {
  return {
    workflowRunId: '4815162342',
    workflowHeadSha: controllerSha,
    controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: sourceSha,
    controllerRevision: controllerSha,
    runnerRevision: runnerSha,
    runnerImage: 'windows-2025',
    setupBindings: bindings,
    jobObjectQualification: {
      schemaVersion: 'windows-job-object-qualification.v1',
      status: 'PASS',
      killOnJobClose: true,
      breakawayDisabled: true,
    },
  };
}

export function evaluatorClosure() {
  return {
    entrypoint: 'scripts/verification/controller-trust-materials.mjs',
    runtime: { name: 'node', version: '24.11.1', platform: 'windows-2025' },
    files: TASK4A_EVALUATOR_PATHS.map((filePath) => ({
      path: filePath,
      mode: '100644',
      bytes: new TextEncoder().encode(`${filePath}\n`),
    })),
  };
}
