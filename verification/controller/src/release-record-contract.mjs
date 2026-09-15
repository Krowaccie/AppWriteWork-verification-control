import { createHash } from 'node:crypto';

import {
  productionEnvironmentDigest,
  productionInventory,
} from './production-readonly-environment.mjs';

const APPROVAL_REF = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,254}$/;
const DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[1-9][0-9]*$/;
const LOGICAL_TARGET = /^[a-z0-9][a-z0-9-]*$/;
const SHA = /^[0-9a-f]{40}$/;
const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const WORKFLOW = 'Release Production';
const ENVIRONMENT = 'production-release';
const EXECUTION_KEYS = Object.freeze([
  'approvalRef',
  'artifactManifestDigest',
  'environmentDigest',
  'qualifyingEvidence',
  'schemaVersion',
  'sourceRevision',
  'status',
  'targets',
  'verifierManifestDigest',
].sort());
const RECORD_KEYS = Object.freeze([
  'approvalRef',
  'artifactManifestDigest',
  'environmentDigest',
  'github',
  'qualifyingEvidence',
  'recordDigest',
  'schemaVersion',
  'sourceRevision',
  'targets',
  'verifierManifestDigest',
].sort());
const GITHUB_KEYS = Object.freeze([
  'environment',
  'repository',
  'runAttempt',
  'runId',
  'workflow',
].sort());
const BINDING_KEYS = Object.freeze([
  'artifactManifestDigest',
  'environment',
  'recordArtifactDigest',
  'recordArtifactId',
  'recordDigest',
  'repository',
  'revision',
  'runAttempt',
  'runId',
  'schemaVersion',
  'workflow',
].sort());
const EVIDENCE_KEYS = Object.freeze(['localDigest', 'testCloudDigest']);
const TARGET_KEYS = Object.freeze([
  'artifactLogicalTarget',
  'canonicalContentDigest',
  'deploymentId',
  'deploymentLogicalTarget',
  'kind',
  'transportDigest',
].sort());
const EXPECTED_TARGET_KEYS = Object.freeze([
  `site:web:${productionInventory.site.logicalId}`,
  ...productionInventory.productFunctions.map(
    ({ logicalId }) => `function:${logicalId}:${logicalId}`,
  ),
].sort());

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0 &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys) &&
    Object.values(Object.getOwnPropertyDescriptors(value))
      .every((descriptor) => Object.hasOwn(descriptor, 'value'));
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  if (ArrayBuffer.isView(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

export function canonicalReleaseJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw blocked('RELEASE_RECORD_INVALID');
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalReleaseJson).join(',')}]`;
  }
  if (!exactObject(value, Object.keys(value).sort())) {
    throw blocked('RELEASE_RECORD_INVALID');
  }
  return `{${Object.keys(value).sort().map(
    (key) => `${JSON.stringify(key)}:${canonicalReleaseJson(value[key])}`,
  ).join(',')}}`;
}

export function digestReleaseRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw blocked('RELEASE_RECORD_INVALID');
  }
  const copy = { ...value };
  delete copy.recordDigest;
  return `sha256:${createHash('sha256')
    .update(canonicalReleaseJson(copy), 'utf8')
    .digest('hex')}`;
}

function validGithub(value) {
  return exactObject(value, GITHUB_KEYS) &&
    value.repository === REPOSITORY &&
    value.workflow === WORKFLOW &&
    typeof value.runId === 'string' && ID.test(value.runId) &&
    Number.isInteger(value.runAttempt) && value.runAttempt >= 1 &&
    value.environment === ENVIRONMENT;
}

function validEvidence(value) {
  return exactObject(value, EVIDENCE_KEYS) &&
    DIGEST.test(value.localDigest) &&
    DIGEST.test(value.testCloudDigest);
}

function validBinding(value) {
  return exactObject(value, BINDING_KEYS) &&
    value.schemaVersion === 'production-release-binding.v1' &&
    typeof value.recordArtifactId === 'string' &&
    ID.test(value.recordArtifactId) &&
    DIGEST.test(value.recordArtifactDigest) &&
    DIGEST.test(value.recordDigest) &&
    SHA.test(value.revision) &&
    DIGEST.test(value.artifactManifestDigest) &&
    value.repository === REPOSITORY &&
    value.workflow === WORKFLOW &&
    typeof value.runId === 'string' &&
    ID.test(value.runId) &&
    Number.isInteger(value.runAttempt) &&
    value.runAttempt >= 1 &&
    value.environment === ENVIRONMENT;
}

function validTargets(value) {
  if (!Array.isArray(value) || value.length !== EXPECTED_TARGET_KEYS.length) return false;
  const actual = [];
  const deployments = new Set();
  for (const target of value) {
    if (!exactObject(target, TARGET_KEYS) ||
        !['site', 'function'].includes(target.kind) ||
        !LOGICAL_TARGET.test(target.artifactLogicalTarget) ||
        !LOGICAL_TARGET.test(target.deploymentLogicalTarget) ||
        !DEPLOYMENT_ID.test(target.deploymentId) ||
        !DIGEST.test(target.canonicalContentDigest) ||
        !DIGEST.test(target.transportDigest) ||
        deployments.has(target.deploymentLogicalTarget) ||
        (target.kind === 'site' && (
          target.artifactLogicalTarget !== 'web' ||
          target.deploymentLogicalTarget !== productionInventory.site.logicalId
        )) ||
        (target.kind === 'function' &&
          target.artifactLogicalTarget !== target.deploymentLogicalTarget)) {
      return false;
    }
    deployments.add(target.deploymentLogicalTarget);
    actual.push(
      `${target.kind}:${target.artifactLogicalTarget}:${target.deploymentLogicalTarget}`,
    );
  }
  return JSON.stringify(actual.sort()) === JSON.stringify(EXPECTED_TARGET_KEYS);
}

function validExecutionResult(value) {
  return exactObject(value, EXECUTION_KEYS) &&
    value.schemaVersion === 'release-execution-result.v1' &&
    value.status === 'PASS' &&
    value.environmentDigest === productionEnvironmentDigest &&
    SHA.test(value.sourceRevision) &&
    DIGEST.test(value.artifactManifestDigest) &&
    DIGEST.test(value.verifierManifestDigest) &&
    validEvidence(value.qualifyingEvidence) &&
    APPROVAL_REF.test(value.approvalRef) &&
    validTargets(value.targets);
}

function validRecord(value) {
  return exactObject(value, RECORD_KEYS) &&
    value.schemaVersion === 'release-record.v1' &&
    DIGEST.test(value.recordDigest) &&
    value.recordDigest === digestReleaseRecord(value) &&
    value.environmentDigest === productionEnvironmentDigest &&
    SHA.test(value.sourceRevision) &&
    DIGEST.test(value.artifactManifestDigest) &&
    DIGEST.test(value.verifierManifestDigest) &&
    validEvidence(value.qualifyingEvidence) &&
    APPROVAL_REF.test(value.approvalRef) &&
    validGithub(value.github) &&
    validTargets(value.targets);
}

export function validateProductionReleaseBinding(value) {
  if (!validBinding(value)) throw blocked('PRODUCTION_RELEASE_BINDING_INVALID');
  return value;
}

export function validateReleaseExecutionResult(value) {
  if (!validExecutionResult(value)) throw blocked('RELEASE_EXECUTION_RESULT_INVALID');
  return value;
}

export function validateReleaseRecord(value) {
  if (!validRecord(value)) throw blocked('RELEASE_RECORD_INVALID');
  return value;
}

export function buildReleaseRecord({ executionResult, github } = {}) {
  validateReleaseExecutionResult(executionResult);
  if (!validGithub(github)) throw blocked('RELEASE_RECORD_INVALID');
  const core = {
    schemaVersion: 'release-record.v1',
    environmentDigest: executionResult.environmentDigest,
    sourceRevision: executionResult.sourceRevision,
    artifactManifestDigest: executionResult.artifactManifestDigest,
    verifierManifestDigest: executionResult.verifierManifestDigest,
    qualifyingEvidence: structuredClone(executionResult.qualifyingEvidence),
    approvalRef: executionResult.approvalRef,
    github: structuredClone(github),
    targets: structuredClone(executionResult.targets),
  };
  const record = { ...core, recordDigest: digestReleaseRecord(core) };
  validateReleaseRecord(record);
  return deepFreeze(record);
}

export function canonicalReleaseRecordBytes(record) {
  validateReleaseRecord(record);
  return Buffer.from(`${canonicalReleaseJson(record)}\n`, 'utf8');
}

export const productionReleaseRecordContract = deepFreeze({
  bindingSchemaVersion: 'production-release-binding.v1',
  environment: ENVIRONMENT,
  repository: REPOSITORY,
  workflow: WORKFLOW,
});
