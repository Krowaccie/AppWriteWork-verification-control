import { createHash } from 'node:crypto';

import { validateReleaseInput } from './production-release-executor.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SHA = /^[0-9a-f]{40}$/;
const RUNNER = 'verification-runner-py';
const LOGICAL_TARGET = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SAFE_PATH_TEXT = /^[^\\\u0000-\u001f\u007f]+$/;
const HANDOFF_KEYS = Object.freeze([
  'artifactManifestDigest',
  'cleanupDebt',
  'controllerBundleDigest',
  'controllerRevision',
  'excludedTestOnlyProof',
  'localEvidenceDigest',
  'qualifyingStatus',
  'releaseEligibleArtifacts',
  'schemaVersion',
  'sourceArchiveDigest',
  'sourceArtifactId',
  'sourceArtifactName',
  'sourceRepositoryId',
  'sourceRevision',
  'sourceRunAttempt',
  'sourceRunId',
  'sourceWorkflowId',
  'testCloudEvidenceDigest',
  'testLeaseStatus',
  'verifierManifestDigest',
].sort());
const RECORD_KEYS = Object.freeze([
  'artifactLogicalTarget',
  'canonicalContentDigest',
  'deploymentLogicalTarget',
  'kind',
  'relativePath',
  'sizeBytes',
  'transportDigest',
].sort());
const PROOF_KEYS = Object.freeze(['classificationDigest', 'count']);

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function exactPlainObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0 ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys)) return false;
  return Object.values(Object.getOwnPropertyDescriptors(value))
    .every((descriptor) => Object.hasOwn(descriptor, 'value'));
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw blocked('PRODUCTION_HANDOFF_INVALID');
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function sha(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sourceTargetKey(value) {
  return `${value?.kind ?? ''}:${value?.logicalTarget ?? value?.artifactLogicalTarget ?? ''}`;
}

function isSafeRepositoryPath(value) {
  return typeof value === 'string' && value.length > 0 &&
    SAFE_PATH_TEXT.test(value) &&
    !value.startsWith('/') &&
    !/^[A-Za-z]:\//.test(value) &&
    !value.includes('//') &&
    !value.split('/').some((part) => part === '.' || part === '..');
}

function inventoryMappings(inventory) {
  const site = inventory?.site ?? inventory?.sites?.[0];
  const functions = inventory?.functions ?? inventory?.productFunctions;
  const siteLogicalId = site?.logicalId ?? site?.logicalTarget;
  if (!site || siteLogicalId !== 'production-site' ||
      !Array.isArray(functions) || functions.length !== 35) {
    throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  }
  const records = [{
    kind: 'site',
    artifactLogicalTarget: 'web',
    deploymentLogicalTarget: siteLogicalId,
  }, ...functions.map((value) => ({
    kind: 'function',
    artifactLogicalTarget: value.logicalId ?? value.logicalTarget,
    deploymentLogicalTarget: value.logicalId ?? value.logicalTarget,
  }))];
  const mappings = new Map();
  for (const record of records) {
    if (!LOGICAL_TARGET.test(record.artifactLogicalTarget ?? '') ||
        !LOGICAL_TARGET.test(record.deploymentLogicalTarget ?? '')) {
      throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
    }
    const key = `${record.kind}:${record.artifactLogicalTarget}`;
    if (mappings.has(key) || record.artifactLogicalTarget === RUNNER) {
      throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
    }
    mappings.set(key, Object.freeze(record));
  }
  if (mappings.size !== 36) throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  return mappings;
}

function validateSourceRecord(record, files) {
  if (!record || !['site', 'function'].includes(record.kind) ||
      !LOGICAL_TARGET.test(record.logicalTarget ?? '') ||
      !isSafeRepositoryPath(record.relativePath) ||
      !DIGEST.test(record.canonicalContentDigest ?? '') ||
      !DIGEST.test(record.transportDigest ?? '') ||
      !Number.isSafeInteger(record.sizeBytes) || record.sizeBytes < 0) {
    throw blocked('PRODUCTION_HANDOFF_INVALID');
  }
  const bytes = files.get(record.relativePath);
  if (!(bytes instanceof Uint8Array) ||
      bytes.byteLength !== record.sizeBytes ||
      sha(bytes) !== record.transportDigest) {
    throw blocked('PRODUCTION_HANDOFF_ARTIFACT_MISMATCH');
  }
}

export function buildVerifiedProductionHandoff({ source, inventory, files }) {
  if (!(files instanceof Map) || !source || typeof source !== 'object') {
    throw blocked('PRODUCTION_HANDOFF_INVALID');
  }
  if (JSON.stringify(source.releaseEligibleArtifacts).includes(RUNNER)) {
    throw blocked('PRODUCTION_TEST_ONLY_LEAK');
  }
  const expected = inventoryMappings(inventory);
  const release = source.releaseEligibleArtifacts;
  if (!Array.isArray(release) || release.length !== 36) {
    throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  }
  const releaseFiles = new Map();
  const records = [];
  for (const record of release) {
    validateSourceRecord(record, files);
    const mapping = expected.get(sourceTargetKey(record));
    if (!mapping) throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
    expected.delete(sourceTargetKey(record));
    if (releaseFiles.has(record.relativePath)) throw blocked('PRODUCTION_HANDOFF_INVALID');
    releaseFiles.set(record.relativePath, files.get(record.relativePath));
    records.push(Object.freeze({
      kind: record.kind,
      artifactLogicalTarget: mapping.artifactLogicalTarget,
      deploymentLogicalTarget: mapping.deploymentLogicalTarget,
      relativePath: record.relativePath,
      canonicalContentDigest: record.canonicalContentDigest,
      transportDigest: record.transportDigest,
      sizeBytes: record.sizeBytes,
    }));
  }
  if (expected.size !== 0) throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');

  const testOnly = source.testOnlyArtifacts;
  if (!Array.isArray(testOnly) || testOnly.length !== 1 ||
      testOnly[0]?.kind !== 'function' || testOnly[0]?.logicalTarget !== RUNNER ||
      testOnly[0]?.relativePath !== 'functions/verification-runner-py.tar.gz') {
    throw blocked('PRODUCTION_TEST_ONLY_SET_MISMATCH');
  }
  validateSourceRecord(testOnly[0], files);
  const excludedTestOnlyProof = Object.freeze({
    count: 1,
    classificationDigest: sha(Buffer.from(canonical(testOnly[0]), 'utf8')),
  });
  records.sort((left, right) => left.relativePath.localeCompare(right.relativePath, 'en'));

  const handoff = Object.freeze({
    schemaVersion: 'verified-production-handoff.v1',
    controllerRevision: source.controllerRevision,
    controllerBundleDigest: source.controllerBundleDigest,
    sourceRepositoryId: source.sourceRepositoryId,
    sourceWorkflowId: source.sourceWorkflowId,
    sourceRunId: source.sourceRunId,
    sourceRunAttempt: source.sourceRunAttempt,
    sourceArtifactId: source.sourceArtifactId,
    sourceArtifactName: source.sourceArtifactName,
    sourceArchiveDigest: source.sourceArchiveDigest,
    sourceRevision: source.sourceRevision,
    artifactManifestDigest: source.artifactManifestDigest,
    verifierManifestDigest: source.verifierManifestDigest,
    localEvidenceDigest: source.localEvidenceDigest,
    testCloudEvidenceDigest: source.testCloudEvidenceDigest,
    qualifyingStatus: source.qualifyingStatus,
    testLeaseStatus: source.testLeaseStatus,
    cleanupDebt: source.cleanupDebt,
    releaseEligibleArtifacts: Object.freeze(records),
    excludedTestOnlyProof,
  });
  assertClosedHandoff(handoff);
  return Object.freeze({ handoff, files: releaseFiles });
}

function assertClosedHandoff(handoff) {
  if (!exactPlainObject(handoff, HANDOFF_KEYS) ||
      handoff.schemaVersion !== 'verified-production-handoff.v1' ||
      !SHA.test(handoff.controllerRevision ?? '') ||
      !SHA.test(handoff.sourceRevision ?? '') ||
      !DIGEST.test(handoff.controllerBundleDigest ?? '') ||
      !DIGEST.test(handoff.sourceArchiveDigest ?? '') ||
      !DIGEST.test(handoff.artifactManifestDigest ?? '') ||
      !DIGEST.test(handoff.verifierManifestDigest ?? '') ||
      !DIGEST.test(handoff.localEvidenceDigest ?? '') ||
      !DIGEST.test(handoff.testCloudEvidenceDigest ?? '') ||
      ![handoff.sourceRepositoryId, handoff.sourceWorkflowId, handoff.sourceRunId,
        handoff.sourceRunAttempt, handoff.sourceArtifactId]
        .every((value) => Number.isSafeInteger(value) && value > 0) ||
      handoff.sourceArtifactName !== `verification-artifacts-${handoff.sourceRevision}` ||
      handoff.qualifyingStatus !== 'PASS' || handoff.testLeaseStatus !== 'idle' ||
      handoff.cleanupDebt !== false ||
      !Array.isArray(handoff.releaseEligibleArtifacts) ||
      handoff.releaseEligibleArtifacts.length !== 36 ||
      !exactPlainObject(handoff.excludedTestOnlyProof, PROOF_KEYS) ||
      handoff.excludedTestOnlyProof.count !== 1 ||
      !DIGEST.test(handoff.excludedTestOnlyProof.classificationDigest ?? '')) {
    throw blocked('PRODUCTION_HANDOFF_INVALID');
  }
  let prior = '';
  const paths = new Set();
  const artifactTargets = new Set();
  const deploymentTargets = new Set();
  for (const record of handoff.releaseEligibleArtifacts) {
    if (!exactPlainObject(record, RECORD_KEYS) ||
        !['site', 'function'].includes(record.kind) ||
        !LOGICAL_TARGET.test(record.artifactLogicalTarget ?? '') ||
        !LOGICAL_TARGET.test(record.deploymentLogicalTarget ?? '') ||
        !isSafeRepositoryPath(record.relativePath) ||
        !DIGEST.test(record.canonicalContentDigest ?? '') ||
        !DIGEST.test(record.transportDigest ?? '') ||
        !Number.isSafeInteger(record.sizeBytes) || record.sizeBytes < 0 ||
        record.relativePath.localeCompare(prior, 'en') < 0 ||
        paths.has(record.relativePath)) {
      throw blocked('PRODUCTION_HANDOFF_INVALID');
    }
    const artifactKey = `${record.kind}:${record.artifactLogicalTarget}`;
    const deploymentKey = `${record.kind}:${record.deploymentLogicalTarget}`;
    if (artifactTargets.has(artifactKey) || deploymentTargets.has(deploymentKey)) {
      throw blocked('PRODUCTION_HANDOFF_INVALID');
    }
    prior = record.relativePath;
    paths.add(record.relativePath);
    artifactTargets.add(artifactKey);
    deploymentTargets.add(deploymentKey);
  }
}

export function validateVerifiedProductionHandoff({
  handoff,
  files,
  inventory,
  expectedExcludedTestOnlyProof,
}) {
  assertClosedHandoff(handoff);
  if (!exactPlainObject(expectedExcludedTestOnlyProof, PROOF_KEYS) ||
      expectedExcludedTestOnlyProof.count !== 1 ||
      !DIGEST.test(expectedExcludedTestOnlyProof.classificationDigest ?? '') ||
      expectedExcludedTestOnlyProof.classificationDigest !== handoff.excludedTestOnlyProof.classificationDigest) {
    throw blocked('PRODUCTION_EXCLUSION_PROOF_MISMATCH');
  }
  return validateReleaseInput({
    inventory,
    handoff,
    files,
    expectedExcludedTestOnlyProof,
  });
}
