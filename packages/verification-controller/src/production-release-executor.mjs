import { createHash } from 'node:crypto';

import { productionEnvironmentDigest } from './production-readonly-environment.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RUNNER = 'verification-runner-py';
const SHA = /^[0-9a-f]{40}$/;
const APPROVAL_REF = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,254}$/;
const RELEASE_RECORD_KEYS = Object.freeze([
  'artifactLogicalTarget',
  'canonicalContentDigest',
  'deploymentLogicalTarget',
  'kind',
  'relativePath',
  'sizeBytes',
  'transportDigest',
].sort());
const COMPLETED_TARGET_KEYS = Object.freeze([
  'artifactLogicalTarget',
  'canonicalContentDigest',
  'deploymentId',
  'deploymentLogicalTarget',
  'kind',
  'transportDigest',
].sort());
const FAILED_TARGET_KEYS = Object.freeze([
  ...COMPLETED_TARGET_KEYS,
  'phase',
].sort());
const PARTIAL_RECORD_KEYS = Object.freeze([
  'approvalRef',
  'artifactManifestDigest',
  'completedTargets',
  'environmentDigest',
  'failedTarget',
  'qualifyingEvidence',
  'schemaVersion',
  'sourceRevision',
  'status',
  'verifierManifestDigest',
].sort());
const QUALIFYING_EVIDENCE_KEYS = Object.freeze(['localDigest', 'testCloudDigest']);
const DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const LOGICAL_TARGET = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PARTIAL_PHASES = Object.freeze(['upload', 'wait-ready', 'activate', 'readback']);

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  if (ArrayBuffer.isView(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0 &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

function inventoryTargets(inventory) {
  const site = inventory?.site ?? (Array.isArray(inventory?.sites) ? inventory.sites[0] : null);
  const functions = inventory?.functions ?? inventory?.productFunctions;
  const siteLogicalTarget = site?.logicalId ?? site?.logicalTarget;
  if (!site || siteLogicalTarget !== 'production-site' ||
      !Array.isArray(functions) || functions.length !== 35) {
    throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  }
  const targets = [{
    ...site,
    kind: 'site',
    artifactLogicalTarget: 'web',
    logicalTarget: siteLogicalTarget,
  }, ...functions.map((target) => {
    const logicalTarget = target.logicalId ?? target.logicalTarget;
    return {
      ...target,
      kind: 'function',
      artifactLogicalTarget: logicalTarget,
      logicalTarget,
    };
  })];
  const keys = new Set();
  for (const target of targets) {
    if (typeof target.logicalTarget !== 'string' || target.logicalTarget.length === 0 ||
        typeof target.artifactLogicalTarget !== 'string' ||
        target.artifactLogicalTarget.length === 0) {
      throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
    }
    const key = `${target.kind}:${target.logicalTarget}`;
    if (keys.has(key) || target.logicalTarget === RUNNER ||
        target.artifactLogicalTarget === RUNNER) {
      throw blocked(target.logicalTarget === RUNNER || target.artifactLogicalTarget === RUNNER
        ? 'PRODUCTION_TEST_ONLY_LEAK'
        : 'PRODUCTION_RELEASE_SET_MISMATCH');
    }
    keys.add(key);
  }
  if (keys.size !== 36) throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  return targets;
}

function recordKey(record) {
  return `${record?.kind ?? ''}:${record?.deploymentLogicalTarget ?? ''}`;
}

function assertNoRunner(handoff, files) {
  const serialized = JSON.stringify(handoff);
  if (serialized.includes(RUNNER) ||
      [...files.keys()].some((path) => String(path).includes(RUNNER))) {
    throw blocked('PRODUCTION_TEST_ONLY_LEAK');
  }
}

export function validateReleaseInput({
  inventory,
  handoff,
  files,
  expectedExcludedTestOnlyProof,
}) {
  if (!(files instanceof Map) || !handoff || typeof handoff !== 'object') {
    throw blocked('PRODUCTION_HANDOFF_INVALID');
  }
  assertNoRunner(handoff, files);
  const targets = inventoryTargets(inventory);
  const records = handoff.releaseEligibleArtifacts;
  if (!Array.isArray(records) || records.length !== 36) {
    throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  }
  const targetsByKey = new Map(targets.map((target) => [
    `${target.kind}:${target.logicalTarget}`,
    target,
  ]));
  const seenPaths = new Set();
  const selected = [];
  for (const record of records) {
    if (!exactObject(record, RELEASE_RECORD_KEYS) ||
        !['site', 'function'].includes(record.kind) ||
        !DIGEST.test(record.canonicalContentDigest ?? '') ||
        !DIGEST.test(record.transportDigest ?? '')) {
      throw blocked('PRODUCTION_HANDOFF_INVALID');
    }
    const target = targetsByKey.get(recordKey(record));
    if (!target ||
        record.artifactLogicalTarget !== target.artifactLogicalTarget) {
      throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
    }
    if (typeof record.relativePath !== 'string' ||
        record.relativePath.startsWith('/') ||
        record.relativePath.includes('..') ||
        record.relativePath.includes('\\') ||
        seenPaths.has(record.relativePath)) {
      throw blocked('PRODUCTION_HANDOFF_INVALID');
    }
    const bytes = files.get(record.relativePath);
    if (!(bytes instanceof Uint8Array) ||
        !Number.isSafeInteger(record.sizeBytes) ||
        record.sizeBytes !== bytes.byteLength ||
        record.transportDigest !== digestBytes(bytes)) {
      throw blocked('PRODUCTION_HANDOFF_ARTIFACT_MISMATCH');
    }
    seenPaths.add(record.relativePath);
    targetsByKey.delete(recordKey(record));
    selected.push(Object.freeze({ target, record, bytes }));
  }
  if (targetsByKey.size !== 0) throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
  if (files.size !== seenPaths.size ||
      [...files.keys()].some((path) => !seenPaths.has(path))) {
    throw blocked('PRODUCTION_HANDOFF_EXTRA_ARTIFACT');
  }

  const proof = handoff.excludedTestOnlyProof;
  const expectedProof = expectedExcludedTestOnlyProof;
  if (!expectedProof || expectedProof.count !== 1 ||
      !DIGEST.test(expectedProof.classificationDigest ?? '') ||
      !proof || proof.count !== 1 || !DIGEST.test(proof.classificationDigest ?? '') ||
      expectedProof.classificationDigest !== proof.classificationDigest) {
    throw blocked('PRODUCTION_EXCLUSION_PROOF_MISMATCH');
  }
  return Object.freeze(selected);
}

function deploymentIdentifier(value) {
  const id = value?.$id ?? value?.id;
  if (typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/.test(id)) {
    throw blocked('PRODUCTION_RELEASE_DEPLOYMENT_RESPONSE_INVALID');
  }
  return id;
}

async function waitUntilReady({ read, target, id, now, sleep, deadlineMs }) {
  const started = now();
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const deployment = await read(target, id);
    if (deployment?.status === 'ready') return deployment;
    if (['failed', 'cancelled', 'stuck'].includes(deployment?.status) ||
        !['waiting', 'processing', 'building', 'queued'].includes(deployment?.status)) {
      throw blocked('PRODUCTION_RELEASE_DEPLOYMENT_FAILED');
    }
    if (now() - started >= deadlineMs) throw blocked('PRODUCTION_RELEASE_POLL_TIMEOUT');
    await sleep(250);
  }
  throw blocked('PRODUCTION_RELEASE_POLL_TIMEOUT');
}

function targetBinding(target, record, deploymentId) {
  return deepFreeze({
    kind: target.kind,
    artifactLogicalTarget: record.artifactLogicalTarget,
    deploymentLogicalTarget: record.deploymentLogicalTarget,
    deploymentId,
    canonicalContentDigest: record.canonicalContentDigest,
    transportDigest: record.transportDigest,
  });
}

function validTargetIdentity(target) {
  return exactObject(target, COMPLETED_TARGET_KEYS) &&
    ['site', 'function'].includes(target.kind) &&
    LOGICAL_TARGET.test(target.artifactLogicalTarget ?? '') &&
    LOGICAL_TARGET.test(target.deploymentLogicalTarget ?? '') &&
    (target.kind === 'site'
      ? target.artifactLogicalTarget === 'web' &&
        target.deploymentLogicalTarget === 'production-site'
      : target.artifactLogicalTarget === target.deploymentLogicalTarget) &&
    DEPLOYMENT_ID.test(target.deploymentId ?? '') &&
    DIGEST.test(target.canonicalContentDigest ?? '') &&
    DIGEST.test(target.transportDigest ?? '');
}

function validFailedTarget(target) {
  if (!exactObject(target, FAILED_TARGET_KEYS) ||
      !PARTIAL_PHASES.includes(target.phase) ||
      !['site', 'function'].includes(target.kind) ||
      !LOGICAL_TARGET.test(target.artifactLogicalTarget ?? '') ||
      !LOGICAL_TARGET.test(target.deploymentLogicalTarget ?? '') ||
      (target.kind === 'site'
        ? target.artifactLogicalTarget !== 'web' ||
          target.deploymentLogicalTarget !== 'production-site'
        : target.artifactLogicalTarget !== target.deploymentLogicalTarget) ||
      !DIGEST.test(target.canonicalContentDigest ?? '') ||
      !DIGEST.test(target.transportDigest ?? '')) {
    return false;
  }
  return target.phase === 'upload'
    ? target.deploymentId === null
    : DEPLOYMENT_ID.test(target.deploymentId ?? '');
}

export function validatePartialReleaseRecord(record) {
  if (!exactObject(record, PARTIAL_RECORD_KEYS) ||
      record.schemaVersion !== 'partial-release-execution-result.v1' ||
      record.status !== 'BLOCKED' ||
      record.environmentDigest !== productionEnvironmentDigest ||
      !SHA.test(record.sourceRevision ?? '') ||
      !DIGEST.test(record.artifactManifestDigest ?? '') ||
      !DIGEST.test(record.verifierManifestDigest ?? '') ||
      !APPROVAL_REF.test(record.approvalRef ?? '') ||
      !exactObject(record.qualifyingEvidence, QUALIFYING_EVIDENCE_KEYS) ||
      !DIGEST.test(record.qualifyingEvidence.localDigest ?? '') ||
      !DIGEST.test(record.qualifyingEvidence.testCloudDigest ?? '') ||
      !Array.isArray(record.completedTargets) ||
      record.completedTargets.length > 35 ||
      !record.completedTargets.every(validTargetIdentity) ||
      !validFailedTarget(record.failedTarget)) {
    throw blocked('PRODUCTION_RELEASE_PARTIAL_RECORD_INVALID');
  }
  const seen = new Set();
  for (const target of record.completedTargets) {
    const key = `${target.kind}:${target.deploymentLogicalTarget}`;
    if (seen.has(key)) throw blocked('PRODUCTION_RELEASE_PARTIAL_RECORD_INVALID');
    seen.add(key);
  }
  if (seen.has(`${record.failedTarget.kind}:${record.failedTarget.deploymentLogicalTarget}`)) {
    throw blocked('PRODUCTION_RELEASE_PARTIAL_RECORD_INVALID');
  }
  return deepFreeze(record);
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function canonicalPartialReleaseRecordBytes(record) {
  const validated = validatePartialReleaseRecord(record);
  return new TextEncoder().encode(`${canonicalJson(validated)}\n`);
}

function partialError({
  completedTargets,
  failedTarget,
  failedRecord,
  phase,
  deploymentId,
  handoff,
  approvalRef,
}) {
  const error = blocked('PRODUCTION_RELEASE_PARTIAL_FAILURE');
  error.partialReleaseRecord = validatePartialReleaseRecord(deepFreeze({
    schemaVersion: 'partial-release-execution-result.v1',
    status: 'BLOCKED',
    environmentDigest: productionEnvironmentDigest,
    sourceRevision: handoff.sourceRevision,
    artifactManifestDigest: handoff.artifactManifestDigest,
    verifierManifestDigest: handoff.verifierManifestDigest,
    qualifyingEvidence: {
      localDigest: handoff.localEvidenceDigest,
      testCloudDigest: handoff.testCloudEvidenceDigest,
    },
    approvalRef,
    completedTargets,
    failedTarget: {
      kind: failedTarget.kind,
      artifactLogicalTarget: failedRecord.artifactLogicalTarget,
      deploymentLogicalTarget: failedRecord.deploymentLogicalTarget,
      canonicalContentDigest: failedRecord.canonicalContentDigest,
      transportDigest: failedRecord.transportDigest,
      phase,
      deploymentId,
    },
  }));
  return error;
}

function validExecutionMetadata(handoff, approvalRef) {
  return SHA.test(handoff?.sourceRevision ?? '') &&
    DIGEST.test(handoff?.artifactManifestDigest ?? '') &&
    DIGEST.test(handoff?.verifierManifestDigest ?? '') &&
    DIGEST.test(handoff?.localEvidenceDigest ?? '') &&
    DIGEST.test(handoff?.testCloudEvidenceDigest ?? '') &&
    APPROVAL_REF.test(approvalRef ?? '');
}

export async function executeProductionRelease({
  inventory,
  handoff,
  files,
  expectedExcludedTestOnlyProof,
  approvalRef,
  createClient,
  now = Date.now,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  pollDeadlineMs = 10 * 60 * 1000,
}) {
  if (!validExecutionMetadata(handoff, approvalRef)) {
    throw blocked('PRODUCTION_RELEASE_METADATA_INVALID');
  }
  const selected = validateReleaseInput({
    inventory,
    handoff,
    files,
    expectedExcludedTestOnlyProof,
  });
  if (typeof createClient !== 'function') throw blocked('PRODUCTION_RELEASE_CLIENT_FACTORY_INVALID');
  const client = createClient(selected.map(({ target }) => target));
  const completed = [];

  for (const { target, record, bytes } of selected) {
    const isSite = target.kind === 'site';
    let phase = 'upload';
    let deploymentId = null;
    try {
      const uploaded = await client[isSite
        ? 'uploadSiteDeployment'
        : 'uploadFunctionDeployment'](target, bytes);
      deploymentId = deploymentIdentifier(uploaded);
      phase = 'wait-ready';
      await waitUntilReady({
        read: client[isSite ? 'readSiteDeployment' : 'readFunctionDeployment'],
        target,
        id: deploymentId,
        now,
        sleep,
        deadlineMs: pollDeadlineMs,
      });
      phase = 'activate';
      await client[isSite
        ? 'activateSiteDeployment'
        : 'activateFunctionDeployment'](target, deploymentId);
      phase = 'readback';
      const parent = await client[isSite
        ? 'readSiteMetadata'
        : 'readFunctionMetadata'](target);
      if (parent?.deploymentId !== deploymentId) {
        throw blocked('PRODUCTION_RELEASE_PARENT_READBACK_MISMATCH');
      }
      completed.push(targetBinding(target, record, deploymentId));
    } catch {
      throw partialError({
        completedTargets: completed,
        failedTarget: target,
        failedRecord: record,
        phase,
        deploymentId,
        handoff,
        approvalRef,
      });
    }
  }

  return deepFreeze({
    schemaVersion: 'release-execution-result.v1',
    status: 'PASS',
    environmentDigest: productionEnvironmentDigest,
    sourceRevision: handoff.sourceRevision,
    artifactManifestDigest: handoff.artifactManifestDigest,
    verifierManifestDigest: handoff.verifierManifestDigest,
    qualifyingEvidence: {
      localDigest: handoff.localEvidenceDigest,
      testCloudDigest: handoff.testCloudEvidenceDigest,
    },
    approvalRef,
    targets: completed,
  });
}
