import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { validateArtifactManifest } from './artifact-manifest.mjs';
import { isTrustedControllerContext } from './controller-bundle.mjs';
import { validateHostedSiteBuildIdentity } from './hosted-site-build-identity.mjs';

const FULL_SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_PATH = /^(?!\/)(?![A-Za-z]:\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const PRODUCT_FUNCTION_IDS = Object.freeze(
  inventory.productFunctions.map(({ logicalId }) => logicalId).sort(),
);
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'buffer',
).get;
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'byteLength',
).get;
const TYPED_ARRAY_BYTE_OFFSET = Object.getOwnPropertyDescriptor(
  TYPED_ARRAY_PROTOTYPE,
  'byteOffset',
).get;

const ARGUMENT_KEYS = Object.freeze([
  'controller',
  'selection',
  'artifactSet',
  'clients',
  'clock',
  'evidenceWriter',
].sort());
const SELECTION_KEYS = Object.freeze([
  'repository',
  'workflow',
  'workflowRunId',
  'workflowRunAttempt',
  'sourceRef',
  'sourceRevision',
  'artifactId',
  'artifactName',
  'archiveDigest',
].sort());
const CLIENT_KEYS = Object.freeze([
  'preflight',
  'acquireLease',
  'deployFunctionArtifacts',
  'deploySiteArtifact',
  'qualifyRunner',
  'runE2E',
  'cleanup',
  'proveAbsence',
  'closeLease',
].sort());
const CLOCK_KEYS = Object.freeze(['now']);
const WRITER_KEYS = Object.freeze(['write']);
const DEPLOYMENT_KEYS = Object.freeze([
  'activeDeploymentId',
  'artifactTransportDigest',
  'deploymentId',
  'kind',
  'logicalTarget',
  'status',
]);
const ARTIFACT_SET_KEYS = Object.freeze([
  'artifactManifest',
  'artifactManifestDigest',
  'buildIdentity',
  'handoff',
  'releaseEligibleArtifacts',
  'testOnlyArtifacts',
]);
const BUILT_ARTIFACT_KEYS = Object.freeze([
  'bytes',
  'canonicalContentDigest',
  'kind',
  'logicalTarget',
  'relativePath',
  'sizeBytes',
  'transportDigest',
]);
const HANDOFF_KEYS = Object.freeze([
  'artifactManifestDigest',
  'artifactName',
  'schemaVersion',
  'sourceRef',
  'sourceRepository',
  'sourceRevision',
  'sourceWorkflow',
  'sourceWorkflowRunAttempt',
  'sourceWorkflowRunId',
  'verifierManifestDigest',
]);
const CONTROLLER_RESULT_KEYS = Object.freeze(['diagnostics', 'status', 'value']);
const DIAGNOSTIC_KEYS = Object.freeze(['code', 'retryable', 'safeMessage']);
const E2E_PASS_KEYS = Object.freeze(['capability', 'lease', 'passed']);
const E2E_FAILURE_STATE_KEYS = Object.freeze(['capability', 'lease']);
const BUILD_IDENTITY_KEYS = Object.freeze([
  'schemaVersion',
  'sourceRevision',
  'sitePayloadDigest',
  'verifierManifestDigest',
].sort());
const ARTIFACT_MANIFEST_KEYS = Object.freeze([
  'artifactManifestDigest',
  'artifacts',
  'schemaVersion',
  'sourceRevision',
  'sourceTreeDigest',
  'verifierManifestDigest',
].sort());
const ARTIFACT_MANIFEST_ENTRY_KEYS = Object.freeze([
  'canonicalContentDigest',
  'kind',
  'logicalTarget',
  'relativePath',
  'sizeBytes',
  'sourcePath',
  'transportDigest',
].sort());

function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || ArrayBuffer.isView(value)
    || seen.has(value)
  ) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

function safeMessage(code) {
  const messages = {
    TRUSTED_CONTROLLER_REQUIRED: 'A protected immutable controller is required.',
    SOURCE_ARTIFACT_INVALID: 'The source artifact selection is invalid.',
    TEST_CLOUD_PREFLIGHT_BLOCKED: 'The test-cloud preflight was blocked.',
    LEASE_ACQUIRE_BLOCKED: 'The test-cloud lease could not be acquired.',
    FUNCTION_DEPLOYMENT_FAILED: 'A test Function deployment did not qualify.',
    SITE_DEPLOYMENT_FAILED: 'The test Site deployment did not qualify.',
    RUNNER_QUALIFICATION_FAILED: 'The trusted runner qualification failed.',
    E2E_FAILED: 'The trusted test-cloud browser scenarios failed.',
    CLEANUP_DEBT: 'Cleanup absence could not be proved.',
    EVIDENCE_WRITE_BLOCKED: 'The closed test-cloud evidence could not be written.',
  };
  return messages[code] ?? 'The test-cloud lane was blocked.';
}

function result(status, value, code = null, retryable = false) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null
      ? []
      : [{ code, safeMessage: safeMessage(code), retryable }],
  });
}

function exactDataObject(value, expectedKeys) {
  try {
    if (
      utilTypes.isProxy(value)
      || value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return false;
    const keys = Object.getOwnPropertyNames(value).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    if (
      keys.length !== sortedExpectedKeys.length
      || keys.some((key, index) => key !== sortedExpectedKeys[index])
    ) return false;
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined
        && descriptor.enumerable === true
        && Object.hasOwn(descriptor, 'value');
    });
  } catch {
    return false;
  }
}

function clientError() {
  const error = new TypeError('Test-cloud client facade is invalid');
  error.code = 'TEST_CLOUD_CLIENTS_INVALID';
  return error;
}

function argumentError() {
  const error = new TypeError('Test-cloud lane dependencies are invalid');
  error.code = 'TEST_CLOUD_LANE_ARGUMENTS_INVALID';
  return error;
}

function validateDependencies(args) {
  if (!exactDataObject(args.clients, CLIENT_KEYS)) throw clientError();
  if (CLIENT_KEYS.some((key) => typeof args.clients[key] !== 'function')) throw clientError();
  if (
    !exactDataObject(args.clock, CLOCK_KEYS)
    || typeof args.clock.now !== 'function'
    || !exactDataObject(args.evidenceWriter, WRITER_KEYS)
    || typeof args.evidenceWriter.write !== 'function'
  ) throw argumentError();
}

function validSelection(value) {
  return exactDataObject(value, SELECTION_KEYS)
    && value.repository === 'Krowaccie/AppWriteWork'
    && value.workflow === 'Verify Main'
    && typeof value.workflowRunId === 'string'
    && SAFE_ID.test(value.workflowRunId)
    && Number.isSafeInteger(value.workflowRunAttempt)
    && value.workflowRunAttempt > 0
    && value.sourceRef === 'refs/heads/main'
    && typeof value.sourceRevision === 'string'
    && FULL_SHA.test(value.sourceRevision)
    && typeof value.artifactId === 'string'
    && SAFE_ID.test(value.artifactId)
    && value.artifactName === `verification-artifacts-${value.sourceRevision}`
    && typeof value.archiveDigest === 'string'
    && DIGEST.test(value.archiveDigest);
}

function denseDataArray(value) {
  try {
    if (
      utilTypes.isProxy(value)
      || !Array.isArray(value)
      || Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return false;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || !names.includes('length')) return false;
    for (let index = 0; index < value.length; index += 1) {
      const key = String(index);
      if (!names.includes(key)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor?.enumerable !== true
        || !Object.hasOwn(descriptor, 'value')
      ) return false;
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    return lengthDescriptor?.enumerable === false
      && Object.hasOwn(lengthDescriptor, 'value')
      && lengthDescriptor.value === value.length;
  } catch {
    return false;
  }
}

function denseArrayValues(value) {
  if (!denseDataArray(value)) return null;
  const values = new Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    values[index] = Object.getOwnPropertyDescriptor(value, String(index)).value;
  }
  return values;
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function snapshotUint8Array(value) {
  try {
    if (
      utilTypes.isProxy(value)
      || !utilTypes.isUint8Array(value)
      || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return null;
    const buffer = TYPED_ARRAY_BUFFER.call(value);
    const byteLength = TYPED_ARRAY_BYTE_LENGTH.call(value);
    const byteOffset = TYPED_ARRAY_BYTE_OFFSET.call(value);
    if (
      (
        typeof SharedArrayBuffer !== 'undefined'
        && buffer instanceof SharedArrayBuffer
      )
      || byteLength === 0
      || byteLength > 256 * 1024 * 1024
    ) return null;
    const copy = new Uint8Array(byteLength);
    copy.set(new Uint8Array(buffer, byteOffset, byteLength));
    return copy;
  } catch {
    return null;
  }
}

function normalizeBuiltArtifact(value) {
  try {
    if (!exactDataObject(value, BUILT_ARTIFACT_KEYS)) return null;
    const bytes = snapshotUint8Array(value.bytes);
    if (
      bytes === null
      || !['function', 'site'].includes(value.kind)
      || typeof value.logicalTarget !== 'string'
      || !SAFE_ID.test(value.logicalTarget)
      || typeof value.relativePath !== 'string'
      || !SAFE_PATH.test(value.relativePath)
      || typeof value.canonicalContentDigest !== 'string'
      || !DIGEST.test(value.canonicalContentDigest)
      || typeof value.transportDigest !== 'string'
      || !DIGEST.test(value.transportDigest)
      || !Number.isSafeInteger(value.sizeBytes)
      || value.sizeBytes !== bytes.byteLength
      || (
        value.kind === 'site'
          ? value.logicalTarget !== 'web' || value.relativePath !== 'site/site.tar.gz'
          : value.relativePath !== `functions/${value.logicalTarget}.tar.gz`
      )
      || digestBytes(bytes) !== value.transportDigest
    ) return null;
    return Object.freeze({
      kind: value.kind,
      logicalTarget: value.logicalTarget,
      relativePath: value.relativePath,
      canonicalContentDigest: value.canonicalContentDigest,
      transportDigest: value.transportDigest,
      sizeBytes: value.sizeBytes,
      bytes,
    });
  } catch {
    return null;
  }
}

function normalizeBuildIdentity(value) {
  if (!exactDataObject(value, BUILD_IDENTITY_KEYS)) return null;
  const snapshot = {
    schemaVersion: value.schemaVersion,
    sourceRevision: value.sourceRevision,
    sitePayloadDigest: value.sitePayloadDigest,
    verifierManifestDigest: value.verifierManifestDigest,
  };
  return validateHostedSiteBuildIdentity(snapshot).ok === true
    ? snapshot
    : null;
}

function normalizeArtifactManifest(value) {
  if (!exactDataObject(value, ARTIFACT_MANIFEST_KEYS)) return null;
  const entries = denseArrayValues(value.artifacts);
  if (entries === null) return null;
  const artifacts = new Array(entries.length);
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!exactDataObject(entry, ARTIFACT_MANIFEST_ENTRY_KEYS)) return null;
    artifacts[index] = {
      kind: entry.kind,
      logicalTarget: entry.logicalTarget,
      sourcePath: entry.sourcePath,
      relativePath: entry.relativePath,
      canonicalContentDigest: entry.canonicalContentDigest,
      transportDigest: entry.transportDigest,
      sizeBytes: entry.sizeBytes,
    };
  }
  const snapshot = {
    schemaVersion: value.schemaVersion,
    sourceRevision: value.sourceRevision,
    sourceTreeDigest: value.sourceTreeDigest,
    verifierManifestDigest: value.verifierManifestDigest,
    artifacts,
    artifactManifestDigest: value.artifactManifestDigest,
  };
  return validateArtifactManifest(snapshot).ok === true
    ? snapshot
    : null;
}

function cloneHandoff(value) {
  return {
    schemaVersion: value.schemaVersion,
    sourceRepository: value.sourceRepository,
    sourceWorkflow: value.sourceWorkflow,
    sourceWorkflowRunId: value.sourceWorkflowRunId,
    sourceWorkflowRunAttempt: value.sourceWorkflowRunAttempt,
    sourceRef: value.sourceRef,
    sourceRevision: value.sourceRevision,
    artifactName: value.artifactName,
    artifactManifestDigest: value.artifactManifestDigest,
    verifierManifestDigest: value.verifierManifestDigest,
  };
}

function artifactRecordMatches(entry, artifact, expectedSourcePath) {
  return entry.kind === artifact.kind
    && entry.logicalTarget === artifact.logicalTarget
    && entry.sourcePath === expectedSourcePath
    && entry.relativePath === artifact.relativePath
    && entry.canonicalContentDigest === artifact.canonicalContentDigest
    && entry.transportDigest === artifact.transportDigest
    && entry.sizeBytes === artifact.sizeBytes;
}

export function validateTestCloudArtifactSet(value, selection) {
  try {
    if (
      !validSelection(selection)
      || !exactDataObject(value, ARTIFACT_SET_KEYS)
      || typeof value.artifactManifestDigest !== 'string'
      || !DIGEST.test(value.artifactManifestDigest)
      || !exactDataObject(value.handoff, HANDOFF_KEYS)
    ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');

    const releaseInput = denseArrayValues(value.releaseEligibleArtifacts);
    const testOnlyInput = denseArrayValues(value.testOnlyArtifacts);
    const buildIdentity = normalizeBuildIdentity(value.buildIdentity);
    const manifest = normalizeArtifactManifest(value.artifactManifest);
    if (
      releaseInput === null
      || releaseInput.length !== PRODUCT_FUNCTION_IDS.length + 1
      || testOnlyInput === null
      || testOnlyInput.length !== 1
      || buildIdentity === null
      || manifest === null
    ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');

    const releaseEligibleArtifacts = new Array(releaseInput.length);
    for (let index = 0; index < releaseInput.length; index += 1) {
      const artifact = normalizeBuiltArtifact(releaseInput[index]);
      if (artifact === null) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
      releaseEligibleArtifacts[index] = artifact;
    }
    const testOnlyArtifacts = new Array(testOnlyInput.length);
    for (let index = 0; index < testOnlyInput.length; index += 1) {
      const artifact = normalizeBuiltArtifact(testOnlyInput[index]);
      if (artifact === null) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
      testOnlyArtifacts[index] = artifact;
    }

    const site = releaseEligibleArtifacts[0];
    if (site.kind !== 'site' || site.logicalTarget !== 'web') {
      return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
    }
    for (let index = 0; index < PRODUCT_FUNCTION_IDS.length; index += 1) {
      const artifact = releaseEligibleArtifacts[index + 1];
      if (
        artifact.kind !== 'function'
        || artifact.logicalTarget !== PRODUCT_FUNCTION_IDS[index]
      ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
    }
    const runner = testOnlyArtifacts[0];
    if (
      runner.kind !== 'function'
      || runner.logicalTarget !== 'verification-runner-py'
    ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');

    const handoff = cloneHandoff(value.handoff);
    if (
      manifest.sourceRevision !== selection.sourceRevision
      || value.artifactManifestDigest !== manifest.artifactManifestDigest
      || buildIdentity.sourceRevision !== selection.sourceRevision
      || buildIdentity.sitePayloadDigest !== site.canonicalContentDigest
      || buildIdentity.verifierManifestDigest !== manifest.verifierManifestDigest
      || handoff.schemaVersion !== 'artifact-handoff.v1'
      || handoff.sourceRepository !== selection.repository
      || handoff.sourceWorkflow !== selection.workflow
      || handoff.sourceWorkflowRunId !== selection.workflowRunId
      || handoff.sourceWorkflowRunAttempt !== selection.workflowRunAttempt
      || handoff.sourceRef !== selection.sourceRef
      || handoff.sourceRevision !== selection.sourceRevision
      || handoff.artifactName !== selection.artifactName
      || handoff.artifactManifestDigest !== manifest.artifactManifestDigest
      || handoff.verifierManifestDigest !== manifest.verifierManifestDigest
    ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');

    const builtArtifacts = [...releaseEligibleArtifacts, ...testOnlyArtifacts];
    const builtByKey = new Map();
    for (let index = 0; index < builtArtifacts.length; index += 1) {
      const artifact = builtArtifacts[index];
      const key = `${artifact.kind}:\0${artifact.logicalTarget}`;
      if (builtByKey.has(key)) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
      builtByKey.set(key, artifact);
    }
    if (manifest.artifacts.length !== builtArtifacts.length) {
      return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
    }
    for (let index = 0; index < manifest.artifacts.length; index += 1) {
      const entry = manifest.artifacts[index];
      const key = `${entry.kind}:\0${entry.logicalTarget}`;
      const artifact = builtByKey.get(key);
      const expectedSourcePath = entry.kind === 'site'
        ? 'src/web'
        : `src/functions/${entry.logicalTarget}`;
      if (
        artifact === undefined
        || !artifactRecordMatches(entry, artifact, expectedSourcePath)
      ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
    }

    return result('PASS', {
      buildIdentity,
      releaseEligibleArtifacts,
      testOnlyArtifacts,
      artifactManifest: manifest,
      artifactManifestDigest: value.artifactManifestDigest,
      handoff,
    });
  } catch {
    return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
  }
}

function deploymentObservation(value, expectedKind) {
  if (
    !exactDataObject(value, DEPLOYMENT_KEYS)
    || value.kind !== expectedKind
    || typeof value.logicalTarget !== 'string'
    || !SAFE_ID.test(value.logicalTarget)
    || typeof value.deploymentId !== 'string'
    || !SAFE_ID.test(value.deploymentId)
    || value.activeDeploymentId !== value.deploymentId
    || typeof value.artifactTransportDigest !== 'string'
    || !DIGEST.test(value.artifactTransportDigest)
    || value.status !== 'ready'
  ) return null;
  return deepFreeze({
    kind: value.kind,
    logicalTarget: value.logicalTarget,
    deploymentId: value.deploymentId,
    activeDeploymentId: value.activeDeploymentId,
    artifactTransportDigest: value.artifactTransportDigest,
    status: value.status,
  });
}

function expectedFunctionArtifacts(artifactSet) {
  const expected = [];
  for (let index = 0; index < artifactSet.releaseEligibleArtifacts.length; index += 1) {
    const artifact = artifactSet.releaseEligibleArtifacts[index];
    if (artifact.kind === 'function') expected.push(artifact);
  }
  for (let index = 0; index < artifactSet.testOnlyArtifacts.length; index += 1) {
    expected.push(artifactSet.testOnlyArtifacts[index]);
  }
  return expected;
}

function functionDeploymentObservations(value, artifactSet) {
  if (!denseDataArray(value)) return null;
  const expectedArtifacts = expectedFunctionArtifacts(artifactSet);
  if (value.length !== expectedArtifacts.length) return null;
  const observations = [];
  const deploymentIds = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const observation = deploymentObservation(value[index], 'function');
    const expectedArtifact = expectedArtifacts[index];
    if (
      observation === null
      || observation.logicalTarget !== expectedArtifact.logicalTarget
      || observation.artifactTransportDigest !== expectedArtifact.transportDigest
      || deploymentIds.has(observation.deploymentId)
    ) return null;
    deploymentIds.add(observation.deploymentId);
    observations.push(observation);
  }
  return deepFreeze(observations);
}

function siteDeploymentObservation(value, artifactSet) {
  const observation = deploymentObservation(value, 'site');
  if (observation === null) return null;
  let expectedSite = null;
  for (let index = 0; index < artifactSet.releaseEligibleArtifacts.length; index += 1) {
    const artifact = artifactSet.releaseEligibleArtifacts[index];
    if (artifact.kind === 'site') {
      if (expectedSite !== null) return null;
      expectedSite = artifact;
    }
  }
  if (
    expectedSite === null
    || observation.logicalTarget !== expectedSite.logicalTarget
    || observation.artifactTransportDigest !== expectedSite.transportDigest
  ) return null;
  return observation;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validDiagnostic(value) {
  return exactDataObject(value, DIAGNOSTIC_KEYS)
    && typeof value.code === 'string'
    && /^[A-Z][A-Z0-9_]{0,127}$/.test(value.code)
    && typeof value.safeMessage === 'string'
    && value.safeMessage.length > 0
    && value.safeMessage.length <= 512
    && !/[\u0000-\u001f\u007f]/u.test(value.safeMessage)
    && typeof value.retryable === 'boolean';
}

function validControllerResult(value, { allowFailureState = false } = {}) {
  if (
    !exactDataObject(value, CONTROLLER_RESULT_KEYS)
    || !['PASS', 'FAIL', 'BLOCKED'].includes(value.status)
    || !denseDataArray(value.diagnostics)
    || value.diagnostics.some((diagnostic) => !validDiagnostic(diagnostic))
  ) return false;
  if (value.status === 'PASS') return value.value !== undefined && value.diagnostics.length === 0;
  const validFailureValue = value.value === null || (
    allowFailureState
    && exactDataObject(value.value, E2E_FAILURE_STATE_KEYS)
    && value.value.lease !== null
    && value.value.lease !== undefined
    && value.value.capability !== null
    && value.value.capability !== undefined
  );
  return validFailureValue
    && value.diagnostics.length > 0
    && value.diagnostics.length <= 16;
}

async function invoke(method, request) {
  try {
    const outcome = await method(deepFreeze(request));
    if (!validControllerResult(outcome)) {
      return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
    }
    if (outcome.status === 'PASS') return result('PASS', outcome.value);
    return result(
      outcome.status,
      null,
      'TEST_CLOUD_PREFLIGHT_BLOCKED',
      outcome.diagnostics.some(({ retryable }) => retryable),
    );
  } catch {
    return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
  }
}

async function invokeE2E(method, request) {
  try {
    const outcome = await method(deepFreeze(request));
    if (!validControllerResult(outcome, { allowFailureState: true })) {
      return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
    }
    if (outcome.status === 'PASS') return result('PASS', outcome.value);
    const failureState = outcome.value === null
      ? null
      : {
        lease: outcome.value.lease,
        capability: outcome.value.capability,
      };
    return result(
      outcome.status,
      failureState,
      'TEST_CLOUD_PREFLIGHT_BLOCKED',
      outcome.diagnostics.some(({ retryable }) => retryable),
    );
  } catch {
    return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
  }
}

function stageFailure(outcome, code, blockedOnly = false) {
  if (outcome.status === 'PASS') return null;
  const status = blockedOnly || outcome.status === 'BLOCKED' ? 'BLOCKED' : 'FAIL';
  return result(status, null, code, outcome.diagnostics.some((item) => item?.retryable === true));
}

function now(clock) {
  const value = clock.now();
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null;
}

function validEvidenceWrite(outcome) {
  return outcome?.status === 'PASS'
    && isPlainObject(outcome.value)
    && typeof outcome.value.path === 'string'
    && outcome.value.path.length > 0
    && !outcome.value.path.includes('..')
    && !/^[A-Za-z]:[\\/]|^\//.test(outcome.value.path)
    && typeof outcome.value.evidenceDigest === 'string'
    && DIGEST.test(outcome.value.evidenceDigest);
}

export async function runTestCloudLane(args) {
  if (!exactDataObject(args, ARGUMENT_KEYS)) throw argumentError();
  if (!isTrustedControllerContext(args.controller)) {
    return result('BLOCKED', null, 'TRUSTED_CONTROLLER_REQUIRED');
  }
  const artifactSetResult = validateTestCloudArtifactSet(args.artifactSet, args.selection);
  if (artifactSetResult.status !== 'PASS') return artifactSetResult;
  validateDependencies(args);
  const artifactSet = artifactSetResult.value;

  const startedAt = now(args.clock);
  if (startedAt === null) return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');

  let primaryFailure = null;
  let leaseState = null;
  let functionDeployments = null;
  let siteDeployment = null;
  let cleanupFailure = null;

  const common = {
    controller: args.controller,
    selection: args.selection,
    artifactSet,
  };

  const preflight = await invoke(args.clients.preflight, common);
  primaryFailure = stageFailure(preflight, 'TEST_CLOUD_PREFLIGHT_BLOCKED', true);
  if (primaryFailure !== null) return primaryFailure;

  const acquired = await invoke(args.clients.acquireLease, {
    ...common,
    preflight: preflight.value,
  });
  primaryFailure = stageFailure(acquired, 'LEASE_ACQUIRE_BLOCKED', true);
  if (primaryFailure !== null) return primaryFailure;
  if (
    !isPlainObject(acquired.value)
    || acquired.value.lease === undefined
    || acquired.value.capability === undefined
  ) return result('BLOCKED', null, 'LEASE_ACQUIRE_BLOCKED');
  leaseState = {
    lease: acquired.value.lease,
    capability: acquired.value.capability,
  };

  try {
    const functions = await invoke(args.clients.deployFunctionArtifacts, {
      ...common,
      ...leaseState,
    });
    primaryFailure = stageFailure(functions, 'FUNCTION_DEPLOYMENT_FAILED');
    if (primaryFailure === null) {
      functionDeployments = functionDeploymentObservations(functions.value, artifactSet);
      if (functionDeployments === null) {
        primaryFailure = result('FAIL', null, 'FUNCTION_DEPLOYMENT_FAILED');
      }
    }

    if (primaryFailure === null) {
      const site = await invoke(args.clients.deploySiteArtifact, {
        ...common,
        ...leaseState,
      });
      primaryFailure = stageFailure(site, 'SITE_DEPLOYMENT_FAILED');
      if (primaryFailure === null) {
        siteDeployment = siteDeploymentObservation(site.value, artifactSet);
        if (siteDeployment === null) {
          primaryFailure = result('FAIL', null, 'SITE_DEPLOYMENT_FAILED');
        }
      }
    }

    if (primaryFailure === null) {
      const qualified = await invoke(args.clients.qualifyRunner, {
        ...common,
        ...leaseState,
        functionDeployments,
        siteDeployment,
      });
      primaryFailure = stageFailure(qualified, 'RUNNER_QUALIFICATION_FAILED');
      if (primaryFailure === null && qualified.value?.qualified !== true) {
        primaryFailure = result('FAIL', null, 'RUNNER_QUALIFICATION_FAILED');
      }
    }

    if (primaryFailure === null) {
      const e2e = await invokeE2E(args.clients.runE2E, {
        ...common,
        ...leaseState,
        functionDeployments,
        siteDeployment,
      });
      if (e2e.status !== 'PASS' && e2e.value !== null) {
        leaseState = {
          lease: e2e.value.lease,
          capability: e2e.value.capability,
        };
      }
      primaryFailure = stageFailure(e2e, 'E2E_FAILED');
      if (primaryFailure === null) {
        if (
          !exactDataObject(e2e.value, E2E_PASS_KEYS)
          || e2e.value.passed !== true
          || e2e.value.lease === null
          || e2e.value.lease === undefined
          || e2e.value.capability === null
          || e2e.value.capability === undefined
        ) {
          primaryFailure = result('BLOCKED', null, 'E2E_FAILED');
        } else {
          leaseState = {
            lease: e2e.value.lease,
            capability: e2e.value.capability,
          };
        }
      }
    }
  } finally {
    const cleaned = await invoke(args.clients.cleanup, {
      controller: args.controller,
      selection: args.selection,
      ...leaseState,
      functionDeployments: functionDeployments ?? [],
      siteDeployment,
    });
    if (
      cleaned.status !== 'PASS'
      || !isPlainObject(cleaned.value)
      || cleaned.value.lease === undefined
      || cleaned.value.capability === undefined
      || !Array.isArray(cleaned.value.intents)
    ) {
      cleanupFailure = result('BLOCKED', null, 'CLEANUP_DEBT');
    } else {
      leaseState = {
        lease: cleaned.value.lease,
        capability: cleaned.value.capability,
      };
      const absent = await invoke(args.clients.proveAbsence, {
        controller: args.controller,
        selection: args.selection,
        ...leaseState,
        intents: cleaned.value.intents,
      });
      if (absent.status !== 'PASS' || absent.value?.absenceProven !== true) {
        cleanupFailure = result('BLOCKED', null, 'CLEANUP_DEBT');
      } else {
        const closed = await invoke(args.clients.closeLease, {
          controller: args.controller,
          selection: args.selection,
          ...leaseState,
        });
        if (closed.status !== 'PASS') {
          cleanupFailure = result('BLOCKED', null, 'CLEANUP_DEBT');
        }
      }
    }
  }

  if (cleanupFailure !== null) return cleanupFailure;
  if (primaryFailure !== null) return primaryFailure;

  const completedAt = now(args.clock);
  if (completedAt === null) return result('BLOCKED', null, 'EVIDENCE_WRITE_BLOCKED');
  const evidence = deepFreeze({
    startedAt,
    completedAt,
    sourceRevision: args.selection.sourceRevision,
    sourceArtifactDigest: args.selection.archiveDigest,
    controllerBundleSha: args.controller.controllerBundleSha,
    controllerBundleDigest: args.controller.controllerBundleDigest,
    siteDeployment,
    functionDeployments,
    runnerQualified: true,
    e2ePassed: true,
    cleanupAbsenceProven: true,
  });

  const written = await invoke(args.evidenceWriter.write, evidence);
  if (!validEvidenceWrite(written)) {
    return result('BLOCKED', null, 'EVIDENCE_WRITE_BLOCKED');
  }

  return result('PASS', {
    sourceRevision: args.selection.sourceRevision,
    siteDeployment,
    functionDeployments,
    runnerQualified: true,
    e2ePassed: true,
    cleanupAbsenceProven: true,
    evidencePath: written.value.path,
    evidenceDigest: written.value.evidenceDigest,
  });
}
