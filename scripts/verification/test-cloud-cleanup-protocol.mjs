import { isProxy } from 'node:util/types';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';

export const CLEANUP_PROTOCOL_SCHEMA_VERSION = 'test-cloud-cleanup-protocol.v1';
export const RECOVERY_CHECKPOINT_SCHEMA_VERSION = 'verification-recovery-checkpoint.v1';

export const RECOVERY_COUNTS = Object.freeze({
  semanticTransitions: 42,
  mutationSteps: 30,
  readOnlySteps: 12,
  knownProductHttpCalls: 188,
  maximumProductHttpCalls: 248,
  knownStoreCalls: 79,
  maximumStoreCalls: 139,
  functionExecutions: 0,
});

const FENCE_SCHEMA_VERSION = 'test-cloud-cleanup-fence.v1';
const RESULT = 'desired-projection-proven';
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const INTENT_ID_PATTERN = /^[0-9a-f]{64}$/u;
const encoder = new TextEncoder();

const CLEANUP_SCENARIOS = Object.freeze({
  'resource.cleanup_preflight_step': 'preflight',
  'resource.cleanup_step': 'cleanup',
  'resource.cleanup_proof_step': 'proof',
  'resource.cleanup': 'terminal',
});

const FENCE_KEYS = Object.freeze([
  'schemaVersion',
  'leaseVersion',
  'ledgerDigest',
  'intentId',
  'intentVersion',
  'intentProjectionDigest',
  'providerContractDigest',
  'providerAggregateDigest',
  'phase',
  'phaseCursor',
  'phaseStepCount',
  'priorPhaseDigest',
  'cleanupCursor',
  'cleanupProgressDigest',
  'cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest',
  'cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionRecordDigest',
]);

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function readExact(value, expectedKeys, label) {
  if (!isPlainRecord(value)) throw new TypeError(`${label} must be a plain data object.`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== expectedKeys.length
    || keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))) {
    throw new TypeError(`${label} has an invalid shape.`);
  }
  const copy = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} accepts only enumerable data properties.`);
    }
    copy[key] = descriptor.value;
  }
  return copy;
}

function readDenseArray(value, label) {
  if (!Array.isArray(value) || isProxy(value)) throw new TypeError(`${label} must be an array.`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) {
    throw new TypeError(`${label} must be a dense plain array.`);
  }
  const copy = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, `${index}`);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} must contain only data entries.`);
    }
    copy.push(descriptor.value);
  }
  return copy;
}

function cloneAndFreeze(value) {
  if (Array.isArray(value)) return Object.freeze(value.map((entry) => cloneAndFreeze(entry)));
  if (value !== null && typeof value === 'object') {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, cloneAndFreeze(entry)]),
    ));
  }
  return value;
}

function digestDomain(domain, payload) {
  return sha256Bytes(encoder.encode(canonicalJson({ domain, payload })));
}

function assertDigest(value, label, nullable = false) {
  if (nullable && value === null) return value;
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest${nullable ? ' or null' : ''}.`);
  }
  return value;
}

function assertNonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a non-negative integer.`);
  return value;
}

function assertPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive integer.`);
  return value;
}

function pointSteps(prefix, phase, targets, operation) {
  return targets.map((target, cursor) => ({
    cursor,
    stepId: `${prefix}.${phase}.point.${target}`,
    operation,
    target,
  }));
}

function querySteps(prefix, phase, targets, offset) {
  return targets.map((target, index) => ({
    cursor: offset + index,
    stepId: `${prefix}.${phase}.query.${target}`,
    operation: 'fixed-query',
    target,
  }));
}

function mutationSteps(rows) {
  return rows.map(([stepId, operation, target], cursor) => ({
    cursor,
    stepId,
    operation,
    target,
  }));
}

const ACL_MEMBERS = Object.freeze([
  'P0', 'P1', 'P2', 'P3', 'P4', 'P5',
  'G0', 'G1', 'G2', 'G3', 'G4',
  'V0', 'V1', 'V2',
]);
const PROJECT_MEMBERS = Object.freeze(['P0', 'P1', 'P2', 'P3', 'P4', 'P5']);
const GRAPH_DELETE_ORDER = Object.freeze(['V2', 'V1', 'V0', 'G4', 'G3', 'G2', 'G0', 'G1']);
const PROJECT_DELETE_ORDER = Object.freeze(['P4', 'P5', 'P2', 'P3', 'P1', 'P0']);
const SHARE_QUERIES = Object.freeze([
  'project-shares',
  'project-snapshots',
  'project-artifact-references',
  'project-artifacts',
  'project-artifact-versions',
]);
const GRAPH_PROJECT_QUERIES = Object.freeze([
  'project-artifact-references',
  'project-artifacts',
  'project-artifact-versions',
]);

function buildResourceCatalog({
  logicalResource,
  prefix,
  preflight,
  mutation,
  proof,
  knownCalls,
  maximumCalls,
}) {
  const terminal = {
    scenarioId: 'resource.cleanup',
    stepId: `${prefix}.terminal`,
    productCalls: 0,
  };
  const planProjection = {
    schemaVersion: 'test-cloud-cleanup-execution-plan.v1',
    logicalResource,
    preflightStepIds: preflight.map(({ stepId }) => stepId),
    mutationStepIds: mutation.map(({ stepId }) => stepId),
    proofStepIds: proof.map(({ stepId }) => stepId),
    terminalStepId: terminal.stepId,
    knownCalls,
    maximumCalls,
    slotCount: maximumCalls,
  };
  const executionPlan = {
    ...planProjection,
    digest: digestDomain('test-cloud-cleanup-execution-plan-digest.v1', planProjection),
  };
  return { logicalResource, preflight, mutation, proof, terminal, executionPlan };
}

const sharePreflight = [
  ...pointSteps('share', 'preflight', ACL_MEMBERS, 'point-read-present-shared'),
  ...querySteps('share', 'preflight', SHARE_QUERIES, ACL_MEMBERS.length),
];
const graphPreflight = [
  ...pointSteps('graph', 'preflight', ACL_MEMBERS, 'point-read-present-owner-only'),
  ...querySteps('graph', 'preflight', GRAPH_PROJECT_QUERIES, ACL_MEMBERS.length),
];
const projectPreflight = [
  ...pointSteps('project', 'preflight', ACL_MEMBERS, 'point-read-dependency-state'),
  ...querySteps('project', 'preflight', GRAPH_PROJECT_QUERIES, ACL_MEMBERS.length),
];

const shareMutation = mutationSteps([
  ['share.delete.viewerShare', 'delete-and-prove-absent', 'S1'],
  ['share.delete.editorShare', 'delete-and-prove-absent', 'S0'],
  ...ACL_MEMBERS.map((target) => [`share.permissions.${target}`, 'converge-owner-only', target]),
]);
const graphMutation = mutationSteps(GRAPH_DELETE_ORDER.map(
  (target) => [`graph.delete.${target}`, 'delete-and-prove-absent', target],
));
const projectMutation = mutationSteps(PROJECT_DELETE_ORDER.map(
  (target) => [`project.delete.${target}`, 'delete-and-prove-absent', target],
));

const shareProof = [
  ...pointSteps('share', 'proof', ACL_MEMBERS, 'point-read-owner-only'),
  ...querySteps('share', 'proof', SHARE_QUERIES, ACL_MEMBERS.length),
];
const graphProof = [
  ...pointSteps('graph', 'proof', GRAPH_DELETE_ORDER, 'point-read-absent'),
  ...pointSteps('graph', 'proof-preserved', PROJECT_MEMBERS, 'point-read-owner-only')
    .map((step, index) => ({ ...step, cursor: GRAPH_DELETE_ORDER.length + index })),
  ...querySteps('graph', 'proof', GRAPH_PROJECT_QUERIES, GRAPH_DELETE_ORDER.length + PROJECT_MEMBERS.length),
];
const projectProof = [
  ...pointSteps('project', 'proof', PROJECT_DELETE_ORDER, 'point-read-absent'),
  ...querySteps('project', 'proof', GRAPH_PROJECT_QUERIES, PROJECT_DELETE_ORDER.length),
];

const resources = {
  'primary-share': buildResourceCatalog({
    logicalResource: 'primary-share',
    prefix: 'share',
    preflight: sharePreflight,
    mutation: shareMutation,
    proof: shareProof,
    knownCalls: 55,
    maximumCalls: 110,
  }),
  'primary-graph': buildResourceCatalog({
    logicalResource: 'primary-graph',
    prefix: 'graph',
    preflight: graphPreflight,
    mutation: graphMutation,
    proof: graphProof,
    knownCalls: 43,
    maximumCalls: 86,
  }),
  'primary-project': buildResourceCatalog({
    logicalResource: 'primary-project',
    prefix: 'project',
    preflight: projectPreflight,
    mutation: projectMutation,
    proof: projectProof,
    knownCalls: 33,
    maximumCalls: 66,
  }),
};

function transition(stepId, resource, member, phase, action) {
  return { stepId, resource, member, phase, action };
}

const transitions = [
  transition('share.start', 'primary-share', 'aggregate', 'shared', 'record-cleanup-started'),
  transition('share.delete.viewerShare', 'primary-share', 'S1/viewerShare', 'shared', 'delete-and-prove-absent'),
  transition('share.delete.editorShare', 'primary-share', 'S0/editorShare', 'shared', 'delete-and-prove-absent'),
  ...ACL_MEMBERS.map((member) => transition(
    `share.permissions.${member}`, 'primary-share', member, 'shared', 'converge-owner-only',
  )),
  transition('project.phase.after-share-cleanup', 'primary-project', 'aggregate', 'shared -> after-share-cleanup', 'commit-proof-recorded-phase'),
  transition('graph.phase.after-share-cleanup', 'primary-graph', 'aggregate', 'shared -> after-share-cleanup', 'commit-proof-recorded-phase'),
  transition('share.phase.after-share-cleanup', 'primary-share', 'aggregate', 'shared -> after-share-cleanup', 'commit-share-absence-proof-and-phase'),
  transition('share.absent', 'primary-share', 'aggregate', 'after-share-cleanup -> absent', 'consume-share-proof-and-commit-absent'),
  transition('graph.start', 'primary-graph', 'aggregate', 'after-share-cleanup', 'record-cleanup-started'),
  ...GRAPH_DELETE_ORDER.map((member) => transition(
    `graph.delete.${member}`, 'primary-graph', member, 'after-share-cleanup', 'delete-and-prove-absent',
  )),
  transition('graph.phase.after-graph-cleanup', 'primary-graph', 'aggregate', 'after-share-cleanup -> after-graph-cleanup', 'commit-graph-absence-proof-and-phase'),
  transition('graph.absent', 'primary-graph', 'aggregate', 'after-graph-cleanup -> absent', 'consume-graph-proof-and-commit-absent'),
  transition('project.phase.after-graph-cleanup', 'primary-project', 'aggregate', 'after-share-cleanup -> after-graph-cleanup', 'commit-proof-recorded-phase'),
  transition('project.start', 'primary-project', 'aggregate', 'after-graph-cleanup', 'record-cleanup-started'),
  ...PROJECT_DELETE_ORDER.map((member) => transition(
    `project.delete.${member}`, 'primary-project', member, 'after-graph-cleanup', 'delete-and-prove-absent',
  )),
  transition('project.phase.fully-clean', 'primary-project', 'aggregate', 'after-graph-cleanup -> fully-clean', 'commit-project-absence-proof-and-phase'),
  transition('project.absent', 'primary-project', 'aggregate', 'fully-clean -> absent', 'consume-project-proof-and-commit-absent'),
].map((row, index) => ({ index, ...row }));

if (transitions.length !== 42) throw new Error('Cleanup transition catalog must contain exactly 42 rows.');

const recoveryTransitionDetails = Object.freeze(transitions.map(({ stepId, resource, member, phase, action }) => Object.freeze({
  stepId,
  logicalResource: resource,
  phase,
  action,
  stepKind: member === 'aggregate' ? 'read-proof' : 'mutation',
  targetBindingRequired: true,
})));
const recoveryTransitions = Object.freeze(recoveryTransitionDetails.map(({ stepId, logicalResource, phase, action, targetBindingRequired }) => Object.freeze({
  stepId, logicalResource, phase, action, targetBindingRequired,
})));

if (recoveryTransitionDetails.filter(({ stepKind }) => stepKind === 'mutation').length
  !== RECOVERY_COUNTS.mutationSteps) {
  throw new Error('Recovery catalog mutation count must match the fixed cleanup catalog.');
}
if (recoveryTransitionDetails.filter(({ stepKind }) => stepKind === 'read-proof').length
  !== RECOVERY_COUNTS.readOnlySteps || recoveryTransitions.some(({ targetBindingRequired }) => !targetBindingRequired)) {
  throw new Error('Recovery catalog read/proof target bindings must match the fixed cleanup catalog.');
}

const INTENT_SNAPSHOT_V2_KEYS = Object.freeze([
  'schemaVersion', 'intentId', 'runId', 'environmentDigest', 'resourceType', 'resourceId',
  'providerAggregateJson', 'providerAggregateDigest', 'ownerMarker', 'dependencyOrder',
  'lifecycleClass', 'state', 'intentVersion', 'observationDigest', 'retentionExpiresAt',
  'cleanupCursor', 'cleanupProgressDigest', 'cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest', 'cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson', 'cleanupRunnerExecutionRecordDigest',
  'cleanupRunnerExecutionRetentionExpiresAt', 'recoveryCheckpointDigest', 'createdAt', 'updatedAt',
]);
const INTENT_SNAPSHOT_V2_LEGACY_KEYS = Object.freeze(
  INTENT_SNAPSHOT_V2_KEYS.filter((key) => key !== 'recoveryCheckpointDigest'),
);
const RECOVERY_TERMINAL_MUTABLE_INTENT_KEYS = new Set([
  'state', 'intentVersion', 'cleanupCursor', 'cleanupProgressDigest', 'cleanupProofDigest',
  'recoveryCheckpointDigest', 'updatedAt',
]);
const ORDINARY_EXECUTION_EVIDENCE_KEYS = Object.freeze([
  'cleanupRunnerExecutionPlanDigest', 'cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson', 'cleanupRunnerExecutionRecordDigest',
  'cleanupRunnerExecutionRetentionExpiresAt',
]);
const RECOVERY_CHECKPOINT_KEYS = Object.freeze([
  'schemaVersion', 'environmentDigest', 'cleanupProtocolDigest', 'sourceAuditHeadDigest',
  'sourceLeaseVersion', 'sourceLedgerDigest', 'sourceIntentSetDigest', 'currentIntentSetDigest',
  'ordinaryExecutionEvidenceDigest', 'accountSessionAbsenceDigest', 'priorCheckpointDigest',
  'eventOrdinal', 'prefixLength', 'intentDispositionCursor', 'checkpointState', 'logicalResource',
  'stepId', 'phase', 'action', 'targetBindingDigest', 'attemptOrdinal', 'preWriteProjectionDigest',
  'desiredProjectionDigest', 'providerObservationDigest', 'recoveryProgressDigest', 'cleanupProofDigest',
]);
const RECOVERY_AUDIT_EVENT_KEYS = Object.freeze([
  'schemaVersion', 'previousLedgerDigest', 'runId', 'leaseVersionBefore', 'leaseVersionAfter',
  'transition', 'intentId', 'intentProjectionDigest', 'recoveryCheckpointJson',
  'recoveryCheckpointDigest', 'recoveryPreviousCheckpointDigest',
]);
const RECOVERY_CHECKPOINT_IMMUTABLE_SUCCESSOR_KEYS = Object.freeze([
  'schemaVersion', 'environmentDigest', 'cleanupProtocolDigest', 'sourceAuditHeadDigest',
  'sourceLeaseVersion', 'sourceLedgerDigest', 'sourceIntentSetDigest',
  'ordinaryExecutionEvidenceDigest', 'accountSessionAbsenceDigest',
]);
const RECOVERY_TERMINAL_CLEANUP_CURSORS = Object.freeze({
  'primary-share': 16,
  'primary-graph': 8,
  'primary-project': 6,
});

const providerMembers = [
  ['P0', 'projectFacade', 'primary-project'],
  ['P1', 'rootArtifact', 'primary-project'],
  ['P2', 'rootVersionInitial', 'primary-project'],
  ['P3', 'rootManifestInitial', 'primary-project'],
  ['P4', 'rootVersionSaved', 'primary-project'],
  ['P5', 'rootManifestSaved', 'primary-project'],
  ['G0', 'entrypointArtifact', 'primary-graph'],
  ['G1', 'entrypointVersionInitial', 'primary-graph'],
  ['G2', 'entrypointSourceInitial', 'primary-graph'],
  ['G3', 'entrypointVersionSaved', 'primary-graph'],
  ['G4', 'entrypointSourceSaved', 'primary-graph'],
  ['V0', 'visualModelSourceSaved', 'primary-graph'],
  ['V1', 'visualModelArtifact', 'primary-graph'],
  ['V2', 'visualModelVersionSaved', 'primary-graph'],
].map(([alias, slot, owner]) => ({ alias, slot, owner }));

const shareMembers = [
  { alias: 'S0', slot: 'editorShare', owner: 'primary-share' },
  { alias: 'S1', slot: 'viewerShare', owner: 'primary-share' },
];

export const QUALIFIED_CLEANUP_PROTOCOL = cloneAndFreeze({
  schemaVersion: CLEANUP_PROTOCOL_SCHEMA_VERSION,
  fenceSchemaVersion: FENCE_SCHEMA_VERSION,
  environmentClass: 'appwrite-cloud-test',
  result: RESULT,
  resourceOrder: ['primary-share', 'primary-graph', 'primary-project'],
  providerMembers,
  shareMembers,
  fixedQueries: [...SHARE_QUERIES],
  resources,
  transitions,
  counts: {
    semanticTransitions: 42,
    readOnlyCheckpoints: 92,
    knownSuccessStoreTransitions: 134,
    absoluteStoreTransitions: 265,
    knownRunnerCalls: 131,
    maximumRunnerCalls: 262,
    knownRunnerSideCalls: 450,
    maximumRunnerSideCalls: 900,
  },
});

export const CLEANUP_PROTOCOL_DIGEST = digestDomain(
  'test-cloud-cleanup-protocol-digest.v1',
  QUALIFIED_CLEANUP_PROTOCOL,
);

function requireResource(logicalResource) {
  if (typeof logicalResource !== 'string'
    || !Object.hasOwn(QUALIFIED_CLEANUP_PROTOCOL.resources, logicalResource)) {
    throw new TypeError('Unknown cleanup logical resource.');
  }
  return QUALIFIED_CLEANUP_PROTOCOL.resources[logicalResource];
}

export function getCleanupResourceCatalog(logicalResource) {
  return requireResource(logicalResource);
}

export function getCleanupTransitionCatalog() {
  return QUALIFIED_CLEANUP_PROTOCOL.transitions;
}

export function getRecoveryTransitionAt(prefixLength) {
  assertNonNegativeInteger(prefixLength, 'recovery prefixLength');
  const transition = recoveryTransitions[prefixLength];
  if (!transition) throw new TypeError('Recovery prefixLength must select one fixed transition.');
  return transition;
}

function getRecoveryTransitionDetailAt(prefixLength) {
  assertNonNegativeInteger(prefixLength, 'recovery prefixLength');
  const transition = recoveryTransitionDetails[prefixLength];
  if (!transition) throw new TypeError('Recovery prefixLength must select one fixed transition.');
  return transition;
}

export function deriveRecoveryPosition(value) {
  const fields = readExact(value, ['prefixLength', 'intentDispositionCursor'], 'Recovery position');
  assertNonNegativeInteger(fields.prefixLength, 'recovery prefixLength');
  assertNonNegativeInteger(fields.intentDispositionCursor, 'recovery intentDispositionCursor');
  if (fields.prefixLength > RECOVERY_COUNTS.semanticTransitions) {
    throw new TypeError('Recovery prefixLength exceeds the fixed catalog.');
  }
  const expectedCursor = recoveryTransitions.slice(0, fields.prefixLength)
    .filter(({ stepId }) => stepId.endsWith('.absent')).length;
  if (fields.intentDispositionCursor !== expectedCursor) {
    throw new TypeError('Recovery intentDispositionCursor does not match the fixed catalog prefix.');
  }
  if (fields.prefixLength === RECOVERY_COUNTS.semanticTransitions) {
    return Object.freeze({
      logicalResource: null,
      stepId: null,
      phase: null,
      action: null,
      targetBindingRequired: false,
    });
  }
  return getRecoveryTransitionAt(fields.prefixLength);
}

function isCanonicalRecoveryGenesisPosition(prefixLength, intentDispositionCursor) {
  deriveRecoveryPosition({ prefixLength, intentDispositionCursor });
  return prefixLength === 0
    || getRecoveryTransitionDetailAt(prefixLength - 1).stepId.endsWith('.absent');
}

function assertString(value, label, { nullable = false, minLength = 0, maxLength = Infinity } = {}) {
  if (nullable && value === null) return value;
  if (typeof value !== 'string' || value.length < minLength || value.length > maxLength) {
    throw new TypeError(`${label} must be a string${nullable ? ' or null' : ''}.`);
  }
  return value;
}

function assertCanonicalIsoTimestamp(value, label, nullable = false) {
  if (nullable && value === null) return value;
  assertString(value, label, { minLength: 1 });
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical ISO-8601 timestamp.`);
  }
  return value;
}

function parseCanonicalJson(value, label) {
  assertString(value, label, { minLength: 1, maxLength: 32768 });
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TypeError(`${label} must be canonical JSON.`);
  }
  if (canonicalJson(parsed) !== value) throw new TypeError(`${label} must be canonical JSON.`);
  return parsed;
}

function validateExecutionSlots(fields, label) {
  const values = ORDINARY_EXECUTION_EVIDENCE_KEYS.map((key) => fields[key]);
  if (values.every((value) => value === null)) return null;
  if (!values.every((value) => value !== null)) throw new TypeError(`${label} execution evidence must be all-null or complete.`);
  const plan = getCleanupExecutionPlan(fields.resourceType);
  if (fields.cleanupRunnerExecutionPlanDigest !== plan.digest) throw new TypeError(`${label} execution plan digest does not match the fixed resource catalog.`);
  assertNonNegativeInteger(fields.cleanupRunnerExecutionCursor, `${label} cleanupRunnerExecutionCursor`);
  if (fields.cleanupRunnerExecutionCursor > plan.knownCalls) throw new TypeError(`${label} execution cursor exceeds the fixed catalog.`);
  const slots = parseCanonicalJson(fields.cleanupRunnerExecutionSlotsJson, `${label} cleanupRunnerExecutionSlotsJson`);
  if (!Array.isArray(slots) || slots.length !== plan.slotCount) throw new TypeError(`${label} execution slots do not match the fixed catalog.`);
  assertDigest(fields.cleanupRunnerExecutionRecordDigest, `${label} cleanupRunnerExecutionRecordDigest`);
  assertCanonicalIsoTimestamp(fields.cleanupRunnerExecutionRetentionExpiresAt, `${label} cleanupRunnerExecutionRetentionExpiresAt`);
  const retainedExecutionIds = new Set();
  for (const [index, slot] of slots.entries()) {
    if (slot === null) continue;
    const slotFields = readExact(slot, ['logicalPosition', 'attemptOrdinal', 'retainedExecutionId', 'safeStateDigest', 'retentionExpiresAt'], `${label} execution slot`);
    if (slotFields.logicalPosition !== Math.floor(index / 2) || slotFields.attemptOrdinal !== (index % 2) + 1
      || slotFields.logicalPosition >= plan.knownCalls || slotFields.logicalPosition > fields.cleanupRunnerExecutionCursor) {
      throw new TypeError(`${label} execution slot position is inconsistent.`);
    }
    assertString(slotFields.retainedExecutionId, `${label} retainedExecutionId`, { minLength: 1 });
    if (retainedExecutionIds.has(slotFields.retainedExecutionId)) throw new TypeError(`${label} execution retained IDs must be unique.`);
    retainedExecutionIds.add(slotFields.retainedExecutionId);
    assertDigest(slotFields.safeStateDigest, `${label} safeStateDigest`);
    assertCanonicalIsoTimestamp(slotFields.retentionExpiresAt, `${label} slot retentionExpiresAt`);
    if (slotFields.retentionExpiresAt !== fields.cleanupRunnerExecutionRetentionExpiresAt) throw new TypeError(`${label} execution slot retention must equal its row retention.`);
  }
  for (let position = 0; position < plan.knownCalls; position += 1) {
    const first = slots[position * 2];
    const second = slots[(position * 2) + 1];
    if (second !== null && first === null) throw new TypeError(`${label} attempt two requires attempt one.`);
    if (position < fields.cleanupRunnerExecutionCursor && first === null) throw new TypeError(`${label} completed execution positions require attempt one.`);
    if (position > fields.cleanupRunnerExecutionCursor && (first !== null || second !== null)) throw new TypeError(`${label} execution evidence contains a future slot.`);
  }
  const executionRecordDigest = sha256Bytes(encoder.encode(canonicalJson({
    schemaVersion: 'verification-cleanup-execution-record.v1',
    logicalResource: fields.resourceType,
    slots,
  })));
  if (fields.cleanupRunnerExecutionRecordDigest !== executionRecordDigest) {
    throw new TypeError(`${label} execution record digest does not match the canonical retained slots.`);
  }
  return Object.freeze({ slots: Object.freeze(slots), retainedExecutionIds: Object.freeze([...retainedExecutionIds]), retentionExpiresAt: fields.cleanupRunnerExecutionRetentionExpiresAt });
}
function validateRecoverySetExecutionEvidence(intents, label) {
  const retainedExecutionIds = new Set();
  let retentionExpiresAt = null;
  for (const intent of intents) {
    const evidence = validateExecutionSlots(intent, `${label} ${intent.resourceType}`);
    if (evidence === null) continue;
    if (retentionExpiresAt === null) retentionExpiresAt = evidence.retentionExpiresAt;
    else if (retentionExpiresAt !== evidence.retentionExpiresAt) throw new TypeError(`${label} execution retention must be common across resources.`);
    for (const retainedExecutionId of evidence.retainedExecutionIds) {
      if (retainedExecutionIds.has(retainedExecutionId)) throw new TypeError(`${label} execution retained IDs must be globally unique.`);
      retainedExecutionIds.add(retainedExecutionId);
    }
  }
}
function copyExact(fields, keys) {
  return Object.freeze(Object.fromEntries(keys.map((key) => [key, fields[key]])));
}

function validateIntentSnapshotV2Fields(fields, label) {
  if (fields.schemaVersion !== 'verification-intent-snapshot.v2'
    || typeof fields.intentId !== 'string' || !INTENT_ID_PATTERN.test(fields.intentId)
    || !['primary-share', 'primary-graph', 'primary-project'].includes(fields.resourceType)
    || typeof fields.ownerMarker !== 'string' || !/^verification-owner\.v1:sha256:[0-9a-f]{64}$/u.test(fields.ownerMarker)
    || fields.lifecycleClass !== 'fixture'
    || !['planned', 'created', 'cleaning', 'absent'].includes(fields.state)
    || fields.observationDigest !== null || fields.retentionExpiresAt !== null) {
    throw new TypeError(`${label} has invalid v2 fields.`);
  }
  assertString(fields.runId, `${label} runId`, { minLength: 1 });
  assertDigest(fields.environmentDigest, `${label} environmentDigest`);
  assertString(fields.resourceId, `${label} resourceId`, { minLength: 1 });
  parseCanonicalJson(fields.providerAggregateJson, `${label} providerAggregateJson`);
  assertDigest(fields.providerAggregateDigest, `${label} providerAggregateDigest`);
  assertNonNegativeInteger(fields.dependencyOrder, `${label} dependencyOrder`);
  assertPositiveInteger(fields.intentVersion, `${label} intentVersion`);
  if (fields.cleanupCursor !== null) assertNonNegativeInteger(fields.cleanupCursor, `${label} cleanupCursor`);
  assertDigest(fields.cleanupProgressDigest, `${label} cleanupProgressDigest`, true);
  assertDigest(fields.cleanupProofDigest, `${label} cleanupProofDigest`, true);
  validateExecutionSlots(fields, label);
  assertDigest(fields.recoveryCheckpointDigest, `${label} recoveryCheckpointDigest`, true);
  assertCanonicalIsoTimestamp(fields.createdAt, `${label} createdAt`);
  assertCanonicalIsoTimestamp(fields.updatedAt, `${label} updatedAt`);
  return fields;
}

function validateIntentSnapshotV2(value, label) {
  return copyExact(validateIntentSnapshotV2Fields(
    readExact(value, INTENT_SNAPSHOT_V2_KEYS, label), label,
  ), INTENT_SNAPSHOT_V2_KEYS);
}

export function validateRecoveryIntentRow(value) {
  if (!isPlainRecord(value)) throw new TypeError('Recovery intent row must be a plain data object.');
  const hasRecoveryCheckpointDigest = Reflect.ownKeys(value).includes('recoveryCheckpointDigest');
  const keys = hasRecoveryCheckpointDigest ? INTENT_SNAPSHOT_V2_KEYS : INTENT_SNAPSHOT_V2_LEGACY_KEYS;
  const supplied = readExact(value, keys, 'Recovery intent row');
  const fields = validateIntentSnapshotV2Fields(
    hasRecoveryCheckpointDigest ? supplied : { ...supplied, recoveryCheckpointDigest: null },
    'Recovery intent row',
  );
  const recoveryCheckpointDigest = hasRecoveryCheckpointDigest ? fields.recoveryCheckpointDigest : null;
  if (fields.state !== 'absent') {
    if (recoveryCheckpointDigest !== null) throw new TypeError('Only a recovery terminal intent may cite a checkpoint.');
    return copyExact(supplied, keys);
  }
  const terminalCursor = RECOVERY_TERMINAL_CLEANUP_CURSORS[fields.resourceType];
  if (fields.cleanupCursor !== terminalCursor || fields.cleanupProgressDigest === null || fields.cleanupProofDigest === null) {
    throw new TypeError('Recovery intent row must use the canonical terminal cleanup state.');
  }
  if (recoveryCheckpointDigest === null) {
    for (const key of ORDINARY_EXECUTION_EVIDENCE_KEYS) {
      if (fields[key] === null) throw new TypeError('Ordinary terminal intent requires retained execution evidence.');
    }
    if (fields.cleanupRunnerExecutionCursor !== getCleanupExecutionPlan(fields.resourceType).knownCalls) {
      throw new TypeError('Ordinary terminal intent requires the complete fixed execution plan.');
    }
  } else {
    const values = ORDINARY_EXECUTION_EVIDENCE_KEYS.map((key) => fields[key]);
    if (!values.every((entry) => entry === null) && !values.every((entry) => entry !== null)) {
      throw new TypeError('Recovery terminal ordinary execution evidence must be an exact tuple.');
    }
  }
  return copyExact(supplied, keys);
}

function readRecoveryIntentSet(value, label) {
  const fields = readExact(value, ['intents'], label);
  const intents = readDenseArray(fields.intents, `${label} intents`);
  if (intents.length !== QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.length) throw new TypeError(`${label} must contain exactly three intents.`);
  const rows = intents.map((intent) => validateRecoveryIntentRow(intent));
  for (const [index, resourceType] of QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.entries()) {
    if (rows[index].resourceType !== resourceType) throw new TypeError(`${label} resource order is not canonical.`);
  }
  if (new Set(rows.map(({ intentId }) => intentId)).size !== rows.length) throw new TypeError(`${label} intent IDs must be unique.`);
  return rows;
}

function recoveryIntentSetDigest(intents, normalizedRecoveryLinkIndex = null) {
  const projection = intents.map((intent, index) => Object.fromEntries(INTENT_SNAPSHOT_V2_KEYS.map((key) => [key,
    key === 'recoveryCheckpointDigest' && index === normalizedRecoveryLinkIndex ? null : (intent[key] ?? null),
  ])));
  return sha256Bytes(encoder.encode(canonicalJson({ schemaVersion: 'verification-recovery-intent-set-projection.v1', intents: projection })));
}

export function createRecoveryIntentSetDigest(value) {
  return recoveryIntentSetDigest(readRecoveryIntentSet(value, 'Recovery intent set'));
}

export function createRecoveryCurrentIntentSetDigest(value) {
  const fields = readExact(value, ['intents', 'recoveryTerminalIndex'], 'Recovery current intent set');
  assertNonNegativeInteger(fields.recoveryTerminalIndex, 'Recovery current intent set recoveryTerminalIndex');
  const intents = readRecoveryIntentSet({ intents: fields.intents }, 'Recovery current intent set');
  const terminal = intents[fields.recoveryTerminalIndex];
  if (!terminal || terminal.state !== 'absent' || typeof terminal.recoveryCheckpointDigest !== 'string') {
    throw new TypeError('Recovery current intent set must normalize exactly one recovery terminal link.');
  }
  return recoveryIntentSetDigest(intents, fields.recoveryTerminalIndex);
}

export function createOrdinaryExecutionEvidenceDigest(value) {
  const intents = readRecoveryIntentSet(value, 'Ordinary execution evidence');
  validateRecoverySetExecutionEvidence(intents, 'Ordinary execution evidence');
  const resources = intents.map((intent) => Object.freeze({
    logicalResource: intent.resourceType,
    cleanupRunnerExecutionPlanDigest: intent.cleanupRunnerExecutionPlanDigest,
    cleanupRunnerExecutionCursor: intent.cleanupRunnerExecutionCursor,
    cleanupRunnerExecutionSlotsJson: intent.cleanupRunnerExecutionSlotsJson,
    cleanupRunnerExecutionRecordDigest: intent.cleanupRunnerExecutionRecordDigest,
    cleanupRunnerExecutionRetentionExpiresAt: intent.cleanupRunnerExecutionRetentionExpiresAt,
  }));
  return sha256Bytes(encoder.encode(canonicalJson({ schemaVersion: 'verification-ordinary-execution-evidence-projection.v1', resources })));
}

function recoveryCatalogPosition(checkpoint) {
  const position = deriveRecoveryPosition({
    prefixLength: checkpoint.prefixLength,
    intentDispositionCursor: checkpoint.intentDispositionCursor,
  });
  return Object.freeze({
    prefixLength: checkpoint.prefixLength,
    intentDispositionCursor: checkpoint.intentDispositionCursor,
    logicalResource: position.logicalResource,
    stepId: position.stepId,
    phase: position.phase,
    action: position.action,
  });
}

function recoveryGenesisProgressDigest(checkpoint) {
  return digestDomain('verification-recovery-progress-genesis.v1', {
    schemaVersion: RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    source: {
      environmentDigest: checkpoint.environmentDigest,
      cleanupProtocolDigest: checkpoint.cleanupProtocolDigest,
      sourceAuditHeadDigest: checkpoint.sourceAuditHeadDigest,
      sourceLeaseVersion: checkpoint.sourceLeaseVersion,
      sourceLedgerDigest: checkpoint.sourceLedgerDigest,
      sourceIntentSetDigest: checkpoint.sourceIntentSetDigest,
      currentIntentSetDigest: checkpoint.currentIntentSetDigest,
      ordinaryExecutionEvidenceDigest: checkpoint.ordinaryExecutionEvidenceDigest,
      accountSessionAbsenceDigest: checkpoint.accountSessionAbsenceDigest,
    },
    transition: 'recovery.checkpoint_started',
    catalogPosition: recoveryCatalogPosition(checkpoint),
    targetBindingDigest: checkpoint.targetBindingDigest,
    providerObservationDigest: checkpoint.providerObservationDigest,
  });
}

function recoverySuccessorProgressDigest(predecessor, candidate, transition) {
  return digestDomain('verification-recovery-progress-link.v1', {
    schemaVersion: RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    priorRecoveryProgressDigest: predecessor.recoveryProgressDigest,
    transition,
    catalogPosition: recoveryCatalogPosition(predecessor),
    targetBindingDigest: predecessor.targetBindingDigest,
    providerObservationDigest: candidate.providerObservationDigest,
  });
}

function recoveryTerminalIntentDigests(checkpoint, logicalResource, cleanupCursor) {
  const cleanupProgressDigest = digestDomain('verification-recovery-terminal-cleanup-progress.v1', {
    schemaVersion: RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    sourceIntentSetDigest: checkpoint.sourceIntentSetDigest,
    logicalResource,
    cleanupCursor,
    recoveryProgressDigest: checkpoint.recoveryProgressDigest,
  });
  const cleanupProofDigest = digestDomain('verification-recovery-terminal-cleanup-proof.v1', {
    schemaVersion: RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    logicalResource,
    cleanupCursor,
    cleanupProgressDigest,
    providerObservationDigest: checkpoint.providerObservationDigest,
  });
  return Object.freeze({ cleanupProgressDigest, cleanupProofDigest });
}

function recoveryResourcesProofDigest(checkpoint) {
  return digestDomain('verification-recovery-resources-proof.v1', {
    schemaVersion: RECOVERY_CHECKPOINT_SCHEMA_VERSION,
    resourceOrder: QUALIFIED_CLEANUP_PROTOCOL.resourceOrder,
    recoveryProgressDigest: checkpoint.recoveryProgressDigest,
    currentIntentSetDigest: checkpoint.currentIntentSetDigest,
  });
}

export function validateRecoveryCheckpoint(value) {
  const fields = readExact(value, RECOVERY_CHECKPOINT_KEYS, 'Recovery checkpoint');
  if (fields.schemaVersion !== RECOVERY_CHECKPOINT_SCHEMA_VERSION
    || !['ready', 'write-issued', 'blocked', 'resources-complete'].includes(fields.checkpointState)) {
    throw new TypeError('Recovery checkpoint has an invalid schema or state.');
  }
  for (const key of [
    'environmentDigest', 'cleanupProtocolDigest', 'sourceAuditHeadDigest', 'sourceLedgerDigest',
    'sourceIntentSetDigest', 'currentIntentSetDigest', 'ordinaryExecutionEvidenceDigest',
    'accountSessionAbsenceDigest', 'recoveryProgressDigest',
  ]) assertDigest(fields[key], `Recovery checkpoint ${key}`);
  if (fields.cleanupProtocolDigest !== CLEANUP_PROTOCOL_DIGEST) throw new TypeError('Recovery checkpoint cleanupProtocolDigest must match the fixed catalog.');
  assertNonNegativeInteger(fields.sourceLeaseVersion, 'Recovery checkpoint sourceLeaseVersion');
  assertNonNegativeInteger(fields.eventOrdinal, 'Recovery checkpoint eventOrdinal');
  assertNonNegativeInteger(fields.prefixLength, 'Recovery checkpoint prefixLength');
  assertNonNegativeInteger(fields.intentDispositionCursor, 'Recovery checkpoint intentDispositionCursor');
  const position = deriveRecoveryPosition({
    prefixLength: fields.prefixLength,
    intentDispositionCursor: fields.intentDispositionCursor,
  });
  for (const key of ['logicalResource', 'stepId', 'phase', 'action']) {
    if (fields[key] !== position[key]) throw new TypeError(`Recovery checkpoint forged ${key}.`);
  }
  if (fields.prefixLength === RECOVERY_COUNTS.semanticTransitions) {
    if (!['ready', 'resources-complete'].includes(fields.checkpointState)) throw new TypeError('Recovery terminal prefix requires ready or resources-complete.');
  } else if (fields.checkpointState === 'resources-complete') {
    throw new TypeError('resources-complete requires the terminal catalog prefix.');
  }
  if (fields.eventOrdinal === 0) {
    if (fields.priorCheckpointDigest !== null || fields.checkpointState !== 'ready'
      || !isCanonicalRecoveryGenesisPosition(fields.prefixLength, fields.intentDispositionCursor)
      || fields.providerObservationDigest !== null) {
      throw new TypeError('Recovery genesis must be ready at a canonical ordinary-absence prefix with no predecessor.');
    }
  } else {
    assertDigest(fields.priorCheckpointDigest, 'Recovery checkpoint priorCheckpointDigest');
  }
  const detail = fields.prefixLength === RECOVERY_COUNTS.semanticTransitions
    ? null : getRecoveryTransitionDetailAt(fields.prefixLength);
  if (detail === null) {
    for (const key of ['targetBindingDigest', 'attemptOrdinal', 'preWriteProjectionDigest', 'desiredProjectionDigest']) if (fields[key] !== null) throw new TypeError(`Recovery terminal ${key} must be null.`);
    if (fields.checkpointState === 'ready') {
      if (fields.eventOrdinal === 0) {
        if (fields.providerObservationDigest !== null) throw new TypeError('Recovery terminal genesis observation must be null.');
      } else assertDigest(fields.providerObservationDigest, 'Recovery terminal ready providerObservationDigest');
      if (fields.cleanupProofDigest !== null) throw new TypeError('Recovery terminal ready cleanupProofDigest must be null.');
    } else {
      if (fields.providerObservationDigest !== null) throw new TypeError('Recovery resources-complete providerObservationDigest must be null.');
      assertDigest(fields.cleanupProofDigest, 'Recovery terminal cleanupProofDigest');
    }
  } else {
    assertDigest(fields.targetBindingDigest, 'Recovery checkpoint targetBindingDigest');
    if (fields.checkpointState === 'ready') {
      for (const key of [
        'attemptOrdinal', 'preWriteProjectionDigest', 'desiredProjectionDigest',
        'cleanupProofDigest',
      ]) if (fields[key] !== null) throw new TypeError(`Recovery ready ${key} must be null.`);
      if (fields.eventOrdinal === 0) {
        if (fields.providerObservationDigest !== null) throw new TypeError('Recovery genesis observation must be null.');
      } else assertDigest(fields.providerObservationDigest, 'Recovery ready providerObservationDigest');
    } else {
      if (detail.stepKind !== 'mutation' || ![1, 2].includes(fields.attemptOrdinal)) {
        throw new TypeError('Recovery mutation state must select a mutation and attempt.');
      }
      assertDigest(fields.preWriteProjectionDigest, 'Recovery mutation preWriteProjectionDigest');
      assertDigest(fields.desiredProjectionDigest, 'Recovery mutation desiredProjectionDigest');
      if (fields.cleanupProofDigest !== null) throw new TypeError('Recovery mutation cleanupProofDigest must be null.');
      if (fields.checkpointState === 'write-issued') {
        if (fields.providerObservationDigest !== null) throw new TypeError('Recovery write-issued observation must be null.');
      } else if (fields.checkpointState === 'blocked') {
        assertDigest(fields.providerObservationDigest, 'Recovery blocked providerObservationDigest');
      } else {
        throw new TypeError('Recovery terminal state must not select an active transition.');
      }
    }
  }
  if (fields.eventOrdinal === 0 && fields.recoveryProgressDigest !== recoveryGenesisProgressDigest(fields)) {
    throw new TypeError('Recovery genesis progress digest does not match its source evidence.');
  }
  return copyExact(fields, RECOVERY_CHECKPOINT_KEYS);
}

export function createRecoveryCheckpointDigest(value) {
  return sha256Bytes(encoder.encode(canonicalJson(validateRecoveryCheckpoint(value))));
}

const RECOVERY_AUDIT_TRANSITIONS = new Set([
  'recovery.checkpoint_started', 'recovery.mutation_issued', 'recovery.mutation_not_committed',
  'recovery.step_committed', 'recovery.step_blocked', 'intent.recovery_absent',
  'recovery.resources_completed',
]);
const TERMINAL_INTENT_TRANSITION_KEYS = Object.freeze([
  'predecessor', 'candidate', 'sourceIntents', 'priorIntents', 'currentIntents',
]);

function assertRecoveryAuditTransition(value, label) {
  if (typeof value !== 'string' || !RECOVERY_AUDIT_TRANSITIONS.has(value)) throw new TypeError(`${label} is not a recovery audit transition.`);
  return value;
}

function assertRecoveryPredecessorTransition(checkpoint, transition) {
  if (checkpoint.checkpointState === 'resources-complete' && transition !== 'recovery.resources_completed') throw new TypeError('resources-complete has no successor.');
  if (checkpoint.checkpointState === 'write-issued' && transition !== 'recovery.mutation_issued') throw new TypeError('write-issued must have been minted by mutation_issued.');
  if (checkpoint.checkpointState === 'blocked') {
    if (checkpoint.providerObservationDigest === checkpoint.desiredProjectionDigest) {
      throw new TypeError('Desired mutation observation must not be represented as blocked.');
    }
    const expectedTransition = checkpoint.attemptOrdinal === 1
      && checkpoint.providerObservationDigest === checkpoint.preWriteProjectionDigest
      ? 'recovery.mutation_not_committed' : 'recovery.step_blocked';
    if (transition !== expectedTransition) throw new TypeError('Blocked checkpoint does not authenticate its observation-derived transition.');
  }
  if (checkpoint.checkpointState === 'ready') {
    let expectedTransition;
    if (checkpoint.eventOrdinal === 0) {
      expectedTransition = 'recovery.checkpoint_started';
    } else {
      if (checkpoint.prefixLength === 0) throw new TypeError('Non-genesis ready checkpoint cannot remain at prefix zero.');
      expectedTransition = getRecoveryTransitionDetailAt(checkpoint.prefixLength - 1).stepId.endsWith('.absent')
        ? 'intent.recovery_absent' : 'recovery.step_committed';
    }
    if (transition !== expectedTransition) throw new TypeError('Ready checkpoint does not authenticate its exact predecessor transition.');
  }
}

function readRecoveryAuditEvent(value, label = 'Recovery audit event') {
  const fields = readExact(value, RECOVERY_AUDIT_EVENT_KEYS, label);
  if (fields.schemaVersion !== 'verification-audit-event.v1') throw new TypeError(`${label} has an invalid schema version.`);
  assertDigest(fields.previousLedgerDigest, `${label} previousLedgerDigest`);
  assertString(fields.runId, `${label} runId`, { minLength: 1, maxLength: 512 });
  assertNonNegativeInteger(fields.leaseVersionBefore, `${label} leaseVersionBefore`);
  assertPositiveInteger(fields.leaseVersionAfter, `${label} leaseVersionAfter`);
  if (fields.leaseVersionAfter !== fields.leaseVersionBefore + 1) throw new TypeError(`${label} lease version must advance exactly once.`);
  const transition = assertRecoveryAuditTransition(fields.transition, `${label} transition`);
  const checkpoint = validateRecoveryCheckpoint(parseCanonicalJson(
    fields.recoveryCheckpointJson,
    `${label} recoveryCheckpointJson`,
  ));
  const checkpointDigest = createRecoveryCheckpointDigest(checkpoint);
  if (fields.recoveryCheckpointDigest !== checkpointDigest
    || fields.recoveryPreviousCheckpointDigest !== checkpoint.priorCheckpointDigest) {
    throw new TypeError(`${label} does not embed the exact checkpoint link.`);
  }
  const expectedLeaseVersionBefore = checkpoint.sourceLeaseVersion + checkpoint.eventOrdinal;
  if (!Number.isSafeInteger(expectedLeaseVersionBefore)
    || fields.leaseVersionBefore !== expectedLeaseVersionBefore) {
    throw new TypeError(`${label} lease version does not match the checkpoint ordinal.`);
  }
  if (checkpoint.eventOrdinal === 0
    && fields.previousLedgerDigest !== checkpoint.sourceLedgerDigest) {
    throw new TypeError(`${label} genesis does not link the source audit head.`);
  }
  if (transition === 'intent.recovery_absent') {
    if (typeof fields.intentId !== 'string' || !INTENT_ID_PATTERN.test(fields.intentId)) {
      throw new TypeError(`${label} recovery absence requires one exact intent ID.`);
    }
    assertDigest(fields.intentProjectionDigest, `${label} intentProjectionDigest`);
  } else if (fields.intentId !== null || fields.intentProjectionDigest !== null) {
    throw new TypeError(`${label} non-intent recovery event must not select an intent.`);
  }
  assertRecoveryPredecessorTransition(checkpoint, transition);
  const event = copyExact(fields, RECOVERY_AUDIT_EVENT_KEYS);
  return Object.freeze({
    event,
    checkpoint,
    digest: sha256Bytes(encoder.encode(canonicalJson(event))),
  });
}

export function validateRecoveryAuditEvent(value) {
  const { event, checkpoint } = readRecoveryAuditEvent(value);
  return Object.freeze({ event, checkpoint });
}

export function createRecoveryAuditEventDigest(value) {
  return readRecoveryAuditEvent(value).digest;
}

function sameRecoveryMutationIdentity(predecessor, candidate) {
  return ['targetBindingDigest', 'preWriteProjectionDigest', 'desiredProjectionDigest']
    .every((key) => predecessor[key] === candidate[key]);
}

function normalizedTerminalIntent(value, label, requireRecoveryDigest) {
  const row = validateRecoveryIntentRow(value);
  const normalized = Object.freeze({ ...row, recoveryCheckpointDigest: row.recoveryCheckpointDigest ?? null });
  if (requireRecoveryDigest && typeof normalized.recoveryCheckpointDigest !== 'string') throw new TypeError(`${label} must contain a recovery checkpoint digest.`);
  return normalized;
}

export function validateRecoveryTerminalIntentSuccessor(value) {
  const fields = readExact(value, ['predecessor', 'candidate', 'predecessorCheckpoint', 'checkpoint', 'authenticatedCheckpointDigest', 'intentDispositionCursorBefore', 'intentDispositionCursorAfter', 'sourceIntents', 'priorIntents', 'currentIntents'], 'Recovery terminal intent successor');
  const predecessor = normalizedTerminalIntent(fields.predecessor, 'Recovery terminal predecessor', false);
  const candidate = normalizedTerminalIntent(fields.candidate, 'Recovery terminal candidate', true);
  const predecessorCheckpoint = validateRecoveryCheckpoint(fields.predecessorCheckpoint);
  const checkpoint = validateRecoveryCheckpoint(fields.checkpoint);
  const sourceIntents = readRecoveryIntentSet({ intents: fields.sourceIntents }, 'Recovery terminal source intent set');
  const priorIntents = readRecoveryIntentSet({ intents: fields.priorIntents }, 'Recovery terminal prior intent set');
  const currentIntents = readRecoveryIntentSet({ intents: fields.currentIntents }, 'Recovery terminal current intent set');
  assertDigest(fields.authenticatedCheckpointDigest, 'Recovery terminal authenticatedCheckpointDigest');
  assertNonNegativeInteger(fields.intentDispositionCursorBefore, 'Recovery terminal intentDispositionCursorBefore');
  assertNonNegativeInteger(fields.intentDispositionCursorAfter, 'Recovery terminal intentDispositionCursorAfter');
  if (!['created', 'cleaning'].includes(predecessor.state) || candidate.state !== 'absent' || predecessor.recoveryCheckpointDigest !== null || candidate.intentVersion !== predecessor.intentVersion + 1) throw new TypeError('Recovery terminal successor has an invalid terminal branch.');
  if (checkpoint.sourceIntentSetDigest !== predecessorCheckpoint.sourceIntentSetDigest || checkpoint.ordinaryExecutionEvidenceDigest !== predecessorCheckpoint.ordinaryExecutionEvidenceDigest || checkpoint.prefixLength !== predecessorCheckpoint.prefixLength + 1 || fields.intentDispositionCursorAfter !== fields.intentDispositionCursorBefore + 1 || checkpoint.checkpointState !== 'ready' || checkpoint.intentDispositionCursor !== fields.intentDispositionCursorAfter || checkpoint.prefixLength === 0) throw new TypeError('Recovery terminal disposition cursor is not a canonical boundary.');
  const logicalResource = QUALIFIED_CLEANUP_PROTOCOL.resourceOrder[fields.intentDispositionCursorBefore];
  const boundary = getRecoveryTransitionDetailAt(checkpoint.prefixLength - 1);
  if (!logicalResource || boundary.logicalResource !== logicalResource || !boundary.stepId.endsWith('.absent') || candidate.resourceType !== logicalResource || candidate.cleanupCursor !== RECOVERY_TERMINAL_CLEANUP_CURSORS[logicalResource]) throw new TypeError('Recovery terminal does not select the exact canonical resource boundary.');
  const expectedTerminalDigests = recoveryTerminalIntentDigests(checkpoint, logicalResource, candidate.cleanupCursor);
  if (candidate.cleanupProgressDigest !== expectedTerminalDigests.cleanupProgressDigest
    || candidate.cleanupProofDigest !== expectedTerminalDigests.cleanupProofDigest) {
    throw new TypeError('Recovery terminal progress or proof digest does not match the authenticated checkpoint evidence.');
  }
  if (createRecoveryCheckpointDigest(checkpoint) !== fields.authenticatedCheckpointDigest || candidate.recoveryCheckpointDigest !== fields.authenticatedCheckpointDigest) throw new TypeError('Recovery terminal checkpoint link is invalid.');
  if (recoveryIntentSetDigest(sourceIntents) !== checkpoint.sourceIntentSetDigest || recoveryIntentSetDigest(priorIntents, fields.intentDispositionCursorBefore === 0 ? null : fields.intentDispositionCursorBefore - 1) !== predecessorCheckpoint.currentIntentSetDigest || recoveryIntentSetDigest(currentIntents, fields.intentDispositionCursorBefore) !== checkpoint.currentIntentSetDigest) throw new TypeError('Recovery terminal intent-set digest mismatch.');
  if (createOrdinaryExecutionEvidenceDigest({ intents: sourceIntents }) !== checkpoint.ordinaryExecutionEvidenceDigest || createOrdinaryExecutionEvidenceDigest({ intents: priorIntents }) !== checkpoint.ordinaryExecutionEvidenceDigest || createOrdinaryExecutionEvidenceDigest({ intents: currentIntents }) !== checkpoint.ordinaryExecutionEvidenceDigest) throw new TypeError('Recovery terminal ordinary-evidence digest mismatch.');
  validateRecoverySetExecutionEvidence(sourceIntents, 'Recovery terminal source set');
  validateRecoverySetExecutionEvidence(priorIntents, 'Recovery terminal prior set');
  validateRecoverySetExecutionEvidence(currentIntents, 'Recovery terminal current set');
  if (canonicalJson(normalizedTerminalIntent(priorIntents[fields.intentDispositionCursorBefore], 'Recovery terminal prior set predecessor', false)) !== canonicalJson(predecessor) || canonicalJson(normalizedTerminalIntent(currentIntents[fields.intentDispositionCursorBefore], 'Recovery terminal current set candidate', true)) !== canonicalJson(candidate)) throw new TypeError('Recovery terminal candidate does not occupy the exact canonical set position.');
  let sourceOrdinaryAbsentPrefix = 0;
  while (sourceOrdinaryAbsentPrefix < sourceIntents.length
    && sourceIntents[sourceOrdinaryAbsentPrefix].state === 'absent') {
    if ((sourceIntents[sourceOrdinaryAbsentPrefix].recoveryCheckpointDigest ?? null) !== null) {
      throw new TypeError('Recovery terminal source set cannot contain a recovery-linked absence.');
    }
    sourceOrdinaryAbsentPrefix += 1;
  }
  if (sourceIntents.slice(sourceOrdinaryAbsentPrefix).some(({ state }) => state === 'absent')
    || sourceOrdinaryAbsentPrefix > fields.intentDispositionCursorBefore) {
    throw new TypeError('Recovery terminal source ordinary absences must form the approved prefix.');
  }
  for (const index of [0, 1, 2]) {
    const sourceBytes = canonicalJson(sourceIntents[index]);
    const priorBytes = canonicalJson(priorIntents[index]);
    const currentBytes = canonicalJson(currentIntents[index]);
    if (index < fields.intentDispositionCursorBefore) {
      if (priorIntents[index].state !== 'absent' || priorBytes !== currentBytes) {
        throw new TypeError('Recovery terminal earlier dispositions must be terminal and byte-identical.');
      }
      if (sourceIntents[index].state === 'absent') {
        if (sourceBytes !== priorBytes) throw new TypeError('Recovery terminal ordinary source absence changed.');
      } else {
        if (!['created', 'cleaning'].includes(sourceIntents[index].state)
          || typeof priorIntents[index].recoveryCheckpointDigest !== 'string'
          || priorIntents[index].intentVersion !== sourceIntents[index].intentVersion + 1) {
          throw new TypeError('Recovery terminal earlier disposition is not an exact recovery terminal.');
        }
        for (const key of INTENT_SNAPSHOT_V2_KEYS) if (!RECOVERY_TERMINAL_MUTABLE_INTENT_KEYS.has(key) && priorIntents[index][key] !== sourceIntents[index][key]) throw new TypeError(`Recovery terminal earlier disposition modified immutable field ${key}.`);
        for (const key of ORDINARY_EXECUTION_EVIDENCE_KEYS) if (priorIntents[index][key] !== sourceIntents[index][key]) throw new TypeError(`Recovery terminal earlier disposition modified ordinary execution evidence ${key}.`);
      }
    } else if (index === fields.intentDispositionCursorBefore) {
      if (sourceBytes !== priorBytes) throw new TypeError('Recovery terminal current predecessor must remain source-identical.');
    } else if (sourceBytes !== priorBytes || priorBytes !== currentBytes) {
      throw new TypeError('Recovery terminal later intents must remain source-identical.');
    }
  }
  for (const key of INTENT_SNAPSHOT_V2_KEYS) if (!RECOVERY_TERMINAL_MUTABLE_INTENT_KEYS.has(key) && candidate[key] !== predecessor[key]) throw new TypeError(`Recovery terminal successor modified immutable field ${key}.`);
  for (const key of ORDINARY_EXECUTION_EVIDENCE_KEYS) if (candidate[key] !== predecessor[key]) throw new TypeError(`Recovery terminal successor modified ordinary execution evidence ${key}.`);
  return Object.freeze({ predecessor, candidate, predecessorCheckpoint, checkpoint });
}

export function validateRecoveryCheckpointSuccessor(value) {
  const fields = readExact(value, [
    'authenticatedAuditHeadDigest', 'predecessorEvent', 'event', 'terminalIntentTransition',
  ], 'Recovery checkpoint successor');
  const predecessorEvent = readRecoveryAuditEvent(fields.predecessorEvent, 'Recovery predecessor audit event');
  const candidateEvent = readRecoveryAuditEvent(fields.event, 'Recovery candidate audit event');
  const predecessor = predecessorEvent.checkpoint;
  const candidate = candidateEvent.checkpoint;
  assertDigest(fields.authenticatedAuditHeadDigest, 'Recovery authenticated audit head digest');
  if (predecessorEvent.digest !== fields.authenticatedAuditHeadDigest
    || candidateEvent.event.previousLedgerDigest !== fields.authenticatedAuditHeadDigest
    || candidateEvent.event.runId !== predecessorEvent.event.runId
    || candidateEvent.event.leaseVersionBefore !== predecessorEvent.event.leaseVersionAfter) {
    throw new TypeError('Recovery checkpoint successor does not authenticate its exact audit edge.');
  }
  const predecessorDigest = predecessorEvent.event.recoveryCheckpointDigest;
  const predecessorTransition = predecessorEvent.event.transition;
  const transition = candidateEvent.event.transition;
  if (candidate.recoveryProgressDigest !== recoverySuccessorProgressDigest(predecessor, candidate, transition)) {
    throw new TypeError('Recovery checkpoint successor progress digest does not match its authenticated transition evidence.');
  }
  if (candidate.priorCheckpointDigest !== predecessorDigest
    || candidate.eventOrdinal !== predecessor.eventOrdinal + 1) {
    throw new TypeError('Recovery checkpoint successor does not link its exact predecessor.');
  }
  for (const key of RECOVERY_CHECKPOINT_IMMUTABLE_SUCCESSOR_KEYS) if (candidate[key] !== predecessor[key]) throw new TypeError(`Recovery checkpoint successor modified immutable ${key}.`);
  const samePosition = candidate.prefixLength === predecessor.prefixLength && candidate.intentDispositionCursor === predecessor.intentDispositionCursor;
  const nextPrefix = predecessor.prefixLength + 1;
  const nextCursor = predecessor.intentDispositionCursor + (predecessor.prefixLength < RECOVERY_COUNTS.semanticTransitions && getRecoveryTransitionDetailAt(predecessor.prefixLength).stepId.endsWith('.absent') ? 1 : 0);
  if (nextPrefix <= RECOVERY_COUNTS.semanticTransitions) deriveRecoveryPosition({ prefixLength: nextPrefix, intentDispositionCursor: nextCursor });
  const nextPosition = nextPrefix <= RECOVERY_COUNTS.semanticTransitions && candidate.prefixLength === nextPrefix && candidate.intentDispositionCursor === nextCursor;
  if (predecessor.checkpointState === 'resources-complete') throw new TypeError('resources-complete has no successor.');
  if (predecessor.prefixLength === RECOVERY_COUNTS.semanticTransitions) {
    if (predecessor.checkpointState !== 'ready' || candidate.checkpointState !== 'resources-complete' || !samePosition || transition !== 'recovery.resources_completed' || fields.terminalIntentTransition !== null || candidate.currentIntentSetDigest !== predecessor.currentIntentSetDigest
      || candidate.cleanupProofDigest !== recoveryResourcesProofDigest(candidate)) {
      throw new TypeError('Only terminal ready may complete resources with the exact terminal proof.');
    }
    return Object.freeze({ predecessor, candidate, predecessorAuditEvent: predecessorEvent.event, candidateAuditEvent: candidateEvent.event });
  }
  const detail = getRecoveryTransitionDetailAt(predecessor.prefixLength);
  let absence = false;
  if (predecessor.checkpointState === 'ready') {
    if (detail.stepKind === 'mutation') {
      if (candidate.checkpointState !== 'write-issued' || candidate.attemptOrdinal !== 1 || !samePosition || transition !== 'recovery.mutation_issued' || candidate.targetBindingDigest !== predecessor.targetBindingDigest) throw new TypeError('Ready mutation must issue attempt one with the exact target and mutation_issued evidence.');
    } else {
      absence = detail.stepId.endsWith('.absent');
      const expectedTransition = absence ? 'intent.recovery_absent' : 'recovery.step_committed';
      if (candidate.checkpointState !== 'ready' || !nextPosition || transition !== expectedTransition) throw new TypeError('Ready read/proof must advance with its exact audit transition.');
    }
  } else if (predecessor.checkpointState === 'write-issued') {
    if (candidate.checkpointState === 'blocked') {
      const expectedTransition = predecessor.attemptOrdinal === 1
        && candidate.providerObservationDigest === predecessor.preWriteProjectionDigest
        ? 'recovery.mutation_not_committed' : 'recovery.step_blocked';
      if (!samePosition || candidate.attemptOrdinal !== predecessor.attemptOrdinal || transition !== expectedTransition || !sameRecoveryMutationIdentity(predecessor, candidate)) throw new TypeError('Mutation block must retain exact identity and use its observation-derived audit transition.');
    } else if (candidate.checkpointState !== 'ready' || !nextPosition
      || transition !== 'recovery.step_committed'
      || candidate.providerObservationDigest !== predecessor.desiredProjectionDigest) {
      throw new TypeError('Desired mutation observation must advance with step_committed evidence.');
    }
  } else if (predecessor.checkpointState === 'blocked') {
    if (predecessorTransition !== 'recovery.mutation_not_committed' || predecessor.attemptOrdinal !== 1 || candidate.checkpointState !== 'write-issued' || candidate.attemptOrdinal !== 2 || !samePosition || transition !== 'recovery.mutation_issued' || !sameRecoveryMutationIdentity(predecessor, candidate)) throw new TypeError('Only mutation_not_committed blocked attempt one may issue exact attempt two.');
  } else throw new TypeError('Invalid recovery checkpoint lifecycle state.');
  if (absence) {
    if (candidate.currentIntentSetDigest === predecessor.currentIntentSetDigest || fields.terminalIntentTransition === null) throw new TypeError('intent.recovery_absent must compose an exact terminal intent transition.');
    const terminalFields = readExact(fields.terminalIntentTransition, TERMINAL_INTENT_TRANSITION_KEYS, 'Recovery terminal intent transition');
    const terminal = validateRecoveryTerminalIntentSuccessor({
      ...terminalFields,
      predecessorCheckpoint: predecessor,
      checkpoint: candidate,
      authenticatedCheckpointDigest: candidateEvent.event.recoveryCheckpointDigest,
      intentDispositionCursorBefore: predecessor.intentDispositionCursor,
      intentDispositionCursorAfter: candidate.intentDispositionCursor,
    });
    const intentProjectionDigest = sha256Bytes(encoder.encode(canonicalJson(terminal.candidate)));
    if (candidateEvent.event.intentId !== terminal.candidate.intentId
      || candidateEvent.event.intentProjectionDigest !== intentProjectionDigest) {
      throw new TypeError('intent.recovery_absent audit event does not bind the exact terminal intent.');
    }
  } else {
    if (candidate.currentIntentSetDigest !== predecessor.currentIntentSetDigest || fields.terminalIntentTransition !== null) throw new TypeError('Only intent.recovery_absent may change the current intent set.');
  }
  return Object.freeze({ predecessor, candidate, predecessorAuditEvent: predecessorEvent.event, candidateAuditEvent: candidateEvent.event });
}
export function getCleanupExecutionPlan(logicalResource) {
  return requireResource(logicalResource).executionPlan;
}

function validateGenesis(value, expectedPhase, extraKeys) {
  const fields = readExact(value, [
    'schemaVersion',
    'environmentDigest',
    'providerContractDigest',
    'providerAggregateDigest',
    'intentId',
    'intentVersion',
    'intentProjectionDigest',
    'logicalResource',
    'phase',
    'phaseStepCount',
    'cleanupRunnerExecutionPlanDigest',
    ...extraKeys,
  ], 'Cleanup digest genesis');
  const catalog = requireResource(fields.logicalResource);
  const steps = expectedPhase === 'preflight' ? catalog.preflight
    : expectedPhase === 'cleanup' ? catalog.mutation : catalog.proof;
  if (fields.schemaVersion !== CLEANUP_PROTOCOL_SCHEMA_VERSION || fields.phase !== expectedPhase
    || fields.phaseStepCount !== steps.length
    || fields.cleanupRunnerExecutionPlanDigest !== catalog.executionPlan.digest) {
    throw new TypeError('Cleanup digest genesis does not match the fixed catalog.');
  }
  assertDigest(fields.environmentDigest, 'environmentDigest');
  assertDigest(fields.providerContractDigest, 'providerContractDigest');
  assertDigest(fields.providerAggregateDigest, 'providerAggregateDigest');
  if (typeof fields.intentId !== 'string' || !INTENT_ID_PATTERN.test(fields.intentId)) {
    throw new TypeError('intentId must be 64 lowercase hex characters.');
  }
  assertPositiveInteger(fields.intentVersion, 'intentVersion');
  assertDigest(fields.intentProjectionDigest, 'intentProjectionDigest');
  for (const key of extraKeys) assertDigest(fields[key], key);
  return fields;
}

export function createCleanupPhaseGenesisDigest(value) {
  return digestDomain(
    'test-cloud-cleanup-phase-genesis.v1',
    validateGenesis(value, 'preflight', []),
  );
}

export function createCleanupProgressGenesisDigest(value) {
  return digestDomain(
    'test-cloud-cleanup-progress-genesis.v1',
    validateGenesis(value, 'cleanup', ['preflightDigest']),
  );
}

export function createCleanupProofGenesisDigest(value) {
  return digestDomain(
    'test-cloud-cleanup-proof-genesis.v1',
    validateGenesis(value, 'proof', ['finalCleanupProgressDigest']),
  );
}

function validateLink(value, keys, priorKey, cursorKey, phase, steps, label) {
  const fields = readExact(value, keys, label);
  assertDigest(fields[priorKey], priorKey);
  const catalog = requireResource(fields.logicalResource);
  const selectedSteps = steps(catalog);
  assertNonNegativeInteger(fields[cursorKey], cursorKey);
  const step = selectedSteps[fields[cursorKey]];
  if (!step || fields.stepId !== step.stepId || fields.result !== RESULT
    || (phase !== null && fields.phase !== phase)) {
    throw new TypeError(`${label} cursor, step, phase, or result does not match the fixed catalog.`);
  }
  return fields;
}

export function advanceCleanupPhaseDigest(value) {
  return digestDomain('test-cloud-cleanup-phase-link.v1', validateLink(
    value,
    ['priorPhaseDigest', 'logicalResource', 'phase', 'phaseCursor', 'stepId', 'result'],
    'priorPhaseDigest',
    'phaseCursor',
    'preflight',
    (catalog) => catalog.preflight,
    'Cleanup phase link',
  ));
}

export function advanceCleanupProgressDigest(value) {
  return digestDomain('test-cloud-cleanup-progress-link.v1', validateLink(
    value,
    ['priorCleanupProgressDigest', 'logicalResource', 'cleanupCursor', 'stepId', 'result'],
    'priorCleanupProgressDigest',
    'cleanupCursor',
    null,
    (catalog) => catalog.mutation,
    'Cleanup progress link',
  ));
}

export function advanceCleanupProofDigest(value) {
  return digestDomain('test-cloud-cleanup-proof-link.v1', validateLink(
    value,
    ['priorCleanupProofDigest', 'logicalResource', 'proofCursor', 'stepId', 'result'],
    'priorCleanupProofDigest',
    'proofCursor',
    null,
    (catalog) => catalog.proof,
    'Cleanup proof link',
  ));
}

function parseFence({ scenarioId, logicalResource, cleanupFence }) {
  const phase = CLEANUP_SCENARIOS[scenarioId];
  if (!phase) throw new TypeError('Scenario is not a cleanup scenario.');
  const catalog = requireResource(logicalResource);
  const fields = readExact(cleanupFence, FENCE_KEYS, 'cleanupFence');
  if (fields.schemaVersion !== FENCE_SCHEMA_VERSION || fields.phase !== phase) {
    throw new TypeError('cleanupFence schema or phase mismatch.');
  }
  assertPositiveInteger(fields.leaseVersion, 'leaseVersion');
  assertDigest(fields.ledgerDigest, 'ledgerDigest');
  if (typeof fields.intentId !== 'string' || !INTENT_ID_PATTERN.test(fields.intentId)) {
    throw new TypeError('cleanupFence intentId is invalid.');
  }
  assertPositiveInteger(fields.intentVersion, 'intentVersion');
  assertDigest(fields.intentProjectionDigest, 'intentProjectionDigest');
  assertDigest(fields.providerContractDigest, 'providerContractDigest');
  assertDigest(fields.providerAggregateDigest, 'providerAggregateDigest');
  assertNonNegativeInteger(fields.phaseCursor, 'phaseCursor');
  assertPositiveInteger(fields.phaseStepCount, 'phaseStepCount');
  assertDigest(fields.priorPhaseDigest, 'priorPhaseDigest', true);
  assertNonNegativeInteger(fields.cleanupCursor, 'cleanupCursor');
  assertDigest(fields.cleanupProgressDigest, 'cleanupProgressDigest', true);
  assertDigest(fields.cleanupProofDigest, 'cleanupProofDigest', true);
  if (fields.cleanupRunnerExecutionPlanDigest !== catalog.executionPlan.digest) {
    throw new TypeError('cleanupFence execution plan digest mismatch.');
  }
  assertNonNegativeInteger(fields.cleanupRunnerExecutionCursor, 'cleanupRunnerExecutionCursor');
  assertDigest(fields.cleanupRunnerExecutionRecordDigest, 'cleanupRunnerExecutionRecordDigest', true);

  const expectedExecutionCursor = phase === 'preflight' ? fields.phaseCursor
    : phase === 'cleanup' ? catalog.preflight.length + fields.cleanupCursor
      : phase === 'proof' ? catalog.preflight.length + catalog.mutation.length + fields.phaseCursor
        : catalog.executionPlan.knownCalls - 1;
  const expectedStepCount = phase === 'preflight' ? catalog.preflight.length
    : phase === 'cleanup' ? catalog.mutation.length : catalog.proof.length;
  if (fields.phaseStepCount !== expectedStepCount
    || fields.cleanupRunnerExecutionCursor !== expectedExecutionCursor
    || (expectedExecutionCursor === 0
      ? fields.cleanupRunnerExecutionRecordDigest !== null
      : fields.cleanupRunnerExecutionRecordDigest === null)) {
    throw new TypeError('cleanupFence cursor or count mismatch.');
  }

  if (phase === 'preflight') {
    if (fields.phaseCursor >= catalog.preflight.length
      || fields.cleanupCursor !== 0
      || fields.cleanupProgressDigest !== null
      || fields.cleanupProofDigest !== null
      || (fields.phaseCursor === 0
        ? fields.priorPhaseDigest !== null
        : fields.priorPhaseDigest === null)) {
      throw new TypeError('cleanupFence preflight state mismatch.');
    }
  } else if (phase === 'cleanup') {
    if (fields.phaseCursor !== 0
      || fields.cleanupCursor >= catalog.mutation.length
      || fields.priorPhaseDigest === null
      || fields.cleanupProgressDigest === null
      || fields.cleanupProofDigest !== null) {
      throw new TypeError('cleanupFence mutation state mismatch.');
    }
  } else if (phase === 'proof') {
    if (fields.phaseCursor >= catalog.proof.length
      || fields.cleanupCursor !== catalog.mutation.length
      || fields.cleanupProgressDigest === null
      || fields.cleanupProofDigest !== null
      || fields.priorPhaseDigest === null) {
      throw new TypeError('cleanupFence proof state mismatch.');
    }
  } else if (fields.phaseCursor !== catalog.proof.length
    || fields.cleanupCursor !== catalog.mutation.length
    || fields.priorPhaseDigest === null
    || fields.cleanupProgressDigest === null
    || fields.cleanupProofDigest === null) {
    throw new TypeError('cleanupFence terminal state mismatch.');
  }

  return cloneAndFreeze(fields);
}

export function validateCleanupFence(value) {
  try {
    const fields = readExact(
      value,
      ['scenarioId', 'logicalResource', 'cleanupFence'],
      'Cleanup fence validation input',
    );
    parseFence(fields);
    return true;
  } catch {
    return false;
  }
}

export function createCleanupStepRequest(value) {
  const fields = readExact(
    value,
    ['scenarioId', 'logicalResource', 'cleanupFence'],
    'Cleanup request builder input',
  );
  const cleanupFence = parseFence(fields);
  return cloneAndFreeze({
    scenarioId: fields.scenarioId,
    parameters: { logicalResource: fields.logicalResource },
    cleanupFence,
  });
}

function createFenceGenesis({ fence, environmentDigest, logicalResource, phase, extra = {} }) {
  assertDigest(environmentDigest, 'environmentDigest');
  return {
    schemaVersion: CLEANUP_PROTOCOL_SCHEMA_VERSION,
    environmentDigest,
    providerContractDigest: fence.providerContractDigest,
    providerAggregateDigest: fence.providerAggregateDigest,
    intentId: fence.intentId,
    intentVersion: fence.intentVersion,
    intentProjectionDigest: fence.intentProjectionDigest,
    logicalResource,
    phase,
    phaseStepCount: fence.phaseStepCount,
    cleanupRunnerExecutionPlanDigest: fence.cleanupRunnerExecutionPlanDigest,
    ...extra,
  };
}

function parseResponseForFence({ scenarioId, logicalResource, environmentDigest, cleanupFence, response }) {
  const fence = parseFence({ scenarioId, logicalResource, cleanupFence });
  assertDigest(environmentDigest, 'environmentDigest');
  if (scenarioId === 'resource.cleanup_preflight_step') {
    const fields = readExact(
      response,
      ['logicalResource', 'nextPhaseCursor', 'phaseProgressDigest'],
      'Cleanup preflight response',
    );
    const priorPhaseDigest = fence.phaseCursor === 0
      ? createCleanupPhaseGenesisDigest(createFenceGenesis({
        fence, environmentDigest, logicalResource, phase: 'preflight',
      }))
      : fence.priorPhaseDigest;
    const expectedPhaseProgressDigest = advanceCleanupPhaseDigest({
      priorPhaseDigest,
      logicalResource,
      phase: 'preflight',
      phaseCursor: fence.phaseCursor,
      stepId: requireResource(logicalResource).preflight[fence.phaseCursor].stepId,
      result: RESULT,
    });
    if (fields.logicalResource !== logicalResource
      || fields.nextPhaseCursor !== fence.phaseCursor + 1
      || fields.phaseProgressDigest !== expectedPhaseProgressDigest) {
      throw new TypeError('Cleanup preflight response cursor mismatch.');
    }
    assertDigest(fields.phaseProgressDigest, 'phaseProgressDigest');
    return fields;
  }
  if (scenarioId === 'resource.cleanup_step') {
    const fields = readExact(
      response,
      ['logicalResource', 'nextCleanupCursor', 'cleanupProgressDigest'],
      'Cleanup mutation response',
    );
    const expectedCleanupProgressDigest = advanceCleanupProgressDigest({
      priorCleanupProgressDigest: fence.cleanupProgressDigest,
      logicalResource,
      cleanupCursor: fence.cleanupCursor,
      stepId: requireResource(logicalResource).mutation[fence.cleanupCursor].stepId,
      result: RESULT,
    });
    if (fields.logicalResource !== logicalResource
      || fields.nextCleanupCursor !== fence.cleanupCursor + 1
      || fields.cleanupProgressDigest !== expectedCleanupProgressDigest) {
      throw new TypeError('Cleanup mutation response cursor mismatch.');
    }
    return fields;
  }
  if (scenarioId === 'resource.cleanup_proof_step') {
    const fields = readExact(
      response,
      ['logicalResource', 'nextPhaseCursor', 'phaseProgressDigest', 'cleanupProofDigest'],
      'Cleanup proof response',
    );
    const expectedPhaseProgressDigest = advanceCleanupProofDigest({
      priorCleanupProofDigest: fence.priorPhaseDigest,
      logicalResource,
      proofCursor: fence.phaseCursor,
      stepId: requireResource(logicalResource).proof[fence.phaseCursor].stepId,
      result: RESULT,
    });
    if (fields.logicalResource !== logicalResource
      || fields.nextPhaseCursor !== fence.phaseCursor + 1
      || fields.phaseProgressDigest !== expectedPhaseProgressDigest) {
      throw new TypeError('Cleanup proof response cursor mismatch.');
    }
    assertDigest(fields.phaseProgressDigest, 'phaseProgressDigest');
    const finalStep = fields.nextPhaseCursor === fence.phaseStepCount;
    if (finalStep) {
      if (fields.cleanupProofDigest !== fields.phaseProgressDigest) {
        throw new TypeError('Final cleanup proof digest mismatch.');
      }
    } else if (fields.cleanupProofDigest !== null) {
      throw new TypeError('Cleanup proof digest is terminal-only.');
    }
    return fields;
  }
  const fields = readExact(
    response,
    ['logicalResource', 'deleted', 'absenceProven', 'cleanupProofDigest'],
    'Cleanup terminal response',
  );
  if (fields.logicalResource !== logicalResource
    || fields.deleted !== true
    || fields.absenceProven !== true
    || fields.cleanupProofDigest !== fence.cleanupProofDigest) {
    throw new TypeError('Cleanup terminal response mismatch.');
  }
  return fields;
}

export function parseCleanupStepResponse(value) {
  const fields = readExact(
    value,
    ['scenarioId', 'logicalResource', 'environmentDigest', 'cleanupFence', 'response'],
    'Cleanup response validation input',
  );
  return cloneAndFreeze(parseResponseForFence(fields));
}

function replay(value, kind) {
  const fields = readExact(
    value,
    ['logicalResource', 'genesis', 'responses'],
    `Cleanup ${kind} replay input`,
  );
  const catalog = requireResource(fields.logicalResource);
  const responses = readDenseArray(fields.responses, `Cleanup ${kind} replay responses`);
  const steps = kind === 'preflight' ? catalog.preflight
    : kind === 'mutation' ? catalog.mutation : catalog.proof;
  if (responses.length !== steps.length) {
    throw new TypeError(`Cleanup ${kind} replay must contain the complete fixed catalog.`);
  }

  let digest = kind === 'preflight' ? createCleanupPhaseGenesisDigest(fields.genesis)
    : kind === 'mutation' ? createCleanupProgressGenesisDigest(fields.genesis)
      : createCleanupProofGenesisDigest(fields.genesis);
  for (let cursor = 0; cursor < steps.length; cursor += 1) {
    const step = steps[cursor];
    digest = kind === 'preflight' ? advanceCleanupPhaseDigest({
      priorPhaseDigest: digest,
      logicalResource: fields.logicalResource,
      phase: 'preflight',
      phaseCursor: cursor,
      stepId: step.stepId,
      result: RESULT,
    }) : kind === 'mutation' ? advanceCleanupProgressDigest({
      priorCleanupProgressDigest: digest,
      logicalResource: fields.logicalResource,
      cleanupCursor: cursor,
      stepId: step.stepId,
      result: RESULT,
    }) : advanceCleanupProofDigest({
      priorCleanupProofDigest: digest,
      logicalResource: fields.logicalResource,
      proofCursor: cursor,
      stepId: step.stepId,
      result: RESULT,
    });

    if (kind === 'preflight') {
      const response = readExact(
        responses[cursor],
        ['logicalResource', 'nextPhaseCursor', 'phaseProgressDigest'],
        'Cleanup preflight replay response',
      );
      if (response.logicalResource !== fields.logicalResource
        || response.nextPhaseCursor !== cursor + 1
        || response.phaseProgressDigest !== digest) {
        throw new TypeError('Cleanup preflight replay mismatch.');
      }
    } else if (kind === 'mutation') {
      const response = readExact(
        responses[cursor],
        ['logicalResource', 'nextCleanupCursor', 'cleanupProgressDigest'],
        'Cleanup mutation replay response',
      );
      if (response.logicalResource !== fields.logicalResource
        || response.nextCleanupCursor !== cursor + 1
        || response.cleanupProgressDigest !== digest) {
        throw new TypeError('Cleanup mutation replay mismatch.');
      }
    } else {
      const response = readExact(
        responses[cursor],
        ['logicalResource', 'nextPhaseCursor', 'phaseProgressDigest', 'cleanupProofDigest'],
        'Cleanup proof replay response',
      );
      const finalStep = cursor + 1 === steps.length;
      if (response.logicalResource !== fields.logicalResource
        || response.nextPhaseCursor !== cursor + 1
        || response.phaseProgressDigest !== digest
        || (finalStep ? response.cleanupProofDigest !== digest : response.cleanupProofDigest !== null)) {
        throw new TypeError('Cleanup proof replay mismatch.');
      }
    }
  }

  return kind === 'preflight'
    ? cloneAndFreeze({ logicalResource: fields.logicalResource, nextPhaseCursor: steps.length, phaseProgressDigest: digest })
    : kind === 'mutation'
      ? cloneAndFreeze({ logicalResource: fields.logicalResource, nextCleanupCursor: steps.length, cleanupProgressDigest: digest })
      : cloneAndFreeze({
        logicalResource: fields.logicalResource,
        nextPhaseCursor: steps.length,
        phaseProgressDigest: digest,
        cleanupProofDigest: digest,
      });
}

export function replayCleanupPreflight(value) {
  return replay(value, 'preflight');
}

export function replayCleanupMutation(value) {
  return replay(value, 'mutation');
}

export function replayCleanupProof(value) {
  return replay(value, 'proof');
}
