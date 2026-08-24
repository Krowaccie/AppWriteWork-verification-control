import { isProxy } from 'node:util/types';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import {
  isAuthenticTestCloudControlClient,
  isAuthenticTestCloudRecoveryControlClient,
} from './test-cloud-appwrite.mjs';
import {
  isAuthenticTestEnvironmentContext,
  isAuthenticTestRecoveryEnvironmentContext,
} from './test-cloud-environment.mjs';
import {
  CLEANUP_PROTOCOL_DIGEST,
  QUALIFIED_CLEANUP_PROTOCOL,
  advanceCleanupPhaseDigest,
  advanceCleanupProgressDigest,
  advanceCleanupProofDigest,
  createCleanupPhaseGenesisDigest,
  createCleanupProgressGenesisDigest,
  createCleanupProofGenesisDigest,
  createRecoveryAuditEventDigest,
  createRecoveryCheckpointDigest,
  createRecoveryCurrentIntentSetDigest,
  createRecoveryIntentSetDigest,
  createOrdinaryExecutionEvidenceDigest,
  deriveRecoveryPosition,
  validateRecoveryAuditEvent,
  validateRecoveryCheckpointSuccessor,
  validateRecoveryIntentRow,
} from './test-cloud-cleanup-protocol.mjs';
import {
  authenticateTestCloudRuntimeActive,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from './test-cloud-provider-contract.mjs';
import {
  contentAddressedRowMatches,
  contentDigestToRowId,
  intentIdToRowId,
  intentProjectionRowMatches,
} from './test-cloud-row-id.mjs';
import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import providerContract from '../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json' with { type: 'json' };

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const INTENT_ID = /^[0-9a-f]{64}$/u;
const V1_INTENT_KEYS = Object.freeze([
  'schemaVersion','intentId','runId','environmentDigest','resourceType','resourceId',
  'providerResourceIds','ownerMarker','dependencyOrder','lifecycleClass','state',
  'intentVersion','observationDigest','retentionExpiresAt','createdAt','updatedAt',
]);
const CLEANUP_V2_INTENT_KEYS = Object.freeze([
  'schemaVersion','intentId','runId','environmentDigest','resourceType','resourceId',
  'providerAggregateJson','providerAggregateDigest','ownerMarker','dependencyOrder',
  'lifecycleClass','state','intentVersion','observationDigest','retentionExpiresAt',
  'cleanupCursor','cleanupProgressDigest','cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest','cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson','cleanupRunnerExecutionRecordDigest',
  'cleanupRunnerExecutionRetentionExpiresAt','createdAt','updatedAt',
]);
const RECOVERY_V2_CLEANUP_KEYS = Object.freeze([
  'cleanupCursor','cleanupProgressDigest','cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest','cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson','cleanupRunnerExecutionRecordDigest',
  'cleanupRunnerExecutionRetentionExpiresAt',
]);
const RECOVERY_V1_IDENTITY_KEYS = Object.freeze([
  'intentId','runId','environmentDigest','resourceType','resourceId','ownerMarker',
  'dependencyOrder','lifecycleClass','createdAt',
]);
const RECOVERY_V2_IDENTITY_KEYS = RECOVERY_V1_IDENTITY_KEYS;
const RECOVERY_EXECUTION_SLOT_KEYS = Object.freeze([
  'logicalPosition','attemptOrdinal','retainedExecutionId','safeStateDigest','retentionExpiresAt',
]);
const RECOVERY_AGGREGATE_KEYS = Object.freeze([
  'aggregateBinding','aggregateBindingDigest','ownedMembers','phase','referencedMembers','schemaVersion',
]);
const RECOVERY_AGGREGATE_BINDING_KEYS = Object.freeze([
  'environmentDigest','intentId','operationKey','operationScenario','ownerMarker','parameters',
  'providerContractDigest','resourceId','resourceType','runId','schemaVersion',
]);
const RECOVERY_OWNER_MARKER = /^verification-owner\.v1:sha256:[0-9a-f]{64}$/u;
const RECOVERY_ACCOUNT_SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const RECOVERY_DEPENDENCY_ORDER = Object.freeze({
  'primary-share':30,'primary-graph':20,'primary-project':10,
});
const RECOVERY_RESOURCE_LIMITS = Object.freeze(Object.fromEntries(
  Object.entries(QUALIFIED_CLEANUP_PROTOCOL.resources).map(([resourceType,catalog])=>[
    resourceType,Object.freeze({cleanupCursor:catalog.mutation.length,
      preflightCount:catalog.preflight.length,knownCalls:catalog.executionPlan.knownCalls,
      slotCount:catalog.executionPlan.slotCount,
      dependencyOrder:RECOVERY_DEPENDENCY_ORDER[resourceType],
      executionPlanDigest:catalog.executionPlan.digest}),
  ]),
));
const RECOVERY_GENESIS_PREFIX_BY_ABSENT_COUNT = Object.freeze([0, 21, 32, 42]);
const RECOVERY_PRIMARY_EXECUTION_RETENTION_MAX_SECONDS =
  inventory.control.primaryExecutionRetentionMaxSeconds;
const RECOVERY_CLEANUP_RESULT = 'desired-projection-proven';
const AUDIT_TRANSITIONS = Object.freeze(new Set([
  'lease.acquire','lease.renew','lease.cleanup_debt','lease.recover','lease.close',
  'intent.planned','intent.created','intent.absent','intent.provider_bound',
  'intent.provider_values_bound','intent.provider_operation_issued',
  'intent.provider_operation_reconciled','intent.provider_phase_reconciled',
  'intent.provider_create_issued','intent.provider_id_discovered',
  'intent.cleanup_started','intent.cleanup_progressed','intent.cleanup_proof_recorded',
  'intent.cleanup_execution_recorded','observation.planned','observation.observed',
]));
const OPERATION_KEYS = Object.freeze([
  'event','expectedLeaseVersion','expectedLedgerDigest','nextLease',
]);
const SNAPSHOT_OPERATION_KEYS = Object.freeze([
  'event','expectedLeaseVersion','expectedLedgerDigest','nextIntent','nextLease','snapshot',
]);
const AUDIT_EVENT_KEYS = Object.freeze([
  'intentId','intentProjectionDigest','leaseVersionAfter','leaseVersionBefore',
  'previousLedgerDigest','runId','schemaVersion','transition',
]);
const RECOVERY_AUDIT_EVENT_KEYS = Object.freeze([
  'intentId','intentProjectionDigest','leaseVersionAfter','leaseVersionBefore',
  'previousLedgerDigest','recoveryCheckpointDigest','recoveryCheckpointJson',
  'recoveryPreviousCheckpointDigest','runId','schemaVersion','transition',
]);
const LEASE_KEYS = Object.freeze([
  'acquiredAt','cleanupDebt','environmentDigest','expiresAt','leaseRowId',
  'leaseTokenDigest','leaseVersion','ledgerDigest','ownerRunId','ownerWorkflowRunId',
  'renewedAt','state',
]);
const STORE_KEYS = Object.freeze([
  'getAuditEventByDigest',
  'getIntentProjection',
  'getIntentSnapshotByDigest',
  'getLease',
  'transact',
]);
const {
  auditTableId: AUDIT_TABLE_ID,
  intentTableId: INTENT_TABLE_ID,
  leaseRowId: LEASE_ROW_ID,
  leaseTableId: LEASE_TABLE_ID,
} = inventory.control;
const encoder = new TextEncoder();
const APPROVED_PROVIDER_CONTRACT_DIGEST = sha256Bytes(encoder.encode(
  `${canonicalJson(providerContract)}\n`,
));
const providerControlStoreRecords = new WeakMap();
const sessionIntentQualificationRecords = new WeakMap();
const providerRecoveryControlStoreRecords = new WeakMap();
const providerRecoveryReadOperationRecords = new WeakMap();
const providerRecoveryCommitOperationRecords = new WeakMap();
const providerRecoverySessionAbsenceOperationRecords = new WeakMap();
const providerRecoveryCloseOperationRecords = new WeakMap();
const RECOVERY_GENESIS_LEDGER_DIGEST = sha256Bytes(encoder.encode(canonicalJson({
  leaseRowId: LEASE_ROW_ID,
  schemaVersion: 'verification-audit-genesis.v1',
})));
const RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST = sha256Bytes(encoder.encode(canonicalJson({
  schemaVersion: 'verification-account-session-absence.v1',
  originallyObservedIntentIds: [],
})));
let installedProviderControlRecord = Object.freeze({ state: 'UNINSTALLED', version: 0 });

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function result(status, value, code = null) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null ? [] : [{
      code,
      safeMessage: code === 'TEST_CLOUD_SETUP_INCOMPLETE'
        ? 'The provider control-store prerequisite is unavailable.'
        : 'The provider control-store transition was blocked.',
      retryable: false,
    }],
  });
}

function privatePass(value) {
  return Object.freeze(Object.assign(Object.create(null), {
    status: 'PASS',
    value,
    diagnostics: Object.freeze([]),
  }));
}

function exactDataObject(value, expectedKeys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || isProxy(value)
      || (Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Object.getOwnPropertyNames(descriptors).sort();
    const expected = [...expectedKeys].sort();
    return names.length === expected.length
      && names.every((name, index) => name === expected[index])
      && names.every((name) => descriptors[name].enumerable
        && Object.hasOwn(descriptors[name], 'value'));
  } catch {
    return false;
  }
}

function safeCopy(value) {
  return JSON.parse(canonicalJson(value));
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function contentDigest(value) {
  return sha256Bytes(encoder.encode(canonicalJson(value)));
}

class StoreMismatch extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function mismatch(code) {
  throw new StoreMismatch(code);
}

function validClientResult(outcome) {
  return exactDataObject(outcome, ['diagnostics', 'status', 'value'])
    && outcome.status === 'PASS'
    && Array.isArray(outcome.diagnostics)
    && outcome.diagnostics.length === 0;
}

function unknownCommit(outcome) {
  return exactDataObject(outcome, ['diagnostics', 'status', 'value'])
    && outcome.status === 'BLOCKED'
    && outcome.value === null
    && Array.isArray(outcome.diagnostics)
    && outcome.diagnostics.length === 1
    && outcome.diagnostics[0]?.code === 'TEST_COMMIT_UNKNOWN';
}

function exactDensePrimitiveArray(value) {
  if (!Array.isArray(value) || isProxy(value) || Reflect.ownKeys(value).length !== value.length + 1) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string') return false;
  }
  return true;
}

function validIntentSnapshotShape(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || isProxy(value)) return false;
  const schemaDescriptor = Object.getOwnPropertyDescriptor(value, 'schemaVersion');
  if (schemaDescriptor?.enumerable !== true || !Object.hasOwn(schemaDescriptor, 'value')) return false;
  if (schemaDescriptor.value === 'verification-intent-snapshot.v1') {
    return exactDataObject(value, V1_INTENT_KEYS)
      && exactDensePrimitiveArray(Object.getOwnPropertyDescriptor(value, 'providerResourceIds').value);
  }
  return schemaDescriptor.value === 'verification-intent-snapshot.v2'
    && (exactDataObject(value, CLEANUP_V2_INTENT_KEYS)
      || exactDataObject(value, PROVIDER_V2_INTENT_KEYS));
}

function transitionMatchesSnapshot(transition, snapshot) {
  if (snapshot.schemaVersion === 'verification-intent-snapshot.v1') {
    if (snapshot.resourceType === 'primary-execution') return transition === 'observation.planned' || transition === 'observation.observed';
    return transition === `intent.${snapshot.state}`;
  }
  if (snapshot.state === 'planned') return transition === 'intent.planned' || transition.startsWith('intent.provider_');
  if (snapshot.state === 'created') {
    return transition === 'intent.created'
      || (snapshot.cleanupRunnerExecutionCursor !== null
        && (transition === 'intent.cleanup_progressed'
          || transition === 'intent.cleanup_execution_recorded'));
  }
  if (snapshot.state === 'absent') return transition === 'intent.absent';
  return snapshot.state === 'cleaning' && transition.startsWith('intent.cleanup_');
}

function normalizeOperation(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || isProxy(value)) mismatch('AUDIT_CHAIN_MISMATCH');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const hasSnapshot = Object.hasOwn(descriptors, 'snapshot');
  const keys = hasSnapshot ? SNAPSHOT_OPERATION_KEYS : OPERATION_KEYS;
  if (!exactDataObject(value, keys)) mismatch('AUDIT_CHAIN_MISMATCH');
  const expectedLeaseVersion = descriptors.expectedLeaseVersion.value;
  const expectedLedgerDigest = descriptors.expectedLedgerDigest.value;
  const rawEvent = descriptors.event.value;
  const rawNextLease = descriptors.nextLease.value;
  if (!Number.isSafeInteger(expectedLeaseVersion) || expectedLeaseVersion < 0 || !DIGEST.test(expectedLedgerDigest)
      || !exactDataObject(rawEvent, AUDIT_EVENT_KEYS)
      || !AUDIT_TRANSITIONS.has(Object.getOwnPropertyDescriptor(rawEvent, 'transition').value)
      || !exactDataObject(rawNextLease, LEASE_KEYS)) mismatch('AUDIT_CHAIN_MISMATCH');
  const event = safeCopy(rawEvent),nextLease = safeCopy(rawNextLease),eventDigest = contentDigest(event);
  if (event.schemaVersion !== 'verification-audit-event.v1' || event.previousLedgerDigest !== expectedLedgerDigest
      || event.leaseVersionBefore !== expectedLeaseVersion || event.leaseVersionAfter !== expectedLeaseVersion + 1
      || nextLease.leaseRowId !== LEASE_ROW_ID || nextLease.leaseVersion !== expectedLeaseVersion + 1
      || nextLease.ledgerDigest !== eventDigest) mismatch('AUDIT_CHAIN_MISMATCH');
  let snapshot=null,snapshotDigest=null,nextIntent=null;
  if (hasSnapshot && descriptors.snapshot.value === null) {
    if (descriptors.nextIntent.value !== null || event.intentId !== null || event.intentProjectionDigest !== null) mismatch('AUDIT_CHAIN_MISMATCH');
  } else if (hasSnapshot) {
    const rawSnapshot=descriptors.snapshot.value,rawNextIntent=descriptors.nextIntent.value;
    if (!validIntentSnapshotShape(rawSnapshot) || !validIntentSnapshotShape(rawNextIntent)) mismatch('AUDIT_CHAIN_MISMATCH');
    snapshot=safeCopy(rawSnapshot);nextIntent=safeCopy(rawNextIntent);snapshotDigest=contentDigest(snapshot);
    if (!INTENT_ID.test(snapshot.intentId) || event.intentId !== snapshot.intentId
        || event.intentProjectionDigest !== snapshotDigest || !same(snapshot,nextIntent)
        || !transitionMatchesSnapshot(event.transition,snapshot)
        || !intentProjectionRowMatches({rowId:intentIdToRowId(snapshot.intentId),data:snapshot})) mismatch('AUDIT_CHAIN_MISMATCH');
  } else if (event.intentId !== null || event.intentProjectionDigest !== null) mismatch('AUDIT_CHAIN_MISMATCH');
  return deepFreeze({event,eventDigest,expectedLeaseVersion,expectedLedgerDigest,nextIntent,nextLease,snapshot,snapshotDigest});
}
export function createProviderControlStore(args = {}) {
  if (
    !exactDataObject(args, ['client', 'context'])
    || !isAuthenticTestEnvironmentContext(args.context)
    || !isAuthenticTestCloudControlClient(args.client, args.context)
  ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');

  const { client } = args;

  async function getRow(tableId, rowId, mismatchCode) {
    const outcome = await client.getRow({ tableId, rowId });
    if (
      !validClientResult(outcome)
      || !exactDataObject(outcome.value, ['data', 'rowId'])
      || outcome.value.rowId !== rowId
    ) mismatch(mismatchCode);
    if (outcome.value.data === null) return null;
    try {
      return safeCopy(outcome.value.data);
    } catch {
      mismatch(mismatchCode);
    }
  }

  async function getLease() {
    const lease = await getRow(LEASE_TABLE_ID, LEASE_ROW_ID, 'LEASE_READBACK_MISMATCH');
    if (lease === null || lease.leaseRowId !== LEASE_ROW_ID) {
      mismatch('LEASE_READBACK_MISMATCH');
    }
    return deepFreeze(lease);
  }

  async function getAuditEventByDigest(value) {
    if (!DIGEST.test(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    const rowId = contentDigestToRowId(value);
    const data = await getRow(AUDIT_TABLE_ID, rowId, 'AUDIT_CHAIN_MISMATCH');
    if (data === null) return null;
    if (!contentAddressedRowMatches({ rowId, contentDigest: value, data })) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    return deepFreeze(data);
  }

  async function getIntentSnapshotByDigest(value) {
    if (!DIGEST.test(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    const rowId = contentDigestToRowId(value);
    const data = await getRow(INTENT_TABLE_ID, rowId, 'AUDIT_CHAIN_MISMATCH');
    if (data === null) return null;
    if (!contentAddressedRowMatches({ rowId, contentDigest: value, data })) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    return deepFreeze(data);
  }

  async function getIntentProjection(value) {
    if (!INTENT_ID.test(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    const rowId = intentIdToRowId(value);
    const data = await getRow(INTENT_TABLE_ID, rowId, 'AUDIT_CHAIN_MISMATCH');
    if (data === null) return null;
    if (!intentProjectionRowMatches({ rowId, data }) || data.intentId !== value) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    return deepFreeze(data);
  }

  async function stagedContentRowsAbsent(operation) {
    const observedEvent = await getAuditEventByDigest(operation.eventDigest);
    if (observedEvent !== null) return false;
    if (operation.snapshot === null) return true;
    return await getIntentSnapshotByDigest(operation.snapshotDigest) === null;
  }

  async function exactReadback(operation) {
    const observedLease = await getLease();
    if (!same(observedLease, operation.nextLease)) {
      return { kind: 'lease-mismatch', observedLease };
    }
    const observedEvent = await getAuditEventByDigest(operation.eventDigest);
    if (observedEvent === null || !same(observedEvent, operation.event)) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    if (operation.snapshot !== null) {
      const observedSnapshot = await getIntentSnapshotByDigest(operation.snapshotDigest);
      const observedProjection = await getIntentProjection(operation.snapshot.intentId);
      if (
        observedSnapshot === null
        || observedProjection === null
        || !same(observedSnapshot, operation.snapshot)
        || !same(observedProjection, operation.nextIntent)
      ) mismatch('AUDIT_CHAIN_MISMATCH');
    }
    return { kind: 'committed', observedLease };
  }

  async function stageAndCommit(operation) {
    const operations = [];
    if (operation.snapshot !== null) {
      const snapshotRowId = contentDigestToRowId(operation.snapshotDigest);
      const observedSnapshot = await getIntentSnapshotByDigest(operation.snapshotDigest);
      if (observedSnapshot === null) {
        operations.push({
          action: 'createRow',
          tableId: INTENT_TABLE_ID,
          rowId: snapshotRowId,
          data: operation.snapshot,
        });
      } else if (!same(observedSnapshot, operation.snapshot)) {
        mismatch('AUDIT_CHAIN_MISMATCH');
      }
    }

    const eventRowId = contentDigestToRowId(operation.eventDigest);
    const observedEvent = await getAuditEventByDigest(operation.eventDigest);
    if (observedEvent === null) {
      operations.push({
        action: 'createRow',
        tableId: AUDIT_TABLE_ID,
        rowId: eventRowId,
        data: operation.event,
      });
    } else if (!same(observedEvent, operation.event)) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }

    if (operation.snapshot !== null) {
      const projectionRowId = intentIdToRowId(operation.snapshot.intentId);
      const projection = await getIntentProjection(operation.snapshot.intentId);
      operations.push({
        action: projection === null ? 'createRow' : 'updateRow',
        tableId: INTENT_TABLE_ID,
        rowId: projectionRowId,
        data: operation.nextIntent,
      });
    }

    operations.push({
      action: 'incrementRowColumn',
      tableId: LEASE_TABLE_ID,
      rowId: LEASE_ROW_ID,
      column: 'leaseVersion',
      value: 1,
      max: operation.nextLease.leaseVersion,
    });
    const leasePatch = { ...operation.nextLease };
    delete leasePatch.leaseVersion;
    operations.push({
      action: 'updateRow',
      tableId: LEASE_TABLE_ID,
      rowId: LEASE_ROW_ID,
      data: leasePatch,
    });

    const opened = await client.createTransaction({ ttl: 60 });
    if (
      !validClientResult(opened)
      || !exactDataObject(opened.value, ['status', 'transactionId'])
      || opened.value.status !== 'pending'
    ) mismatch('LEASE_VERSION_MISMATCH');
    const transactionId = opened.value.transactionId;
    const staged = await client.createTransactionOperations({
      transactionId,
      operations,
    });
    if (
      !validClientResult(staged)
      || !exactDataObject(staged.value, ['status', 'transactionId'])
      || staged.value.transactionId !== transactionId
      || staged.value.status !== 'pending'
    ) mismatch('LEASE_VERSION_MISMATCH');
    const committed = await client.commitOrRollbackTransaction({
      transactionId,
      action: 'commit',
    });
    if (
      validClientResult(committed)
      && exactDataObject(committed.value, ['status', 'transactionId'])
      && committed.value.transactionId === transactionId
      && committed.value.status === 'committed'
    ) return 'committed';
    return unknownCommit(committed) ? 'unknown' : 'rejected';
  }

  async function transact(value) {
    let operation;
    try {
      operation = normalizeOperation(value);
      const oldLease = await getLease();
      if (
        oldLease.leaseVersion !== operation.expectedLeaseVersion
        || oldLease.ledgerDigest !== operation.expectedLedgerDigest
      ) return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');

      for (let attempt = 0; attempt < 2; attempt += 1) {
        const disposition = await stageAndCommit(operation);
        if (disposition === 'rejected') {
          return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
        }
        if (disposition === 'committed') {
          const readback = await exactReadback(operation);
          return readback.kind === 'committed'
            ? result('PASS', operation.nextLease)
            : result('BLOCKED', null, 'LEASE_READBACK_MISMATCH');
        }

        const observed = await getLease();
        if (same(observed, operation.nextLease)) {
          const readback = await exactReadback(operation);
          return readback.kind === 'committed'
            ? result('PASS', operation.nextLease)
            : result('BLOCKED', null, 'AUDIT_CHAIN_MISMATCH');
        }
        if (!same(observed, oldLease)) {
          return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
        }
        if (!await stagedContentRowsAbsent(operation)) {
          return result('BLOCKED', null, 'AUDIT_CHAIN_MISMATCH');
        }
        if (attempt === 1) {
          return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
        }
      }
      return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
    } catch (error) {
      const code = error instanceof StoreMismatch
        ? error.code
        : 'TEST_CLOUD_SETUP_INCOMPLETE';
      return result('BLOCKED', null, code);
    }
  }

  const store = Object.freeze({
    getAuditEventByDigest,
    getIntentProjection,
    getIntentSnapshotByDigest,
    getLease,
    transact,
  });
  if (Object.keys(store).sort().some((key, index) => key !== STORE_KEYS[index])) {
    return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
  }
  providerControlStoreRecords.set(store, Object.freeze({
    client,
    context: args.context,
    methods: Object.freeze(STORE_KEYS.map((key) => store[key])),
  }));
  return result('PASS', store);
}

function createRecoveryOpaqueOperation(records, record) {
  const operation = Object.freeze(Object.create(null));
  records.set(operation, record);
  return operation;
}

function recoveryIntentRow(value) {
  let schemaVersion;
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || isProxy(value)) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, 'schemaVersion');
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    schemaVersion = descriptor.value;
  } catch (error) {
    if (error instanceof StoreMismatch) throw error;
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  if (schemaVersion === 'verification-intent-snapshot.v1') {
    if (!validIntentSnapshotShape(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    return safeCopy(value);
  }
  if (schemaVersion !== 'verification-intent-snapshot.v2') {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  try {
    return safeCopy(validateRecoveryIntentRow(value));
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
}

function recoveryAuditEvent(value) {
  if (exactDataObject(value, RECOVERY_AUDIT_EVENT_KEYS)) {
    try {
      return safeCopy(validateRecoveryAuditEvent(value).event);
    } catch {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
  }
  if (
    !exactDataObject(value, AUDIT_EVENT_KEYS)
    || value.schemaVersion !== 'verification-audit-event.v1'
    || !AUDIT_TRANSITIONS.has(value.transition)
    || !DIGEST.test(value.previousLedgerDigest)
    || !Number.isSafeInteger(value.leaseVersionBefore)
    || value.leaseVersionBefore < 0
    || value.leaseVersionAfter !== value.leaseVersionBefore + 1
    || typeof value.runId !== 'string'
    || value.runId.length === 0
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  if (value.intentId === null || value.intentProjectionDigest === null) {
    if (value.intentId !== null || value.intentProjectionDigest !== null) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
  } else if (!INTENT_ID.test(value.intentId) || !DIGEST.test(value.intentProjectionDigest)) {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  return safeCopy(value);
}

function recoveryFailure(error) {
  return result(
    'BLOCKED',
    null,
    error instanceof StoreMismatch ? error.code : 'TEST_CLOUD_SETUP_INCOMPLETE',
  );
}

function recoveryPositionEvidence(checkpoint) {
  const position = deriveRecoveryPosition({
    prefixLength: checkpoint.prefixLength,
    intentDispositionCursor: checkpoint.intentDispositionCursor,
  });
  return {
    prefixLength: checkpoint.prefixLength,
    intentDispositionCursor: checkpoint.intentDispositionCursor,
    logicalResource: position.logicalResource,
    stepId: position.stepId,
    phase: position.phase,
    action: position.action,
  };
}

function recoveryTargetBindingDigest(sourceIntents, prefixLength, intentDispositionCursor) {
  const position = deriveRecoveryPosition({ prefixLength, intentDispositionCursor });
  if (position.logicalResource === null) return null;
  const source = sourceIntents.find(({ resourceType }) => resourceType === position.logicalResource);
  if (source === undefined) throw new TypeError('Recovery source target is missing.');
  return contentDigest({
    schemaVersion: 'verification-recovery-target-binding.v1',
    cleanupProtocolDigest: CLEANUP_PROTOCOL_DIGEST,
    logicalResource: position.logicalResource,
    stepId: position.stepId,
    phase: position.phase,
    action: position.action,
    intentId: source.intentId,
    resourceId: source.resourceId,
    providerAggregateDigest: source.providerAggregateDigest,
  });
}

function recoveryCurrentIntentDigest(intents, cursor) {
  const terminalLink = cursor === 0
    ? null : (intents[cursor - 1]?.recoveryCheckpointDigest ?? null);
  if (terminalLink === null) {
    if (intents.some((intent) => (intent.recoveryCheckpointDigest ?? null) !== null)) {
      throw new TypeError('Recovery current intent links are invalid.');
    }
    return createRecoveryIntentSetDigest({ intents });
  }
  return createRecoveryCurrentIntentSetDigest({ intents, recoveryTerminalIndex: cursor - 1 });
}

function exactRecoverySourceBindings(checkpoint, proof, currentIntents) {
  return checkpoint.environmentDigest === proof.environmentDigest
    && checkpoint.cleanupProtocolDigest === CLEANUP_PROTOCOL_DIGEST
    && checkpoint.sourceAuditHeadDigest === proof.sourceAuditHeadDigest
    && checkpoint.sourceLeaseVersion === proof.sourceLeaseVersion
    && checkpoint.sourceLedgerDigest === proof.sourceAuditHeadDigest
    && checkpoint.sourceIntentSetDigest === createRecoveryIntentSetDigest({ intents: proof.sourceIntents })
    && checkpoint.currentIntentSetDigest === recoveryCurrentIntentDigest(
      currentIntents,
      checkpoint.intentDispositionCursor,
    )
    && checkpoint.ordinaryExecutionEvidenceDigest === createOrdinaryExecutionEvidenceDigest({
      intents: proof.sourceIntents,
    })
    && checkpoint.accountSessionAbsenceDigest === RECOVERY_ACCOUNT_SESSION_ABSENCE_DIGEST
    && checkpoint.targetBindingDigest === recoveryTargetBindingDigest(
      proof.sourceIntents,
      checkpoint.prefixLength,
      checkpoint.intentDispositionCursor,
    );
}

function exactRecoveryGenesis(checkpoint, proof) {
  if (
    checkpoint.priorCheckpointDigest !== null
    || checkpoint.eventOrdinal !== 0
    || checkpoint.prefixLength !== proof.genesisPosition?.prefixLength
    || checkpoint.intentDispositionCursor !== proof.genesisPosition?.intentDispositionCursor
    || checkpoint.checkpointState !== 'ready'
    || checkpoint.attemptOrdinal !== null
    || checkpoint.preWriteProjectionDigest !== null
    || checkpoint.desiredProjectionDigest !== null
    || checkpoint.providerObservationDigest !== null
    || checkpoint.cleanupProofDigest !== null
    || !exactRecoverySourceBindings(checkpoint, proof, proof.sourceIntents)
  ) return false;
  return checkpoint.recoveryProgressDigest === contentDigest({
    domain: 'verification-recovery-progress-genesis.v1',
    payload: {
      schemaVersion: checkpoint.schemaVersion,
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
      catalogPosition: recoveryPositionEvidence(checkpoint),
      targetBindingDigest: checkpoint.targetBindingDigest,
      providerObservationDigest: null,
    },
  });
}

function recoveryValidIso(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) return false;
  try { return new Date(value).toISOString() === value; } catch { return false; }
}

function recoveryIntentKeys(value) {
  if (value.schemaVersion === 'verification-intent-snapshot.v1') return V1_INTENT_KEYS;
  if (value.schemaVersion !== 'verification-intent-snapshot.v2') return null;
  return Object.hasOwn(value, 'recoveryCheckpointDigest')
    ? [...CLEANUP_V2_INTENT_KEYS, 'recoveryCheckpointDigest'] : CLEANUP_V2_INTENT_KEYS;
}

function recoverySameExcept(prior, next, keys) {
  const excluded = new Set(keys);
  return recoveryIntentKeys(prior).filter((key) => !excluded.has(key))
    .every((key) => same(prior[key], next[key]));
}

function recoverySortedUniqueProviderIds(value) {
  return Array.isArray(value)
    && value.every((id) => typeof id === 'string' && id.length > 0)
    && new Set(value).size === value.length
    && value.every((id, index) => index === 0 || value[index - 1] < id);
}

function validRecoveryPrimaryExecutionSnapshot(value) {
  if (value.resourceType !== 'primary-execution'
    || value.lifecycleClass !== 'provider-retained-observation'
    || value.dependencyOrder !== 50 || !recoveryValidIso(value.createdAt)
    || !recoveryValidIso(value.updatedAt) || Date.parse(value.updatedAt) < Date.parse(value.createdAt)
    || !recoverySortedUniqueProviderIds(value.providerResourceIds)) return false;
  if (value.state === 'planned') return [1, 2].includes(value.intentVersion)
    && value.providerResourceIds.length === 0 && value.observationDigest === null
    && value.retentionExpiresAt === null;
  if (value.state !== 'created' || ![3, 4].includes(value.intentVersion)
    || value.providerResourceIds.length !== value.intentVersion - 2
    || !DIGEST.test(value.observationDigest) || !recoveryValidIso(value.retentionExpiresAt)) return false;
  const created = Date.parse(value.createdAt), expires = Date.parse(value.retentionExpiresAt);
  return expires > created
    && expires - created <= RECOVERY_PRIMARY_EXECUTION_RETENTION_MAX_SECONDS * 1000;
}

function validRecoveryPrimaryExecutionSuccessor(prior, next) {
  if (!validRecoveryPrimaryExecutionSnapshot(prior)
    || !validRecoveryPrimaryExecutionSnapshot(next)
    || next.intentVersion !== prior.intentVersion + 1
    || Date.parse(next.updatedAt) < Date.parse(prior.updatedAt)) return false;
  if (prior.intentVersion === 1) return next.intentVersion === 2
    && prior.state === 'planned' && next.state === 'planned'
    && recoverySameExcept(prior, next, ['intentVersion', 'updatedAt']);
  if (prior.intentVersion === 2) return next.intentVersion === 3
    && prior.state === 'planned' && next.state === 'created'
    && prior.providerResourceIds.length === 0 && next.providerResourceIds.length === 1
    && recoverySameExcept(prior, next, [
      'providerResourceIds','state','intentVersion','observationDigest','retentionExpiresAt','updatedAt',
    ]);
  if (prior.intentVersion === 3) return next.intentVersion === 4
    && prior.state === 'created' && next.state === 'created'
    && next.providerResourceIds.length === prior.providerResourceIds.length + 1
    && prior.providerResourceIds.every((id) => next.providerResourceIds.includes(id))
    && recoverySameExcept(prior, next, ['providerResourceIds','intentVersion','updatedAt']);
  return false;
}

function recoveryCleanupFieldsNull(value) {
  return RECOVERY_V2_CLEANUP_KEYS.every((key) => value[key] === null);
}

function parseRecoveryCleanupSlots(value) {
  const limits = RECOVERY_RESOURCE_LIMITS[value.resourceType];
  try {
    const slots = JSON.parse(value.cleanupRunnerExecutionSlotsJson);
    if (!Array.isArray(slots) || slots.length !== limits.slotCount
      || canonicalJson(slots) !== value.cleanupRunnerExecutionSlotsJson) return null;
    const retainedExecutionIds = new Set();
    for (let index = 0; index < slots.length; index += 1) {
      const slot = slots[index];
      if (slot === null) continue;
      if (!exactDataObject(slot, RECOVERY_EXECUTION_SLOT_KEYS)
        || slot.logicalPosition !== Math.floor(index / 2)
        || slot.attemptOrdinal !== index % 2 + 1
        || typeof slot.retainedExecutionId !== 'string' || slot.retainedExecutionId.length === 0
        || !DIGEST.test(slot.safeStateDigest)
        || slot.retentionExpiresAt !== value.cleanupRunnerExecutionRetentionExpiresAt
        || retainedExecutionIds.has(slot.retainedExecutionId)) return null;
      retainedExecutionIds.add(slot.retainedExecutionId);
    }
    for (let position = 0; position < limits.knownCalls; position += 1) {
      const first = slots[position * 2], second = slots[position * 2 + 1];
      if (second !== null && first === null) return null;
      if (position < value.cleanupRunnerExecutionCursor && first === null) return null;
      if (position > value.cleanupRunnerExecutionCursor && (first !== null || second !== null)) return null;
    }
    return slots;
  } catch { return null; }
}

function validRecoveryGlobalCleanupState(latest) {
  const retainedExecutionIds = new Set();
  let retentionExpiresAt = null;
  for (const value of latest) {
    if (value.schemaVersion !== 'verification-intent-snapshot.v2'
      || value.cleanupRunnerExecutionSlotsJson === null) continue;
    const slots = parseRecoveryCleanupSlots(value);
    if (slots === null) return false;
    if (retentionExpiresAt === null) retentionExpiresAt = value.cleanupRunnerExecutionRetentionExpiresAt;
    else if (value.cleanupRunnerExecutionRetentionExpiresAt !== retentionExpiresAt) return false;
    for (const slot of slots) {
      if (slot === null) continue;
      if (retainedExecutionIds.has(slot.retainedExecutionId)) return false;
      retainedExecutionIds.add(slot.retainedExecutionId);
    }
  }
  return true;
}

function recoveryProviderContractDigest(value) {
  if (value.schemaVersion !== 'verification-intent-snapshot.v2') return null;
  try {
    const aggregate = JSON.parse(value.providerAggregateJson);
    if (!exactDataObject(aggregate, RECOVERY_AGGREGATE_KEYS)
      || aggregate.schemaVersion !== 'verification-provider-aggregate.v1'
      || !Array.isArray(aggregate.ownedMembers) || !Array.isArray(aggregate.referencedMembers)
      || typeof aggregate.phase !== 'string' || aggregate.phase.length === 0
      || !exactDataObject(aggregate.aggregateBinding, RECOVERY_AGGREGATE_BINDING_KEYS)) return null;
    const binding = aggregate.aggregateBinding;
    if (binding.schemaVersion !== 'verification-provider-aggregate-binding.v1'
      || !DIGEST.test(binding.providerContractDigest)
      || aggregate.aggregateBindingDigest !== contentDigest(binding)
      || binding.environmentDigest !== value.environmentDigest
      || binding.runId !== value.runId || binding.resourceType !== value.resourceType
      || binding.resourceId !== value.resourceId || binding.intentId !== value.intentId
      || binding.ownerMarker !== value.ownerMarker
      || typeof binding.operationKey !== 'string' || binding.operationKey.length === 0
      || typeof binding.operationScenario !== 'string' || binding.operationScenario.length === 0
      || binding.parameters === null || typeof binding.parameters !== 'object'
      || Array.isArray(binding.parameters)) return null;
    return binding.providerContractDigest;
  } catch { return null; }
}

function recoveryCleanupGenesis(root, providerContractDigest, phase, extra = {}) {
  const catalog = QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType];
  const steps = phase === 'preflight' ? catalog.preflight
    : phase === 'cleanup' ? catalog.mutation : catalog.proof;
  return {schemaVersion:QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest:root.environmentDigest,providerContractDigest,
    providerAggregateDigest:root.providerAggregateDigest,intentId:root.intentId,
    intentVersion:root.intentVersion,intentProjectionDigest:contentDigest(root),
    logicalResource:root.resourceType,phase,phaseStepCount:steps.length,
    cleanupRunnerExecutionPlanDigest:catalog.executionPlan.digest,...extra};
}

function recoveryPreflightDigestAt(root, providerContractDigest, cursor) {
  const catalog = QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType];
  let value = createCleanupPhaseGenesisDigest(
    recoveryCleanupGenesis(root, providerContractDigest, 'preflight'));
  for (let phaseCursor = 0; phaseCursor < cursor; phaseCursor += 1) {
    value = advanceCleanupPhaseDigest({priorPhaseDigest:value,logicalResource:root.resourceType,
      phase:'preflight',phaseCursor,stepId:catalog.preflight[phaseCursor].stepId,
      result:RECOVERY_CLEANUP_RESULT});
  }
  return value;
}

function recoveryCompletePreflightDigest(root, providerContractDigest) {
  return recoveryPreflightDigestAt(root, providerContractDigest,
    QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType].preflight.length);
}

function recoveryCleanupProgressGenesis(root, providerContractDigest) {
  return createCleanupProgressGenesisDigest(recoveryCleanupGenesis(root, providerContractDigest,
    'cleanup',{preflightDigest:recoveryCompletePreflightDigest(root, providerContractDigest)}));
}

function recoveryProofDigestAt(root, providerContractDigest, finalCleanupProgressDigest, cursor) {
  const catalog = QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType];
  let value = createCleanupProofGenesisDigest(recoveryCleanupGenesis(root, providerContractDigest,
    'proof',{finalCleanupProgressDigest}));
  for (let proofCursor = 0; proofCursor < cursor; proofCursor += 1) {
    value = advanceCleanupProofDigest({priorCleanupProofDigest:value,
      logicalResource:root.resourceType,proofCursor,stepId:catalog.proof[proofCursor].stepId,
      result:RECOVERY_CLEANUP_RESULT});
  }
  return value;
}

function recoveryCompleteProofDigest(root, providerContractDigest, finalCleanupProgressDigest) {
  return recoveryProofDigestAt(root, providerContractDigest, finalCleanupProgressDigest,
    QUALIFIED_CLEANUP_PROTOCOL.resources[root.resourceType].proof.length);
}

function exactRecoveryCleanupDigestSuccessor(prior, next, validationContext) {
  const {providerContractDigest, cleanupRoot} = validationContext;
  if (!DIGEST.test(providerContractDigest) || cleanupRoot === null
    || cleanupRoot.state !== 'created') return false;
  if (prior.state === 'created') {
    if (next.cleanupProofDigest !== null) return false;
    return next.state === 'created'
      ? next.cleanupProgressDigest === recoveryPreflightDigestAt(cleanupRoot,
        providerContractDigest,next.cleanupRunnerExecutionCursor)
      : next.state === 'cleaning' && next.cleanupProgressDigest ===
        recoveryCleanupProgressGenesis(cleanupRoot,providerContractDigest);
  }
  if (next.cleanupCursor === prior.cleanupCursor + 1) {
    const step = QUALIFIED_CLEANUP_PROTOCOL.resources[prior.resourceType]
      .mutation[prior.cleanupCursor];
    if (!step || next.cleanupProgressDigest !== advanceCleanupProgressDigest({
      priorCleanupProgressDigest:prior.cleanupProgressDigest,
      logicalResource:prior.resourceType,cleanupCursor:prior.cleanupCursor,
      stepId:step.stepId,result:RECOVERY_CLEANUP_RESULT})) return false;
  } else if (next.cleanupProgressDigest !== prior.cleanupProgressDigest) return false;
  if (next.cleanupProofDigest !== prior.cleanupProofDigest) {
    return prior.cleanupProofDigest === null && next.cleanupProofDigest ===
      recoveryCompleteProofDigest(cleanupRoot,providerContractDigest,next.cleanupProgressDigest);
  }
  return true;
}

function validRecoveryV2Snapshot(value) {
  const limits = RECOVERY_RESOURCE_LIMITS[value.resourceType];
  if (!limits || value.schemaVersion !== 'verification-intent-snapshot.v2'
    || !INTENT_ID.test(value.intentId) || typeof value.runId !== 'string' || value.runId.length === 0
    || !DIGEST.test(value.environmentDigest) || typeof value.resourceId !== 'string'
    || value.resourceId.length === 0 || !RECOVERY_OWNER_MARKER.test(value.ownerMarker)
    || value.dependencyOrder !== limits.dependencyOrder || value.lifecycleClass !== 'fixture'
    || !['planned','created','cleaning','absent'].includes(value.state)
    || !Number.isSafeInteger(value.intentVersion) || value.intentVersion < 1
    || value.observationDigest !== null || value.retentionExpiresAt !== null
    || !recoveryValidIso(value.createdAt) || !recoveryValidIso(value.updatedAt)
    || Date.parse(value.updatedAt) < Date.parse(value.createdAt)
    || typeof value.providerAggregateJson !== 'string' || !DIGEST.test(value.providerAggregateDigest)
    || (value.recoveryCheckpointDigest ?? null) !== null) return false;
  try {
    const aggregate = JSON.parse(value.providerAggregateJson);
    if (canonicalJson(aggregate) !== value.providerAggregateJson
      || contentDigest(aggregate) !== value.providerAggregateDigest) return false;
  } catch { return false; }
  if (value.state === 'planned') return recoveryCleanupFieldsNull(value);
  if (value.state === 'created' && recoveryCleanupFieldsNull(value)) return true;
  if (!Number.isSafeInteger(value.cleanupCursor) || value.cleanupCursor < 0
    || value.cleanupCursor > limits.cleanupCursor || !DIGEST.test(value.cleanupProgressDigest)
    || (value.cleanupProofDigest !== null && !DIGEST.test(value.cleanupProofDigest))
    || value.cleanupRunnerExecutionPlanDigest !== limits.executionPlanDigest
    || !Number.isSafeInteger(value.cleanupRunnerExecutionCursor)
    || value.cleanupRunnerExecutionCursor < 0 || value.cleanupRunnerExecutionCursor > limits.knownCalls
    || !DIGEST.test(value.cleanupRunnerExecutionRecordDigest)
    || !recoveryValidIso(value.cleanupRunnerExecutionRetentionExpiresAt)) return false;
  const slots = parseRecoveryCleanupSlots(value);
  if (slots === null || contentDigest({schemaVersion:'verification-cleanup-execution-record.v1',
    logicalResource:value.resourceType,slots}) !== value.cleanupRunnerExecutionRecordDigest) return false;
  if (value.state === 'created') return value.cleanupCursor === 0
    && value.cleanupProofDigest === null
    && value.cleanupRunnerExecutionCursor < limits.preflightCount;
  if (value.cleanupRunnerExecutionCursor < limits.preflightCount) return false;
  if (value.state === 'absent') return value.cleanupProofDigest !== null
    && value.cleanupCursor === limits.cleanupCursor
    && value.cleanupRunnerExecutionCursor === limits.knownCalls;
  if (value.cleanupProofDigest !== null) return value.cleanupCursor === limits.cleanupCursor
    && value.cleanupRunnerExecutionCursor === limits.knownCalls - 1;
  const mutationExecutionCursor = limits.preflightCount + value.cleanupCursor;
  return value.cleanupCursor < limits.cleanupCursor
    ? value.cleanupRunnerExecutionCursor === mutationExecutionCursor
    : value.cleanupRunnerExecutionCursor >= mutationExecutionCursor
      && value.cleanupRunnerExecutionCursor < limits.knownCalls - 1;
}

function recoveryChangedSlotIndexes(prior, next) {
  const changed = [];
  for (let index = 0; index < prior.length; index += 1) {
    if (!same(prior[index], next[index])) changed.push(index);
  }
  return changed;
}

function validRecoveryV2CleanupSuccessor(prior, next, validationContext) {
  const limits = RECOVERY_RESOURCE_LIMITS[prior.resourceType];
  if (prior.providerAggregateJson !== next.providerAggregateJson
    || prior.providerAggregateDigest !== next.providerAggregateDigest) return false;
  if (prior.state === 'created' && recoveryCleanupFieldsNull(prior)) {
    const slots = parseRecoveryCleanupSlots(next);
    if (next.state !== 'created' || next.cleanupCursor !== 0) return false;
    if (next.cleanupProofDigest !== null || slots === null
      || ![0, 1].includes(next.cleanupRunnerExecutionCursor)
      || slots.slice(2).some((slot) => slot !== null)
      || slots[0] === null || slots[1] !== null) return false;
    return slots[0].safeStateDigest === recoveryPreflightDigestAt(validationContext.cleanupRoot,
      validationContext.providerContractDigest,next.cleanupRunnerExecutionCursor)
      && exactRecoveryCleanupDigestSuccessor(prior,next,validationContext);
  }
  if (prior.state === 'created') {
    if (prior.cleanupRunnerExecutionPlanDigest !== next.cleanupRunnerExecutionPlanDigest
      || prior.cleanupRunnerExecutionRetentionExpiresAt !== next.cleanupRunnerExecutionRetentionExpiresAt
      || next.cleanupCursor !== 0 || next.cleanupProofDigest !== null
      || next.cleanupRunnerExecutionCursor < prior.cleanupRunnerExecutionCursor
      || next.cleanupRunnerExecutionCursor > prior.cleanupRunnerExecutionCursor + 1
      || next.cleanupRunnerExecutionCursor > limits.preflightCount) return false;
    const expectedState = next.cleanupRunnerExecutionCursor === limits.preflightCount ? 'cleaning' : 'created';
    if (next.state !== expectedState) return false;
    const priorSlots = parseRecoveryCleanupSlots(prior), nextSlots = parseRecoveryCleanupSlots(next);
    if (priorSlots === null || nextSlots === null) return false;
    const changed = recoveryChangedSlotIndexes(priorSlots, nextSlots);
    if (changed.some((index) => priorSlots[index] !== null || nextSlots[index] === null)
      || changed.length !== 1) return false;
    const position = prior.cleanupRunnerExecutionCursor;
    const firstIndex = position * 2, secondIndex = firstIndex + 1;
    const executionAdvanced = next.cleanupRunnerExecutionCursor === position + 1;
    if (executionAdvanced) {
      if (!(changed[0] === firstIndex
        || (changed[0] === secondIndex && priorSlots[firstIndex] !== null))) return false;
    } else if (!((changed[0] === firstIndex && priorSlots[firstIndex] === null)
      || (changed[0] === secondIndex && priorSlots[firstIndex] !== null
        && priorSlots[secondIndex] === null))) return false;
    return nextSlots[changed[0]].safeStateDigest === recoveryPreflightDigestAt(
      validationContext.cleanupRoot,validationContext.providerContractDigest,
      next.cleanupRunnerExecutionCursor)
      && exactRecoveryCleanupDigestSuccessor(prior,next,validationContext);
  }
  if (prior.state !== 'cleaning'
    || prior.cleanupRunnerExecutionPlanDigest !== next.cleanupRunnerExecutionPlanDigest
    || prior.cleanupRunnerExecutionRetentionExpiresAt !== next.cleanupRunnerExecutionRetentionExpiresAt
    || next.cleanupCursor < prior.cleanupCursor || next.cleanupCursor > prior.cleanupCursor + 1
    || next.cleanupRunnerExecutionCursor < prior.cleanupRunnerExecutionCursor
    || next.cleanupRunnerExecutionCursor > prior.cleanupRunnerExecutionCursor + 1
    || (prior.cleanupProofDigest !== null && next.cleanupProofDigest !== prior.cleanupProofDigest)
    || (next.cleanupCursor > prior.cleanupCursor
      && next.cleanupProgressDigest === prior.cleanupProgressDigest)) return false;
  const priorSlots = parseRecoveryCleanupSlots(prior), nextSlots = parseRecoveryCleanupSlots(next);
  if (priorSlots === null || nextSlots === null) return false;
  const changed = recoveryChangedSlotIndexes(priorSlots, nextSlots);
  if (changed.some((index) => priorSlots[index] !== null || nextSlots[index] === null)
    || changed.length > 1) return false;
  const position = prior.cleanupRunnerExecutionCursor;
  const firstIndex = position * 2, secondIndex = firstIndex + 1;
  if (next.state === 'absent') return prior.cleanupProofDigest !== null
    && prior.cleanupCursor === limits.cleanupCursor
    && prior.cleanupRunnerExecutionCursor === limits.knownCalls - 1
    && next.cleanupCursor === prior.cleanupCursor
    && next.cleanupProgressDigest === prior.cleanupProgressDigest
    && next.cleanupProofDigest === prior.cleanupProofDigest
    && next.cleanupRunnerExecutionCursor === limits.knownCalls && changed.length === 1
    && (changed[0] === firstIndex || (changed[0] === secondIndex && priorSlots[firstIndex] !== null))
    && nextSlots[changed[0]].safeStateDigest === prior.cleanupProofDigest
    && exactRecoveryCleanupDigestSuccessor(prior,next,validationContext);
  if (prior.cleanupProofDigest !== null) return next.state === 'cleaning'
    && next.cleanupCursor === prior.cleanupCursor
    && next.cleanupProgressDigest === prior.cleanupProgressDigest
    && next.cleanupProofDigest === prior.cleanupProofDigest
    && next.cleanupRunnerExecutionCursor === prior.cleanupRunnerExecutionCursor
    && changed.length === 1
    && ((changed[0] === firstIndex && priorSlots[firstIndex] === null)
      || (changed[0] === secondIndex && priorSlots[firstIndex] !== null
        && priorSlots[secondIndex] === null))
    && nextSlots[changed[0]].safeStateDigest === prior.cleanupProofDigest
    && exactRecoveryCleanupDigestSuccessor(prior,next,validationContext);
  if (next.state !== 'cleaning') return false;
  const executionAdvanced = next.cleanupRunnerExecutionCursor === prior.cleanupRunnerExecutionCursor + 1;
  if (executionAdvanced) {
    if (changed.length !== 1 || !(changed[0] === firstIndex
      || (changed[0] === secondIndex && priorSlots[firstIndex] !== null))) return false;
  } else if (changed.length === 1 && !((changed[0] === firstIndex && priorSlots[firstIndex] === null)
    || (changed[0] === secondIndex && priorSlots[firstIndex] !== null
      && priorSlots[secondIndex] === null))) return false;
  if (prior.cleanupCursor < limits.cleanupCursor) {
    if (changed.length !== 1) return false;
    const expectedSafeStateDigest = executionAdvanced
      ? next.cleanupProgressDigest : prior.cleanupProgressDigest;
    if (nextSlots[changed[0]].safeStateDigest !== expectedSafeStateDigest) return false;
  } else if (prior.cleanupProofDigest === null) {
    if (changed.length !== 1) return false;
    const proofCursor = prior.cleanupRunnerExecutionCursor
      - limits.preflightCount - limits.cleanupCursor;
    const expectedSafeStateDigest = recoveryProofDigestAt(validationContext.cleanupRoot,
      validationContext.providerContractDigest,prior.cleanupProgressDigest,
      proofCursor + (executionAdvanced ? 1 : 0));
    if (nextSlots[changed[0]].safeStateDigest !== expectedSafeStateDigest) return false;
  }
  if (!executionAdvanced && changed.length === 0
    && next.cleanupCursor === prior.cleanupCursor
    && next.cleanupProgressDigest === prior.cleanupProgressDigest
    && next.cleanupProofDigest === prior.cleanupProofDigest) return false;
  if (next.cleanupProofDigest !== null && prior.cleanupProofDigest === null
    && (next.cleanupCursor !== limits.cleanupCursor
      || next.cleanupRunnerExecutionCursor !== limits.knownCalls - 1)) return false;
  return exactRecoveryCleanupDigestSuccessor(prior,next,validationContext);
}

function validRecoveryV2Successor(prior, next, validationContext) {
  return validRecoveryV2Snapshot(prior) && validRecoveryV2Snapshot(next)
    && next.intentVersion === prior.intentVersion + 1
    && RECOVERY_V2_IDENTITY_KEYS.every((key) => same(prior[key], next[key]))
    && Date.parse(next.updatedAt) >= Date.parse(prior.updatedAt)
    && (prior.state === 'planned'
      ? (next.state === 'planned' || next.state === 'created') && recoveryCleanupFieldsNull(next)
      : validRecoveryV2CleanupSuccessor(prior, next, validationContext));
}

function validRecoveryOrdinarySuccessor(prior, next, validationContext) {
  if (prior.schemaVersion !== next.schemaVersion
    || next.intentVersion !== prior.intentVersion + 1
    || (prior.schemaVersion === 'verification-intent-snapshot.v2'
      ? RECOVERY_V2_IDENTITY_KEYS : RECOVERY_V1_IDENTITY_KEYS)
      .some((key) => !same(prior[key], next[key]))
    || !recoveryValidIso(next.updatedAt)
    || Date.parse(next.updatedAt) < Date.parse(prior.updatedAt)) return false;
  if (prior.schemaVersion === 'verification-intent-snapshot.v2') {
    return validRecoveryV2Successor(prior, next, validationContext);
  }
  if (prior.resourceType === 'primary-execution') {
    return validRecoveryPrimaryExecutionSuccessor(prior, next);
  }
  return prior.observationDigest === null && next.observationDigest === null
    && same(prior.providerResourceIds, next.providerResourceIds)
    && prior.retentionExpiresAt === next.retentionExpiresAt
    && ((prior.state === 'planned' && next.state === 'created')
      || (prior.state === 'created' && next.state === 'absent'));
}

function validRecoveryInitialOrdinaryIntent(value) {
  if (value.schemaVersion === 'verification-intent-snapshot.v2') {
    return value.state === 'planned' && value.intentVersion === 1 && validRecoveryV2Snapshot(value);
  }
  return value.state === 'planned' && value.intentVersion === 1
    && (value.resourceType === 'primary-execution'
      ? validRecoveryPrimaryExecutionSnapshot(value) : value.observationDigest === null);
}

function recoveryAccountSessionIntent(value) {
  if (!exactDataObject(value, V1_INTENT_KEYS)
    || value.schemaVersion !== 'verification-intent-snapshot.v1'
    || !INTENT_ID.test(value.intentId)
    || typeof value.runId !== 'string' || value.runId.length === 0
    || !DIGEST.test(value.environmentDigest)
    || value.resourceType !== 'account-session-set' || value.resourceId !== 'owner'
    || !RECOVERY_OWNER_MARKER.test(value.ownerMarker)
    || value.dependencyOrder !== 40 || value.lifecycleClass !== 'session-aggregate'
    || !['planned','created','absent'].includes(value.state)
    || !Number.isSafeInteger(value.intentVersion)
    || value.observationDigest !== null || value.retentionExpiresAt !== null
    || !recoveryValidIso(value.createdAt) || !recoveryValidIso(value.updatedAt)
    || Date.parse(value.updatedAt) < Date.parse(value.createdAt)
    || !exactDensePrimitiveArray(value.providerResourceIds)
    || value.providerResourceIds.length > 4
    || new Set(value.providerResourceIds).size !== value.providerResourceIds.length
    || value.providerResourceIds.some((id) => !RECOVERY_ACCOUNT_SESSION_ID.test(id))
    || (value.state === 'planned' && value.intentVersion !== 1)
    || (value.state === 'created' && value.intentVersion !== 2)
    || (value.state === 'absent' && value.intentVersion !== 3)) return null;
  const sorted = [...value.providerResourceIds].sort();
  if (!same(sorted, value.providerResourceIds)) return null;
  return deepFreeze(safeCopy(value));
}

function recoveryTransitionForSnapshot(prior, snapshot) {
  if (snapshot.schemaVersion === 'verification-intent-snapshot.v1') {
    return snapshot.resourceType === 'primary-execution'
      ? (snapshot.state === 'planned' ? 'observation.planned' : 'observation.observed')
      : `intent.${snapshot.state}`;
  }
  if (prior === undefined) return 'intent.planned';
  if (prior.state === 'planned' && snapshot.state === 'created') return 'intent.created';
  if (snapshot.state === 'absent') return 'intent.absent';
  if (prior.state === 'created' && snapshot.state === 'cleaning') return 'intent.cleanup_started';
  if (prior.cleanupProofDigest === null && snapshot.cleanupProofDigest !== null) {
    return 'intent.cleanup_proof_recorded';
  }
  if (prior.cleanupRunnerExecutionCursor === snapshot.cleanupRunnerExecutionCursor
    && prior.cleanupRunnerExecutionSlotsJson !== snapshot.cleanupRunnerExecutionSlotsJson) {
    return 'intent.cleanup_execution_recorded';
  }
  return 'intent.cleanup_progressed';
}

function recoveryTransitionMatchesSnapshot(prior, snapshot, transition) {
  if (snapshot.schemaVersion === 'verification-intent-snapshot.v1') {
    return transition === recoveryTransitionForSnapshot(prior, snapshot);
  }
  if (prior !== undefined && prior.state === 'planned' && snapshot.state === 'planned') {
    return transition.startsWith('intent.provider_');
  }
  return transition === recoveryTransitionForSnapshot(prior, snapshot);
}

function providerRecoveryGenesisPosition(sourceIntents) {
  let intentDispositionCursor = 0;
  for (let index = 0; index < sourceIntents.length; index += 1) {
    const intent = sourceIntents[index];
    if ((intent.recoveryCheckpointDigest ?? null) !== null) return null;
    if (intent.state === 'absent') {
      if (index !== intentDispositionCursor) return null;
      intentDispositionCursor += 1;
    } else if (!['created', 'cleaning'].includes(intent.state)) return null;
  }
  const prefixLength = RECOVERY_GENESIS_PREFIX_BY_ABSENT_COUNT[intentDispositionCursor];
  if (prefixLength === undefined) return null;
  try {
    deriveRecoveryPosition({ prefixLength, intentDispositionCursor });
    return { prefixLength, intentDispositionCursor };
  } catch {
    return null;
  }
}

function recoverySourceIntentSet(latest) {
  const matches = QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.map((resourceType) => (
    [...latest.values()].filter((intent) => intent.resourceType === resourceType)
  ));
  if (matches.every((items) => items.length === 0)) return [];
  if (matches.some((items) => items.length !== 1)) {
    throw new TypeError('Recovery source intent set is invalid.');
  }
  return matches.map(([intent]) => intent);
}

function reconstructProviderRecoveryProof(snapshot, recoveryContext) {
  let activeRun = null;
  let ordinaryLeaseState = 'idle';
  let latest = new Map();
  let cleanupRoots = new Map();
  let activeProviderContractDigest = null;
  let accountSessionObserved = false;
  let accountSessionIntent = null;
  let accountSessionIntentIds = new Set();
  let recoveryStarted = false;
  let sourceIntents = null;
  let sourceAuditHeadDigest = null;
  let sourceLeaseVersion = null;
  let currentIntents = null;
  let predecessorRecoveryEvent = null;
  for (const entry of snapshot.auditTrail) {
    const isRecovery = exactDataObject(entry.event, RECOVERY_AUDIT_EVENT_KEYS);
    if (!isRecovery) {
      if (recoveryStarted) throw new TypeError('Ordinary audit evidence follows recovery.');
      const event = entry.event;
      if (event.transition === 'lease.acquire') {
        if (activeRun !== null || ordinaryLeaseState !== 'idle'
          || event.intentId !== null || event.intentProjectionDigest !== null) {
          throw new TypeError('Recovery source lease acquisition is invalid.');
        }
        activeRun = event.runId;
        ordinaryLeaseState = 'active';
        latest = new Map();
        cleanupRoots = new Map();
        activeProviderContractDigest = null;
        accountSessionObserved = false;
        accountSessionIntent = null;
        accountSessionIntentIds = new Set();
      } else if (event.runId !== activeRun) {
        throw new TypeError('Recovery source run chain is invalid.');
      }
      if (event.intentProjectionDigest === null) {
        if (event.transition === 'lease.renew') {
          if (ordinaryLeaseState !== 'active') throw new TypeError('Recovery source lease renewal is invalid.');
        } else if (event.transition === 'lease.cleanup_debt') {
          if (ordinaryLeaseState !== 'active') throw new TypeError('Recovery source cleanup debt is invalid.');
          ordinaryLeaseState = 'cleanup-debt';
        } else if (event.transition === 'lease.recover') {
          if (ordinaryLeaseState !== 'cleanup-debt') throw new TypeError('Recovery source lease recovery is invalid.');
          ordinaryLeaseState = 'recovering';
        } else if (event.transition === 'lease.close') {
          if (!['active', 'recovering'].includes(ordinaryLeaseState)) throw new TypeError('Recovery source lease close is invalid.');
          ordinaryLeaseState = 'idle';
          activeRun = null;
        }
        continue;
      }
      const candidate = entry.snapshot;
      const prior = candidate === null ? undefined : latest.get(candidate.intentId);
      const candidateProviderContractDigest = candidate?.schemaVersion ===
        'verification-intent-snapshot.v2' ? recoveryProviderContractDigest(candidate) : null;
      if (candidate?.schemaVersion === 'verification-intent-snapshot.v2') {
        if (candidateProviderContractDigest === null
          || (activeProviderContractDigest !== null
            && candidateProviderContractDigest !== activeProviderContractDigest)) {
          throw new TypeError('Recovery source provider binding is invalid.');
        }
        activeProviderContractDigest = candidateProviderContractDigest;
      }
      const validationContext = {providerContractDigest:activeProviderContractDigest,
        cleanupRoot:candidate === null ? null
          : cleanupRoots.get(candidate.intentId) ?? (prior?.state === 'created' ? prior : null)};
      if (candidate === null || candidate.intentId !== event.intentId
        || candidate.runId !== event.runId || contentDigest(candidate) !== event.intentProjectionDigest
        || (prior === undefined
          ? !validRecoveryInitialOrdinaryIntent(candidate)
          : !validRecoveryOrdinarySuccessor(prior, candidate, validationContext))
        || !recoveryTransitionMatchesSnapshot(prior, candidate, event.transition)) {
        throw new TypeError('Recovery source intent evidence is invalid.');
      }
      if (candidate.schemaVersion === 'verification-intent-snapshot.v2'
        && candidate.state === 'created' && !cleanupRoots.has(candidate.intentId)) {
        cleanupRoots.set(candidate.intentId, candidate);
      }
      latest.set(candidate.intentId, candidate);
      if (!validRecoveryGlobalCleanupState([...latest.values()])) {
        throw new TypeError('Recovery source global cleanup evidence is invalid.');
      }
      if (candidate.resourceType === 'account-session') accountSessionObserved = true;
      if (candidate.resourceType === 'account-session-set') {
        const sessionIntent = recoveryAccountSessionIntent(candidate);
        if (sessionIntent === null) {
          throw new TypeError('Recovery source account-session intent is invalid.');
        }
        accountSessionIntentIds.add(sessionIntent.intentId);
        if (accountSessionIntentIds.size !== 1) {
          throw new TypeError('Recovery source account-session intent is duplicated.');
        }
        accountSessionIntent = sessionIntent;
      }
      continue;
    }

    const validated = validateRecoveryAuditEvent(entry.event);
    const checkpoint = validated.checkpoint;
    if (activeRun === null || entry.event.runId !== activeRun) {
      throw new TypeError('Recovery event run is invalid.');
    }
    if (!recoveryStarted) {
      if (ordinaryLeaseState !== 'cleanup-debt') throw new TypeError('Recovery source lease state is invalid.');
      recoveryStarted = true;
      sourceAuditHeadDigest = entry.event.previousLedgerDigest;
      sourceLeaseVersion = entry.event.leaseVersionBefore;
      sourceIntents = recoverySourceIntentSet(latest);
      const genesisPosition = providerRecoveryGenesisPosition(sourceIntents);
      if (sourceIntents.length !== 3 || accountSessionObserved
        || genesisPosition === null || sourceIntents.some((intent) => (
        intent.runId !== activeRun
        || intent.environmentDigest !== snapshot.lease.environmentDigest
      ))) throw new TypeError('Recovery source intent set is invalid.');
      currentIntents = sourceIntents.map(safeCopy);
      const proof = { environmentDigest: snapshot.lease.environmentDigest, sourceAuditHeadDigest,
        sourceLeaseVersion, sourceIntents, genesisPosition };
      if (entry.event.transition !== 'recovery.checkpoint_started'
        || checkpoint.prefixLength !== genesisPosition.prefixLength
        || checkpoint.intentDispositionCursor !== genesisPosition.intentDispositionCursor
        || entry.snapshot !== null || !exactRecoveryGenesis(checkpoint, proof)) {
        throw new TypeError('Recovery genesis proof is invalid.');
      }
    } else {
      let terminalIntentTransition = null;
      if (entry.event.transition === 'intent.recovery_absent') {
        const cursor = predecessorRecoveryEvent === null
          ? -1 : validateRecoveryAuditEvent(predecessorRecoveryEvent).checkpoint.intentDispositionCursor;
        const candidate = entry.snapshot;
        if (cursor < 0 || cursor >= currentIntents.length || candidate === null) {
          throw new TypeError('Recovery terminal intent proof is invalid.');
        }
        const priorIntents = currentIntents.map(safeCopy);
        const nextIntents = priorIntents.map((intent, index) => index === cursor ? candidate : intent);
        terminalIntentTransition = { predecessor: priorIntents[cursor], candidate,
          sourceIntents, priorIntents, currentIntents: nextIntents };
        currentIntents = nextIntents;
      } else if (entry.snapshot !== null) throw new TypeError('Recovery event snapshot is invalid.');
      validateRecoveryCheckpointSuccessor({ authenticatedAuditHeadDigest: entry.event.previousLedgerDigest,
        predecessorEvent: predecessorRecoveryEvent, event: entry.event, terminalIntentTransition });
      const proof = { environmentDigest: snapshot.lease.environmentDigest, sourceAuditHeadDigest,
        sourceLeaseVersion, sourceIntents };
      if (!exactRecoverySourceBindings(checkpoint, proof, currentIntents)) {
        throw new TypeError('Recovery successor source proof is invalid.');
      }
    }
    predecessorRecoveryEvent = entry.event;
  }

  if (activeRun !== snapshot.lease.ownerRunId
    || snapshot.lease.cleanupDebt !== true
    || typeof snapshot.lease.ownerWorkflowRunId !== 'string'
    || snapshot.lease.ownerWorkflowRunId !== recoveryContext.originalWorkflowRunId) {
    throw new TypeError('Recovery source owner is invalid.');
  }
  if (!recoveryStarted) {
    if (ordinaryLeaseState !== 'cleanup-debt' || snapshot.lease.state !== 'cleanup-debt') {
      throw new TypeError('Recovery source lease state is invalid.');
    }
    sourceAuditHeadDigest = snapshot.lease.ledgerDigest;
    sourceLeaseVersion = snapshot.lease.leaseVersion;
    sourceIntents = recoverySourceIntentSet(latest);
    const genesisPosition = providerRecoveryGenesisPosition(sourceIntents);
    if (accountSessionObserved
      || genesisPosition === null || sourceIntents.some((intent) => (
      intent.environmentDigest !== snapshot.lease.environmentDigest
    ))) throw new TypeError('Recovery source intent set is invalid.');
    currentIntents = sourceIntents.map(safeCopy);
  } else if (snapshot.lease.state !== 'recovering') {
    throw new TypeError('Recovery lease state is invalid.');
  }
  for (const { intentId, projection } of snapshot.intentProjections) {
    const expected = latest.get(intentId);
    const recoveryIntent = currentIntents.find((intent) => intent.intentId === intentId);
    if ((recoveryIntent === undefined || !same(recoveryIntent, projection))
      && (expected === undefined || !same(expected, projection))) {
      throw new TypeError('Recovery projection evidence is invalid.');
    }
  }
  const primaryExecutionIntents=[...latest.values()].filter((intent)=>(
    intent.schemaVersion==='verification-intent-snapshot.v1'
      &&intent.resourceType==='primary-execution'
  ));
  if(primaryExecutionIntents.length>1
    ||(primaryExecutionIntents.length===1
      &&!validRecoveryPrimaryExecutionSnapshot(primaryExecutionIntents[0]))){
    throw new TypeError('Recovery primary execution evidence is invalid.');
  }
  const primaryExecutionIntent=primaryExecutionIntents.length===1
    ?primaryExecutionIntents[0]:null;
  return { environmentDigest: snapshot.lease.environmentDigest, sourceAuditHeadDigest,
    sourceLeaseVersion, sourceIntents, currentIntents, predecessorRecoveryEvent, activeRun,
    accountSessionIntent,primaryExecutionIntent,
    genesisPosition: providerRecoveryGenesisPosition(sourceIntents) };
}

function validateProviderRecoveryCandidate(sourceSnapshot, event, intentSuccessor, recoveryContext) {
  const proof = reconstructProviderRecoveryProof(sourceSnapshot, recoveryContext);
  const validated = validateRecoveryAuditEvent(event);
  if (event.runId !== proof.activeRun) throw new TypeError('Recovery event run is invalid.');
  if (proof.predecessorRecoveryEvent === null) {
    if (event.transition !== 'recovery.checkpoint_started' || intentSuccessor !== null
      || validated.checkpoint.prefixLength !== proof.genesisPosition?.prefixLength
      || validated.checkpoint.intentDispositionCursor !== proof.genesisPosition?.intentDispositionCursor
      || !exactRecoveryGenesis(validated.checkpoint, proof)) {
      throw new TypeError('Recovery genesis proof is invalid.');
    }
    return;
  }
  let terminalIntentTransition = null;
  let currentIntents = proof.currentIntents;
  if (event.transition === 'intent.recovery_absent') {
    const predecessor = validateRecoveryAuditEvent(proof.predecessorRecoveryEvent).checkpoint;
    const cursor = predecessor.intentDispositionCursor;
    if (intentSuccessor === null || cursor < 0 || cursor >= currentIntents.length) {
      throw new TypeError('Recovery terminal intent proof is invalid.');
    }
    const priorIntents = currentIntents.map(safeCopy);
    currentIntents = priorIntents.map((intent, index) => index === cursor ? intentSuccessor : intent);
    terminalIntentTransition = { predecessor: priorIntents[cursor], candidate: intentSuccessor,
      sourceIntents: proof.sourceIntents, priorIntents, currentIntents };
  }
  validateRecoveryCheckpointSuccessor({
    authenticatedAuditHeadDigest: sourceSnapshot.lease.ledgerDigest,
    predecessorEvent: proof.predecessorRecoveryEvent,
    event,
    terminalIntentTransition,
  });
  if (!exactRecoverySourceBindings(validated.checkpoint, proof, currentIntents)) {
    throw new TypeError('Recovery successor source proof is invalid.');
  }
}

export function isAuthenticProviderRecoveryControlStore(value, context) {
  try {
    return providerRecoveryControlStoreRecords.get(value)?.context === context;
  } catch {
    return false;
  }
}

export function createProviderRecoveryControlStore(args = {}) {
  if (
    !exactDataObject(args, ['context', 'recoveryControlClient'])
    || !isAuthenticTestRecoveryEnvironmentContext(args.context)
    || !isAuthenticTestCloudRecoveryControlClient(
      args.recoveryControlClient,
      args.context,
    )
  ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');

  const client = args.recoveryControlClient;
  let store;

  async function getRecoveryRow(tableId, rowId, mismatchCode) {
    const outcome = await client.getRow({ tableId, rowId });
    if (
      !validClientResult(outcome)
      || !exactDataObject(outcome.value, ['data', 'rowId'])
      || outcome.value.rowId !== rowId
    ) mismatch(mismatchCode);
    if (outcome.value.data === null) return null;
    try {
      return safeCopy(outcome.value.data);
    } catch {
      mismatch(mismatchCode);
    }
  }

  async function getRecoveryLease() {
    const lease = await getRecoveryRow(
      LEASE_TABLE_ID,
      LEASE_ROW_ID,
      'LEASE_READBACK_MISMATCH',
    );
    if (
      lease === null
      || !exactDataObject(lease, LEASE_KEYS)
      || lease.leaseRowId !== LEASE_ROW_ID
      || !Number.isSafeInteger(lease.leaseVersion)
      || lease.leaseVersion < 0
      || !DIGEST.test(lease.ledgerDigest)
    ) mismatch('LEASE_READBACK_MISMATCH');
    return deepFreeze(lease);
  }

  async function getRecoveryAuditEventByDigest(value) {
    if (!DIGEST.test(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    const rowId = contentDigestToRowId(value);
    const data = await getRecoveryRow(AUDIT_TABLE_ID, rowId, 'AUDIT_CHAIN_MISMATCH');
    if (data === null) return null;
    if (!contentAddressedRowMatches({ rowId, contentDigest: value, data })) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    return deepFreeze(recoveryAuditEvent(data));
  }

  async function getRecoveryIntentSnapshotByDigest(value) {
    if (!DIGEST.test(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    const rowId = contentDigestToRowId(value);
    const data = await getRecoveryRow(INTENT_TABLE_ID, rowId, 'AUDIT_CHAIN_MISMATCH');
    if (data === null) return null;
    if (!contentAddressedRowMatches({ rowId, contentDigest: value, data })) {
      mismatch('AUDIT_CHAIN_MISMATCH');
    }
    return deepFreeze(recoveryIntentRow(data));
  }

  async function getRecoveryIntentProjection(value) {
    if (!INTENT_ID.test(value)) mismatch('AUDIT_CHAIN_MISMATCH');
    const rowId = intentIdToRowId(value);
    const data = await getRecoveryRow(INTENT_TABLE_ID, rowId, 'AUDIT_CHAIN_MISMATCH');
    if (data === null) return null;
    const projection = recoveryIntentRow(data);
    if (
      projection.intentId !== value
      || !intentProjectionRowMatches({ rowId, data: projection })
    ) mismatch('AUDIT_CHAIN_MISMATCH');
    return deepFreeze(projection);
  }

  async function readRecoverySnapshotValue() {
    const lease = await getRecoveryLease();
    const reversedTrail = [];
    const seenDigests = new Set();
    const intentIds = new Set();
    let authoritativeRunId=lease.ownerRunId;
    let auditDigest = lease.ledgerDigest;
    let expectedLeaseVersionAfter = lease.leaseVersion;

    while (auditDigest !== RECOVERY_GENESIS_LEDGER_DIGEST) {
      if (seenDigests.has(auditDigest)) mismatch('AUDIT_CHAIN_MISMATCH');
      seenDigests.add(auditDigest);
      const event = await getRecoveryAuditEventByDigest(auditDigest);
      if (event === null || event.leaseVersionAfter !== expectedLeaseVersionAfter) {
        mismatch('AUDIT_CHAIN_MISMATCH');
      }
      if(reversedTrail.length===0&&authoritativeRunId===null&&lease.state==='idle'
        &&event.transition==='lease.close')authoritativeRunId=event.runId;
      let snapshot = null;
      if (event.intentId === null || event.intentProjectionDigest === null) {
        if (event.intentId !== null || event.intentProjectionDigest !== null) {
          mismatch('AUDIT_CHAIN_MISMATCH');
        }
      } else {
        snapshot = await getRecoveryIntentSnapshotByDigest(event.intentProjectionDigest);
        if (snapshot === null || snapshot.intentId !== event.intentId) {
          mismatch('AUDIT_CHAIN_MISMATCH');
        }
        if (event.runId === authoritativeRunId) intentIds.add(event.intentId);
      }
      reversedTrail.push(deepFreeze({ digest: auditDigest, event, snapshot }));
      expectedLeaseVersionAfter = event.leaseVersionBefore;
      auditDigest = event.previousLedgerDigest;
    }
    if (expectedLeaseVersionAfter !== 0) mismatch('AUDIT_CHAIN_MISMATCH');

    const intentProjections = [];
    for (const intentId of [...intentIds].sort()) {
      intentProjections.push(deepFreeze({
        intentId,
        projection: await getRecoveryIntentProjection(intentId),
      }));
    }
    return deepFreeze({
      lease,
      auditTrail: reversedTrail.reverse(),
      intentProjections,
    });
  }

  function mintReadOperation() {
    return createRecoveryOpaqueOperation(providerRecoveryReadOperationRecords, {
      consumed: false,
      store,
    });
  }

  function committedSnapshotFor(operation) {
    const auditTrail = [
      ...operation.sourceSnapshot.auditTrail,
      deepFreeze({
        digest: operation.eventDigest,
        event: operation.event,
        snapshot: operation.intentSuccessor,
      }),
    ];
    const projectionByIntent = new Map(operation.sourceSnapshot.intentProjections.map(
      (entry) => [entry.intentId, entry],
    ));
    if (operation.intentSuccessor !== null) {
      projectionByIntent.set(operation.intentSuccessor.intentId, deepFreeze({
        intentId: operation.intentSuccessor.intentId,
        projection: operation.intentSuccessor,
      }));
    }
    return deepFreeze({
      lease: operation.nextLease,
      auditTrail,
      intentProjections: [...projectionByIntent.values()].sort(
        (left, right) => left.intentId < right.intentId ? -1 : left.intentId > right.intentId ? 1 : 0,
      ),
    });
  }

  function makeCommitOperationFactory(sourceSnapshot) {
    let consumed = false;
    return function createCommitOperation(value) {
      if (consumed || !exactDataObject(value, ['event', 'intentSuccessor', 'nextLease'])) {
        throw new TypeError('Recovery commit operation is invalid.');
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      let validatedEvent;
      try {
        validatedEvent = validateRecoveryAuditEvent(descriptors.event.value).event;
      } catch {
        throw new TypeError('Recovery commit event is invalid.');
      }
      if (!exactDataObject(descriptors.nextLease.value, LEASE_KEYS)) {
        throw new TypeError('Recovery commit lease is invalid.');
      }
      const event = deepFreeze(safeCopy(validatedEvent));
      const eventDigest = createRecoveryAuditEventDigest(event);
      const authorizedNextLease = deepFreeze({
        ...sourceSnapshot.lease,
        state: 'recovering',
        cleanupDebt: true,
        leaseVersion: sourceSnapshot.lease.leaseVersion + 1,
        ledgerDigest: eventDigest,
      });
      const nextLease = deepFreeze(safeCopy(descriptors.nextLease.value));
      if (
        event.previousLedgerDigest !== sourceSnapshot.lease.ledgerDigest
        || event.leaseVersionBefore !== sourceSnapshot.lease.leaseVersion
        || event.leaseVersionAfter !== sourceSnapshot.lease.leaseVersion + 1
        || !same(nextLease, authorizedNextLease)
      ) throw new TypeError('Recovery commit compare-and-swap is invalid.');

      let intentSuccessor = null;
      let intentSuccessorDigest = null;
      const rawIntentSuccessor = descriptors.intentSuccessor.value;
      if (rawIntentSuccessor === null) {
        if (
          event.transition === 'intent.recovery_absent'
          || event.intentId !== null
          || event.intentProjectionDigest !== null
        ) throw new TypeError('Recovery commit intent is invalid.');
      } else {
        let validatedIntent;
        try {
          validatedIntent = validateRecoveryIntentRow(rawIntentSuccessor);
        } catch {
          throw new TypeError('Recovery commit intent is invalid.');
        }
        intentSuccessor = deepFreeze(safeCopy(validatedIntent));
        intentSuccessorDigest = contentDigest(intentSuccessor);
        const currentProjection = sourceSnapshot.intentProjections.find(
          ({ intentId }) => intentId === intentSuccessor.intentId,
        )?.projection;
        if (
          event.transition !== 'intent.recovery_absent'
          || event.intentId !== intentSuccessor.intentId
          || event.intentProjectionDigest !== intentSuccessorDigest
          || intentSuccessor.recoveryCheckpointDigest !== event.recoveryCheckpointDigest
          || currentProjection === null
          || currentProjection === undefined
        ) throw new TypeError('Recovery commit intent is invalid.');
      }

      validateProviderRecoveryCandidate(sourceSnapshot, event, intentSuccessor, args.context);
      consumed = true;
      return createRecoveryOpaqueOperation(providerRecoveryCommitOperationRecords, {
        consumed: false,
        event,
        eventDigest,
        intentSuccessor,
        intentSuccessorDigest,
        nextLease,
        sourceSnapshot,
        store,
      });
    };
  }

  function makeAccountSessionAbsenceOperationFactory(sourceSnapshot, sourceIntent) {
    let consumed = false;
    return function createAbsenceOperation(value) {
      if (consumed || !exactDataObject(value, ['event', 'intentSuccessor', 'nextLease'])) {
        throw new TypeError('Recovery account-session absence operation is invalid.');
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const event = deepFreeze(recoveryAuditEvent(descriptors.event.value));
      const intentSuccessor = recoveryAccountSessionIntent(descriptors.intentSuccessor.value);
      if (intentSuccessor === null || !exactDataObject(descriptors.nextLease.value, LEASE_KEYS)) {
        throw new TypeError('Recovery account-session absence operation is invalid.');
      }
      const eventDigest = contentDigest(event);
      const intentSuccessorDigest = contentDigest(intentSuccessor);
      const nextLease = deepFreeze(safeCopy(descriptors.nextLease.value));
      const authorizedNextLease = deepFreeze({
        ...sourceSnapshot.lease,
        leaseVersion: sourceSnapshot.lease.leaseVersion + 1,
        ledgerDigest: eventDigest,
      });
      if (event.transition !== 'intent.absent'
        || event.previousLedgerDigest !== sourceSnapshot.lease.ledgerDigest
        || event.runId !== sourceSnapshot.lease.ownerRunId
        || event.leaseVersionBefore !== sourceSnapshot.lease.leaseVersion
        || event.leaseVersionAfter !== sourceSnapshot.lease.leaseVersion + 1
        || event.intentId !== intentSuccessor.intentId
        || event.intentProjectionDigest !== intentSuccessorDigest
        || sourceIntent.state !== 'created' || intentSuccessor.state !== 'absent'
        || !validRecoveryOrdinarySuccessor(sourceIntent, intentSuccessor, {
          providerContractDigest:null, cleanupRoot:null,
        })
        || !same(nextLease, authorizedNextLease)) {
        throw new TypeError('Recovery account-session absence operation is invalid.');
      }
      consumed = true;
      return createRecoveryOpaqueOperation(providerRecoverySessionAbsenceOperationRecords, {
        consumed:false,event,eventDigest,intentSuccessor,intentSuccessorDigest,nextLease,
        sourceSnapshot,store,
      });
    };
  }

  function makeRecoveryCloseOperationFactory(sourceSnapshot, proof) {
    let consumed=false;
    return function createCloseOperation(value) {
      if(consumed||!exactDataObject(value,['event','nextLease'])){
        throw new TypeError('Recovery close operation is invalid.');
      }
      const descriptors=Object.getOwnPropertyDescriptors(value);
      const event=deepFreeze(recoveryAuditEvent(descriptors.event.value));
      if(!exactDataObject(descriptors.nextLease.value,LEASE_KEYS)){
        throw new TypeError('Recovery close operation is invalid.');
      }
      const eventDigest=contentDigest(event);
      const nextLease=deepFreeze(safeCopy(descriptors.nextLease.value));
      const authorizedNextLease=deepFreeze({...sourceSnapshot.lease,
        state:'idle',ownerRunId:null,ownerWorkflowRunId:null,environmentDigest:null,
        acquiredAt:null,renewedAt:null,expiresAt:null,leaseTokenDigest:null,cleanupDebt:false,
        leaseVersion:sourceSnapshot.lease.leaseVersion+1,ledgerDigest:eventDigest});
      const checkpoint=proof.predecessorRecoveryEvent===null?null
        :validateRecoveryAuditEvent(proof.predecessorRecoveryEvent).checkpoint;
      const completedResourceClose=sourceSnapshot.lease.state==='recovering'
        &&sourceSnapshot.lease.cleanupDebt===true
        &&checkpoint?.checkpointState==='resources-complete'&&checkpoint.prefixLength===42
        &&checkpoint.intentDispositionCursor===3
        &&proof.currentIntents.every((intent)=>intent.state==='absent')
        &&proof.accountSessionIntent?.state==='absent'
        &&proof.primaryExecutionIntent?.state==='created';
      const emptyResourceClose=proof.predecessorRecoveryEvent===null
        &&sourceSnapshot.lease.state==='cleanup-debt'&&sourceSnapshot.lease.cleanupDebt===true
        &&proof.sourceIntents.length===0&&proof.currentIntents.length===0
        &&(proof.accountSessionIntent===null||proof.accountSessionIntent.state==='absent')
        &&(proof.primaryExecutionIntent===null
          ||['planned','created'].includes(proof.primaryExecutionIntent.state));
      if(event.transition!=='lease.close'||event.previousLedgerDigest!==sourceSnapshot.lease.ledgerDigest
        ||event.runId!==sourceSnapshot.lease.ownerRunId
        ||event.leaseVersionBefore!==sourceSnapshot.lease.leaseVersion
        ||event.leaseVersionAfter!==sourceSnapshot.lease.leaseVersion+1
        ||event.intentId!==null||event.intentProjectionDigest!==null
        ||(!completedResourceClose&&!emptyResourceClose)
        ||!same(nextLease,authorizedNextLease)){
        throw new TypeError('Recovery close operation is invalid.');
      }
      consumed=true;
      return createRecoveryOpaqueOperation(providerRecoveryCloseOperationRecords,{
        consumed:false,event,eventDigest,intentSuccessor:null,intentSuccessorDigest:null,
        nextLease,sourceSnapshot,store,
      });
    };
  }

  async function readRecoveryAccountSessionSource(request) {
    const operation = providerRecoveryReadOperationRecords.get(request);
    if (operation?.store !== store || operation.consumed) {
      return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
    }
    operation.consumed = true;
    try {
      const snapshot = await readRecoverySnapshotValue();
      const proof = reconstructProviderRecoveryProof(snapshot, args.context);
      const sourceIntent = proof.accountSessionIntent;
      if(sourceIntent===null){
        if(proof.sourceIntents.length!==0||proof.predecessorRecoveryEvent!==null){
          return result('BLOCKED',null,'AUDIT_CHAIN_MISMATCH');
        }
        return result('PASS',{snapshot,nextRequest:mintReadOperation()});
      }
      if(sourceIntent?.state==='absent'){
        return result('PASS',{snapshot,nextRequest:mintReadOperation()});
      }
      if (proof.predecessorRecoveryEvent !== null || sourceIntent?.state !== 'created') {
        return result('BLOCKED', null, 'AUDIT_CHAIN_MISMATCH');
      }
      return result('PASS', {
        snapshot,
        nextRequest:mintReadOperation(),
        createAbsenceOperation:makeAccountSessionAbsenceOperationFactory(snapshot, sourceIntent),
      });
    } catch (error) {
      return recoveryFailure(error);
    }
  }

  async function readRecoverySnapshot(request) {
    const operation = providerRecoveryReadOperationRecords.get(request);
    if (operation?.store !== store || operation.consumed) {
      return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
    }
    operation.consumed = true;
    try {
      const snapshot = await readRecoverySnapshotValue();
      if (snapshot.auditTrail.some(({ event }) => (
        Object.hasOwn(event, 'recoveryCheckpointJson')
      ))) reconstructProviderRecoveryProof(snapshot, args.context);
      return result('PASS', {
        snapshot,
        nextRequest: mintReadOperation(),
        createCommitOperation: makeCommitOperationFactory(snapshot),
      });
    } catch (error) {
      return recoveryFailure(error);
    }
  }

  async function readRecoveryCloseSource(request) {
    const operation=providerRecoveryReadOperationRecords.get(request);
    if(operation?.store!==store||operation.consumed){
      return result('BLOCKED',null,'TEST_CLOUD_SETUP_INCOMPLETE');
    }
    operation.consumed=true;
    try{
      const snapshot=await readRecoverySnapshotValue();
      const proof=reconstructProviderRecoveryProof(snapshot,args.context);
      const checkpoint=proof.predecessorRecoveryEvent===null?null
        :validateRecoveryAuditEvent(proof.predecessorRecoveryEvent).checkpoint;
      const completedResourceClose=checkpoint?.checkpointState==='resources-complete'
        &&proof.currentIntents.every((intent)=>intent.state==='absent')
        &&proof.accountSessionIntent?.state==='absent'
        &&proof.primaryExecutionIntent?.state==='created';
      const emptyResourceClose=proof.predecessorRecoveryEvent===null
        &&snapshot.lease.state==='cleanup-debt'&&snapshot.lease.cleanupDebt===true
        &&proof.sourceIntents.length===0&&proof.currentIntents.length===0
        &&(proof.accountSessionIntent===null||proof.accountSessionIntent.state==='absent')
        &&(proof.primaryExecutionIntent===null
          ||['planned','created'].includes(proof.primaryExecutionIntent.state));
      if(!completedResourceClose&&!emptyResourceClose){
        return result('BLOCKED',null,'AUDIT_CHAIN_MISMATCH');
      }
      return result('PASS',{snapshot,
        createCloseOperation:makeRecoveryCloseOperationFactory(snapshot,proof)});
    }catch(error){return recoveryFailure(error);}
  }

  async function recoveryCandidateRowsAbsent(operation) {
    if (await getRecoveryAuditEventByDigest(operation.eventDigest) !== null) return false;
    return operation.intentSuccessor === null
      || await getRecoveryIntentSnapshotByDigest(operation.intentSuccessorDigest) === null;
  }

  function recoveryTransactionOperations(operation) {
    const operations = [];
    if (operation.intentSuccessor !== null) {
      operations.push({
        action: 'createRow',
        tableId: INTENT_TABLE_ID,
        rowId: contentDigestToRowId(operation.intentSuccessorDigest),
        data: operation.intentSuccessor,
      });
    }
    operations.push({
      action: 'createRow',
      tableId: AUDIT_TABLE_ID,
      rowId: contentDigestToRowId(operation.eventDigest),
      data: operation.event,
    });
    if (operation.intentSuccessor !== null) {
      operations.push({
        action: 'updateRow',
        tableId: INTENT_TABLE_ID,
        rowId: intentIdToRowId(operation.intentSuccessor.intentId),
        data: operation.intentSuccessor,
      });
    }
    operations.push({
      action: 'incrementRowColumn',
      tableId: LEASE_TABLE_ID,
      rowId: LEASE_ROW_ID,
      column: 'leaseVersion',
      value: 1,
      max: operation.nextLease.leaseVersion,
    });
    const leasePatch = { ...operation.nextLease };
    delete leasePatch.leaseVersion;
    operations.push({
      action: 'updateRow',
      tableId: LEASE_TABLE_ID,
      rowId: LEASE_ROW_ID,
      data: leasePatch,
    });
    return deepFreeze(operations);
  }

  async function commitRecoveryTransaction(operations) {
    const opened = await client.createTransaction({ ttl: 60 });
    if (
      !validClientResult(opened)
      || !exactDataObject(opened.value, ['status', 'transactionId'])
      || opened.value.status !== 'pending'
    ) return 'rejected';
    const transactionId = opened.value.transactionId;
    const staged = await client.createTransactionOperations({ transactionId, operations });
    if (
      !validClientResult(staged)
      || !exactDataObject(staged.value, ['status', 'transactionId'])
      || staged.value.transactionId !== transactionId
      || staged.value.status !== 'pending'
    ) return 'rejected';
    const committed = await client.commitOrRollbackTransaction({
      transactionId,
      action: 'commit',
    });
    if (
      validClientResult(committed)
      && exactDataObject(committed.value, ['status', 'transactionId'])
      && committed.value.transactionId === transactionId
      && committed.value.status === 'committed'
    ) return 'committed';
    if (
      validClientResult(committed)
      && exactDataObject(committed.value, ['status', 'transactionId'])
      && committed.value.transactionId === transactionId
      && committed.value.status === 'pending'
    ) return 'unknown';
    return unknownCommit(committed) ? 'unknown' : 'rejected';
  }

  async function commitBoundedRecoveryOperation(operation) {
    try {
      const freshSnapshot = await readRecoverySnapshotValue();
      if (!same(freshSnapshot, operation.sourceSnapshot)) {
        return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
      }
      if (!await recoveryCandidateRowsAbsent(operation)) {
        return result('BLOCKED', null, 'AUDIT_CHAIN_MISMATCH');
      }

      const operations = recoveryTransactionOperations(operation);
      const expectedSnapshot = committedSnapshotFor(operation);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const disposition = await commitRecoveryTransaction(operations);
        if (disposition === 'rejected') {
          return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
        }
        const observedSnapshot = await readRecoverySnapshotValue();
        if (same(observedSnapshot, expectedSnapshot)) {
          return result('PASS', {
            snapshot: observedSnapshot,
            nextRequest: mintReadOperation(),
          });
        }
        if (disposition === 'committed' || !same(observedSnapshot, operation.sourceSnapshot)) {
          return result('BLOCKED', null, 'AUDIT_CHAIN_MISMATCH');
        }
        if (!await recoveryCandidateRowsAbsent(operation)) {
          return result('BLOCKED', null, 'AUDIT_CHAIN_MISMATCH');
        }
        if (attempt === 1) {
          return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
        }
      }
      return result('BLOCKED', null, 'LEASE_VERSION_MISMATCH');
    } catch (error) {
      return recoveryFailure(error);
    }
  }

  async function commitRecoveryTransition(commitOperation) {
    const operation = providerRecoveryCommitOperationRecords.get(commitOperation);
    if (operation?.store !== store || operation.consumed) {
      return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
    }
    operation.consumed = true;
    return commitBoundedRecoveryOperation(operation);
  }

  async function commitRecoveryAccountSessionAbsence(commitOperation) {
    const operation = providerRecoverySessionAbsenceOperationRecords.get(commitOperation);
    if (operation?.store !== store || operation.consumed) {
      return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
    }
    operation.consumed = true;
    return commitBoundedRecoveryOperation(operation);
  }

  async function commitRecoveryClose(commitOperation) {
    const operation=providerRecoveryCloseOperationRecords.get(commitOperation);
    if(operation?.store!==store||operation.consumed){
      return result('BLOCKED',null,'TEST_CLOUD_SETUP_INCOMPLETE');
    }
    operation.consumed=true;
    return commitBoundedRecoveryOperation(operation);
  }

  store = Object.freeze({
    commitRecoveryAccountSessionAbsence,
    commitRecoveryClose,
    commitRecoveryTransition,
    readRecoveryAccountSessionSource,
    readRecoveryCloseSource,
    readRecoverySnapshot,
  });
  providerRecoveryControlStoreRecords.set(store, Object.freeze({
    client,
    context: args.context,
  }));
  return result('PASS', { request: mintReadOperation(), store });
}

const BOOTSTRAP_HUB_PROPERTY = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const reflectApply = Reflect.apply;
const PROVIDER_CONTROL_RECEIVER = Object.freeze(Object.create(null));
let providerControlBootstrapState = 'EMPTY';
let providerControlHubDispatchers;
let providerTupleRecord = Object.freeze({
  state: 'READY',
  version: 0,
  nextMutationOrdinal: 0,
  providerBoundCount: 0,
  providerValuesBoundBatchCount: 0,
  providerOperationIssuedCount: 0,
  providerOperationReconciledCount: 0,
  providerCreateIssuedCount: 0,
  providerIdDiscoveredCount: 0,
});
const providerMutationIssueRecords = new WeakMap();
const boundProviderIds = new Map();
const boundCompositeProviderIds = new Set();
const providerObservedMemberStates = new Map();
const shareProviderIds = new Set();
const mutationReconciliationRecords = new WeakMap();
const mutationReconciliationQualifications = new Map();
const initialProviderPrefixRecords = new WeakMap();
const sharePreparationRecords = new WeakMap();
const shareCommitReceiptRecords = new WeakMap();
const shareBaselineProofRecords = new WeakMap();
const shareIssueRecords = new WeakMap();
const providerQualificationRecords = new WeakMap();
const GENERIC_ISSUE_KEYS = Object.freeze([
  'runtimeQualification', 'context', 'sessionIntentQualification', 'mutationOrdinal',
  'observationQualification', 'routeProjection', 'expectedStateMapping',
]);
const GENERIC_RECONCILE_KEYS = Object.freeze([
  'runtimeQualification', 'providerMutationIssue', 'observationQualification',
  'releaseDisposition',
]);
const ROUTE_PROJECTION_KEYS = Object.freeze([
  'method', 'originBinding', 'pathBinding', 'queryBinding', 'bodyBinding',
  'sourceBytesDigest', 'generatedIdBindings',
]);
const EXPECTED_STATE_MAPPING_KEYS = Object.freeze([
  'requestInstanceDigest', 'expectedResultState', 'expectedStateContractDigest',
]);
const PROVIDER_BOUND_ORDINALS = Object.freeze(new Set([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 14, 15, 16,
]));
const PROVIDER_VALUE_BATCHES = Object.freeze([
  Object.freeze({ mutationOrdinal: 0, resourceType: 'primary-project', rows: Object.freeze([
    ['rootManifestInitial', 'sourceBytesDigest', 'source-bytes-digest'],
    ['rootArtifact', 'rootArtifactId', 'artifact-id'],
    ['rootVersionInitial', 'rootContentHash', 'content-hash'],
    ['projectFacade', 'projectId', 'project-id'],
  ]) }),
  Object.freeze({ mutationOrdinal: 0, resourceType: 'primary-graph', rows: Object.freeze([
    ['entrypointArtifact', 'entrypointArtifactId', 'artifact-id'],
    ['entrypointVersionInitial', 'initialEntrypointVersionId', 'artifact-version-id'],
    ['entrypointVersionInitial', 'workflowContentHash', 'content-hash'],
  ]) }),
  Object.freeze({ mutationOrdinal: 1, resourceType: 'primary-graph', rows: Object.freeze([
    ['entrypointSourceInitial', 'sourceBytesDigest', 'source-bytes-digest'],
  ]) }),
  Object.freeze({ mutationOrdinal: 2, resourceType: 'primary-project', rows: Object.freeze([
    ['rootVersionInitial', 'initialRootVersionId', 'artifact-version-id'],
  ]) }),
  Object.freeze({ mutationOrdinal: 7, resourceType: 'primary-graph', rows: Object.freeze([
    ['entrypointSourceSaved', 'sourceBytesDigest', 'source-bytes-digest'],
    ['entrypointVersionSaved', 'workflowContentHash', 'content-hash'],
  ]) }),
  Object.freeze({ mutationOrdinal: 8, resourceType: 'primary-graph', rows: Object.freeze([
    ['entrypointVersionSaved', 'savedEntrypointVersionId', 'artifact-version-id'],
  ]) }),
  Object.freeze({ mutationOrdinal: 10, resourceType: 'primary-project', rows: Object.freeze([
    ['rootManifestSaved', 'sourceBytesDigest', 'source-bytes-digest'],
    ['rootVersionSaved', 'rootContentHash', 'content-hash'],
  ]) }),
  Object.freeze({ mutationOrdinal: 11, resourceType: 'primary-project', rows: Object.freeze([
    ['rootVersionSaved', 'savedRootVersionId', 'artifact-version-id'],
  ]) }),
  Object.freeze({ mutationOrdinal: 14, resourceType: 'primary-graph', rows: Object.freeze([
    ['visualModelSourceSaved', 'sourceBytesDigest', 'source-bytes-digest'],
    ['visualModelArtifact', 'visualArtifactId', 'artifact-id'],
    ['visualModelVersionSaved', 'visualContentHash', 'content-hash'],
  ]) }),
  Object.freeze({ mutationOrdinal: 15, resourceType: 'primary-graph', rows: Object.freeze([
    ['visualModelVersionSaved', 'visualVersionId', 'artifact-version-id'],
  ]) }),
]);
const SHARE_VALUE_ROWS = Object.freeze([
  ['canonicalTargetEmail', 'canonical-email'],
  ['sharePermissionsDigest', 'permissions-digest'],
  ['sharedByUserId', 'fixture-user-id'],
  ['targetIdentityDigest', 'identity-digest'],
  ['targetUserId', 'fixture-user-id'],
  ['tupleDigest', 'share-tuple-digest'],
]);
const CLOCK_RECONCILIATION_ORDINALS = Object.freeze([4, 5, 8, 11, 16]);
const PROJECT_MUTATION_ORDINALS = Object.freeze(new Set([0, 2, 4, 6, 10, 11, 12, 13]));
const PROVIDER_V2_INTENT_KEYS = Object.freeze([
  'schemaVersion', 'intentId', 'runId', 'environmentDigest', 'resourceType',
  'resourceId', 'providerResourceIds', 'providerAggregateJson',
  'providerAggregateDigest', 'ownerMarker', 'dependencyOrder', 'lifecycleClass',
  'state', 'intentVersion', 'observationDigest', 'retentionExpiresAt',
  'createdAt', 'updatedAt',
]);
const PROVIDER_AGGREGATE_KEYS = Object.freeze([
  'aggregateBinding', 'aggregateBindingDigest', 'ownedMembers', 'phase',
  'referencedMembers', 'schemaVersion',
]);
const AGGREGATE_BINDING_KEYS = Object.freeze([
  'environmentDigest', 'intentId', 'operationKey', 'operationScenario',
  'ownerMarker', 'parameters', 'providerContractDigest', 'resourceId',
  'resourceType', 'runId', 'schemaVersion',
]);
const PROVIDER_MEMBER_KEYS = Object.freeze([
  'bindingState', 'logicalValueBindings', 'memberBinding', 'memberBindingDigest',
  'memberState', 'operationStates', 'providerId', 'providerIdentity', 'schemaVersion',
]);
const SESSION_LINEAGE_PUBLICATION_KEYS = Object.freeze([
  'context', 'intentSetDigest', 'leaseAcquiredAt', 'leaseTokenDigest',
  'leaseVersion', 'ledgerDigest', 'providerContractDigest',
  'providerContractQualification', 'providerControlStore',
  'runtimeQualification', 'sessionIntentQualification', 'state',
]);
const OPERATION_STATE_KEYS = Object.freeze([
  'baselineDigest', 'discoveryProofDigest', 'expectedResultState',
  'mutationOrdinal', 'requestInstanceDigest', 'resultStateDigest', 'state',
]);

function nominalToken(value) {
  try {
    return value !== null
      && typeof value === 'object'
      && Object.getPrototypeOf(value) === null
      && Object.isFrozen(value)
      && Object.getOwnPropertyNames(value).length === 0
      && Object.getOwnPropertySymbols(value).length === 0;
  } catch {
    return false;
  }
}

function makeToken() {
  return Object.freeze(Object.create(null));
}

function frozenExact(value, keys, prototype = null) {
  try {
    return exactDataObject(value, keys)
      && Object.getPrototypeOf(value) === prototype
      && Object.isFrozen(value);
  } catch {
    return false;
  }
}

function frozenDenseArray(value) {
  return Array.isArray(value)
    && Object.isFrozen(value)
    && value.every((entry, index) => Object.hasOwn(value, index));
}

function validRouteProjection(routeProjection, expectedPathClass = null) {
  if (!frozenExact(routeProjection, ROUTE_PROJECTION_KEYS)) return false;
  const {
    method, originBinding, pathBinding, queryBinding, bodyBinding,
    sourceBytesDigest, generatedIdBindings,
  } = routeProjection;
  const pathClasses = expectedPathClass === null
    ? ['row-create', 'row-update', 'file-create']
    : [expectedPathClass];
  return typeof method === 'string'
    && /^[A-Z]+$/u.test(method)
    && frozenExact(originBinding, ['originClass', 'originDigest'])
    && originBinding.originClass === 'appwrite-api'
    && DIGEST.test(originBinding.originDigest)
    && frozenExact(pathBinding, ['pathClass', 'pathDigest'])
    && pathClasses.includes(pathBinding.pathClass)
    && DIGEST.test(pathBinding.pathDigest)
    && frozenExact(queryBinding, ['queryClass', 'queryDigest'])
    && queryBinding.queryClass === 'absent'
    && DIGEST.test(queryBinding.queryDigest)
    && frozenExact(bodyBinding, [
      'semanticBodyDigest', 'boundValuesDigest', 'executionEnvelopeDigest',
    ])
    && DIGEST.test(bodyBinding.semanticBodyDigest)
    && DIGEST.test(bodyBinding.boundValuesDigest)
    && (bodyBinding.executionEnvelopeDigest === null
      || DIGEST.test(bodyBinding.executionEnvelopeDigest))
    && (sourceBytesDigest === null || DIGEST.test(sourceBytesDigest))
    && frozenDenseArray(generatedIdBindings)
    && generatedIdBindings.every((binding) => (
      frozenExact(binding, ['bindingName', 'valueDigest'])
      && typeof binding.bindingName === 'string'
      && binding.bindingName.length > 0
      && DIGEST.test(binding.valueDigest)
    ));
}

function validExpectedStateMapping(mapping) {
  return frozenExact(mapping, EXPECTED_STATE_MAPPING_KEYS)
    && DIGEST.test(mapping.requestInstanceDigest)
    && DIGEST.test(mapping.expectedStateContractDigest)
    && mapping.expectedResultState !== null
    && typeof mapping.expectedResultState === 'object'
    && Object.getPrototypeOf(mapping.expectedResultState) === null
    && Object.isFrozen(mapping.expectedResultState);
}

function replaceProviderTupleRecord(expected, successorFields) {
  if (providerTupleRecord !== expected) return null;
  const successor = Object.freeze({
    ...successorFields,
    version: expected.version + 1,
  });
  if (providerTupleRecord !== expected) return null;
  providerTupleRecord = successor;
  return providerTupleRecord === successor ? successor : null;
}

function blockProviderLifecycle() {
  const observed = providerTupleRecord;
  replaceProviderTupleRecord(observed, {
    state: 'BLOCKED',
    nextMutationOrdinal: observed.nextMutationOrdinal,
    providerBoundCount: observed.providerBoundCount,
    providerValuesBoundBatchCount: observed.providerValuesBoundBatchCount,
    providerOperationIssuedCount: observed.providerOperationIssuedCount,
    providerOperationReconciledCount: observed.providerOperationReconciledCount,
    providerCreateIssuedCount: observed.providerCreateIssuedCount,
    providerIdDiscoveredCount: observed.providerIdDiscoveredCount,
  });
  return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
}

function installedFor(runtimeQualification, context = installedProviderControlRecord.context) {
  return providerControlBootstrapState === 'REGISTERED'
    && installedProviderControlRecord.state === 'INSTALLED'
    && currentRuntimeQualification(runtimeQualification)
    && context === installedProviderControlRecord.context;
}

function authenticateInitialProviderPrefix(args) {
  try {

    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'context', 'providerContractQualification',
        'identityBindingsQualification', 'sessionIntentQualification', 'clock',
      ])
      || !installedFor(args.runtimeQualification, args.context)
      || args.providerContractQualification
        !== installedProviderControlRecord.providerContractQualification
      || !nominalToken(args.identityBindingsQualification)
      || !currentSessionLineage(args)
      || !nominalToken(args.clock)
    ) return false;
    let record = initialProviderPrefixRecords.get(args.clock);
    if (record === undefined) {
      const current = providerTupleRecord;
      if (
        current.state !== 'READY'
        || current.nextMutationOrdinal !== 8
        || current.providerBoundCount !== 8
        || current.providerValuesBoundBatchCount !== 5
        || current.providerOperationIssuedCount !== 8
        || current.providerOperationReconciledCount !== 8
      ) return false;
      record = Object.freeze({
        state: 'ACTIVE',
        runtimeQualification: args.runtimeQualification,
        context: args.context,
        providerContractQualification: args.providerContractQualification,
        identityBindingsQualification: args.identityBindingsQualification,
        sessionIntentQualification: args.sessionIntentQualification,
      });
      initialProviderPrefixRecords.set(args.clock, record);
      if (initialProviderPrefixRecords.get(args.clock) !== record) return false;
    }
    return record !== undefined
      && record.state === 'ACTIVE'
      && record.runtimeQualification === args.runtimeQualification
      && record.context === args.context
      && record.providerContractQualification === args.providerContractQualification
      && record.identityBindingsQualification === args.identityBindingsQualification
      && record.sessionIntentQualification === args.sessionIntentQualification;
  } catch {
    return false;
  }
}

function authenticateMutationReconciliation(args) {
  try {

    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'clock', 'mutationOrdinal', 'qualification',
      ])
      || !installedFor(args.runtimeQualification)
      || !nominalToken(args.clock)
      || !nominalToken(args.qualification)
      || !CLOCK_RECONCILIATION_ORDINALS.includes(args.mutationOrdinal)
    ) return false;
    let record = mutationReconciliationRecords.get(args.qualification);

    if (
      record !== undefined
      && record.clock === null
      && record.state === 'ACTIVE'
      && record.runtimeQualification === args.runtimeQualification
      && record.mutationOrdinal === args.mutationOrdinal
    ) {
      record = Object.freeze({ ...record, clock: args.clock });
      mutationReconciliationRecords.set(args.qualification, record);
    }
    return record !== undefined
      && record.state === 'ACTIVE'
      && record.runtimeQualification === args.runtimeQualification
      && record.clock === args.clock
      && record.mutationOrdinal === args.mutationOrdinal;
  } catch {
    return false;
  }
}

function terminallyBlockProviderControlInstall() {
  const observed = installedProviderControlRecord;
  if (
    observed.state === 'INSTALLED'
    && !publishSessionLineageWitness(
      observed.lineage,
      observed.sessionIntentQualification,
      'REVOKED',
    )
  ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
  installedProviderControlRecord = Object.freeze({
    state: 'BLOCKED',
    version: observed.version + 1,
  });
  return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
}

function replaceInstalledProviderControlRecord(expected, successorFields) {
  if (installedProviderControlRecord !== expected) return null;
  const successor = Object.freeze({
    ...successorFields,
    version: expected.version + 1,
  });
  if (installedProviderControlRecord !== expected) return null;
  installedProviderControlRecord = successor;
  return installedProviderControlRecord === successor ? successor : null;
}

function currentRuntimeQualification(runtimeQualification) {
  if (readTestCloudRuntimeLifecycle() !== 'ACTIVE') return false;
  const authenticationArgs = Object.freeze({
    runtimeQualification,
  });
  return authenticateTestCloudRuntimeActive(authenticationArgs) === true;
}

function deterministicResourceId(context, resourceType) {
  return `vr-${sha256Bytes(encoder.encode(
    `${context.environmentDigest}|${context.runId}|${resourceType}`,
  )).slice(7, 39)}`;
}

function deterministicIntentId(context, resourceType) {
  const resourceId = deterministicResourceId(context, resourceType);
  return sha256Bytes(encoder.encode(
    `${context.environmentDigest}|${context.runId}|${resourceType}|${resourceId}`,
  )).slice(7);
}

function deterministicFixtureIdentity(context, resourceType) {
  const resourceId = deterministicResourceId(context, resourceType);
  const operationKey = sha256Bytes(encoder.encode(
    `${context.runId}|sharing-permissions|${canonicalJson({})}`,
  ));
  const ownerMarker = `verification-owner.v1:${contentDigest({
    schemaVersion: 'verification-owner-marker.v1',
    environmentDigest: context.environmentDigest,
    operationKey,
    resourceId,
    resourceType,
    runId: context.runId,
  })}`;
  return { intentId: deterministicIntentId(context, resourceType), operationKey, ownerMarker, resourceId };
}

function plannedFixtureBinding(context, identity) {
  return {
    schemaVersion: 'verification-provider-aggregate-binding.v1',
    environmentDigest: context.environmentDigest,
    providerContractDigest: APPROVED_PROVIDER_CONTRACT_DIGEST,
    runId: context.runId,
    resourceType: identity.resourceType,
    resourceId: identity.resourceId,
    operationScenario: 'sharing-permissions',
    parameters: {},
    operationKey: identity.operationKey,
    ownerMarker: identity.ownerMarker,
    intentId: identity.intentId,
  };
}

function plannedFixtureMember(template, identity, aggregateBindingDigest) {
  const memberBinding = {
    schemaVersion: 'verification-provider-member-binding.v1',
    aggregateBindingDigest,
    ownerResourceType: identity.resourceType,
    ownerResourceId: identity.resourceId,
    slot: template.slot,
    ownerOrdinal: template.ownerOrdinal,
    memberTemplateDigest: template.memberTemplateDigest,
  };
  const memberState = identity.resourceType === 'primary-share'
    ? { schemaVersion: 'tablesdb-row-state.v1', dataDigest: null, permissionsDigest: null, presence: 'absent' }
    : template.providerKind === 'storage-file'
      ? { schemaVersion: 'storage-file-metadata-state.v1', metadataDigest: null, permissionsDigest: null, presence: 'unknown' }
      : { schemaVersion: 'tablesdb-row-state.v1', dataDigest: null, permissionsDigest: null, presence: 'unknown' };
  return {
    schemaVersion: 'verification-provider-member.v1',
    memberBinding,
    memberBindingDigest: contentDigest(memberBinding),
    providerId: null,
    providerIdentity: null,
    bindingState: identity.resourceType === 'primary-share' ? 'unissued' : 'unbound',
    logicalValueBindings: template.logicalValueBindingContracts.map((contract) => ({
      name: contract.name,
      valueKind: contract.valueKind,
      sourceMutationOrdinal: contract.sourceMutationOrdinal,
      state: 'unbound',
      value: null,
      valueDigest: null,
    })),
    operationStates: template.operations.map((operation) => ({
      mutationOrdinal: operation.mutationOrdinal,
      state: 'pending',
      requestInstanceDigest: null,
      expectedResultState: null,
      resultStateDigest: null,
      baselineDigest: null,
      discoveryProofDigest: null,
    })),
    memberState,
  };
}

function plannedFixtureReference(context, reference) {
  const owner = {
    ...deterministicFixtureIdentity(context, reference.ownerResourceType),
    resourceType: reference.ownerResourceType,
  };
  const ownerBinding = plannedFixtureBinding(context, owner);
  const ownerResource = providerContract.aggregateContracts.resources.find((resource) => (
    resource.resourceType === reference.ownerResourceType
  ));
  const template = ownerResource.memberTemplates[reference.ownerOrdinal];
  const memberBinding = {
    schemaVersion: 'verification-provider-member-binding.v1',
    aggregateBindingDigest: contentDigest(ownerBinding),
    ownerResourceType: reference.ownerResourceType,
    ownerResourceId: owner.resourceId,
    slot: reference.ownerSlot,
    ownerOrdinal: reference.ownerOrdinal,
    memberTemplateDigest: template.memberTemplateDigest,
  };
  return {
    schemaVersion: 'verification-provider-member-reference.v1',
    memberBinding,
    memberBindingDigest: contentDigest(memberBinding),
  };
}

function plannedFixtureAggregate(context, resourceType) {
  const identity = {
    ...deterministicFixtureIdentity(context, resourceType),
    resourceType,
  };
  const resource = providerContract.aggregateContracts.resources.find((candidate) => (
    candidate.resourceType === resourceType
  ));
  const aggregateBinding = plannedFixtureBinding(context, identity);
  const aggregateBindingDigest = contentDigest(aggregateBinding);
  return {
    schemaVersion: 'verification-provider-aggregate.v1',
    phase: 'owner-baseline',
    aggregateBinding,
    aggregateBindingDigest,
    ownedMembers: resource.memberTemplates.map((template) => (
      plannedFixtureMember(template, identity, aggregateBindingDigest)
    )),
    referencedMembers: resource.referencedSlots.map((reference) => (
      plannedFixtureReference(context, reference)
    )),
  };
}

function exactPlannedFixtureIntent(intent, context, resourceType) {
  try {
    const identity = deterministicFixtureIdentity(context, resourceType);
    const aggregate = JSON.parse(intent.providerAggregateJson);
    const resource = providerContract.aggregateContracts.resources.find((candidate) => (
      candidate.resourceType === resourceType
    ));
    const expectedAggregate = plannedFixtureAggregate(context, resourceType);
    return exactDataObject(intent, CLEANUP_V2_INTENT_KEYS)
      && intent.schemaVersion === 'verification-intent-snapshot.v2'
      && intent.intentId === identity.intentId
      && intent.runId === context.runId
      && intent.environmentDigest === context.environmentDigest
      && intent.resourceType === resourceType
      && intent.resourceId === identity.resourceId
      && intent.ownerMarker === identity.ownerMarker
      && intent.dependencyOrder === resource.dependencyOrder
      && intent.lifecycleClass === 'fixture'
      && intent.state === 'planned'
      && intent.intentVersion === 1
      && intent.observationDigest === null
      && intent.retentionExpiresAt === null
      && RECOVERY_V2_CLEANUP_KEYS.every((key) => intent[key] === null)
      && typeof intent.providerAggregateJson === 'string'
      && contentDigest(aggregate) === intent.providerAggregateDigest
      && exactDataObject(aggregate, [
        'aggregateBinding', 'aggregateBindingDigest', 'ownedMembers', 'phase',
        'referencedMembers', 'schemaVersion',
      ])
      && aggregate.schemaVersion === 'verification-provider-aggregate.v1'
      && aggregate.phase === 'owner-baseline'
      && same(aggregate, expectedAggregate);
  } catch {
    return false;
  }
}

function reconstructProviderPrefix(intents) {
  const aggregates = new Map();
  const operations = new Map();
  for (const intent of intents) {
    if (
      !exactDataObject(intent, CLEANUP_V2_INTENT_KEYS)
      || !['planned', 'created'].includes(intent.state)
    ) return null;
    let aggregate;
    try {
      aggregate = JSON.parse(intent.providerAggregateJson);
    } catch {
      return null;
    }
    if (
      canonicalJson(aggregate) !== intent.providerAggregateJson
      || contentDigest(aggregate) !== intent.providerAggregateDigest
      || aggregate.aggregateBinding.intentId !== intent.intentId
      || aggregate.aggregateBinding.resourceType !== intent.resourceType
    ) return null;
    aggregates.set(intent.resourceType, aggregate);
    for (const member of aggregate.ownedMembers) {
      for (const operation of member.operationStates) {
        if (operations.has(operation.mutationOrdinal)) return null;
        operations.set(operation.mutationOrdinal, { member, operation });
      }
    }
  }
  if (operations.size !== 19) return null;
  let nextMutationOrdinal = 0;
  while (
    nextMutationOrdinal < 19
    && operations.get(nextMutationOrdinal)?.operation.state === 'reconciled'
  ) nextMutationOrdinal += 1;
  for (let ordinal = 0; ordinal < 19; ordinal += 1) {
    const state = operations.get(ordinal)?.operation.state;
    if (state !== (ordinal < nextMutationOrdinal ? 'reconciled' : 'pending')) return null;
  }
  let providerBoundCount = 0;
  let providerValuesBoundBatchCount = 0;
  for (const resource of providerContract.aggregateContracts.resources) {
    const aggregate = aggregates.get(resource.resourceType);
    if (aggregate === undefined) return null;
    for (const template of resource.memberTemplates) {
      const matches = aggregate.ownedMembers.filter((member) => (
        member.memberBinding.slot === template.slot
        && member.memberBinding.ownerOrdinal === template.ownerOrdinal
      ));
      if (matches.length !== 1) return null;
      const member = matches[0];
      if (template.firstBindOrdinal !== null) {
        const shouldBeBound = template.firstBindOrdinal < nextMutationOrdinal;
        if ((member.bindingState === 'bound') !== shouldBeBound) return null;
        if (shouldBeBound) {
          const compositeIdentity = `${template.bindingName}|${member.providerId}`;
          if (boundCompositeProviderIds.has(compositeIdentity)) return null;
          providerBoundCount += 1;
          boundProviderIds.set(template.firstBindOrdinal, member.providerId);
          boundCompositeProviderIds.add(compositeIdentity);
        }
      } else if (template.issueOrdinal !== null) {
        const expectedState = template.issueOrdinal < nextMutationOrdinal
          ? 'bound'
          : 'unissued';
        if (member.bindingState !== expectedState) return null;
        if (expectedState === 'bound') shareProviderIds.add(member.providerId);
      }
    }
  }
  for (const batch of PROVIDER_VALUE_BATCHES) {
    const aggregate = aggregates.get(batch.resourceType);
    const allBound = batch.rows.every(([ownerSlot, name]) => (
      aggregate.ownedMembers.find((member) => member.memberBinding.slot === ownerSlot)
        ?.logicalValueBindings.find((binding) => binding.name === name)?.state === 'bound'
    ));
    if (allBound !== (batch.mutationOrdinal < nextMutationOrdinal)) return null;
    if (allBound) providerValuesBoundBatchCount += 1;
  }
  for (const [ownerSlot, mutationOrdinal] of [
    ['editorShare', 17], ['viewerShare', 18],
  ]) {
    const member = aggregates.get('primary-share').ownedMembers.find((candidate) => (
      candidate.memberBinding.slot === ownerSlot
    ));
    const allBound = member.logicalValueBindings.every((binding) => binding.state === 'bound');
    if (allBound !== (mutationOrdinal < nextMutationOrdinal)) return null;
    if (allBound) providerValuesBoundBatchCount += 1;
  }
  if (
    providerBoundCount !== [...PROVIDER_BOUND_ORDINALS]
      .filter((ordinal) => ordinal < nextMutationOrdinal).length
    || providerValuesBoundBatchCount !== (
      PROVIDER_VALUE_BATCHES.filter((batch) => batch.mutationOrdinal < nextMutationOrdinal).length
      + [17, 18].filter((ordinal) => ordinal < nextMutationOrdinal).length
    )
  ) return null;
  const projectAggregate = aggregates.get('primary-project');
  const graphAggregate = aggregates.get('primary-graph');
  const shareAggregate = aggregates.get('primary-share');
  if (
    (nextMutationOrdinal >= 17) !== (
      projectAggregate.phase === 'normal-owner' && graphAggregate.phase === 'normal-owner'
    )
    || (nextMutationOrdinal >= 17) !== (
      intents.filter((intent) => ['primary-project', 'primary-graph'].includes(intent.resourceType))
        .every((intent) => intent.state === 'created')
    )
    || (nextMutationOrdinal === 19) !== (
      shareAggregate.phase === 'shared'
      && intents.find((intent) => intent.resourceType === 'primary-share').state === 'created'
    )
  ) return null;
  const projectId = boundProviderIds.get(6);
  return Object.freeze({
    state: nextMutationOrdinal === 19
      ? 'PROVIDER_COMPLETE'
      : nextMutationOrdinal >= 17 ? 'GENERIC_COMPLETE' : 'READY',
    version: providerTupleRecord.version + 1,
    nextMutationOrdinal,
    providerBoundCount,
    providerValuesBoundBatchCount,
    providerOperationIssuedCount: Math.min(nextMutationOrdinal, 17),
    providerOperationReconciledCount: Math.min(nextMutationOrdinal, 17),
    providerCreateIssuedCount: Math.max(0, nextMutationOrdinal - 17),
    providerIdDiscoveredCount: Math.max(0, nextMutationOrdinal - 17),
    ...(typeof projectId === 'string'
      ? { projectIdentityDigest: sha256Bytes(encoder.encode(projectId)) }
      : {}),
  });
}

async function readExactProviderFixtureIntents(store, context) {
  const resources = ['primary-project', 'primary-graph', 'primary-share'];
  const intents = [];
  for (const resourceType of resources) {
    const intent = await store.getIntentProjection(deterministicIntentId(context, resourceType));
    if (
      !exactDataObject(intent, CLEANUP_V2_INTENT_KEYS)
      || intent.intentId !== deterministicIntentId(context, resourceType)
      || intent.resourceId !== deterministicResourceId(context, resourceType)
      || intent.resourceType !== resourceType
      || intent.runId !== context.runId
      || intent.environmentDigest !== context.environmentDigest
    ) return null;
    intents.push(intent);
  }
  const prefix = reconstructProviderPrefix(intents);
  return prefix === null ? null : { intents, prefix };
}

function orderedLineageIntentSet(intents) {
  return Object.freeze(intents.map((intent) => Object.freeze({
    intentId: intent.intentId,
    projectionDigest: contentDigest(intent),
    resourceType: intent.resourceType,
  })));
}

async function readExactLineageIntentSet(store, context, expectedSet) {
  const resources = ['primary-project', 'primary-graph', 'primary-share'];
  if (!Array.isArray(expectedSet) || expectedSet.length !== resources.length) return null;
  const intents = [];
  for (let index = 0; index < resources.length; index += 1) {
    const resourceType = resources[index];
    const expected = expectedSet[index];
    const intent = await store.getIntentProjection(deterministicIntentId(context, resourceType));
    if (
      !exactDataObject(intent, CLEANUP_V2_INTENT_KEYS)
      || expected === null
      || typeof expected !== 'object'
      || expected.intentId !== intent.intentId
      || expected.resourceType !== resourceType
      || expected.projectionDigest !== contentDigest(intent)
    ) return null;
    intents.push(intent);
  }
  return intents;
}

function currentSessionLineage(args) {
  const lineage = sessionIntentQualificationRecords.get(args.sessionIntentQualification);
  return lineage !== undefined
    && lineage.state === 'ACTIVE'
    && currentRuntimeQualification(args.runtimeQualification)
    && lineage.runtimeQualification === args.runtimeQualification
    && lineage.context === args.context
    && lineage.store === installedProviderControlRecord.store
    && lineage.providerContractQualification === installedProviderControlRecord.providerContractQualification
    && lineage.providerContractDigest === APPROVED_PROVIDER_CONTRACT_DIGEST
    && installedProviderControlRecord.sessionIntentQualification === args.sessionIntentQualification;
}

async function activeSessionLineage(args) {
  try {
    if (!currentSessionLineage(args)) {
      revokeSessionLineageWitness(args.sessionIntentQualification);
      return false;
    }
    const lineage = sessionIntentQualificationRecords.get(args.sessionIntentQualification);
    const lease = await lineage.store.getLease();
    const intents = await readExactLineageIntentSet(
      lineage.store,
      args.context,
      lineage.intentSet,
    );
    const active = lease !== null
      && lease.state === 'active'
      && lease.ownerRunId === args.context.runId
      && lease.environmentDigest === args.context.environmentDigest
      && lease.acquiredAt === lineage.leaseAcquiredAt
      && lease.leaseTokenDigest === lineage.leaseTokenDigest
      && lease.leaseVersion === lineage.leaseVersion
      && lease.ledgerDigest === lineage.ledgerDigest
      && intents !== null
      && contentDigest(orderedLineageIntentSet(intents)) === lineage.intentSetDigest;
    if (!active) revokeSessionLineageWitness(args.sessionIntentQualification);
    return active;
  } catch {
    revokeSessionLineageWitness(args.sessionIntentQualification);
    return false;
  }
}

async function installProviderControlStore(args) {
  try {

    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || providerControlBootstrapState !== 'REGISTERED'
      || !exactDataObject(args, [
        'context',
        'providerContractQualification',
        'providerControlStore',
        'runtimeQualification',
      ])
      || !currentRuntimeQualification(args.runtimeQualification)
      || !isAuthenticTestEnvironmentContext(args.context)
      || args.providerContractQualification === null
      || typeof args.providerContractQualification !== 'object'
    ) {

      return terminallyBlockProviderControlInstall();
    }
    const authentic = providerControlStoreRecords.get(args.providerControlStore);
    if (
      authentic === undefined
      || authentic.context !== args.context
      || STORE_KEYS.some((key, index) => (
        args.providerControlStore[key] !== authentic.methods[index]
      ))
    ) {

      return terminallyBlockProviderControlInstall();
    }

    const lease = await args.providerControlStore.getLease();
    if (
      lease === null
      || lease.state !== 'active'
      || lease.ownerRunId !== args.context.runId
      || lease.environmentDigest !== args.context.environmentDigest
    ) {

      return terminallyBlockProviderControlInstall();
    }
    if (installedProviderControlRecord.state === 'INSTALLED') {
      const existing = installedProviderControlRecord;
      const intents = await readExactLineageIntentSet(
        args.providerControlStore,
        args.context,
        existing.lineage.intentSet,
      );
      if (
        existing.store !== args.providerControlStore
        || existing.context !== args.context
        || existing.providerContractQualification !== args.providerContractQualification
        || existing.lineage.runtimeQualification !== args.runtimeQualification
        || existing.lineage.providerContractDigest !== APPROVED_PROVIDER_CONTRACT_DIGEST
        || lease.acquiredAt !== existing.lineage.leaseAcquiredAt
        || lease.leaseTokenDigest !== existing.lineage.leaseTokenDigest
        || lease.leaseVersion !== existing.lineage.leaseVersion
        || lease.ledgerDigest !== existing.lineage.ledgerDigest
        || intents === null
        || contentDigest(orderedLineageIntentSet(intents)) !== existing.lineage.intentSetDigest
      ) {
        await commitCleanupDebtWithoutLineage(args.providerControlStore, args.context);
        return terminallyBlockProviderControlInstall();
      }
      if (!publishSessionLineageWitness(
        existing.lineage,
        existing.sessionIntentQualification,
        'ACTIVE',
      )) return terminallyBlockProviderControlInstall();
      return privatePass(closedRecord({
        installed: true,
        sessionIntentQualification: existing.sessionIntentQualification,
      }));
    }
    if (installedProviderControlRecord.state !== 'UNINSTALLED') {
      return terminallyBlockProviderControlInstall();
    }
    const providerState = await readExactProviderFixtureIntents(
      args.providerControlStore,
      args.context,
    );
    if (providerState === null) {

      await commitCleanupDebtWithoutLineage(args.providerControlStore, args.context);
      return terminallyBlockProviderControlInstall();
    }
    const { intents, prefix } = providerState;

    providerTupleRecord = prefix;
    const sessionIntentQualification = Object.freeze(Object.create(null));
    const intentSet = orderedLineageIntentSet(intents);
    const lineage = Object.freeze({
      state: 'ACTIVE',
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      providerContractQualification: args.providerContractQualification,
      providerContractDigest: APPROVED_PROVIDER_CONTRACT_DIGEST,
      store: args.providerControlStore,
      leaseAcquiredAt: lease.acquiredAt,
      leaseTokenDigest: lease.leaseTokenDigest,
      leaseVersion: lease.leaseVersion,
      ledgerDigest: lease.ledgerDigest,
      intentSet,
      intentSetDigest: contentDigest(intentSet),
    });
    sessionIntentQualificationRecords.set(sessionIntentQualification, lineage);
    if (sessionIntentQualificationRecords.get(sessionIntentQualification) !== lineage) {
      return terminallyBlockProviderControlInstall();
    }
    const installing = replaceInstalledProviderControlRecord(
      installedProviderControlRecord,
      {
      state: 'INSTALLING',
      store: args.providerControlStore,
      context: args.context,
      providerContractQualification: args.providerContractQualification,
      sessionIntentQualification,
      lineage,
      },
    );
    if (installing === null) return terminallyBlockProviderControlInstall();
    const installed = replaceInstalledProviderControlRecord(installing, {
      state: 'INSTALLED',
      store: installing.store,
      context: installing.context,
      providerContractQualification: installing.providerContractQualification,
      sessionIntentQualification: installing.sessionIntentQualification,
      lineage: installing.lineage,
    });
    if (installed === null) return terminallyBlockProviderControlInstall();
    if (!publishSessionLineageWitness(
      installed.lineage,
      installed.sessionIntentQualification,
      'ACTIVE',
    )) {

      return terminallyBlockProviderControlInstall();
    }

    return privatePass(closedRecord({ installed: true, sessionIntentQualification }));
  } catch {

    return terminallyBlockProviderControlInstall();
  }
}

function replaceWeakRecord(registry, token, expected, successorFields) {
  if (registry.get(token) !== expected) return null;
  const successor = Object.freeze({
    ...successorFields,
    version: expected.version + 1,
  });
  if (registry.get(token) !== expected) return null;
  registry.set(token, successor);
  return registry.get(token) === successor ? successor : null;
}

function successorLineageIntentSet(lineage, operation) {
  if (!Object.hasOwn(operation, 'nextIntent')) return lineage.intentSet;
  const targetDigest = contentDigest(operation.nextIntent);
  let replacements = 0;
  const successor = lineage.intentSet.map((entry) => {
    if (entry.intentId !== operation.nextIntent.intentId) return entry;
    replacements += 1;
    return Object.freeze({
      intentId: entry.intentId,
      projectionDigest: targetDigest,
      resourceType: entry.resourceType,
    });
  });
  return replacements === 1 ? Object.freeze(successor) : null;
}

async function advanceSessionLineageAfterSuccess(args, operation) {
  const prior = sessionIntentQualificationRecords.get(args.sessionIntentQualification);
  if (
    prior === undefined
    || !currentSessionLineage(args)
    || installedProviderControlRecord.lineage !== prior
  ) return false;
  const intentSet = successorLineageIntentSet(prior, operation);
  if (intentSet === null) return false;
  const lease = await prior.store.getLease();
  const intents = await readExactLineageIntentSet(prior.store, args.context, intentSet);
  if (
    lease === null
    || !same(lease, operation.nextLease)
    || intents === null
    || contentDigest(orderedLineageIntentSet(intents)) !== contentDigest(intentSet)
  ) return false;
  const successor = Object.freeze({
    ...prior,
    leaseVersion: lease.leaseVersion,
    ledgerDigest: lease.ledgerDigest,
    intentSet,
    intentSetDigest: contentDigest(intentSet),
  });
  sessionIntentQualificationRecords.set(args.sessionIntentQualification, successor);
  if (sessionIntentQualificationRecords.get(args.sessionIntentQualification) !== successor) {
    return false;
  }
  const installed = replaceInstalledProviderControlRecord(installedProviderControlRecord, {
    state: 'INSTALLED',
    store: installedProviderControlRecord.store,
    context: installedProviderControlRecord.context,
    providerContractQualification: installedProviderControlRecord.providerContractQualification,
    sessionIntentQualification: installedProviderControlRecord.sessionIntentQualification,
    lineage: successor,
  });
  return installed !== null
    && publishSessionLineageWitness(successor, args.sessionIntentQualification, 'ACTIVE');
}

function closedRecord(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function publishSessionLineageWitness(lineage, sessionIntentQualification, state) {
  if (
    providerControlHubDispatchers === undefined
    || typeof providerControlHubDispatchers.authenticateSessionLineage !== 'function'
  ) return false;
  try {
    return reflectApply(
      providerControlHubDispatchers.authenticateSessionLineage,
      providerControlHubDispatchers.receiver,
      [closedRecord({
        context: lineage.context,
        intentSetDigest: lineage.intentSetDigest,
        leaseAcquiredAt: lineage.leaseAcquiredAt,
        leaseTokenDigest: lineage.leaseTokenDigest,
        leaseVersion: lineage.leaseVersion,
        ledgerDigest: lineage.ledgerDigest,
        providerContractDigest: lineage.providerContractDigest,
        providerContractQualification: lineage.providerContractQualification,
        providerControlStore: lineage.store,
        runtimeQualification: lineage.runtimeQualification,
        sessionIntentQualification,
        state,
      })],
    ) === true;
  } catch {
    return false;
  }
}

function revokeSessionLineageWitness(sessionIntentQualification) {
  const lineage = sessionIntentQualificationRecords.get(sessionIntentQualification);
  return lineage === undefined
    ? true
    : publishSessionLineageWitness(lineage, sessionIntentQualification, 'REVOKED');
}

function shareOwnerPair(ownerSlot) {
  if (ownerSlot === 'editorShare') {
    return Object.freeze({
      mutationOrdinal: 17, batchBefore: 10, targetRole: 'editor', canRun: true,
    });
  }
  if (ownerSlot === 'viewerShare') {
    return Object.freeze({
      mutationOrdinal: 18, batchBefore: 11, targetRole: 'viewer', canRun: false,
    });
  }
  return null;
}

function validExpectedShareIdentity(value, pair, bindingValues) {
  return frozenExact(value, [
    'userId', 'userEmail', 'userName', 'role', 'canRun',
    'sharedBy', 'permissions',
  ])
    && [value.userId, value.userEmail, value.userName, value.role, value.sharedBy]
      .every((item) => typeof item === 'string' && item.length > 0)
    && typeof value.canRun === 'boolean'
    && frozenDenseArray(value.permissions)
    && value.permissions.every((permission) => typeof permission === 'string')
    && value.userEmail === bindingValues[0]
    && contentDigest(value.permissions) === bindingValues[1]
    && value.sharedBy === bindingValues[2]
    && value.userId === bindingValues[4]
    && value.role === pair.targetRole
    && value.canRun === pair.canRun;
}

async function prepareShareValuesTransition(args) {
  try {

    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'context', 'identityBindingsQualification',
        'shareBindingQualification', 'ownerSlot', 'mutationOrdinal',
      ])
      || !installedFor(args.runtimeQualification, args.context)
      || !nominalToken(args.identityBindingsQualification)
      || !nominalToken(args.shareBindingQualification)
      || providerControlHubDispatchers === undefined
    ) {
      blockProviderLifecycle();
      return false;
    }
    const pair = shareOwnerPair(args.ownerSlot);
    const current = providerTupleRecord;

    if (
      pair === null
      || args.mutationOrdinal !== pair.mutationOrdinal
      || current.state !== 'GENERIC_COMPLETE'
      || current.nextMutationOrdinal !== pair.mutationOrdinal
      || current.providerOperationIssuedCount !== 17
      || current.providerOperationReconciledCount !== 17
      || current.providerBoundCount !== 14
      || current.providerValuesBoundBatchCount !== pair.batchBefore
      || !DIGEST.test(current.projectIdentityDigest)
    ) {
      blockProviderLifecycle();
      return false;
    }
    const tupleReserving = replaceProviderTupleRecord(current, {
      ...current,
      state: 'SHARE_RESERVING',
    });
    if (tupleReserving === null) {
      blockProviderLifecycle();
      return false;
    }
    const preparation = makeToken();
    const reserving = Object.freeze({
      state: 'RESERVING',
      version: 1,
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      identityBindingsQualification: args.identityBindingsQualification,
      shareBindingQualification: args.shareBindingQualification,
      ownerSlot: args.ownerSlot,
      mutationOrdinal: args.mutationOrdinal,
      projectIdentityDigest: current.projectIdentityDigest,
      tupleRecord: tupleReserving,
    });
    sharePreparationRecords.set(preparation, reserving);
    if (sharePreparationRecords.get(preparation) !== reserving) {
      blockProviderLifecycle();
      return false;
    }
    const digestResult = reflectApply(
      providerControlHubDispatchers.readAuthenticatedShareBindingDigests,
      providerControlHubDispatchers.receiver,
      [closedRecord({
        runtimeQualification: args.runtimeQualification,
        shareBindingQualification: args.shareBindingQualification,
        expectedProjectIdentityDigest: current.projectIdentityDigest,
        ownerSlot: args.ownerSlot,
        mutationOrdinal: args.mutationOrdinal,
      })],
    );
    if (
      providerTupleRecord !== tupleReserving
      || sharePreparationRecords.get(preparation) !== reserving
      || !frozenExact(digestResult, ['targetIdentityDigest', 'tupleDigest'])
      || !DIGEST.test(digestResult.targetIdentityDigest)
      || !DIGEST.test(digestResult.tupleDigest)
    ) {
      replaceWeakRecord(sharePreparationRecords, preparation, reserving, {
        state: 'ABORTED',
        runtimeQualification: args.runtimeQualification,
      });
      blockProviderLifecycle();
      return false;
    }
    const tupleReserved = replaceProviderTupleRecord(tupleReserving, {
      ...tupleReserving,
      state: 'SHARE_RESERVED',
    });
    const reserved = replaceWeakRecord(sharePreparationRecords, preparation, reserving, {
      ...reserving,
      state: 'RESERVED',
      targetIdentityDigest: digestResult.targetIdentityDigest,
      tupleDigest: digestResult.tupleDigest,
      tupleRecord: tupleReserved,
    });
    if (tupleReserved === null || reserved === null) {
      blockProviderLifecycle();
      return false;
    }
    const tuplePrepared = replaceProviderTupleRecord(tupleReserved, {
      ...tupleReserved,
      state: 'SHARE_PREPARED',
    });
    const prepared = replaceWeakRecord(sharePreparationRecords, preparation, reserved, {
      ...reserved,
      state: 'PREPARED',
      tupleRecord: tuplePrepared,
    });
    if (tuplePrepared === null || prepared === null) {
      blockProviderLifecycle();
      return false;
    }
    return closedRecord({
      preparation,
      projectIdentityDigest: prepared.projectIdentityDigest,
      targetIdentityDigest: prepared.targetIdentityDigest,
      tupleDigest: prepared.tupleDigest,
    });
  } catch {
    blockProviderLifecycle();
    return false;
  }
}

function abortShareValuesTransition(args) {
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, ['runtimeQualification', 'preparation'])
      || !installedFor(args.runtimeQualification)
      || !nominalToken(args.preparation)
    ) {
      blockProviderLifecycle();
      return false;
    }
    const current = sharePreparationRecords.get(args.preparation);
    if (
      current === undefined
      || current.state !== 'PREPARED'
      || current.runtimeQualification !== args.runtimeQualification
      || providerTupleRecord !== current.tupleRecord
      || providerTupleRecord.state !== 'SHARE_PREPARED'
    ) {
      blockProviderLifecycle();
      return false;
    }
    const aborted = replaceWeakRecord(
      sharePreparationRecords,
      args.preparation,
      current,
      { state: 'ABORTED', runtimeQualification: current.runtimeQualification },
    );
    const tupleAborted = replaceProviderTupleRecord(current.tupleRecord, {
      ...current.tupleRecord,
      state: 'BLOCKED',
    });
    if (aborted === null || tupleAborted === null) {
      blockProviderLifecycle();
      return false;
    }
    return true;
  } catch {
    blockProviderLifecycle();
    return false;
  }
}

async function commitShareValuesTransition(args) {
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'preparation', 'bindingNames', 'boundValues',
        'expectedShareIdentity',
      ])
      || !installedFor(args.runtimeQualification)
      || !nominalToken(args.preparation)
      || !frozenDenseArray(args.bindingNames)
      || !frozenDenseArray(args.boundValues)
      || args.bindingNames.length !== 6
      || args.boundValues.length !== 6
      || !same(args.bindingNames, [
        'canonicalTargetEmail', 'sharePermissionsDigest', 'sharedByUserId',
        'targetIdentityDigest', 'targetUserId', 'tupleDigest',
      ])
      || args.boundValues.some((value) => typeof value !== 'string')
    ) {
      blockProviderLifecycle();
      return false;
    }
    const current = sharePreparationRecords.get(args.preparation);
    const tuple = providerTupleRecord;
    const pair = current === undefined ? null : shareOwnerPair(current.ownerSlot);
    if (
      current === undefined
      || current.state !== 'PREPARED'
      || current.runtimeQualification !== args.runtimeQualification
      || current.tupleRecord !== tuple
      || pair === null
      || tuple.state !== 'SHARE_PREPARED'
      || tuple.nextMutationOrdinal !== current.mutationOrdinal
      || tuple.providerValuesBoundBatchCount !== pair.batchBefore
      || !validExpectedShareIdentity(args.expectedShareIdentity, pair, args.boundValues)
    ) {
      blockProviderLifecycle();
      return false;
    }
    const committing = replaceWeakRecord(
      sharePreparationRecords,
      args.preparation,
      current,
      {
        ...current,
        state: 'COMMITTING',
        boundValuesDigest: contentDigest(args.bindingNames.map((name, index) => ({
          name,
          valueDigest: sha256Bytes(encoder.encode(args.boundValues[index])),
        }))),
        expectedShareIdentity: args.expectedShareIdentity,
      },
    );
    const tupleCommitting = replaceProviderTupleRecord(tuple, {
      ...tuple,
      state: 'SHARE_COMMITTING',
    });
    if (committing === null || tupleCommitting === null) {
      blockProviderLifecycle();
      return false;
    }
    const store = installedProviderControlRecord.store;
    const shareIntentId = deterministicIntentId(current.context, 'primary-share');
    const prior = await store.getIntentProjection(shareIntentId);
    const lease = await store.getLease();
    if (
      providerTupleRecord !== tupleCommitting
      || sharePreparationRecords.get(args.preparation) !== committing
    ) {
      blockProviderLifecycle();
      return false;
    }
    const batch = Object.freeze({
      mutationOrdinal: current.mutationOrdinal,
      resourceType: 'primary-share',
      rows: Object.freeze(SHARE_VALUE_ROWS.map(([name, valueKind]) => (
        [current.ownerSlot, name, valueKind]
      ))),
    });
    const bindings = Object.freeze(SHARE_VALUE_ROWS.map(([name, valueKind], index) => (
      closedRecord({
        ownerSlot: current.ownerSlot,
        name,
        valueKind,
        value: args.boundValues[index],
        valueDigest: sha256Bytes(encoder.encode(args.boundValues[index])),
      })
    )));
    const operation = providerValuesBoundIntentOperation(
      prior,
      lease,
      { context: current.context },
      batch,
      bindings,
    );
    const committedValue = await store.transact(operation);
    const lineageArgs = {
      runtimeQualification: args.runtimeQualification,
      context: current.context,
      sessionIntentQualification:
        installedProviderControlRecord.sessionIntentQualification,
    };
    if (
      providerTupleRecord !== tupleCommitting
      || sharePreparationRecords.get(args.preparation) !== committing
      || committedValue.status !== 'PASS'
      || !same(committedValue.value, operation.nextLease)
      || !await advanceSessionLineageAfterSuccess(lineageArgs, operation)
      || !same(await store.getIntentProjection(shareIntentId), operation.nextIntent)
      || !same(await store.getLease(), operation.nextLease)
    ) {
      blockProviderLifecycle();
      return false;
    }
    const tupleCommitted = replaceProviderTupleRecord(tupleCommitting, {
      ...tupleCommitting,
      state: 'GENERIC_COMPLETE',
      providerValuesBoundBatchCount: tuple.providerValuesBoundBatchCount + 1,
    });
    const committed = replaceWeakRecord(
      sharePreparationRecords,
      args.preparation,
      committing,
      { ...committing, state: 'COMMITTED', tupleRecord: tupleCommitted },
    );
    if (tupleCommitted === null || committed === null) {
      blockProviderLifecycle();
      return false;
    }
    const commitReceipt = makeToken();
    const receipt = Object.freeze({
      state: 'ACTIVE',
      version: 1,
      runtimeQualification: args.runtimeQualification,
      preparation: args.preparation,
      ownerSlot: committed.ownerSlot,
      boundValuesDigest: committed.boundValuesDigest,
    });
    shareCommitReceiptRecords.set(commitReceipt, receipt);
    if (shareCommitReceiptRecords.get(commitReceipt) !== receipt) {
      blockProviderLifecycle();
      return false;
    }
    return closedRecord({ commitReceipt });
  } catch {
    blockProviderLifecycle();
    return false;
  }
}
function finalizeShareValuesTransition(args) {
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'preparation', 'commitReceipt', 'handoff',
      ])
      || !installedFor(args.runtimeQualification)
      || !nominalToken(args.preparation)
      || !nominalToken(args.commitReceipt)
      || !nominalToken(args.handoff)
      || providerControlHubDispatchers === undefined
    ) return false;
    const preparation = sharePreparationRecords.get(args.preparation);
    const receipt = shareCommitReceiptRecords.get(args.commitReceipt);
    if (
      preparation === undefined
      || preparation.state !== 'COMMITTED'
      || preparation.runtimeQualification !== args.runtimeQualification
      || receipt === undefined
      || receipt.state !== 'ACTIVE'
      || receipt.preparation !== args.preparation
    ) return false;
    const pending = replaceWeakRecord(
      sharePreparationRecords,
      args.preparation,
      preparation,
      { ...preparation, state: 'PENDING_IDENTITY_FINAL_STATE' },
    );
    if (pending === null) return false;
    const finalIdentity = reflectApply(
      providerControlHubDispatchers.authenticateShareIdentityFinalState,
      providerControlHubDispatchers.receiver,
      [closedRecord({
        runtimeQualification: args.runtimeQualification,
        handoff: args.handoff,
        commitReceipt: args.commitReceipt,
        ownerSlot: pending.ownerSlot,
      })],
    );
    if (!nominalToken(finalIdentity)) return false;
    const projectProviderId = boundProviderIds.get(6);
    if (typeof projectProviderId !== 'string' || projectProviderId.length === 0) return false;
    const providerQualification = finalIdentity;
    const qualification = Object.freeze({
      state: 'ACTIVE',
      version: 1,
      runtimeQualification: args.runtimeQualification,
      context: pending.context,
      ownerSlot: pending.ownerSlot,
      mutationOrdinal: pending.mutationOrdinal,
      projectIdentityDigest: pending.projectIdentityDigest,
      targetIdentityDigest: pending.targetIdentityDigest,
      tupleDigest: pending.tupleDigest,
      boundValuesDigest: pending.boundValuesDigest,
      expectedShareRow: closedRecord({
        projectId: projectProviderId,
        ...pending.expectedShareIdentity,
      }),
      finalIdentity,
    });
    providerQualificationRecords.set(providerQualification, qualification);
    providerQualificationRecords.set(args.handoff, qualification);
    if (providerQualificationRecords.get(providerQualification) !== qualification) return false;
    return replaceWeakRecord(
      sharePreparationRecords,
      args.preparation,
      pending,
      { state: 'ACTIVE', runtimeQualification: args.runtimeQualification, providerQualification },
    ) !== null;
  } catch {
    blockProviderLifecycle();
    return false;
  }
}

function logicalResourceForMutation(mutationOrdinal) {
  return PROJECT_MUTATION_ORDINALS.has(mutationOrdinal)
    ? 'primary-project'
    : 'primary-graph';
}

function intentIdentityForMutation(context, mutationOrdinal) {
  const resourceType = logicalResourceForMutation(mutationOrdinal);
  const resourceId = `vr-${sha256Bytes(encoder.encode(
    `${context.environmentDigest}|${context.runId}|${resourceType}`,
  )).slice(7, 39)}`;
  return Object.freeze({
    intentId: sha256Bytes(encoder.encode(
      `${context.environmentDigest}|${context.runId}|${resourceType}|${resourceId}`,
    )).slice(7),
    resourceId,
    resourceType,
  });
}

function oneMillisecondAfter(value) {
  if (typeof value !== 'string') mismatch('AUDIT_CHAIN_MISMATCH');
  const milliseconds = Date.parse(value);
  if (
    !Number.isSafeInteger(milliseconds)
    || new Date(milliseconds).toISOString() !== value
    || !Number.isSafeInteger(milliseconds + 1)
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  try {
    const successor = new Date(milliseconds + 1).toISOString();
    if (Date.parse(successor) !== milliseconds + 1) mismatch('AUDIT_CHAIN_MISMATCH');
    return successor;
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
}

function memberTemplateForMutation(mutationOrdinal) {
  const matches = [];
  for (const resource of providerContract.aggregateContracts.resources) {
    if (!['primary-project', 'primary-graph'].includes(resource.resourceType)) continue;
    for (const memberTemplate of resource.memberTemplates) {
      if (memberTemplate.firstBindOrdinal === mutationOrdinal) {
        matches.push({ memberTemplate, resourceType: resource.resourceType });
      }
    }
  }
  return matches.length === 1 ? matches[0] : null;
}

function providerReadbackIdentity(prior, mutationOrdinal) {
  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    return null;
  }
  if (
    !exactDataObject(aggregate, PROVIDER_AGGREGATE_KEYS)
    || canonicalJson(aggregate) !== prior.providerAggregateJson
    || contentDigest(aggregate) !== prior.providerAggregateDigest
  ) return null;
  const matches = [];
  const resourceContract = providerContract.aggregateContracts.resources.find((entry) => (
    entry.resourceType === prior.resourceType
  ));
  if (resourceContract === undefined) return null;
  for (const member of aggregate.ownedMembers) {
    const operations = member.operationStates?.filter((operation) => (
      operation.mutationOrdinal === mutationOrdinal
    ));
    if (operations?.length !== 1) continue;
    const template = resourceContract.memberTemplates.find((entry) => (
      entry.slot === member.memberBinding?.slot
      && entry.ownerOrdinal === member.memberBinding?.ownerOrdinal
      && entry.operations.some((operation) => operation.mutationOrdinal === mutationOrdinal)
    ));
    if (
      template === undefined
      || member.bindingState !== 'bound'
      || typeof member.providerId !== 'string'
      || !exactDataObject(member.providerIdentity, [
        'bindingName', 'providerId', 'providerKind',
      ])
      || member.providerIdentity.bindingName !== template.bindingName
      || member.providerIdentity.providerId !== member.providerId
      || member.providerIdentity.providerKind !== template.providerKind
    ) return null;
    matches.push(closedRecord({
      logicalResource: prior.resourceType,
      ownerSlot: template.slot,
      providerKind: template.providerKind,
      providerId: member.providerId,
      providerCompositeIdentity: `${template.bindingName}|${member.providerId}`,
    }));
  }
  return matches.length === 1 ? matches[0] : null;
}

function routeClassForMutation(mutationOrdinal) {
  const matches = [];
  for (const resource of providerContract.aggregateContracts.resources) {
    for (const memberTemplate of resource.memberTemplates) {
      for (const operation of memberTemplate.operations) {
        if (operation.mutationOrdinal === mutationOrdinal) {
          matches.push(operation.requestTemplate.bodyKind);
        }
      }
    }
  }
  return matches.length === 1
    && ['row-create', 'row-update', 'file-create'].includes(matches[0])
    ? matches[0]
    : null;
}

function providerBoundIntentOperation(prior, lease, args, providerId) {
  const target = memberTemplateForMutation(args.mutationOrdinal);
  const identity = intentIdentityForMutation(args.context, args.mutationOrdinal);
  if (
    target === null
    || target.resourceType !== identity.resourceType
    || !exactDataObject(prior, CLEANUP_V2_INTENT_KEYS)
    || prior.intentId !== identity.intentId
    || prior.state !== 'planned'
    || !exactDataObject(lease, LEASE_KEYS)
    || lease.state !== 'active'
    || lease.cleanupDebt !== false
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  const members = aggregate.ownedMembers.filter((member) => (
    member.memberBinding.slot === target.memberTemplate.slot
    && member.memberBinding.ownerOrdinal === target.memberTemplate.ownerOrdinal
  ));
  if (members.length !== 1) mismatch('AUDIT_CHAIN_MISMATCH');
  const member = members[0];
  if (
    member.bindingState !== 'unbound'
    || member.providerId !== null
    || member.providerIdentity !== null
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  member.bindingState = 'bound';
  member.providerId = providerId;
  member.providerIdentity = {
    bindingName: target.memberTemplate.bindingName,
    providerId,
    providerKind: target.memberTemplate.providerKind,
  };
  const nextAggregateJson = canonicalJson(aggregate);
  const snapshot = {
    ...prior,
    providerAggregateJson: nextAggregateJson,
    providerAggregateDigest: sha256Bytes(encoder.encode(nextAggregateJson)),
    intentVersion: prior.intentVersion + 1,
    updatedAt: oneMillisecondAfter(prior.updatedAt),
  };
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: prior.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition: 'intent.provider_bound',
    intentId: prior.intentId,
    intentProjectionDigest: contentDigest(snapshot),
  };
  const nextLease = {
    ...lease,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    snapshot,
    nextLease,
    nextIntent: snapshot,
  };
}

function providerValuesBoundIntentOperation(prior, lease, args, batch, bindings) {
  const identity = batch.resourceType === 'primary-share'
    ? {
      intentId: deterministicIntentId(args.context, 'primary-share'),
      resourceId: deterministicResourceId(args.context, 'primary-share'),
      resourceType: 'primary-share',
    }
    : intentIdentityForMutation(
      args.context,
      batch.resourceType === 'primary-project' ? 0 : 1,
    );
  if (
    identity.resourceType !== batch.resourceType
    || !exactDataObject(prior, CLEANUP_V2_INTENT_KEYS)
    || prior.intentId !== identity.intentId
    || prior.state !== 'planned'
    || !exactDataObject(lease, LEASE_KEYS)
    || lease.state !== 'active'
    || lease.cleanupDebt !== false
    || !frozenDenseArray(bindings)
    || bindings.length !== batch.rows.length
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  for (let index = 0; index < batch.rows.length; index += 1) {
    const [ownerSlot, name, valueKind] = batch.rows[index];
    const binding = bindings[index];
    if (
      !frozenExact(binding, ['ownerSlot', 'name', 'valueKind', 'value', 'valueDigest'])
      || binding.ownerSlot !== ownerSlot
      || binding.name !== name
      || binding.valueKind !== valueKind
      || typeof binding.value !== 'string'
      || binding.value.length === 0
      || binding.valueDigest !== sha256Bytes(encoder.encode(binding.value))
    ) mismatch('AUDIT_CHAIN_MISMATCH');
    const members = aggregate.ownedMembers.filter((member) => (
      member.memberBinding.slot === ownerSlot
    ));
    if (members.length !== 1) mismatch('AUDIT_CHAIN_MISMATCH');
    const rows = members[0].logicalValueBindings.filter((row) => (
      row.name === name && row.valueKind === valueKind
    ));
    if (
      rows.length !== 1
      || rows[0].state !== 'unbound'
      || rows[0].value !== null
      || rows[0].valueDigest !== null
    ) mismatch('AUDIT_CHAIN_MISMATCH');
    rows[0].state = 'bound';
    rows[0].value = binding.value;
    rows[0].valueDigest = binding.valueDigest;
  }
  const nextAggregateJson = canonicalJson(aggregate);
  const snapshot = {
    ...prior,
    providerAggregateJson: nextAggregateJson,
    providerAggregateDigest: sha256Bytes(encoder.encode(nextAggregateJson)),
    intentVersion: prior.intentVersion + 1,
    updatedAt: oneMillisecondAfter(prior.updatedAt),
  };
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: prior.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition: 'intent.provider_values_bound',
    intentId: prior.intentId,
    intentProjectionDigest: contentDigest(snapshot),
  };
  const nextLease = {
    ...lease,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    snapshot,
    nextLease,
    nextIntent: snapshot,
  };
}

function issuedIntentOperation(prior, lease, args) {
  const identity = intentIdentityForMutation(args.context, args.mutationOrdinal);
  if (
    !exactDataObject(prior, CLEANUP_V2_INTENT_KEYS)
    || prior.schemaVersion !== 'verification-intent-snapshot.v2'
    || prior.intentId !== identity.intentId
    || prior.runId !== args.context.runId
    || prior.environmentDigest !== args.context.environmentDigest
    || prior.resourceType !== identity.resourceType
    || prior.resourceId !== identity.resourceId
    || !DIGEST.test(prior.providerAggregateDigest)
    || typeof prior.ownerMarker !== 'string'
    || prior.ownerMarker.length === 0
    || prior.lifecycleClass !== 'fixture'
    || prior.state !== 'planned'
    || !Number.isSafeInteger(prior.intentVersion)
    || prior.intentVersion < 1
    || prior.intentVersion === Number.MAX_SAFE_INTEGER
    || prior.observationDigest !== null
    || prior.retentionExpiresAt !== null
    || typeof prior.createdAt !== 'string'
    || typeof prior.providerAggregateJson !== 'string'
    || !exactDataObject(lease, [
      'acquiredAt', 'cleanupDebt', 'environmentDigest', 'expiresAt', 'leaseRowId',
      'leaseTokenDigest', 'leaseVersion', 'ledgerDigest', 'ownerRunId',
      'ownerWorkflowRunId', 'renewedAt', 'state',
    ])
    || lease.state !== 'active'
    || lease.ownerRunId !== args.context.runId
    || lease.environmentDigest !== args.context.environmentDigest
    || lease.cleanupDebt !== false
    || !Number.isSafeInteger(lease.leaseVersion)
    || lease.leaseVersion < 0
    || lease.leaseVersion === Number.MAX_SAFE_INTEGER
    || !DIGEST.test(lease.ledgerDigest)
  ) mismatch('AUDIT_CHAIN_MISMATCH');

  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  if (
    !exactDataObject(aggregate, PROVIDER_AGGREGATE_KEYS)
    || canonicalJson(aggregate) !== prior.providerAggregateJson
    || contentDigest(aggregate) !== prior.providerAggregateDigest
    || aggregate.schemaVersion !== 'verification-provider-aggregate.v1'
    || !exactDataObject(aggregate.aggregateBinding, AGGREGATE_BINDING_KEYS)
    || contentDigest(aggregate.aggregateBinding) !== aggregate.aggregateBindingDigest
    || aggregate.aggregateBinding.intentId !== prior.intentId
    || aggregate.aggregateBinding.runId !== prior.runId
    || aggregate.aggregateBinding.environmentDigest !== prior.environmentDigest
    || aggregate.aggregateBinding.resourceType !== prior.resourceType
    || aggregate.aggregateBinding.resourceId !== prior.resourceId
    || aggregate.aggregateBinding.ownerMarker !== prior.ownerMarker
    || !Array.isArray(aggregate.ownedMembers)
    || !Array.isArray(aggregate.referencedMembers)
  ) mismatch('AUDIT_CHAIN_MISMATCH');

  let targetOperation = null;
  for (const member of aggregate.ownedMembers) {
    if (
      !exactDataObject(member, PROVIDER_MEMBER_KEYS)
      || !Array.isArray(member.operationStates)
      || !Array.isArray(member.logicalValueBindings)
    ) mismatch('AUDIT_CHAIN_MISMATCH');
    for (const operation of member.operationStates) {
      if (!exactDataObject(operation, OPERATION_STATE_KEYS)) {
        mismatch('AUDIT_CHAIN_MISMATCH');
      }
      if (operation.mutationOrdinal === args.mutationOrdinal) {
        if (targetOperation !== null) mismatch('AUDIT_CHAIN_MISMATCH');
        if (
          !DIGEST.test(member.memberBindingDigest)
          || contentDigest(member.memberBinding) !== member.memberBindingDigest
        ) mismatch('AUDIT_CHAIN_MISMATCH');
        targetOperation = operation;
      }
    }
  }
  if (
    targetOperation === null
    || targetOperation.state !== 'pending'
    || targetOperation.requestInstanceDigest !== null
    || targetOperation.expectedResultState !== null
    || targetOperation.resultStateDigest !== null
    || targetOperation.baselineDigest !== null
    || targetOperation.discoveryProofDigest !== null
  ) mismatch('AUDIT_CHAIN_MISMATCH');

  targetOperation.state = 'issued';
  targetOperation.requestInstanceDigest = args.expectedStateMapping.requestInstanceDigest;
  targetOperation.expectedResultState = safeCopy(
    args.expectedStateMapping.expectedResultState,
  );
  const nextAggregateJson = canonicalJson(aggregate);
  const snapshot = {
    ...prior,
    providerAggregateJson: nextAggregateJson,
    providerAggregateDigest: sha256Bytes(encoder.encode(nextAggregateJson)),
    intentVersion: prior.intentVersion + 1,
    updatedAt: oneMillisecondAfter(prior.updatedAt),
  };
  const snapshotDigest = contentDigest(snapshot);
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: prior.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition: 'intent.provider_operation_issued',
    intentId: prior.intentId,
    intentProjectionDigest: snapshotDigest,
  };
  const nextLease = {
    ...lease,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    snapshot,
    nextLease,
    nextIntent: snapshot,
  };
}

function reconciledIntentOperation(prior, lease, issue, readback) {
  const identity = intentIdentityForMutation(issue.context, issue.mutationOrdinal);
  if (
    !exactDataObject(prior, CLEANUP_V2_INTENT_KEYS)
    || prior.schemaVersion !== 'verification-intent-snapshot.v2'
    || prior.intentId !== identity.intentId
    || prior.runId !== issue.context.runId
    || prior.environmentDigest !== issue.context.environmentDigest
    || prior.resourceType !== identity.resourceType
    || prior.resourceId !== identity.resourceId
    || !DIGEST.test(prior.providerAggregateDigest)
    || typeof prior.providerAggregateJson !== 'string'
    || !Number.isSafeInteger(prior.intentVersion)
    || prior.intentVersion < 2
    || prior.intentVersion === Number.MAX_SAFE_INTEGER
    || !exactDataObject(lease, LEASE_KEYS)
    || lease.state !== 'active'
    || lease.ownerRunId !== issue.context.runId
    || lease.environmentDigest !== issue.context.environmentDigest
    || lease.cleanupDebt !== false
    || !Number.isSafeInteger(lease.leaseVersion)
    || lease.leaseVersion < 1
    || lease.leaseVersion === Number.MAX_SAFE_INTEGER
    || !DIGEST.test(lease.ledgerDigest)
  ) mismatch('AUDIT_CHAIN_MISMATCH');

  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  if (
    !exactDataObject(aggregate, PROVIDER_AGGREGATE_KEYS)
    || canonicalJson(aggregate) !== prior.providerAggregateJson
    || contentDigest(aggregate) !== prior.providerAggregateDigest
    || aggregate.schemaVersion !== 'verification-provider-aggregate.v1'
    || !exactDataObject(aggregate.aggregateBinding, AGGREGATE_BINDING_KEYS)
    || contentDigest(aggregate.aggregateBinding) !== aggregate.aggregateBindingDigest
    || aggregate.aggregateBinding.intentId !== prior.intentId
    || !Array.isArray(aggregate.ownedMembers)
    || !Array.isArray(aggregate.referencedMembers)
  ) mismatch('AUDIT_CHAIN_MISMATCH');

  let targetMember = null;
  let targetOperation = null;
  for (const member of aggregate.ownedMembers) {
    if (
      !exactDataObject(member, PROVIDER_MEMBER_KEYS)
      || !Array.isArray(member.operationStates)
    ) mismatch('AUDIT_CHAIN_MISMATCH');
    for (const operation of member.operationStates) {
      if (!exactDataObject(operation, OPERATION_STATE_KEYS)) {
        mismatch('AUDIT_CHAIN_MISMATCH');
      }
      if (operation.mutationOrdinal === issue.mutationOrdinal) {
        if (targetOperation !== null) mismatch('AUDIT_CHAIN_MISMATCH');
        targetMember = member;
        targetOperation = operation;
      }
    }
  }
  const trustedReadbackIdentity = providerReadbackIdentity(
    prior,
    issue.mutationOrdinal,
  );
  if (
    trustedReadbackIdentity === null
    || !frozenExact(readback, [
      'logicalResource', 'ownerSlot', 'providerKind', 'providerId',
      'providerCompositeIdentity', 'memberState', 'observedResultState',
    ])
    || Object.keys(trustedReadbackIdentity).some((key) => (
      readback[key] !== trustedReadbackIdentity[key]
    ))
  ) {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  const detachedObservedResultState = safeCopy(readback.observedResultState);
  const detachedMemberState = safeCopy(readback.memberState);
  const fileState = targetMember?.memberState?.schemaVersion
    === 'storage-file-metadata-state.v1';
  const contentKey = fileState ? 'metadataDigest' : 'dataDigest';
  const stateKeys = fileState
    ? ['metadataDigest', 'permissionsDigest', 'presence', 'schemaVersion']
    : ['dataDigest', 'permissionsDigest', 'presence', 'schemaVersion'];
  const observedResultDigest = contentDigest(detachedObservedResultState);
  if (
    targetOperation === null
    || targetMember === null
    || targetOperation.state !== 'issued'
    || targetOperation.requestInstanceDigest !== issue.expectedStateMapping.requestInstanceDigest
    || !same(targetOperation.expectedResultState, detachedObservedResultState)
    || targetOperation.resultStateDigest !== null
    || targetOperation.baselineDigest !== null
    || targetOperation.discoveryProofDigest !== null
    || !exactDataObject(detachedMemberState, stateKeys)
    || detachedMemberState.schemaVersion !== targetMember.memberState.schemaVersion
    || detachedMemberState.presence !== 'present'
    || detachedMemberState[contentKey] !== observedResultDigest
    || !DIGEST.test(detachedMemberState.permissionsDigest)
  ) mismatch('AUDIT_CHAIN_MISMATCH');

  targetOperation.state = 'reconciled';
  targetOperation.resultStateDigest = observedResultDigest;
  const nextAggregateJson = canonicalJson(aggregate);
  const snapshot = {
    ...prior,
    providerAggregateJson: nextAggregateJson,
    providerAggregateDigest: sha256Bytes(encoder.encode(nextAggregateJson)),
    intentVersion: prior.intentVersion + 1,
    updatedAt: oneMillisecondAfter(prior.updatedAt),
  };
  const snapshotDigest = contentDigest(snapshot);
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: prior.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition: 'intent.provider_operation_reconciled',
    intentId: prior.intentId,
    intentProjectionDigest: snapshotDigest,
  };
  const nextLease = {
    ...lease,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    snapshot,
    nextLease,
    nextIntent: snapshot,
  };
}

function createdIntentOperation(prior, lease, context, resourceType) {
  const identity = intentIdentityForMutation(
    context,
    resourceType === 'primary-project' ? 0 : 1,
  );
  if (
    identity.resourceType !== resourceType
    || !exactDataObject(prior, CLEANUP_V2_INTENT_KEYS)
    || prior.intentId !== identity.intentId
    || prior.state !== 'planned'
    || !exactDataObject(lease, LEASE_KEYS)
    || lease.state !== 'active'
    || lease.ownerRunId !== context.runId
    || lease.environmentDigest !== context.environmentDigest
    || lease.cleanupDebt !== false
    || lease.leaseVersion === Number.MAX_SAFE_INTEGER
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  const requiredOrdinals = resourceType === 'primary-project'
    ? PROJECT_MUTATION_ORDINALS
    : new Set([1, 3, 5, 7, 8, 9, 14, 15, 16]);
  const observedOrdinals = new Set();
  for (const member of aggregate.ownedMembers ?? []) {
    for (const operation of member.operationStates ?? []) {
      if (requiredOrdinals.has(operation.mutationOrdinal)) {
        if (operation.state !== 'reconciled') mismatch('AUDIT_CHAIN_MISMATCH');
        observedOrdinals.add(operation.mutationOrdinal);
      }
    }
  }
  if (
    aggregate.phase !== 'owner-baseline'
    || observedOrdinals.size !== requiredOrdinals.size
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  const resourceContract = providerContract.aggregateContracts.resources.find((entry) => (
    entry.resourceType === resourceType
  ));
  if (resourceContract === undefined) mismatch('AUDIT_CHAIN_MISMATCH');
  for (const member of aggregate.ownedMembers) {
    const template = resourceContract.memberTemplates.find((entry) => (
      entry.slot === member.memberBinding.slot
      && entry.ownerOrdinal === member.memberBinding.ownerOrdinal
    ));
    const phaseState = template?.memberStateContract.expectedStatesByPhase.find((entry) => (
      entry.phase === 'normal-owner'
    ));
    const observedState = phaseState === undefined ? undefined : providerObservedMemberStates.get(
      `${resourceType}|${template.slot}|${phaseState.dataSourceMutationOrdinal}`,
    );
    if (observedState === undefined) mismatch('AUDIT_CHAIN_MISMATCH');
    member.memberState = safeCopy(observedState);
  }
  aggregate.phase = 'normal-owner';
  const nextAggregateJson = canonicalJson(aggregate);
  const snapshot = {
    ...prior,
    state: 'created',
    providerAggregateJson: nextAggregateJson,
    providerAggregateDigest: sha256Bytes(encoder.encode(nextAggregateJson)),
    intentVersion: prior.intentVersion + 1,
    updatedAt: oneMillisecondAfter(prior.updatedAt),
  };
  const snapshotDigest = contentDigest(snapshot);
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: prior.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition: 'intent.created',
    intentId: prior.intentId,
    intentProjectionDigest: snapshotDigest,
  };
  const nextLease = {
    ...lease,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    snapshot,
    nextLease,
    nextIntent: snapshot,
  };
}

function shareIntentOperation(prior, lease, context, transition, mutate) {
  const intentId = deterministicIntentId(context, 'primary-share');
  const resourceId = deterministicResourceId(context, 'primary-share');
  if (
    !exactDataObject(prior, CLEANUP_V2_INTENT_KEYS)
    || prior.schemaVersion !== 'verification-intent-snapshot.v2'
    || prior.intentId !== intentId
    || prior.resourceType !== 'primary-share'
    || prior.resourceId !== resourceId
    || prior.state !== 'planned'
    || !exactDataObject(lease, LEASE_KEYS)
    || lease.state !== 'active'
    || lease.ownerRunId !== context.runId
    || lease.environmentDigest !== context.environmentDigest
    || lease.cleanupDebt !== false
    || lease.leaseVersion === Number.MAX_SAFE_INTEGER
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  let aggregate;
  try {
    aggregate = JSON.parse(prior.providerAggregateJson);
  } catch {
    mismatch('AUDIT_CHAIN_MISMATCH');
  }
  if (
    !exactDataObject(aggregate, PROVIDER_AGGREGATE_KEYS)
    || canonicalJson(aggregate) !== prior.providerAggregateJson
    || contentDigest(aggregate) !== prior.providerAggregateDigest
    || aggregate.aggregateBinding.intentId !== prior.intentId
    || aggregate.aggregateBinding.resourceType !== 'primary-share'
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  mutate(aggregate);
  const nextAggregateJson = canonicalJson(aggregate);
  const snapshot = {
    ...prior,
    providerAggregateJson: nextAggregateJson,
    providerAggregateDigest: sha256Bytes(encoder.encode(nextAggregateJson)),
    intentVersion: prior.intentVersion + 1,
    updatedAt: oneMillisecondAfter(prior.updatedAt),
  };
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: prior.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition,
    intentId: prior.intentId,
    intentProjectionDigest: contentDigest(snapshot),
  };
  const nextLease = {
    ...lease,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    snapshot,
    nextLease,
    nextIntent: snapshot,
  };
}

function shareCreateIssuedIntentOperation(prior, lease, issue) {
  return shareIntentOperation(
    prior,
    lease,
    issue.context,
    'intent.provider_create_issued',
    (aggregate) => {
      const expectedPhase = issue.mutationOrdinal === 17
        ? 'owner-baseline'
        : 'editor-issued';
      const nextPhase = issue.mutationOrdinal === 17
        ? 'editor-issued'
        : 'viewer-issued';
      const members = aggregate.ownedMembers.filter((member) => (
        member.memberBinding.slot === issue.ownerSlot
      ));
      if (aggregate.phase !== expectedPhase || members.length !== 1) {
        mismatch('AUDIT_CHAIN_MISMATCH');
      }
      const member = members[0];
      const operations = member.operationStates.filter((operation) => (
        operation.mutationOrdinal === issue.mutationOrdinal
      ));
      if (
        member.bindingState !== 'unissued'
        || member.providerId !== null
        || member.providerIdentity !== null
        || member.logicalValueBindings.some((binding) => binding.state !== 'bound')
        || operations.length !== 1
      ) mismatch('AUDIT_CHAIN_MISMATCH');
      const operation = operations[0];
      if (
        operation.state !== 'pending'
        || operation.requestInstanceDigest !== null
        || operation.baselineDigest !== null
      ) mismatch('AUDIT_CHAIN_MISMATCH');
      member.bindingState = 'issued';
      operation.state = 'issued';
      operation.requestInstanceDigest = issue.requestTuple.requestInstanceDigest;
      operation.baselineDigest = issue.baselineDigest;
      aggregate.phase = nextPhase;
    },
  );
}

function shareIdDiscoveredIntentOperation(prior, lease, issue, readback) {
  return shareIntentOperation(
    prior,
    lease,
    issue.context,
    'intent.provider_id_discovered',
    (aggregate) => {
      const expectedPhase = issue.mutationOrdinal === 17
        ? 'editor-issued'
        : 'viewer-issued';
      const members = aggregate.ownedMembers.filter((member) => (
        member.memberBinding.slot === issue.ownerSlot
      ));
      if (aggregate.phase !== expectedPhase || members.length !== 1) {
        mismatch('AUDIT_CHAIN_MISMATCH');
      }
      const member = members[0];
      const operations = member.operationStates.filter((operation) => (
        operation.mutationOrdinal === issue.mutationOrdinal
      ));
      if (
        member.bindingState !== 'issued'
        || member.providerId !== null
        || member.providerIdentity !== null
        || operations.length !== 1
      ) mismatch('AUDIT_CHAIN_MISMATCH');
      const operation = operations[0];
      if (
        operation.state !== 'issued'
        || operation.requestInstanceDigest !== issue.requestTuple.requestInstanceDigest
        || operation.baselineDigest !== issue.baselineDigest
        || operation.resultStateDigest !== null
        || operation.discoveryProofDigest !== null
      ) mismatch('AUDIT_CHAIN_MISMATCH');
      member.bindingState = 'bound';
      member.providerId = readback.providerId;
      member.providerIdentity = {
        bindingName: 'project-shares',
        providerId: readback.providerId,
        providerKind: 'tablesdb-row',
      };
      member.memberState = safeCopy(readback.memberState);
      operation.state = 'reconciled';
      operation.resultStateDigest = readback.resultStateDigest;
      operation.discoveryProofDigest = readback.discoveryProofDigest;
    },
  );
}

function shareCreatedIntentOperation(prior, lease, context) {
  const operation = shareIntentOperation(
    prior,
    lease,
    context,
    'intent.created',
    (aggregate) => {
      if (
        aggregate.phase !== 'viewer-issued'
        || aggregate.ownedMembers.length !== 2
        || aggregate.ownedMembers.some((member) => (
          member.bindingState !== 'bound'
          || member.operationStates.length !== 1
          || member.operationStates[0].state !== 'reconciled'
          || member.memberState.presence !== 'present'
        ))
      ) mismatch('AUDIT_CHAIN_MISMATCH');
      aggregate.phase = 'shared';
    },
  );
  operation.snapshot.state = 'created';
  operation.event.intentProjectionDigest = contentDigest(operation.snapshot);
  operation.nextLease.ledgerDigest = contentDigest(operation.event);
  return operation;
}

function cleanupDebtLeaseOperation(lease, context) {
  if (
    !exactDataObject(lease, LEASE_KEYS)
    || lease.state !== 'active'
    || lease.cleanupDebt !== false
    || lease.ownerRunId !== context.runId
    || lease.environmentDigest !== context.environmentDigest
    || lease.leaseVersion === Number.MAX_SAFE_INTEGER
  ) mismatch('AUDIT_CHAIN_MISMATCH');
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: lease.ledgerDigest,
    runId: context.runId,
    leaseVersionBefore: lease.leaseVersion,
    leaseVersionAfter: lease.leaseVersion + 1,
    transition: 'lease.cleanup_debt',
    intentId: null,
    intentProjectionDigest: null,
  };
  const nextLease = {
    ...lease,
    state: 'cleanup-debt',
    cleanupDebt: true,
    leaseVersion: lease.leaseVersion + 1,
    ledgerDigest: contentDigest(event),
  };
  return {
    expectedLeaseVersion: lease.leaseVersion,
    expectedLedgerDigest: lease.ledgerDigest,
    event,
    nextLease,
  };
}

async function commitCleanupDebt(args) {
  const store = installedProviderControlRecord.store;
  const prior = await store.getLease();
  const operation = cleanupDebtLeaseOperation(prior, args.context);
  const committed = await store.transact(operation);
  return committed.status === 'PASS'
    && same(committed.value, operation.nextLease)
    && await advanceSessionLineageAfterSuccess(args, operation)
    && same(await store.getLease(), operation.nextLease);
}

async function commitCleanupDebtWithoutLineage(store, context) {
  try {
    const prior = await store.getLease();
    const operation = cleanupDebtLeaseOperation(prior, context);
    const committed = await store.transact(operation);
    return committed.status === 'PASS'
      && same(committed.value, operation.nextLease)
      && same(await store.getLease(), operation.nextLease);
  } catch {
    return false;
  }
}

async function blockAfterDurableProviderMutation(args) {
  try {
    await commitCleanupDebt(args);
  } catch {
    // The caller is terminally blocked even if the exact debt write cannot be proved.
  }
  return blockProviderLifecycle();
}

async function commitCreatedOwnerIntents(args) {
  if (
    providerTupleRecord.providerBoundCount !== 14
    || providerTupleRecord.providerValuesBoundBatchCount !== 10
    || providerTupleRecord.providerOperationIssuedCount !== 17
  ) return false;
  const store = installedProviderControlRecord.store;
  for (const resourceType of ['primary-project', 'primary-graph']) {
    const identity = intentIdentityForMutation(
      args.context,
      resourceType === 'primary-project' ? 0 : 1,
    );
    const prior = await store.getIntentProjection(identity.intentId);
    let aggregate;
    try {
      aggregate = JSON.parse(prior.providerAggregateJson);
    } catch {
      return false;
    }
    const resourceContract = providerContract.aggregateContracts.resources.find((entry) => (
      entry.resourceType === resourceType
    ));
    if (resourceContract === undefined) return false;
    for (const template of resourceContract.memberTemplates) {
      const phaseState = template.memberStateContract.expectedStatesByPhase.find((entry) => (
        entry.phase === 'normal-owner'
      ));
      const sourceOrdinal = phaseState?.dataSourceMutationOrdinal;
      const stateKey = `${resourceType}|${template.slot}|${sourceOrdinal}`;
      if (providerObservedMemberStates.has(stateKey)) continue;
      const member = aggregate.ownedMembers.find((entry) => (
        entry.memberBinding.slot === template.slot
        && entry.memberBinding.ownerOrdinal === template.ownerOrdinal
      ));
      const sourceOperation = member?.operationStates.find((entry) => (
        entry.mutationOrdinal === sourceOrdinal
      ));
      const readback = await reflectApply(
        providerControlHubDispatchers.captureProviderMutationRoute,
        providerControlHubDispatchers.receiver,
        [closedRecord({
          operation: 'read-provider-member-state',
          runtimeQualification: args.runtimeQualification,
          context: args.context,
          sessionIntentQualification: args.sessionIntentQualification,
          logicalResource: resourceType,
          ownerSlot: template.slot,
          mutationOrdinal: sourceOrdinal,
          providerId: member?.providerId,
        })],
      );
      const fileState = template.providerKind === 'storage-file';
      const stateKeys = fileState
        ? ['metadataDigest', 'permissionsDigest', 'presence', 'schemaVersion']
        : ['dataDigest', 'permissionsDigest', 'presence', 'schemaVersion'];
      const contentKey = fileState ? 'metadataDigest' : 'dataDigest';
      if (
        member === undefined
        || member.bindingState !== 'bound'
        || typeof member.providerId !== 'string'
        || sourceOperation?.state !== 'reconciled'
        || !frozenExact(readback, ['memberState'])
        || !exactDataObject(readback.memberState, stateKeys)
        || readback.memberState.schemaVersion !== (fileState
          ? 'storage-file-metadata-state.v1' : 'tablesdb-row-state.v1')
        || readback.memberState.presence !== 'present'
        || readback.memberState[contentKey] !== sourceOperation.resultStateDigest
        || !DIGEST.test(readback.memberState.permissionsDigest)
      ) return false;
      providerObservedMemberStates.set(
        stateKey,
        deepFreeze(safeCopy(readback.memberState)),
      );
    }
    const lease = await store.getLease();
    const operation = createdIntentOperation(prior, lease, args.context, resourceType);
    const committed = await store.transact(operation);
    if (committed.status !== 'PASS' || !same(committed.value, operation.nextLease)) {
      return false;
    }
    if (!await advanceSessionLineageAfterSuccess(args, operation)) return false;
  }
  return true;
}

async function issueProviderMutation(args) {
  try {

    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, GENERIC_ISSUE_KEYS)
      || !installedFor(args.runtimeQualification, args.context)
      || !await activeSessionLineage(args)
      || !nominalToken(args.observationQualification)
      || !Number.isSafeInteger(args.mutationOrdinal)
      || args.mutationOrdinal < 0
      || args.mutationOrdinal > 16
      || !validRouteProjection(
        args.routeProjection,
        routeClassForMutation(args.mutationOrdinal),
      )
      || !validExpectedStateMapping(args.expectedStateMapping)
    ) {

      return blockProviderLifecycle();
    }

    const current = providerTupleRecord;
    if (
      current.state !== 'READY'
      || current.nextMutationOrdinal !== args.mutationOrdinal
      || current.providerOperationIssuedCount !== args.mutationOrdinal
      || current.providerOperationReconciledCount !== args.mutationOrdinal
    ) {

      return blockProviderLifecycle();
    }
    let transitionTuple = replaceProviderTupleRecord(current, {
      ...current,
      state: 'GENERIC_DURABLE_RESERVING',
    });
    if (transitionTuple === null) return blockProviderLifecycle();

    let providerId = null;
    let providerCompositeIdentity = null;
    if (PROVIDER_BOUND_ORDINALS.has(args.mutationOrdinal)) {
      const target = memberTemplateForMutation(args.mutationOrdinal);
      if (target === null) return blockProviderLifecycle();
      const binding = reflectApply(
        providerControlHubDispatchers.captureProviderMutationRoute,
        providerControlHubDispatchers.receiver,
        [closedRecord({
          operation: 'read-provider-binding',
          runtimeQualification: args.runtimeQualification,
          context: args.context,
          sessionIntentQualification: args.sessionIntentQualification,
          mutationOrdinal: args.mutationOrdinal,
          observationQualification: args.observationQualification,
        })],
      );
      if (
        !frozenExact(binding, ['providerId'])
        || typeof binding.providerId !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(binding.providerId)
        || !args.routeProjection.generatedIdBindings.some((entry) => (
          entry.valueDigest === sha256Bytes(encoder.encode(binding.providerId))
        ))
      ) {

        return blockProviderLifecycle();
      }
      providerId = binding.providerId;
      providerCompositeIdentity = `${target.memberTemplate.bindingName}|${providerId}`;
      if (
        boundProviderIds.has(args.mutationOrdinal)
        || boundCompositeProviderIds.has(providerCompositeIdentity)
      ) return blockProviderLifecycle();
    }

    const store = installedProviderControlRecord.store;
    const identity = intentIdentityForMutation(args.context, args.mutationOrdinal);
    let prior = await store.getIntentProjection(identity.intentId);
    let lease = await store.getLease();
    if (providerTupleRecord !== transitionTuple) return blockProviderLifecycle();
    if (providerId !== null) {
      const bindingOperation = providerBoundIntentOperation(prior, lease, args, providerId);
      const bindingCommitted = await store.transact(bindingOperation);
      if (
        providerTupleRecord !== transitionTuple
        || bindingCommitted.status !== 'PASS'
        || !same(bindingCommitted.value, bindingOperation.nextLease)
        || !await advanceSessionLineageAfterSuccess(args, bindingOperation)
      ) return blockProviderLifecycle();
      prior = await store.getIntentProjection(identity.intentId);
      lease = await store.getLease();
      if (
        !same(prior, bindingOperation.nextIntent)
        || !same(lease, bindingOperation.nextLease)
      ) return blockProviderLifecycle();
      const boundTuple = replaceProviderTupleRecord(transitionTuple, {
        ...transitionTuple,
        providerBoundCount: transitionTuple.providerBoundCount + 1,
      });
      if (boundTuple === null) return blockProviderLifecycle();
      transitionTuple = boundTuple;
    }
    const applicableBatches = PROVIDER_VALUE_BATCHES
      .map((batch, batchIndex) => ({ batch, batchIndex }))
      .filter(({ batch }) => batch.mutationOrdinal === args.mutationOrdinal);
    for (const { batch, batchIndex } of applicableBatches) {

      const valueReadback = reflectApply(
        providerControlHubDispatchers.captureProviderMutationRoute,
        providerControlHubDispatchers.receiver,
        [closedRecord({
          operation: 'read-provider-values',
          runtimeQualification: args.runtimeQualification,
          context: args.context,
          sessionIntentQualification: args.sessionIntentQualification,
          mutationOrdinal: args.mutationOrdinal,
          observationQualification: args.observationQualification,
          logicalResource: batch.resourceType,
          batchIndex,
        })],
      );
      if (!frozenExact(valueReadback, ['bindings'])) {

        return blockProviderLifecycle();
      }
      const batchIdentity = intentIdentityForMutation(
        args.context,
        batch.resourceType === 'primary-project' ? 0 : 1,
      );
      const batchPrior = await store.getIntentProjection(batchIdentity.intentId);
      const batchLease = await store.getLease();
      const valueOperation = providerValuesBoundIntentOperation(
        batchPrior,
        batchLease,
        args,
        batch,
        valueReadback.bindings,
      );

      const valueCommitted = await store.transact(valueOperation);
      if (
        providerTupleRecord !== transitionTuple
        || valueCommitted.status !== 'PASS'
        || !same(valueCommitted.value, valueOperation.nextLease)
        || !await advanceSessionLineageAfterSuccess(args, valueOperation)
      ) {

        return blockProviderLifecycle();
      }
      const valuesTuple = replaceProviderTupleRecord(transitionTuple, {
        ...transitionTuple,
        providerValuesBoundBatchCount:
          transitionTuple.providerValuesBoundBatchCount + 1,
      });
      if (valuesTuple === null) return blockProviderLifecycle();
      transitionTuple = valuesTuple;
    }
    prior = await store.getIntentProjection(identity.intentId);
    lease = await store.getLease();
    const operation = issuedIntentOperation(prior, lease, args);

    const committed = await store.transact(operation);
    if (
      providerTupleRecord !== transitionTuple
      || committed.status !== 'PASS'
      || !same(committed.value, operation.nextLease)
    ) return blockProviderLifecycle();
    if (!await advanceSessionLineageAfterSuccess(args, operation)) {
      revokeSessionLineageWitness(args.sessionIntentQualification);
      return blockProviderLifecycle();
    }

    const issuedTuple = replaceProviderTupleRecord(transitionTuple, {
      ...transitionTuple,
      state: 'GENERIC_WRITE_ISSUED',
      nextMutationOrdinal: current.nextMutationOrdinal + 1,
      providerOperationIssuedCount: current.providerOperationIssuedCount + 1,
    });
    if (issuedTuple === null) return blockProviderLifecycle();

    const providerMutationIssue = makeToken();
    const writeIssued = Object.freeze({
      state: 'WRITE_ISSUED',
      version: 1,
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      sessionIntentQualification: args.sessionIntentQualification,
      mutationOrdinal: args.mutationOrdinal,
      observationQualification: args.observationQualification,
      routeProjection: args.routeProjection,
      expectedStateMapping: args.expectedStateMapping,
      providerId,
      tupleRecord: issuedTuple,
      durableSnapshotDigest: contentDigest(operation.snapshot),
    });
    providerMutationIssueRecords.set(providerMutationIssue, writeIssued);
    if (providerMutationIssueRecords.get(providerMutationIssue) !== writeIssued) {
      return blockProviderLifecycle();
    }
    if (providerId !== null) {
      boundProviderIds.set(args.mutationOrdinal, providerId);
      boundCompositeProviderIds.add(providerCompositeIdentity);
    }

    return privatePass(closedRecord({ providerMutationIssue }));
  } catch (error) {

    return blockProviderLifecycle();
  }
}
async function reconcileProviderMutation(args) {
  let durableFailureArgs;
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, GENERIC_RECONCILE_KEYS)
      || !installedFor(args.runtimeQualification)
      || !nominalToken(args.providerMutationIssue)
      || !nominalToken(args.observationQualification)
      || !['returned', 'threw', 'unknown'].includes(args.releaseDisposition)
    ) return blockProviderLifecycle();
    const current = providerMutationIssueRecords.get(args.providerMutationIssue);
    if (
      current === undefined
      || current.state !== 'WRITE_ISSUED'
      || current.runtimeQualification !== args.runtimeQualification
      || current.observationQualification !== args.observationQualification
      || providerTupleRecord !== current.tupleRecord
      || providerTupleRecord.state !== 'GENERIC_WRITE_ISSUED'
    ) return blockProviderLifecycle();
    const released = replaceWeakRecord(
      providerMutationIssueRecords,
      args.providerMutationIssue,
      current,
      { ...current, state: 'RELEASE_' + args.releaseDisposition.toUpperCase() },
    );
    if (released === null) return blockProviderLifecycle();
    const reconciling = replaceWeakRecord(
      providerMutationIssueRecords,
      args.providerMutationIssue,
      released,
      { ...released, state: 'RECONCILING' },
    );
    if (reconciling === null) return blockProviderLifecycle();
    durableFailureArgs = reconciling;
    const store = installedProviderControlRecord.store;
    const identity = intentIdentityForMutation(
      reconciling.context,
      reconciling.mutationOrdinal,
    );
    const prior = await store.getIntentProjection(identity.intentId);
    const lease = await store.getLease();
    if (providerMutationIssueRecords.get(args.providerMutationIssue) !== reconciling) {
      return blockAfterDurableProviderMutation(reconciling);
    }
    const readbackIdentity = providerReadbackIdentity(
      prior,
      reconciling.mutationOrdinal,
    );
    if (readbackIdentity === null) return blockAfterDurableProviderMutation(reconciling);
    let readback;
    try {
      readback = await reflectApply(
        providerControlHubDispatchers.captureProviderMutationRoute,
        providerControlHubDispatchers.receiver,
        [closedRecord({
          operation: 'read-provider-result',
          runtimeQualification: args.runtimeQualification,
          context: reconciling.context,
          sessionIntentQualification: reconciling.sessionIntentQualification,
          mutationOrdinal: reconciling.mutationOrdinal,
          observationQualification: args.observationQualification,
          ...readbackIdentity,
        })],
      );
    } catch {
      return blockAfterDurableProviderMutation(reconciling);
    }
    if (
      !frozenExact(readback, [
        'logicalResource', 'ownerSlot', 'providerKind', 'providerId',
        'providerCompositeIdentity', 'memberState', 'observedResultState',
      ])
      || Object.keys(readbackIdentity).some((key) => readback[key] !== readbackIdentity[key])
      || readback.observedResultState === null
      || typeof readback.observedResultState !== 'object'
      || Object.getPrototypeOf(readback.observedResultState) !== null
      || !Object.isFrozen(readback.observedResultState)
    ) return blockAfterDurableProviderMutation(reconciling);
    const operation = reconciledIntentOperation(
      prior,
      lease,
      reconciling,
      readback,
    );
    const committed = await store.transact(operation);
    if (
      providerMutationIssueRecords.get(args.providerMutationIssue) !== reconciling
      || committed.status !== 'PASS'
      || !same(committed.value, operation.nextLease)
    ) return blockAfterDurableProviderMutation(reconciling);
    if (!await advanceSessionLineageAfterSuccess(reconciling, operation)) {
      revokeSessionLineageWitness(reconciling.sessionIntentQualification);
      return blockAfterDurableProviderMutation(reconciling);
    }
    const target = memberTemplateForMutation(reconciling.mutationOrdinal);
    if (target === null) {
      const resourceContract = providerContract.aggregateContracts.resources.find((entry) => (
        entry.resourceType === identity.resourceType
      ));
      const templates = resourceContract?.memberTemplates.filter((entry) => (
        entry.operations.some((operationState) => (
          operationState.mutationOrdinal === reconciling.mutationOrdinal
        ))
      ));
      if (templates?.length !== 1) return blockAfterDurableProviderMutation(reconciling);
      providerObservedMemberStates.set(
        `${identity.resourceType}|${templates[0].slot}|${reconciling.mutationOrdinal}`,
        deepFreeze(safeCopy(readback.memberState)),
      );
    } else {
      providerObservedMemberStates.set(
        `${identity.resourceType}|${target.memberTemplate.slot}|${reconciling.mutationOrdinal}`,
        deepFreeze(safeCopy(readback.memberState)),
      );
    }
    if (
      reconciling.mutationOrdinal === 16
      && !await commitCreatedOwnerIntents(reconciling)
    ) return blockAfterDurableProviderMutation(reconciling);
    if (
      args.releaseDisposition !== 'returned'
      && !await commitCleanupDebt(reconciling)
    ) return blockProviderLifecycle();
    const finalGenericMutation = reconciling.mutationOrdinal === 16;
    const projectId = finalGenericMutation ? boundProviderIds.get(6) : undefined;
    if (finalGenericMutation && typeof projectId !== 'string') {
      return blockAfterDurableProviderMutation(reconciling);
    }
    const reconciledTuple = replaceProviderTupleRecord(providerTupleRecord, {
      ...providerTupleRecord,
      state: finalGenericMutation ? 'GENERIC_COMPLETE' : 'READY',
      providerOperationReconciledCount:
        providerTupleRecord.providerOperationReconciledCount + 1,
      ...(finalGenericMutation
        ? { projectIdentityDigest: sha256Bytes(encoder.encode(projectId)) }
        : {}),
    });
    if (reconciledTuple === null) return blockAfterDurableProviderMutation(reconciling);
    const reconciliationQualification = makeToken();
    if (CLOCK_RECONCILIATION_ORDINALS.includes(reconciling.mutationOrdinal)) {
      if (mutationReconciliationQualifications.has(reconciling.mutationOrdinal)) {
        return blockAfterDurableProviderMutation(reconciling);
      }
      const reconciliationRecord = Object.freeze({
        state: 'ACTIVE',
        runtimeQualification: args.runtimeQualification,
        clock: null,
        mutationOrdinal: reconciling.mutationOrdinal,
      });
      mutationReconciliationRecords.set(
        reconciliationQualification,
        reconciliationRecord,
      );
      mutationReconciliationQualifications.set(
        reconciling.mutationOrdinal,
        reconciliationQualification,
      );
    }
    const reconciled = replaceWeakRecord(
      providerMutationIssueRecords,
      args.providerMutationIssue,
      reconciling,
      {
        ...reconciling,
        state: 'RECONCILED',
        tupleRecord: reconciledTuple,
        reconciliationQualification,
      },
    );
    if (reconciled === null) return blockAfterDurableProviderMutation(reconciling);
    return privatePass(closedRecord({ reconciliationQualification }));
  } catch {
    return durableFailureArgs === undefined
      ? blockProviderLifecycle()
      : blockAfterDurableProviderMutation(durableFailureArgs);
  }
}

async function createShareBaselineProof(args) {
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'context', 'sessionIntentQualification',
        'providerQualification', 'ownerSlot',
      ])
      || !installedFor(args.runtimeQualification, args.context)
      || !await activeSessionLineage(args)
      || !nominalToken(args.providerQualification)
    ) return blockProviderLifecycle();
    const qualification = providerQualificationRecords.get(args.providerQualification);
    const pair = shareOwnerPair(args.ownerSlot);
    if (
      qualification === undefined
      || qualification.state !== 'ACTIVE'
      || qualification.runtimeQualification !== args.runtimeQualification
      || qualification.context !== args.context
      || qualification.ownerSlot !== args.ownerSlot
      || !frozenExact(qualification.expectedShareRow, [
        'projectId', 'userId', 'userEmail', 'userName', 'role', 'canRun',
        'sharedBy', 'permissions',
      ])
      || pair === null
      || providerTupleRecord.nextMutationOrdinal !== pair.mutationOrdinal
    ) return blockProviderLifecycle();
    const baselineProof = makeToken();
    const reserving = Object.freeze({
      state: 'BASELINE_RESERVING',
      version: 1,
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      sessionIntentQualification: args.sessionIntentQualification,
      providerQualification: args.providerQualification,
      ownerSlot: args.ownerSlot,
      mutationOrdinal: pair.mutationOrdinal,
    });
    shareBaselineProofRecords.set(baselineProof, reserving);
    const reading = replaceWeakRecord(
      shareBaselineProofRecords,
      baselineProof,
      reserving,
      { ...reserving, state: 'BASELINE_READING' },
    );
    if (reading === null) return blockProviderLifecycle();
    const baselineReadback = await reflectApply(
      providerControlHubDispatchers.captureProviderMutationRoute,
      providerControlHubDispatchers.receiver,
      [closedRecord({
        operation: 'read-share-baseline',
        runtimeQualification: args.runtimeQualification,
        context: args.context,
        sessionIntentQualification: args.sessionIntentQualification,
        providerQualification: args.providerQualification,
        ownerSlot: args.ownerSlot,
        mutationOrdinal: pair.mutationOrdinal,
        expectedShareRow: qualification.expectedShareRow,
      })],
    );
    if (
      !frozenExact(baselineReadback, ['baselineDigest'])
      || !DIGEST.test(baselineReadback.baselineDigest)
    ) return blockProviderLifecycle();
    const qualified = replaceWeakRecord(
      shareBaselineProofRecords,
      baselineProof,
      reading,
      {
        ...reading,
        state: 'BASELINE_QUALIFIED',
        baselineDigest: baselineReadback.baselineDigest,
      },
    );
    if (qualified === null) return blockProviderLifecycle();
    return privatePass(closedRecord({ baselineProof }));
  } catch {
    return blockProviderLifecycle();
  }
}

async function issueShareCreate(args) {
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'context', 'sessionIntentQualification',
        'providerQualification', 'baselineProof', 'requestTupleSeed',
        'observationQualification', 'routeProjection',
      ])
      || !installedFor(args.runtimeQualification, args.context)
      || !await activeSessionLineage(args)
      || !nominalToken(args.providerQualification)
      || !nominalToken(args.baselineProof)
      || !nominalToken(args.observationQualification)
      || !validRouteProjection(args.routeProjection, 'share-create')
    ) return blockProviderLifecycle();
    const baseline = shareBaselineProofRecords.get(args.baselineProof);
    const qualification = providerQualificationRecords.get(args.providerQualification);
    if (
      baseline === undefined
      || baseline.state !== 'BASELINE_QUALIFIED'
      || qualification === undefined
      || qualification.state !== 'ACTIVE'
      || qualification.runtimeQualification !== args.runtimeQualification
      || baseline.providerQualification !== args.providerQualification
      || baseline.context !== args.context
      || baseline.sessionIntentQualification !== args.sessionIntentQualification
      || baseline.ownerSlot !== qualification.ownerSlot
      || providerTupleRecord.state !== 'GENERIC_COMPLETE'
      || providerTupleRecord.nextMutationOrdinal !== qualification.mutationOrdinal
      || providerTupleRecord.providerValuesBoundBatchCount
        !== (qualification.mutationOrdinal === 17 ? 11 : 12)
      || !frozenExact(args.requestTupleSeed, [
        'schemaVersion', 'ownerSlot', 'mutationOrdinal', 'requestInstanceDigest',
        'projectIdentityDigest', 'targetIdentityDigest', 'tupleDigest',
        'boundValuesDigest',
      ])
      || args.requestTupleSeed.schemaVersion !== 'verification-share-create-request.v1'
      || args.requestTupleSeed.ownerSlot !== qualification.ownerSlot
      || args.requestTupleSeed.mutationOrdinal !== qualification.mutationOrdinal
      || args.requestTupleSeed.projectIdentityDigest !== qualification.projectIdentityDigest
      || args.requestTupleSeed.targetIdentityDigest !== qualification.targetIdentityDigest
      || args.requestTupleSeed.tupleDigest !== qualification.tupleDigest
      || args.requestTupleSeed.boundValuesDigest !== qualification.boundValuesDigest
      || !DIGEST.test(args.requestTupleSeed.requestInstanceDigest)
    ) return blockProviderLifecycle();
    const requestTuple = closedRecord({
      ...args.requestTupleSeed,
      baselineDigest: baseline.baselineDigest,
    });
    const consumedBaseline = replaceWeakRecord(
      shareBaselineProofRecords,
      args.baselineProof,
      baseline,
      { ...baseline, state: 'CONSUMED' },
    );
    if (consumedBaseline === null) return blockProviderLifecycle();
    const durableCandidate = {
      context: args.context,
      ownerSlot: qualification.ownerSlot,
      mutationOrdinal: qualification.mutationOrdinal,
      requestTuple,
      baselineDigest: baseline.baselineDigest,
    };
    const store = installedProviderControlRecord.store;
    const shareIntentId = deterministicIntentId(args.context, 'primary-share');
    const prior = await store.getIntentProjection(shareIntentId);
    const lease = await store.getLease();
    const operation = shareCreateIssuedIntentOperation(
      prior,
      lease,
      durableCandidate,
    );
    const committed = await store.transact(operation);
    if (
      shareBaselineProofRecords.get(args.baselineProof) !== consumedBaseline
      || committed.status !== 'PASS'
      || !same(committed.value, operation.nextLease)
      || !await advanceSessionLineageAfterSuccess(args, operation)
      || !same(await store.getIntentProjection(shareIntentId), operation.nextIntent)
      || !same(await store.getLease(), operation.nextLease)
    ) return blockProviderLifecycle();
    const shareIssue = makeToken();
    const issueRecord = Object.freeze({
      state: 'WRITE_ISSUED',
      version: 1,
      runtimeQualification: args.runtimeQualification,
      observationQualification: args.observationQualification,
      providerQualification: args.providerQualification,
      baselineProof: args.baselineProof,
      requestTuple,
      routeProjection: args.routeProjection,
      context: args.context,
      sessionIntentQualification: args.sessionIntentQualification,
      mutationOrdinal: qualification.mutationOrdinal,
      ownerSlot: qualification.ownerSlot,
      baselineDigest: baseline.baselineDigest,
      durableSnapshotDigest: contentDigest(operation.snapshot),
    });
    shareIssueRecords.set(shareIssue, issueRecord);
    if (shareIssueRecords.get(shareIssue) !== issueRecord) return blockProviderLifecycle();
    const issuedTuple = replaceProviderTupleRecord(providerTupleRecord, {
      ...providerTupleRecord,
      state: 'SHARE_WRITE_ISSUED',
      nextMutationOrdinal: providerTupleRecord.nextMutationOrdinal + 1,
      providerCreateIssuedCount: providerTupleRecord.providerCreateIssuedCount + 1,
    });
    if (issuedTuple === null) return blockProviderLifecycle();
    return privatePass(closedRecord({ shareIssue }));
  } catch {
    return blockProviderLifecycle();
  }
}

async function reconcileShareCreate(args) {
  let durableFailureArgs;
  try {
    if (
      this !== PROVIDER_CONTROL_RECEIVER
      || !exactDataObject(args, [
        'runtimeQualification', 'shareIssue', 'observationQualification',
        'releaseDisposition',
      ])
      || !installedFor(args.runtimeQualification)
      || !nominalToken(args.shareIssue)
      || !nominalToken(args.observationQualification)
      || !['returned', 'threw', 'unknown'].includes(args.releaseDisposition)
    ) return blockProviderLifecycle();
    const current = shareIssueRecords.get(args.shareIssue);
    if (
      current === undefined
      || current.state !== 'WRITE_ISSUED'
      || current.runtimeQualification !== args.runtimeQualification
      || current.observationQualification !== args.observationQualification
      || providerTupleRecord.state !== 'SHARE_WRITE_ISSUED'
    ) return blockProviderLifecycle();
    const released = replaceWeakRecord(
      shareIssueRecords,
      args.shareIssue,
      current,
      { ...current, state: 'RELEASE_' + args.releaseDisposition.toUpperCase() },
    );
    if (released === null) return blockProviderLifecycle();
    const reconciling = replaceWeakRecord(
      shareIssueRecords,
      args.shareIssue,
      released,
      { ...released, state: 'RECONCILING' },
    );
    if (reconciling === null) return blockProviderLifecycle();
    durableFailureArgs = current;
    let readback;
    try {
      readback = await reflectApply(
        providerControlHubDispatchers.captureProviderMutationRoute,
        providerControlHubDispatchers.receiver,
        [closedRecord({
          operation: 'read-share-result',
          runtimeQualification: args.runtimeQualification,
          context: current.context,
          sessionIntentQualification: current.sessionIntentQualification,
          mutationOrdinal: current.mutationOrdinal,
          observationQualification: args.observationQualification,
        })],
      );
    } catch {
      return blockAfterDurableProviderMutation(current);
    }
    if (
      !frozenExact(readback, [
        'discoveryProofDigest', 'memberState', 'providerId', 'resultStateDigest',
      ])
      || !DIGEST.test(readback.discoveryProofDigest)
      || !DIGEST.test(readback.resultStateDigest)
      || typeof readback.providerId !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(readback.providerId)
      || shareProviderIds.has(readback.providerId)
      || !frozenExact(readback.memberState, [
        'dataDigest', 'permissionsDigest', 'presence', 'schemaVersion',
      ])
      || readback.memberState.schemaVersion !== 'tablesdb-row-state.v1'
      || readback.memberState.presence !== 'present'
      || !DIGEST.test(readback.memberState.dataDigest)
      || !DIGEST.test(readback.memberState.permissionsDigest)
      || readback.resultStateDigest !== contentDigest(readback.memberState)
    ) return blockAfterDurableProviderMutation(current);
    const store = installedProviderControlRecord.store;
    const shareIntentId = deterministicIntentId(current.context, 'primary-share');
    const prior = await store.getIntentProjection(shareIntentId);
    const lease = await store.getLease();
    const operation = shareIdDiscoveredIntentOperation(prior, lease, current, readback);
    const committed = await store.transact(operation);
    if (
      shareIssueRecords.get(args.shareIssue) !== reconciling
      || committed.status !== 'PASS'
      || !same(committed.value, operation.nextLease)
      || !await advanceSessionLineageAfterSuccess(current, operation)
      || !same(await store.getIntentProjection(shareIntentId), operation.nextIntent)
      || !same(await store.getLease(), operation.nextLease)
    ) return blockAfterDurableProviderMutation(current);
    if (current.mutationOrdinal === 18) {
      const createdPrior = await store.getIntentProjection(shareIntentId);
      const createdLease = await store.getLease();
      const createdOperation = shareCreatedIntentOperation(
        createdPrior,
        createdLease,
        current.context,
      );
      const createdCommit = await store.transact(createdOperation);
      if (
        shareIssueRecords.get(args.shareIssue) !== reconciling
        || createdCommit.status !== 'PASS'
        || !same(createdCommit.value, createdOperation.nextLease)
        || !await advanceSessionLineageAfterSuccess(current, createdOperation)
        || !same(await store.getIntentProjection(shareIntentId), createdOperation.nextIntent)
        || !same(await store.getLease(), createdOperation.nextLease)
      ) return blockAfterDurableProviderMutation(current);
    }
    if (
      args.releaseDisposition !== 'returned'
      && !await commitCleanupDebt(current)
    ) return blockProviderLifecycle();
    const reconciledTuple = replaceProviderTupleRecord(providerTupleRecord, {
      ...providerTupleRecord,
      state: current.mutationOrdinal === 18 ? 'PROVIDER_COMPLETE' : 'GENERIC_COMPLETE',
      providerIdDiscoveredCount: providerTupleRecord.providerIdDiscoveredCount + 1,
    });
    if (reconciledTuple === null) return blockAfterDurableProviderMutation(current);
    const reconciliationQualification = makeToken();
    const reconciled = replaceWeakRecord(
      shareIssueRecords,
      args.shareIssue,
      reconciling,
      {
        ...reconciling,
        state: 'RECONCILED',
        providerId: readback.providerId,
        discoveryProofDigest: readback.discoveryProofDigest,
        resultStateDigest: readback.resultStateDigest,
        reconciliationQualification,
      },
    );
    if (reconciled === null) return blockAfterDurableProviderMutation(current);
    shareProviderIds.add(readback.providerId);
    return privatePass(closedRecord({ reconciled: true, reconciliationQualification }));
  } catch {
    return durableFailureArgs === undefined
      ? blockProviderLifecycle()
      : blockAfterDurableProviderMutation(durableFailureArgs);
  }
}

const PROVIDER_CONTROL_IMPLEMENTATION = Object.freeze(Object.assign(
  Object.create(null),
  {
    receiver: PROVIDER_CONTROL_RECEIVER,
    installProviderControlStore,
    prepareShareValuesTransition,
    abortShareValuesTransition,
    commitShareValuesTransition,
    finalizeShareValuesTransition,
    issueProviderMutation,
    reconcileProviderMutation,
    createShareBaselineProof,
    issueShareCreate,
    reconcileShareCreate,
  },
));

function blockProviderControlBootstrap() {
  providerControlBootstrapState = 'BLOCKED';
  isAuthenticTestCloudBootstrapHub(undefined);
  return false;
}

function registrationEnvelope(implementation) {
  return Object.freeze(Object.assign(Object.create(null), {
    receiver: PROVIDER_CONTROL_RECEIVER,
    implementation,
    moduleUrl: import.meta.url,
  }));
}

function currentAuthenticBootstrapHub() {
  const descriptor = reflectApply(
    getOwnPropertyDescriptor,
    Object,
    [globalThis, BOOTSTRAP_HUB_PROPERTY],
  );
  if (
    descriptor === undefined
    || descriptor.configurable !== true
    || descriptor.enumerable !== false
    || descriptor.writable !== false
    || !Object.hasOwn(descriptor, 'value')
    || !isAuthenticTestCloudBootstrapHub(descriptor.value)
  ) return null;
  return descriptor.value;
}

export function registerTestCloudProviderControlBootstrap() {
  if (
    arguments.length !== 0
    || providerControlBootstrapState !== 'EMPTY'
    || readTestCloudRuntimeLifecycle() !== 'BOOTSTRAPPING'
  ) return blockProviderControlBootstrap();

  const hub = currentAuthenticBootstrapHub();
  if (hub === null) return blockProviderControlBootstrap();
  providerControlBootstrapState = 'REGISTERING';
  providerControlHubDispatchers = Object.freeze({
    receiver: hub.bridgeReceiver,
    authenticateSessionLineage: hub.authenticateSessionLineage,
    readAuthenticatedShareBindingDigests: hub.readAuthenticatedShareBindingDigests,
    authenticateShareIdentityFinalState: hub.authenticateShareIdentityFinalState,
    captureProviderMutationRoute: hub.captureProviderMutationRoute,
  });
  if (
    typeof providerControlHubDispatchers.authenticateSessionLineage !== 'function'
    ||
    typeof providerControlHubDispatchers.readAuthenticatedShareBindingDigests !== 'function'
    || typeof providerControlHubDispatchers.authenticateShareIdentityFinalState !== 'function'
    || typeof providerControlHubDispatchers.captureProviderMutationRoute !== 'function'
  ) return blockProviderControlBootstrap();
  try {
    const registrations = [
      [
        hub.registerProviderControlImplementation,
        registrationEnvelope(PROVIDER_CONTROL_IMPLEMENTATION),
      ],
      [
        hub.registerInitialProviderPrefixAuthenticator,
        registrationEnvelope(authenticateInitialProviderPrefix),
      ],
      [
        hub.registerMutationReconciliationAuthenticator,
        registrationEnvelope(authenticateMutationReconciliation),
      ],
    ];
    for (const [registrar, envelope] of registrations) {
      if (
        typeof registrar !== 'function'
        || reflectApply(registrar, hub.bridgeReceiver, [envelope]) !== true
      ) return blockProviderControlBootstrap();
    }
    providerControlBootstrapState = 'REGISTERED';
    return true;
  } catch {
    return blockProviderControlBootstrap();
  }
}
