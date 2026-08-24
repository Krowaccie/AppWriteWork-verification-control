import { types as utilTypes } from 'node:util';

import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { canonicalJson, sha256Bytes } from '../../../scripts/verification/canonical-json.mjs';
import {
  closeLease,
  commitIntentSnapshot,
  consumeRunnerRequest,
  createRunnerRequest,
  markCleanupDebt,
  reconstructAuthoritativeIntents,
} from '../../../scripts/verification/test-cloud-control-store.mjs';
import {
  QUALIFIED_CLEANUP_PROTOCOL,
  createCleanupPhaseGenesisDigest,
  createCleanupProgressGenesisDigest,
  createCleanupProofGenesisDigest,
  createCleanupStepRequest,
  getCleanupResourceCatalog,
} from '../../../scripts/verification/test-cloud-cleanup-protocol.mjs';
import { isAuthenticTestCloudOperatorClient } from '../../../scripts/verification/test-cloud-appwrite.mjs';
import { isAuthenticTestEnvironmentContext } from '../../../scripts/verification/test-cloud-environment.mjs';
import {
  RUNNER_PROTOCOL_VERSION,
  mapRunnerExecution,
  parseRunnerRequest,
} from '../../../scripts/verification/runner-protocol.mjs';

const ARGUMENT_KEYS = Object.freeze([
  'context',
  'client',
  'store',
  'lease',
  'capability',
  'clock',
  'providerContractDigest',
]);
const CLOSED_LEASE_KEYS = Object.freeze([
  'leaseRowId',
  'leaseVersion',
  'state',
  'ownerRunId',
  'ownerWorkflowRunId',
  'environmentDigest',
  'acquiredAt',
  'renewedAt',
  'expiresAt',
  'ledgerDigest',
  'leaseTokenDigest',
  'cleanupDebt',
]);
const AUDIT_EVENT_KEYS = Object.freeze([
  'schemaVersion',
  'previousLedgerDigest',
  'runId',
  'leaseVersionBefore',
  'leaseVersionAfter',
  'transition',
  'intentId',
  'intentProjectionDigest',
]);
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const encoder = new TextEncoder();

function exactDataObject(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Reflect.ownKeys(value).length !== keys.length) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

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
      safeMessage: 'The trusted test-cloud cleanup was blocked.',
      retryable: false,
    }],
  });
}

const blocked = () => result('BLOCKED', null, 'TRUSTED_CLEANUP_DRIVER_BLOCKED');
const passed = (lease, predecessorLease, event) => result('PASS', {
  closed: true,
  lease,
  closeProof: { predecessorLease, event },
});
const digest = (value) => sha256Bytes(encoder.encode(canonicalJson(value)));
const iso = (clock) => new Date(clock.nowEpochSeconds() * 1000).toISOString();
const monotonicIso = (clock, prior) => {
  const current = iso(clock);
  return Date.parse(current) < Date.parse(prior) ? prior : current;
};

function exactClosedLease(candidate, prior, context) {
  const candidateFields = exactDataObject(candidate, CLOSED_LEASE_KEYS);
  const priorFields = exactDataObject(prior, CLOSED_LEASE_KEYS);
  if (
    candidateFields === null
    || priorFields === null
    || Object.getPrototypeOf(candidate) !== Object.prototype
    || Object.getPrototypeOf(prior) !== Object.prototype
    || !Object.isFrozen(candidate)
    || !Object.isFrozen(prior)
    || priorFields.leaseRowId !== inventory.control.leaseRowId
    || priorFields.state !== 'active'
    || priorFields.cleanupDebt !== false
    || priorFields.ownerRunId !== context.runId
    || typeof priorFields.ownerWorkflowRunId !== 'string'
    || priorFields.environmentDigest !== context.environmentDigest
    || !Number.isFinite(Date.parse(priorFields.acquiredAt))
    || !Number.isFinite(Date.parse(priorFields.renewedAt))
    || !Number.isFinite(Date.parse(priorFields.expiresAt))
    || Date.parse(priorFields.renewedAt) < Date.parse(priorFields.acquiredAt)
    || Date.parse(priorFields.expiresAt) <= Date.parse(priorFields.renewedAt)
    || !Number.isSafeInteger(priorFields.leaseVersion)
    || priorFields.leaseVersion < 0
    || !DIGEST.test(priorFields.ledgerDigest)
    || !DIGEST.test(priorFields.leaseTokenDigest)
  ) return null;
  const event = {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: priorFields.ledgerDigest,
    runId: context.runId,
    leaseVersionBefore: priorFields.leaseVersion,
    leaseVersionAfter: priorFields.leaseVersion + 1,
    transition: 'lease.close',
    intentId: null,
    intentProjectionDigest: null,
  };
  const expected = {
    ...priorFields,
    leaseVersion: priorFields.leaseVersion + 1,
    state: 'idle',
    ownerRunId: null,
    ownerWorkflowRunId: null,
    environmentDigest: null,
    acquiredAt: null,
    renewedAt: null,
    expiresAt: null,
    ledgerDigest: digest(event),
    leaseTokenDigest: null,
    cleanupDebt: false,
  };
  return canonicalJson(candidateFields) === canonicalJson(expected) ? event : null;
}

function exactBlockedRunnerRequest(value) {
  const diagnostic = Array.isArray(value?.diagnostics) && value.diagnostics.length === 1
    ? exactDataObject(value.diagnostics[0], ['code', 'safeMessage', 'retryable'])
    : null;
  return exactDataObject(value, ['status', 'value', 'diagnostics']) !== null
    && value.status === 'BLOCKED'
    && value.value === null
    && diagnostic !== null
    && diagnostic.code === 'LEASE_VERSION_MISMATCH'
    && diagnostic.retryable === false;
}

async function validateClosedGeneration(fields, predecessor, closed) {
  const event = exactClosedLease(closed, predecessor, fields.context);
  if (event === null) return null;
  const readback = await fields.store.getLease();
  if (
    exactDataObject(readback, CLOSED_LEASE_KEYS) === null
    || Object.getPrototypeOf(readback) !== Object.prototype
    || canonicalJson(readback) !== canonicalJson(closed)
  ) return null;
  const auditReadback = await fields.store.getAuditEventByDigest(closed.ledgerDigest);
  if (
    exactDataObject(auditReadback, AUDIT_EVENT_KEYS) === null
    || Object.getPrototypeOf(auditReadback) !== Object.prototype
    || canonicalJson(auditReadback) !== canonicalJson(event)
  ) return null;
  const scenario = {
    scenarioId: 'closed-generation-must-be-invalid',
    parameters: {},
  };
  const invalidated = exactBlockedRunnerRequest(createRunnerRequest({
    capability: fields.capability,
    lease: predecessor,
    context: fields.context,
    clock: fields.clock,
    scenario,
  })) && exactBlockedRunnerRequest(createRunnerRequest({
    capability: fields.capability,
    lease: closed,
    context: fields.context,
    clock: fields.clock,
    scenario,
  }));
  return invalidated ? event : null;
}

function cleanupGenesis(root, providerContractDigest, phase, phaseStepCount, extra = {}) {
  const catalog = getCleanupResourceCatalog(root.resourceType);
  return {
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest: root.environmentDigest,
    providerContractDigest,
    providerAggregateDigest: root.providerAggregateDigest,
    intentId: root.intentId,
    intentVersion: root.intentVersion,
    intentProjectionDigest: digest(root),
    logicalResource: root.resourceType,
    phase,
    phaseStepCount,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    ...extra,
  };
}

function slotsFor(snapshot, catalog) {
  if (snapshot.cleanupRunnerExecutionSlotsJson === null) {
    return Array(catalog.executionPlan.slotCount).fill(null);
  }
  const slots = JSON.parse(snapshot.cleanupRunnerExecutionSlotsJson);
  if (!Array.isArray(slots) || slots.length !== catalog.executionPlan.slotCount) throw new TypeError('slots');
  return structuredClone(slots);
}

function usedSlotAt(slots, logicalPosition) {
  return slots[logicalPosition * 2 + 1] ?? slots[logicalPosition * 2];
}

function retainExecutionId(fields, retainedExecutionId) {
  if (fields.retainedExecutionIds.has(retainedExecutionId)) return false;
  fields.retainedExecutionIds.add(retainedExecutionId);
  return true;
}

function executionRecordDigest(logicalResource, slots) {
  return digest({
    schemaVersion: 'verification-cleanup-execution-record.v1',
    logicalResource,
    slots,
  });
}

function selectStep(snapshot, root, providerContractDigest, slots) {
  const catalog = getCleanupResourceCatalog(root.resourceType);
  if (snapshot.state === 'created') {
    const cursor = snapshot.cleanupRunnerExecutionCursor ?? 0;
    if (cursor < 0 || cursor >= catalog.preflight.length
      || (snapshot.cleanupRunnerExecutionCursor !== null && slots[cursor * 2] !== null)) {
      throw new TypeError('preflight state');
    }
    const priorSafeStateDigest = cursor === 0
      ? createCleanupPhaseGenesisDigest(cleanupGenesis(
        root, providerContractDigest, 'preflight', catalog.preflight.length,
      ))
      : snapshot.cleanupProgressDigest;
    return {
      scenarioId: 'resource.cleanup_preflight_step',
      phase: 'preflight',
      phaseCursor: cursor,
      phaseStepCount: catalog.preflight.length,
      priorPhaseDigest: cursor === 0 ? null : snapshot.cleanupProgressDigest,
      cleanupCursor: 0,
      cleanupProgressDigest: null,
      cleanupProofDigest: null,
      logicalPosition: cursor,
      priorSafeStateDigest,
    };
  }
  if (snapshot.state !== 'cleaning') throw new TypeError('cleanup state');
  const logicalPosition = snapshot.cleanupRunnerExecutionCursor;
  if (snapshot.cleanupCursor < catalog.mutation.length) {
    const finalPreflight = usedSlotAt(slots, catalog.preflight.length - 1);
    if (finalPreflight === null) throw new TypeError('preflight proof');
    return {
      scenarioId: 'resource.cleanup_step',
      phase: 'cleanup',
      phaseCursor: 0,
      phaseStepCount: catalog.mutation.length,
      priorPhaseDigest: finalPreflight.safeStateDigest,
      cleanupCursor: snapshot.cleanupCursor,
      cleanupProgressDigest: snapshot.cleanupProgressDigest,
      cleanupProofDigest: null,
      logicalPosition,
      priorSafeStateDigest: snapshot.cleanupProgressDigest,
    };
  }
  if (snapshot.cleanupProofDigest === null) {
    const proofCursor = logicalPosition - catalog.preflight.length - catalog.mutation.length;
    if (proofCursor < 0 || proofCursor >= catalog.proof.length) throw new TypeError('proof cursor');
    const priorPhaseDigest = proofCursor === 0
      ? createCleanupProofGenesisDigest(cleanupGenesis(
        root,
        providerContractDigest,
        'proof',
        catalog.proof.length,
        { finalCleanupProgressDigest: snapshot.cleanupProgressDigest },
      ))
      : usedSlotAt(slots, logicalPosition - 1)?.safeStateDigest ?? null;
    const priorSafeStateDigest = priorPhaseDigest;
    if (priorPhaseDigest === null) throw new TypeError('proof state');
    return {
      scenarioId: 'resource.cleanup_proof_step',
      phase: 'proof',
      phaseCursor: proofCursor,
      phaseStepCount: catalog.proof.length,
      priorPhaseDigest,
      cleanupCursor: snapshot.cleanupCursor,
      cleanupProgressDigest: snapshot.cleanupProgressDigest,
      cleanupProofDigest: null,
      logicalPosition,
      priorSafeStateDigest,
    };
  }
  if (logicalPosition !== catalog.executionPlan.knownCalls - 1) throw new TypeError('terminal cursor');
  const finalProof = usedSlotAt(slots, logicalPosition - 1);
  if (finalProof === null || finalProof.safeStateDigest !== snapshot.cleanupProofDigest) {
    throw new TypeError('terminal proof');
  }
  return {
    scenarioId: 'resource.cleanup',
    phase: 'terminal',
    phaseCursor: catalog.proof.length,
    phaseStepCount: catalog.proof.length,
    priorPhaseDigest: snapshot.cleanupProofDigest,
    cleanupCursor: snapshot.cleanupCursor,
    cleanupProgressDigest: snapshot.cleanupProgressDigest,
    cleanupProofDigest: snapshot.cleanupProofDigest,
    logicalPosition,
    priorSafeStateDigest: snapshot.cleanupProofDigest,
  };
}

function buildExecution({ fields, snapshot, root, step }) {
  const catalog = getCleanupResourceCatalog(root.resourceType);
  const cleanupFence = {
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.fenceSchemaVersion,
    leaseVersion: fields.lease.leaseVersion,
    ledgerDigest: fields.lease.ledgerDigest,
    intentId: snapshot.intentId,
    intentVersion: snapshot.intentVersion,
    intentProjectionDigest: digest(snapshot),
    providerContractDigest: fields.providerContractDigest,
    providerAggregateDigest: snapshot.providerAggregateDigest,
    phase: step.phase,
    phaseCursor: step.phaseCursor,
    phaseStepCount: step.phaseStepCount,
    priorPhaseDigest: step.priorPhaseDigest,
    cleanupCursor: step.cleanupCursor,
    cleanupProgressDigest: step.cleanupProgressDigest,
    cleanupProofDigest: step.cleanupProofDigest,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    cleanupRunnerExecutionCursor: step.logicalPosition,
    cleanupRunnerExecutionRecordDigest: step.logicalPosition === 0
      ? null
      : snapshot.cleanupRunnerExecutionRecordDigest,
  };
  const cleanupRequest = createCleanupStepRequest({
    scenarioId: step.scenarioId,
    logicalResource: root.resourceType,
    cleanupFence,
  });
  const opaque = createRunnerRequest({
    capability: fields.capability,
    lease: fields.lease,
    context: fields.context,
    clock: fields.clock,
    scenario: {
      scenarioId: cleanupRequest.scenarioId,
      parameters: cleanupRequest.parameters,
    },
  });
  if (opaque.status !== 'PASS') throw new TypeError('runner request');
  const request = parseRunnerRequest({
    protocolVersion: RUNNER_PROTOCOL_VERSION,
    ...consumeRunnerRequest({ context: fields.context, runnerRequest: opaque.value }),
    environmentDigest: fields.context.environmentDigest,
    cleanupFence: cleanupRequest.cleanupFence,
  });
  return {
    request,
    body: { async: false, body: canonicalJson(request) },
  };
}

function mapInvocation(invocation, request, context) {
  const value = invocation?.status === 'PASS' ? invocation.value : null;
  const execution = value?.execution;
  const retainedExecutionId = typeof execution?.executionId === 'string'
    && PROVIDER_ID.test(execution.executionId) ? execution.executionId : null;
  const mapped = mapRunnerExecution({
    request,
    expectedRunnerRevision: context.candidateRevision,
    transportStatus: value?.transportStatus ?? null,
    execution: execution === null || execution === undefined ? null : {
      status: execution.status,
      responseStatusCode: execution.responseStatusCode,
      responseBody: execution.responseBody,
    },
  });
  return { mapped, retainedExecutionId };
}

function successfulStateDigest(step, envelope) {
  if (step.phase === 'preflight' || step.phase === 'proof') return envelope.data.phaseProgressDigest;
  if (step.phase === 'cleanup') return envelope.data.cleanupProgressDigest;
  return envelope.data.cleanupProofDigest;
}

function nextSnapshot({ snapshot, root, step, slots, slotIndex, retainedExecutionId,
  safeStateDigest, retentionExpiresAt, clock, advance }) {
  const catalog = getCleanupResourceCatalog(root.resourceType);
  slots[slotIndex] = {
    logicalPosition: step.logicalPosition,
    attemptOrdinal: slotIndex % 2 + 1,
    retainedExecutionId,
    safeStateDigest,
    retentionExpiresAt,
  };
  const base = {
    ...snapshot,
    intentVersion: snapshot.intentVersion + 1,
    cleanupCursor: snapshot.cleanupCursor ?? 0,
    cleanupProgressDigest: snapshot.cleanupProgressDigest ?? step.priorSafeStateDigest,
    cleanupProofDigest: snapshot.cleanupProofDigest,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    cleanupRunnerExecutionCursor: snapshot.cleanupRunnerExecutionCursor ?? 0,
    cleanupRunnerExecutionSlotsJson: canonicalJson(slots),
    cleanupRunnerExecutionRecordDigest: executionRecordDigest(root.resourceType, slots),
    cleanupRunnerExecutionRetentionExpiresAt: retentionExpiresAt,
    updatedAt: monotonicIso(clock, snapshot.updatedAt),
  };
  if (!advance) return base;
  base.cleanupRunnerExecutionCursor = step.logicalPosition + 1;
  if (step.phase === 'preflight') {
    if (base.cleanupRunnerExecutionCursor === catalog.preflight.length) {
      base.state = 'cleaning';
      base.cleanupProgressDigest = createCleanupProgressGenesisDigest(cleanupGenesis(
        root,
        step.providerContractDigest,
        'cleanup',
        catalog.mutation.length,
        { preflightDigest: safeStateDigest },
      ));
    } else {
      base.state = 'created';
      base.cleanupProgressDigest = safeStateDigest;
    }
  } else if (step.phase === 'cleanup') {
    base.cleanupCursor += 1;
    base.cleanupProgressDigest = safeStateDigest;
  } else if (step.phase === 'proof') {
    if (base.cleanupRunnerExecutionCursor === catalog.executionPlan.knownCalls - 1) {
      base.cleanupProofDigest = safeStateDigest;
    }
  } else {
    base.state = 'absent';
  }
  return base;
}

async function persist(fields, snapshot) {
  const committed = await commitIntentSnapshot({
    context: fields.context,
    store: fields.store,
    lease: fields.lease,
    capability: fields.capability,
    clock: fields.clock,
    snapshot,
  });
  if (committed.status !== 'PASS') return null;
  fields.lease = committed.value.lease;
  fields.capability = committed.value.capability;
  return committed.value.snapshot;
}

async function poison(fields) {
  try {
    await markCleanupDebt({
      context: fields.context,
      store: fields.store,
      lease: fields.lease,
      capability: fields.capability,
      clock: fields.clock,
    });
  } catch {
    // The closed result remains BLOCKED regardless of whether debt persistence itself fails.
  }
  return blocked();
}

async function driveResource(fields, root) {
  let snapshot = root;
  const catalog = getCleanupResourceCatalog(root.resourceType);
  const retentionExpiresAt = snapshot.cleanupRunnerExecutionRetentionExpiresAt
    ?? fields.cleanupRunnerExecutionRetentionExpiresAt;
  while (snapshot.state !== 'absent') {
    const slots = slotsFor(snapshot, catalog);
    const step = selectStep(snapshot, root, fields.providerContractDigest, slots);
    step.providerContractDigest = fields.providerContractDigest;
    const planned = buildExecution({ fields, snapshot, root, step });
    const invoke = async () => {
      try {
        return await fields.client.createFunctionExecution({
          functionId: inventory.control.runnerFunctionId,
          body: planned.body,
        });
      } catch {
        return null;
      }
    };

    const firstInvocation = await invoke();
    const first = mapInvocation(firstInvocation, planned.request, fields.context);
    if (first.retainedExecutionId === null) return poison(fields);
    if (!retainExecutionId(fields, first.retainedExecutionId)) return poison(fields);
    if (first.mapped.status === 'PASS') {
      const next = nextSnapshot({
        snapshot,
        root,
        step,
        slots,
        slotIndex: step.logicalPosition * 2,
        retainedExecutionId: first.retainedExecutionId,
        safeStateDigest: successfulStateDigest(step, first.mapped.envelope),
        retentionExpiresAt,
        clock: fields.clock,
        advance: true,
      });
      snapshot = await persist(fields, next);
      if (snapshot === null) return blocked();
      continue;
    }

    const checkpoint = nextSnapshot({
      snapshot,
      root,
      step,
      slots,
      slotIndex: step.logicalPosition * 2,
      retainedExecutionId: first.retainedExecutionId,
      safeStateDigest: step.priorSafeStateDigest,
      retentionExpiresAt,
      clock: fields.clock,
      advance: false,
    });
    snapshot = await persist(fields, checkpoint);
    if (snapshot === null) return blocked();
    if (first.mapped.code !== 'RUNNER_EXECUTION_INCOMPLETE') return poison(fields);

    const secondInvocation = await invoke();
    const second = mapInvocation(secondInvocation, planned.request, fields.context);
    if (second.retainedExecutionId === null) return poison(fields);
    if (!retainExecutionId(fields, second.retainedExecutionId)) return poison(fields);
    const secondSlots = slotsFor(snapshot, catalog);
    if (second.mapped.status !== 'PASS') {
      const retainedSecond = nextSnapshot({
        snapshot,
        root,
        step,
        slots: secondSlots,
        slotIndex: step.logicalPosition * 2 + 1,
        retainedExecutionId: second.retainedExecutionId,
        safeStateDigest: step.priorSafeStateDigest,
        retentionExpiresAt,
        clock: fields.clock,
        advance: false,
      });
      snapshot = await persist(fields, retainedSecond);
      return snapshot === null ? blocked() : poison(fields);
    }
    const next = nextSnapshot({
      snapshot,
      root,
      step,
      slots: secondSlots,
      slotIndex: step.logicalPosition * 2 + 1,
      retainedExecutionId: second.retainedExecutionId,
      safeStateDigest: successfulStateDigest(step, second.mapped.envelope),
      retentionExpiresAt,
      clock: fields.clock,
      advance: true,
    });
    snapshot = await persist(fields, next);
    if (snapshot === null) return blocked();
  }
  return snapshot;
}

export async function runTrustedTestCloudCleanup(args) {
  try {
    const values = exactDataObject(args, ARGUMENT_KEYS);
    if (values === null || !isAuthenticTestEnvironmentContext(values.context)
      || !isAuthenticTestCloudOperatorClient(values.client, values.context)
      || values.store === null || typeof values.store !== 'object'
      || values.clock === null || typeof values.clock !== 'object') return blocked();
    const nowEpochSecondsMethod = values.clock.nowEpochSeconds;
    if (typeof nowEpochSecondsMethod !== 'function'
      || typeof values.providerContractDigest !== 'string'
      || !DIGEST.test(values.providerContractDigest)) return blocked();
    const entryNowEpochSeconds = nowEpochSecondsMethod.call(values.clock);
    if (!Number.isSafeInteger(entryNowEpochSeconds)) return blocked();

    const reconstructed = await reconstructAuthoritativeIntents({
      store: values.store,
      lease: values.lease,
      primaryExecutionRetentionMaxSeconds: inventory.control.primaryExecutionRetentionMaxSeconds,
    });
    if (reconstructed.status !== 'PASS') return blocked();
    const fixtures = reconstructed.value.filter((snapshot) => (
      snapshot.schemaVersion === 'verification-intent-snapshot.v2'
      && snapshot.lifecycleClass === 'fixture'
    ));
    if (fixtures.length !== QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.length) return blocked();
    const byResource = new Map(fixtures.map((snapshot) => [snapshot.resourceType, snapshot]));
    if (byResource.size !== QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.length
      || QUALIFIED_CLEANUP_PROTOCOL.resourceOrder.some((resource) => !byResource.has(resource))) return blocked();

    // Durable cleanup debt is reconstructed here, but ordinary active-run cleanup
    // must never manufacture replacement authority for a null-capability handoff.
    if (values.capability === null) return blocked();

    const retainedExecutionIds = new Set();
    let priorRetentionExpiresAt = null;
    for (const fixture of fixtures) {
      if (fixture.cleanupRunnerExecutionSlotsJson === null) continue;
      if (priorRetentionExpiresAt === null) {
        priorRetentionExpiresAt = fixture.cleanupRunnerExecutionRetentionExpiresAt;
      } else if (fixture.cleanupRunnerExecutionRetentionExpiresAt !== priorRetentionExpiresAt) {
        return blocked();
      }
      for (const slot of slotsFor(fixture, getCleanupResourceCatalog(fixture.resourceType))) {
        if (slot === null) continue;
        if (retainedExecutionIds.has(slot.retainedExecutionId)) return blocked();
        retainedExecutionIds.add(slot.retainedExecutionId);
      }
    }
    const cleanupRunnerExecutionRetentionExpiresAt = priorRetentionExpiresAt
      ?? new Date((entryNowEpochSeconds
        + inventory.control.primaryExecutionRetentionMaxSeconds) * 1000).toISOString();
    const fields = {
      ...values,
      cleanupRunnerExecutionRetentionExpiresAt,
      retainedExecutionIds,
    };
    for (const logicalResource of QUALIFIED_CLEANUP_PROTOCOL.resourceOrder) {
      const root = byResource.get(logicalResource);
      if (root.state !== 'created' || root.cleanupRunnerExecutionCursor !== null) return blocked();
      const driven = await driveResource(fields, root);
      if (driven?.state !== 'absent') return blocked();
    }
    const closePredecessor = fields.lease;
    const closed = await closeLease({
      context: fields.context,
      store: fields.store,
      lease: closePredecessor,
      capability: fields.capability,
      clock: fields.clock,
    });
    if (
      exactDataObject(closed, ['status', 'value', 'diagnostics']) === null
      || closed.status !== 'PASS'
      || !Array.isArray(closed.diagnostics)
      || closed.diagnostics.length !== 0
    ) return blocked();
    const closeEvent = await validateClosedGeneration(fields, closePredecessor, closed.value);
    if (closeEvent === null) return blocked();
    return passed(closed.value, closePredecessor, closeEvent);
  } catch {
    return blocked();
  }
}
