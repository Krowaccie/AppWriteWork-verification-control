import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import { canonicalJson, sha256Bytes } from '../../../scripts/verification/canonical-json.mjs';
import { createTestCloudClients } from '../../../scripts/verification/test-cloud-appwrite.mjs';
import {
  QUALIFIED_CLEANUP_PROTOCOL,
  advanceCleanupPhaseDigest,
  advanceCleanupProgressDigest,
  advanceCleanupProofDigest,
  createCleanupPhaseGenesisDigest,
  createCleanupProgressGenesisDigest,
  createCleanupProofGenesisDigest,
  createCleanupStepRequest,
  getCleanupResourceCatalog,
  parseCleanupStepResponse,
} from '../../../scripts/verification/test-cloud-cleanup-protocol.mjs';
import {
  RUNNER_PROTOCOL_VERSION,
  mapRunnerExecution,
  parseRunnerRequest,
} from '../../../scripts/verification/runner-protocol.mjs';
import {
  authenticPreflight,
  createSyntheticTestCloudContext,
  loadSyntheticControlModule,
} from '../../../scripts/verification/test-cloud-control-test-helper.mjs';

const {
  acquireLease,
  commitIntentSnapshot,
  consumeRunnerRequest,
  createInMemoryControlStore,
  createRunnerRequest,
  createTestCloudPreflightHandoff,
} = await loadSyntheticControlModule();

const dataModule = (source) =>
  `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const controlStoreUrl = new URL(
  '../../../scripts/verification/test-cloud-control-store.mjs',
  import.meta.url,
);
const syntheticControlFacade = dataModule(`
  import { loadSyntheticControlModule } from ${JSON.stringify(
    new URL('../../../scripts/verification/test-cloud-control-test-helper.mjs', import.meta.url).href,
  )};
  const control = await loadSyntheticControlModule();
  export async function closeLease(args) {
    const override = globalThis[Symbol.for('appwritework.test-cloud.cleanup-close-override.v1')];
    return typeof override === 'function' ? override(args) : control.closeLease(args);
  }
  export const commitIntentSnapshot = control.commitIntentSnapshot;
  export const consumeRunnerRequest = control.consumeRunnerRequest;
  export const createRunnerRequest = control.createRunnerRequest;
  export const markCleanupDebt = control.markCleanupDebt;
  export const reconstructAuthoritativeIntents = control.reconstructAuthoritativeIntents;
`);
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (
      context.parentURL !== undefined
      && new URL(specifier, context.parentURL).href === controlStoreUrl.href
    ) {
      return { url: syntheticControlFacade, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});
let cleanupDriverModule;
try {
  cleanupDriverModule = await import(
    new URL('./test-cloud-cleanup-driver.mjs?synthetic-control', import.meta.url)
  );
} catch {
  cleanupDriverModule = null;
} finally {
  hooks.deregister();
}

const encoder = new TextEncoder();
const digest = (value) => sha256Bytes(encoder.encode(canonicalJson(value)));
const clock = (now) => Object.freeze({ nowEpochSeconds: () => now });
const at = (now) => new Date(now * 1000).toISOString();
const SANITIZED_BLOCKED = {
  status: 'BLOCKED',
  value: null,
  diagnostics: [{
    code: 'TRUSTED_CLEANUP_DRIVER_BLOCKED',
    safeMessage: 'The trusted test-cloud cleanup was blocked.',
    retryable: false,
  }],
};

async function observeCleanupInvocation(args) {
  try {
    return {
      escaped: false,
      outcome: await cleanupDriverModule.runTrustedTestCloudCleanup(args),
    };
  } catch {
    return { escaped: true, outcome: null };
  }
}

test('cleanup driver exposes one closed trusted entrypoint', () => {
  assert.notEqual(cleanupDriverModule, null, 'test-cloud-cleanup-driver.mjs is missing');
  assert.deepEqual(Object.keys(cleanupDriverModule), ['runTrustedTestCloudCleanup']);
  assert.equal(typeof cleanupDriverModule.runTrustedTestCloudCleanup, 'function');
});

test('cleanup driver sanitizes a throwing clock accessor before any provider call', async () => {
  const harness = await createDriverHarness();
  let accessorReads = 0;
  const hostileClock = Object.defineProperty({}, 'nowEpochSeconds', {
    enumerable: true,
    get() {
      accessorReads += 1;
      throw new Error('hostile accessor detail');
    },
  });

  const observed = await observeCleanupInvocation({ ...harness.args, clock: hostileClock });

  assert.deepEqual(observed, { escaped: false, outcome: SANITIZED_BLOCKED });
  assert.equal(accessorReads, 1);
  assert.equal(harness.calls.length, 0);
});

test('cleanup driver sanitizes throwing clock methods and proxy traps', async () => {
  const harness = await createDriverHarness();
  let proxyReads = 0;
  const hostileClocks = [
    Object.freeze({
      nowEpochSeconds() {
        throw new Error('hostile method detail');
      },
    }),
    new Proxy(Object.create(null), {
      get() {
        proxyReads += 1;
        throw new Error('hostile proxy detail');
      },
    }),
  ];
  const observed = [];
  for (const hostileClock of hostileClocks) {
    observed.push(await observeCleanupInvocation({ ...harness.args, clock: hostileClock }));
  }

  assert.deepEqual(observed, hostileClocks.map(() => ({
    escaped: false,
    outcome: SANITIZED_BLOCKED,
  })));
  assert.equal(proxyReads, 1);
  assert.equal(harness.calls.length, 0);
});

test('cleanup driver rejects a non-string digest without hostile coercion', async () => {
  const harness = await createDriverHarness();
  let coercionTraps = 0;
  const hostileDigest = {
    [Symbol.toPrimitive]() {
      coercionTraps += 1;
      throw new Error('hostile digest detail');
    },
  };

  const observed = await observeCleanupInvocation({
    ...harness.args,
    providerContractDigest: hostileDigest,
  });

  assert.deepEqual(observed, { escaped: false, outcome: SANITIZED_BLOCKED });
  assert.equal(coercionTraps, 0);
  assert.equal(harness.calls.length, 0);
});

test('first successful preflight call has a durable retained slot before the second call', async () => {
  const { context, credentialHandles } = createSyntheticTestCloudContext();
  const aggregate = Object.freeze({
    schemaVersion: 'verification-provider-aggregate.v1',
    phase: 'shared',
  });
  const cleanupFields = {
    cleanupCursor: null,
    cleanupProgressDigest: null,
    cleanupProofDigest: null,
    cleanupRunnerExecutionPlanDigest: null,
    cleanupRunnerExecutionCursor: null,
    cleanupRunnerExecutionSlotsJson: null,
    cleanupRunnerExecutionRecordDigest: null,
    cleanupRunnerExecutionRetentionExpiresAt: null,
  };
  const planned = {
    schemaVersion: 'verification-intent-snapshot.v2',
    intentId: '9'.repeat(64),
    runId: context.runId,
    environmentDigest: context.environmentDigest,
    resourceType: 'primary-share',
    resourceId: 'vr-primary-share',
    providerAggregateJson: canonicalJson(aggregate),
    providerAggregateDigest: digest(aggregate),
    ownerMarker: `verification-owner.v1:sha256:${'a'.repeat(64)}`,
    dependencyOrder: 30,
    lifecycleClass: 'fixture',
    state: 'planned',
    intentVersion: 1,
    observationDigest: null,
    retentionExpiresAt: null,
    ...cleanupFields,
    createdAt: at(1002),
    updatedAt: at(1002),
  };
  const prepareCreated = async (randomByte) => {
    const store = createInMemoryControlStore();
    const preflight = await authenticPreflight(context, store, 1000);
    const handoff = createTestCloudPreflightHandoff({
      context,
      preflight: preflight.preflight,
      clock: clock(1000),
    });
    assert.equal(handoff.status, 'PASS');
    const acquired = await acquireLease({
      store,
      context,
      handoff: handoff.value,
      clock: clock(1001),
      randomBytes: () => Buffer.alloc(32, randomByte),
    });
    assert.equal(acquired.status, 'PASS');
    let { lease, capability } = acquired.value;
    const commit = async (snapshot, now) => {
      const outcome = await commitIntentSnapshot({
        context,
        store,
        lease,
        capability,
        clock: clock(now),
        snapshot,
      });
      if (outcome.status === 'PASS') {
        lease = outcome.value.lease;
        capability = outcome.value.capability;
      }
      return outcome;
    };
    assert.equal((await commit(planned, 1002)).status, 'PASS');
    const created = { ...planned, state: 'created', intentVersion: 2, updatedAt: at(1003) };
    assert.equal((await commit(created, 1003)).status, 'PASS');
    return {
      preflight,
      created,
      commit,
      current: () => ({ lease, capability }),
    };
  };
  const candidate = await prepareCreated(6);
  const control = await prepareCreated(7);
  const { preflight, created, commit } = candidate;
  const { lease, capability } = candidate.current();
  assert.deepEqual(control.created, created);

  const logicalResource = 'primary-share';
  const scenarioId = 'resource.cleanup_preflight_step';
  const catalog = getCleanupResourceCatalog(logicalResource);
  const providerContractDigest = preflight.provenance.safeDigests.providerContractDigest;
  const digestGenesis = (phase, phaseStepCount, extra = {}) => ({
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest: context.environmentDigest,
    providerContractDigest,
    providerAggregateDigest: created.providerAggregateDigest,
    intentId: created.intentId,
    intentVersion: created.intentVersion,
    intentProjectionDigest: digest(created),
    logicalResource,
    phase,
    phaseStepCount,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    ...extra,
  });
  let phaseDigest = createCleanupPhaseGenesisDigest(
    digestGenesis('preflight', catalog.preflight.length),
  );
  const phaseDigests = [];
  for (let phaseCursor = 0; phaseCursor < catalog.preflight.length; phaseCursor += 1) {
    phaseDigest = advanceCleanupPhaseDigest({
      priorPhaseDigest: phaseDigest,
      logicalResource,
      phase: 'preflight',
      phaseCursor,
      stepId: catalog.preflight[phaseCursor].stepId,
      result: QUALIFIED_CLEANUP_PROTOCOL.result,
    });
    phaseDigests.push(phaseDigest);
  }
  const cleanupProgressDigest = createCleanupProgressGenesisDigest(
    digestGenesis('cleanup', catalog.mutation.length, {
      preflightDigest: phaseDigests.at(-1),
    }),
  );
  const cleanupFence = {
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.fenceSchemaVersion,
    leaseVersion: lease.leaseVersion,
    ledgerDigest: lease.ledgerDigest,
    intentId: created.intentId,
    intentVersion: created.intentVersion,
    intentProjectionDigest: digest(created),
    providerContractDigest,
    providerAggregateDigest: created.providerAggregateDigest,
    phase: 'preflight',
    phaseCursor: 0,
    phaseStepCount: catalog.preflight.length,
    priorPhaseDigest: null,
    cleanupCursor: 0,
    cleanupProgressDigest: null,
    cleanupProofDigest: null,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    cleanupRunnerExecutionCursor: 0,
    cleanupRunnerExecutionRecordDigest: null,
  };
  const cleanupRequest = createCleanupStepRequest({
    scenarioId,
    logicalResource,
    cleanupFence,
  });
  const opaqueRequest = createRunnerRequest({
    capability,
    lease,
    context,
    clock: clock(1004),
    scenario: {
      scenarioId: cleanupRequest.scenarioId,
      parameters: cleanupRequest.parameters,
    },
  });
  assert.equal(opaqueRequest.status, 'PASS');
  const request = parseRunnerRequest({
    protocolVersion: RUNNER_PROTOCOL_VERSION,
    ...consumeRunnerRequest({ context, runnerRequest: opaqueRequest.value }),
    environmentDigest: context.environmentDigest,
    cleanupFence: cleanupRequest.cleanupFence,
  });
  const response = parseCleanupStepResponse({
    scenarioId,
    logicalResource,
    environmentDigest: context.environmentDigest,
    cleanupFence: cleanupRequest.cleanupFence,
    response: {
      logicalResource,
      nextPhaseCursor: 1,
      phaseProgressDigest: phaseDigests[0],
    },
  });
  const envelope = {
    protocolVersion: RUNNER_PROTOCOL_VERSION,
    scenarioId,
    runId: context.runId,
    status: 'passed',
    durationMs: 1,
    data: response,
  };
  const calls = [];
  const fetch = async (url, options) => {
    calls.push({ url, options });
    const transport = JSON.parse(options.body);
    assert.equal(transport.async, false);
    assert.deepEqual(JSON.parse(transport.body), request);
    return new Response(JSON.stringify({
      $id: 'cleanup-preflight-execution-0',
      status: 'completed',
      responseStatusCode: 200,
      responseBody: canonicalJson(envelope),
    }), {
      status: 201,
      headers: { 'content-type': 'application/json' },
    });
  };
  const clients = createTestCloudClients({ context, credentialHandles, fetch });
  assert.equal(clients.status, 'PASS');
  const invocation = await clients.value.operator.createFunctionExecution({
    functionId: inventory.control.runnerFunctionId,
    body: { async: false, body: canonicalJson(request) },
  });
  assert.equal(invocation.status, 'PASS');
  assert.equal(calls.length, 1);
  const mapped = mapRunnerExecution({
    request,
    expectedRunnerRevision: context.candidateRevision,
    transportStatus: invocation.value.transportStatus,
    execution: {
      status: invocation.value.execution.status,
      responseStatusCode: invocation.value.execution.responseStatusCode,
      responseBody: invocation.value.execution.responseBody,
    },
  });
  assert.equal(mapped.status, 'PASS');

  const retentionExpiresAt = at(1004 + inventory.control.primaryExecutionRetentionMaxSeconds);
  const executionSlot = (logicalPosition, retainedExecutionId, safeStateDigest) => ({
    logicalPosition,
    attemptOrdinal: 1,
    retainedExecutionId,
    safeStateDigest,
    retentionExpiresAt,
  });
  const fullSlots = Array(catalog.executionPlan.slotCount).fill(null);
  for (let logicalPosition = 0; logicalPosition < catalog.preflight.length; logicalPosition += 1) {
    fullSlots[logicalPosition * 2] = executionSlot(
      logicalPosition,
      logicalPosition === 0
        ? invocation.value.execution.executionId
        : `synthetic-preflight-execution-${logicalPosition}`,
      phaseDigests[logicalPosition],
    );
  }
  const recordDigest = (slots) => digest({
    schemaVersion: 'verification-cleanup-execution-record.v1',
    logicalResource,
    slots,
  });
  const checkpoint = (slots, cleanupRunnerExecutionCursor) => ({
    ...created,
    state: cleanupRunnerExecutionCursor === catalog.preflight.length ? 'cleaning' : 'created',
    intentVersion: created.intentVersion + cleanupRunnerExecutionCursor,
    cleanupCursor: 0,
    cleanupProgressDigest: cleanupRunnerExecutionCursor === catalog.preflight.length
      ? cleanupProgressDigest
      : phaseDigests[cleanupRunnerExecutionCursor - 1],
    cleanupProofDigest: null,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    cleanupRunnerExecutionCursor,
    cleanupRunnerExecutionSlotsJson: canonicalJson(slots),
    cleanupRunnerExecutionRecordDigest: recordDigest(slots),
    cleanupRunnerExecutionRetentionExpiresAt: retentionExpiresAt,
    updatedAt: at(1003 + cleanupRunnerExecutionCursor),
  });

  const firstSlots = Array(catalog.executionPlan.slotCount).fill(null);
  firstSlots[0] = executionSlot(
    0,
    invocation.value.execution.executionId,
    response.phaseProgressDigest,
  );
  const firstOutcome = await commit(checkpoint(firstSlots, 1), 1004);

  assert.equal(
    control.preflight.provenance.safeDigests.providerContractDigest,
    providerContractDigest,
  );
  const controlSlots = Array(catalog.executionPlan.slotCount).fill(null);
  let fullControl = null;
  for (let cursor = 1; cursor <= catalog.preflight.length; cursor += 1) {
    controlSlots[(cursor - 1) * 2] = fullSlots[(cursor - 1) * 2];
    fullControl = await control.commit(
      checkpoint(controlSlots, cursor),
      1003 + cursor,
    );
    assert.equal(fullControl.status, 'PASS', `control cursor ${cursor}: ${JSON.stringify(fullControl)}`);
  }
  assert.equal(
    firstOutcome.status,
    'PASS',
    `the first canonical outer-call slot must be durable before the second call: ${
      firstOutcome.diagnostics[0]?.code ?? 'no diagnostic'
    }`,
  );
});

function cleanupGenesisFromFence(request, logicalResource, phase, phaseStepCount, extra = {}) {
  const fence = request.cleanupFence;
  return {
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest: request.environmentDigest,
    providerContractDigest: fence.providerContractDigest,
    providerAggregateDigest: fence.providerAggregateDigest,
    intentId: fence.intentId,
    intentVersion: fence.intentVersion,
    intentProjectionDigest: fence.intentProjectionDigest,
    logicalResource,
    phase,
    phaseStepCount,
    cleanupRunnerExecutionPlanDigest: fence.cleanupRunnerExecutionPlanDigest,
    ...extra,
  };
}

function successfulCleanupData(request) {
  const { cleanupFence: fence, scenarioId } = request;
  const logicalResource = request.parameters.logicalResource;
  const catalog = getCleanupResourceCatalog(logicalResource);
  if (scenarioId === 'resource.cleanup_preflight_step') {
    const prior = fence.phaseCursor === 0
      ? createCleanupPhaseGenesisDigest(cleanupGenesisFromFence(
        request,
        logicalResource,
        'preflight',
        catalog.preflight.length,
      ))
      : fence.priorPhaseDigest;
    const phaseProgressDigest = advanceCleanupPhaseDigest({
      priorPhaseDigest: prior,
      logicalResource,
      phase: 'preflight',
      phaseCursor: fence.phaseCursor,
      stepId: catalog.preflight[fence.phaseCursor].stepId,
      result: QUALIFIED_CLEANUP_PROTOCOL.result,
    });
    return { logicalResource, nextPhaseCursor: fence.phaseCursor + 1, phaseProgressDigest };
  }
  if (scenarioId === 'resource.cleanup_step') {
    const cleanupProgressDigest = advanceCleanupProgressDigest({
      priorCleanupProgressDigest: fence.cleanupProgressDigest,
      logicalResource,
      cleanupCursor: fence.cleanupCursor,
      stepId: catalog.mutation[fence.cleanupCursor].stepId,
      result: QUALIFIED_CLEANUP_PROTOCOL.result,
    });
    return { logicalResource, nextCleanupCursor: fence.cleanupCursor + 1, cleanupProgressDigest };
  }
  if (scenarioId === 'resource.cleanup_proof_step') {
    const phaseProgressDigest = advanceCleanupProofDigest({
      priorCleanupProofDigest: fence.priorPhaseDigest,
      logicalResource,
      proofCursor: fence.phaseCursor,
      stepId: catalog.proof[fence.phaseCursor].stepId,
      result: QUALIFIED_CLEANUP_PROTOCOL.result,
    });
    return {
      logicalResource,
      nextPhaseCursor: fence.phaseCursor + 1,
      phaseProgressDigest,
      cleanupProofDigest: fence.phaseCursor + 1 === catalog.proof.length
        ? phaseProgressDigest
        : null,
    };
  }
  return {
    logicalResource,
    deleted: true,
    absenceProven: true,
    cleanupProofDigest: fence.cleanupProofDigest,
  };
}

async function createDriverHarness({ mode = 'success', resources = QUALIFIED_CLEANUP_PROTOCOL.resourceOrder } = {}) {
  const { context, credentialHandles } = createSyntheticTestCloudContext();
  const store = createInMemoryControlStore();
  const preflight = await authenticPreflight(context, store, 1000);
  const providerContractDigest = preflight.provenance.safeDigests.providerContractDigest;
  const handoff = createTestCloudPreflightHandoff({
    context,
    preflight: preflight.preflight,
    clock: clock(1000),
  });
  assert.equal(handoff.status, 'PASS');
  const acquired = await acquireLease({
    context,
    store,
    handoff: handoff.value,
    clock: clock(1001),
    randomBytes: () => Buffer.alloc(32, 23),
  });
  assert.equal(acquired.status, 'PASS');
  let { lease, capability } = acquired.value;
  const roots = new Map();
  const resourceMeta = {
    'primary-share': { dependencyOrder: 30, id: '9' },
    'primary-graph': { dependencyOrder: 20, id: '8' },
    'primary-project': { dependencyOrder: 10, id: '7' },
  };
  let setupNow = 1002;
  for (const logicalResource of resources) {
    const aggregate = {
      schemaVersion: 'verification-provider-aggregate.v1',
      logicalResource,
    };
    const meta = resourceMeta[logicalResource];
    const planned = {
      schemaVersion: 'verification-intent-snapshot.v2',
      intentId: meta.id.repeat(64),
      runId: context.runId,
      environmentDigest: context.environmentDigest,
      resourceType: logicalResource,
      resourceId: `vr-${logicalResource}`,
      providerAggregateJson: canonicalJson(aggregate),
      providerAggregateDigest: digest(aggregate),
      ownerMarker: `verification-owner.v1:sha256:${meta.id.repeat(64)}`,
      dependencyOrder: meta.dependencyOrder,
      lifecycleClass: 'fixture',
      state: 'planned',
      intentVersion: 1,
      observationDigest: null,
      retentionExpiresAt: null,
      cleanupCursor: null,
      cleanupProgressDigest: null,
      cleanupProofDigest: null,
      cleanupRunnerExecutionPlanDigest: null,
      cleanupRunnerExecutionCursor: null,
      cleanupRunnerExecutionSlotsJson: null,
      cleanupRunnerExecutionRecordDigest: null,
      cleanupRunnerExecutionRetentionExpiresAt: null,
      createdAt: at(setupNow),
      updatedAt: at(setupNow),
    };
    const created = { ...planned, state: 'created', intentVersion: 2, updatedAt: at(setupNow + 1) };
    for (const snapshot of [planned, created]) {
      const committed = await commitIntentSnapshot({
        context,
        store,
        lease,
        capability,
        clock: clock(setupNow),
        snapshot,
      });
      assert.equal(committed.status, 'PASS', JSON.stringify(committed));
      lease = committed.value.lease;
      capability = committed.value.capability;
      setupNow += 1;
    }
    roots.set(logicalResource, created);
  }

  const calls = [];
  const attempts = new Map();
  const fetch = async (_url, options) => {
    const request = JSON.parse(JSON.parse(options.body).body);
    const logicalResource = request.parameters.logicalResource;
    const position = request.cleanupFence.cleanupRunnerExecutionCursor;
    const key = `${logicalResource}:${position}`;
    const attempt = (attempts.get(key) ?? 0) + 1;
    attempts.set(key, attempt);
    calls.push({ logicalResource, position, scenarioId: request.scenarioId, attempt, request });

    let behavior = 'success';
    if (mode === 'ambiguous-first-everywhere' && attempt === 1) behavior = 'ambiguous';
    if (mode === 'always-ambiguous') behavior = 'ambiguous';
    const ambiguousScenario = {
      'second-nonpass-preflight': 'resource.cleanup_preflight_step',
      'second-nonpass-mutation': 'resource.cleanup_step',
      'second-nonpass-proof': 'resource.cleanup_proof_step',
      'second-nonpass-terminal': 'resource.cleanup',
    }[mode];
    if (request.scenarioId === ambiguousScenario) behavior = 'ambiguous';
    if (mode === 'reordered-first' && logicalResource === 'primary-share' && position === 0) behavior = 'reordered';
    if (mode === 'incomplete-terminal' && request.scenarioId === 'resource.cleanup') behavior = 'incomplete-terminal';

    const executionId = mode === 'duplicate-across-resources' && position === 0
      ? 'cleanup-cross-resource-duplicate'
      : `cleanup-${logicalResource}-${position}-${attempt}`;
    if (behavior === 'ambiguous') {
      return new Response(JSON.stringify({
        $id: executionId,
        status: 'processing',
        responseStatusCode: 0,
        responseBody: '',
      }), { status: 201, headers: { 'content-type': 'application/json' } });
    }

    const data = successfulCleanupData(request);
    if (behavior === 'reordered') {
      if (Object.hasOwn(data, 'nextPhaseCursor')) data.nextPhaseCursor += 1;
      if (Object.hasOwn(data, 'nextCleanupCursor')) data.nextCleanupCursor += 1;
    }
    if (behavior === 'incomplete-terminal') data.absenceProven = false;
    const envelope = {
      protocolVersion: RUNNER_PROTOCOL_VERSION,
      scenarioId: request.scenarioId,
      runId: context.runId,
      status: 'passed',
      durationMs: 1,
      data,
    };
    return new Response(JSON.stringify({
      $id: executionId,
      status: 'completed',
      responseStatusCode: 200,
      responseBody: canonicalJson(envelope),
    }), { status: 201, headers: { 'content-type': 'application/json' } });
  };
  const clients = createTestCloudClients({ context, credentialHandles, fetch });
  assert.equal(clients.status, 'PASS');
  return {
    args: {
      context,
      client: clients.value.operator,
      store,
      lease,
      capability,
      clock: clock(2000),
      providerContractDigest,
    },
    calls,
    roots,
    store,
  };
}

test('the first logical position reuses the exact planned request for its one second attempt', async () => {
  const harness = await createDriverHarness({ mode: 'ambiguous-first-everywhere' });
  const root = harness.roots.get('primary-share');
  const catalog = getCleanupResourceCatalog(root.resourceType);
  const retentionExpiresAt = at(2000 + inventory.control.primaryExecutionRetentionMaxSeconds);
  const phaseGenesisDigest = createCleanupPhaseGenesisDigest({
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest: root.environmentDigest,
    providerContractDigest: harness.args.providerContractDigest,
    providerAggregateDigest: root.providerAggregateDigest,
    intentId: root.intentId,
    intentVersion: root.intentVersion,
    intentProjectionDigest: digest(root),
    logicalResource: root.resourceType,
    phase: 'preflight',
    phaseStepCount: catalog.preflight.length,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
  });
  const cleanupFence = {
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.fenceSchemaVersion,
    leaseVersion: harness.args.lease.leaseVersion,
    ledgerDigest: harness.args.lease.ledgerDigest,
    intentId: root.intentId,
    intentVersion: root.intentVersion,
    intentProjectionDigest: digest(root),
    providerContractDigest: harness.args.providerContractDigest,
    providerAggregateDigest: root.providerAggregateDigest,
    phase: 'preflight',
    phaseCursor: 0,
    phaseStepCount: catalog.preflight.length,
    priorPhaseDigest: null,
    cleanupCursor: 0,
    cleanupProgressDigest: null,
    cleanupProofDigest: null,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    cleanupRunnerExecutionCursor: 0,
    cleanupRunnerExecutionRecordDigest: null,
  };
  const cleanupRequest = createCleanupStepRequest({
    scenarioId: 'resource.cleanup_preflight_step',
    logicalResource: root.resourceType,
    cleanupFence,
  });
  const opaque = createRunnerRequest({
    capability: harness.args.capability,
    lease: harness.args.lease,
    context: harness.args.context,
    clock: harness.args.clock,
    scenario: {
      scenarioId: cleanupRequest.scenarioId,
      parameters: cleanupRequest.parameters,
    },
  });
  assert.equal(opaque.status, 'PASS');
  const request = parseRunnerRequest({
    protocolVersion: RUNNER_PROTOCOL_VERSION,
    ...consumeRunnerRequest({ context: harness.args.context, runnerRequest: opaque.value }),
    environmentDigest: harness.args.context.environmentDigest,
    cleanupFence: cleanupRequest.cleanupFence,
  });
  const body = { async: false, body: canonicalJson(request) };
  const invoke = () => harness.args.client.createFunctionExecution({
    functionId: inventory.control.runnerFunctionId,
    body,
  });
  const map = (invocation) => mapRunnerExecution({
    request,
    expectedRunnerRevision: harness.args.context.candidateRevision,
    transportStatus: invocation.value.transportStatus,
    execution: {
      status: invocation.value.execution.status,
      responseStatusCode: invocation.value.execution.responseStatusCode,
      responseBody: invocation.value.execution.responseBody,
    },
  });

  const firstInvocation = await invoke();
  assert.equal(firstInvocation.status, 'PASS');
  assert.equal(map(firstInvocation).status, 'FAIL');
  const slots = Array(catalog.executionPlan.slotCount).fill(null);
  slots[0] = {
    logicalPosition: 0,
    attemptOrdinal: 1,
    retainedExecutionId: firstInvocation.value.execution.executionId,
    safeStateDigest: phaseGenesisDigest,
    retentionExpiresAt,
  };
  const recordDigest = (value) => digest({
    schemaVersion: 'verification-cleanup-execution-record.v1',
    logicalResource: root.resourceType,
    slots: value,
  });
  const checkpoint = {
    ...root,
    intentVersion: root.intentVersion + 1,
    cleanupCursor: 0,
    cleanupProgressDigest: phaseGenesisDigest,
    cleanupProofDigest: null,
    cleanupRunnerExecutionPlanDigest: catalog.executionPlan.digest,
    cleanupRunnerExecutionCursor: 0,
    cleanupRunnerExecutionSlotsJson: canonicalJson(slots),
    cleanupRunnerExecutionRecordDigest: recordDigest(slots),
    cleanupRunnerExecutionRetentionExpiresAt: retentionExpiresAt,
    updatedAt: at(2000),
  };
  const committed = await commitIntentSnapshot({
    context: harness.args.context,
    store: harness.store,
    lease: harness.args.lease,
    capability: harness.args.capability,
    clock: harness.args.clock,
    snapshot: checkpoint,
  });
  assert.equal(committed.status, 'PASS', JSON.stringify(committed));

  const secondInvocation = await invoke();
  assert.equal(secondInvocation.status, 'PASS', JSON.stringify(secondInvocation));
  const mapped = map(secondInvocation);
  assert.equal(mapped.status, 'PASS', JSON.stringify(mapped));
  assert.equal(harness.calls.length, 2);
  assert.equal(canonicalJson(harness.calls[0].request), canonicalJson(harness.calls[1].request));
  slots[1] = {
    logicalPosition: 0,
    attemptOrdinal: 2,
    retainedExecutionId: secondInvocation.value.execution.executionId,
    safeStateDigest: mapped.envelope.data.phaseProgressDigest,
    retentionExpiresAt,
  };
  const advanced = await commitIntentSnapshot({
    context: harness.args.context,
    store: harness.store,
    lease: committed.value.lease,
    capability: committed.value.capability,
    clock: harness.args.clock,
    snapshot: {
      ...checkpoint,
      intentVersion: checkpoint.intentVersion + 1,
      cleanupProgressDigest: mapped.envelope.data.phaseProgressDigest,
      cleanupRunnerExecutionCursor: 1,
      cleanupRunnerExecutionSlotsJson: canonicalJson(slots),
      cleanupRunnerExecutionRecordDigest: recordDigest(slots),
      updatedAt: at(2001),
    },
  });
  assert.equal(advanced.status, 'PASS', JSON.stringify(advanced));
});

test('cleanup driver selects immutable catalogs and closes after exactly 131 ordered calls', async () => {
  const harness = await createDriverHarness();
  for (const forbidden of [
    { catalog: [] },
    { logicalOrdinal: 0 },
    { retainedExecutionIds: [] },
    { resourceId: 'vr-primary-share' },
    { retryCount: 1 },
  ]) {
    const outcome = await cleanupDriverModule.runTrustedTestCloudCleanup({ ...harness.args, ...forbidden });
    assert.equal(outcome.status, 'BLOCKED');
    assert.equal(harness.calls.length, 0);
  }

  const outcome = await cleanupDriverModule.runTrustedTestCloudCleanup(harness.args);
  assert.equal(outcome.status, 'PASS', JSON.stringify({
    outcome,
    callCount: harness.calls.length,
    lastCall: harness.calls.at(-1),
  }));
  assert.deepEqual(Object.keys(outcome.value).sort(), ['closeProof', 'closed', 'lease']);
  assert.equal(outcome.value.closed, true);
  assert.deepEqual(Object.keys(outcome.value.closeProof).sort(), ['event', 'predecessorLease']);
  assert.equal(Object.isFrozen(outcome.value.closeProof), true);
  assert.equal(Object.getPrototypeOf(outcome.value.closeProof), Object.prototype);
  assert.notEqual(outcome.value.closeProof.predecessorLease, outcome.value.lease);
  assert.equal(Object.isFrozen(outcome.value.closeProof.predecessorLease), true);
  assert.equal(Object.getPrototypeOf(outcome.value.closeProof.predecessorLease), Object.prototype);
  assert.equal(Object.isFrozen(outcome.value.closeProof.event), true);
  assert.equal(Object.getPrototypeOf(outcome.value.closeProof.event), Object.prototype);
  for (const record of [
    outcome.value.closeProof,
    outcome.value.closeProof.predecessorLease,
    outcome.value.closeProof.event,
  ]) {
    assert.equal(Object.values(Object.getOwnPropertyDescriptors(record)).every(
      (descriptor) => Object.hasOwn(descriptor, 'value')
        && descriptor.enumerable === true
        && descriptor.configurable === false
        && descriptor.writable === false,
    ), true);
  }
  assert.doesNotMatch(
    JSON.stringify(outcome.value.closeProof),
    /capability|store|client|callback|"leaseToken":/u,
  );
  assert.equal(outcome.value.lease.state, 'idle');
  assert.deepEqual(Object.keys(outcome.value.lease).sort(), [
    'acquiredAt', 'cleanupDebt', 'environmentDigest', 'expiresAt', 'leaseRowId',
    'leaseTokenDigest', 'leaseVersion', 'ledgerDigest', 'ownerRunId',
    'ownerWorkflowRunId', 'renewedAt', 'state',
  ]);
  assert.equal(Object.isFrozen(outcome.value.lease), true);
  assert.equal(Object.getPrototypeOf(outcome.value.lease), Object.prototype);
  assert.equal(Object.values(Object.getOwnPropertyDescriptors(outcome.value.lease)).every(
    (descriptor) => Object.hasOwn(descriptor, 'value')
      && descriptor.enumerable === true
      && descriptor.configurable === false
      && descriptor.writable === false,
  ), true);
  const closeEvent = await harness.store.getAuditEventByDigest(outcome.value.lease.ledgerDigest);
  assert.deepEqual(outcome.value.closeProof.event, closeEvent);
  assert.deepEqual(closeEvent, {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: outcome.value.closeProof.predecessorLease.ledgerDigest,
    runId: harness.args.context.runId,
    leaseVersionBefore: outcome.value.closeProof.predecessorLease.leaseVersion,
    leaseVersionAfter: outcome.value.lease.leaseVersion,
    transition: 'lease.close',
    intentId: null,
    intentProjectionDigest: null,
  });
  assert.equal(
    outcome.value.lease.leaseVersion,
    outcome.value.closeProof.predecessorLease.leaseVersion + 1,
  );
  assert.equal(outcome.value.lease.ledgerDigest, digest(closeEvent));
  assert.deepEqual(await harness.store.getLease(), outcome.value.lease);
  assert.equal(createRunnerRequest({
    capability: harness.args.capability,
    lease: harness.args.lease,
    context: harness.args.context,
    clock: harness.args.clock,
    scenario: { scenarioId: 'closed-generation', parameters: {} },
  }).status, 'BLOCKED');
  assert.equal(harness.calls.length, 131);
  assert.deepEqual([...new Set(harness.calls.map((call) => call.logicalResource))],
    QUALIFIED_CLEANUP_PROTOCOL.resourceOrder);

  let offset = 0;
  for (const logicalResource of QUALIFIED_CLEANUP_PROTOCOL.resourceOrder) {
    const catalog = getCleanupResourceCatalog(logicalResource);
    const calls = harness.calls.slice(offset, offset + catalog.executionPlan.knownCalls);
    assert.deepEqual(calls.map((call) => call.position),
      Array.from({ length: catalog.executionPlan.knownCalls }, (_, index) => index));
    const projection = await harness.store.getIntentProjection(harness.roots.get(logicalResource).intentId);
    const slots = JSON.parse(projection.cleanupRunnerExecutionSlotsJson);
    assert.equal(projection.state, 'absent');
    assert.equal(slots.length, catalog.executionPlan.slotCount);
    for (let position = 0; position < catalog.executionPlan.knownCalls; position += 1) {
      assert.notEqual(slots[position * 2], null);
      assert.equal(slots[position * 2 + 1], null);
    }
    offset += catalog.executionPlan.knownCalls;
  }
  assert.doesNotMatch(JSON.stringify(outcome), /cleanup-primary-/u);
});

test('cleanup driver rejects a state-only idle close and leaves no PASS evidence', async () => {
  const harness = await createDriverHarness();
  const key = Symbol.for('appwritework.test-cloud.cleanup-close-override.v1');
  Object.defineProperty(globalThis, key, {
    configurable: true,
    value: async ({ lease }) => Object.freeze({
      status: 'PASS',
      value: Object.freeze({ ...lease, state: 'idle' }),
      diagnostics: Object.freeze([]),
    }),
  });
  try {
    const outcome = await cleanupDriverModule.runTrustedTestCloudCleanup(harness.args);
    assert.deepEqual(outcome, SANITIZED_BLOCKED);
    assert.equal(harness.calls.length, 131);
    assert.equal(harness.store.peekLease().state, 'active');
  } finally {
    Reflect.deleteProperty(globalThis, key);
  }
});

test('cleanup driver blocks a provider ID already retained by a prior resource', async () => {
  const harness = await createDriverHarness({ mode: 'duplicate-across-resources' });
  const shareCalls = getCleanupResourceCatalog('primary-share').executionPlan.knownCalls;

  const outcome = await cleanupDriverModule.runTrustedTestCloudCleanup(harness.args);

  assert.deepEqual(outcome, SANITIZED_BLOCKED);
  assert.equal(harness.calls.length, shareCalls + 1);
  assert.equal(harness.calls.at(-1).logicalResource, 'primary-graph');
  assert.equal(harness.calls.at(-1).position, 0);
  assert.equal(harness.calls.at(-1).attempt, 1);
  const graph = await harness.store.getIntentProjection(harness.roots.get('primary-graph').intentId);
  assert.equal(graph.state, 'created');
  assert.equal(graph.cleanupRunnerExecutionCursor, null);
  assert.equal(graph.cleanupRunnerExecutionSlotsJson, null);
});

test('cleanup driver fixes one retention expiry before an advancing clock can drift', async () => {
  const harness = await createDriverHarness();
  let now = 2000;
  harness.args.clock = Object.freeze({ nowEpochSeconds: () => now++ });

  const outcome = await cleanupDriverModule.runTrustedTestCloudCleanup(harness.args);

  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
  const retentionExpiries = new Set();
  for (const root of harness.roots.values()) {
    const projection = await harness.store.getIntentProjection(root.intentId);
    retentionExpiries.add(projection.cleanupRunnerExecutionRetentionExpiresAt);
  }
  assert.equal(retentionExpiries.size, 1);
});

test('cleanup driver retains both closed slots at the 262-call ceiling and never reconciles twice', async () => {
  const maximum = await createDriverHarness({ mode: 'ambiguous-first-everywhere' });
  const outcome = await cleanupDriverModule.runTrustedTestCloudCleanup(maximum.args);
  assert.equal(outcome.status, 'PASS', JSON.stringify({
    outcome,
    callCount: maximum.calls.length,
    lastCall: maximum.calls.at(-1),
  }));
  assert.equal(maximum.calls.length, 262);
  for (const logicalResource of QUALIFIED_CLEANUP_PROTOCOL.resourceOrder) {
    const catalog = getCleanupResourceCatalog(logicalResource);
    const projection = await maximum.store.getIntentProjection(maximum.roots.get(logicalResource).intentId);
    const slots = JSON.parse(projection.cleanupRunnerExecutionSlotsJson);
    assert.equal(slots.length, catalog.executionPlan.slotCount);
    assert.equal(slots.every((slot) => slot !== null), true);
    assert.equal(new Set(slots.map((slot) => slot.retentionExpiresAt)).size, 1);
  }
  const repeated = await cleanupDriverModule.runTrustedTestCloudCleanup(maximum.args);
  assert.equal(repeated.status, 'BLOCKED');
  assert.equal(maximum.calls.length, 262);
});

test('cleanup driver permits one exact replay only for an incomplete acknowledgement', async () => {
  const ambiguous = await createDriverHarness({ mode: 'always-ambiguous' });
  const blocked = await cleanupDriverModule.runTrustedTestCloudCleanup(ambiguous.args);
  assert.equal(blocked.status, 'BLOCKED');
  assert.equal(ambiguous.calls.length, 2);
  assert.equal(canonicalJson(ambiguous.calls[0].request), canonicalJson(ambiguous.calls[1].request));
  const projection = await ambiguous.store.getIntentProjection(
    ambiguous.roots.get('primary-share').intentId,
  );
  const retainedSlots = JSON.parse(projection.cleanupRunnerExecutionSlotsJson);
  assert.notEqual(retainedSlots[0], null);
  assert.notEqual(retainedSlots[1], null, 'the used exact-second execution was not retained');
  const again = await cleanupDriverModule.runTrustedTestCloudCleanup(ambiguous.args);
  assert.equal(again.status, 'BLOCKED');
  assert.equal(ambiguous.calls.length, 2, 'a second reconciliation or third attempt occurred');
});

test('cleanup driver retains an exact-second non-PASS slot in every cleanup phase', async () => {
  const catalog = getCleanupResourceCatalog('primary-share');
  for (const [mode, position] of [
    ['second-nonpass-preflight', 0],
    ['second-nonpass-mutation', catalog.preflight.length],
    ['second-nonpass-proof', catalog.preflight.length + catalog.mutation.length],
    ['second-nonpass-terminal', catalog.executionPlan.knownCalls - 1],
  ]) {
    const harness = await createDriverHarness({ mode });
    assert.equal((await cleanupDriverModule.runTrustedTestCloudCleanup(harness.args)).status, 'BLOCKED');
    const calls = harness.calls.filter((call) => call.position === position);
    assert.deepEqual(calls.map((call) => call.attempt), [1, 2], mode);
    assert.equal(canonicalJson(calls[0].request), canonicalJson(calls[1].request), mode);
    const projection = await harness.store.getIntentProjection(
      harness.roots.get('primary-share').intentId,
    );
    const slots = JSON.parse(projection.cleanupRunnerExecutionSlotsJson);
    assert.notEqual(slots[position * 2], null, mode);
    assert.notEqual(slots[position * 2 + 1], null, mode);
    assert.equal(projection.cleanupRunnerExecutionCursor, position, mode);
    const callsBeforeRepeat = harness.calls.length;
    assert.equal((await cleanupDriverModule.runTrustedTestCloudCleanup(harness.args)).status, 'BLOCKED');
    assert.equal(harness.calls.length, callsBeforeRepeat, mode);
  }
});

test('cleanup driver never replays a retained deterministic protocol mismatch', async () => {
  const reordered = await createDriverHarness({ mode: 'reordered-first' });
  const reorderedOutcome = await cleanupDriverModule.runTrustedTestCloudCleanup(reordered.args);
  assert.equal(reorderedOutcome.status, 'BLOCKED');
  assert.deepEqual(reordered.calls.map(({ position }) => position), [0]);
  const reorderedProjection = await reordered.store.getIntentProjection(
    reordered.roots.get('primary-share').intentId,
  );
  assert.equal(reorderedProjection.state, 'created');
  assert.equal(reorderedProjection.cleanupRunnerExecutionCursor, 0);
});

test('cleanup driver rejects retention/list drift and incomplete close before more calls', async () => {
  const missing = await createDriverHarness({ resources: ['primary-share', 'primary-graph'] });
  const missingOutcome = await cleanupDriverModule.runTrustedTestCloudCleanup(missing.args);
  assert.equal(missingOutcome.status, 'BLOCKED');
  assert.equal(missing.calls.length, 0, 'incomplete close reached an outer call');

  const terminal = await createDriverHarness({ mode: 'incomplete-terminal' });
  const terminalOutcome = await cleanupDriverModule.runTrustedTestCloudCleanup(terminal.args);
  assert.equal(terminalOutcome.status, 'BLOCKED');
  assert.notEqual(terminal.store.peekLease().state, 'idle');
  assert.equal(terminal.calls.at(-1).scenarioId, 'resource.cleanup');
  assert.equal(terminal.calls.at(-1).attempt, 1);

  const closed = await createDriverHarness();
  assert.equal((await cleanupDriverModule.runTrustedTestCloudCleanup(closed.args)).status, 'PASS');
  const shareId = closed.roots.get('primary-share').intentId;
  const original = await closed.store.getIntentProjection(shareId);
  const originalSlots = JSON.parse(original.cleanupRunnerExecutionSlotsJson);
  const drifts = [
    { ...original, retainedExecutionIds: originalSlots.filter(Boolean).map((slot) => slot.retainedExecutionId) },
    (() => {
      const slots = structuredClone(originalSlots);
      slots[0].safeStateDigest = `sha256:${'f'.repeat(64)}`;
      return {
        ...original,
        cleanupRunnerExecutionSlotsJson: canonicalJson(slots),
        cleanupRunnerExecutionRecordDigest: digest({
          schemaVersion: 'verification-cleanup-execution-record.v1',
          logicalResource: 'primary-share',
          slots,
        }),
      };
    })(),
    (() => {
      const slots = structuredClone(originalSlots);
      const retentionExpiresAt = at(2000 + inventory.control.primaryExecutionRetentionMaxSeconds + 1);
      for (const slot of slots) if (slot !== null) slot.retentionExpiresAt = retentionExpiresAt;
      return {
        ...original,
        cleanupRunnerExecutionRetentionExpiresAt: retentionExpiresAt,
        cleanupRunnerExecutionSlotsJson: canonicalJson(slots),
        cleanupRunnerExecutionRecordDigest: digest({
          schemaVersion: 'verification-cleanup-execution-record.v1',
          logicalResource: 'primary-share',
          slots,
        }),
      };
    })(),
  ];
  const callsBeforeDrift = closed.calls.length;
  for (const drift of drifts) {
    const tamperedStore = Object.freeze({
      ...closed.store,
      async getIntentProjection(intentId) {
        return intentId === shareId ? structuredClone(drift) : closed.store.getIntentProjection(intentId);
      },
    });
    const result = await cleanupDriverModule.runTrustedTestCloudCleanup({
      ...closed.args,
      store: tamperedStore,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(closed.calls.length, callsBeforeDrift);
  }
});
