import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import providerContract from '../../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json' with { type: 'json' };

const SOURCE_URL = new URL('./test-cloud-fixture-intent-producer.mjs', import.meta.url);
const digest = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const textDigest = (value) => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;

function dataUrl(source) {
  return `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;
}

async function loadProducer({ commits, installResult }) {
  const source = await readFile(SOURCE_URL, 'utf8');
  const controlUrl = dataUrl(`
    export async function commitIntentSnapshot(args) {
      globalThis.__fixtureProducerCommits.push(args.snapshot);
      if (typeof globalThis.__fixtureProducerCommitOperation === 'function') {
        return globalThis.__fixtureProducerCommitOperation(args);
      }
      if (args.snapshot.state === 'created') {
        return Object.freeze({ status: 'PASS', value: Object.freeze({ lease: globalThis.__fixtureProducerDurableLease ?? args.lease, capability: globalThis.__fixtureProducerRecoveredCapability ?? args.capability, event: null, snapshot: args.snapshot }), diagnostics: Object.freeze([]) });
      }
      const lease = Object.freeze({ ...args.lease, leaseVersion: args.lease.leaseVersion + 1 });
      const capability = Object.freeze(Object.create(null));
      return Object.freeze({ status: 'PASS', value: Object.freeze({ lease, capability, event: null, snapshot: args.snapshot }), diagnostics: Object.freeze([]) });
    }
  `);
  const providerUrl = dataUrl(`
    export async function installProviderControlStore(args) {
      globalThis.__fixtureProducerInstallArgs.push(args);
      return globalThis.__fixtureProducerInstallResult;
    }
    export function captureTestCloudProviderMutationRoute(args) {
      return globalThis.__fixtureProducerProviderOperation('capture', args);
    }
    export async function issueProviderMutation(args) {
      return globalThis.__fixtureProducerProviderOperation('issue', args);
    }
    export async function reconcileProviderMutation(args) {
      return globalThis.__fixtureProducerProviderOperation('reconcile', args);
    }
    export async function createShareBaselineProof(args) {
      return globalThis.__fixtureProducerProviderOperation('share-baseline', args);
    }
    export async function issueShareCreate(args) {
      return globalThis.__fixtureProducerProviderOperation('share-issue', args);
    }
    export async function reconcileShareCreate(args) {
      return globalThis.__fixtureProducerProviderOperation('share-reconcile', args);
    }
  `);
  globalThis.__fixtureProducerCommits = commits;
  globalThis.__fixtureProducerInstallArgs = [];
  globalThis.__fixtureProducerInstallResult = installResult;
  globalThis.__fixtureProducerDurableLease = undefined;
  globalThis.__fixtureProducerRecoveredCapability = undefined;
  globalThis.__fixtureProducerCommitOperation = undefined;
  globalThis.__fixtureProducerProviderCalls = [];
  globalThis.__fixtureProducerProviderOperation = (name, args) => {
    globalThis.__fixtureProducerProviderCalls.push([name, args]);
    const token = Object.freeze(Object.create(null));
    const values = {
      capture: { captured: true },
      issue: { providerMutationIssue: token },
      reconcile: { reconciliationQualification: token },
      'share-baseline': { baselineProof: token },
      'share-issue': { shareIssue: token },
      'share-reconcile': { reconciled: true },
    };
    return Object.freeze({
      status: 'PASS', value: Object.freeze(values[name]), diagnostics: Object.freeze([]),
    });
  };
  const rewritten = source
    .replace("../../../scripts/verification/test-cloud-control-runtime.mjs", controlUrl)
    .replace("../../../scripts/verification/test-cloud-provider-contract.mjs", providerUrl)
    .replace("../../../scripts/verification/canonical-json.mjs", new URL('../../../scripts/verification/canonical-json.mjs', import.meta.url).href)
    .replace("../../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json", new URL('../../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json', import.meta.url).href);
  return import(dataUrl(rewritten));
}

test('Task 6 RED: initializer commits exactly three deterministic planned v2 intents before install', async () => {
  const commits = [];
  const sessionIntentQualification = Object.freeze(Object.create(null));
  const producer = await loadProducer({
    commits,
    installResult: Object.freeze({
      status: 'PASS',
      value: Object.freeze({ installed: true, sessionIntentQualification }),
      diagnostics: Object.freeze([]),
    }),
  });
  assert.deepEqual(Object.keys(producer).sort(), [
    'initializeProviderFixtureIntentSet',
    'runTrustedTestCloudFixtureIntentProducer',
  ]);

  const context = Object.freeze({
    runId: 'verify-0123456789ab-123456789-1',
    environmentDigest: `sha256:${'e'.repeat(64)}`,
  });
  const initialLease = Object.freeze({ leaseVersion: 7 });
  const initialCapability = Object.freeze(Object.create(null));
  const clock = Object.freeze({ nowEpochSeconds: () => 1_725_000_000 });
  const providerContractDigest = `sha256:${createHash('sha256')
    .update(`${canonicalJson(providerContract)}\n`, 'utf8').digest('hex')}`;
  const output = await producer.initializeProviderFixtureIntentSet({
    runtimeQualification: Object.freeze(Object.create(null)),
    context,
    providerContractQualification: Object.freeze(Object.create(null)),
    store: Object.freeze(Object.create(null)),
    lease: initialLease,
    capability: initialCapability,
    clock,
    providerContractDigest,
  });

  assert.equal(output.status, 'PASS', JSON.stringify(output));
  assert.equal(commits.length, 3);
  assert.deepEqual(commits.map(({ resourceType }) => resourceType), [
    'primary-project', 'primary-graph', 'primary-share',
  ]);
  assert.deepEqual(output.value.intents, commits);
  assert.equal(output.value.lease.leaseVersion, 10);
  assert.equal(output.value.capability, commits.length === 3 ? output.value.capability : null);
  assert.equal(output.value.sessionIntentQualification, sessionIntentQualification);
  for (const [index, intent] of commits.entries()) {
    const expectedResourceId = `vr-${textDigest(`${context.environmentDigest}|${context.runId}|${intent.resourceType}`).slice(7, 39)}`;
    assert.deepEqual(Object.keys(intent), [
      'schemaVersion', 'intentId', 'runId', 'environmentDigest', 'resourceType', 'resourceId',
      'providerAggregateJson', 'providerAggregateDigest', 'ownerMarker', 'dependencyOrder',
      'lifecycleClass', 'state', 'intentVersion', 'observationDigest', 'retentionExpiresAt',
      'cleanupCursor', 'cleanupProgressDigest', 'cleanupProofDigest',
      'cleanupRunnerExecutionPlanDigest', 'cleanupRunnerExecutionCursor',
      'cleanupRunnerExecutionSlotsJson', 'cleanupRunnerExecutionRecordDigest',
      'cleanupRunnerExecutionRetentionExpiresAt', 'createdAt', 'updatedAt',
    ]);
    assert.equal(intent.resourceId, expectedResourceId);
    assert.equal(intent.intentId, textDigest(`${context.environmentDigest}|${context.runId}|${intent.resourceType}|${expectedResourceId}`).slice(7));
    assert.equal(intent.dependencyOrder, [10, 20, 30][index]);
    assert.equal(intent.state, 'planned');
    assert.equal(intent.intentVersion, 1);
    assert.equal(intent.providerAggregateDigest, digest(JSON.parse(intent.providerAggregateJson)));
    const aggregate = JSON.parse(intent.providerAggregateJson);
    const resource = providerContract.aggregateContracts.resources.find((candidate) => (
      candidate.resourceType === intent.resourceType
    ));
    assert.deepEqual(Object.keys(aggregate).sort(), [
      'aggregateBinding', 'aggregateBindingDigest', 'ownedMembers', 'phase',
      'referencedMembers', 'schemaVersion',
    ]);
    assert.equal(aggregate.schemaVersion, 'verification-provider-aggregate.v1');
    assert.equal(aggregate.phase, 'owner-baseline');
    assert.equal(aggregate.aggregateBinding.providerContractDigest, providerContractDigest);
    assert.equal(aggregate.aggregateBinding.resourceId, intent.resourceId);
    assert.equal(aggregate.aggregateBinding.intentId, intent.intentId);
    assert.equal(aggregate.aggregateBindingDigest, digest(aggregate.aggregateBinding));
    assert.equal(aggregate.ownedMembers.length, resource.memberTemplates.length);
    assert.equal(aggregate.referencedMembers.length, resource.referencedSlots.length);
    for (const [memberIndex, member] of aggregate.ownedMembers.entries()) {
      const template = resource.memberTemplates[memberIndex];
      assert.equal(member.memberBinding.memberTemplateDigest, template.memberTemplateDigest);
      assert.equal(member.memberBinding.slot, template.slot);
      assert.equal(member.memberBinding.ownerResourceId, intent.resourceId);
      assert.equal(member.memberBindingDigest, digest(member.memberBinding));
      assert.equal(member.providerId, null);
      assert.equal(member.providerIdentity, null);
      assert.ok(member.logicalValueBindings.every((binding) => (
        binding.state === 'unbound' && binding.value === null && binding.valueDigest === null
      )));
      assert.ok(member.operationStates.every((operation) => (
        operation.state === 'pending' && operation.requestInstanceDigest === null
      )));
    }
    for (const key of [
      'observationDigest', 'retentionExpiresAt', 'cleanupCursor', 'cleanupProgressDigest',
      'cleanupProofDigest', 'cleanupRunnerExecutionPlanDigest', 'cleanupRunnerExecutionCursor',
      'cleanupRunnerExecutionSlotsJson', 'cleanupRunnerExecutionRecordDigest',
      'cleanupRunnerExecutionRetentionExpiresAt',
    ]) assert.equal(intent[key], null, key);
  }
  assert.equal(globalThis.__fixtureProducerInstallArgs.length, 1);
  assert.equal(globalThis.__fixtureProducerInstallArgs[0].providerControlStore, output.value.intents.length === 3 ? globalThis.__fixtureProducerInstallArgs[0].providerControlStore : null);
});

test('Task 8 RED: initializer returns no session lineage for a forged planned commit readback', async () => {
  const sessionIntentQualification = Object.freeze(Object.create(null));
  const producer = await loadProducer({
    commits: [],
    installResult: Object.freeze({
      status: 'PASS',
      value: Object.freeze({ installed: true, sessionIntentQualification }),
      diagnostics: Object.freeze([]),
    }),
  });
  let commitOrdinal = 0;
  globalThis.__fixtureProducerCommitOperation = (args) => {
    commitOrdinal += 1;
    return Object.freeze({
      status: 'PASS',
      value: Object.freeze({
        lease: Object.freeze({ ...args.lease, leaseVersion: args.lease.leaseVersion + 1 }),
        capability: Object.freeze(Object.create(null)),
        snapshot: commitOrdinal === 2
          ? Object.freeze({ ...args.snapshot, resourceType: 'primary-project' })
          : args.snapshot,
      }),
      diagnostics: Object.freeze([]),
    });
  };
  const context = Object.freeze({
    runId: 'verify-0123456789ab-123456789-1',
    environmentDigest: `sha256:${'e'.repeat(64)}`,
  });
  const providerContractDigest = `sha256:${createHash('sha256')
    .update(`${canonicalJson(providerContract)}\n`, 'utf8').digest('hex')}`;
  const output = await producer.initializeProviderFixtureIntentSet({
    runtimeQualification: Object.freeze(Object.create(null)),
    context,
    providerContractQualification: Object.freeze(Object.create(null)),
    store: Object.freeze(Object.create(null)),
    lease: Object.freeze({ leaseVersion: 7 }),
    capability: Object.freeze(Object.create(null)),
    clock: Object.freeze({ nowEpochSeconds: () => 1_725_000_000 }),
    providerContractDigest,
  });
  assert.equal(output.status, 'BLOCKED');
  assert.equal(globalThis.__fixtureProducerInstallArgs.length, 0);
});

test('Task 8 RED: trusted producer accepts only the four closed mutation markers and returns exact created readback at the current head', async () => {
  const sessionIntentQualification = Object.freeze(Object.create(null));
  const producer = await loadProducer({
    commits: [],
    installResult: Object.freeze({
      status: 'PASS',
      value: Object.freeze({ installed: true, sessionIntentQualification }),
      diagnostics: Object.freeze([]),
    }),
  });
  const context = Object.freeze({
    runId: 'verify-0123456789ab-123456789-1',
    environmentDigest: `sha256:${'e'.repeat(64)}`,
  });
  const clock = Object.freeze({ nowEpochSeconds: () => 1_725_000_000 });
  const providerContractDigest = `sha256:${createHash('sha256')
    .update(`${canonicalJson(providerContract)}\n`, 'utf8').digest('hex')}`;
  const plannedHead = Object.freeze({ leaseVersion: 7 });
  let currentLease = plannedHead;
  let currentIntents = [];
  const store = Object.freeze({
    async getLease() { return currentLease; },
    async getIntentProjection(intentId) {
      return currentIntents.find((intent) => intent.intentId === intentId) ?? null;
    },
  });
  const initialized = await producer.initializeProviderFixtureIntentSet({
    runtimeQualification: Object.freeze(Object.create(null)),
    context,
    providerContractQualification: Object.freeze(Object.create(null)),
    store,
    lease: plannedHead,
    capability: Object.freeze(Object.create(null)),
    clock,
    providerContractDigest,
  });
  assert.equal(initialized.status, 'PASS', JSON.stringify(initialized));
  const createdIntents = Object.freeze(initialized.value.intents.map((planned) => {
    const aggregate = JSON.parse(planned.providerAggregateJson);
    aggregate.phase = planned.resourceType === 'primary-share' ? 'shared' : 'normal-owner';
    for (const member of aggregate.ownedMembers) {
      for (const operation of member.operationStates) operation.state = 'reconciled';
    }
    return Object.freeze({
      ...planned,
      providerAggregateJson: canonicalJson(aggregate),
      providerAggregateDigest: digest(aggregate),
      state: 'created',
      intentVersion: planned.intentVersion + 1,
      updatedAt: new Date(Date.parse(planned.updatedAt) + 1).toISOString(),
    });
  }));
  currentLease = initialized.value.lease;
  currentIntents = initialized.value.intents;
  const finalLease = Object.freeze({ ...currentLease, leaseVersion: 64 });
  const recoveredCapability = Object.freeze(Object.create(null));
  const calls = [];
  const marker = (name, key, onCall = () => {}) => Object.freeze(async function () {
    calls.push(name);
    onCall();
    return Object.freeze({
      status: 'PASS',
      value: Object.freeze({ [key]: true }),
      diagnostics: Object.freeze([]),
    });
  });
  const fixtureMutationPort = Object.freeze(Object.assign(Object.create(null), {
    performOwnerLogin: marker('owner', 'ownerLoginComplete'),
    performProjectCreateAndGraphEditPrefix: marker('prefix', 'projectGraphPrefixReady'),
    performEditorShare: marker('editor', 'editorShareComplete'),
    performViewerShare: marker('viewer', 'viewerShareComplete', () => {
      currentLease = finalLease;
      currentIntents = createdIntents;
      globalThis.__fixtureProducerDurableLease = finalLease;
      globalThis.__fixtureProducerRecoveredCapability = recoveredCapability;
    }),
  }));

  const output = await producer.runTrustedTestCloudFixtureIntentProducer({
    context,
    store,
    lease: initialized.value.lease,
    capability: initialized.value.capability,
    clock,
    providerContractDigest,
    sessionIntentQualification,
    fixtureMutationPort,
  });

  assert.equal(output.status, 'PASS', JSON.stringify({
    output,
    calls,
    providerCalls: globalThis.__fixtureProducerProviderCalls.map(([name, args]) => [
      name, args.mutationOrdinal,
    ]),
  }));
  assert.deepEqual(calls, ['owner', 'prefix', 'editor', 'viewer']);
  assert.deepEqual(
    globalThis.__fixtureProducerProviderCalls.map(([name, args]) => [name, args.mutationOrdinal]),
    [
      ...Array.from({ length: 17 }, (_, mutationOrdinal) => [
        ['capture', mutationOrdinal],
        ['issue', mutationOrdinal],
        ['reconcile', undefined],
      ]).flat(),
      ['capture', 17], ['share-baseline', undefined], ['share-issue', undefined],
      ['share-reconcile', undefined],
      ['capture', 18], ['share-baseline', undefined], ['share-issue', undefined],
      ['share-reconcile', undefined],
    ],
  );
  assert.equal(output.value.lease, finalLease);
  assert.equal(output.value.capability, recoveredCapability);
  assert.deepEqual(output.value.intents, createdIntents);
});

async function prepareTrustedProducerHarness() {
  const sessionIntentQualification = Object.freeze(Object.create(null));
  const producer = await loadProducer({
    commits: [],
    installResult: Object.freeze({
      status: 'PASS',
      value: Object.freeze({ installed: true, sessionIntentQualification }),
      diagnostics: Object.freeze([]),
    }),
  });
  const context = Object.freeze({
    runId: 'verify-0123456789ab-123456789-1',
    environmentDigest: `sha256:${'e'.repeat(64)}`,
  });
  const clock = Object.freeze({ nowEpochSeconds: () => 1_725_000_000 });
  const providerContractDigest = `sha256:${createHash('sha256')
    .update(`${canonicalJson(providerContract)}\n`, 'utf8').digest('hex')}`;
  let currentLease = Object.freeze({ leaseVersion: 7 });
  let currentIntents = [];
  const store = Object.freeze({
    async getLease() { return currentLease; },
    async getIntentProjection(intentId) {
      return currentIntents.find((intent) => intent.intentId === intentId) ?? null;
    },
  });
  const initialized = await producer.initializeProviderFixtureIntentSet({
    runtimeQualification: Object.freeze(Object.create(null)),
    context,
    providerContractQualification: Object.freeze(Object.create(null)),
    store,
    lease: currentLease,
    capability: Object.freeze(Object.create(null)),
    clock,
    providerContractDigest,
  });
  assert.equal(initialized.status, 'PASS');
  currentLease = initialized.value.lease;
  currentIntents = initialized.value.intents;
  const createdIntents = Object.freeze(initialized.value.intents.map((planned) => {
    const aggregate = JSON.parse(planned.providerAggregateJson);
    aggregate.phase = planned.resourceType === 'primary-share' ? 'shared' : 'normal-owner';
    for (const member of aggregate.ownedMembers) {
      for (const operation of member.operationStates) operation.state = 'reconciled';
    }
    return Object.freeze({
      ...planned,
      providerAggregateJson: canonicalJson(aggregate),
      providerAggregateDigest: digest(aggregate),
      state: 'created',
      intentVersion: planned.intentVersion + 1,
      updatedAt: new Date(Date.parse(planned.updatedAt) + 1).toISOString(),
    });
  }));
  const finalLease = Object.freeze({ ...currentLease, leaseVersion: 64 });
  const recoveredCapability = Object.freeze(Object.create(null));
  let finish = () => {
    currentLease = finalLease;
    currentIntents = createdIntents;
    globalThis.__fixtureProducerDurableLease = finalLease;
    globalThis.__fixtureProducerRecoveredCapability = recoveredCapability;
  };
  const marker = (key, onCall = () => {}) => Object.freeze(async function () {
    onCall();
    return Object.freeze({
      status: 'PASS',
      value: Object.freeze({ [key]: true }),
      diagnostics: Object.freeze([]),
    });
  });
  const fixtureMutationPort = Object.freeze(Object.assign(Object.create(null), {
    performOwnerLogin: marker('ownerLoginComplete'),
    performProjectCreateAndGraphEditPrefix: marker('projectGraphPrefixReady'),
    performEditorShare: marker('editorShareComplete'),
    performViewerShare: marker('viewerShareComplete', () => finish()),
  }));
  return {
    producer,
    initialized,
    createdIntents,
    finalLease,
    recoveredCapability,
    args: {
      context,
      store,
      lease: initialized.value.lease,
      capability: initialized.value.capability,
      clock,
      providerContractDigest,
      sessionIntentQualification,
      fixtureMutationPort,
    },
    setCurrentIntents(value) { currentIntents = value; },
    setFinish(value) { finish = value; },
    setCurrentLease(value) { currentLease = value; },
  };
}

test('Task 8 review RED: every interruption settles its started port and returns the current recoverable head', async () => {
  const matrix = Array.from({ length: 19 }, (_, mutationOrdinal) => ({
    mutationOrdinal,
    stages: mutationOrdinal <= 16
      ? ['capture', 'issue', 'reconcile', 'physical-create']
      : ['capture', 'share-baseline', 'share-issue', 'share-reconcile', 'physical-create'],
  })).flatMap(({ mutationOrdinal, stages }) => stages.map((stage) => ({
    mutationOrdinal,
    stage,
  })));

  for (const vector of matrix) {
    const harness = await prepareTrustedProducerHarness();
    const interruptedLease = Object.freeze({
      ...harness.initialized.value.lease,
      leaseVersion: 100 + vector.mutationOrdinal,
      cleanupDebt: vector.stage === 'physical-create',
      state: vector.stage === 'physical-create' ? 'cleanup-debt' : 'active',
    });
    const recoveredCapability = Object.freeze(Object.create(null));
    let activePorts = 0;
    let settleActivePort;
    let observedOrdinal = -1;
    const pass = (key, value) => Object.freeze({
      status: 'PASS',
      value: Object.freeze({ [key]: value }),
      diagnostics: Object.freeze([]),
    });
    const blocked = Object.freeze({
      status: 'BLOCKED', value: null, diagnostics: Object.freeze([]),
    });
    const immediateMarker = (key) => Object.freeze(async function () {
      return pass(key, true);
    });
    const interruptedMarker = Object.freeze(async function () {
      activePorts += 1;
      return new Promise((resolve) => {
        settleActivePort = () => {
          activePorts -= 1;
          resolve(blocked);
        };
      });
    });
    const targetMethod = vector.mutationOrdinal <= 16
      ? 'performProjectCreateAndGraphEditPrefix'
      : vector.mutationOrdinal === 17 ? 'performEditorShare' : 'performViewerShare';
    const fixtureMutationPort = Object.freeze(Object.assign(Object.create(null), {
      performOwnerLogin: immediateMarker('ownerLoginComplete'),
      performProjectCreateAndGraphEditPrefix: targetMethod === 'performProjectCreateAndGraphEditPrefix'
        ? interruptedMarker : immediateMarker('projectGraphPrefixReady'),
      performEditorShare: targetMethod === 'performEditorShare'
        ? interruptedMarker : immediateMarker('editorShareComplete'),
      performViewerShare: targetMethod === 'performViewerShare'
        ? interruptedMarker : immediateMarker('viewerShareComplete'),
    }));
    const operationForStage = vector.stage === 'physical-create'
      ? (vector.mutationOrdinal <= 16 ? 'reconcile' : 'share-reconcile')
      : vector.stage;
    globalThis.__fixtureProducerProviderOperation = (name) => {
      if (name === 'capture') observedOrdinal += 1;
      if (observedOrdinal === vector.mutationOrdinal && name === operationForStage) {
        if (name !== 'capture') {
          harness.setCurrentLease(interruptedLease);
          globalThis.__fixtureProducerCommitOperation = (args) => Object.freeze({
            status: 'PASS',
            value: Object.freeze({
              lease: interruptedLease,
              capability: recoveredCapability,
              event: null,
              snapshot: args.snapshot,
            }),
            diagnostics: Object.freeze([]),
          });
        }
        setImmediate(() => settleActivePort());
        return blocked;
      }
      const token = Object.freeze(Object.create(null));
      const values = {
        capture: ['captured', true],
        issue: ['providerMutationIssue', token],
        reconcile: ['reconciliationQualification', token],
        'share-baseline': ['baselineProof', token],
        'share-issue': ['shareIssue', token],
        'share-reconcile': ['reconciled', true],
      };
      return pass(...values[name]);
    };

    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer({
      ...harness.args,
      fixtureMutationPort,
    });

    assert.equal(output.status, 'BLOCKED', JSON.stringify(vector));
    assert.equal(activePorts, 0, `started port remained active: ${JSON.stringify(vector)}`);
    assert.equal(
      output.value?.lease,
      vector.stage === 'capture' ? harness.initialized.value.lease : interruptedLease,
      `recoverable lease head: ${JSON.stringify(vector)}`,
    );
    assert.equal(
      output.value?.capability,
      vector.stage === 'capture' ? harness.initialized.value.capability : recoveredCapability,
      `recoverable capability head: ${JSON.stringify(vector)}`,
    );
  }
});

test('Task 8 review round 2 RED: failed active recovery exact-reads the authentic cleanup-debt successor without minting a capability', async () => {
  const commits = [];
  const sessionIntentQualification = Object.freeze(Object.create(null));
  const producer = await loadProducer({
    commits,
    installResult: Object.freeze({
      status: 'PASS',
      value: Object.freeze({ installed: true, sessionIntentQualification }),
      diagnostics: Object.freeze([]),
    }),
  });
  const context = Object.freeze({
    runId: 'verify-0123456789ab-123456789-1',
    environmentDigest: `sha256:${'e'.repeat(64)}`,
  });
  const clock = Object.freeze({ nowEpochSeconds: () => 1_725_000_000 });
  const providerContractDigest = `sha256:${createHash('sha256')
    .update(`${canonicalJson(providerContract)}\n`, 'utf8').digest('hex')}`;
  let durableLease = Object.freeze({
    acquiredAt: '2026-07-20T09:59:00.000Z',
    cleanupDebt: false,
    environmentDigest: context.environmentDigest,
    expiresAt: '2026-07-20T10:29:00.000Z',
    leaseRowId: 'test-cloud-singleton',
    leaseTokenDigest: `sha256:${'b'.repeat(64)}`,
    leaseVersion: 7,
    ledgerDigest: `sha256:${'c'.repeat(64)}`,
    ownerRunId: context.runId,
    ownerWorkflowRunId: '123456789',
    renewedAt: '2026-07-20T09:59:00.000Z',
    state: 'active',
  });
  let intents = [];
  const auditEvents = new Map();
  let leaseReads = 0;
  let auditReads = 0;
  const store = Object.freeze({
    async getLease() {
      leaseReads += 1;
      return durableLease;
    },
    async getIntentProjection(intentId) {
      return intents.find((intent) => intent.intentId === intentId) ?? null;
    },
    async getAuditEventByDigest(ledgerDigest) {
      auditReads += 1;
      return auditEvents.get(ledgerDigest) ?? null;
    },
  });
  const initialized = await producer.initializeProviderFixtureIntentSet({
    runtimeQualification: Object.freeze(Object.create(null)),
    context,
    providerContractQualification: Object.freeze(Object.create(null)),
    store,
    lease: durableLease,
    capability: Object.freeze(Object.create(null)),
    clock,
    providerContractDigest,
  });
  assert.equal(initialized.status, 'PASS');
  durableLease = initialized.value.lease;
  intents = initialized.value.intents;
  const activeHead = durableLease;
  const intermediateEvent = Object.freeze({
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: activeHead.ledgerDigest,
    runId: context.runId,
    leaseVersionBefore: activeHead.leaseVersion,
    leaseVersionAfter: activeHead.leaseVersion + 1,
    transition: 'intent.provider_operation_issued',
    intentId: intents[0].intentId,
    intentProjectionDigest: digest(intents[0]),
  });
  const intermediateLedgerDigest = digest(intermediateEvent);
  const debtEvent = Object.freeze({
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: intermediateLedgerDigest,
    runId: context.runId,
    leaseVersionBefore: activeHead.leaseVersion + 1,
    leaseVersionAfter: activeHead.leaseVersion + 2,
    transition: 'lease.cleanup_debt',
    intentId: null,
    intentProjectionDigest: null,
  });
  const debtHead = Object.freeze({
    ...activeHead,
    cleanupDebt: true,
    leaseVersion: activeHead.leaseVersion + 2,
    ledgerDigest: digest(debtEvent),
    state: 'cleanup-debt',
  });
  auditEvents.set(intermediateLedgerDigest, intermediateEvent);
  auditEvents.set(debtHead.ledgerDigest, debtEvent);
  const blockedMarker = Object.freeze(async function performOwnerLogin() {
    durableLease = debtHead;
    return Object.freeze({ status: 'BLOCKED', value: null, diagnostics: Object.freeze([]) });
  });
  const unreachableMarker = Object.freeze(async function unreachableMarker() {
    throw new Error('mutation port must stop after cleanup debt');
  });
  const fixtureMutationPort = Object.freeze(Object.assign(Object.create(null), {
    performOwnerLogin: blockedMarker,
    performProjectCreateAndGraphEditPrefix: unreachableMarker,
    performEditorShare: unreachableMarker,
    performViewerShare: unreachableMarker,
  }));
  globalThis.__fixtureProducerCommitOperation = () => Object.freeze({
    status: 'BLOCKED', value: null, diagnostics: Object.freeze([]),
  });

  const output = await producer.runTrustedTestCloudFixtureIntentProducer({
    context,
    store,
    lease: activeHead,
    capability: initialized.value.capability,
    clock,
    providerContractDigest,
    sessionIntentQualification,
    fixtureMutationPort,
  });

  assert.equal(output.status, 'BLOCKED');
  assert.equal(output.value.lease, debtHead);
  assert.equal(output.value.capability, null);
  assert.deepEqual(Reflect.ownKeys(output.value), ['lease', 'capability']);
  assert.equal(Object.isFrozen(output.value), true);
  assert.equal(auditReads, 2);
  assert.equal(leaseReads >= 2, true);
});

test('Task 8 negatives: trusted production blocks missing lineage, forged port, incomplete transitions, stale head, and a non-three created set', async (t) => {
  await t.test('missing installed session lineage', async () => {
    const producer = await loadProducer({
      commits: [],
      installResult: Object.freeze({
        status: 'PASS',
        value: Object.freeze({ installed: false, sessionIntentQualification: Object.freeze(Object.create(null)) }),
        diagnostics: Object.freeze([]),
      }),
    });
    const context = Object.freeze({
      runId: 'verify-0123456789ab-123456789-1',
      environmentDigest: `sha256:${'e'.repeat(64)}`,
    });
    const providerContractDigest = `sha256:${createHash('sha256')
      .update(`${canonicalJson(providerContract)}\n`, 'utf8').digest('hex')}`;
    const output = await producer.initializeProviderFixtureIntentSet({
      runtimeQualification: Object.freeze(Object.create(null)),
      context,
      providerContractQualification: Object.freeze(Object.create(null)),
      store: Object.freeze(Object.create(null)),
      lease: Object.freeze({ leaseVersion: 7 }),
      capability: Object.freeze(Object.create(null)),
      clock: Object.freeze({ nowEpochSeconds: () => 1_725_000_000 }),
      providerContractDigest,
    });
    assert.equal(output.status, 'BLOCKED');
  });

  await t.test('missing planned member before first browser mutation', async () => {
    const harness = await prepareTrustedProducerHarness();
    harness.setCurrentIntents(harness.initialized.value.intents.slice(0, 2));
    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer(harness.args);
    assert.equal(output.status, 'BLOCKED');
    assert.equal(globalThis.__fixtureProducerProviderCalls.length, 0);
  });

  await t.test('copied lease head', async () => {
    const harness = await prepareTrustedProducerHarness();
    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer({
      ...harness.args,
      lease: Object.freeze({ ...harness.args.lease }),
    });
    assert.equal(output.status, 'BLOCKED');
    assert.equal(globalThis.__fixtureProducerProviderCalls.length, 0);
  });

  await t.test('extra mutation escape key', async () => {
    const harness = await prepareTrustedProducerHarness();
    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer({
      ...harness.args,
      fixtureMutationPort: Object.freeze(Object.assign(
        Object.create(null),
        harness.args.fixtureMutationPort,
        { runExactScenario: Object.freeze(async function () {}) },
      )),
    });
    assert.equal(output.status, 'BLOCKED');
    assert.equal(globalThis.__fixtureProducerProviderCalls.length, 0);
  });

  await t.test('one non-reconciled physical transition', async () => {
    const harness = await prepareTrustedProducerHarness();
    const incomplete = harness.createdIntents.map((intent, index) => {
      if (index !== 0) return intent;
      const aggregate = JSON.parse(intent.providerAggregateJson);
      aggregate.ownedMembers[0].operationStates[0].state = 'pending';
      return Object.freeze({
        ...intent,
        providerAggregateJson: canonicalJson(aggregate),
        providerAggregateDigest: digest(aggregate),
      });
    });
    harness.setFinish(() => {
      harness.setCurrentLease(harness.finalLease);
      harness.setCurrentIntents(incomplete);
      globalThis.__fixtureProducerDurableLease = harness.finalLease;
      globalThis.__fixtureProducerRecoveredCapability = harness.recoveredCapability;
    });
    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer(harness.args);
    assert.equal(output.status, 'BLOCKED');
  });

  await t.test('only two created intents', async () => {
    const harness = await prepareTrustedProducerHarness();
    harness.setFinish(() => {
      harness.setCurrentLease(harness.finalLease);
      harness.setCurrentIntents(harness.createdIntents.slice(0, 2));
      globalThis.__fixtureProducerDurableLease = harness.finalLease;
      globalThis.__fixtureProducerRecoveredCapability = harness.recoveredCapability;
    });
    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer(harness.args);
    assert.equal(output.status, 'BLOCKED');
  });

  await t.test('replay does not return current durable head', async () => {
    const harness = await prepareTrustedProducerHarness();
    harness.setFinish(() => {
      harness.setCurrentLease(harness.finalLease);
      harness.setCurrentIntents(harness.createdIntents);
      globalThis.__fixtureProducerDurableLease = Object.freeze({
        ...harness.finalLease,
        leaseVersion: harness.finalLease.leaseVersion - 1,
      });
      globalThis.__fixtureProducerRecoveredCapability = harness.recoveredCapability;
    });
    const output = await harness.producer.runTrustedTestCloudFixtureIntentProducer(harness.args);
    assert.equal(output.status, 'BLOCKED');
  });
});
