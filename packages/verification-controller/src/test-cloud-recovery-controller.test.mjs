import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import path from 'node:path';
import test from 'node:test';

import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { createTestCloudRecoveryClients } from '../../../scripts/verification/test-cloud-appwrite.mjs';
import { createTestRecoveryEnvironmentContext } from '../../../scripts/verification/test-cloud-environment.mjs';
import {
  contentDigestToRowId,
  intentIdToRowId,
} from '../../../scripts/verification/test-cloud-row-id.mjs';
import { qualifyExecutionObservationReadback } from '../../../scripts/verification/test-cloud-setup-check.mjs';
import {
  createRecoveryTargetEnvironment,
  main,
  runTestCloudRecoveryStateMachine,
} from './test-cloud-recovery-controller.mjs';
import { readExactBindingDirectory } from './test-cloud-controller.mjs';

const SOURCE_REVISION = 'a'.repeat(40);
const SOURCE_RUN_ID = '456';
const SOURCE_RUN_ATTEMPT = '2';
const RUN_ID = `verify-${SOURCE_REVISION.slice(0, 12)}-${SOURCE_RUN_ID}-${SOURCE_RUN_ATTEMPT}`;
const ENVIRONMENT_DIGEST = `sha256:${'b'.repeat(64)}`;
const RECOVERY_NOW = 1_784_631_600;

function digest(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function textDigest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

const GENESIS_LEDGER_DIGEST = digest({
  leaseRowId: inventory.control.leaseRowId,
  schemaVersion: 'verification-audit-genesis.v1',
});

function recoveryHandle() {
  const configured = inventory.credentialVariables.recovery;
  return Object.freeze({
    ...configured,
    scopes: Object.freeze([...configured.scopes]),
    readSecret() { return 'recovery-secret'; },
  });
}

function executionObservationReadback() {
  return Object.freeze({
    schemaVersion: 'appwrite-execution-observation-readback.v1',
    observationAccess: 'read-only',
    providerManagedRetention: true,
    retentionMaxSeconds: inventory.control.primaryExecutionRetentionMaxSeconds,
  });
}

function observationQualification() {
  const readback = executionObservationReadback();
  const result = qualifyExecutionObservationReadback({
    expectedReadbackDigest: digest(readback),
    inventory,
    readback,
  });
  assert.equal(result.status, 'PASS', JSON.stringify(result));
  return result.value;
}

function bindingDirectoryIo(root, counters = { reads: 0 }) {
  const hosted = Object.freeze({ executionObservation: executionObservationReadback() });
  const bindings = {};
  for (const name of [
    'TEST_CLOUD_SETUP_READBACK',
    'TEST_CLOUD_SETUP_ATTESTATION',
    'TEST_CLOUD_HOSTED_SETUP_READBACK',
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION',
  ]) {
    const value = name === 'TEST_CLOUD_HOSTED_SETUP_READBACK' ? hosted : Object.freeze({});
    bindings[`${name}_JSON`] = canonicalJson(value);
    bindings[`${name}_DIGEST`] = digest(value);
  }
  const filenames = Object.keys(bindings).map((name) => `${name}.txt`).sort();
  return Object.freeze({
    async lstat(value) {
      counters.reads += 1;
      return value === root
        ? Object.freeze({ isDirectory: () => true, isSymbolicLink: () => false })
        : Object.freeze({ isFile: () => true, isSymbolicLink: () => false });
    },
    async readFile(value) {
      counters.reads += 1;
      return Buffer.from(bindings[path.basename(value, '.txt')], 'utf8');
    },
    async readdir() {
      counters.reads += 1;
      return filenames;
    },
    async realpath(value) {
      counters.reads += 1;
      return value;
    },
  });
}

function providerJson(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function inMemoryRecoveryProvider({ lease, rows: initialRows = [] }) {
  const rowKey = (tableId, rowId) => `${tableId}\0${rowId}`;
  const rows = new Map(initialRows.map(({ tableId, rowId, data }) => [
    rowKey(tableId, rowId),
    structuredClone(data),
  ]));
  rows.set(
    rowKey(inventory.control.leaseTableId, inventory.control.leaseRowId),
    structuredClone(lease),
  );
  const transactions = new Map();
  const calls = [];
  let nextTransaction = 1;

  function apply(operations) {
    const staged = new Map([...rows].map(([key, value]) => [key, structuredClone(value)]));
    for (const operation of operations) {
      const key = rowKey(operation.tableId, operation.rowId);
      if (operation.action === 'create') {
        if (staged.has(key)) return false;
        staged.set(key, structuredClone(operation.data));
      } else if (operation.action === 'update') {
        if (!staged.has(key)) return false;
        staged.set(key, { ...staged.get(key), ...structuredClone(operation.data) });
      } else if (operation.action === 'increment') {
        const prior = staged.get(key);
        if (prior === undefined) return false;
        const next = prior[operation.data.column] + operation.data.value;
        if (!Number.isSafeInteger(next) || next > operation.data.max) return false;
        staged.set(key, { ...prior, [operation.data.column]: next });
      } else {
        return false;
      }
    }
    rows.clear();
    for (const [key, value] of staged) rows.set(key, value);
    return true;
  }

  const fetch = async (url, options) => {
    const requestPath = new URL(url).pathname.replace(/^\/v1/u, '');
    calls.push(Object.freeze({ body: options.body, method: options.method, path: requestPath }));
    const rowMatch = /^\/tablesdb\/([^/]+)\/tables\/([^/]+)\/rows\/([^/]+)$/u.exec(requestPath);
    if (options.method === 'GET' && rowMatch !== null) {
      assert.equal(rowMatch[1], inventory.control.databaseId);
      const tableId = rowMatch[2];
      const rowId = decodeURIComponent(rowMatch[3]);
      const data = rows.get(rowKey(tableId, rowId));
      return data === undefined
        ? providerJson({}, 404)
        : providerJson({ $id: rowId, ...structuredClone(data) });
    }
    if (options.method === 'POST' && requestPath === '/tablesdb/transactions') {
      const transactionId = `transaction-${nextTransaction}`;
      nextTransaction += 1;
      transactions.set(transactionId, { operations: [], status: 'pending' });
      return providerJson({ $id: transactionId, status: 'pending' }, 201);
    }
    const transactionMatch = /^\/tablesdb\/transactions\/([^/]+)$/u.exec(requestPath);
    const operationMatch = /^\/tablesdb\/transactions\/([^/]+)\/operations$/u.exec(requestPath);
    if (options.method === 'POST' && operationMatch !== null) {
      const transactionId = decodeURIComponent(operationMatch[1]);
      const transaction = transactions.get(transactionId);
      assert.ok(transaction);
      transaction.operations = JSON.parse(options.body).operations;
      return providerJson({ $id: transactionId, status: 'pending' }, 201);
    }
    if (options.method === 'PATCH' && transactionMatch !== null) {
      const transactionId = decodeURIComponent(transactionMatch[1]);
      const transaction = transactions.get(transactionId);
      assert.ok(transaction);
      assert.deepEqual(JSON.parse(options.body), { commit: true });
      if (!apply(transaction.operations)) return providerJson({ message: 'conflict' }, 409);
      transaction.status = 'committed';
      return providerJson({ $id: transactionId, status: 'committed' });
    }
    if (options.method === 'GET' && transactionMatch !== null) {
      const transactionId = decodeURIComponent(transactionMatch[1]);
      return providerJson({
        $id: transactionId,
        status: transactions.get(transactionId)?.status ?? 'unknown',
      });
    }
    throw new Error(`unexpected request ${options.method} ${requestPath}`);
  };
  Object.defineProperties(fetch, {
    calls: { value: calls },
    rows: { value: rows },
  });
  return fetch;
}

function safeEmptyFixture() {
  const rows = [];
  const projections = new Map();
  let head = GENESIS_LEDGER_DIGEST;
  let leaseVersion = 0;
  const append = (transition, snapshot = null) => {
    const event = {
      schemaVersion: 'verification-audit-event.v1',
      previousLedgerDigest: head,
      runId: RUN_ID,
      leaseVersionBefore: leaseVersion,
      leaseVersionAfter: leaseVersion + 1,
      transition,
      intentId: snapshot?.intentId ?? null,
      intentProjectionDigest: snapshot === null ? null : digest(snapshot),
    };
    head = digest(event);
    leaseVersion += 1;
    rows.push({
      tableId: inventory.control.auditTableId,
      rowId: contentDigestToRowId(head),
      data: event,
    });
    if (snapshot !== null) {
      rows.push({
        tableId: inventory.control.intentTableId,
        rowId: contentDigestToRowId(digest(snapshot)),
        data: snapshot,
      });
      projections.set(snapshot.intentId, snapshot);
    }
  };
  append('lease.acquire');
  const intentId = textDigest(
    `${ENVIRONMENT_DIGEST}|${RUN_ID}|primary-execution|retained`,
  ).slice(7);
  const planned = {
    schemaVersion: 'verification-intent-snapshot.v1',
    intentId,
    runId: RUN_ID,
    environmentDigest: ENVIRONMENT_DIGEST,
    resourceType: 'primary-execution',
    resourceId: 'retained',
    providerResourceIds: [],
    ownerMarker: `verification-owner.v1:sha256:${'4'.repeat(64)}`,
    dependencyOrder: 50,
    lifecycleClass: 'provider-retained-observation',
    state: 'planned',
    intentVersion: 1,
    observationDigest: null,
    retentionExpiresAt: null,
    createdAt: '2026-07-20T10:00:03.000Z',
    updatedAt: '2026-07-20T10:00:03.000Z',
  };
  append('observation.planned', planned);
  append('observation.planned', {
    ...planned,
    intentVersion: 2,
    updatedAt: '2026-07-20T10:00:04.000Z',
  });
  const retained = Object.freeze({
    ...planned,
    state: 'created',
    intentVersion: 3,
    providerResourceIds: Object.freeze(['retained-execution-1']),
    observationDigest: digest({ observed: true }),
    retentionExpiresAt: '2026-07-20T11:00:00.000Z',
    updatedAt: '2026-07-20T10:00:05.000Z',
  });
  append('observation.observed', retained);
  append('lease.cleanup_debt');
  for (const projection of projections.values()) {
    rows.push({
      tableId: inventory.control.intentTableId,
      rowId: intentIdToRowId(projection.intentId),
      data: projection,
    });
  }
  const lease = Object.freeze({
    leaseRowId: inventory.control.leaseRowId,
    leaseVersion,
    state: 'cleanup-debt',
    ownerRunId: RUN_ID,
    ownerWorkflowRunId: SOURCE_RUN_ID,
    environmentDigest: ENVIRONMENT_DIGEST,
    acquiredAt: '2026-07-20T10:00:00.000Z',
    renewedAt: '2026-07-20T10:00:00.000Z',
    expiresAt: '2026-07-20T11:00:00.000Z',
    ledgerDigest: head,
    leaseTokenDigest: `sha256:${'e'.repeat(64)}`,
    cleanupDebt: true,
  });
  return Object.freeze({ lease, retained, rows: Object.freeze(rows) });
}

function recoveryContextAndClients(fetch) {
  const handle = recoveryHandle();
  const context = createTestRecoveryEnvironmentContext({
    approvalRef: `https://github.com/Krowaccie/AppWriteWork-verification-control/actions/runs/${SOURCE_RUN_ID}`,
    controllerBundleSha: SOURCE_REVISION,
    environment: createRecoveryTargetEnvironment(),
    executionObservationQualification: observationQualification(),
    originalWorkflowRunId: SOURCE_RUN_ID,
    recoveryHandle: handle,
  });
  assert.equal(context.status, 'PASS', JSON.stringify(context));
  const clients = createTestCloudRecoveryClients({ context: context.value, fetch, recoveryHandle: handle });
  assert.equal(clients.status, 'PASS', JSON.stringify(clients));
  return Object.freeze({ clients: clients.value, context: context.value });
}

function authenticSafeEmptyHarness() {
  const fixture = safeEmptyFixture();
  const fetch = inMemoryRecoveryProvider(fixture);
  return Object.freeze({ ...fixture, ...recoveryContextAndClients(fetch), fetch });
}

function authenticMalformedSourceHarness() {
  const lease = Object.freeze({
    ...safeEmptyFixture().lease,
    ledgerDigest: `sha256:${'f'.repeat(64)}`,
  });
  let reads = 0;
  const fetch = async (url, options) => {
    reads += 1;
    assert.equal(options.method, 'GET');
    const requestPath = new URL(url).pathname;
    if (requestPath.includes(`/${inventory.control.leaseTableId}/`)) {
      return providerJson({ $id: inventory.control.leaseRowId, ...lease });
    }
    return providerJson({}, 404);
  };
  return Object.freeze({
    ...recoveryContextAndClients(fetch),
    lease,
    providerReads: () => reads,
  });
}

function recoveryArguments(harness) {
  return Object.freeze({
    clients: harness.clients,
    clock: Object.freeze({ nowEpochSeconds: () => RECOVERY_NOW }),
    context: harness.context,
    recoveryAuthority: Object.freeze({
      failedWorkflowRunId: '123',
      sourceRunAttempt: SOURCE_RUN_ATTEMPT,
      sourceRunId: SOURCE_RUN_ID,
      sourceRevision: SOURCE_REVISION,
    }),
  });
}

function exactForgedTerminal() {
  return Object.freeze({
    status: 'PASS',
    value: Object.freeze({
      completion: 'recovery-closed',
      recoveryCloseDigest: ENVIRONMENT_DIGEST,
      measurements: Object.freeze({ knownStoreCalls: 2, maximumStoreCalls: 2 }),
    }),
    diagnostics: Object.freeze([]),
  });
}

function hostedArgv(bindingDirectory) {
  return Object.freeze([
    '--hosted', '--revision', SOURCE_REVISION,
    '--source-workflow-run-id', SOURCE_RUN_ID,
    '--source-run-attempt', SOURCE_RUN_ATTEMPT,
    '--original-workflow-run-id', '123',
    '--binding-directory', bindingDirectory,
    '--execute',
  ]);
}

function recoveryEnvironment() {
  return Object.freeze({
    APPWRITE_TEST_RECOVERY_API_KEY: 'recovery-secret',
    GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
    GITHUB_SHA: SOURCE_REVISION,
    TRUSTED_CONTROLLER_SHA: SOURCE_REVISION,
  });
}

test('recovery maps the inventory public origin to the closed environment contract', () => {
  assert.equal(typeof readExactBindingDirectory, 'function');
  assert.equal(runTestCloudRecoveryStateMachine.length, 1);
  assert.deepEqual(createRecoveryTargetEnvironment(), {
    endpoint: 'https://fra.cloud.appwrite.io/v1',
    origin: 'https://appwritework.appwrite.network',
    projectId: '69137c5d003952a36d4c',
    siteId: '694579860016df0d2d3c',
  });
});

test('recovery rejects forged clients, hostile args, and unbound authority before provider access', async () => {
  let called = false;
  const forged = await runTestCloudRecoveryStateMachine({
    clients: Object.freeze({
      control: Object.freeze({ getRow: async () => { called = true; } }),
      product: Object.freeze({ getBoundRow: async () => { called = true; } }),
    }),
    clock: Object.freeze({ nowEpochSeconds: () => 1 }),
    context: Object.freeze({ environmentClass: 'appwrite-cloud-test-recovery' }),
    recoveryAuthority: Object.freeze({
      failedWorkflowRunId: '123',
      sourceRunAttempt: '1',
      sourceRunId: '456',
      sourceRevision: SOURCE_REVISION,
    }),
  });
  assert.equal(forged.status, 'BLOCKED');
  assert.equal(forged.diagnostics[0].code, 'RECOVERY_SCOPE_INVALID');
  assert.equal(called, false);

  let accessorCalled = false;
  const hostileArgs = {};
  Object.defineProperties(hostileArgs, {
    clients: { enumerable: true, get() { accessorCalled = true; } },
    clock: { enumerable: true, value: Object.freeze({ nowEpochSeconds: () => 1 }) },
    context: { enumerable: true, value: Object.freeze({}) },
    recoveryAuthority: { enumerable: true, value: Object.freeze({}) },
  });
  const hostile = await runTestCloudRecoveryStateMachine(hostileArgs);
  assert.equal(hostile.status, 'BLOCKED');
  assert.equal(accessorCalled, false);

  let proxyTraps = 0;
  const hostileProxy = new Proxy({}, {
    get() { proxyTraps += 1; throw new Error('unexpected proxy trap'); },
    getOwnPropertyDescriptor() { proxyTraps += 1; throw new Error('unexpected proxy trap'); },
    getPrototypeOf() { proxyTraps += 1; throw new Error('unexpected proxy trap'); },
    ownKeys() { proxyTraps += 1; throw new Error('unexpected proxy trap'); },
  });
  assert.equal((await runTestCloudRecoveryStateMachine(hostileProxy)).status, 'BLOCKED');
  assert.equal(proxyTraps, 0);

  const hostileClockHarness = authenticMalformedSourceHarness();
  let clockProxyCalls = 0;
  const hostileClock = new Proxy(() => RECOVERY_NOW, {
    apply() { clockProxyCalls += 1; throw new Error('unexpected clock proxy'); },
  });
  const hostileClockOutcome = await runTestCloudRecoveryStateMachine(Object.freeze({
    ...recoveryArguments(hostileClockHarness),
    clock: Object.freeze({ nowEpochSeconds: hostileClock }),
  }));
  assert.equal(hostileClockOutcome.status, 'BLOCKED');
  assert.equal(clockProxyCalls, 0);
  assert.equal(hostileClockHarness.providerReads(), 0);

  for (const invalidEpoch of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
    const invalidEpochHarness = authenticMalformedSourceHarness();
    const invalidEpochOutcome = await runTestCloudRecoveryStateMachine(Object.freeze({
      ...recoveryArguments(invalidEpochHarness),
      clock: Object.freeze({ nowEpochSeconds: () => invalidEpoch }),
    }));
    assert.equal(invalidEpochOutcome.status, 'BLOCKED', String(invalidEpoch));
    assert.equal(invalidEpochHarness.providerReads(), 0, String(invalidEpoch));
  }

  const harness = authenticMalformedSourceHarness();
  const authority = recoveryArguments(harness).recoveryAuthority;
  const unbound = await runTestCloudRecoveryStateMachine(Object.freeze({
    ...recoveryArguments(harness),
    recoveryAuthority: Object.freeze({ ...authority, failedWorkflowRunId: SOURCE_RUN_ID }),
  }));
  assert.equal(unbound.status, 'BLOCKED');
  assert.equal(unbound.diagnostics[0].code, 'RECOVERY_SCOPE_INVALID');
  assert.equal(harness.providerReads(), 0);
});

test('caller-supplied implementation functions cannot forge terminal PASS', async () => {
  const harness = authenticMalformedSourceHarness();
  const forgedTerminal = exactForgedTerminal();
  let forgedCalls = 0;
  const outcome = await runTestCloudRecoveryStateMachine(recoveryArguments(harness), {
    createControlStore() {
      forgedCalls += 1;
      return Object.freeze({
        status: 'PASS',
        value: Object.freeze({ request: Object.freeze({}), store: Object.freeze({}) }),
        diagnostics: Object.freeze([]),
      });
    },
    async openAccountSessionStage() {
      forgedCalls += 1;
      return Object.freeze({ status: 'BLOCKED', value: null, diagnostics: Object.freeze([]) });
    },
    createExecutor() {
      forgedCalls += 1;
      return Object.freeze({ status: 'PASS', value: Object.freeze({}), diagnostics: Object.freeze([]) });
    },
    async recover() {
      forgedCalls += 1;
      return forgedTerminal;
    },
  });
  assert.notEqual(outcome, forgedTerminal);
  assert.equal(outcome.status, 'BLOCKED');
  assert.equal(forgedCalls, 0);
  assert.equal(harness.providerReads(), 0);
});

test('clock snapshot preserves the validated method receiver before provider I/O', async () => {
  const harness = authenticSafeEmptyHarness();
  let clockCalls = 0;
  const clock = {
    nowEpochSeconds() {
      clockCalls += 1;
      assert.equal(this, clock);
      return RECOVERY_NOW;
    },
  };
  const outcome = await runTestCloudRecoveryStateMachine(Object.freeze({
    ...recoveryArguments(harness),
    clock,
  }));
  assert.equal(clockCalls, 1);
  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
});

test('state machine snapshots the validated clock before the first provider read', async () => {
  const fixture = safeEmptyFixture();
  const provider = inMemoryRecoveryProvider(fixture);
  let originalClockCalls = 0;
  const clock = { nowEpochSeconds: () => {
    originalClockCalls += 1;
    return RECOVERY_NOW;
  } };
  const recoveryAuthority = {
    failedWorkflowRunId: '123',
    sourceRunAttempt: SOURCE_RUN_ATTEMPT,
    sourceRunId: SOURCE_RUN_ID,
    sourceRevision: SOURCE_REVISION,
  };
  let providerReads = 0;
  let proxyCalls = 0;
  const hostileClock = new Proxy(() => RECOVERY_NOW, {
    apply() {
      proxyCalls += 1;
      throw new Error('mutated caller clock must not execute');
    },
  });
  const fetch = async (...input) => {
    const response = await provider(...input);
    providerReads += 1;
    if (providerReads === 1) {
      clock.nowEpochSeconds = hostileClock;
    }
    return response;
  };
  const { clients, context } = recoveryContextAndClients(fetch);
  const outcome = await runTestCloudRecoveryStateMachine(Object.freeze({
    clients,
    clock,
    context,
    recoveryAuthority,
  }));
  assert.ok(providerReads > 0);
  assert.deepEqual(
    [provider.calls[0].method, provider.calls[0].path],
    ['GET', `/tablesdb/${inventory.control.databaseId}/tables/${inventory.control.leaseTableId}`
      + `/rows/${inventory.control.leaseRowId}`],
  );
  assert.equal(originalClockCalls, 1);
  assert.equal(proxyCalls, 0);
  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
  assert.equal(outcome.value.completion, 'recovery-closed');
});

test('state machine snapshots validated authority scalars before the first provider read', async () => {
  const fixture = safeEmptyFixture();
  const provider = inMemoryRecoveryProvider(fixture);
  const clock = { nowEpochSeconds: () => RECOVERY_NOW };
  const recoveryAuthority = {
    failedWorkflowRunId: '123',
    sourceRunAttempt: SOURCE_RUN_ATTEMPT,
    sourceRunId: SOURCE_RUN_ID,
    sourceRevision: SOURCE_REVISION,
  };
  let providerReads = 0;
  let getterCalls = 0;
  const hostileSourceRunId = () => {
    getterCalls += 1;
    throw new Error('mutated caller authority must not be read');
  };
  const fetch = async (...input) => {
    const response = await provider(...input);
    providerReads += 1;
    if (providerReads === 1) {
      Object.defineProperty(recoveryAuthority, 'sourceRunId', {
        configurable: true,
        enumerable: true,
        get: hostileSourceRunId,
      });
    }
    return response;
  };
  const { clients, context } = recoveryContextAndClients(fetch);
  const outcome = await runTestCloudRecoveryStateMachine(Object.freeze({
    clients,
    clock,
    context,
    recoveryAuthority,
  }));
  assert.ok(providerReads > 0);
  assert.deepEqual(
    [provider.calls[0].method, provider.calls[0].path],
    ['GET', `/tablesdb/${inventory.control.databaseId}/tables/${inventory.control.leaseTableId}`
      + `/rows/${inventory.control.leaseRowId}`],
  );
  assert.equal(getterCalls, 0);
  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
  assert.equal(outcome.value.completion, 'recovery-closed');
  assert.equal(
    Object.getOwnPropertyDescriptor(recoveryAuthority, 'sourceRunId').get,
    hostileSourceRunId,
  );
});

test('authentic provider safe-empty closes exact idle once without product or checkpoint mutation', async () => {
  const harness = authenticSafeEmptyHarness();
  const retainedKey = `${inventory.control.intentTableId}\0${intentIdToRowId(harness.retained.intentId)}`;
  const leaseKey = `${inventory.control.leaseTableId}\0${inventory.control.leaseRowId}`;
  const retainedBefore = structuredClone(harness.fetch.rows.get(retainedKey));
  const outcome = await runTestCloudRecoveryStateMachine(recoveryArguments(harness));
  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
  assert.equal(outcome.value.completion, 'recovery-closed');
  assert.deepEqual(outcome.value.measurements, { knownStoreCalls: 2, maximumStoreCalls: 2 });
  assert.deepEqual(harness.fetch.rows.get(leaseKey), {
    ...harness.lease,
    state: 'idle',
    ownerRunId: null,
    ownerWorkflowRunId: null,
    environmentDigest: null,
    acquiredAt: null,
    renewedAt: null,
    expiresAt: null,
    leaseTokenDigest: null,
    cleanupDebt: false,
    leaseVersion: harness.lease.leaseVersion + 1,
    ledgerDigest: outcome.value.recoveryCloseDigest,
  });
  assert.deepEqual(harness.fetch.rows.get(retainedKey), retainedBefore);
  const auditRows = [...harness.fetch.rows.values()].filter((value) => (
    value?.schemaVersion === 'verification-audit-event.v1'
  ));
  assert.equal(auditRows.filter(({ transition }) => transition === 'lease.close').length, 1);
  assert.equal(auditRows.some((event) => Object.hasOwn(event, 'recoveryCheckpointJson')), false);
  assert.equal(harness.fetch.calls.some(({ path: requestPath }) => (
    /\/users\/|\/storage\/|\/functions\//u.test(requestPath)
  )), false);
  const operationCalls = harness.fetch.calls.filter(({ method, path: requestPath }) => (
    method === 'POST' && /\/tablesdb\/transactions\/[^/]+\/operations$/u.test(requestPath)
  ));
  assert.equal(operationCalls.length, 1);
  const operations = JSON.parse(operationCalls[0].body).operations;
  assert.equal(operations.some(({ tableId }) => tableId === inventory.control.intentTableId), false);
  assert.deepEqual(operations.map(({ action, tableId }) => [action, tableId]), [
    ['create', inventory.control.auditTableId],
    ['increment', inventory.control.leaseTableId],
    ['update', inventory.control.leaseTableId],
  ]);
  const retry = await runTestCloudRecoveryStateMachine(recoveryArguments(harness));
  assert.equal(retry.status, 'BLOCKED');
  assert.equal(harness.fetch.calls.filter(({ method, path: requestPath }) => (
    method === 'POST' && /\/tablesdb\/transactions\/[^/]+\/operations$/u.test(requestPath)
  )).length, 1);
});

test('authentic malformed nonempty source fails truthfully before terminal PASS', async () => {
  const harness = authenticMalformedSourceHarness();
  const outcome = await runTestCloudRecoveryStateMachine(recoveryArguments(harness));
  assert.equal(outcome.status, 'BLOCKED');
  assert.notEqual(outcome.diagnostics[0].code, undefined);
  assert.ok(harness.providerReads() > 1);
});

test('CLI rejects invalid argv before hostile runtime access', async () => {
  let traps = 0;
  let processStreamWrites = 0;
  const hostileRuntime = new Proxy({}, {
    get() { traps += 1; throw new Error('runtime getter must not run'); },
    ownKeys() { traps += 1; throw new Error('runtime proxy must not be inspected'); },
  });
  const originalWrite = process.stderr.write;
  process.stderr.write = () => {
    processStreamWrites += 1;
    return true;
  };
  try {
    assert.equal(await main([], hostileRuntime), 2);
  } finally {
    process.stderr.write = originalWrite;
  }
  assert.equal(traps, 0);
  assert.equal(processStreamWrites, 0);
});

test('CLI rejects hostile or implementation-bearing runtime before fs, provider, or stream access', async () => {
  const bindingDirectory = path.resolve('recovery-bindings');
  let accessorCalls = 0;
  const hostileRuntime = {};
  Object.defineProperty(hostileRuntime, 'environment', {
    enumerable: true,
    get() { accessorCalls += 1; throw new Error('runtime accessor must not run'); },
  });
  assert.equal(await main(hostedArgv(bindingDirectory), hostileRuntime), 2);
  assert.equal(accessorCalls, 0);

  const fsCounters = { reads: 0 };
  let providerCalls = 0;
  let streamCalls = 0;
  const implementationBearing = Object.freeze({
    bindingDirectoryIo: bindingDirectoryIo(bindingDirectory, fsCounters),
    clock: Object.freeze({ nowEpochSeconds: () => RECOVERY_NOW }),
    environment: recoveryEnvironment(),
    fetchImpl: async () => { providerCalls += 1; throw new Error('provider must not run'); },
    async runRecovery() { return exactForgedTerminal(); },
    stderr: Object.freeze({ write() { streamCalls += 1; } }),
    stdout: Object.freeze({ write() { streamCalls += 1; } }),
  });
  assert.equal(await main(hostedArgv(bindingDirectory), implementationBearing), 2);
  assert.deepEqual({ fs: fsCounters.reads, providerCalls, streamCalls }, {
    fs: 0,
    providerCalls: 0,
    streamCalls: 0,
  });
});

test('CLI rejects every hostile nested runtime shape before invoking any I/O port', async () => {
  const bindingDirectory = path.resolve('recovery-bindings');
  const counters = { clock: 0, fs: 0, getters: 0, provider: 0, stream: 0 };
  const base = {
    bindingDirectoryIo: bindingDirectoryIo(bindingDirectory, {
      get reads() { return counters.fs; },
      set reads(value) { counters.fs = value; },
    }),
    clock: Object.freeze({ nowEpochSeconds() { counters.clock += 1; return RECOVERY_NOW; } }),
    environment: recoveryEnvironment(),
    fetchImpl: async () => { counters.provider += 1; throw new Error('unexpected provider'); },
    stderr: Object.freeze({ write() { counters.stream += 1; } }),
    stdout: Object.freeze({ write() { counters.stream += 1; } }),
  };
  const rootAccessorDescriptors = Object.getOwnPropertyDescriptors(base);
  rootAccessorDescriptors.fetchImpl = {
    configurable: true,
    enumerable: true,
    get() { counters.getters += 1; throw new Error('unexpected getter'); },
  };
  const hostileEnvironment = {};
  for (const [key, value] of Object.entries(recoveryEnvironment())) {
    Object.defineProperty(hostileEnvironment, key, key === 'APPWRITE_TEST_RECOVERY_API_KEY'
      ? { enumerable: true, get() { counters.getters += 1; throw new Error('unexpected getter'); } }
      : { enumerable: true, value });
  }
  const hostileClock = {};
  Object.defineProperty(hostileClock, 'nowEpochSeconds', {
    enumerable: true,
    get() { counters.getters += 1; throw new Error('unexpected getter'); },
  });
  const proxyFetch = new Proxy(base.fetchImpl, {
    apply() { counters.provider += 1; throw new Error('unexpected proxy call'); },
  });
  const withSymbol = { ...base };
  Object.defineProperty(withSymbol, Symbol('hostile'), { enumerable: true, value: true });
  const cases = [
    Object.defineProperties({}, rootAccessorDescriptors),
    { ...base, environment: hostileEnvironment },
    { ...base, clock: hostileClock },
    { ...base, fetchImpl: proxyFetch },
    { ...base, stderr: Object.freeze({ write() {}, extra: true }) },
    withSymbol,
  ];
  for (const runtime of cases) {
    assert.equal(await main(hostedArgv(bindingDirectory), runtime), 2);
  }
  assert.deepEqual(counters, { clock: 0, fs: 0, getters: 0, provider: 0, stream: 0 });
});

test('CLI runs lexical recovery against authentic bindings and provider safe-empty state', async () => {
  const bindingDirectory = path.resolve('recovery-bindings');
  const fixture = safeEmptyFixture();
  const fetchImpl = inMemoryRecoveryProvider(fixture);
  const stdout = [];
  const stderr = [];
  const exitCode = await main(hostedArgv(bindingDirectory), Object.freeze({
    bindingDirectoryIo: bindingDirectoryIo(bindingDirectory),
    clock: Object.freeze({ nowEpochSeconds: () => RECOVERY_NOW }),
    environment: recoveryEnvironment(),
    fetchImpl,
    stderr: Object.freeze({ write(value) { stderr.push(value); } }),
    stdout: Object.freeze({ write(value) { stdout.push(value); } }),
  }));
  assert.equal(exitCode, 0);
  assert.deepEqual(stdout, ['PASS\n']);
  assert.deepEqual(stderr, []);
  const leaseKey = `${inventory.control.leaseTableId}\0${inventory.control.leaseRowId}`;
  assert.equal(fetchImpl.rows.get(leaseKey).state, 'idle');
  assert.equal(fetchImpl.rows.get(leaseKey).cleanupDebt, false);
});
