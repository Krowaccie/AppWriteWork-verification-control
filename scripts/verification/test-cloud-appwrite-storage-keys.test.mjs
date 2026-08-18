import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createTestCloudClients } from './test-cloud-appwrite.mjs';
import { createTestEnvironmentContext } from './test-cloud-environment.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const inventory = JSON.parse(await readFile(
  path.join(ROOT, 'dev/verification/environments/test-cloud.inventory.v1.json'),
  'utf8',
));

const ENDPOINT = 'https://fra.cloud.appwrite.io/v1';
const PROJECT_ID = '69137c5d003952a36d4c';
const REVISION = '6d796c14ceba6676c85e78b760f1cf6288e4564e';
const RUN_ID = 'verify-6d796c14ceba-32106399617-1';
const INTENT_TABLE_ID = 'verification_intents';
const INTENT_ROW_ID = `h${'a'.repeat(35)}`;
const LOGICAL_RETENTION_KEY = 'cleanupRunnerExecutionRetentionExpiresAt';
const STORAGE_RETENTION_KEY = 'cleanupRunnerExecutionRetentionAt';
const RETENTION_TIMESTAMP = '2026-08-19T08:00:00.000Z';

function credentialHandle(record) {
  return Object.freeze({
    credentialClass: record.credentialClass,
    variableName: record.variableName,
    scopes: Object.freeze([...record.scopes]),
    readSecret() {
      return `${record.credentialClass}-secret-sentinel`;
    },
  });
}

function createHarness(responses) {
  const credentialHandles = Object.freeze({
    operator: credentialHandle(inventory.credentialVariables.operator),
    fixture: credentialHandle(inventory.credentialVariables.fixture),
  });
  const contextResult = createTestEnvironmentContext({
    inventory,
    environment: {
      endpoint: ENDPOINT,
      projectId: PROJECT_ID,
      siteId: '694579860016df0d2d3c',
      origin: 'https://appwritework.appwrite.network',
    },
    candidateRevision: REVISION,
    runId: RUN_ID,
    credentialHandles,
  });
  assert.equal(contextResult.status, 'PASS');

  const calls = [];
  const queue = [...responses];
  const fetch = async (url, options) => {
    calls.push({ options, url });
    assert.notEqual(queue.length, 0, 'fake response queue exhausted');
    return queue.shift();
  };
  const clientsResult = createTestCloudClients({
    context: contextResult.value,
    credentialHandles,
    fetch,
  });
  assert.equal(clientsResult.status, 'PASS');
  return { calls, fixture: clientsResult.value.fixture };
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('intent row transport aliases the overlong retention key and restores it on readback', async () => {
  assert.ok(STORAGE_RETENTION_KEY.length <= 36);
  const logicalData = {
    state: 'cleaning',
    [LOGICAL_RETENTION_KEY]: RETENTION_TIMESTAMP,
  };
  const { calls, fixture } = createHarness([
    jsonResponse({
      $id: INTENT_ROW_ID,
      state: 'cleaning',
      [STORAGE_RETENTION_KEY]: RETENTION_TIMESTAMP,
    }, 201),
  ]);

  const result = await fixture.upsertRow({
    tableId: INTENT_TABLE_ID,
    rowId: INTENT_ROW_ID,
    data: logicalData,
  });

  assert.equal(result.status, 'PASS');
  assert.deepEqual(result.value.data, logicalData);
  const wire = JSON.parse(calls[0].options.body);
  assert.equal(wire.data[STORAGE_RETENTION_KEY], RETENTION_TIMESTAMP);
  assert.equal(Object.hasOwn(wire.data, LOGICAL_RETENTION_KEY), false);
});

test('intent transaction operations use the bounded storage alias', async () => {
  const transactionId = 'transaction-1';
  const { calls, fixture } = createHarness([
    jsonResponse({ $id: transactionId, status: 'pending' }, 201),
    jsonResponse({ $id: transactionId, status: 'pending' }, 201),
  ]);
  const created = await fixture.createTransaction({ ttl: 60 });
  assert.equal(created.status, 'PASS');

  const result = await fixture.createTransactionOperations({
    transactionId,
    operations: [{
      action: 'upsertRow',
      tableId: INTENT_TABLE_ID,
      rowId: INTENT_ROW_ID,
      data: {
        state: 'cleaning',
        [LOGICAL_RETENTION_KEY]: RETENTION_TIMESTAMP,
      },
    }],
  });

  assert.equal(result.status, 'PASS');
  const wire = JSON.parse(calls[1].options.body);
  assert.equal(wire.operations[0].data[STORAGE_RETENTION_KEY], RETENTION_TIMESTAMP);
  assert.equal(Object.hasOwn(wire.operations[0].data, LOGICAL_RETENTION_KEY), false);
});
