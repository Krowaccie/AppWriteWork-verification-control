import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import {
  createRecoveryTargetEnvironment,
  main,
  runTestCloudRecoveryStateMachine,
} from './test-cloud-recovery-controller.mjs';

test('recovery maps the inventory public origin to the closed environment contract', () => {
  assert.deepEqual(createRecoveryTargetEnvironment(), {
    endpoint: 'https://fra.cloud.appwrite.io/v1',
    origin: 'https://appwritework.appwrite.network',
    projectId: '69137c5d003952a36d4c',
    siteId: '694579860016df0d2d3c',
  });
});

test('recovery CLI rejects malformed authority before filesystem or network access', async () => {
  let called = false;
  const dependencies = {
    fetchImpl: async () => {
      called = true;
      throw new Error('unexpected fetch');
    },
    environment: Object.freeze({}),
  };
  assert.equal(await main([], dependencies), 2);
  assert.equal(await main([
    '--hosted',
    '--original-workflow-run-id',
    '0',
    '--binding-directory',
    path.resolve('bindings'),
    '--execute',
  ], dependencies), 2);
  assert.equal(called, false);
});

test('recovery state machine rejects forged recovery clients before a provider call', async () => {
  let called = false;
  const forged = Object.freeze({
    control: Object.freeze({ getRow: async () => { called = true; } }),
    product: Object.freeze({ getBoundRow: async () => { called = true; } }),
  });
  const outcome = await runTestCloudRecoveryStateMachine({
    clients: forged,
    clock: Object.freeze({ nowEpochSeconds: () => 1 }),
    context: Object.freeze({ environmentClass: 'appwrite-cloud-test-recovery' }),
  });
  assert.equal(outcome.status, 'BLOCKED');
  assert.equal(outcome.diagnostics[0].code, 'RECOVERY_SCOPE_INVALID');
  assert.equal(called, false);
});
