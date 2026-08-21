import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  createRecoveryTargetEnvironment,
  describeRecoveryStageFailure,
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

test('recovery replaces ambiguous internals with a fixed safe stage diagnostic', () => {
  const cases = {
    'account-sessions-open': 'RECOVERY_ACCOUNT_SESSIONS_OPEN_INVALID',
    'account-sessions-list': 'RECOVERY_ACCOUNT_SESSIONS_LIST_INVALID',
    'account-sessions-list-commit': 'RECOVERY_ACCOUNT_SESSIONS_LIST_COMMIT_INVALID',
    'account-sessions-delete': 'RECOVERY_ACCOUNT_SESSIONS_DELETE_INVALID',
    'account-sessions-delete-commit': 'RECOVERY_ACCOUNT_SESSIONS_DELETE_COMMIT_INVALID',
  };
  for (const [stage, expected] of Object.entries(cases)) {
    const outcome = describeRecoveryStageFailure(stage, {
      status: 'BLOCKED',
      value: null,
      diagnostics: [{ code: 'AUDIT_CHAIN_MISMATCH' }],
    });
    assert.equal(outcome.status, 'BLOCKED');
    assert.equal(outcome.diagnostics[0].code, expected);
  }
});

test('recovery preserves an already fixed nested stage diagnostic', () => {
  const nested = {
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code: 'RECOVERY_ACCOUNT_SESSIONS_OPEN_INVALID',
      safeMessage: 'Appwrite Test recovery was blocked.',
      retryable: false,
    }],
  };
  assert.equal(describeRecoveryStageFailure('account-sessions', nested), nested);
});

test('account-session open classifies source, snapshot, intent, binding, and lease failures', async () => {
  const source = await readFile('scripts/verification/test-cloud-control-store.mjs', 'utf8');
  for (const code of [
    'RECOVERY_ACCOUNT_SESSION_SOURCE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_SNAPSHOT_INVALID',
    'RECOVERY_ACCOUNT_SESSION_INTENT_MISSING',
    'RECOVERY_ACCOUNT_SESSION_BINDING_INVALID',
    'RECOVERY_ACCOUNT_SESSION_LEASE_INVALID',
  ]) {
    assert.match(source, new RegExp(`blocked\\('${code}'\\)`, 'u'));
    const nested = {
      status: 'BLOCKED',
      value: null,
      diagnostics: [{ code, safeMessage: 'safe', retryable: false }],
    };
    assert.equal(describeRecoveryStageFailure('account-sessions-open', nested), nested);
  }
});

test('provider account-session source separates remote reads from proof reconstruction', async () => {
  const source = await readFile(
    'scripts/verification/test-cloud-provider-control-store.mjs',
    'utf8',
  );
  for (const code of [
    'RECOVERY_ACCOUNT_SESSION_PROVIDER_READ_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROVIDER_PROOF_INVALID',
  ]) {
    assert.match(source, new RegExp(`'${code}'`, 'u'));
    const nested = {
      status: 'BLOCKED',
      value: null,
      diagnostics: [{ code, safeMessage: 'safe', retryable: false }],
    };
    assert.equal(describeRecoveryStageFailure('account-sessions-open', nested), nested);
  }
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
