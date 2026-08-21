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
    'RECOVERY_ACCOUNT_SESSION_PROVIDER_INTENT_MISSING',
    'RECOVERY_ACCOUNT_SESSION_PROVIDER_INTENT_STATE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_ACQUIRE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RUN_CHAIN_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RENEW_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_CLEANUP_DEBT_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RECOVER_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_CLOSE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_SOURCE_STATE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_RUN_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_DEBT_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_WORKFLOW_TYPE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_OWNER_WORKFLOW_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_LEASE_RECOVERY_STATE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PROVIDER_BINDING_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_EVIDENCE_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_GLOBAL_CLEANUP_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_SESSION_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_SHARE_MISSING',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_SHARE_DUPLICATED',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_GRAPH_MISSING',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_GRAPH_DUPLICATED',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_PROJECT_MISSING',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PRIMARY_PROJECT_DUPLICATED',
    'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_POSITION_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_RUN_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_ENVIRONMENT_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_INTENT_SET_ACCOUNT_SESSION_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_RECOVERY_EVENT_INVALID',
    'RECOVERY_ACCOUNT_SESSION_PROOF_PROJECTION_INVALID',
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

test('recovery keeps the failed controller run separate from the source lease owner', async () => {
  const [controller, environment, controlStore, providerStore, workflow] = await Promise.all([
    readFile('packages/verification-controller/src/test-cloud-recovery-controller.mjs', 'utf8'),
    readFile('scripts/verification/test-cloud-environment.mjs', 'utf8'),
    readFile('scripts/verification/test-cloud-control-store.mjs', 'utf8'),
    readFile('scripts/verification/test-cloud-provider-control-store.mjs', 'utf8'),
    readFile('.github/workflows/recover-appwrite-test.yml', 'utf8'),
  ]);
  assert.match(controller, /--source-workflow-run-id/u);
  assert.match(controller, /sourceWorkflowRunId: parsed\.sourceWorkflowRunId/u);
  assert.match(environment, /'sourceWorkflowRunId'/u);
  assert.match(controlStore, /ownerWorkflowRunId!==fields\.context\.sourceWorkflowRunId/u);
  assert.match(providerStore, /ownerWorkflowRunId !== recoveryContext\.sourceWorkflowRunId/u);
  assert.doesNotMatch(providerStore, /ownerWorkflowRunId !== recoveryContext\.originalWorkflowRunId/u);
  assert.match(workflow, /--source-workflow-run-id "\$\{\{ inputs\.source_run_id \}\}"/u);
});

test('recovery admits an expired active lease without weakening the cleanup-debt pair', async () => {
  const [controlStore, providerStore] = await Promise.all([
    readFile('scripts/verification/test-cloud-control-store.mjs', 'utf8'),
    readFile('scripts/verification/test-cloud-provider-control-store.mjs', 'utf8'),
  ]);
  for (const source of [controlStore, providerStore]) {
    assert.match(source, /state === 'active' && cleanupDebt === false/u);
    assert.match(source, /state === 'cleanup-debt' && cleanupDebt === true/u);
    assert.match(source, /state === 'recovering' && cleanupDebt === true/u);
  }
  assert.match(controlStore, /Date\.parse\(reconstruction\.lease\.expiresAt\)>now\*1000/u);
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
