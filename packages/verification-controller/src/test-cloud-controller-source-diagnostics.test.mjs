import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  githubSourceRequest,
  runHostedTestCloudController,
  selectSafeDiagnosticCode,
  selectSafePreflightDiagnosticCode,
} from './test-cloud-controller.mjs';

const SHA = '1'.repeat(40);

function stage(status, value, code = null) {
  return {
    status,
    value,
    diagnostics: code === null ? [] : [{
      code,
      retryable: false,
      safeMessage: 'safe diagnostic',
    }],
  };
}

function dependencies(sourceCode) {
  return {
    async bootstrapRuntime() { return stage('PASS', {}); },
    async createOrdinaryLane() { return stage('PASS', {}); },
    async createPlaywrightFacade() { return stage('PASS', {}); },
    async qualifyContainment() { return stage('PASS', {}); },
    async consumeSourceArtifact() { return stage('BLOCKED', null, sourceCode); },
    async reattestController() { return stage('PASS', {}); },
    async runLane() { return stage('PASS', {}); },
    async validateSetupBindings() { return stage('PASS', {}); },
    async validateSourceArtifact() { return stage('PASS', {}); },
  };
}

async function run(sourceCode) {
  return runHostedTestCloudController({
    dependencies: dependencies(sourceCode),
    environment: { SOURCE_ARTIFACT_READER_PRIVATE_KEY: 'secret' },
    request: {
      requestedRevision: SHA,
      sourceRunId: '123',
      sourceRunAttempt: 1,
    },
  });
}

test('preserves an allowlisted source-reader diagnostic', async () => {
  const outcome = await run('SOURCE_INSTALLATION_TOKEN_CREATE_FAILED');
  assert.equal(outcome.status, 'BLOCKED');
  assert.equal(
    outcome.diagnostics[0].code,
    'SOURCE_INSTALLATION_TOKEN_CREATE_FAILED',
  );
  assert.equal(
    outcome.diagnostics[0].safeMessage,
    'The selected source artifact failed the trusted handoff checks.',
  );
});

test('collapses an unknown source-reader diagnostic', async () => {
  const outcome = await run('SECRET_VALUE_DO_NOT_EXPOSE');
  assert.equal(outcome.status, 'BLOCKED');
  assert.equal(outcome.diagnostics[0].code, 'SOURCE_ARTIFACT_INVALID');
});

test('downloads a bounded source artifact through one trusted redirect', async () => {
  const archive = Uint8Array.from({ length: 24 }, (_, index) => index);
  const redirectUrl =
    'https://productionresultssa2.blob.core.windows.net/actions-results/run/artifact.zip?sig=test';
  const calls = [];
  const outcome = await githubSourceRequest(async (url, options) => {
    calls.push([url, options]);
    if (calls.length === 1) {
      return new Response(null, { status: 302, headers: { location: redirectUrl } });
    }
    return new Response(archive, {
      status: 200,
      headers: { 'content-length': String(archive.byteLength) },
    });
  }, '/repos/Krowaccie/AppWriteWork/actions/artifacts/9420071362/zip', {
    method: 'GET',
    headers: { Authorization: 'Bearer source-token' },
    redirect: 'error',
    expectedBytes: archive.byteLength,
  });
  assert.deepEqual(outcome.bytes, archive);
  assert.equal(calls[0][1].redirect, 'manual');
  assert.equal(calls[1][0], redirectUrl);
  assert.equal(calls[1][1].redirect, 'error');
  assert.equal(Object.hasOwn(calls[1][1].headers, 'Authorization'), false);
});

test('rejects a source artifact redirect outside trusted storage', async () => {
  await assert.rejects(
    githubSourceRequest(async () => new Response(null, {
      status: 302,
      headers: { location: 'https://example.invalid/artifact.zip?sig=test' },
    }), '/repos/Krowaccie/AppWriteWork/actions/artifacts/9420071362/zip', {
      method: 'GET',
      headers: { Authorization: 'Bearer source-token' },
      redirect: 'error',
      expectedBytes: 24,
    }),
    (error) => error?.code === 'SOURCE_ARTIFACT_DOWNLOAD_FAILED',
  );
});

test('selects only an explicitly safe stage diagnostic', () => {
  const allowed = new Set(['TEST_CLOUD_RUNNER_VARIABLE_READBACK_INVALID']);
  const outcome = stage(
    'BLOCKED',
    null,
    'TEST_CLOUD_RUNNER_VARIABLE_READBACK_INVALID',
  );
  assert.equal(
    selectSafeDiagnosticCode(
      outcome,
      'TEST_CLOUD_PREFLIGHT_BLOCKED',
      allowed,
    ),
    'TEST_CLOUD_RUNNER_VARIABLE_READBACK_INVALID',
  );
  outcome.diagnostics[0].code = 'SECRET_VALUE_DO_NOT_EXPOSE';
  assert.equal(
    selectSafeDiagnosticCode(
      outcome,
      'TEST_CLOUD_PREFLIGHT_BLOCKED',
      allowed,
    ),
    'TEST_CLOUD_PREFLIGHT_BLOCKED',
  );
});

test('preserves only allowlisted identity-shape diagnostics at preflight', () => {
  assert.equal(
    selectSafePreflightDiagnosticCode(stage(
      'BLOCKED',
      null,
      'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID',
    )),
    'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID',
  );
  assert.equal(
    selectSafePreflightDiagnosticCode(stage(
      'BLOCKED',
      null,
      'TEST_IDENTITY_USER_KEYS_INVALID',
    )),
    'TEST_IDENTITY_USER_KEYS_INVALID',
  );
  assert.equal(
    selectSafePreflightDiagnosticCode(stage(
      'BLOCKED',
      null,
      'SECRET_VALUE_DO_NOT_EXPOSE',
    )),
    'TEST_CLOUD_PREFLIGHT_BLOCKED',
  );
});

test('ordinary lane reports the exact cleanup phase without exposing provider details', async () => {
  const [source, fixtures] = await Promise.all([
    readFile('scripts/verification/test-cloud-lane.mjs', 'utf8'),
    readFile('scripts/verification/test-cloud-fixtures.mjs', 'utf8'),
  ]);
  for (const code of [
    'CLEANUP_EXECUTION_FAILED',
    'CLEANUP_ABSENCE_PROOF_FAILED',
    'CLEANUP_LEASE_CLOSE_FAILED',
  ]) {
    assert.match(source, new RegExp(`'${code}'`, 'u'));
  }
  assert.match(
    source,
    /cleanupFailure = result\('BLOCKED', null, 'CLEANUP_EXECUTION_FAILED'\);/u,
  );
  assert.match(
    source,
    /cleanupFailure = result\('BLOCKED', null, 'CLEANUP_ABSENCE_PROOF_FAILED'\);/u,
  );
  assert.match(
    source,
    /cleanupFailure = result\('BLOCKED', null, 'CLEANUP_LEASE_CLOSE_FAILED'\);/u,
  );
  for (const code of [
    'CLEANUP_READ_FAILED',
    'CLEANUP_OWNERSHIP_MISMATCH',
    'CLEANUP_DELETE_FAILED',
    'CLEANUP_DELETE_READBACK_FAILED',
    'CLEANUP_INTENT_COMMIT_FAILED',
    'CLEANUP_EXECUTION_EXCEPTION',
  ]) {
    assert.match(source, new RegExp(`'${code}'`, 'u'));
    assert.match(fixtures, new RegExp(`'${code}'`, 'u'));
  }
  assert.match(
    source,
    /stageFailure\(cleaned, 'CLEANUP_EXECUTION_FAILED', true\)/u,
  );
});
