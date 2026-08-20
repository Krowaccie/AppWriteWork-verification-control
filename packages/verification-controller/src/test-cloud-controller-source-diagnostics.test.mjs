import assert from 'node:assert/strict';
import test from 'node:test';

import { runHostedTestCloudController } from './test-cloud-controller.mjs';

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
