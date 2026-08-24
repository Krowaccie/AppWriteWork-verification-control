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
      safeMessage: 'untrusted diagnostic text',
    }],
  };
}

function dependencies(sourceCode) {
  const diagnostic = typeof sourceCode === 'string'
    ? {
      code: sourceCode,
      retryable: false,
      safeMessage: 'untrusted diagnostic text',
    }
    : sourceCode;
  return {
    async bootstrapRuntime() { return stage('PASS', {}); },
    async createOrdinaryLane() { return stage('PASS', {}); },
    async createPlaywrightFacade() { return stage('PASS', {}); },
    async qualifyContainment() { return stage('PASS', {}); },
    async consumeSourceArtifact() {
      return { status: 'BLOCKED', value: null, diagnostics: [diagnostic] };
    },
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

test('preserves an allowlisted source-reader diagnostic with fixed safe text', async () => {
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

test('collapses an unknown source-reader diagnostic without reflecting it', async () => {
  const outcome = await run('SECRET_VALUE_DO_NOT_EXPOSE');
  assert.equal(outcome.status, 'BLOCKED');
  assert.equal(outcome.diagnostics[0].code, 'SOURCE_ARTIFACT_INVALID');
  assert.equal(JSON.stringify(outcome).includes('SECRET_VALUE_DO_NOT_EXPOSE'), false);
});

test('does not invoke or reflect stateful and throwing source diagnostic accessors', async (t) => {
  const cases = [
    ['stateful', (calls) => (
      calls === 1
        ? 'SOURCE_INSTALLATION_TOKEN_CREATE_FAILED'
        : 'SECRET_VALUE_DO_NOT_EXPOSE'
    )],
    ['throwing', () => { throw new Error('SECRET_ACCESSOR_VALUE'); }],
  ];
  for (const [name, readCode] of cases) {
    await t.test(name, async () => {
      let getterCalls = 0;
      const diagnostic = { retryable: false, safeMessage: 'untrusted' };
      Object.defineProperty(diagnostic, 'code', {
        enumerable: true,
        get() {
          getterCalls += 1;
          return readCode(getterCalls);
        },
      });
      const outcome = await run(diagnostic);
      assert.equal(outcome.status, 'BLOCKED');
      assert.equal(outcome.diagnostics[0].code, 'SOURCE_ARTIFACT_INVALID');
      assert.equal(getterCalls, 0);
      assert.equal(JSON.stringify(outcome).includes('SECRET_VALUE_DO_NOT_EXPOSE'), false);
      assert.equal(JSON.stringify(outcome).includes('SECRET_ACCESSOR_VALUE'), false);
    });
  }
});
