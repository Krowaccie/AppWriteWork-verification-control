import assert from 'node:assert/strict';
import test from 'node:test';

import { issueTrustedControllerContextForArtifactVerifier } from '../../core/controller-bundle.mjs';
import { digestJson } from '../../core/controller-trust-materials-test-helper.mjs';
import inventory from '../../fixtures/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import { runHostedTestCloudController } from './test-cloud-controller.mjs';

const SHA = '1'.repeat(40);
const CONTROLLER_SHA = '2'.repeat(40);
const DIGEST = `sha256:${'a'.repeat(64)}`;

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

function trustedController() {
  const issued = issueTrustedControllerContextForArtifactVerifier({
    manifest: {
      schemaVersion: 'controller-bundle.v2',
      sourceRepository: 'Krowaccie/AppWriteWork',
      sourceRepositoryRevision: SHA,
      controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
      controllerRevision: CONTROLLER_SHA,
      entrypoints: [
        { path: 'verification/controller/src/test-cloud-controller.mjs', sha256: DIGEST },
      ],
      files: [
        { path: 'verification/controller/src/test-cloud-controller.mjs', sha256: DIGEST },
      ],
      schemaDigests: [
        { path: 'verification/schemas/controller-bundle.v2.schema.json', sha256: DIGEST },
      ],
      trustMaterials: [
        { kind: 'evaluator', path: 'trust/evaluator.v1.json', sha256: DIGEST },
        { kind: 'evidenceValidator', path: 'trust/evidence-validator.v1.json', sha256: DIGEST },
        { kind: 'networkPolicy', path: 'trust/network-policy.v1.json', sha256: DIGEST },
        { kind: 'transcriptCorpus', path: 'trust/transcript-corpus.v2.json', sha256: DIGEST },
      ],
      provenance: { path: 'trust/provenance.v1.json', sha256: DIGEST },
    },
    controllerArtifactId: '1',
    controllerBundleDigest: DIGEST,
  });
  assert.equal(issued.status, 'PASS');
  return issued.value;
}

function setupBindings(controller) {
  return Object.freeze({
    constructionBinding: Object.freeze({
      controllerArtifactId: controller.controllerArtifactId,
      controllerBundleDigest: controller.controllerBundleDigest,
      controllerRevision: controller.controllerBundleSha,
      controllerSourceRepositoryRevision: controller.sourceRepositoryRevision,
      environmentDigest: digestJson(inventory),
      hostedSetupReadbackDigest: DIGEST,
      providerContractDigest: inventory.providerContractDigest,
      providerSetupReadbackDigest: DIGEST,
    }),
  });
}

function dependencies(sourceCode) {
  const controller = trustedController();
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
    async reattestController() { return stage('PASS', controller); },
    async runLane() { return stage('PASS', {}); },
    async validateSetupBindings() { return stage('PASS', setupBindings(controller)); },
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
