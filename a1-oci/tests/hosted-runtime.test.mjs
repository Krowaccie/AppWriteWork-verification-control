import assert from 'node:assert/strict';
import test from 'node:test';

import {
  captureGithubArtifactRuntimeBinding,
  createHostedRuntimeConfiguration,
  HOSTED_RUNTIME_PATHS,
  parseHostedRequest,
  runHostedRuntime,
} from '../host/hosted-runtime.mjs';
import { createGithubArtifactClient } from '../host/github-artifact-client.mjs';

const REVISION = '0123456789abcdef0123456789abcdef01234567';
const TREE_DIGEST = `sha256:${'a'.repeat(64)}`;

function request(overrides = {}) {
  return {
    repository: 'Krowaccie/AppWriteWork',
    schemaVersion: 'verification-a1-hosted-request.v1',
    sourceRef: 'refs/heads/main',
    sourceRevision: REVISION,
    sourceTreeDigest: TREE_DIGEST,
    workflow: 'Verify Main',
    workflowRunAttempt: 2,
    workflowRunId: '12345',
    ...overrides,
  };
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

test('hosted request is an exact canonical source and workflow binding', () => {
  const text = canonical(request());
  assert.deepEqual(parseHostedRequest(text), Object.freeze(request()));
  assert.throws(() => parseHostedRequest(`${text}\n`), /HOSTED_REQUEST_INVALID/u);
  assert.throws(() => parseHostedRequest(canonical(request({ extra: true }))), /HOSTED_REQUEST_INVALID/u);
  assert.throws(() => parseHostedRequest(canonical(request({ repository: 'other/repo' }))), /HOSTED_REQUEST_INVALID/u);
  assert.throws(() => parseHostedRequest(canonical(request({ sourceRevision: 'main' }))), /HOSTED_REQUEST_INVALID/u);
});

test('runtime binding removes GitHub artifact credentials before candidate work and restores only for upload', async () => {
  const environment = {
    ACTIONS_RESULTS_URL: 'https://results.example.invalid/',
    ACTIONS_RUNTIME_TOKEN: 'secret-runtime-token',
    GITHUB_ACTIONS: 'true',
  };
  const binding = captureGithubArtifactRuntimeBinding(environment);
  assert.deepEqual(Object.keys(binding), ['runUpload']);
  assert.equal(environment.ACTIONS_RUNTIME_TOKEN, undefined);
  assert.equal(environment.ACTIONS_RESULTS_URL, undefined);

  const observed = await binding.runUpload(async () => {
    assert.equal(environment.ACTIONS_RUNTIME_TOKEN, 'secret-runtime-token');
    assert.equal(environment.ACTIONS_RESULTS_URL, 'https://results.example.invalid/');
    await assert.rejects(() => binding.runUpload(async () => null), /ARTIFACT_UPLOAD_ACTIVE/u);
    return 'uploaded';
  });
  assert.equal(observed, 'uploaded');
  assert.equal(environment.ACTIONS_RUNTIME_TOKEN, undefined);
  assert.equal(environment.ACTIONS_RESULTS_URL, undefined);
  await assert.rejects(() => binding.runUpload(async () => null), /ARTIFACT_UPLOAD_ALREADY_USED/u);
});

test('runtime binding fails closed outside GitHub Actions without deleting unrelated values', () => {
  const environment = { KEEP: 'value' };
  assert.throws(() => captureGithubArtifactRuntimeBinding(environment), /ARTIFACT_UPLOAD_RUNTIME_UNAVAILABLE/u);
  assert.deepEqual(environment, { KEEP: 'value' });
});

test('official artifact client restores runtime values only around the pinned upload operation', async () => {
  const environment = {
    ACTIONS_RESULTS_URL: 'https://results.example.invalid/',
    ACTIONS_RUNTIME_TOKEN: 'secret-runtime-token',
    GITHUB_ACTIONS: 'true',
  };
  const runtimeBinding = captureGithubArtifactRuntimeBinding(environment);
  const client = createGithubArtifactClient({
    runtimeBinding,
    uploadOperation: async ({ artifactName, files, rootDirectory }) => {
      assert.equal(environment.ACTIONS_RUNTIME_TOKEN, 'secret-runtime-token');
      assert.equal(artifactName, 'verification-artifacts-test');
      assert.equal(files.length, 39);
      assert.equal(rootDirectory, '/trusted/staging');
      return { id: 1, size: 39 };
    },
  });
  const files = Array.from({ length: 39 }, (_, index) => `/trusted/staging/${index}`);
  const result = await client.uploadArtifact(
    'verification-artifacts-test',
    files,
    '/trusted/staging',
    { compressionLevel: 0 },
  );
  assert.deepEqual(result, { id: 1, size: 39 });
  assert.equal(environment.ACTIONS_RUNTIME_TOKEN, undefined);
  assert.equal(environment.ACTIONS_RESULTS_URL, undefined);
});

test('hosted runtime configuration is frozen and contains no credential values', () => {
  const configuration = createHostedRuntimeConfiguration(parseHostedRequest(canonical(request())));
  assert.equal(Object.isFrozen(configuration), true);
  assert.equal(configuration.sourceCheckoutRoot, '/github/workspace');
  assert.equal(configuration.nodeExecutable, '/usr/local/bin/node');
  assert.equal(configuration.npmExecutable, '/usr/local/bin/npm');
  assert.equal(configuration.producerArgv.at(1), `.verification/artifacts/${REVISION}`);
  assert.equal(configuration.limits.outputFileMembers, 39);
  assert.equal(JSON.stringify(configuration).includes('ACTIONS_RUNTIME_TOKEN'), false);
});

test('hosted runtime paths keep candidate, workspace, and upload staging physically disjoint', () => {
  assert.deepEqual(HOSTED_RUNTIME_PATHS, Object.freeze({
    artifactOutputRoot: '/work/artifacts',
    candidateWorkspaceRoot: '/github/workspace',
    childTemp: '/work/launcher/child',
    configHome: '/work/launcher/child/config-home',
    controllerTempRoot: '/work/controller-upload',
    exportRoot: '/work/launcher/source',
    gitExecutable: '/usr/bin/git',
    launcherTempRoot: '/work/launcher',
    nodeExecutable: '/usr/local/bin/node',
    npmCache: '/work/launcher/child/npm-cache',
    npmExecutable: '/usr/local/bin/npm',
    siteOutput: '/work/launcher/site',
  }));
  assert.equal(HOSTED_RUNTIME_PATHS.controllerTempRoot.startsWith(`${HOSTED_RUNTIME_PATHS.candidateWorkspaceRoot}/`), false);
  assert.equal(HOSTED_RUNTIME_PATHS.artifactOutputRoot.startsWith(`${HOSTED_RUNTIME_PATHS.candidateWorkspaceRoot}/`), false);
});

test('hosted runtime returns a closed blocker before composition when artifact runtime is absent', async () => {
  const result = await runHostedRuntime({
    environment: { GITHUB_ACTIONS: 'false' },
    requestText: canonical(request()),
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'ARTIFACT_UPLOAD_RUNTIME_UNAVAILABLE');
  assert.equal(result.value, null);
});
