import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  collectAppwriteTestReadback,
  githubSourceRequest,
  runCollectAppwriteTestReadbackCli,
} from './collect-appwrite-test-readback.mjs';

const SHA_A = '1'.repeat(40);
const SHA_B = '2'.repeat(40);
const SHA_C = '3'.repeat(40);
const DIGEST = `sha256:${'a'.repeat(64)}`;
const BINDING_NAMES = [
  'TEST_CLOUD_SETUP_READBACK_JSON',
  'TEST_CLOUD_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
];

function sha256(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function input() {
  return {
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
    runnerRevision: SHA_C,
    sourceRunId: '123456789',
    sourceRunAttempt: 1,
    initialSeed: true,
    controllerArtifact: null,
    sourceReader: {
      appId: '4632510',
      installationId: '154580138',
      sourceRepositoryId: 1119118902,
      sourceWorkflowId: 334307313,
    },
  };
}

function environment() {
  return {
    SOURCE_ARTIFACT_READER_PRIVATE_KEY: 'source-reader-private-key',
    APPWRITE_TEST_OPERATOR_API_KEY: 'operator-secret',
    APPWRITE_TEST_FIXTURE_API_KEY: 'fixture-secret',
    E2E_EDITOR_EMAIL: 'editor@appwrite-test.invalid',
    E2E_OWNER_EMAIL: 'owner@appwrite-test.invalid',
    E2E_VIEWER_EMAIL: 'viewer@appwrite-test.invalid',
  };
}

function dependencies(calls = []) {
  const bindings = Object.fromEntries(BINDING_NAMES.map((name) => [
    name,
    name.endsWith('_DIGEST') ? DIGEST : canonicalJson({ name }),
  ]));
  return {
    async readSourceArtifactImpl(args) {
      calls.push(['source', args]);
      return {
        releaseEligibleArtifacts: [{
          kind: 'site',
          logicalTarget: 'web',
          relativePath: 'site/site.tar.gz',
          canonicalContentDigest: DIGEST,
          transportDigest: DIGEST,
          sizeBytes: 3,
        }],
        files: new Map([['site/site.tar.gz', Uint8Array.from([1, 2, 3])]]),
      };
    },
    async projectRowsImpl(args) {
      calls.push(['rows', args]);
      return {
        status: 'PASS', diagnostics: [], value: {
          browserArtifactSetDigest: DIGEST,
          originFreeArtifactPolicyDigest: DIGEST,
          originFreeArtifactPolicyRows: [],
        },
      };
    },
    async readLiveImpl(args) {
      calls.push(['live', args]);
      return { status: 'PASS', diagnostics: [], value: { sanitized: true } };
    },
    createPolicyImpl(args) {
      calls.push(['policy', args]);
      return {
        status: 'PASS', diagnostics: [], value: {
          browserRequestPolicy: { schemaVersion: 'test-cloud.browser-request-policy.v1' },
        },
      };
    },
    createBindingsImpl(args) {
      calls.push(['bindings', args]);
      return {
        status: 'PASS', diagnostics: [], value: {
          bindings,
          evidence: { schemaVersion: 'appwrite-test-setup-binding-evidence.v1' },
        },
      };
    },
    githubRequestImpl: async () => { throw new Error('unused fake'); },
    extractSourceArtifactZipImpl: () => { throw new Error('unused fake'); },
  };
}

test('composes the exact source, live, policy, and binding stages', async () => {
  const calls = [];
  const result = await collectAppwriteTestReadback({
    input: input(),
    environment: environment(),
    dependencies: dependencies(calls),
  });
  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
  assert.deepEqual(calls.map(([name]) => name), ['source', 'rows', 'live', 'policy', 'bindings']);
  assert.deepEqual(Object.keys(result.value.bindings), BINDING_NAMES);
  const serialized = JSON.stringify(result);
  for (const secret of Object.values(environment())) assert.equal(serialized.includes(secret), false);
  assert.equal(calls[0][1].revision, SHA_B);
  assert.equal(calls[4][1].browserRequestPolicy.schemaVersion,
    'test-cloud.browser-request-policy.v1');
});

test('preserves an allowlisted source-reader failure code without serializing secrets', async () => {
  const safeCode = 'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH';
  const sourceError = new Error('provider response contained a secret-value-sentinel');
  sourceError.code = safeCode;
  const fakes = dependencies();
  fakes.readSourceArtifactImpl = async () => { throw sourceError; };

  const result = await collectAppwriteTestReadback({
    input: input(),
    environment: environment(),
    dependencies: fakes,
  });

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, safeCode);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('secret-value-sentinel'), false);
  for (const secret of Object.values(environment())) assert.equal(serialized.includes(secret), false);
});

test('collapses an unknown source-reader failure code to the generic collector code', async () => {
  const sourceError = new Error('provider response contained a secret-value-sentinel');
  sourceError.code = 'MALICIOUS_SECRET_VALUE_SENTINEL';
  const fakes = dependencies();
  fakes.readSourceArtifactImpl = async () => { throw sourceError; };

  const result = await collectAppwriteTestReadback({
    input: input(),
    environment: environment(),
    dependencies: fakes,
  });

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_COLLECT_INVALID');
  assert.equal(JSON.stringify(result).includes('secret-value-sentinel'), false);
});

test('preserves an allowlisted live-readback failure code without serializing secrets', async () => {
  const fakes = dependencies();
  fakes.readLiveImpl = async () => ({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code: 'APPWRITE_TEST_RUNNER_CONFIGURATION_INVALID',
      safeMessage: 'safe stage message',
      secretValue: 'secret-value-sentinel',
    }],
  });

  const result = await collectAppwriteTestReadback({
    input: input(),
    environment: environment(),
    dependencies: fakes,
  });

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_RUNNER_CONFIGURATION_INVALID');
  assert.equal(JSON.stringify(result).includes('secret-value-sentinel'), false);
});

test('collapses an unknown live-readback failure code to the stage code', async () => {
  const fakes = dependencies();
  fakes.readLiveImpl = async () => ({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{ code: 'MALICIOUS_SECRET_VALUE_SENTINEL' }],
  });

  const result = await collectAppwriteTestReadback({
    input: input(),
    environment: environment(),
    dependencies: fakes,
  });

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_LIVE_PROJECTION_INVALID');
});

test('downloads a bounded source artifact through one trusted Azure redirect', async () => {
  const archive = Uint8Array.from({ length: 24 }, (_, index) => index);
  const redirectUrl =
    'https://productionresultssa2.blob.core.windows.net/actions-results/run/artifact.zip?sig=test';
  const calls = [];
  const result = await githubSourceRequest(async (url, options) => {
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
    headers: { Authorization: 'Bearer test-source-token' },
    redirect: 'error',
    expectedBytes: archive.byteLength,
  });

  assert.equal(result.status, 200);
  assert.deepEqual(result.bytes, archive);
  assert.equal(calls[0][1].redirect, 'manual');
  assert.equal(calls[0][1].headers.Authorization, 'Bearer test-source-token');
  assert.equal(calls[1][0], redirectUrl);
  assert.equal(calls[1][1].redirect, 'error');
  assert.equal(Object.hasOwn(calls[1][1].headers, 'Authorization'), false);
});

test('rejects an artifact redirect outside the exact trusted storage host class', async () => {
  await assert.rejects(
    githubSourceRequest(async () => new Response(null, {
      status: 302,
      headers: { location: 'https://example.invalid/artifact.zip?sig=test' },
    }), '/repos/Krowaccie/AppWriteWork/actions/artifacts/9420071362/zip', {
      method: 'GET',
      headers: { Authorization: 'Bearer test-source-token' },
      redirect: 'error',
      expectedBytes: 24,
    }),
    (error) => error?.code === 'SOURCE_ARTIFACT_DOWNLOAD_FAILED',
  );
});

test('CLI writes exactly eight bindings plus canonical evidence and manifest files', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'appwrite-test-readback-'));
  const inputPath = path.join(root, 'input.json');
  const outputPath = path.join(root, 'output');
  try {
    await writeFile(inputPath, `${canonicalJson(input())}\n`, 'utf8');
    const result = await runCollectAppwriteTestReadbackCli(
      ['--input', inputPath, '--output', outputPath],
      environment(),
      dependencies(),
    );
    assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
    const files = (await readdir(outputPath)).sort();
    assert.deepEqual(files, [
      ...BINDING_NAMES.map((name) => `${name}.txt`),
      'binding-manifest.json',
      'evidence.json',
    ].sort());
    const evidence = await readFile(path.join(outputPath, 'evidence.json'), 'utf8');
    assert.equal(evidence, `${canonicalJson({
      schemaVersion: 'appwrite-test-setup-binding-evidence.v1',
    })}\n`);
    for (const name of BINDING_NAMES) {
      const value = await readFile(path.join(outputPath, `${name}.txt`), 'utf8');
      assert.equal(value.length > 0, true);
    }
    const manifestText = await readFile(path.join(outputPath, 'binding-manifest.json'), 'utf8');
    const manifest = JSON.parse(manifestText);
    assert.equal(manifestText, `${canonicalJson(manifest)}\n`);
    assert.deepEqual({
      schemaVersion: manifest.schemaVersion,
      controllerRevision: manifest.controllerRevision,
      sourceRepositoryRevision: manifest.sourceRepositoryRevision,
      runnerRevision: manifest.runnerRevision,
      initialSeed: manifest.initialSeed,
      controllerArtifact: manifest.controllerArtifact,
    }, {
      schemaVersion: 'appwrite-test-binding-artifact-manifest.v1',
      controllerRevision: SHA_A,
      sourceRepositoryRevision: SHA_B,
      runnerRevision: SHA_C,
      initialSeed: true,
      controllerArtifact: null,
    });
    assert.deepEqual(manifest.files.map(({ path: filePath }) => filePath), [
      ...BINDING_NAMES.map((name) => `${name}.txt`),
      'evidence.json',
    ].sort());
    for (const record of manifest.files) {
      const value = await readFile(path.join(outputPath, record.path), 'utf8');
      assert.equal(record.byteLength, Buffer.byteLength(value, 'utf8'));
      assert.equal(record.sha256, sha256(value));
    }

    const repeated = await runCollectAppwriteTestReadbackCli(
      ['--input', inputPath, '--output', outputPath],
      environment(),
      dependencies(),
    );
    assert.equal(repeated.status, 'BLOCKED');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rejects malformed arguments without reading any secret', async () => {
  let secretRead = false;
  const env = new Proxy({}, {
    get() {
      secretRead = true;
      throw new Error('secret read');
    },
  });
  const result = await runCollectAppwriteTestReadbackCli(['--wrong'], env, dependencies());
  assert.equal(result.status, 'BLOCKED');
  assert.equal(secretRead, false);
});
