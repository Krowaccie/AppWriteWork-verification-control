import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';

import * as hostedArtifactHandoff from '../../../scripts/verification/hosted-artifact-handoff.mjs';
import * as sourceArtifactReader from './source-artifact-reader.mjs';

const { createGithubAppJwt, readSourceArtifact } = sourceArtifactReader;

const SHA = 'a'.repeat(40);
const zipBytes = new Uint8Array(22).fill(1);
const zipDigest = `sha256:${createHash('sha256').update(zipBytes).digest('hex')}`;
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

function validRun(overrides = {}) {
  return {
    id: 33,
    workflow_id: 22,
    run_attempt: 1,
    status: 'completed',
    conclusion: 'success',
    event: 'push',
    head_branch: 'main',
    head_sha: SHA,
    head_repository: { full_name: 'Krowaccie/AppWriteWork' },
    ...overrides,
  };
}

function validArtifact(overrides = {}) {
  return {
    id: 44,
    name: `verification-artifacts-${SHA}`,
    expired: false,
    digest: zipDigest,
    size_in_bytes: zipBytes.byteLength,
    ...overrides,
  };
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function digestBytes(bytes) {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex');
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function storedZip(entries) {
  const locals = [];
  const centrals = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.path, 'utf8');
    const bytes = Buffer.from(entry.bytes);
    const checksum = crc32(bytes);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(bytes.length, 18);
    local.writeUInt32LE(bytes.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, bytes);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(bytes.length, 20);
    central.writeUInt32LE(bytes.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE((((entry.mode ?? 0o100644) << 16) >>> 0), 38);
    central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset += local.length + name.length + bytes.length;
  }
  const localBytes = Buffer.concat(locals);
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  return Buffer.concat([localBytes, centralBytes, end]);
}

function streamedResponse(chunks, declaredLength = chunks.reduce(
  (total, chunk) => total + chunk.byteLength,
  0,
)) {
  const state = { arrayBufferCalls: 0, cancelled: false, reads: 0 };
  let cursor = 0;
  return {
    state,
    response: {
      headers: new Headers({ 'content-length': String(declaredLength) }),
      body: {
        getReader() {
          return {
            async read() {
              state.reads += 1;
              if (cursor === chunks.length) return { done: true, value: undefined };
              const value = chunks[cursor];
              cursor += 1;
              return { done: false, value };
            },
            async cancel() { state.cancelled = true; },
            releaseLock() {},
          };
        },
      },
      async arrayBuffer() {
        state.arrayBufferCalls += 1;
        throw new Error('arrayBuffer fallback forbidden for streamed source archive');
      },
    },
  };
}

function validBundleEntries({ extra = false } = {}) {
  const artifacts = [
    { kind: 'site', logicalTarget: 'production-site', sourcePath: 'src/web', relativePath: 'site/site.zip' },
    ...Array.from({ length: 35 }, (_, index) => {
      const logicalTarget = 'function-' + String(index + 1).padStart(2, '0');
      return { kind: 'function', logicalTarget, sourcePath: 'src/functions/' + logicalTarget, relativePath: 'functions/' + logicalTarget + '.tar.gz' };
    }),
    { kind: 'function', logicalTarget: 'verification-runner-py', sourcePath: 'src/functions/verification-runner-py', relativePath: 'functions/verification-runner-py.tar.gz' },
  ].map((record, index) => {
    const bytes = new Uint8Array([index + 1]);
    return { ...record, bytes, canonicalContentDigest: digestBytes(bytes), transportDigest: digestBytes(bytes), sizeBytes: bytes.byteLength };
  });
  const core = { schemaVersion: 1, sourceRevision: SHA, sourceTreeDigest: 'sha256:' + 'b'.repeat(64), verifierManifestDigest: 'sha256:' + 'c'.repeat(64), artifacts: artifacts.map(({ bytes, ...record }) => record) };
  const manifest = { ...core, artifactManifestDigest: digestBytes(Buffer.from(canonical(core), 'utf8')) };
  const handoff = { schemaVersion: 'artifact-handoff.v1', sourceRepository: 'Krowaccie/AppWriteWork', sourceWorkflow: 'Verify Main', sourceWorkflowRunId: '33', sourceWorkflowRunAttempt: 1, sourceRef: 'refs/heads/main', sourceRevision: SHA, artifactName: 'verification-artifacts-' + SHA, artifactManifestDigest: manifest.artifactManifestDigest, verifierManifestDigest: manifest.verifierManifestDigest };
  const entries = [
    { path: 'artifact-manifest.v1.json', bytes: Buffer.from(JSON.stringify(manifest)), mode: 0o644, type: 'file' },
    { path: 'artifact-handoff.v1.json', bytes: Buffer.from(JSON.stringify(handoff)), mode: 0o644, type: 'file' },
    ...artifacts.map(({ bytes, relativePath }) => ({ path: relativePath, bytes, mode: 0o644, type: 'file' })),
  ];
  if (extra) entries.push({ path: 'undeclared.bin', bytes: new Uint8Array([1]), mode: 0o644, type: 'file' });
  return entries;
}

function readerTrustedSource() {
  return {
    repository: 'Krowaccie/AppWriteWork',
    workflow: 'Verify Main',
    workflowRunId: '33',
    workflowRunAttempt: 1,
    sourceRef: 'refs/heads/main',
    sourceRevision: SHA,
  };
}

function hostedCorpusFromBundle(entries) {
  const manifestEntry = entries.find(({ path }) => path === 'artifact-manifest.v1.json');
  const handoffEntry = entries.find(({ path }) => path === 'artifact-handoff.v1.json');
  return {
    handoff: JSON.parse(Buffer.from(handoffEntry.bytes).toString('utf8')),
    manifest: JSON.parse(Buffer.from(manifestEntry.bytes).toString('utf8')),
    trustedSource: readerTrustedSource(),
  };
}

function bundleWithRewrittenHandoff(transform) {
  return validBundleEntries().map((entry) => {
    if (entry.path !== 'artifact-handoff.v1.json') return entry;
    const handoff = JSON.parse(Buffer.from(entry.bytes).toString('utf8'));
    return {
      ...entry,
      bytes: Buffer.from(JSON.stringify(transform(handoff)), 'utf8'),
    };
  });
}

async function readBundleEntries(entries) {
  const request = async (requestPath) => {
    if (requestPath.includes('/access_tokens')) return {
      status: 201,
      body: {
        token: 'x',
        permissions: { actions: 'read' },
        repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }],
      },
    };
    if (requestPath === '/repos/Krowaccie/AppWriteWork') return {
      status: 200,
      body: { id: 11, full_name: 'Krowaccie/AppWriteWork' },
    };
    if (requestPath.includes('/actions/workflows/')) return {
      status: 200,
      body: { id: 22, name: 'Verify Main', path: '.github/workflows/verify-main.yml' },
    };
    if (requestPath.endsWith('/actions/runs/33')) return { status: 200, body: validRun() };
    if (requestPath.endsWith('/artifacts')) return {
      status: 200,
      body: { artifacts: [validArtifact()] },
    };
    if (requestPath.endsWith('/zip')) return { status: 200, bytes: zipBytes };
    if (requestPath === '/installation/token') return { status: 204 };
    throw new Error('unexpected request');
  };
  return readSourceArtifact({
    config: {
      appId: '123',
      installationId: '9',
      sourceRepositoryId: 11,
      sourceWorkflowId: 22,
    },
    revision: SHA,
    qualifyingRunId: '33',
    runAttempt: 1,
    privateKey: privateKeyPem,
    request,
    readZip: async () => entries,
    nowSeconds: 1_000,
  });
}

test('GitHub App JWT is RS256 and expires exactly nine minutes after issuance', () => {
  const token = createGithubAppJwt({ appId: '123', privateKey: privateKeyPem, nowSeconds: 1_000 });
  const [header, payload] = token.split('.').slice(0, 2).map((part) => (
    JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
  ));
  assert.deepEqual(header, { alg: 'RS256', typ: 'JWT' });
  assert.equal(payload.iss, '123');
  assert.equal(payload.exp - payload.iat, 540);
});

test('source reader uses exact allowlisted GitHub operations and always revokes installation token', async () => {
  const calls = [];
  const request = async (path, init) => {
    calls.push([path, init.method]);
    if (path.includes('/access_tokens')) return {
      status: 201,
      body: {
        token: 'installation-secret',
        permissions: { actions: 'read' },
        repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }],
      },
    };
    if (path === '/repos/Krowaccie/AppWriteWork') return { status: 200, body: { id: 11, full_name: 'Krowaccie/AppWriteWork' } };
    if (path.endsWith('/actions/workflows/verify-main.yml')) return { status: 200, body: { id: 22, name: 'Verify Main', path: '.github/workflows/verify-main.yml' } };
    if (path.endsWith('/actions/runs/33')) return { status: 200, body: validRun() };
    if (path.endsWith('/actions/runs/33/artifacts')) return { status: 200, body: { artifacts: [validArtifact()] } };
    if (path.endsWith('/actions/artifacts/44/zip')) return { status: 200, bytes: zipBytes };
    if (path === '/installation/token') return { status: 204 };
    throw new Error('unexpected path');
  };
  const result = await readSourceArtifact({
    config: {
      appId: '123',
      installationId: '9',
      sourceRepositoryId: 11,
      sourceWorkflowId: 22,
    },
    revision: SHA,
    qualifyingRunId: '33',
    runAttempt: 1,
    privateKey: privateKeyPem,
    request,
    readZip: async () => validBundleEntries(),
    nowSeconds: 1_000,
  });
  assert.equal(result.sourceArtifactId, 44);
  assert.deepEqual(calls.map(([path, method]) => [method, path]), [
    ['POST', '/app/installations/9/access_tokens'],
    ['GET', '/repos/Krowaccie/AppWriteWork'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/workflows/verify-main.yml'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/runs/33'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/runs/33/artifacts'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/artifacts/44/zip'],
    ['DELETE', '/installation/token'],
  ]);
});

test('source reader revokes token after a malicious ZIP rejection', async () => {
  let revoked = false;
  const request = async (path) => {
    if (path.includes('/access_tokens')) return { status: 201, body: { token: 'x', permissions: { actions: 'read' }, repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }] } };
    if (path === '/repos/Krowaccie/AppWriteWork') return { status: 200, body: { id: 11, full_name: 'Krowaccie/AppWriteWork' } };
    if (path.includes('/actions/workflows/')) return { status: 200, body: { id: 22, name: 'Verify Main', path: '.github/workflows/verify-main.yml' } };
    if (path.endsWith('/actions/runs/33')) return { status: 200, body: validRun() };
    if (path.endsWith('/artifacts')) return { status: 200, body: { artifacts: [validArtifact()] } };
    if (path.endsWith('/zip')) return { status: 200, bytes: zipBytes };
    if (path === '/installation/token') { revoked = true; return { status: 204 }; }
  };
  await assert.rejects(() => readSourceArtifact({
    config: { appId: '123', installationId: '9', sourceRepositoryId: 11, sourceWorkflowId: 22 },
    revision: SHA,
    qualifyingRunId: '33',
    runAttempt: 1,
    privateKey: privateKeyPem,
    request,
    readZip: async () => [{ path: '../escape', bytes: new Uint8Array([1]), mode: 0o644, type: 'file' }],
    nowSeconds: 1_000,
  }), /SOURCE_ARTIFACT_ZIP_UNSAFE/);
  assert.equal(revoked, true);
});

test('invalid minted installation token is still revoked and revocation failure wins closed', async () => {
  let deletes = 0;
  const request = async (path) => {
    if (path.includes('/access_tokens')) return { status: 201, body: { token: 'minted-secret', permissions: { actions: 'write' }, repositories: [] } };
    if (path === '/installation/token') { deletes += 1; return { status: 500 }; }
    throw new Error('unexpected request');
  };
  await assert.rejects(() => readSourceArtifact({ config: { appId: '123', installationId: '9', sourceRepositoryId: 11, sourceWorkflowId: 22 }, revision: SHA, qualifyingRunId: '33', runAttempt: 1, privateKey: privateKeyPem, request, readZip: async () => [], nowSeconds: 1_000 }), /SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED/);
  assert.equal(deletes, 1);
});


test('source reader binds workflow ID and rejects extra API or ZIP artifacts', async () => {
  const invoke = async ({ workflowId = 22, apiExtra = false, zipExtra = false }) => {
    const request = async (path) => {
      if (path.includes('/access_tokens')) return { status: 201, body: { token: 'x', permissions: { actions: 'read' }, repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }] } };
      if (path === '/repos/Krowaccie/AppWriteWork') return { status: 200, body: { id: 11, full_name: 'Krowaccie/AppWriteWork' } };
      if (path.includes('/actions/workflows/')) return { status: 200, body: { id: 22, name: 'Verify Main', path: '.github/workflows/verify-main.yml' } };
      if (path.endsWith('/actions/runs/33')) return { status: 200, body: validRun({ workflow_id: workflowId }) };
      if (path.endsWith('/artifacts')) {
        const artifacts = [validArtifact()];
        if (apiExtra) artifacts.push(validArtifact({ id: 45, name: 'unexpected' }));
        return { status: 200, body: { artifacts } };
      }
      if (path.endsWith('/zip')) return { status: 200, bytes: zipBytes };
      if (path === '/installation/token') return { status: 204 };
      throw new Error('unexpected request');
    };
    return readSourceArtifact({
      config: { appId: '123', installationId: '9', sourceRepositoryId: 11, sourceWorkflowId: 22 },
      revision: SHA,
      qualifyingRunId: '33',
      runAttempt: 1,
      privateKey: privateKeyPem,
      request,
      readZip: async () => validBundleEntries({ extra: zipExtra }),
      nowSeconds: 1_000,
    });
  };
  await assert.rejects(() => invoke({ workflowId: 99 }), /SOURCE_RUN_IDENTITY_MISMATCH/);
  await assert.rejects(() => invoke({ apiExtra: true }), /SOURCE_ARTIFACT_IDENTITY_MISMATCH/);
  await assert.rejects(() => invoke({ zipExtra: true }), /PRODUCTION_HANDOFF_EXTRA_ARTIFACT/);
});



test('source reader accepts only a push event from the canonical source repository', async () => {
  const invoke = async (runOverrides) => {
    const request = async (path) => {
      if (path.includes('/access_tokens')) return { status: 201, body: { token: 'x', permissions: { actions: 'read' }, repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }] } };
      if (path === '/repos/Krowaccie/AppWriteWork') return { status: 200, body: { id: 11, full_name: 'Krowaccie/AppWriteWork' } };
      if (path.includes('/actions/workflows/')) return { status: 200, body: { id: 22, name: 'Verify Main', path: '.github/workflows/verify-main.yml' } };
      if (path.endsWith('/actions/runs/33')) return { status: 200, body: validRun(runOverrides) };
      if (path.endsWith('/artifacts')) return { status: 200, body: { artifacts: [validArtifact()] } };
      if (path.endsWith('/zip')) return { status: 200, bytes: zipBytes };
      if (path === '/installation/token') return { status: 204 };
      throw new Error('unexpected request');
    };
    return readSourceArtifact({
      config: { appId: '123', installationId: '9', sourceRepositoryId: 11, sourceWorkflowId: 22 },
      revision: SHA,
      qualifyingRunId: '33',
      runAttempt: 1,
      privateKey: privateKeyPem,
      request,
      readZip: async () => validBundleEntries(),
      nowSeconds: 1_000,
    });
  };

  await assert.rejects(() => invoke({ event: 'pull_request' }), /SOURCE_RUN_IDENTITY_MISMATCH/);
  await assert.rejects(() => invoke({
    head_repository: { full_name: 'attacker/AppWriteWork' },
  }), /SOURCE_RUN_IDENTITY_MISMATCH/);
});


test('source reader rejects absent, oversized, and mismatched provider archive sizes', async () => {
  const invoke = async (artifactOverrides) => {
    const request = async (path) => {
      if (path.includes('/access_tokens')) return { status: 201, body: { token: 'x', permissions: { actions: 'read' }, repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }] } };
      if (path === '/repos/Krowaccie/AppWriteWork') return { status: 200, body: { id: 11, full_name: 'Krowaccie/AppWriteWork' } };
      if (path.includes('/actions/workflows/')) return { status: 200, body: { id: 22, name: 'Verify Main', path: '.github/workflows/verify-main.yml' } };
      if (path.endsWith('/actions/runs/33')) return { status: 200, body: validRun() };
      if (path.endsWith('/artifacts')) return { status: 200, body: { artifacts: [validArtifact(artifactOverrides)] } };
      if (path.endsWith('/zip')) return { status: 200, bytes: zipBytes };
      if (path === '/installation/token') return { status: 204 };
      throw new Error('unexpected request');
    };
    return readSourceArtifact({
      config: { appId: '123', installationId: '9', sourceRepositoryId: 11, sourceWorkflowId: 22 },
      revision: SHA,
      qualifyingRunId: '33',
      runAttempt: 1,
      privateKey: privateKeyPem,
      request,
      readZip: async () => validBundleEntries(),
      nowSeconds: 1_000,
    });
  };

  await assert.rejects(
    () => invoke({ size_in_bytes: undefined }),
    /SOURCE_ARTIFACT_IDENTITY_MISMATCH/,
  );
  await assert.rejects(
    () => invoke({ size_in_bytes: 64 * 1024 * 1024 + 1 }),
    /SOURCE_ARTIFACT_IDENTITY_MISMATCH/,
  );
  await assert.rejects(
    () => invoke({ size_in_bytes: zipBytes.byteLength + 1 }),
    /SOURCE_ARTIFACT_DOWNLOAD_FAILED/,
  );
});


test('source archive transport streams exact provider-sized bytes without arrayBuffer', async () => {
  assert.equal(typeof sourceArtifactReader.readBoundedSourceArtifactArchive, 'function');
  const streamed = streamedResponse([
    zipBytes.subarray(0, 7),
    zipBytes.subarray(7, 16),
    zipBytes.subarray(16),
  ]);
  const actual = await sourceArtifactReader.readBoundedSourceArtifactArchive(
    streamed.response,
    zipBytes.byteLength,
  );
  assert.deepEqual(actual, zipBytes);
  assert.equal(streamed.state.arrayBufferCalls, 0);
  assert.equal(streamed.state.cancelled, false);

  const mismatched = streamedResponse([zipBytes]);
  await assert.rejects(
    () => sourceArtifactReader.readBoundedSourceArtifactArchive(
      mismatched.response,
      zipBytes.byteLength + 1,
    ),
    /SOURCE_ARTIFACT_DOWNLOAD_FAILED/,
  );
});

test('source ZIP wrapper returns closed file entries and translates unsafe archives', () => {
  assert.equal(typeof sourceArtifactReader.extractSourceArtifactZip, 'function');
  const archive = storedZip([
    { path: 'artifact-manifest.v1.json', bytes: Buffer.from('{}') },
    { path: 'artifact-handoff.v1.json', bytes: Buffer.from('{"ok":true}') },
  ]);
  const entries = sourceArtifactReader.extractSourceArtifactZip(archive);
  assert.deepEqual(entries.map(({ path, type, mode }) => ({ path, type, mode })), [
    { path: 'artifact-manifest.v1.json', type: 'file', mode: 0o644 },
    { path: 'artifact-handoff.v1.json', type: 'file', mode: 0o644 },
  ]);
  assert.deepEqual(Buffer.from(entries[0].bytes), Buffer.from('{}'));

  assert.throws(
    () => sourceArtifactReader.extractSourceArtifactZip(storedZip([
      { path: '../escape', bytes: Buffer.from('x') },
      { path: 'safe.txt', bytes: Buffer.from('y') },
    ])),
    /SOURCE_ARTIFACT_ZIP_UNSAFE/,
  );
  assert.throws(
    () => sourceArtifactReader.extractSourceArtifactZip(archive.subarray(0, archive.length - 1)),
    /SOURCE_ARTIFACT_ZIP_UNSAFE/,
  );
});

test('5B source reader shares the handoff golden and common-negative contract only', async (t) => {
  const validateHostedArtifactHandoff = hostedArtifactHandoff.validateHostedArtifactHandoff;
  assert.equal(typeof validateHostedArtifactHandoff, 'function');
  const goldenEntries = validBundleEntries();
  const direct = validateHostedArtifactHandoff(hostedCorpusFromBundle(goldenEntries));
  const readback = await readBundleEntries(goldenEntries);
  assert.equal(direct.status, 'PASS');
  assert.equal(readback.artifactManifestDigest, direct.value.artifactManifestDigest);
  assert.equal(readback.verifierManifestDigest, direct.value.verifierManifestDigest);
  assert.equal(readback.releaseEligibleArtifacts.length, 36);
  assert.equal(readback.testOnlyArtifacts.length, 1);
  assert.equal(readback.testOnlyArtifacts[0].logicalTarget, 'verification-runner-py');

  const cases = [
    ['wrong-run', (handoff) => ({ ...handoff, sourceWorkflowRunId: '34' })],
    ['wrong-attempt', (handoff) => ({ ...handoff, sourceWorkflowRunAttempt: 2 })],
    ['wrong-ref', (handoff) => ({ ...handoff, sourceRef: 'refs/heads/release' })],
    ['wrong-revision', (handoff) => ({ ...handoff, sourceRevision: 'd'.repeat(40) })],
    ['artifact-digest-mismatch', (handoff) => ({
      ...handoff,
      artifactManifestDigest: `sha256:${'d'.repeat(64)}`,
    })],
    ['verifier-digest-mismatch', (handoff) => ({
      ...handoff,
      verifierManifestDigest: `sha256:${'e'.repeat(64)}`,
    })],
    ['extra-field', (handoff) => ({ ...handoff, artifactId: 44 })],
  ];
  for (const [name, transform] of cases) {
    await t.test(name, async () => {
      const entries = bundleWithRewrittenHandoff(transform);
      const helperResult = validateHostedArtifactHandoff(hostedCorpusFromBundle(entries));
      assert.equal(helperResult.status, 'BLOCKED');
      assert.equal(helperResult.diagnostics[0].code, 'ARTIFACT_HANDOFF_INVALID');
      await assert.rejects(() => readBundleEntries(entries), /SOURCE_ARTIFACT_MANIFEST_INVALID/);
    });
  }
});
