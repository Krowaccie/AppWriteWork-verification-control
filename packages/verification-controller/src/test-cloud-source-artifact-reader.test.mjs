import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import * as sharedReader from './source-artifact-reader.mjs';
import * as testReader from './test-cloud-source-artifact-reader.mjs';

const REVISION = 'a'.repeat(40);
const ARCHIVE = new Uint8Array(22).fill(7);
const ARCHIVE_DIGEST = digest(ARCHIVE);
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' });

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonical(value[key])}`
  )).join(',')}}`;
}

function validBundleEntries() {
  const artifacts = [
    {
      kind: 'site',
      logicalTarget: 'production-site',
      sourcePath: 'src/web',
      relativePath: 'site/site.zip',
    },
    ...Array.from({ length: 35 }, (_, index) => {
      const logicalTarget = `function-${String(index + 1).padStart(2, '0')}`;
      return {
        kind: 'function',
        logicalTarget,
        sourcePath: `src/functions/${logicalTarget}`,
        relativePath: `functions/${logicalTarget}.tar.gz`,
      };
    }),
    {
      kind: 'function',
      logicalTarget: 'verification-runner-py',
      sourcePath: 'src/functions/verification-runner-py',
      relativePath: 'functions/verification-runner-py.tar.gz',
    },
  ].map((record, index) => {
    const bytes = new Uint8Array([index + 1]);
    return {
      ...record,
      bytes,
      canonicalContentDigest: digest(bytes),
      transportDigest: digest(bytes),
      sizeBytes: bytes.byteLength,
    };
  });
  const core = {
    schemaVersion: 1,
    sourceRevision: REVISION,
    sourceTreeDigest: `sha256:${'b'.repeat(64)}`,
    verifierManifestDigest: `sha256:${'c'.repeat(64)}`,
    artifacts: artifacts.map(({ bytes, ...record }) => record),
  };
  const manifest = {
    ...core,
    artifactManifestDigest: digest(Buffer.from(canonical(core), 'utf8')),
  };
  const handoff = {
    schemaVersion: 'artifact-handoff.v1',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceWorkflow: 'Verify Main',
    sourceWorkflowRunId: '33',
    sourceWorkflowRunAttempt: 1,
    sourceRef: 'refs/heads/main',
    sourceRevision: REVISION,
    artifactName: `verification-artifacts-${REVISION}`,
    artifactManifestDigest: manifest.artifactManifestDigest,
    verifierManifestDigest: manifest.verifierManifestDigest,
  };
  return [
    {
      path: 'artifact-manifest.v1.json',
      bytes: Buffer.from(JSON.stringify(manifest), 'utf8'),
      mode: 0o644,
      type: 'file',
    },
    {
      path: 'artifact-handoff.v1.json',
      bytes: Buffer.from(JSON.stringify(handoff), 'utf8'),
      mode: 0o644,
      type: 'file',
    },
    ...artifacts.map(({ bytes, relativePath }) => ({
      path: relativePath,
      bytes,
      mode: 0o644,
      type: 'file',
    })),
  ];
}

function passthroughResponse(value) {
  return new Proxy(value, {
    ownKeys() {
      throw new Error('non-token responses must not be cloned');
    },
  });
}

function readerArgs({
  permissions = { actions: 'read', metadata: 'read' },
  revokeStatus = 204,
  mutateAfterMint = false,
  mutateRequestOptionsAfterMint = false,
} = {}) {
  const calls = [];
  const mintedBody = Object.freeze({
    token: 'minted-test-token',
    permissions: Object.freeze(permissions),
    repositories: Object.freeze([
      Object.freeze({ id: 11, full_name: 'Krowaccie/AppWriteWork' }),
    ]),
    expires_at: '2026-08-22T12:00:00Z',
  });
  const mintedResponse = Object.freeze({
    status: 201,
    body: mintedBody,
    requestId: 'provider-request-1',
  });
  const args = {
    config: {
      appId: '123',
      installationId: '9',
      sourceRepositoryId: 11,
      sourceWorkflowId: 22,
    },
    revision: REVISION,
    qualifyingRunId: '33',
    runAttempt: 1,
    privateKey: PRIVATE_KEY,
    nowSeconds: 1_000,
    readZip: async () => validBundleEntries(),
    request: null,
  };
  const request = async (requestPath, options) => {
    calls.push({ requestPath, options });
    if (requestPath === '/app/installations/9/access_tokens') {
      if (mutateRequestOptionsAfterMint) options.method = 'GET';
      if (mutateAfterMint) {
        args.config.appId = 'invalid';
        args.config.installationId = 'mutated';
        args.config.sourceRepositoryId = 999;
        args.config.sourceWorkflowId = 999;
        args.revision = 'f'.repeat(40);
        args.qualifyingRunId = '999';
        args.runAttempt = 9;
        args.privateKey = 'invalid';
        args.nowSeconds = 9_999;
        args.request = async () => { throw new Error('mutated request used'); };
        args.readZip = async () => { throw new Error('mutated readZip used'); };
      }
      return mintedResponse;
    }
    if (requestPath === '/repos/Krowaccie/AppWriteWork') {
      return passthroughResponse({
        status: 200,
        body: { id: 11, full_name: 'Krowaccie/AppWriteWork' },
      });
    }
    if (requestPath.endsWith('/actions/workflows/verify-main.yml')) {
      return passthroughResponse({
        status: 200,
        body: {
          id: 22,
          name: 'Verify Main',
          path: '.github/workflows/verify-main.yml',
        },
      });
    }
    if (requestPath.endsWith('/actions/runs/33')) {
      return passthroughResponse({
        status: 200,
        body: {
          id: 33,
          workflow_id: 22,
          run_attempt: 1,
          status: 'completed',
          conclusion: 'success',
          event: 'push',
          head_repository: { full_name: 'Krowaccie/AppWriteWork' },
          head_branch: 'main',
          head_sha: REVISION,
        },
      });
    }
    if (requestPath.endsWith('/actions/runs/33/artifacts')) {
      return passthroughResponse({
        status: 200,
        body: {
          artifacts: [{
            id: 44,
            name: `verification-artifacts-${REVISION}`,
            expired: false,
            digest: ARCHIVE_DIGEST,
            size_in_bytes: ARCHIVE.byteLength,
          }],
        },
      });
    }
    if (requestPath.endsWith('/actions/artifacts/44/zip')) {
      return passthroughResponse({ status: 200, bytes: ARCHIVE });
    }
    if (requestPath === '/installation/token') {
      return passthroughResponse({ status: revokeStatus });
    }
    throw new Error(`unexpected request: ${requestPath}`);
  };
  args.request = request;
  return { args, calls, mintedResponse, mintedBody };
}

function overrideTokenResponse(fixture, createResponse) {
  const downstream = fixture.args.request;
  fixture.args.request = (requestPath, options) => {
    if (requestPath === '/app/installations/9/access_tokens') {
      fixture.calls.push({ requestPath, options });
      return createResponse();
    }
    return downstream(requestPath, options);
  };
}

function errorCode(code) {
  return (error) => {
    assert.equal(error?.code, code);
    return true;
  };
}

test('Test source reader exposes only the two bounded helpers and Test read operation', () => {
  assert.deepEqual(Object.keys(testReader).sort(), [
    'extractSourceArtifactZip',
    'readBoundedSourceArtifactArchive',
    'readTestCloudSourceArtifact',
  ]);
  assert.equal(testReader.extractSourceArtifactZip, sharedReader.extractSourceArtifactZip);
  assert.equal(
    testReader.readBoundedSourceArtifactArchive,
    sharedReader.readBoundedSourceArtifactArchive,
  );
});

test('Test reader admits exact Actions-plus-Metadata without mutating provider response', async () => {
  const fixture = readerArgs({ mutateAfterMint: true });
  const originalBody = {
    token: fixture.mintedBody.token,
    permissions: { ...fixture.mintedBody.permissions },
    repositories: fixture.mintedBody.repositories.map((record) => ({ ...record })),
    expires_at: fixture.mintedBody.expires_at,
  };

  const result = await testReader.readTestCloudSourceArtifact(fixture.args);

  assert.equal(result.sourceArtifactId, 44);
  assert.deepEqual(fixture.mintedResponse, {
    status: 201,
    body: originalBody,
    requestId: 'provider-request-1',
  });
  assert.deepEqual(fixture.calls.map(({ requestPath, options }) => [
    options.method,
    requestPath,
  ]), [
    ['POST', '/app/installations/9/access_tokens'],
    ['GET', '/repos/Krowaccie/AppWriteWork'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/workflows/verify-main.yml'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/runs/33'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/runs/33/artifacts'],
    ['GET', '/repos/Krowaccie/AppWriteWork/actions/artifacts/44/zip'],
    ['DELETE', '/installation/token'],
  ]);
  const revoke = fixture.calls.at(-1);
  assert.equal(revoke.options.headers.Authorization, 'Bearer minted-test-token');
});

test('Test reader fixes the exact token-route predicate before awaiting caller transport', async () => {
  const fixture = readerArgs({ mutateRequestOptionsAfterMint: true });
  const result = await testReader.readTestCloudSourceArtifact(fixture.args);
  assert.equal(result.sourceArtifactId, 44);
  assert.equal(fixture.calls.at(-1).requestPath, '/installation/token');
});

test('Test reader never invokes throwing or stateful token body accessors', async (t) => {
  const cases = [
    ['throwing', () => { throw new Error('TOKEN_BODY_ACCESSOR_INVOKED'); }],
    ['stateful', (calls) => (calls === 1
      ? {
        token: 'minted-test-token',
        permissions: { actions: 'read', metadata: 'read' },
        repositories: [{ id: 999, full_name: 'Krowaccie/AppWriteWork' }],
      }
      : {
        token: 'minted-test-token',
        permissions: { actions: 'read', metadata: 'read' },
        repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }],
      })],
  ];
  for (const [name, readBody] of cases) {
    await t.test(name, async () => {
      const fixture = readerArgs();
      let getterCalls = 0;
      const response = { status: 201, requestId: `hostile-${name}` };
      Object.defineProperty(response, 'body', {
        enumerable: true,
        get() {
          getterCalls += 1;
          return readBody(getterCalls);
        },
      });
      overrideTokenResponse(fixture, () => response);

      await assert.rejects(
        () => testReader.readTestCloudSourceArtifact(fixture.args),
        errorCode('SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH'),
      );
      assert.equal(getterCalls, 0);
      assert.deepEqual(fixture.calls.map(({ requestPath }) => requestPath), [
        '/app/installations/9/access_tokens',
      ]);
    });
  }
});

test('Test reader rejects unsafe response and body containers without hostile execution', async (t) => {
  await t.test('hostile response prototype with recoverable token', async () => {
    const fixture = readerArgs();
    const response = Object.assign(Object.create(null), {
      status: 201,
      body: fixture.mintedBody,
    });
    overrideTokenResponse(fixture, () => response);

    await assert.rejects(
      () => testReader.readTestCloudSourceArtifact(fixture.args),
      errorCode('SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH'),
    );
    assert.deepEqual(fixture.calls.map(({ requestPath }) => requestPath), [
      '/app/installations/9/access_tokens',
      '/installation/token',
    ]);
  });

  await t.test('proxied body without recoverable token', async () => {
    const fixture = readerArgs();
    let trapCalls = 0;
    const body = new Proxy(fixture.mintedBody, {
      get() {
        trapCalls += 1;
        throw new Error('TOKEN_BODY_PROXY_INVOKED');
      },
      ownKeys() {
        trapCalls += 1;
        throw new Error('TOKEN_BODY_PROXY_INVOKED');
      },
    });
    overrideTokenResponse(fixture, () => ({ status: 201, body }));

    await assert.rejects(
      () => testReader.readTestCloudSourceArtifact(fixture.args),
      errorCode('SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH'),
    );
    assert.equal(trapCalls, 0);
    assert.deepEqual(fixture.calls.map(({ requestPath }) => requestPath), [
      '/app/installations/9/access_tokens',
    ]);
  });
});

test('Test reader retains an own-data minted token when another body field is unsafe', async (t) => {
  for (const [name, revokeStatus, expectedCode] of [
    ['revoked', 204, 'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH'],
    ['revocation-failure', 500, 'SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED'],
  ]) {
    await t.test(name, async () => {
      const fixture = readerArgs({ revokeStatus });
      let accessorCalls = 0;
      const body = {
        token: 'minted-test-token',
        permissions: { actions: 'read', metadata: 'read' },
        repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }],
      };
      Object.defineProperty(body, 'unsafe', {
        enumerable: true,
        get() {
          accessorCalls += 1;
          throw new Error('UNSAFE_TOKEN_BODY_FIELD_INVOKED');
        },
      });
      overrideTokenResponse(fixture, () => ({ status: 201, body }));

      await assert.rejects(
        () => testReader.readTestCloudSourceArtifact(fixture.args),
        errorCode(expectedCode),
      );
      assert.equal(accessorCalls, 0);
      assert.deepEqual(fixture.calls.map(({ requestPath }) => requestPath), [
        '/app/installations/9/access_tokens',
        '/installation/token',
      ]);
      assert.equal(
        fixture.calls.at(-1).options.headers.Authorization,
        'Bearer minted-test-token',
      );
    });
  }
});

test('Test reader sanitizes a hostile fallback status before revoking the minted token', async (t) => {
  const cases = [
    [
      'proxied-status',
      204,
      'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH',
      (calls) => new Proxy({}, {
        isExtensible() {
          calls.count += 1;
          throw new Error('TOKEN_STATUS_PROXY_INVOKED');
        },
      }),
    ],
    [
      'accessor-status-with-revocation-failure',
      500,
      'SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED',
      (calls) => {
        const status = {};
        Object.defineProperty(status, 'unsafe', {
          enumerable: true,
          get() {
            calls.count += 1;
            throw new Error('TOKEN_STATUS_ACCESSOR_INVOKED');
          },
        });
        return status;
      },
    ],
  ];
  for (const [name, revokeStatus, expectedCode, createStatus] of cases) {
    await t.test(name, async () => {
      const fixture = readerArgs({ revokeStatus });
      const hostileCalls = { count: 0 };
      let bodyAccessorCalls = 0;
      const body = {
        token: 'minted-test-token',
        permissions: { actions: 'read', metadata: 'read' },
        repositories: [{ id: 11, full_name: 'Krowaccie/AppWriteWork' }],
      };
      Object.defineProperty(body, 'unsafe', {
        enumerable: true,
        get() {
          bodyAccessorCalls += 1;
          throw new Error('TOKEN_BODY_ACCESSOR_INVOKED');
        },
      });
      overrideTokenResponse(fixture, () => ({
        status: createStatus(hostileCalls),
        body,
      }));

      await assert.rejects(
        () => testReader.readTestCloudSourceArtifact(fixture.args),
        errorCode(expectedCode),
      );
      assert.equal(hostileCalls.count, 0);
      assert.equal(bodyAccessorCalls, 0);
      assert.deepEqual(fixture.calls.map(({ requestPath }) => requestPath), [
        '/app/installations/9/access_tokens',
        '/installation/token',
      ]);
      assert.equal(
        fixture.calls.at(-1).options.headers.Authorization,
        'Bearer minted-test-token',
      );
    });
  }
});

test('Test reader detaches nested repository scope before caller mutation', async () => {
  const fixture = readerArgs();
  const repository = { id: 11, full_name: 'Krowaccie/AppWriteWork' };
  const body = {
    token: 'minted-test-token',
    permissions: { actions: 'read', metadata: 'read' },
    repositories: [repository],
    expires_at: '2026-08-22T12:00:00Z',
  };
  const response = { status: 201, body, requestId: 'mutable-provider-response' };
  overrideTokenResponse(fixture, () => ({
    then(resolve) {
      resolve(response);
      queueMicrotask(() => {
        repository.id = 999;
        repository.full_name = 'Krowaccie/Mutated';
      });
    },
  }));

  const result = await testReader.readTestCloudSourceArtifact(fixture.args);
  assert.equal(result.sourceArtifactId, 44);
  assert.deepEqual(repository, { id: 999, full_name: 'Krowaccie/Mutated' });
  assert.equal(fixture.calls.at(-1).requestPath, '/installation/token');
  assert.equal(
    fixture.calls.at(-1).options.headers.Authorization,
    'Bearer minted-test-token',
  );
});

test('Test reader rejects missing Metadata and extra permissions after revoking minted token', async (t) => {
  let accessorCalls = 0;
  const accessorPermissions = {};
  Object.defineProperties(accessorPermissions, {
    actions: {
      enumerable: true,
      get() {
        accessorCalls += 1;
        return 'read';
      },
    },
    metadata: { enumerable: true, value: 'read' },
  });
  const symbolPermissions = { actions: 'read', metadata: 'read' };
  Object.defineProperty(symbolPermissions, Symbol('hidden'), { value: 'read' });
  const nullPrototypePermissions = Object.assign(Object.create(null), {
    actions: 'read',
    metadata: 'read',
  });
  const proxyPermissions = new Proxy(
    { actions: 'read', metadata: 'read' },
    {},
  );
  const cases = [
    ['missing-metadata', { actions: 'read' }],
    ['extra-permission', { actions: 'read', metadata: 'read', contents: 'read' }],
    ['accessor-permission', accessorPermissions],
    ['symbol-permission', symbolPermissions],
    ['nonordinary-permissions', nullPrototypePermissions],
    ['proxy-permissions', proxyPermissions],
  ];
  for (const [name, permissions] of cases) {
    await t.test(name, async () => {
      const fixture = readerArgs({ permissions });
      await assert.rejects(
        () => testReader.readTestCloudSourceArtifact(fixture.args),
        errorCode('SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH'),
      );
      assert.deepEqual(fixture.calls.map(({ requestPath }) => requestPath), [
        '/app/installations/9/access_tokens',
        '/installation/token',
      ]);
      assert.equal(
        fixture.calls[1].options.headers.Authorization,
        'Bearer minted-test-token',
      );
    });
  }
  assert.equal(accessorCalls, 0);
});

test('Test reader preserves shared revocation-failure precedence on invalid scope', async () => {
  const fixture = readerArgs({ permissions: { actions: 'read' }, revokeStatus: 500 });
  await assert.rejects(
    () => testReader.readTestCloudSourceArtifact(fixture.args),
    errorCode('SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED'),
  );
  assert.equal(fixture.calls.at(-1).requestPath, '/installation/token');
  assert.equal(
    fixture.calls.at(-1).options.headers.Authorization,
    'Bearer minted-test-token',
  );
});

test('adapter predicate is exact token-route equality paired with POST', async () => {
  const source = await readFile(new URL('./test-cloud-source-artifact-reader.mjs', import.meta.url), 'utf8');
  assert.match(source, /requestPath === tokenPath\s*&&\s*options\.method === 'POST'/u);
  assert.doesNotMatch(source, /includes\(|endsWith\(|startsWith\(/u);
});

test('only the collector and hosted Test controller own the Test reader adapter', async () => {
  const collector = await readFile(
    new URL('./collect-appwrite-test-readback.mjs', import.meta.url),
    'utf8',
  );
  const controller = await readFile(
    new URL('./test-cloud-controller.mjs', import.meta.url),
    'utf8',
  );
  const production = await readFile(
    new URL('../workflows/release-production.yml', import.meta.url),
    'utf8',
  );
  assert.match(
    collector,
    /from '\.\/test-cloud-source-artifact-reader\.mjs';/u,
  );
  assert.match(collector, /readSourceArtifactImpl: readTestCloudSourceArtifact/u);
  assert.doesNotMatch(collector, /from '\.\/source-artifact-reader\.mjs';/u);
  assert.match(
    controller,
    /import\('\.\/test-cloud-source-artifact-reader\.mjs'\)/u,
  );
  assert.doesNotMatch(controller, /import\('\.\/source-artifact-reader\.mjs'\)/u);
  assert.match(
    production,
    /from '\.\/packages\/verification-controller\/src\/source-artifact-reader\.mjs'/u,
  );
  assert.doesNotMatch(production, /test-cloud-source-artifact-reader\.mjs/u);
});
