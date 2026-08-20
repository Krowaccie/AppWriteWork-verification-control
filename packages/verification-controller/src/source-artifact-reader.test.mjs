import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import { readSourceArtifact } from './source-artifact-reader.mjs';

const REVISION = '1'.repeat(40);
const CONFIG = Object.freeze({
  appId: '4632510',
  installationId: '154580138',
  sourceRepositoryId: 1119118902,
  sourceWorkflowId: 334307313,
});
const PRIVATE_KEY = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' });

function sourceRequest(permissions, calls) {
  return async (requestPath, options) => {
    calls.push([requestPath, options]);
    if (requestPath === `/app/installations/${CONFIG.installationId}/access_tokens`) {
      return {
        status: 201,
        body: {
          token: 'test-installation-token',
          permissions,
          repositories: [{
            id: CONFIG.sourceRepositoryId,
            full_name: 'Krowaccie/AppWriteWork',
          }],
        },
      };
    }
    if (requestPath === '/repos/Krowaccie/AppWriteWork') {
      return { status: 500, body: {} };
    }
    if (requestPath === '/installation/token') {
      return { status: 204, body: null };
    }
    throw new Error(`unexpected test request: ${requestPath}`);
  };
}

async function readUntilRepositoryRequest(permissions, calls = []) {
  return readSourceArtifact({
    config: CONFIG,
    revision: REVISION,
    qualifyingRunId: '32404161044',
    runAttempt: 1,
    privateKey: PRIVATE_KEY,
    request: sourceRequest(permissions, calls),
    readZip: async () => [],
    nowSeconds: 1_787_252_400,
  });
}

test('accepts the exact Actions read and implicit Metadata read token response', async () => {
  const calls = [];
  await assert.rejects(
    readUntilRepositoryRequest({ metadata: 'read', actions: 'read' }, calls),
    (error) => error?.code === 'SOURCE_REPOSITORY_READ_FAILED',
  );
  assert.deepEqual(JSON.parse(calls[0][1].body), {
    repositories: ['AppWriteWork'],
    permissions: { actions: 'read' },
  });
  assert.deepEqual(calls.map(([requestPath]) => requestPath), [
    `/app/installations/${CONFIG.installationId}/access_tokens`,
    '/repos/Krowaccie/AppWriteWork',
    '/installation/token',
  ]);
});

test('rejects a token response missing the implicit Metadata read permission', async () => {
  await assert.rejects(
    readUntilRepositoryRequest({ actions: 'read' }),
    (error) => error?.code === 'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH',
  );
});

test('rejects a token response containing any additional repository permission', async () => {
  await assert.rejects(
    readUntilRepositoryRequest({ actions: 'read', metadata: 'read', contents: 'read' }),
    (error) => error?.code === 'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH',
  );
});
