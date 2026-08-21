import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createTestCloudClients } from './test-cloud-appwrite.mjs';
import { createTestEnvironmentContext } from './test-cloud-environment.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const inventory = JSON.parse(await readFile(
  path.join(ROOT, 'dev/verification/environments/test-cloud.inventory.v1.json'),
  'utf8',
));

function credentialHandle(record) {
  return Object.freeze({
    credentialClass: record.credentialClass,
    variableName: record.variableName,
    scopes: Object.freeze([...record.scopes]),
    readSecret() {
      return `${record.credentialClass}-secret-sentinel`;
    },
  });
}

function createOperator(responses) {
  const credentialHandles = Object.freeze({
    operator: credentialHandle(inventory.credentialVariables.operator),
    fixture: credentialHandle(inventory.credentialVariables.fixture),
  });
  const context = createTestEnvironmentContext({
    inventory,
    environment: {
      endpoint: inventory.environment.endpoint,
      projectId: inventory.environment.projectId,
      siteId: inventory.environment.siteId,
      origin: inventory.environment.publicOrigin,
    },
    candidateRevision: '0d7c599b9f512c50b141556e76fbf4a48c59603e',
    runId: 'verify-0d7c599b9f51-32438374110-1',
    credentialHandles,
  });
  assert.equal(context.status, 'PASS');
  const calls = [];
  const queue = [...responses];
  const clients = createTestCloudClients({
    context: context.value,
    credentialHandles,
    async fetch(url, options) {
      calls.push({ options, url });
      assert.notEqual(queue.length, 0, 'fake response queue exhausted');
      return queue.shift();
    },
  });
  assert.equal(clients.status, 'PASS');
  return { calls, operator: clients.value.operator };
}

function deploymentResponse(deploymentId, status = 202) {
  return new Response(JSON.stringify({
    $id: deploymentId,
    status: 'waiting',
  }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('function artifact upload accepts the Appwrite asynchronous 202 deployment response', async () => {
  const { calls, operator } = createOperator([deploymentResponse('function-deployment-1')]);

  const result = await operator.createFunctionDeployment({
    functionId: 'api-keys-py',
    code: new Uint8Array([1, 2, 3]),
    activate: false,
  });

  assert.equal(result.status, 'PASS');
  assert.equal(result.value.deploymentId, 'function-deployment-1');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, 'POST');
});

test('site artifact upload accepts the Appwrite asynchronous 202 deployment response', async () => {
  const { calls, operator } = createOperator([deploymentResponse('site-deployment-1')]);

  const result = await operator.createSiteDeployment({
    code: new Uint8Array([4, 5, 6]),
    activate: false,
  });

  assert.equal(result.status, 'PASS');
  assert.equal(result.value.deploymentId, 'site-deployment-1');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, 'POST');
});
