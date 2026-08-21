import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

async function loadExactFunctionProjection() {
  const source = await readFile(
    new URL('./test-cloud-appwrite.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('function exactFunctionProjection(value, functionId)');
  const end = source.indexOf('\n\nfunction createRequest', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);

  const context = {
    FUNCTION_RECORDS: new Map([
      ['function-1', { entrypoint: 'main.py', runtime: 'python-3.12' }],
    ]),
    isProviderId(value) {
      return typeof value === 'string'
        && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value);
    },
    responseObject(value) {
      return value;
    },
  };
  vm.runInNewContext(
    `${source.slice(start, end)}\n`
      + 'globalThis.project = exactFunctionProjection;',
    context,
  );
  return context.project;
}

function functionResponse(deploymentId) {
  return {
    $id: 'function-1',
    commands: '',
    deploymentId,
    enabled: true,
    entrypoint: 'main.py',
    events: [],
    execute: [],
    logging: false,
    name: 'fixture',
    providerRootDirectory: '',
    runtime: 'python-3.12',
    schedule: '',
    scopes: [],
    timeout: 30,
  };
}

test('function readback normalizes Appwrite empty deployment ID to no active deployment', async () => {
  const project = await loadExactFunctionProjection();

  assert.equal(project(functionResponse(''), 'function-1').activeDeploymentId, null);
  assert.equal(project(functionResponse(null), 'function-1').activeDeploymentId, null);
  assert.equal(
    project(functionResponse('deployment-1'), 'function-1').activeDeploymentId,
    'deployment-1',
  );
  assert.throws(
    () => project(functionResponse('invalid deployment'), 'function-1'),
    /invalid function response/u,
  );
});
