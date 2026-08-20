import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createTestEnvironmentContext } from '../../../scripts/verification/test-cloud-environment.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const inventory = JSON.parse(await readFile(
  path.join(ROOT, 'dev/verification/environments/test-cloud.inventory.v1.json'),
  'utf8',
));
const providerContractPath =
  'src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json';

function credentialHandle(record) {
  let handle;
  handle = Object.freeze({
    credentialClass: record.credentialClass,
    variableName: record.variableName,
    scopes: Object.freeze([...record.scopes]),
    readSecret() {
      assert.equal(this, handle);
      return `${record.credentialClass}-secret-sentinel`;
    },
  });
  return handle;
}

test('provider bootstrap qualification remains valid for the authentic test-cloud context', async () => {
  const provider = await import('../../../scripts/verification/test-cloud-provider-contract.mjs');
  const outcome = await provider.bootstrapRuntime();
  assert.equal(outcome.status, 'PASS', outcome.diagnostics?.[0]?.code);

  const context = createTestEnvironmentContext({
    inventory,
    environment: {
      endpoint: inventory.environment.endpoint,
      projectId: inventory.environment.projectId,
      siteId: inventory.environment.siteId,
      origin: inventory.environment.publicOrigin,
    },
    candidateRevision: '0d7c599b9f512c50b141556e76fbf4a48c59603e',
    runId: 'verify-0d7c599b9f51-32404161044-1',
    credentialHandles: Object.freeze({
      fixture: credentialHandle(inventory.credentialVariables.fixture),
      operator: credentialHandle(inventory.credentialVariables.operator),
    }),
  });
  assert.equal(context.status, 'PASS', context.diagnostics?.[0]?.code);

  const qualified = await provider.loadQualifiedTestCloudProviderContract(Object.freeze({
    runtimeQualification: outcome.value.runtimeQualification,
    context: context.value,
  }));
  assert.equal(qualified.status, 'PASS', qualified.diagnostics?.[0]?.code);
});

test('digest-bound provider contract is checked out with exact LF bytes', async () => {
  const attributes = await readFile(path.join(ROOT, '.gitattributes'), 'utf8');
  assert.match(
    attributes,
    new RegExp(`^${providerContractPath.replaceAll('.', '\\.')} text eol=lf$`, 'mu'),
  );
  const bytes = await readFile(path.join(ROOT, ...providerContractPath.split('/')));
  assert.equal(bytes.includes(0x0d), false);
});
