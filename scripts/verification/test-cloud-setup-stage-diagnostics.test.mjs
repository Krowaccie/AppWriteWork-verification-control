import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const SAFE_SETUP_STAGE_CODES = Object.freeze([
  'TEST_CLOUD_SETUP_REQUEST_INVALID',
  'TEST_CLOUD_SETUP_PROVIDER_BINDING_INVALID',
  'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID',
  'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID',
  'TEST_CLOUD_SETUP_ENVIRONMENT_BINDING_INVALID',
  'TEST_CLOUD_SETUP_PAYLOAD_INVALID',
  'TEST_CLOUD_SETUP_IDENTITY_DIGEST_MISMATCH',
  'TEST_CLOUD_SETUP_FINALIZATION_INVALID',
]);

test('setup readback emits only fixed stage diagnostics', async () => {
  const source = await readFile(
    new URL('./test-cloud-provider-contract.mjs', import.meta.url),
    'utf8',
  );
  for (const code of SAFE_SETUP_STAGE_CODES) {
    assert.match(source, new RegExp(`loadBlocked\\('setup', '${code}'\\)`, 'u'));
  }
  assert.match(source, /return loadBlocked\('setup', failureCode\);/u);
});
