import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('setup qualification consumes the verified binding object directly', async () => {
  const [providerSource, controllerSource] = await Promise.all([
    readFile(new URL('./test-cloud-provider-contract.mjs', import.meta.url), 'utf8'),
    readFile(new URL(
      '../../packages/verification-controller/src/test-cloud-controller.mjs',
      import.meta.url,
    ), 'utf8'),
  ]);

  assert.doesNotMatch(providerSource, /env as PROCESS_ENV/u);
  assert.match(
    providerSource,
    /const SETUP_LOAD_KEYS = OBJECT_FREEZE\(\[[\s\S]*?'setupReadbackJson',[\s\S]*?'setupReadbackDigest',[\s\S]*?\]\);/u,
  );
  assert.match(
    controllerSource,
    /setupReadbackJson: readEnvironmentValue\([\s\S]*?'TEST_CLOUD_SETUP_READBACK_JSON',[\s\S]*?setupReadbackDigest: readEnvironmentValue\([\s\S]*?'TEST_CLOUD_SETUP_READBACK_DIGEST'/u,
  );
});
