import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

function providerRootDirectory(source, constantName) {
  const start = source.indexOf(`const ${constantName} = Object.freeze({`);
  const end = source.indexOf('\n});', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const block = source.slice(start, end);
  const match = block.match(/providerRootDirectory: '([^']*)'/u);
  assert.notEqual(match, null);
  return match[1];
}

test('preflight and readback keep the test runner disconnected from VCS', async () => {
  const [preflight, readback] = await Promise.all([
    readFile(new URL('./test-cloud-preflight.mjs', import.meta.url), 'utf8'),
    readFile(
      new URL('../../packages/verification-controller/src/appwrite-test-live-readback.mjs', import.meta.url),
      'utf8',
    ),
  ]);

  const preflightRoot = providerRootDirectory(
    preflight,
    'EXPECTED_RUNNER_CONFIGURATION',
  );
  const readbackRoot = providerRootDirectory(readback, 'EXPECTED_RUNNER');

  assert.equal(preflightRoot, readbackRoot);
  assert.equal(preflightRoot, '');
});
