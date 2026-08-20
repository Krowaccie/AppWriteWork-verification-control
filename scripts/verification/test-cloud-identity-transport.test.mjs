import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('identity readback requests disable response compression for byte-exact bounds', async () => {
  const source = await readFile(
    new URL('./test-cloud-identity-bindings.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('function nonSecretHeaders(projectId)');
  const end = source.indexOf('\n}\n\nfunction listRecipe', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  assert.match(
    source.slice(start, end),
    /'Accept-Encoding': 'identity'/u,
  );
});
