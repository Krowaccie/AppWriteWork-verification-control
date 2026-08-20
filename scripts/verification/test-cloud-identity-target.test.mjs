import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

async function loadProviderIdValidator() {
  const source = await readFile(
    new URL('./test-cloud-identity-bindings.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('function validNullableProviderId(value)');
  const end = source.indexOf('\n\nfunction validateTarget', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);

  const context = {
    utf8Length: (value) => Buffer.byteLength(value, 'utf8'),
  };
  vm.runInNewContext(
    `${source.slice(start, end)}\n`
      + 'globalThis.validator = validNullableProviderId;',
    context,
  );
  return context.validator;
}

test('identity target provider ID accepts only null or a bounded string', async () => {
  const validNullableProviderId = await loadProviderIdValidator();

  assert.equal(validNullableProviderId(null), true);
  assert.equal(validNullableProviderId(''), true);
  assert.equal(validNullableProviderId('provider-id'), true);
  assert.equal(validNullableProviderId('x'.repeat(513)), false);
  assert.equal(validNullableProviderId(0), false);
  assert.equal(validNullableProviderId(undefined), false);
});
