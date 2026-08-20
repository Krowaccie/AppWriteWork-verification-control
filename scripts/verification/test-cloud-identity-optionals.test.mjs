import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

async function loadNullableUserIdValidator() {
  const source = await readFile(
    new URL('./test-cloud-identity-bindings.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('function validNullableUserId(value)');
  const end = source.indexOf('\n\nfunction validateTarget', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);

  const context = {
    ID_PATTERN: /^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$/,
  };
  vm.runInNewContext(
    `${source.slice(start, end)}\n`
      + 'globalThis.validator = validNullableUserId;',
    context,
  );
  return context.validator;
}

test('optional impersonator user ID accepts only null or an exact user ID', async () => {
  const validNullableUserId = await loadNullableUserIdValidator();

  assert.equal(validNullableUserId(null), true);
  assert.equal(validNullableUserId('user-123'), true);
  assert.equal(validNullableUserId('x'.repeat(36)), true);
  assert.equal(validNullableUserId(''), false);
  assert.equal(validNullableUserId('-user'), false);
  assert.equal(validNullableUserId('x'.repeat(37)), false);
  assert.equal(validNullableUserId(0), false);
});
