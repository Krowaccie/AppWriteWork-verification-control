import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

async function loadPasswordValidator() {
  const source = await readFile(
    new URL('./test-cloud-identity-bindings.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('function validatePasswordArm(value)');
  const end = source.indexOf('\n\nfunction validateUser', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);

  const context = {
    Boolean,
    Number,
    OBJECT_HAS_OWN: Object.hasOwn,
    PRINTABLE_ASCII_PATTERN: /^[\x20-\x7e]+$/,
    arrayEvery: (value, predicate) => value.every(predicate),
    arrayIncludes: (value, candidate) => value.includes(candidate),
    arrayMap: (value, callback) => value.map(callback),
    arraySlice: (value, startIndex) => value.slice(startIndex),
    arraySome: (value, predicate) => value.some(predicate),
    exactObject: (value, keys) => {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return null;
      }
      const actual = Object.keys(value).sort();
      const expected = [...keys].sort();
      return actual.length === expected.length
        && actual.every((key, index) => key === expected[index]) ? value : null;
    },
    invalid: (code) => {
      throw new Error(code);
    },
    utf8Length: (value) => Buffer.byteLength(value, 'utf8'),
  };
  vm.runInNewContext(
    `${source.slice(start, end)}\n`
      + 'globalThis.validator = validatePasswordArm;',
    context,
  );
  return context.validator;
}

test('identity password arm accepts exact Appwrite Cloud Argon2 options', async () => {
  const validatePasswordArm = await loadPasswordValidator();
  const base = {
    hash: 'argon2',
    password: '$argon2id$v=19$m=65536,t=4,p=3$test$test',
  };

  assert.doesNotThrow(() => validatePasswordArm({
    ...base,
    hashOptions: {
      type: 'argon2',
      memory_cost: 65_536,
      time_cost: 4,
      threads: 3,
    },
  }));
  assert.throws(
    () => validatePasswordArm({
      ...base,
      hashOptions: {
        type: 'argon2',
        memoryCost: 65_536,
        timeCost: 4,
        threads: 3,
      },
    }),
    /TEST_IDENTITY_USER_PASSWORD_INVALID/u,
  );
});
