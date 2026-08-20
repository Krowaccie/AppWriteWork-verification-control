import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

async function loadTimestampValidator() {
  const source = await readFile(
    new URL('./test-cloud-identity-bindings.mjs', import.meta.url),
    'utf8',
  );
  const patternStart = source.indexOf('const RFC3339_MILLISECONDS =');
  const patternEnd = source.indexOf('\n\nfunction utf8Length', patternStart);
  const functionStart = source.indexOf('function isExactTimestamp(value)');
  const functionEnd = source.indexOf('\n\nfunction isDenseArray', functionStart);
  assert.notEqual(patternStart, -1);
  assert.notEqual(patternEnd, -1);
  assert.notEqual(functionStart, -1);
  assert.notEqual(functionEnd, -1);

  const context = {
    CAPTURED_DATE: Date,
    CAPTURED_DATE_PARSE: Date.parse,
    CAPTURED_DATE_PROTOTYPE: Date.prototype,
    CAPTURED_DATE_TO_ISO_STRING: Date.prototype.toISOString,
    CAPTURED_STRING_SLICE: String.prototype.slice,
    Number,
    OBJECT_GET_PROTOTYPE_OF: Object.getPrototypeOf,
    REFLECT_APPLY: Reflect.apply,
    REFLECT_CONSTRUCT: Reflect.construct,
    capturedIdentityIntrinsicsAvailable: () => true,
    forbidden: () => {
      throw new Error('forbidden');
    },
    isProxy: () => false,
  };
  vm.runInNewContext(
    `${source.slice(patternStart, patternEnd)}\n`
      + `${source.slice(functionStart, functionEnd)}\n`
      + 'globalThis.validator = isExactTimestamp;',
    context,
  );
  return context.validator;
}

test('identity timestamps accept exact Appwrite UTC ISO 8601 forms only', async () => {
  const isExactTimestamp = await loadTimestampValidator();

  assert.equal(isExactTimestamp('2020-10-15T06:38:00.000+00:00'), true);
  assert.equal(isExactTimestamp('2020-10-15T06:38:00.000Z'), true);
  assert.equal(isExactTimestamp('2020-10-15T06:38:00.000+01:00'), false);
  assert.equal(isExactTimestamp('2020-02-31T06:38:00.000+00:00'), false);
  assert.equal(isExactTimestamp('2020-10-15T06:38:00.00+00:00'), false);
});
