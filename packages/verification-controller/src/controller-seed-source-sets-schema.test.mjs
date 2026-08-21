import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('controller seed schema pins the exact materialized relocation set', async () => {
  const [schema, sourceSets] = await Promise.all([
    readFile('dev/verification/schemas/controller-seed-source-sets.v1.schema.json', 'utf8')
      .then(JSON.parse),
    readFile('packages/verification-controller/controller-seed-source-sets.v1.json', 'utf8')
      .then(JSON.parse),
  ]);
  const expected = schema.$defs.controller.allOf[1].properties.relocations.const;
  const actual = sourceSets.sets.find(({ name }) => name === 'controller').relocations;
  assert.deepEqual(actual, expected);
  assert.deepEqual(actual.map(({ destination }) => destination), [
    'package-lock.json',
    'package.json',
    '.github/workflows/collect-appwrite-test-readback.yml',
    '.github/workflows/publish-controller-bundle.yml',
    '.github/workflows/recover-appwrite-test.yml',
    '.github/workflows/verify-test-cloud.yml',
  ]);
});
