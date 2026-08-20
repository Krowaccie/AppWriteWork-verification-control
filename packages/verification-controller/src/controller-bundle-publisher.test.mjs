import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildControllerBundlePublication,
  runControllerBundlePublisherCli,
} from './controller-bundle-publisher.mjs';

test('classifies invalid publisher input without exposing values', async () => {
  const result = await buildControllerBundlePublication({}, {
    clock: Object.freeze({ nowEpochSeconds: () => 1_800_000_000 }),
  });

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'CONTROLLER_BUNDLE_PUBLISHER_INPUT_INVALID');
  assert.equal(JSON.stringify(result).includes('secret-value-sentinel'), false);
});

test('classifies invalid CLI input before reading files or environment', async () => {
  const result = await runControllerBundlePublisherCli([], {});

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'CONTROLLER_BUNDLE_PUBLISHER_CLI_INPUT_INVALID');
});
