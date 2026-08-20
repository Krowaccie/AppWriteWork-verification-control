import assert from 'node:assert/strict';
import test from 'node:test';

import {
  windowsHelperWatchdogTimeoutMs,
} from './process-containment.mjs';

test('Windows helper watchdog includes bounded startup and shutdown time', () => {
  assert.equal(windowsHelperWatchdogTimeoutMs(30_000), 105_000);
  assert.equal(windowsHelperWatchdogTimeoutMs(86_400_000), 86_475_000);
});

test('Windows helper watchdog rejects invalid process timeouts', () => {
  for (const value of [0, -1, 1.5, Number.NaN, 86_400_001]) {
    assert.throws(
      () => windowsHelperWatchdogTimeoutMs(value),
      /timeoutMs/u,
    );
  }
});
