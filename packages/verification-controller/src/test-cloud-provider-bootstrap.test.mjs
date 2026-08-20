import assert from 'node:assert/strict';
import test from 'node:test';

test('provider bootstrap accepts the exact seven-export browser artifact namespace', async () => {
  const provider = await import('../../../scripts/verification/test-cloud-provider-contract.mjs');
  const outcome = await provider.bootstrapRuntime();
  assert.equal(outcome.status, 'PASS', outcome.diagnostics?.[0]?.code);
});
