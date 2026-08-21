import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const SAFE_PREFLIGHT_STAGE_CODES = Object.freeze([
  'TEST_CLOUD_PREFLIGHT_AUTHORIZATION_INVALID',
  'TEST_CLOUD_PREFLIGHT_ATTESTATION_STALE',
  'TEST_CLOUD_PREFLIGHT_MANIFEST_INVALID',
  'TEST_CLOUD_PREFLIGHT_CLIENTS_INVALID',
  'TEST_CLOUD_PREFLIGHT_SITE_READBACK_INVALID',
  'TEST_CLOUD_PREFLIGHT_FUNCTION_READBACK_INVALID',
  'TEST_CLOUD_PREFLIGHT_RUNNER_CONFIGURATION_INVALID',
  'TEST_CLOUD_PREFLIGHT_PROJECTION_MISMATCH',
  'TEST_CLOUD_PREFLIGHT_LEASE_INVALID',
  'TEST_CLOUD_PREFLIGHT_INTERNAL_INVALID',
]);

test('preflight preserves only fixed non-sensitive stage diagnostics', async () => {
  const [preflightSource, laneSource] = await Promise.all([
    readFile(new URL('./test-cloud-preflight.mjs', import.meta.url), 'utf8'),
    readFile(new URL('./test-cloud-lane.mjs', import.meta.url), 'utf8'),
  ]);

  for (const code of SAFE_PREFLIGHT_STAGE_CODES) {
    assert.match(preflightSource, new RegExp(`blocked\\('${code}'\\)`, 'u'));
    assert.match(laneSource, new RegExp(`'${code}'`, 'u'));
  }
  assert.match(laneSource, /safeOperationDiagnosticCode\(outcome,/u);
});
