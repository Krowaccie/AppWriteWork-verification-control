import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflows = [
  '.github/workflows/collect-appwrite-test-readback.yml',
  'packages/verification-controller/workflows/collect-appwrite-test-readback.yml',
];

test('protected readback workflow is manual, fixed-target, pinned, and secret-minimal', async () => {
  for (const workflow of workflows) {
    const text = await readFile(workflow, 'utf8');
    assert.match(text, /^on:\r?\n  workflow_dispatch:/mu);
    assert.doesNotMatch(text, /^  (?:push|pull_request|pull_request_target|schedule):/mu);
    assert.match(text, /runs-on: windows-2025/u);
    assert.match(text, /environment: appwrite-test/u);
    assert.match(
      text,
      /^    if: github\.repository == 'Krowaccie\/AppWriteWork-verification-control'\r?$/mu,
    );
    assert.doesNotMatch(text, /^    if:.*vars\.TRUSTED_CONTROLLER_SHA.*$/mu);
    assert.match(text, /TRUSTED_CONTROLLER_SHA: \$\{\{ vars\.TRUSTED_CONTROLLER_SHA \}\}/u);
    assert.match(text, /WORKFLOW_HEAD_SHA: \$\{\{ github\.sha \}\}/u);
    assert.match(text, /WORKFLOW_HEAD_SHA -cne \$env:TRUSTED_CONTROLLER_SHA/u);
    assert.match(text, /node-version: '24\.11\.1'/u);
    assert.match(text, /retention-days: 7/u);
    assert.match(text, /actions\/checkout@[0-9a-f]{40}/u);
    assert.match(text, /actions\/setup-node@[0-9a-f]{40}/u);
    assert.match(text, /actions\/upload-artifact@[0-9a-f]{40}/u);
    assert.doesNotMatch(text, /APPWRITE_TEST_RECOVERY_API_KEY/u);
    assert.doesNotMatch(text, /69eb4818000afa64a7fa|69eb4a020024c520642e|branch production/iu);
    const mappedSecrets = [...text.matchAll(/secrets\.([A-Z0-9_]+)/gu)].map((match) => match[1]);
    assert.deepEqual([...new Set(mappedSecrets)].sort(), [
      'APPWRITE_TEST_FIXTURE_API_KEY',
      'APPWRITE_TEST_OPERATOR_API_KEY',
      'E2E_EDITOR_EMAIL',
      'E2E_OWNER_EMAIL',
      'E2E_VIEWER_EMAIL',
      'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
    ]);
  }
});
