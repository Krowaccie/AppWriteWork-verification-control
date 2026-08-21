import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const paths = [
  '.github/workflows/recover-appwrite-test.yml',
  'packages/verification-controller/workflows/recover-appwrite-test.yml',
];

test('recovery workflow copies are exact and remain manual-only', async () => {
  const [root, packaged] = await Promise.all(paths.map((value) => readFile(value, 'utf8')));
  assert.equal(packaged, root);
  assert.match(root, /^  workflow_dispatch:\r?$/mu);
  assert.doesNotMatch(root, /^  (?:pull_request|pull_request_target|push|workflow_run):/mu);
  assert.match(root, /environment: appwrite-test/u);
  assert.match(root, /concurrency:\r?\n  group: appwrite-test-verification/u);
});

test('recovery workflow proves the failed owner, old binding, and protected signed controller separately', async () => {
  const workflow = await readFile(paths[0], 'utf8');
  const controller = await readFile(
    'packages/verification-controller/src/test-cloud-recovery-controller.mjs',
    'utf8',
  );
  assert.match(workflow, /run\.workflow_id !== 336735803/u);
  assert.match(workflow, /run\.conclusion !== 'failure'/u);
  assert.match(workflow, /CONTROLLER_REVISION: \$\{\{ inputs\.original_controller_sha \}\}/u);
  assert.match(workflow, /TRUSTED_CONTROLLER_SHA: \$\{\{ vars\.TRUSTED_CONTROLLER_SHA \}\}/u);
  assert.match(workflow, /git\/ref\/heads\/main/u);
  assert.match(workflow, /commit\.commit\?\.verification\?\.verified !== true/u);
  assert.doesNotMatch(workflow, /prepare-controller-artifact\.mjs|TRUSTED_CONTROLLER_ARTIFACT_ID|TRUSTED_CONTROLLER_BUNDLE_DIGEST/u);
  assert.match(workflow, /test-cloud-binding-artifact-verifier\.mjs/u);
  assert.match(workflow, /test-cloud-recovery-controller\.mjs/u);
  assert.doesNotMatch(controller, /reattestLocalControllerArtifact|CONTROLLER_ARTIFACT_DIRECTORY/u);
});

test('recovery credential is exposed only to the final recovery step', async () => {
  const workflow = await readFile(paths[0], 'utf8');
  const finalStep = workflow.slice(workflow.indexOf('- name: Recover only the expired Appwrite Test lease'));
  const prefix = workflow.slice(0, workflow.indexOf('- name: Recover only the expired Appwrite Test lease'));
  assert.doesNotMatch(prefix, /APPWRITE_TEST_RECOVERY_API_KEY/u);
  assert.match(finalStep, /APPWRITE_TEST_RECOVERY_API_KEY: \$\{\{ secrets\.APPWRITE_TEST_RECOVERY_API_KEY \}\}/u);
  assert.doesNotMatch(finalStep, /GITHUB_TOKEN|github\.token|CONTROLLER_ARTIFACT_READ_TOKEN/u);
});
