import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const pairs = [
  ['.github/workflows/publish-controller-bundle.yml',
    'packages/verification-controller/workflows/publish-controller-bundle.yml'],
  ['.github/workflows/verify-test-cloud.yml',
    'packages/verification-controller/workflows/verify-test-cloud.yml'],
];

test('publisher and hosted workflow consume a verified artifact directory, not oversized variables', async () => {
  for (const [rootPath, packagePath] of pairs) {
    const root = await readFile(rootPath, 'utf8');
    const packaged = await readFile(packagePath, 'utf8');
    assert.equal(packaged, root);
    assert.match(root, /TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_ID/u);
    assert.match(root, /TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_DIGEST/u);
    assert.match(root, /test-cloud-binding-artifact-verifier\.mjs/u);
    assert.match(root, /BINDING_DIRECTORY/u);
    assert.doesNotMatch(root, /vars\.TEST_CLOUD_(?:HOSTED_)?SETUP_(?:READBACK|ATTESTATION)_(?:JSON|DIGEST)/u);
    assert.doesNotMatch(root, /APPWRITE_TEST_RECOVERY_API_KEY/u);
  }
});

test('hosted workflow passes the exact verified directory to the controller CLI', async () => {
  const workflow = await readFile('.github/workflows/verify-test-cloud.yml', 'utf8');
  assert.match(workflow, /--binding-directory "\$BINDING_DIRECTORY"/u);
});
