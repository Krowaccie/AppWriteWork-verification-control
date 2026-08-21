import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import { main } from './prepare-controller-artifact.mjs';

test('prepare CLI emits only the closed controller proof after successful preparation', async () => {
  const output = path.resolve('controller-artifact-test');
  let appended = null;
  let observed = null;
  const environment = Object.freeze({
    CONTROLLER_ARTIFACT_READ_TOKEN: 'token',
    GITHUB_ENV: path.resolve('github-env'),
    GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
    REQUIRED_CONTROLLER_ENTRYPOINT:
      'packages/verification-controller/workflows/recover-appwrite-test.yml',
    TRUSTED_CONTROLLER_ARTIFACT_ID: '123',
    TRUSTED_CONTROLLER_BUNDLE_DIGEST: `sha256:${'b'.repeat(64)}`,
    TRUSTED_CONTROLLER_SHA: 'a'.repeat(40),
  });
  const exitCode = await main(['--output', output], {
    appendFileSync(_path, value) {
      appended = value;
    },
    environment,
    async prepare(input) {
      observed = input;
      return Object.freeze({
        artifactId: input.artifactId,
        bundleDigest: input.bundleDigest,
        repository: input.repository,
        sha: input.sha,
      });
    },
  });
  assert.equal(exitCode, 0);
  assert.equal(observed.outputDirectory, output);
  assert.match(appended, /^PROOF_STATUS=PASS$/mu);
  assert.match(appended, /^PROOF_ARTIFACT_ID=123$/mu);
  assert.doesNotMatch(appended, /token/u);
});

test('prepare CLI rejects malformed argv before preparation', async () => {
  let called = false;
  assert.equal(await main([], {
    async prepare() {
      called = true;
    },
  }), 2);
  assert.equal(called, false);
});
