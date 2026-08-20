import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { main } from './test-cloud-controller.mjs';

const SHA = '1'.repeat(40);
const BINDING_NAMES = [
  'TEST_CLOUD_SETUP_READBACK_JSON',
  'TEST_CLOUD_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
];

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stream() {
  let value = '';
  return { write(chunk) { value += chunk; }, read() { return value; } };
}

async function bindingDirectory(root) {
  const directory = path.join(root, 'bindings');
  await mkdir(directory);
  for (let index = 0; index < BINDING_NAMES.length; index += 2) {
    const json = '{}';
    await writeFile(path.join(directory, `${BINDING_NAMES[index]}.txt`), json, 'utf8');
    await writeFile(path.join(directory, `${BINDING_NAMES[index + 1]}.txt`), digest(json), 'utf8');
  }
  return directory;
}

test('hosted CLI loads verified bindings from an exact directory without process env values', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'test-cloud-bindings-'));
  try {
    const directory = await bindingDirectory(root);
    const stdout = stream();
    const stderr = stream();
    let capturedEnvironment;
    const code = await main([
      '--hosted', '--revision', SHA, '--source-run-id', '123',
      '--source-run-attempt', '1', '--binding-directory', directory,
    ], {
      environment: { SAFE_EXISTING_VALUE: 'preserved' },
      inventory: { control: { primaryExecutionRetentionMaxSeconds: 86_400 } },
      stdout,
      stderr,
      createHostedDependencies(args) {
        capturedEnvironment = args.environment;
        return Object.freeze({});
      },
      async runHostedController() {
        return { status: 'PASS', value: {}, diagnostics: [] };
      },
    });
    assert.equal(code, 0, stderr.read());
    assert.equal(stdout.read(), 'PASS\n');
    assert.equal(capturedEnvironment.SAFE_EXISTING_VALUE, 'preserved');
    assert.equal(capturedEnvironment.TEST_CLOUD_SETUP_READBACK_JSON, '{}');
    assert.equal(capturedEnvironment.TEST_CLOUD_SETUP_READBACK_DIGEST, digest('{}'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('hosted CLI rejects a binding directory containing an extra file', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'test-cloud-bindings-'));
  try {
    const directory = await bindingDirectory(root);
    await writeFile(path.join(directory, 'extra.txt'), 'unexpected', 'utf8');
    const stderr = stream();
    const code = await main([
      '--hosted', '--revision', SHA, '--source-run-id', '123',
      '--source-run-attempt', '1', '--binding-directory', directory,
    ], {
      environment: {},
      inventory: { control: { primaryExecutionRetentionMaxSeconds: 86_400 } },
      stdout: stream(),
      stderr,
    });
    assert.equal(code, 2);
    assert.equal(stderr.read(), 'BLOCKED TEST_CLOUD_SETUP_INCOMPLETE\n');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('hosted CLI passes the staged controller artifact directory to local reattestation', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'test-cloud-controller-artifact-'));
  try {
    const directory = await bindingDirectory(root);
    const controllerArtifactDirectory = path.join(root, 'controller-artifact');
    await mkdir(controllerArtifactDirectory);
    const stderr = stream();
    let capturedDependencies;
    const code = await main([
      '--hosted', '--revision', SHA, '--source-run-id', '123',
      '--source-run-attempt', '1', '--binding-directory', directory,
    ], {
      environment: { CONTROLLER_ARTIFACT_DIRECTORY: controllerArtifactDirectory },
      inventory: { control: { primaryExecutionRetentionMaxSeconds: 86_400 } },
      stdout: stream(),
      stderr,
      createHostedDependencies(args) {
        capturedDependencies = args;
        return Object.freeze({});
      },
      async runHostedController() {
        return { status: 'PASS', value: {}, diagnostics: [] };
      },
    });

    assert.equal(code, 0, stderr.read());
    assert.equal(capturedDependencies.controllerArtifactIo.root, controllerArtifactDirectory);
    assert.equal(typeof capturedDependencies.controllerArtifactIo.lstat, 'function');
    assert.equal(typeof capturedDependencies.controllerArtifactIo.readFile, 'function');
    assert.equal(typeof capturedDependencies.controllerArtifactIo.realpath, 'function');
    assert.equal(
      Object.hasOwn(capturedDependencies.environment, 'CONTROLLER_ARTIFACT_READ_TOKEN'),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
