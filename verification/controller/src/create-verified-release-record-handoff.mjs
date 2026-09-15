import { appendFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

import { createGithubDeploymentReader } from './github-deployment-reader.mjs';
import { createGithubProductionReadonlyTransport } from './github-production-readonly-transport.mjs';
import {
  buildVerifiedReleaseRecordHandoff,
  canonicalVerifiedReleaseRecordHandoffBytes,
} from './verified-release-record-handoff.mjs';

const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[1-9][0-9]*$/;
const GITHUB_SCOPES = Object.freeze(['actions:read', 'deployments:read']);

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function safeOutputPath(value) {
  return typeof value === 'string'
    && value.length > 0
    && !path.isAbsolute(value)
    && !value.includes('\\')
    && !value.split('/').some((part) => part === '' || part === '.' || part === '..')
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function dataValue(env, name) {
  const descriptor = Object.getOwnPropertyDescriptor(env, name);
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function trustedTuple(env) {
  const repository = dataValue(env, 'GITHUB_REPOSITORY');
  const revision = dataValue(env, 'GITHUB_SHA');
  const artifactId = dataValue(env, 'TRUSTED_CONTROLLER_ARTIFACT_ID');
  const bundleDigest = dataValue(env, 'TRUSTED_CONTROLLER_BUNDLE_DIGEST');
  if (dataValue(env, 'PROOF_STATUS') !== 'PASS'
      || repository !== REPOSITORY
      || dataValue(env, 'PROOF_REPOSITORY') !== repository
      || !SHA.test(revision ?? '')
      || dataValue(env, 'TRUSTED_CONTROLLER_SHA') !== revision
      || dataValue(env, 'PROOF_SHA') !== revision
      || !ID.test(artifactId ?? '')
      || dataValue(env, 'PROOF_ARTIFACT_ID') !== artifactId
      || !DIGEST.test(bundleDigest ?? '')
      || dataValue(env, 'PROOF_BUNDLE_DIGEST') !== bundleDigest) {
    throw blocked('TRUSTED_CONTROLLER_REQUIRED');
  }
  return Object.freeze({ repository, revision, artifactId, bundleDigest });
}

function producerTuple(env) {
  const runId = dataValue(env, 'GITHUB_RUN_ID');
  const runAttemptText = dataValue(env, 'GITHUB_RUN_ATTEMPT');
  if (!ID.test(runId ?? '') || !ID.test(runAttemptText ?? '')) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_PRODUCER_INVALID');
  }
  const runAttempt = Number(runAttemptText);
  if (!Number.isSafeInteger(runAttempt)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_PRODUCER_INVALID');
  }
  return Object.freeze({
    repository: REPOSITORY,
    workflow: 'Production Readonly',
    runId,
    runAttempt,
  });
}

function credentialHandle(env) {
  return Object.freeze({
    credentialClass: 'github-deployments-read',
    variableName: 'GITHUB_TOKEN',
    scopes: GITHUB_SCOPES,
    readSecret() {
      return env.GITHUB_TOKEN;
    },
  });
}

function controllerReaderTuple(controller) {
  return Object.freeze({
    repository: controller.repository,
    sha: controller.revision,
    trustedControllerSha: controller.revision,
    bundleDigest: controller.bundleDigest,
    trustedBundleDigest: controller.bundleDigest,
  });
}

export function parseVerifiedReleaseRecordHandoffArguments(argv) {
  if (JSON.stringify(argv) === JSON.stringify(['--help'])) return { help: true };
  if (!Array.isArray(argv) || argv.length !== 4
      || argv[0] !== '--artifact-id' || !ID.test(argv[1] ?? '')
      || argv[2] !== '--output' || !safeOutputPath(argv[3])) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_ARGUMENT_INVALID');
  }
  return { artifactId: argv[1], help: false, outputPath: argv[3] };
}

export async function createVerifiedReleaseRecordHandoffArtifact({
  artifactId,
  env,
  outputPath,
  fetchImpl = globalThis.fetch,
  now = Date.now,
  recordReader = null,
  createGithubTransport = createGithubProductionReadonlyTransport,
  write = writeFile,
  appendOutput = appendFile,
} = {}) {
  if (!ID.test(artifactId ?? '') || env === null || typeof env !== 'object'
      || utilTypes.isProxy(env) || !safeOutputPath(outputPath)
      || typeof fetchImpl !== 'function' || typeof now !== 'function'
      || typeof createGithubTransport !== 'function'
      || typeof write !== 'function' || typeof appendOutput !== 'function') {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INPUT_INVALID');
  }
  const names = Object.getOwnPropertyNames(env);
  if (names.some((name) => /^APPWRITE_/u.test(name))) {
    throw blocked('PRODUCTION_CREDENTIAL_ISOLATION');
  }
  const githubOutput = dataValue(env, 'GITHUB_OUTPUT');
  if (typeof githubOutput !== 'string' || githubOutput.length === 0) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_OUTPUT_UNAVAILABLE');
  }
  const controller = trustedTuple(env);
  const producer = producerTuple(env);
  let reader = recordReader;
  if (reader === null) {
    const transport = createGithubTransport({ fetchImpl, trustedControllerSha: controller.revision });
    reader = createGithubDeploymentReader({
      controller: controllerReaderTuple(controller),
      credentialHandle: credentialHandle(env),
      transport,
      now,
    });
  }
  if (typeof reader?.readTrustedReleaseRecord !== 'function') {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_READER_INVALID');
  }
  const read = await reader.readTrustedReleaseRecord({ artifactId });
  if (read?.status !== 'PASS') {
    throw blocked(read?.diagnostics?.[0]?.code ?? 'RELEASE_RECORD_UNTRUSTED');
  }
  const handoff = buildVerifiedReleaseRecordHandoff({
    controller,
    producer,
    releaseBinding: read.value.releaseBinding,
    releaseRecord: read.value.record,
  });
  const bytes = canonicalVerifiedReleaseRecordHandoffBytes(handoff);
  await write(outputPath, bytes, { flag: 'wx' });
  await appendOutput(githubOutput, [
    `handoff_digest=${handoff.handoffDigest}`,
    `record_artifact_id=${handoff.releaseBinding.recordArtifactId}`,
    `record_artifact_digest=${handoff.releaseBinding.recordArtifactDigest}`,
    '',
  ].join('\n'), 'utf8');
  return Object.freeze({ handoff });
}

async function main() {
  try {
    const parsed = parseVerifiedReleaseRecordHandoffArguments(process.argv.slice(2));
    if (parsed.help) {
      process.stdout.write('Usage: create-verified-release-record-handoff --artifact-id ID --output PATH\n');
      return 0;
    }
    await createVerifiedReleaseRecordHandoffArtifact({ ...parsed, env: process.env });
    return 0;
  } catch (error) {
    process.stderr.write(`${error?.message ?? 'BLOCKED VERIFIED_RELEASE_RECORD_HANDOFF_FAILED'}\n`);
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exitCode = await main();
}
