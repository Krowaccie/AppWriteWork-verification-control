import { createHash } from 'node:crypto';
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

import { createProductionReadonlyAdapter } from './production-readonly-adapter.mjs';
import * as productionAppwrite from './production-readonly-appwrite.mjs';
import { productionBrowserPolicy } from './production-readonly-browser.mjs';
import {
  createProductionReadonlyEnvironment,
  productionInventory,
} from './production-readonly-environment.mjs';
import * as productionHttp from './production-readonly-http.mjs';
import { runProductionReadonlyLane } from './production-readonly-lane.mjs';
import { parseVerifiedReleaseRecordHandoffBytes } from './verified-release-record-handoff.mjs';

const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const READONLY_KEY = 'APPWRITE_PRODUCTION_READONLY_API_KEY';
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[1-9][0-9]*$/;
const GITHUB_METADATA_CREDENTIAL = /^(?:GITHUB|GH|CONTROLLER_ARTIFACT).*(?:TOKEN|SECRET|KEY|PRIVATE|CREDENTIAL)$/u;
const PRODUCTION_ENVIRONMENT = Object.freeze({
  endpoint: 'https://api.salmora.net/v1',
  projectId: '69eb4818000afa64a7fa',
  siteId: '69eb4a020024c520642e',
  origin: 'https://salmora.net',
});
const PRODUCTION_SCOPES = Object.freeze(['functions.read', 'sites.read']);

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function safePath(value) {
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

function controllerExpectation(env) {
  const repository = dataValue(env, 'GITHUB_REPOSITORY');
  const revision = dataValue(env, 'GITHUB_SHA');
  const artifactId = dataValue(env, 'TRUSTED_CONTROLLER_ARTIFACT_ID');
  const bundleDigest = dataValue(env, 'TRUSTED_CONTROLLER_BUNDLE_DIGEST');
  if (repository !== CONTROLLER_REPOSITORY
      || !SHA.test(revision ?? '')
      || dataValue(env, 'TRUSTED_CONTROLLER_SHA') !== revision
      || !ID.test(artifactId ?? '')
      || !DIGEST.test(bundleDigest ?? '')) {
    throw blocked('TRUSTED_CONTROLLER_REQUIRED');
  }
  return Object.freeze({ repository, revision, artifactId, bundleDigest });
}

function producerExpectation(env) {
  const runId = dataValue(env, 'GITHUB_RUN_ID');
  const attemptText = dataValue(env, 'GITHUB_RUN_ATTEMPT');
  if (!ID.test(runId ?? '') || !ID.test(attemptText ?? '')) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_PRODUCER_INVALID');
  }
  const runAttempt = Number(attemptText);
  if (!Number.isSafeInteger(runAttempt)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_PRODUCER_INVALID');
  }
  return Object.freeze({
    repository: CONTROLLER_REPOSITORY,
    workflow: 'Production Readonly',
    runId,
    runAttempt,
  });
}

function adapterController(controller) {
  return Object.freeze({
    repository: controller.repository,
    sha: controller.revision,
    trustedControllerSha: controller.revision,
    bundleDigest: controller.bundleDigest,
    trustedBundleDigest: controller.bundleDigest,
  });
}

function appwriteCredentialSource(env) {
  return Object.freeze({
    names: Object.freeze([READONLY_KEY]),
    read(name) {
      if (name !== READONLY_KEY) throw blocked('PRODUCTION_CREDENTIAL_ISOLATION');
      return env[READONLY_KEY];
    },
  });
}

function localRecordReader(handoff) {
  return Object.freeze({
    async readTrustedReleaseRecord({ artifactId } = {}) {
      if (artifactId !== handoff.releaseBinding.recordArtifactId) {
        return Object.freeze({
          status: 'BLOCKED', value: null,
          diagnostics: Object.freeze([{ code: 'RELEASE_RECORD_INPUT_INVALID' }]),
        });
      }
      return Object.freeze({
        status: 'PASS',
        value: Object.freeze({
          record: handoff.releaseRecord,
          recordArtifactDigest: handoff.releaseBinding.recordArtifactDigest,
          recordDigest: handoff.releaseBinding.recordDigest,
        }),
        diagnostics: Object.freeze([]),
      });
    },
  });
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

export function parseProductionBrowserPolicyArguments(argv) {
  if (JSON.stringify(argv) === JSON.stringify(['--help'])) return { help: true };
  if (!Array.isArray(argv) || argv.length !== 6
      || argv[0] !== '--verified-handoff' || !safePath(argv[1])
      || argv[2] !== '--expected-handoff-digest' || !DIGEST.test(argv[3] ?? '')
      || argv[4] !== '--output' || !safePath(argv[5])) {
    throw blocked('PRODUCTION_BROWSER_POLICY_ARGUMENT_INVALID');
  }
  return {
    verifiedHandoffPath: argv[1],
    expectedHandoffDigest: argv[3],
    help: false,
    outputPath: argv[5],
  };
}

export async function createProductionBrowserPolicy({
  verifiedHandoffPath,
  expectedHandoffDigest,
  env,
  fetchImpl = globalThis.fetch,
  outputPath,
  readFile: readFileImpl = readFile,
  createEnvironment = createProductionReadonlyEnvironment,
  createAdapter = createProductionReadonlyAdapter,
  runLane = runProductionReadonlyLane,
  write = writeFile,
  appendOutput = appendFile,
} = {}) {
  if (!safePath(verifiedHandoffPath) || !DIGEST.test(expectedHandoffDigest ?? '')
      || env === null || typeof env !== 'object' || utilTypes.isProxy(env)
      || typeof fetchImpl !== 'function' || !safePath(outputPath)
      || typeof readFileImpl !== 'function' || typeof createEnvironment !== 'function'
      || typeof createAdapter !== 'function' || typeof runLane !== 'function'
      || typeof write !== 'function' || typeof appendOutput !== 'function') {
    throw blocked('PRODUCTION_BROWSER_POLICY_INPUT_INVALID');
  }
  const names = Object.getOwnPropertyNames(env);
  if (names.some((name) => GITHUB_METADATA_CREDENTIAL.test(name))) {
    throw blocked('PRODUCTION_CREDENTIAL_ISOLATION');
  }
  const appwriteNames = names.filter((name) => /^APPWRITE_/u.test(name)).sort();
  if (JSON.stringify(appwriteNames) !== JSON.stringify([READONLY_KEY])) {
    throw blocked('PRODUCTION_CREDENTIAL_ISOLATION');
  }
  const githubOutput = dataValue(env, 'GITHUB_OUTPUT');
  if (typeof githubOutput !== 'string' || githubOutput.length === 0) {
    throw blocked('PRODUCTION_BROWSER_POLICY_OUTPUT_UNAVAILABLE');
  }
  const expectedController = controllerExpectation(env);
  const expectedProducer = producerExpectation(env);
  const handoffBytes = await readFileImpl(verifiedHandoffPath);
  const handoff = parseVerifiedReleaseRecordHandoffBytes({
    bytes: handoffBytes,
    expectedController,
    expectedProducer,
  });
  if (handoff.handoffDigest !== expectedHandoffDigest) {
    throw blocked('PRODUCTION_BROWSER_POLICY_HANDOFF_DIGEST_MISMATCH');
  }

  let environmentContext = null;
  const adapter = createAdapter({
    controller: adapterController(expectedController),
    recordReader: localRecordReader(handoff),
    appwrite: productionAppwrite,
    http: productionHttp,
    createEnvironment() {
      const created = createEnvironment({
        credentialSource: appwriteCredentialSource(env),
        environment: PRODUCTION_ENVIRONMENT,
        fetchImpl,
        inventory: productionInventory,
        scopes: PRODUCTION_SCOPES,
      });
      if (created?.status === 'PASS') environmentContext = created.value;
      return created;
    },
    resolveTarget(targetRecord) {
      if (environmentContext === null) return null;
      if (targetRecord?.kind === 'site') {
        return environmentContext.siteTarget.logicalId === targetRecord.deploymentLogicalTarget
          ? environmentContext.siteTarget : null;
      }
      if (targetRecord?.kind !== 'function') return null;
      return environmentContext.functionTargets.find(
        ({ logicalId }) => logicalId === targetRecord.deploymentLogicalTarget,
      ) ?? null;
    },
  });
  const verification = await runLane({
    adapter,
    artifactId: handoff.releaseBinding.recordArtifactId,
    candidateRevision: null,
  });
  if (verification?.status !== 'PASS') {
    throw blocked(verification?.diagnostics?.[0]?.code ?? 'PRODUCTION_READONLY_BLOCKED');
  }
  const bytes = Buffer.from(JSON.stringify(productionBrowserPolicy), 'utf8');
  const policyDigest = digestBytes(bytes);
  await write(outputPath, bytes, { flag: 'wx' });
  await appendOutput(githubOutput, `policy_digest=${policyDigest}\n`, 'utf8');
  return deepFreeze({ policy: productionBrowserPolicy, policyDigest, verification });
}

async function main() {
  try {
    const parsed = parseProductionBrowserPolicyArguments(process.argv.slice(2));
    if (parsed.help) {
      process.stdout.write('Usage: create-production-browser-policy --verified-handoff PATH --expected-handoff-digest SHA256 --output PATH\n');
      return 0;
    }
    await createProductionBrowserPolicy({ ...parsed, env: process.env });
    return 0;
  } catch (error) {
    process.stderr.write(`${error?.message ?? 'BLOCKED PRODUCTION_BROWSER_POLICY_FAILED'}\n`);
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exitCode = await main();
}
