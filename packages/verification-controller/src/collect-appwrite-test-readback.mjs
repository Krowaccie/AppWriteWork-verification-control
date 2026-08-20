#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { createAppwriteTestBrowserPolicy } from './appwrite-test-browser-policy.mjs';
import { readAppwriteTestLiveProjection } from './appwrite-test-live-readback.mjs';
import { createAppwriteTestSetupBindings } from './appwrite-test-setup-bindings.mjs';
import {
  extractSourceArtifactZip,
  readBoundedSourceArtifactArchive,
  readSourceArtifact,
} from './source-artifact-reader.mjs';
import { projectTestCloudBrowserArtifactPolicyRows } from
  './test-cloud-browser-artifact-set.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const INPUT_KEYS = Object.freeze([
  'controllerArtifact',
  'controllerRevision',
  'initialSeed',
  'runnerRevision',
  'sourceReader',
  'sourceRepositoryRevision',
  'sourceRunAttempt',
  'sourceRunId',
]);
const SOURCE_READER_KEYS = Object.freeze([
  'appId', 'installationId', 'sourceRepositoryId', 'sourceWorkflowId',
]);
const OUTER_KEYS = Object.freeze(['dependencies', 'environment', 'input']);
const BINDING_NAMES = Object.freeze([
  'TEST_CLOUD_SETUP_READBACK_JSON',
  'TEST_CLOUD_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
]);
const ENVIRONMENT_NAMES = Object.freeze([
  'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
  'APPWRITE_TEST_OPERATOR_API_KEY',
  'APPWRITE_TEST_FIXTURE_API_KEY',
  'E2E_EDITOR_EMAIL',
  'E2E_OWNER_EMAIL',
  'E2E_VIEWER_EMAIL',
]);
const MAX_GITHUB_JSON_BYTES = 2 * 1024 * 1024;
const SAFE_SOURCE_READER_DIAGNOSTIC_CODES = new Set([
  'SOURCE_ARTIFACT_DIGEST_MISMATCH',
  'SOURCE_ARTIFACT_DOWNLOAD_FAILED',
  'SOURCE_ARTIFACT_IDENTITY_MISMATCH',
  'SOURCE_ARTIFACT_LIST_FAILED',
  'SOURCE_ARTIFACT_MANIFEST_INVALID',
  'SOURCE_ARTIFACT_READER_INPUT_INVALID',
  'SOURCE_ARTIFACT_ZIP_UNSAFE',
  'SOURCE_APP_JWT_INPUT_INVALID',
  'SOURCE_APP_JWT_SIGN_FAILED',
  'SOURCE_INSTALLATION_TOKEN_CREATE_FAILED',
  'SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED',
  'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH',
  'SOURCE_REPOSITORY_IDENTITY_MISMATCH',
  'SOURCE_REPOSITORY_READ_FAILED',
  'SOURCE_RUN_IDENTITY_MISMATCH',
  'SOURCE_RUN_READ_FAILED',
  'SOURCE_WORKFLOW_IDENTITY_MISMATCH',
  'SOURCE_WORKFLOW_READ_FAILED',
  'PRODUCTION_HANDOFF_EXTRA_ARTIFACT',
  'PRODUCTION_RELEASE_SET_MISMATCH',
  'PRODUCTION_TEST_ONLY_SET_MISMATCH',
]);
const SAFE_LIVE_READBACK_DIAGNOSTIC_CODES = new Set([
  'APPWRITE_TEST_CREDENTIAL_INVALID',
  'APPWRITE_TEST_FUNCTION_READBACK_INVALID',
  'APPWRITE_TEST_IDENTITY_READBACK_INVALID',
  'APPWRITE_TEST_LEASE_READBACK_INVALID',
  'APPWRITE_TEST_LIVE_READBACK_INPUT_INVALID',
  'APPWRITE_TEST_LIVE_READBACK_INVALID',
  'APPWRITE_TEST_RESPONSE_INVALID',
  'APPWRITE_TEST_ROUTE_INVALID',
  'APPWRITE_TEST_RUNNER_CONFIGURATION_INVALID',
  'APPWRITE_TEST_RUNNER_VARIABLE_READBACK_INVALID',
  'APPWRITE_TEST_SITE_READBACK_INVALID',
]);
for (const routeClass of ['FUNCTION', 'IDENTITY', 'LEASE', 'RUNNER_VARIABLE', 'SITE']) {
  for (const failureClass of [
    'BODY_INVALID',
    'CONTENT_LENGTH_INVALID',
    'CONTENT_TYPE_INVALID',
    'CONTRACT_INVALID',
    'FETCH_INVALID',
    'JSON_INVALID',
    'REDIRECT_INVALID',
    'SECRET_REFLECTION_INVALID',
    'STATUS_INVALID',
  ]) {
    SAFE_LIVE_READBACK_DIAGNOSTIC_CODES.add(
      `APPWRITE_TEST_${routeClass}_RESPONSE_${failureClass}`,
    );
  }
}

function sha256Text(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.getOwnPropertySymbols(value).length === 0;
}

function exactObject(value, keys) {
  if (!isPlainObject(value)) return null;
  const names = Object.keys(value).sort();
  const expected = [...keys].sort();
  return names.length === expected.length
    && names.every((name, index) => name === expected[index]) ? value : null;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function blocked(code) {
  return deepFreeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code,
      retryable: false,
      safeMessage: 'The protected Appwrite Test readback artifact could not be produced.',
    }],
  });
}

function pass(value = null) {
  return deepFreeze({ status: 'PASS', value, diagnostics: [] });
}

function validInput(value) {
  const input = exactObject(value, INPUT_KEYS);
  const sourceReader = input === null ? null : exactObject(input.sourceReader, SOURCE_READER_KEYS);
  if (
    input === null
    || sourceReader === null
    || !SHA.test(input.controllerRevision ?? '')
    || !SHA.test(input.sourceRepositoryRevision ?? '')
    || !SHA.test(input.runnerRevision ?? '')
    || new Set([
      input.controllerRevision, input.sourceRepositoryRevision, input.runnerRevision,
    ]).size !== 3
    || !/^[1-9][0-9]{0,19}$/u.test(input.sourceRunId ?? '')
    || !Number.isSafeInteger(input.sourceRunAttempt)
    || input.sourceRunAttempt < 1
    || typeof input.initialSeed !== 'boolean'
    || !/^[1-9][0-9]*$/u.test(String(sourceReader.appId))
    || !/^[1-9][0-9]*$/u.test(String(sourceReader.installationId))
    || !Number.isSafeInteger(sourceReader.sourceRepositoryId)
    || !Number.isSafeInteger(sourceReader.sourceWorkflowId)
  ) return null;
  if (
    (input.initialSeed && input.controllerArtifact !== null)
    || (!input.initialSeed && (
      exactObject(input.controllerArtifact, ['artifactId', 'digest']) === null
      || !SAFE_ID.test(input.controllerArtifact.artifactId ?? '')
      || !DIGEST.test(input.controllerArtifact.digest ?? '')
    ))
  ) return null;
  return input;
}

function readEnvironment(environment) {
  if (environment === null || typeof environment !== 'object' || utilTypes.isProxy(environment)) {
    return null;
  }
  const values = {};
  for (const name of ENVIRONMENT_NAMES) {
    const descriptor = Object.getOwnPropertyDescriptor(environment, name);
    const value = descriptor?.value;
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || typeof value !== 'string'
      || value.length < 1
      || Buffer.byteLength(value, 'utf8') > 16_384
    ) return null;
    values[name] = value;
  }
  return values;
}

function sourceArtifactDownloadFailure() {
  const error = new Error('The source artifact download failed its closed transport contract.');
  error.code = 'SOURCE_ARTIFACT_DOWNLOAD_FAILED';
  return error;
}

function trustedArtifactRedirect(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 8192) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:'
      || url.username !== ''
      || url.password !== ''
      || url.port !== ''
      || url.hash !== ''
      || url.search.length < 2
      || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.blob\.core\.windows\.net$/u
        .test(url.hostname)
    ) return null;
    return url.href;
  } catch {
    return null;
  }
}

export async function githubSourceRequest(fetchImpl, requestPath, options = {}) {
  if (typeof fetchImpl !== 'function' || typeof requestPath !== 'string') {
    throw new TypeError('GitHub source request is invalid.');
  }
  if (Number.isSafeInteger(options.expectedBytes)) {
    try {
      let response = await fetchImpl(`https://api.github.com${requestPath}`, {
        method: options.method,
        headers: options.headers,
        body: options.body,
        redirect: 'manual',
      });
      if (response?.status === 302) {
        const location = typeof response.headers?.get === 'function'
          ? response.headers.get('location')
          : null;
        const redirectUrl = trustedArtifactRedirect(location);
        if (redirectUrl === null) throw sourceArtifactDownloadFailure();
        response = await fetchImpl(redirectUrl, {
          method: 'GET',
          headers: { Accept: 'application/octet-stream' },
          redirect: 'error',
        });
      }
      return Object.freeze({
        status: response.status,
        bytes: await readBoundedSourceArtifactArchive(response, options.expectedBytes),
      });
    } catch (error) {
      if (error?.code === 'SOURCE_ARTIFACT_DOWNLOAD_FAILED') throw error;
      throw sourceArtifactDownloadFailure();
    }
  }
  const response = await fetchImpl(`https://api.github.com${requestPath}`, {
    method: options.method,
    headers: options.headers,
    body: options.body,
    redirect: options.redirect ?? 'error',
  });
  if (response.status === 204) return Object.freeze({ status: 204, body: null });
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength < 2 || bytes.byteLength > MAX_GITHUB_JSON_BYTES) {
    throw new TypeError('GitHub source response is outside the bounded JSON contract.');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return Object.freeze({ status: response.status, body: JSON.parse(text) });
}

function credential(value) {
  let handle;
  handle = Object.freeze({
    readSecret() {
      if (this !== handle) throw new TypeError('credential receiver');
      return value;
    },
  });
  return handle;
}

function materializeSiteArtifact(source) {
  if (
    !Array.isArray(source?.releaseEligibleArtifacts)
    || !(source?.files instanceof Map)
  ) throw new TypeError('source artifact');
  const matches = source.releaseEligibleArtifacts.filter((entry) => (
    entry?.kind === 'site'
    && entry.logicalTarget === 'web'
    && entry.relativePath === 'site/site.tar.gz'
  ));
  if (matches.length !== 1) throw new TypeError('source artifact');
  const descriptor = matches[0];
  const bytes = source.files.get(descriptor.relativePath);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== descriptor.sizeBytes) {
    throw new TypeError('source artifact');
  }
  return {
    releaseEligibleArtifacts: [{
      ...descriptor,
      bytes: new Uint8Array(bytes),
    }],
  };
}

const DEFAULT_DEPENDENCIES = Object.freeze({
  readSourceArtifactImpl: readSourceArtifact,
  projectRowsImpl: projectTestCloudBrowserArtifactPolicyRows,
  readLiveImpl: readAppwriteTestLiveProjection,
  createPolicyImpl: createAppwriteTestBrowserPolicy,
  createBindingsImpl: createAppwriteTestSetupBindings,
  githubRequestImpl: (requestPath, options) => githubSourceRequest(
    globalThis.fetch,
    requestPath,
    options,
  ),
  extractSourceArtifactZipImpl: extractSourceArtifactZip,
});

export async function collectAppwriteTestReadback(args) {
  try {
    const outer = exactObject(args, OUTER_KEYS);
    const input = outer === null ? null : validInput(outer.input);
    if (outer === null || input === null || !isPlainObject(outer.dependencies)) {
      return blocked('APPWRITE_TEST_COLLECT_INPUT_INVALID');
    }
    const environment = readEnvironment(outer.environment);
    if (environment === null) return blocked('APPWRITE_TEST_COLLECT_CREDENTIAL_INVALID');
    const dependencies = outer.dependencies;
    for (const name of [
      'readSourceArtifactImpl', 'projectRowsImpl', 'readLiveImpl', 'createPolicyImpl',
      'createBindingsImpl', 'githubRequestImpl', 'extractSourceArtifactZipImpl',
    ]) {
      if (typeof dependencies[name] !== 'function') {
        return blocked('APPWRITE_TEST_COLLECT_DEPENDENCY_INVALID');
      }
    }
    const source = await dependencies.readSourceArtifactImpl({
      config: input.sourceReader,
      revision: input.sourceRepositoryRevision,
      qualifyingRunId: input.sourceRunId,
      runAttempt: input.sourceRunAttempt,
      privateKey: environment.SOURCE_ARTIFACT_READER_PRIVATE_KEY,
      request: dependencies.githubRequestImpl,
      readZip: dependencies.extractSourceArtifactZipImpl,
    });
    const projected = await dependencies.projectRowsImpl({
      sourceArtifactSet: materializeSiteArtifact(source),
    });
    if (projected?.status !== 'PASS') return blocked('APPWRITE_TEST_SOURCE_POLICY_INVALID');
    const live = await dependencies.readLiveImpl({
      inventory,
      configuredEmails: {
        editor: environment.E2E_EDITOR_EMAIL,
        owner: environment.E2E_OWNER_EMAIL,
        viewer: environment.E2E_VIEWER_EMAIL,
      },
      operatorCredential: credential(environment.APPWRITE_TEST_OPERATOR_API_KEY),
      fixtureCredential: credential(environment.APPWRITE_TEST_FIXTURE_API_KEY),
      fetchImpl: globalThis.fetch,
      clock: Object.freeze({ nowEpochSeconds: () => Math.floor(Date.now() / 1000) }),
    });
    if (live?.status !== 'PASS') {
      const code = Array.isArray(live?.diagnostics)
        && live.diagnostics.length === 1
        && SAFE_LIVE_READBACK_DIAGNOSTIC_CODES.has(live.diagnostics[0]?.code)
        ? live.diagnostics[0].code
        : 'APPWRITE_TEST_LIVE_PROJECTION_INVALID';
      return blocked(code);
    }
    const policy = dependencies.createPolicyImpl({
      browserArtifactProjection: projected.value,
      environmentDigest: 'sha256:e83dac9cc615ccf37fd027683690edb2ff7332ac523d57130c1e86fa8617f302',
      providerContractDigest:
        'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8',
    });
    if (policy?.status !== 'PASS') return blocked('APPWRITE_TEST_BROWSER_POLICY_INVALID');
    const bindings = dependencies.createBindingsImpl({
      controllerRevision: input.controllerRevision,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      runnerRevision: input.runnerRevision,
      initialSeed: input.initialSeed,
      liveProjection: live.value,
      browserRequestPolicy: policy.value.browserRequestPolicy,
      nowEpochSeconds: Math.floor(Date.now() / 1000),
      controllerArtifact: input.controllerArtifact,
    });
    if (
      bindings?.status !== 'PASS'
      || exactObject(bindings.value?.bindings, BINDING_NAMES) === null
      || !isPlainObject(bindings.value?.evidence)
    ) return blocked('APPWRITE_TEST_BINDING_OUTPUT_INVALID');
    return pass({
      bindings: bindings.value.bindings,
      evidence: bindings.value.evidence,
    });
  } catch (error) {
    const code = error !== null && typeof error === 'object'
      && typeof error.code === 'string'
      && SAFE_SOURCE_READER_DIAGNOSTIC_CODES.has(error.code)
      ? error.code
      : 'APPWRITE_TEST_COLLECT_INVALID';
    return blocked(code);
  }
}

export async function runCollectAppwriteTestReadbackCli(
  argv = process.argv.slice(2),
  environment = process.env,
  dependencies = DEFAULT_DEPENDENCIES,
) {
  try {
    if (
      !Array.isArray(argv)
      || argv.length !== 4
      || argv[0] !== '--input'
      || argv[2] !== '--output'
      || typeof argv[1] !== 'string'
      || typeof argv[3] !== 'string'
    ) return blocked('APPWRITE_TEST_COLLECT_CLI_INVALID');
    const inputPath = path.resolve(argv[1]);
    const outputPath = path.resolve(argv[3]);
    const text = await readFile(inputPath, 'utf8');
    if (Buffer.byteLength(text, 'utf8') > 65_536 || !text.endsWith('\n')) {
      return blocked('APPWRITE_TEST_COLLECT_CLI_INVALID');
    }
    const canonical = text.slice(0, -1);
    const input = JSON.parse(canonical);
    if (canonicalJson(input) !== canonical) return blocked('APPWRITE_TEST_COLLECT_CLI_INVALID');
    const collected = await collectAppwriteTestReadback({ input, environment, dependencies });
    if (collected.status !== 'PASS') return collected;
    const outputFiles = new Map(BINDING_NAMES.map((name) => {
      const value = collected.value.bindings[name];
      if (typeof value !== 'string' || value.length < 1) {
        throw new TypeError('invalid binding');
      }
      return [`${name}.txt`, value];
    }));
    outputFiles.set('evidence.json', `${canonicalJson(collected.value.evidence)}\n`);
    const files = [...outputFiles]
      .map(([filePath, value]) => ({
        path: filePath,
        byteLength: Buffer.byteLength(value, 'utf8'),
        sha256: sha256Text(value),
      }))
      .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    const manifest = {
      schemaVersion: 'appwrite-test-binding-artifact-manifest.v1',
      controllerRevision: input.controllerRevision,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      runnerRevision: input.runnerRevision,
      initialSeed: input.initialSeed,
      controllerArtifact: input.controllerArtifact,
      files,
    };
    outputFiles.set('binding-manifest.json', `${canonicalJson(manifest)}\n`);
    await mkdir(outputPath, { recursive: false });
    for (const [filePath, value] of outputFiles) {
      await writeFile(path.join(outputPath, filePath), value, {
        encoding: 'utf8', flag: 'wx', mode: 0o600,
      });
    }
    return pass();
  } catch {
    return blocked('APPWRITE_TEST_COLLECT_CLI_INVALID');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outcome = await runCollectAppwriteTestReadbackCli();
  if (outcome.status !== 'PASS') {
    process.stderr.write(`BLOCKED ${outcome.diagnostics[0].code}\n`);
    process.exitCode = 1;
  }
}
