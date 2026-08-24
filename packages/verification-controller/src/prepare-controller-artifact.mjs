import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isProxy } from 'node:util/types';

import {
  extractBoundedZipArchive,
  MAX_VERIFICATION_ARCHIVE_BYTES,
  readBoundedResponseBytes,
} from './controller-archive-verifier.mjs';
import { verifyGithubControllerArtifact } from './github-controller-artifact-verifier.mjs';
import { createProductionExactShaGitAdapter } from './production-exact-sha-git-adapter.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const POSITIVE_ID = /^[1-9][0-9]*$/u;
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const INPUT_KEYS = Object.freeze([
  'artifactId',
  'authorization',
  'bundleDigest',
  'outputDirectory',
  'repository',
  'requiredEntrypoint',
  'sha',
]);
const PREPARE_RUNTIME_KEYS = Object.freeze([
  'createGit',
  'fetchImpl',
  'lstat',
  'mkdir',
  'now',
  'readFile',
  'realpath',
  'root',
  'writeFile',
]);
const MAIN_RUNTIME_KEYS = Object.freeze([
  'appendFileSync',
  ...PREPARE_RUNTIME_KEYS,
  'environment',
].sort());
const ENVIRONMENT_KEYS = Object.freeze([
  'CONTROLLER_ARTIFACT_READ_TOKEN',
  'GITHUB_ENV',
  'GITHUB_REPOSITORY',
  'REQUIRED_CONTROLLER_ENTRYPOINT',
  'TRUSTED_CONTROLLER_ARTIFACT_ID',
  'TRUSTED_CONTROLLER_BUNDLE_DIGEST',
  'TRUSTED_CONTROLLER_SHA',
]);

function exactPlainDataObject(value, keys) {
  try {
    if (value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || isProxy(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    return ownKeys.length === keys.length
      && ownKeys.every((key) => typeof key === 'string'
        && keys.includes(key)
        && descriptors[key]?.enumerable === true
        && Object.hasOwn(descriptors[key], 'value'));
  } catch {
    return false;
  }
}

function dataValue(value, key) {
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

function safeFunction(value) {
  try {
    return typeof value === 'function' && !isProxy(value);
  } catch {
    return false;
  }
}

function snapshotDataObject(value, keys) {
  return Object.freeze(Object.fromEntries(keys.map((key) => [key, dataValue(value, key)])));
}

function defaultPrepareRuntime() {
  return Object.freeze({
    createGit: createProductionExactShaGitAdapter,
    fetchImpl: globalThis.fetch,
    lstat,
    mkdir,
    now: Date.now,
    readFile,
    realpath,
    root: path.resolve('.'),
    writeFile,
  });
}

function readPrepareRuntime(runtimeInput) {
  const runtime = runtimeInput === undefined ? defaultPrepareRuntime() : runtimeInput;
  if (!exactPlainDataObject(runtime, PREPARE_RUNTIME_KEYS)) return null;
  const snapshot = snapshotDataObject(runtime, PREPARE_RUNTIME_KEYS);
  if (!PREPARE_RUNTIME_KEYS.filter((key) => key !== 'root').every((key) => (
    safeFunction(snapshot[key])
  ))
    || typeof snapshot.root !== 'string'
    || !path.isAbsolute(snapshot.root)
    || path.resolve(snapshot.root) !== snapshot.root) return null;
  return snapshot;
}

function defaultMainRuntime() {
  const lower = defaultPrepareRuntime();
  return Object.freeze({
    appendFileSync,
    ...lower,
    environment: Object.freeze(Object.fromEntries(ENVIRONMENT_KEYS.map((key) => (
      [key, process.env[key]]
    )))),
  });
}

function readMainRuntime(runtimeInput) {
  const runtime = runtimeInput === undefined ? defaultMainRuntime() : runtimeInput;
  if (!exactPlainDataObject(runtime, MAIN_RUNTIME_KEYS)) return null;
  const snapshot = snapshotDataObject(runtime, MAIN_RUNTIME_KEYS);
  const lower = readPrepareRuntime(snapshotDataObject(snapshot, PREPARE_RUNTIME_KEYS));
  if (lower === null
    || !safeFunction(snapshot.appendFileSync)
    || !exactPlainDataObject(snapshot.environment, ENVIRONMENT_KEYS)) return null;
  const environment = snapshotDataObject(snapshot.environment, ENVIRONMENT_KEYS);
  if (typeof environment.GITHUB_ENV !== 'string'
    || !path.isAbsolute(environment.GITHUB_ENV)
    || path.resolve(environment.GITHUB_ENV) !== environment.GITHUB_ENV) return null;
  return Object.freeze({ appendFileSync: snapshot.appendFileSync, environment, lower });
}

function safeSignedUrl(rawLocation) {
  try {
    const candidate = new URL(rawLocation);
    const hostname = candidate.hostname.toLowerCase();
    if (candidate.protocol !== 'https:'
      || !(
        hostname === 'objects.githubusercontent.com'
        || hostname.endsWith('.githubusercontent.com')
        || hostname.endsWith('.blob.core.windows.net')
      )
      || candidate.username !== ''
      || candidate.password !== ''
      || (candidate.port !== '' && candidate.port !== '443')
      || !candidate.pathname.startsWith('/')
      || candidate.pathname.length < 2
      || candidate.hash !== '') return null;
    return candidate.toString();
  } catch {
    return null;
  }
}

function validInput(input) {
  return exactPlainDataObject(input, INPUT_KEYS)
    && dataValue(input, 'repository') === CONTROLLER_REPOSITORY
    && FULL_SHA.test(dataValue(input, 'sha') ?? '')
    && POSITIVE_ID.test(dataValue(input, 'artifactId') ?? '')
    && DIGEST.test(dataValue(input, 'bundleDigest') ?? '')
    && typeof dataValue(input, 'authorization') === 'string'
    && dataValue(input, 'authorization').length > 0
    && typeof dataValue(input, 'requiredEntrypoint') === 'string'
    && dataValue(input, 'requiredEntrypoint').length > 0
    && typeof dataValue(input, 'outputDirectory') === 'string'
    && path.isAbsolute(dataValue(input, 'outputDirectory'))
    && path.resolve(dataValue(input, 'outputDirectory')) === dataValue(input, 'outputDirectory');
}

export async function prepareControllerArtifact(input, runtimeInput) {
  if (!validInput(input)) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const runtime = readPrepareRuntime(runtimeInput);
  if (runtime === null) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const request = snapshotDataObject(input, INPUT_KEYS);
  const { root, fetchImpl } = runtime;
  const readSourceBytes = runtime.readFile;
  const proposal = JSON.parse(await readSourceBytes(
    path.join(root, 'packages/verification-controller/controller-bundle.proposal.json'),
    'utf8',
  ));
  const git = runtime.createGit({
    repositoryRoot: root,
  });
  const verified = await verifyGithubControllerArtifact(Object.freeze({
    artifactId: request.artifactId,
    authorization: request.authorization,
    bundleDigest: request.bundleDigest,
    repository: request.repository,
    requiredEntrypoint: request.requiredEntrypoint,
    runtimeSha: request.sha,
    trustedSha: request.sha,
  }), {
    fetchImpl,
    git,
    lstat: runtime.lstat,
    now: runtime.now,
    proposal,
    readFile: runtime.readFile,
    realpath: runtime.realpath,
    root,
  });
  if (verified.status !== 'PASS') throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');

  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${request.authorization}`,
    'User-Agent': 'appwritework-verification-controller',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const redirectResponse = await fetchImpl(
    `https://api.github.com/repos/${request.repository}/actions/artifacts/${request.artifactId}/zip`,
    { method: 'GET', redirect: 'manual', headers },
  );
  const signedUrl = redirectResponse.status === 302
    ? safeSignedUrl(redirectResponse.headers.get('location'))
    : null;
  if (signedUrl === null) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const archiveResponse = await fetchImpl(signedUrl, {
    method: 'GET',
    redirect: 'error',
    headers: {
      Accept: 'application/octet-stream',
      'User-Agent': 'appwritework-verification-controller',
    },
  });
  if (archiveResponse.status !== 200) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const archive = await readBoundedResponseBytes(
    archiveResponse,
    MAX_VERIFICATION_ARCHIVE_BYTES,
  );
  const archiveDigest = `sha256:${createHash('sha256').update(archive).digest('hex')}`;
  if (archiveDigest !== request.bundleDigest) {
    throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  }

  const outputRoot = request.outputDirectory;
  await runtime.mkdir(outputRoot);
  const entries = [...extractBoundedZipArchive(archive).entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  for (const [relativePath, bytes] of entries) {
    const destination = path.resolve(outputRoot, ...relativePath.split('/'));
    if (!destination.startsWith(`${outputRoot}${path.sep}`)) {
      throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
    }
    await runtime.mkdir(path.dirname(destination), { recursive: true });
    await runtime.writeFile(destination, bytes, { flag: 'wx', mode: 0o600 });
  }
  return Object.freeze({
    artifactId: verified.value.controllerArtifactId,
    bundleDigest: verified.value.controllerBundleDigest,
    repository: verified.value.controllerRepository,
    sha: verified.value.controllerBundleSha,
  });
}

function parseOutputArgs(argv) {
  try {
    if (!Array.isArray(argv) || isProxy(argv)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(argv);
    if (Reflect.ownKeys(descriptors).length !== 3
      || descriptors.length?.value !== 2
      || !['0', '1'].every((key) => descriptors[key]?.enumerable === true
        && Object.hasOwn(descriptors[key], 'value'))) return null;
    const first = descriptors[0].value;
    const second = descriptors[1].value;
    return first === '--output' && typeof second === 'string'
      ? Object.freeze({ outputDirectory: second })
      : null;
  } catch {
    return null;
  }
}

export async function main(argv = process.argv.slice(2), runtimeInput) {
  const parsed = parseOutputArgs(argv);
  if (parsed === null) return 2;
  const runtime = readMainRuntime(runtimeInput);
  if (runtime === null) return 2;
  const { environment } = runtime;
  try {
    const prepared = await prepareControllerArtifact(Object.freeze({
      artifactId: environment.TRUSTED_CONTROLLER_ARTIFACT_ID,
      authorization: environment.CONTROLLER_ARTIFACT_READ_TOKEN,
      bundleDigest: environment.TRUSTED_CONTROLLER_BUNDLE_DIGEST,
      outputDirectory: path.resolve(parsed.outputDirectory),
      repository: environment.GITHUB_REPOSITORY,
      requiredEntrypoint: environment.REQUIRED_CONTROLLER_ENTRYPOINT,
      sha: environment.TRUSTED_CONTROLLER_SHA,
    }), runtime.lower);
    runtime.appendFileSync(environment.GITHUB_ENV, [
      'PROOF_STATUS=PASS',
      `PROOF_REPOSITORY=${prepared.repository}`,
      `PROOF_SHA=${prepared.sha}`,
      `PROOF_ARTIFACT_ID=${prepared.artifactId}`,
      `PROOF_BUNDLE_DIGEST=${prepared.bundleDigest}`,
      '',
    ].join('\n'), 'utf8');
    return 0;
  } catch {
    return 2;
  }
}

if (process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
