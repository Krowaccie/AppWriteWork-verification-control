import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

import {
  issueTrustedControllerContextForArtifactVerifier,
  validateControllerBundleManifest,
} from '../../../scripts/verification/controller-bundle.mjs';
import {
  MAX_VERIFICATION_ARCHIVE_BYTES,
  extractBoundedZipArchive,
  readBoundedResponseBytes,
} from './controller-archive-verifier.mjs';
import {
  readControllerSourceAtExactSha,
} from './exact-sha-controller-source.mjs';
import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  TRUST_MATERIAL_PATHS,
  validatePublishedControllerTrustArtifacts,
} from '../../../scripts/verification/controller-trust-materials.mjs';

const API_ORIGIN = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const MANIFEST_PATH = 'packages/verification-controller/controller-bundle.manifest.json';
const REMOTE_KEYS = [
  'artifactId', 'authorization', 'bundleDigest', 'repository',
  'requiredEntrypoint', 'runtimeSha', 'trustedSha',
].sort();
const LOCAL_KEYS = [
  'artifactId', 'bundleDigest', 'proofRepository', 'proofSha', 'proofStatus',
  'repository', 'requiredEntrypoint', 'runtimeSha', 'trustedArtifactId',
  'trustedBundleDigest', 'trustedSha',
].sort();
const REMOTE_DEPENDENCY_KEYS = [
  'fetchImpl', 'git', 'lstat', 'now', 'proposal', 'readFile', 'realpath', 'root',
].sort();
const LOCAL_DEPENDENCY_KEYS = ['lstat', 'readFile', 'realpath', 'root'].sort();
const ID = /^[1-9][0-9]*$/;
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const WINDOWS_RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu;
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_SNAPSHOT_NODES = 2048;
const MAX_SNAPSHOT_ARRAY_LENGTH = 512;
const MAX_SNAPSHOT_KEYS = 32;
const MAX_SNAPSHOT_STRING_BYTES = 1024 * 1024;
const INVALID_SNAPSHOT = Symbol('INVALID_SNAPSHOT');

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function closedResult(status, value, code = null) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null ? [] : [{
      code,
      safeMessage: 'A materialized trusted controller artifact is required.',
      retryable: false,
    }],
  });
}

function blockedResult() {
  return closedResult('BLOCKED', null, 'TRUSTED_CONTROLLER_REQUIRED');
}

function snapshotExactObject(value, keys) {
  try {
    if (
      utilTypes.isProxy(value)
      || value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return null;
    const names = Object.getOwnPropertyNames(value).sort();
    const expected = [...keys].sort();
    if (
      names.length !== expected.length
      || names.some((name, index) => name !== expected[index])
    ) return null;
    const snapshot = {};
    for (const name of expected) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return null;
      snapshot[name] = descriptor.value;
    }
    return Object.freeze(snapshot);
  } catch {
    return null;
  }
}

function exactObject(value, keys) {
  return snapshotExactObject(value, keys) !== null;
}

function snapshotStringRecord(value, keys) {
  const snapshot = snapshotExactObject(value, keys);
  return snapshot !== null
    && Object.values(snapshot).every((field) => typeof field === 'string')
    ? snapshot
    : null;
}

function snapshotClosedData(value, state = { nodes: 0, stringBytes: 0 }, depth = 0) {
  try {
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      state.stringBytes += Buffer.byteLength(value, 'utf8');
      return state.stringBytes <= MAX_SNAPSHOT_STRING_BYTES ? value : INVALID_SNAPSHOT;
    }
    if (typeof value === 'number') {
      return Number.isFinite(value) ? value : INVALID_SNAPSHOT;
    }
    if (
      typeof value !== 'object'
      || utilTypes.isProxy(value)
      || depth > 4
      || ++state.nodes > MAX_SNAPSHOT_NODES
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return INVALID_SNAPSHOT;

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return INVALID_SNAPSHOT;
      const length = Object.getOwnPropertyDescriptor(value, 'length');
      if (
        !Object.hasOwn(length ?? {}, 'value')
        || length.value > MAX_SNAPSHOT_ARRAY_LENGTH
      ) return INVALID_SNAPSHOT;
      const names = Object.getOwnPropertyNames(value);
      if (names.length !== length.value + 1 || !names.includes('length')) {
        return INVALID_SNAPSHOT;
      }
      const snapshot = new Array(length.value);
      for (let index = 0; index < length.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
          return INVALID_SNAPSHOT;
        }
        const child = snapshotClosedData(descriptor.value, state, depth + 1);
        if (child === INVALID_SNAPSHOT) return INVALID_SNAPSHOT;
        snapshot[index] = child;
      }
      return Object.freeze(snapshot);
    }

    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      return INVALID_SNAPSHOT;
    }
    const names = Object.getOwnPropertyNames(value).sort();
    if (names.length > MAX_SNAPSHOT_KEYS) return INVALID_SNAPSHOT;
    const snapshot = Object.create(null);
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
        return INVALID_SNAPSHOT;
      }
      const child = snapshotClosedData(descriptor.value, state, depth + 1);
      if (child === INVALID_SNAPSHOT) return INVALID_SNAPSHOT;
      snapshot[name] = child;
    }
    return Object.freeze(snapshot);
  } catch {
    return INVALID_SNAPSHOT;
  }
}

function validCapability(value) {
  return typeof value === 'function' && !utilTypes.isProxy(value);
}

function validPath(value) {
  return typeof value === 'string'
    && SAFE_PATH.test(value)
    && value.split('/').every((segment) => (
      !segment.endsWith('.')
      && !segment.endsWith(' ')
      && !WINDOWS_RESERVED.test(segment)
    ));
}

function validAuthorization(value) {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 4096
    && !/[\u0000-\u001f\u007f]/u.test(value)
    && !/^Bearer\s/iu.test(value);
}

function digestBytes(bytes) {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex');
}

function providerId(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value > 0 ? String(value) : null;
  }
  return typeof value === 'string' && ID.test(value) ? value : null;
}

function ownData(value, key) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value')
    ? descriptor.value
    : undefined;
}

function responseHeader(response, name) {
  if (typeof response?.headers?.get === 'function') return response.headers.get(name);
  if (response?.headers && typeof response.headers === 'object') {
    const key = Object.keys(response.headers)
      .find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key === undefined ? null : response.headers[key];
  }
  return null;
}

async function readJson(response) {
  if (response?.status !== 200) throw new Error('provider response rejected');
  const contentType = responseHeader(response, 'content-type');
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|$)/iu.test(contentType)) {
    throw new Error('provider content type rejected');
  }
  const bytes = await readBoundedResponseBytes(response, MAX_JSON_BYTES);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function githubHeaders(authorization) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: 'Bearer ' + authorization,
    'User-Agent': 'appwritework-verification-controller',
    'X-GitHub-Api-Version': API_VERSION,
  };
}

function artifactUrl(artifactId) {
  return API_ORIGIN + '/repos/' + CONTROLLER_REPOSITORY
    + '/actions/artifacts/' + artifactId + '/zip';
}

function validMetadata(metadata, input, now) {
  const workflowRun = ownData(metadata, 'workflow_run');
  const expiresAt = ownData(metadata, 'expires_at');
  return providerId(ownData(metadata, 'id')) === input.artifactId
    && ownData(metadata, 'name') === 'verification-controller-bundle-' + input.trustedSha
    && ownData(metadata, 'expired') === false
    && typeof expiresAt === 'string'
    && UTC_TIMESTAMP.test(expiresAt)
    && Number.isFinite(Date.parse(expiresAt))
    && Date.parse(expiresAt) > now
    && Number.isSafeInteger(ownData(metadata, 'size_in_bytes'))
    && ownData(metadata, 'size_in_bytes') >= 22
    && ownData(metadata, 'size_in_bytes') <= MAX_VERIFICATION_ARCHIVE_BYTES
    && ownData(metadata, 'digest') === input.bundleDigest
    && ownData(metadata, 'archive_download_url') === artifactUrl(input.artifactId)
    && providerId(ownData(workflowRun, 'id')) !== null
    && ownData(workflowRun, 'head_sha') === input.trustedSha;
}

function signedArtifactUrl(value) {
  try {
    const url = new URL(value);
    const hostname = url.hostname.toLowerCase();
    const allowed = hostname === 'objects.githubusercontent.com'
      || hostname.endsWith('.githubusercontent.com')
      || hostname.endsWith('.blob.core.windows.net');
    return url.protocol === 'https:'
      && allowed
      && url.username === ''
      && url.password === ''
      && (url.port === '' || url.port === '443')
      && url.pathname.startsWith('/')
      && url.pathname.length > 1
      && url.hash === ''
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

function rootFile(rootPath, relativePath) {
  const absolutePath = path.resolve(rootPath, relativePath);
  return absolutePath !== rootPath && absolutePath.startsWith(rootPath + path.sep)
    ? absolutePath
    : null;
}

async function authenticRegularFile(absolutePath, deps) {
  const metadata = await deps.lstat(absolutePath);
  return metadata?.isFile?.() === true
    && metadata.isSymbolicLink?.() === false
    && await deps.realpath(absolutePath) === absolutePath;
}

function defaultRemoteDependencies() {
  return {
    fetchImpl: globalThis.fetch,
    git: null,
    lstat,
    now: Date.now,
    proposal: null,
    readFile,
    realpath,
    root: process.cwd(),
  };
}

function defaultLocalDependencies() {
  return { lstat, readFile, realpath, root: process.cwd() };
}

function remoteDependencies(overrides) {
  const candidate = overrides === undefined ? defaultRemoteDependencies() : overrides;
  const snapshot = snapshotExactObject(candidate, REMOTE_DEPENDENCY_KEYS);
  if (snapshot === null) return null;
  const proposal = snapshotClosedData(snapshot.proposal);
  return proposal === INVALID_SNAPSHOT
    ? null
    : Object.freeze({ ...snapshot, proposal });
}

function localDependencies(overrides) {
  const candidate = overrides === undefined ? defaultLocalDependencies() : overrides;
  const local = snapshotExactObject(candidate, LOCAL_DEPENDENCY_KEYS);
  if (local !== null) return local;
  const remote = snapshotExactObject(candidate, REMOTE_DEPENDENCY_KEYS);
  return remote === null
    ? null
    : Object.freeze({
      lstat: remote.lstat,
      readFile: remote.readFile,
      realpath: remote.realpath,
      root: remote.root,
    });
}

async function verifyCheckout(input, archiveEntries, deps) {
  const rootPath = path.resolve(deps.root);
  if (await deps.realpath(rootPath) !== rootPath) throw new Error('unsafe root');
  const absoluteManifest = rootFile(rootPath, MANIFEST_PATH);
  if (absoluteManifest === null || !await authenticRegularFile(absoluteManifest, deps)) {
    throw new Error('manifest unavailable');
  }
  const manifestBytes = Buffer.from(await deps.readFile(absoluteManifest));
  if (archiveEntries !== null) {
    const artifactManifest = archiveEntries.get(MANIFEST_PATH);
    if (artifactManifest === undefined || !manifestBytes.equals(artifactManifest)) {
      throw new Error('manifest mismatch');
    }
  }
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
  const validated = validateControllerBundleManifest(parsed);
  if (
    validated.status !== 'PASS'
    || validated.value.controllerRevision !== input.trustedSha
    || !validated.value.entrypoints.some(({ path: entryPath }) => (
      entryPath === input.requiredEntrypoint
    ))
  ) throw new Error('manifest invalid');

  const records = [...validated.value.files, ...validated.value.schemaDigests];
  const expectedPaths = new Set([MANIFEST_PATH, ...records.map(({ path: recordPath }) => recordPath)]);
  if (archiveEntries !== null) {
    if (archiveEntries.size !== expectedPaths.size) throw new Error('archive set mismatch');
    for (const entryPath of archiveEntries.keys()) {
      if (!expectedPaths.has(entryPath)) throw new Error('archive extra');
    }
  }
  for (const record of records) {
    const absolutePath = rootFile(rootPath, record.path);
    if (absolutePath === null || !await authenticRegularFile(absolutePath, deps)) {
      throw new Error('file unavailable');
    }
    const localBytes = Buffer.from(await deps.readFile(absolutePath));
    if (digestBytes(localBytes) !== record.sha256) throw new Error('local digest');
    if (archiveEntries !== null) {
      const artifactBytes = archiveEntries.get(record.path);
      if (
        artifactBytes === undefined
        || digestBytes(artifactBytes) !== record.sha256
        || !localBytes.equals(artifactBytes)
      ) throw new Error('artifact bytes');
    }
  }
  return validated.value;
}

function validExactSourceResult(candidate, input) {
  return exactObject(candidate, ['diagnostics', 'status', 'value'])
    && candidate.status === 'PASS'
    && Array.isArray(candidate.diagnostics)
    && candidate.diagnostics.length === 0
    && exactObject(candidate.value, ['controllerRepository', 'controllerRevision', 'files'])
    && candidate.value.controllerRepository === CONTROLLER_REPOSITORY
    && candidate.value.controllerRevision === input.trustedSha
    && Array.isArray(candidate.value.files);
}

function parseCanonicalJsonMember(archiveEntries, memberPath) {
  const bytes = archiveEntries.get(memberPath);
  if (bytes === undefined) throw new Error('archive member unavailable');
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!Buffer.from(`${canonicalJson(value)}\n`, 'utf8').equals(bytes)) {
    throw new Error('archive member is not canonical');
  }
  return value;
}

function verifyArchiveAgainstExactSource(input, archiveEntries, proposal, exactSource) {
  const manifestBytes = archiveEntries.get(MANIFEST_PATH);
  if (manifestBytes === undefined) throw new Error('manifest unavailable');
  const manifest = parseCanonicalJsonMember(archiveEntries, MANIFEST_PATH);
  const validated = validateControllerBundleManifest(manifest);
  if (
    validated.status !== 'PASS'
    || manifest.controllerRevision !== input.trustedSha
    || !manifest.entrypoints.some(({ path: entryPath }) => (
      entryPath === input.requiredEntrypoint
    ))
  ) throw new Error('manifest invalid');

  const records = [...manifest.files, ...manifest.schemaDigests]
    .sort((left, right) => (
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0
    ));
  const generatedPaths = [
    TRUST_MATERIAL_PATHS.evaluator,
    TRUST_MATERIAL_PATHS.evidenceValidator,
    TRUST_MATERIAL_PATHS.networkPolicy,
    TRUST_MATERIAL_PATHS.transcriptCorpus,
    TRUST_MATERIAL_PATHS.provenance,
    TRUST_MATERIAL_PATHS.qualification,
  ];
  const expectedPaths = new Set([
    MANIFEST_PATH,
    ...records.map(({ path: recordPath }) => recordPath),
    ...generatedPaths,
  ]);
  if (
    exactSource.files.length !== records.length
    || archiveEntries.size !== expectedPaths.size
  ) throw new Error('archive set mismatch');
  for (const entryPath of archiveEntries.keys()) {
    if (!expectedPaths.has(entryPath)) throw new Error('archive extra');
  }

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const sourceRecord = exactSource.files[index];
    const artifactBytes = archiveEntries.get(record.path);
    if (
      !exactObject(sourceRecord, ['bytes', 'mode', 'path', 'sha256'])
      || sourceRecord.path !== record.path
      || !['100644', '100755'].includes(sourceRecord.mode)
      || sourceRecord.sha256 !== record.sha256
      || artifactBytes === undefined
      || digestBytes(artifactBytes) !== record.sha256
      || !Buffer.from(sourceRecord.bytes).equals(artifactBytes)
    ) throw new Error('exact source mismatch');
  }

  const materialValues = {};
  for (const trustRecord of manifest.trustMaterials) {
    const expectedPath = TRUST_MATERIAL_PATHS[trustRecord.kind];
    const artifactBytes = archiveEntries.get(expectedPath);
    if (
      trustRecord.path !== expectedPath
      || artifactBytes === undefined
      || digestBytes(artifactBytes) !== trustRecord.sha256
    ) throw new Error('trust material mismatch');
    materialValues[trustRecord.kind] = parseCanonicalJsonMember(archiveEntries, expectedPath);
  }
  const provenanceBytes = archiveEntries.get(TRUST_MATERIAL_PATHS.provenance);
  if (provenanceBytes === undefined || digestBytes(provenanceBytes) !== manifest.provenance.sha256) {
    throw new Error('provenance digest mismatch');
  }
  const provenance = parseCanonicalJsonMember(archiveEntries, TRUST_MATERIAL_PATHS.provenance);
  const qualification = parseCanonicalJsonMember(archiveEntries, TRUST_MATERIAL_PATHS.qualification);
  if (validatePublishedControllerTrustArtifacts({
    qualification,
    provenance,
    materials: materialValues,
  }).status !== 'PASS') throw new Error('trust artifact invalid');
  if (
    provenance.schemaVersion !== 'controller-trust-provenance.v1'
    || qualification.schemaVersion !== 'controller-runner-qualification.v1'
    || provenance.controllerRepository !== CONTROLLER_REPOSITORY
    || provenance.controllerRevision !== manifest.controllerRevision
    || provenance.sourceRepository !== manifest.sourceRepository
    || provenance.sourceRepositoryRevision !== manifest.sourceRepositoryRevision
    || provenance.workflowHeadSha !== manifest.controllerRevision
    || qualification.workflowRunId !== provenance.workflowRunId
    || qualification.workflowHeadSha !== provenance.workflowHeadSha
    || qualification.controllerRevision !== provenance.controllerRevision
    || qualification.sourceRepositoryRevision !== provenance.sourceRepositoryRevision
    || digestBytes(archiveEntries.get(TRUST_MATERIAL_PATHS.qualification)) !== provenance.qualificationDigest
    || canonicalJson(provenance.materials) !== canonicalJson(manifest.trustMaterials)
  ) throw new Error('provenance binding mismatch');
  return manifest;
}

function issueBoundContext(manifest, artifactId, bundleDigest) {
  return issueTrustedControllerContextForArtifactVerifier({
    manifest,
    controllerArtifactId: artifactId,
    controllerBundleDigest: bundleDigest,
  });
}

function validRemoteInput(input) {
  return exactObject(input, REMOTE_KEYS)
    && input.repository === CONTROLLER_REPOSITORY
    && SHA.test(input.runtimeSha ?? '')
    && input.runtimeSha === input.trustedSha
    && ID.test(input.artifactId ?? '')
    && DIGEST.test(input.bundleDigest ?? '')
    && validPath(input.requiredEntrypoint)
    && validAuthorization(input.authorization);
}

function validLocalInput(input) {
  return exactObject(input, LOCAL_KEYS)
    && input.proofStatus === 'PASS'
    && input.proofRepository === CONTROLLER_REPOSITORY
    && input.repository === input.proofRepository
    && input.proofSha === input.runtimeSha
    && input.runtimeSha === input.trustedSha
    && SHA.test(input.trustedSha ?? '')
    && input.artifactId === input.trustedArtifactId
    && ID.test(input.artifactId ?? '')
    && input.bundleDigest === input.trustedBundleDigest
    && DIGEST.test(input.bundleDigest ?? '')
    && validPath(input.requiredEntrypoint);
}

export async function verifyGithubControllerArtifact(input, dependencyOverrides) {
  try {
    const inputSnapshot = snapshotStringRecord(input, REMOTE_KEYS);
    const deps = remoteDependencies(dependencyOverrides);
    if (
      inputSnapshot === null
      || deps === null
      || !validRemoteInput(inputSnapshot)
      || !validCapability(deps.fetchImpl)
      || !exactObject(deps.git, ['readExactSource'])
      || Object.isFrozen(deps.git) !== true
      || !validCapability(deps.git.readExactSource)
      || !validCapability(deps.now)
      || typeof deps.root !== 'string'
      || !validCapability(deps.readFile)
      || !validCapability(deps.lstat)
      || !validCapability(deps.realpath)
    ) return blockedResult();

    input = inputSnapshot;
    const now = deps.now();
    if (!Number.isFinite(now)) throw new Error('invalid clock');
    const exactSource = await readControllerSourceAtExactSha({
      controllerRepository: CONTROLLER_REPOSITORY,
      controllerRevision: input.trustedSha,
      proposal: deps.proposal,
      git: deps.git,
    });
    if (!validExactSourceResult(exactSource, input)) throw new Error('exact source unavailable');

    const metadataResponse = await deps.fetchImpl(
      API_ORIGIN + '/repos/' + CONTROLLER_REPOSITORY
        + '/actions/artifacts/' + input.artifactId,
      { method: 'GET', redirect: 'error', headers: githubHeaders(input.authorization) },
    );
    const metadata = await readJson(metadataResponse);
    if (!validMetadata(metadata, input, now)) throw new Error('metadata mismatch');
    const redirectResponse = await deps.fetchImpl(artifactUrl(input.artifactId), {
      method: 'GET',
      redirect: 'manual',
      headers: githubHeaders(input.authorization),
    });
    if (redirectResponse?.status !== 302) throw new Error('redirect missing');
    const signedUrl = signedArtifactUrl(responseHeader(redirectResponse, 'location'));
    if (signedUrl === null) throw new Error('unsafe redirect');
    const archiveResponse = await deps.fetchImpl(signedUrl, {
      method: 'GET',
      redirect: 'error',
      headers: {
        Accept: 'application/octet-stream',
        'User-Agent': 'appwritework-verification-controller',
      },
    });
    if (archiveResponse?.status !== 200) throw new Error('download failed');
    const archive = await readBoundedResponseBytes(
      archiveResponse,
      MAX_VERIFICATION_ARCHIVE_BYTES,
    );
    if (
      archive.length !== ownData(metadata, 'size_in_bytes')
      || digestBytes(archive) !== input.bundleDigest
    ) throw new Error('archive digest mismatch');
    const manifest = verifyArchiveAgainstExactSource(
      input,
      extractBoundedZipArchive(archive),
      deps.proposal,
      exactSource.value,
    );
    const issued = issueBoundContext(manifest, input.artifactId, input.bundleDigest);
    return issued.status === 'PASS' ? closedResult('PASS', issued.value) : blockedResult();
  } catch {
    return blockedResult();
  }
}

export async function reattestLocalControllerArtifact(input, dependencyOverrides) {
  try {
    const inputSnapshot = snapshotStringRecord(input, LOCAL_KEYS);
    const deps = localDependencies(dependencyOverrides);
    if (
      inputSnapshot === null
      || deps === null
      || !validLocalInput(inputSnapshot)
      || typeof deps.root !== 'string'
      || !validCapability(deps.readFile)
      || !validCapability(deps.lstat)
      || !validCapability(deps.realpath)
    ) return blockedResult();
    input = inputSnapshot;
    const manifest = await verifyCheckout(input, null, deps);
    const issued = issueBoundContext(manifest, input.artifactId, input.bundleDigest);
    return issued.status === 'PASS' ? closedResult('PASS', issued.value) : blockedResult();
  } catch {
    return blockedResult();
  }
}
