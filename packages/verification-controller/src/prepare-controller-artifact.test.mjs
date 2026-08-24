import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import path from 'node:path';
import test from 'node:test';
import { deflateRawSync } from 'node:zlib';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  produceControllerRunnerQualification,
  produceControllerTrustMaterials,
} from '../../../scripts/verification/controller-trust-materials.mjs';
import {
  evaluatorClosure,
  qualificationContext,
  setupBindings as canonicalSetupBindings,
} from '../../../scripts/verification/controller-trust-materials-test-helper.mjs';
import { main, prepareControllerArtifact } from './prepare-controller-artifact.mjs';

const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const SHA = 'a'.repeat(40);
const SOURCE_SHA = 'c'.repeat(40);
const ARTIFACT_ID = '123';
const ENTRYPOINT = 'packages/verification-controller/src/create-production-browser-policy.mjs';
const SCHEMA = 'dev/verification/schemas/production-browser-policy.v1.schema.json';
const MANIFEST_PATH = 'packages/verification-controller/controller-bundle.manifest.json';
const SIGNED_URL = 'https://productionresultssa0.blob.core.windows.net/actions-results/controller.zip?sig=test';
const NOW = Date.parse('2026-07-21T12:00:00.000Z');

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sourceProposal() {
  return {
    schemaVersion: 'controller-bundle.proposal.v2',
    proposalStatus: 'BLOCKED_UNMATERIALIZED',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: 'UNMATERIALIZED',
    controllerRepository: REPOSITORY,
    controllerRevision: 'UNMATERIALIZED',
    seedSourceSets: {
      schemaVersion: 'controller-seed-source-sets-reference.v1',
      path: 'packages/verification-controller/controller-seed-source-sets.v1.json',
      schemaPath: 'dev/verification/schemas/controller-seed-source-sets.v1.schema.json',
    },
    entrypoints: [{ path: ENTRYPOINT, sha256: 'UNMATERIALIZED' }],
    files: [{ path: ENTRYPOINT, sha256: 'UNMATERIALIZED' }],
    schemaDigests: [{ path: SCHEMA, sha256: 'UNMATERIALIZED' }],
    trustMaterials: [
      { kind: 'evaluator', path: 'trust/evaluator.v1.json', sha256: 'UNMATERIALIZED' },
      { kind: 'evidenceValidator', path: 'trust/evidence-validator.v1.json', sha256: 'UNMATERIALIZED' },
      { kind: 'networkPolicy', path: 'trust/network-policy.v1.json', sha256: 'UNMATERIALIZED' },
      { kind: 'transcriptCorpus', path: 'trust/transcript-corpus.v2.json', sha256: 'UNMATERIALIZED' },
    ],
    provenance: { path: 'trust/provenance.v1.json', sha256: 'UNMATERIALIZED' },
  };
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zip(entries) {
  const locals = [];
  const centrals = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = Buffer.from(entry.data ?? '', 'utf8');
    const compressed = deflateRawSync(data);
    const checksum = crc32(data);
    const flags = 0x0808;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(name.length, 26);
    const descriptor = Buffer.alloc(16);
    descriptor.writeUInt32LE(0x08074b50, 0);
    descriptor.writeUInt32LE(checksum, 4);
    descriptor.writeUInt32LE(compressed.length, 8);
    descriptor.writeUInt32LE(data.length, 12);
    locals.push(local, name, compressed, descriptor);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset += local.length + name.length + compressed.length + descriptor.length;
  }
  const localBytes = Buffer.concat(locals);
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  return Buffer.concat([localBytes, centralBytes, end]);
}

function jsonResponse(value) {
  const bytes = Buffer.from(JSON.stringify(value), 'utf8');
  return {
    status: 200,
    headers: new Headers({
      'content-length': String(bytes.length),
      'content-type': 'application/json',
    }),
    async arrayBuffer() {
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
}

function bytesResponse(bytes) {
  return {
    status: 200,
    headers: new Headers({ 'content-length': String(bytes.length) }),
    async arrayBuffer() {
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
}

function verifierFixture() {
  const entrypointBytes = Buffer.from('trusted entrypoint\n', 'utf8');
  const schemaBytes = Buffer.from('{}\n', 'utf8');
  const setupBindings = canonicalSetupBindings();
  const context = qualificationContext();
  const qualified = produceControllerRunnerQualification({
    workflowRunId: '987',
    workflowHeadSha: SHA,
    controllerRepository: REPOSITORY,
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: SOURCE_SHA,
    controllerRevision: SHA,
    runnerRevision: 'd'.repeat(40),
    runnerImage: 'windows-2025',
    setupBindings,
    jobObjectQualification: {
      schemaVersion: 'windows-job-object-qualification.v1',
      status: 'PASS',
      killOnJobClose: true,
      breakawayDisabled: true,
    },
  }, context).value;
  const qualificationBytes = Buffer.from(`${canonicalJson(qualified.qualification)}\n`, 'utf8');
  const producedTrust = produceControllerTrustMaterials({
    qualification: qualified.qualification,
    qualificationDigest: qualified.digest,
    setupBindings,
    evaluatorClosure: evaluatorClosure(),
    primaryExecutionRetentionMaxSeconds: 3600,
  }, { clock: context.clock }).value;
  const trustMaterials = Object.fromEntries(Object.entries(producedTrust.materials).map(
    ([kind, artifact]) => [kind, Buffer.from(artifact.bytes)],
  ));
  const provenanceBytes = Buffer.from(producedTrust.provenance.bytes);
  const manifest = {
    schemaVersion: 'controller-bundle.v2',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: SOURCE_SHA,
    controllerRepository: REPOSITORY,
    controllerRevision: SHA,
    entrypoints: [{ path: ENTRYPOINT, sha256: digestBytes(entrypointBytes) }],
    files: [{ path: ENTRYPOINT, sha256: digestBytes(entrypointBytes) }],
    schemaDigests: [{ path: SCHEMA, sha256: digestBytes(schemaBytes) }],
    trustMaterials: producedTrust.provenance.value.materials,
    provenance: { path: 'trust/provenance.v1.json', sha256: digestBytes(provenanceBytes) },
  };
  const entries = [
    { name: MANIFEST_PATH, data: Buffer.from(`${canonicalJson(manifest)}\n`, 'utf8') },
    { name: ENTRYPOINT, data: entrypointBytes },
    { name: SCHEMA, data: schemaBytes },
    ...manifest.trustMaterials.map(({ kind, path: trustPath }) => ({
      name: trustPath,
      data: trustMaterials[kind],
    })),
    { name: 'trust/provenance.v1.json', data: provenanceBytes },
    { name: 'trust/controller-runner-qualification.v1.json', data: qualificationBytes },
  ];
  const archive = zip(entries);
  const bundleDigest = digestBytes(archive);
  const metadata = {
    id: Number(ARTIFACT_ID),
    name: `verification-controller-bundle-${SHA}`,
    expired: false,
    expires_at: '2026-07-22T12:00:00.000Z',
    size_in_bytes: archive.length,
    digest: bundleDigest,
    archive_download_url: `https://api.github.com/repos/${REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/zip`,
    workflow_run: { id: 987, head_sha: SHA },
  };
  const localFiles = new Map(entries.map(({ name, data }) => [name, Buffer.from(data)]));
  const root = path.resolve('trusted-controller-fixture');
  const calls = [];
  const fetchImpl = async (rawUrl, init) => {
    const url = new URL(rawUrl);
    calls.push(Object.freeze({
      authorization: init?.headers?.Authorization ?? null,
      redirect: init?.redirect,
      url: url.toString(),
    }));
    if (url.hostname === 'api.github.com' && url.pathname.endsWith(`/artifacts/${ARTIFACT_ID}`)) {
      return jsonResponse(metadata);
    }
    if (url.hostname === 'api.github.com' && url.pathname.endsWith(`/artifacts/${ARTIFACT_ID}/zip`)) {
      return { status: 302, headers: new Headers({ location: SIGNED_URL }) };
    }
    if (url.hostname !== 'api.github.com') return bytesResponse(archive);
    throw new Error('unexpected fake route');
  };
  const git = Object.freeze({
    async readExactSource() {
      return Object.freeze({
        files: Object.freeze([
          Object.freeze({ path: SCHEMA, mode: '100644', bytes: new Uint8Array(schemaBytes) }),
          Object.freeze({ path: ENTRYPOINT, mode: '100644', bytes: new Uint8Array(entrypointBytes) }),
        ]),
      });
    },
  });
  const writes = [];
  const directories = [];
  const proposalPath = path.join(
    root,
    'packages/verification-controller/controller-bundle.proposal.json',
  );
  const lower = Object.freeze({
    createGit(input) {
      assert.deepEqual(input, { repositoryRoot: root });
      return git;
    },
    fetchImpl,
    async lstat(absolutePath) {
      return Object.freeze({
        isFile: () => localFiles.has(path.relative(root, absolutePath).replaceAll('\\', '/')),
        isSymbolicLink: () => false,
      });
    },
    async mkdir(...args) { directories.push(args); },
    now: () => NOW,
    async readFile(absolutePath) {
      if (absolutePath === proposalPath) return canonicalJson(sourceProposal());
      const relative = path.relative(root, absolutePath).replaceAll('\\', '/');
      const value = localFiles.get(relative);
      if (value === undefined) throw new Error('missing local file');
      return Buffer.from(value);
    },
    async realpath(value) { return value; },
    root,
    async writeFile(destination, bytes, options) {
      writes.push(Object.freeze({ destination, bytes: Buffer.from(bytes), options }));
    },
  });
  return Object.freeze({ archive, bundleDigest, calls, directories, entries, lower, writes });
}

function environment(bundleDigest, githubEnv = path.resolve('github-env')) {
  return Object.freeze({
    CONTROLLER_ARTIFACT_READ_TOKEN: 'github-bootstrap-token',
    GITHUB_ENV: githubEnv,
    GITHUB_REPOSITORY: REPOSITORY,
    REQUIRED_CONTROLLER_ENTRYPOINT: ENTRYPOINT,
    TRUSTED_CONTROLLER_ARTIFACT_ID: ARTIFACT_ID,
    TRUSTED_CONTROLLER_BUNDLE_DIGEST: bundleDigest,
    TRUSTED_CONTROLLER_SHA: SHA,
  });
}

function mainRuntime(fixture, appendFileSync) {
  return Object.freeze({
    appendFileSync,
    ...fixture.lower,
    environment: environment(fixture.bundleDigest),
  });
}

test('prepare public function verifies and materializes the exact controller archive', async () => {
  const fixture = verifierFixture();
  const outputDirectory = path.resolve('controller-artifact-direct');
  const prepared = await prepareControllerArtifact(Object.freeze({
    artifactId: ARTIFACT_ID,
    authorization: 'github-bootstrap-token',
    bundleDigest: fixture.bundleDigest,
    outputDirectory,
    repository: REPOSITORY,
    requiredEntrypoint: ENTRYPOINT,
    sha: SHA,
  }), fixture.lower);
  assert.deepEqual(prepared, {
    artifactId: ARTIFACT_ID,
    bundleDigest: fixture.bundleDigest,
    repository: REPOSITORY,
    sha: SHA,
  });
  assert.equal(fixture.calls.length, 5);
  assert.deepEqual(fixture.calls.map(({ redirect }) => redirect), [
    'error', 'manual', 'error', 'manual', 'error',
  ]);
  assert.deepEqual(fixture.calls.map(({ authorization }) => authorization), [
    'Bearer github-bootstrap-token',
    'Bearer github-bootstrap-token',
    null,
    'Bearer github-bootstrap-token',
    null,
  ]);
  assert.deepEqual(fixture.writes.map(({ options }) => options),
    fixture.writes.map(() => ({ flag: 'wx', mode: 0o600 })));
  assert.equal(fixture.writes.length, fixture.entries.length);
  assert.deepEqual(fixture.writes.map(({ destination }) => destination),
    [...fixture.entries].map(({ name }) => path.resolve(outputDirectory, ...name.split('/'))).sort());
});

test('prepare CLI emits proof only after the real verifier and all writes complete', async () => {
  const fixture = verifierFixture();
  const output = path.resolve('controller-artifact-test');
  const appended = [];
  const exitCode = await main(Object.freeze(['--output', output]), mainRuntime(
    fixture,
    (destination, value, encoding) => appended.push({ destination, value, encoding }),
  ));
  assert.equal(exitCode, 0);
  assert.equal(fixture.writes.length, fixture.entries.length);
  assert.deepEqual(appended.map(({ destination, encoding }) => [destination, encoding]), [
    [path.resolve('github-env'), 'utf8'],
  ]);
  assert.match(appended[0].value, /^PROOF_STATUS=PASS$/mu);
  assert.match(appended[0].value, /^PROOF_ARTIFACT_ID=123$/mu);
  assert.match(appended[0].value, new RegExp(`^PROOF_BUNDLE_DIGEST=${fixture.bundleDigest}$`, 'mu'));
  assert.doesNotMatch(appended[0].value, /github-bootstrap-token/u);
});

test('prepare rejects fake replacement and hostile runtime without invoking caller code', async () => {
  let getterCalls = 0;
  const runtime = {};
  Object.defineProperty(runtime, 'prepare', {
    enumerable: true,
    get() { getterCalls += 1; return async () => Object.freeze({}); },
  });
  assert.equal(await main(Object.freeze(['--output', path.resolve('out')]), runtime), 2);
  assert.equal(getterCalls, 0);
  const proxy = new Proxy({}, {
    ownKeys() { getterCalls += 1; throw new Error('proxy trap'); },
    get() { getterCalls += 1; throw new Error('proxy trap'); },
  });
  assert.equal(await main(Object.freeze(['--output', path.resolve('out')]), proxy), 2);
  assert.equal(getterCalls, 0);
});

test('prepare rejects accessor, symbol, proxy-function, missing, and unknown runtime mutations', async () => {
  const output = path.resolve('controller-artifact-test');
  const fixture = verifierFixture();
  let getterCalls = 0;
  let appendCalls = 0;
  const base = mainRuntime(fixture, () => { appendCalls += 1; });
  const fetchAccessorDescriptors = Object.getOwnPropertyDescriptors(base);
  fetchAccessorDescriptors.fetchImpl = {
    configurable: true,
    enumerable: true,
    get() { getterCalls += 1; throw new Error('unexpected getter'); },
  };
  const environmentAccessor = {};
  for (const [key, value] of Object.entries(base.environment)) {
    Object.defineProperty(environmentAccessor, key, key === 'CONTROLLER_ARTIFACT_READ_TOKEN'
      ? { enumerable: true, get() { getterCalls += 1; throw new Error('unexpected getter'); } }
      : { enumerable: true, value });
  }
  const withSymbol = { ...base };
  Object.defineProperty(withSymbol, Symbol('hostile'), { enumerable: true, value: true });
  const proxyFetch = new Proxy(base.fetchImpl, {
    apply() { throw new Error('unexpected proxy call'); },
  });
  const { writeFile: _missingWriteFile, ...missingWriteFile } = base;
  const cases = [
    Object.defineProperties({}, fetchAccessorDescriptors),
    { ...base, environment: environmentAccessor },
    { ...base, fetchImpl: proxyFetch },
    missingWriteFile,
    { ...base, prepare: async () => Object.freeze({}) },
    withSymbol,
  ];
  for (const runtime of cases) {
    assert.equal(await main(Object.freeze(['--output', output]), runtime), 2);
  }
  assert.equal(getterCalls, 0);
  assert.equal(appendCalls, 0);
  assert.equal(fixture.calls.length, 0);
  assert.equal(fixture.writes.length, 0);
});

test('prepare reaches the verifier input path and fails closed before network on invalid proposal', async () => {
  let collaboratorCalls = 0;
  const root = path.resolve('invalid-controller-fixture');
  const runtime = Object.freeze({
    createGit() { collaboratorCalls += 1; },
    async fetchImpl() { collaboratorCalls += 1; },
    async lstat() { collaboratorCalls += 1; },
    async mkdir() { collaboratorCalls += 1; },
    now() { collaboratorCalls += 1; return NOW; },
    async readFile() { return '{'; },
    async realpath() { collaboratorCalls += 1; },
    root,
    async writeFile() { collaboratorCalls += 1; },
  });
  await assert.rejects(prepareControllerArtifact(Object.freeze({
    artifactId: ARTIFACT_ID,
    authorization: 'token',
    bundleDigest: `sha256:${'b'.repeat(64)}`,
    outputDirectory: path.resolve('controller-artifact-test'),
    repository: REPOSITORY,
    requiredEntrypoint: ENTRYPOINT,
    sha: SHA,
  }), runtime), SyntaxError);
  assert.equal(collaboratorCalls, 0);
});

test('prepare CLI rejects malformed argv before inspecting hostile runtime', async () => {
  let called = false;
  const runtime = new Proxy({}, {
    get() { called = true; throw new Error('runtime touched'); },
    ownKeys() { called = true; throw new Error('runtime touched'); },
  });
  assert.equal(await main([], runtime), 2);
  assert.equal(called, false);
});
