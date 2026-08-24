import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { deflateRawSync } from 'node:zlib';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { createAppwriteTestSetupBindings } from './appwrite-test-setup-bindings.mjs';
import { extractBoundedZipArchive } from './controller-archive-verifier.mjs';
import {
  runTestCloudBindingArtifactVerifierCli,
  validateTestCloudBindingSet,
  verifyGithubTestCloudBindingArtifact,
} from './test-cloud-binding-artifact-verifier.mjs';

const CONTROLLER_SHA = '1'.repeat(40);
const SOURCE_SHA = '2'.repeat(40);
const RUNNER_SHA = '3'.repeat(40);
const ARTIFACT_ID = '123456';
const NOW_SECONDS = 1_800_000_000;
const SIGNED_URL = 'https://productionresultssa0.blob.core.windows.net/actions-results/bindings.zip?sig=test';
const ENVIRONMENT_DIGEST =
  'sha256:02560e84745ed7b577b334a3412885f6a547b2a22f164f4978b255d3b35c0044';
const PROVIDER_CONTRACT_DIGEST =
  'sha256:47a1d778ca8b8cea333b10574ffbc2db488fd711c12a1c40faf9da5235e27184';
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

function browserProfile(index) {
  if (index < 25) return {
    profileId: 'synthetic-immutable-asset',
    requestClass: index === 0 ? 'main-document' : 'build-asset',
    credentialCarrier: 'none', method: 'GET',
    lifecyclePhase: index <= 12 ? 'APPLICATION_NAVIGATION' : index <= 21 ? 'OWNER_LOGIN' : 'APPLICATION_READ',
    resourceType: index === 0 ? 'document' : index >= 22 ? 'fetch' : 'script',
  };
  const profiles = [
    'cors-preflight-owner-session-post', 'owner-session-create',
    'cors-preflight-appwrite-prefs-get', 'authenticated-appwrite-read',
    'cors-preflight-appwrite-multipart-post', 'cors-preflight-appwrite-json-post',
    'cors-preflight-appwrite-json-post', 'cors-preflight-appwrite-json-post',
    'cors-preflight-appwrite-json-patch', 'cors-preflight-appwrite-json-patch',
    'cors-preflight-appwrite-json-patch', 'cors-preflight-appwrite-function-json-post',
    'authenticated-appwrite-multipart-mutation', 'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-json-mutation', 'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation', 'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation', 'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-json-mutation', 'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-multipart-mutation', 'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation', 'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-multipart-mutation', 'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation', 'authenticated-appwrite-function-json-mutation',
    'authenticated-appwrite-function-json-mutation',
  ];
  const preflight = [25, 27, 29, 30, 31, 32, 33, 34, 35, 36].includes(index);
  if (preflight) return {
    profileId: profiles[index - 25], requestClass: 'cors-preflight', credentialCarrier: 'none',
    method: 'OPTIONS', lifecyclePhase: index <= 27 ? 'OWNER_LOGIN' : 'APPLICATION_MUTATION',
    resourceType: 'other',
  };
  if (index === 26) return {
    profileId: profiles[index - 25], requestClass: 'owner-session-create',
    credentialCarrier: 'raw-playwright-request-body-only', method: 'POST',
    lifecyclePhase: 'OWNER_LOGIN', resourceType: 'fetch',
  };
  if (index === 28) return {
    profileId: profiles[index - 25], requestClass: 'appwrite-read',
    credentialCarrier: 'browser-cookie-jar-only', method: 'GET',
    lifecyclePhase: 'OWNER_LOGIN', resourceType: 'fetch',
  };
  return {
    profileId: profiles[index - 25],
    requestClass: [37, 38, 44, 47, 51].includes(index)
      ? 'appwrite-multipart-mutation' : 'appwrite-json-mutation',
    credentialCarrier: 'browser-cookie-jar-only',
    method: [46, 49, 50].includes(index) ? 'PATCH' : 'POST',
    lifecyclePhase: 'APPLICATION_MUTATION', resourceType: 'fetch',
  };
}

function browserPolicy() {
  const rows = Array.from({ length: 56 }, (_, ordinal) => ({
    ...browserProfile(ordinal), exactCount: 1, expectedResponseStatus: 200,
    finalUrl: ordinal < 25
      ? `${inventory.environment.publicOrigin}/asset-${ordinal}`
      : `${inventory.environment.endpoint}/closed-route-${ordinal}`,
    ordinal, requestHeaderBindings: [], requestOpaqueHeaderRules: [],
    responseBodyDigest: ordinal < 25 ? digest(`asset-${ordinal}`) : null,
    responseByteLength: ordinal < 25 ? 1 : null,
    responseHeaderBindings: [],
    responseMimeEssence: ordinal < 25 ? 'application/octet-stream' : null,
    responseOpaqueHeaderRules: [],
  }));
  const withoutDigest = {
    schemaVersion: 'test-cloud.browser-request-policy.v1', timeoutMilliseconds: 5000, rows,
  };
  return { ...withoutDigest, digest: digest(canonicalJson(withoutDigest)) };
}

function liveProjection() {
  const identityBindingsDigest = digest('identity-bindings');
  const literals = {
    VERIFICATION_AUDIT_TABLE_ID: inventory.control.auditTableId,
    VERIFICATION_CONTROL_DATABASE_ID: inventory.control.databaseId,
    VERIFICATION_ENDPOINT_ORIGIN: inventory.environment.endpoint,
    VERIFICATION_ENVIRONMENT_CLASS: inventory.environmentClass,
    VERIFICATION_ENVIRONMENT_DIGEST: ENVIRONMENT_DIGEST,
    VERIFICATION_IDENTITY_BINDINGS_DIGEST: identityBindingsDigest,
    VERIFICATION_INTENT_TABLE_ID: inventory.control.intentTableId,
    VERIFICATION_LEASE_ROW_ID: inventory.control.leaseRowId,
    VERIFICATION_LEASE_TABLE_ID: inventory.control.leaseTableId,
    VERIFICATION_PRIMARY_DATABASE_ID: 'project',
    VERIFICATION_PROJECTS_TABLE_ID: 'projects',
    VERIFICATION_PROJECT_FILES_BUCKET_ID: 'project-files',
    VERIFICATION_PROJECT_ID: inventory.environment.projectId,
    VERIFICATION_PROVIDER_CONTRACT_DIGEST: PROVIDER_CONTRACT_DIGEST,
    VERIFICATION_SHARES_TABLE_ID: 'project_shares',
    VERIFICATION_WORKER_FUNCTION_ID: 'execute-node-py',
  };
  const variables = Object.entries(literals).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, value]) => ({ key, valueDigest: digest(value) }));
  return {
    environmentDigest: ENVIRONMENT_DIGEST, providerContractDigest: PROVIDER_CONTRACT_DIGEST,
    identityBindingsDigest,
    expectedRunnerVariables: { identityQualifiedKey: 'VERIFICATION_IDENTITY_BINDINGS_DIGEST', staticTotal: 15, total: 16, variables },
    runnerVariableReadbackDigest: digest('runner-readback'),
    siteConfigurationDigest: digest('site-configuration'),
    functionConfigurationsDigest: digest('function-configurations'),
    globalCleanupReadbackDigest: digest('global-cleanup'),
    projectReadbackDigest: digest('project-readback'),
  };
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zip(entries) {
  const locals = [];
  const centrals = [];
  let localOffset = 0;
  for (const [entryName, entryValue] of entries) {
    const name = Buffer.from(entryName, 'utf8');
    const data = Buffer.from(entryValue);
    const compressed = deflateRawSync(data);
    const checksum = crc32(data);
    const flags = 0x0808;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6); local.writeUInt16LE(8, 8); local.writeUInt16LE(name.length, 26);
    const descriptor = Buffer.alloc(16);
    descriptor.writeUInt32LE(0x08074b50, 0); descriptor.writeUInt32LE(checksum, 4);
    descriptor.writeUInt32LE(compressed.length, 8); descriptor.writeUInt32LE(data.length, 12);
    locals.push(local, name, compressed, descriptor);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6); central.writeUInt16LE(flags, 8); central.writeUInt16LE(8, 10);
    central.writeUInt32LE(checksum, 16); central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38); central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset += local.length + name.length + compressed.length + descriptor.length;
  }
  const localBytes = Buffer.concat(locals);
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  const entryCount = entries.size ?? entries.length;
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entryCount, 8);
  end.writeUInt16LE(entryCount, 10); end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  return Buffer.concat([localBytes, centralBytes, end]);
}

function fixture(transformEntries = (entries) => entries) {
  const created = createAppwriteTestSetupBindings({
    controllerRevision: CONTROLLER_SHA, sourceRepositoryRevision: SOURCE_SHA,
    runnerRevision: RUNNER_SHA, initialSeed: true, liveProjection: liveProjection(),
    browserRequestPolicy: browserPolicy(), nowEpochSeconds: NOW_SECONDS,
    controllerArtifact: null,
  });
  assert.equal(created.status, 'PASS', created.diagnostics?.[0]?.code);
  const files = new Map(BINDING_NAMES.map((name) => [`${name}.txt`, created.value.bindings[name]]));
  files.set('evidence.json', `${canonicalJson(created.value.evidence)}\n`);
  const records = [...files].map(([filePath, value]) => ({
    path: filePath, byteLength: Buffer.byteLength(value), sha256: digest(value),
  })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const manifest = {
    schemaVersion: 'appwrite-test-binding-artifact-manifest.v1',
    controllerRevision: CONTROLLER_SHA, sourceRepositoryRevision: SOURCE_SHA,
    runnerRevision: RUNNER_SHA, initialSeed: true, controllerArtifact: null, files: records,
  };
  files.set('binding-manifest.json', `${canonicalJson(manifest)}\n`);
  const archive = zip(transformEntries(new Map(files)));
  const pointer = {
    artifactId: ARTIFACT_ID, authorization: 'test-token', bundleDigest: digest(archive),
    initialSeed: true, repository: 'Krowaccie/AppWriteWork-verification-control',
    runnerRevision: RUNNER_SHA, sourceRepositoryRevision: SOURCE_SHA, trustedSha: CONTROLLER_SHA,
  };
  const metadata = {
    id: Number(ARTIFACT_ID),
    name: `appwrite-test-setup-readback-${CONTROLLER_SHA}-${SOURCE_SHA}`,
    expired: false, expires_at: '2028-01-01T00:00:00Z', size_in_bytes: archive.length,
    digest: pointer.bundleDigest,
    archive_download_url: `https://api.github.com/repos/Krowaccie/AppWriteWork-verification-control/actions/artifacts/${ARTIFACT_ID}/zip`,
    workflow_run: { id: 999, head_sha: CONTROLLER_SHA },
  };
  const response = (status, bytes, headers = {}) => ({
    status, headers: new Headers({ 'content-length': String(bytes.length), ...headers }),
    async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  });
  const fetchImpl = async (url) => {
    if (url.endsWith(`/actions/artifacts/${ARTIFACT_ID}`)) {
      const bytes = Buffer.from(JSON.stringify(metadata));
      return response(200, bytes, { 'content-type': 'application/json' });
    }
    if (url.endsWith(`/actions/artifacts/${ARTIFACT_ID}/zip`)) {
      return { status: 302, headers: new Headers({ location: SIGNED_URL }) };
    }
    if (url === SIGNED_URL) return response(200, archive);
    throw new Error('unexpected request');
  };
  return { pointer, fetchImpl, archive, semantic: {
    bindings: created.value.bindings,
    evidence: created.value.evidence,
    input: pointer,
    manifest,
    nowEpochSeconds: NOW_SECONDS,
  } };
}

test('downloads and validates one exact canonical binding artifact', async () => {
  const value = fixture();
  assert.equal(extractBoundedZipArchive(value.archive).size, 10);
  const semantic = validateTestCloudBindingSet(value.semantic);
  assert.equal(semantic.status, 'PASS', semantic.diagnostics?.[0]?.code);
  const verified = await verifyGithubTestCloudBindingArtifact(value.pointer, {
    fetchImpl: value.fetchImpl, now: () => NOW_SECONDS * 1000,
  });
  assert.equal(verified.status, 'PASS', verified.diagnostics?.[0]?.code);
  assert.deepEqual(Object.keys(verified.value.bindings), BINDING_NAMES);
  assert.equal(verified.value.evidence.sourceRepositoryRevision, SOURCE_SHA);
});

test('rejects a member changed after the signed manifest was created', async () => {
  const value = fixture((entries) => {
    entries.set('TEST_CLOUD_SETUP_READBACK_JSON.txt', '{}');
    return entries;
  });
  const verified = await verifyGithubTestCloudBindingArtifact(value.pointer, {
    fetchImpl: value.fetchImpl, now: () => NOW_SECONDS * 1000,
  });
  assert.equal(verified.status, 'BLOCKED');
});

test('CLI materializes only the eight verified binding files', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'binding-verifier-'));
  try {
    const value = fixture();
    const inputPath = path.join(root, 'input.json');
    const outputPath = path.join(root, 'bindings');
    const { authorization, repository, ...cliInput } = value.pointer;
    await writeFile(inputPath, `${canonicalJson(cliInput)}\n`, 'utf8');
    const outcome = await runTestCloudBindingArtifactVerifierCli(
      ['--input', inputPath, '--output', outputPath],
      { GITHUB_TOKEN: authorization, GITHUB_REPOSITORY: repository },
      { fetchImpl: value.fetchImpl, now: () => NOW_SECONDS * 1000 },
    );
    assert.equal(outcome.status, 'PASS', outcome.diagnostics?.[0]?.code);
    assert.deepEqual((await readdir(outputPath)).sort(),
      BINDING_NAMES.map((name) => `${name}.txt`).sort());
    assert.equal((await readFile(path.join(outputPath, 'TEST_CLOUD_SETUP_READBACK_JSON.txt'), 'utf8')).startsWith('{'), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('CLI can delegate semantic validation to the exact historical controller', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'binding-verifier-recovery-time-'));
  try {
    const value = fixture();
    const inputPath = path.join(root, 'input.json');
    const outputPath = path.join(root, 'bindings');
    const { authorization, repository, ...cliInput } = value.pointer;
    const expiredNow = (NOW_SECONDS + 21_601) * 1000;
    await writeFile(inputPath, `${canonicalJson(cliInput)}\n`, 'utf8');
    const outcome = await runTestCloudBindingArtifactVerifierCli(
      ['--input', inputPath, '--output', outputPath],
      { GITHUB_TOKEN: authorization, GITHUB_REPOSITORY: repository },
      {
        artifactVerifier: (input) => verifyGithubTestCloudBindingArtifact(input, {
          fetchImpl: value.fetchImpl,
          now: () => NOW_SECONDS * 1000,
        }),
        fetchImpl: value.fetchImpl,
        now: () => expiredNow,
      },
    );
    assert.equal(outcome.status, 'PASS', outcome.diagnostics?.[0]?.code);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
