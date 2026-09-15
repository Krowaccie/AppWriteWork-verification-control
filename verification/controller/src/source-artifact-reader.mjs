import { createHash, createSign } from 'node:crypto';

import {
  MAX_VERIFICATION_ARCHIVE_BYTES,
  extractBoundedZipArchive,
  readBoundedResponseBytes,
} from './controller-archive-verifier.mjs';

const SOURCE_REPOSITORY = 'Krowaccie/AppWriteWork';
const SOURCE_WORKFLOW_PATH = '.github/workflows/verify-main.yml';
const MAX_SOURCE_ARCHIVE_BYTES = MAX_VERIFICATION_ARCHIVE_BYTES;
const SAFE_PATH = /^(?!\/)(?![A-Za-z]:\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)[\x20-\x7e]+$/;

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function encoded(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

export function createGithubAppJwt({ appId, privateKey, nowSeconds = Math.floor(Date.now() / 1000) }) {
  if (!/^[1-9][0-9]*$/.test(String(appId)) ||
      typeof privateKey !== 'string' ||
      !Number.isSafeInteger(nowSeconds)) {
    throw blocked('SOURCE_APP_JWT_INPUT_INVALID');
  }
  const header = encoded({ alg: 'RS256', typ: 'JWT' });
  const payload = encoded({ iat: nowSeconds, exp: nowSeconds + 540, iss: String(appId) });
  const signingInput = `${header}.${payload}`;
  let signature;
  try {
    signature = createSign('RSA-SHA256').update(signingInput).end().sign(privateKey).toString('base64url');
  } catch {
    throw blocked('SOURCE_APP_JWT_SIGN_FAILED');
  }
  return `${signingInput}.${signature}`;
}

function assertStatus(response, expected, code) {
  if (response?.status !== expected) throw blocked(code);
  return response.body;
}

function auth(token, extra = {}) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': '2022-11-28',
    ...extra,
  };
}

function sha(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export async function readBoundedSourceArtifactArchive(response, expectedBytes) {
  if (!Number.isSafeInteger(expectedBytes) ||
      expectedBytes < 22 ||
      expectedBytes > MAX_SOURCE_ARCHIVE_BYTES) {
    throw blocked('SOURCE_ARTIFACT_DOWNLOAD_FAILED');
  }
  try {
    const bytes = await readBoundedResponseBytes(response, MAX_SOURCE_ARCHIVE_BYTES);
    if (bytes.byteLength !== expectedBytes) {
      throw blocked('SOURCE_ARTIFACT_DOWNLOAD_FAILED');
    }
    return new Uint8Array(bytes);
  } catch {
    throw blocked('SOURCE_ARTIFACT_DOWNLOAD_FAILED');
  }
}

export function extractSourceArtifactZip(archive) {
  try {
    return Object.freeze([...extractBoundedZipArchive(archive)].map(([path, bytes]) => (
      Object.freeze({
        path,
        type: 'file',
        mode: 0o644,
        bytes,
      })
    )));
  } catch {
    throw blocked('SOURCE_ARTIFACT_ZIP_UNSAFE');
  }
}

function validateToken(body, config) {
  if (!body || typeof body.token !== 'string' || body.token.length === 0 ||
      JSON.stringify(body.permissions) !== JSON.stringify({ actions: 'read' }) ||
      !Array.isArray(body.repositories) || body.repositories.length !== 1 ||
      body.repositories[0]?.id !== config.sourceRepositoryId ||
      body.repositories[0]?.full_name !== SOURCE_REPOSITORY) {
    throw blocked('SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH');
  }
  return body.token;
}

function validateEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw blocked('SOURCE_ARTIFACT_ZIP_UNSAFE');
  }
  const seen = new Set();
  let total = 0;
  const files = new Map();
  for (const entry of entries) {
    if (!entry || entry.type !== 'file' ||
        typeof entry.path !== 'string' || !SAFE_PATH.test(entry.path) ||
        entry.path.split('/').some((part) => part === '' || part === '.' || part === '..') ||
        seen.has(entry.path.toLowerCase()) ||
        !Number.isInteger(entry.mode) || (entry.mode & 0o111) !== 0 ||
        !(entry.bytes instanceof Uint8Array) ||
        entry.bytes.byteLength > 256 * 1024 * 1024) {
      throw blocked('SOURCE_ARTIFACT_ZIP_UNSAFE');
    }
    total += entry.bytes.byteLength;
    if (total > 1024 * 1024 * 1024) throw blocked('SOURCE_ARTIFACT_ZIP_UNSAFE');
    seen.add(entry.path.toLowerCase());
    files.set(entry.path, entry.bytes);
  }
  return files;
}


function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw blocked('SOURCE_ARTIFACT_MANIFEST_INVALID');
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0 &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function parseJsonFile(files, path) {
  const bytes = files.get(path);
  if (!(bytes instanceof Uint8Array)) throw blocked('SOURCE_ARTIFACT_MANIFEST_INVALID');
  try {
    return JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    throw blocked('SOURCE_ARTIFACT_MANIFEST_INVALID');
  }
}

function validateArtifactBundle(files, { revision, runId, runAttempt }) {
  const manifest = parseJsonFile(files, 'artifact-manifest.v1.json');
  const handoff = parseJsonFile(files, 'artifact-handoff.v1.json');
  const manifestKeys = ['schemaVersion', 'sourceRevision', 'sourceTreeDigest',
    'verifierManifestDigest', 'artifacts', 'artifactManifestDigest'];
  const artifactKeys = ['kind', 'logicalTarget', 'sourcePath', 'relativePath',
    'canonicalContentDigest', 'transportDigest', 'sizeBytes'];
  const handoffKeys = ['schemaVersion', 'sourceRepository', 'sourceWorkflow',
    'sourceWorkflowRunId', 'sourceWorkflowRunAttempt', 'sourceRef',
    'sourceRevision', 'artifactName', 'artifactManifestDigest', 'verifierManifestDigest'];
  if (!exactKeys(manifest, manifestKeys) || manifest.schemaVersion !== 1 ||
      manifest.sourceRevision !== revision ||
      !/^sha256:[0-9a-f]{64}$/.test(manifest.sourceTreeDigest ?? '') ||
      !/^sha256:[0-9a-f]{64}$/.test(manifest.verifierManifestDigest ?? '') ||
      !/^sha256:[0-9a-f]{64}$/.test(manifest.artifactManifestDigest ?? '') ||
      !Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 37 ||
      !exactKeys(handoff, handoffKeys) || handoff.schemaVersion !== 'artifact-handoff.v1' ||
      handoff.sourceRepository !== SOURCE_REPOSITORY || handoff.sourceWorkflow !== 'Verify Main' ||
      handoff.sourceWorkflowRunId !== String(runId) ||
      handoff.sourceWorkflowRunAttempt !== runAttempt ||
      handoff.sourceRef !== 'refs/heads/main' || handoff.sourceRevision !== revision ||
      handoff.artifactName !== `verification-artifacts-${revision}` ||
      handoff.artifactManifestDigest !== manifest.artifactManifestDigest ||
      handoff.verifierManifestDigest !== manifest.verifierManifestDigest) {
    throw blocked('SOURCE_ARTIFACT_MANIFEST_INVALID');
  }
  const core = { ...manifest };
  delete core.artifactManifestDigest;
  if (sha(Buffer.from(canonical(core), 'utf8')) !== manifest.artifactManifestDigest) {
    throw blocked('SOURCE_ARTIFACT_MANIFEST_INVALID');
  }
  const expectedPaths = new Set(['artifact-manifest.v1.json', 'artifact-handoff.v1.json']);
  const targetKeys = new Set();
  let runnerCount = 0;
  for (const artifact of manifest.artifacts) {
    if (!exactKeys(artifact, artifactKeys) || !['site', 'function'].includes(artifact.kind) ||
        typeof artifact.logicalTarget !== 'string' || artifact.logicalTarget.length === 0 ||
        typeof artifact.sourcePath !== 'string' || !SAFE_PATH.test(artifact.sourcePath) ||
        typeof artifact.relativePath !== 'string' || !SAFE_PATH.test(artifact.relativePath) ||
        !/^sha256:[0-9a-f]{64}$/.test(artifact.canonicalContentDigest ?? '') ||
        !/^sha256:[0-9a-f]{64}$/.test(artifact.transportDigest ?? '') ||
        !Number.isSafeInteger(artifact.sizeBytes) || artifact.sizeBytes < 0 ||
        expectedPaths.has(artifact.relativePath)) {
      throw blocked('SOURCE_ARTIFACT_MANIFEST_INVALID');
    }
    const bytes = files.get(artifact.relativePath);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== artifact.sizeBytes ||
        sha(bytes) !== artifact.transportDigest) {
      throw blocked('SOURCE_ARTIFACT_DIGEST_MISMATCH');
    }
    expectedPaths.add(artifact.relativePath);
    const key = `${artifact.kind}:${artifact.logicalTarget}`;
    if (targetKeys.has(key)) throw blocked('PRODUCTION_RELEASE_SET_MISMATCH');
    targetKeys.add(key);
    if (artifact.logicalTarget === 'verification-runner-py') {
      runnerCount += 1;
      if (artifact.kind !== 'function' ||
          artifact.relativePath !== 'functions/verification-runner-py.tar.gz') {
        throw blocked('PRODUCTION_TEST_ONLY_SET_MISMATCH');
      }
    }
  }
  if (runnerCount !== 1 || manifest.artifacts.filter(({ logicalTarget }) =>
    logicalTarget !== 'verification-runner-py').length !== 36) {
    throw blocked('PRODUCTION_TEST_ONLY_SET_MISMATCH');
  }
  if (files.size !== expectedPaths.size ||
      [...files.keys()].some((path) => !expectedPaths.has(path))) {
    throw blocked('PRODUCTION_HANDOFF_EXTRA_ARTIFACT');
  }
  return Object.freeze({
    artifactManifestDigest: manifest.artifactManifestDigest,
    verifierManifestDigest: manifest.verifierManifestDigest,
    sourceTreeDigest: manifest.sourceTreeDigest,
    releaseEligibleArtifacts: Object.freeze(manifest.artifacts.filter(
      ({ logicalTarget }) => logicalTarget !== 'verification-runner-py',
    )),
    testOnlyArtifacts: Object.freeze(manifest.artifacts.filter(
      ({ logicalTarget }) => logicalTarget === 'verification-runner-py',
    )),
  });
}

export async function readSourceArtifact({
  config,
  revision,
  qualifyingRunId,
  runAttempt,
  privateKey,
  request,
  readZip,
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  if (!config || !/^[1-9][0-9]*$/.test(String(config.installationId)) ||
      !Number.isSafeInteger(config.sourceRepositoryId) ||
      !Number.isSafeInteger(config.sourceWorkflowId) ||
      !/^[0-9a-f]{40}$/.test(revision) ||
      !/^[1-9][0-9]*$/.test(String(qualifyingRunId)) ||
      !Number.isSafeInteger(runAttempt) || runAttempt < 1 ||
      typeof request !== 'function' || typeof readZip !== 'function') {
    throw blocked('SOURCE_ARTIFACT_READER_INPUT_INVALID');
  }
  const jwt = createGithubAppJwt({ appId: config.appId, privateKey, nowSeconds });
  const tokenResponse = await request(`/app/installations/${config.installationId}/access_tokens`, {
    method: 'POST',
    headers: auth(jwt, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      repositories: ['AppWriteWork'],
      permissions: { actions: 'read' },
    }),
  });
  const mintedToken = typeof tokenResponse?.body?.token === 'string'
    ? tokenResponse.body.token
    : null;
  let token;
  try {
    token = validateToken(assertStatus(
      tokenResponse,
      201,
      'SOURCE_INSTALLATION_TOKEN_CREATE_FAILED',
    ), config);
    const headers = auth(token);
    const repository = assertStatus(await request(`/repos/${SOURCE_REPOSITORY}`, {
      method: 'GET',
      headers,
    }), 200, 'SOURCE_REPOSITORY_READ_FAILED');
    if (repository?.id !== config.sourceRepositoryId ||
        repository?.full_name !== SOURCE_REPOSITORY) {
      throw blocked('SOURCE_REPOSITORY_IDENTITY_MISMATCH');
    }

    const workflow = assertStatus(await request(
      `/repos/${SOURCE_REPOSITORY}/actions/workflows/verify-main.yml`,
      { method: 'GET', headers },
    ), 200, 'SOURCE_WORKFLOW_READ_FAILED');
    if (workflow?.id !== config.sourceWorkflowId ||
        workflow?.name !== 'Verify Main' ||
        workflow?.path !== SOURCE_WORKFLOW_PATH) {
      throw blocked('SOURCE_WORKFLOW_IDENTITY_MISMATCH');
    }

    const runId = String(qualifyingRunId);
    const run = assertStatus(await request(
      `/repos/${SOURCE_REPOSITORY}/actions/runs/${runId}`,
      { method: 'GET', headers },
    ), 200, 'SOURCE_RUN_READ_FAILED');
    if (String(run?.id) !== runId || run?.workflow_id !== config.sourceWorkflowId ||
        run?.run_attempt !== runAttempt || run?.status !== 'completed' || run?.conclusion !== 'success' ||
        run?.event !== 'push' || run?.head_repository?.full_name !== SOURCE_REPOSITORY ||
        run?.head_branch !== 'main' || run?.head_sha !== revision) {
      throw blocked('SOURCE_RUN_IDENTITY_MISMATCH');
    }

    const listing = assertStatus(await request(
      `/repos/${SOURCE_REPOSITORY}/actions/runs/${runId}/artifacts`,
      { method: 'GET', headers },
    ), 200, 'SOURCE_ARTIFACT_LIST_FAILED');
    const name = `verification-artifacts-${revision}`;
    const artifacts = Array.isArray(listing?.artifacts) ? listing.artifacts : [];
    if (artifacts.length !== 1 || artifacts[0]?.name !== name ||
        artifacts[0]?.expired !== false || !Number.isSafeInteger(artifacts[0]?.id) ||
        !/^sha256:[0-9a-f]{64}$/.test(artifacts[0]?.digest ?? '') ||
        !Number.isSafeInteger(artifacts[0]?.size_in_bytes) ||
        artifacts[0].size_in_bytes < 22 ||
        artifacts[0].size_in_bytes > MAX_SOURCE_ARCHIVE_BYTES) {
      throw blocked('SOURCE_ARTIFACT_IDENTITY_MISMATCH');
    }
    const artifact = artifacts[0];
    const archiveResponse = await request(
      `/repos/${SOURCE_REPOSITORY}/actions/artifacts/${artifact.id}/zip`,
      {
        method: 'GET',
        headers,
        redirect: 'error',
        expectedBytes: artifact.size_in_bytes,
      },
    );
    if (archiveResponse?.status !== 200 ||
        !(archiveResponse.bytes instanceof Uint8Array) ||
        archiveResponse.bytes.byteLength !== artifact.size_in_bytes) {
      throw blocked('SOURCE_ARTIFACT_DOWNLOAD_FAILED');
    }
    if (sha(archiveResponse.bytes) !== artifact.digest) {
      throw blocked('SOURCE_ARTIFACT_DIGEST_MISMATCH');
    }
    const entries = validateEntries(await readZip(archiveResponse.bytes));
    const bundle = validateArtifactBundle(entries, {
      revision,
      runId: run.id,
      runAttempt: run.run_attempt,
    });
    return Object.freeze({
      sourceRepositoryId: repository.id,
      sourceWorkflowId: workflow.id,
      sourceRunId: run.id,
      sourceRunAttempt: run.run_attempt,
      sourceArtifactId: artifact.id,
      sourceArtifactName: artifact.name,
      sourceArchiveDigest: artifact.digest,
      sourceRevision: revision,
      ...bundle,
      files: entries,
    });
  } finally {
    if (mintedToken !== null) {
      let revoked;
      try {
        revoked = await request('/installation/token', {
          method: 'DELETE',
          headers: auth(mintedToken),
        });
      } catch {
        throw blocked('SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED');
      }
      if (revoked?.status !== 204) {
        throw blocked('SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED');
      }
    }
  }
}
