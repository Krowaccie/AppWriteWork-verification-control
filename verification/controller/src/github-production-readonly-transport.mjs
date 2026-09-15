import { inflateRawSync } from 'node:zlib';

import { validateProductionReleaseBinding } from './release-record-contract.mjs';

const API_ORIGIN = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const ENVIRONMENT = 'production-release';
const WORKFLOW = 'Release Production';
const WORKFLOW_PATH = '.github/workflows/release-production.yml';
const PUBLISH_JOB = 'publish-release-record';
const RECORD_FILE = 'release-record.v1.json';
const ID = /^[1-9][0-9]*$/;
const SHA = /^[0-9a-f]{40}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 1024 * 1024;
const MAX_RECORD_BYTES = 256 * 1024;
const INPUT_KEYS = Object.freeze(['fetchImpl', 'trustedControllerSha']);
const LIST_KEYS = Object.freeze(['artifactId', 'authorization', 'environment', 'repository']);
const DOWNLOAD_KEYS = Object.freeze(['artifactId', 'authorization', 'repository']);

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function exactObject(value, keys) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.getOwnPropertySymbols(value).length === 0
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
    && Object.values(Object.getOwnPropertyDescriptors(value))
      .every((descriptor) => Object.hasOwn(descriptor, 'value'));
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function validAuthorization(value) {
  return typeof value === 'string'
    && value.length >= 1
    && value.length <= 4096
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeProviderId(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 1 ? String(value) : null;
  }
  return typeof value === 'string' && ID.test(value) ? value : null;
}

function ownDataProperty(value, key) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function validTimestamp(value) {
  return typeof value === 'string'
    && UTC_TIMESTAMP.test(value)
    && Number.isFinite(Date.parse(value));
}

function header(response, name) {
  if (typeof response?.headers?.get === 'function') return response.headers.get(name);
  if (response?.headers && typeof response.headers === 'object') {
    const key = Object.keys(response.headers).find(
      (candidate) => candidate.toLowerCase() === name.toLowerCase(),
    );
    return key === undefined ? null : response.headers[key];
  }
  return null;
}

function requireNoPagination(response) {
  const link = header(response, 'link');
  if (typeof link === 'string' && link.trim().length > 0) {
    throw blocked('PRODUCTION_RELEASE_PROOF_INVALID');
  }
}

async function readBoundedBytes(response, limit) {
  const rawLength = header(response, 'content-length');
  if (rawLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(rawLength)) throw new Error('invalid length');
    const length = Number(rawLength);
    if (!Number.isSafeInteger(length) || length > limit) throw new Error('body too large');
  }
  if (response?.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) throw new Error('invalid body chunk');
        length += value.byteLength;
        if (length > limit) {
          await reader.cancel();
          throw new Error('body too large');
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      reader.releaseLock();
    }
    return Buffer.concat(chunks, length);
  }
  if (typeof response?.arrayBuffer !== 'function') throw new Error('body unavailable');
  const value = Buffer.from(await response.arrayBuffer());
  if (value.byteLength > limit) throw new Error('body too large');
  return value;
}

async function readJson(response) {
  if (response?.status !== 200) throw new Error('provider response rejected');
  const contentType = header(response, 'content-type');
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new Error('provider content type rejected');
  }
  if (response?.body && typeof response.body.getReader === 'function') {
    const bytes = await readBoundedBytes(response, MAX_JSON_BYTES);
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  }
  const rawLength = header(response, 'content-length');
  if (rawLength !== null && (!/^(?:0|[1-9][0-9]*)$/.test(rawLength)
      || Number(rawLength) > MAX_JSON_BYTES)) {
    throw new Error('provider response too large');
  }
  if (typeof response?.json !== 'function') throw new Error('provider body unavailable');
  return response.json();
}

function githubHeaders(authorization) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${authorization}`,
    'User-Agent': 'appwritework-verification-controller',
    'X-GitHub-Api-Version': API_VERSION,
  };
}

function validRun(value, proof, trustedControllerSha) {
  const workflowPath = typeof value?.path === 'string'
    ? value.path.split('@')
    : [];
  return safeProviderId(value?.id) === proof.runId
    && value?.run_attempt === proof.runAttempt
    && value?.name === WORKFLOW
    && workflowPath[0] === WORKFLOW_PATH
    && workflowPath.length <= 2
    && (workflowPath.length === 1
      || /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/.test(workflowPath[1]))
    && value?.event === 'workflow_dispatch'
    && value?.status === 'completed'
    && value?.conclusion === 'success'
    && value?.head_sha === trustedControllerSha;
}

function validPublisherJobs(value, proof, trustedControllerSha) {
  const selected = value.jobs.filter((candidate) => candidate?.name === PUBLISH_JOB);
  if (selected.length !== 1) return false;
  const candidate = selected[0];
  return safeProviderId(candidate.id) !== null
    && safeProviderId(candidate.run_id) === proof.runId
    && candidate.workflow_name === WORKFLOW
    && candidate.status === 'completed'
    && candidate.conclusion === 'success'
    && candidate.head_sha === trustedControllerSha;
}

function validApprovalHistory(value) {
  if (!Array.isArray(value) || value.length !== 1) return false;
  const review = value[0];
  return review?.state === 'approved'
    && Array.isArray(review.environments)
    && review.environments.length === 1
    && review.environments[0]?.name === ENVIRONMENT
    && safeProviderId(review.environments[0]?.id) !== null;
}

function validStatusHistory(value) {
  if (!Array.isArray(value) || value.length !== 1) return false;
  const candidate = value[0];
  return safeProviderId(candidate?.id) !== null
    && candidate.state === 'success'
    && candidate.environment === ENVIRONMENT
    && validTimestamp(candidate.created_at);
}

function expectedArtifactName(proof) {
  return `release-record-${proof.revision}`;
}

function expectedArtifactUrl(proof) {
  return `${API_ORIGIN}/repos/${REPOSITORY}/actions/artifacts/${proof.recordArtifactId}/zip`;
}

function validArtifact(value, proof, trustedControllerSha) {
  return safeProviderId(value?.id) === proof.recordArtifactId
    && value?.name === expectedArtifactName(proof)
    && value?.expired === false
    && value?.archive_download_url === expectedArtifactUrl(proof)
    && safeProviderId(value?.workflow_run?.id) === proof.runId
    && value?.workflow_run?.head_sha === trustedControllerSha;
}

function selectArtifact(value, proof, trustedControllerSha) {
  const named = value.artifacts.filter(
    (candidate) => candidate?.name === expectedArtifactName(proof),
  );
  if (named.length !== 1 || !validArtifact(named[0], proof, trustedControllerSha)) return null;
  return named[0];
}

function completeProviderCollection(value, key) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Array.isArray(value[key])
    && Number.isSafeInteger(value.total_count)
    && value.total_count === value[key].length
    && value[key].length <= 100;
}

function safeSignedArtifactUrl(value) {
  try {
    const url = new URL(value);
    const hostname = url.hostname.toLowerCase();
    const allowedHost = hostname === 'objects.githubusercontent.com'
      || hostname.endsWith('.githubusercontent.com')
      || hostname.endsWith('.blob.core.windows.net');
    return url.protocol === 'https:'
      && allowedHost
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

function parseExtraFields(buffer, start, length) {
  const end = start + length;
  if (!Number.isSafeInteger(end) || end > buffer.length) throw new Error('invalid extra fields');
  let offset = start;
  while (offset < end) {
    if (offset + 4 > end) throw new Error('invalid extra field');
    const id = buffer.readUInt16LE(offset);
    const fieldLength = buffer.readUInt16LE(offset + 2);
    offset += 4;
    if (id === 0x0001 || offset + fieldLength > end) throw new Error('unsafe extra field');
    offset += fieldLength;
  }
}

function decodeEntryName(bytes, flags) {
  if (bytes.includes(0)) throw new Error('invalid filename');
  if ((flags & 0x0800) === 0 && [...bytes].some((byte) => byte > 0x7f)) {
    throw new Error('ambiguous filename');
  }
  const name = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (name !== RECORD_FILE
      || name.includes('\\')
      || name.startsWith('/')
      || /^[A-Za-z]:/.test(name)
      || name.split('/').includes('..')) throw new Error('unsafe filename');
  return name;
}

function findEndOfCentralDirectory(buffer) {
  const earliest = Math.max(0, buffer.length - 22 - 0xffff);
  const candidates = [];
  for (let offset = buffer.length - 22; offset >= earliest; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === buffer.length) candidates.push(offset);
  }
  if (candidates.length !== 1) throw new Error('ambiguous central directory');
  return candidates[0];
}

function extractReleaseRecord(archive) {
  const buffer = Buffer.from(archive.buffer, archive.byteOffset, archive.byteLength);
  if (buffer.length < 22 || buffer.length > MAX_ARCHIVE_BYTES) throw new Error('invalid archive size');
  const endOffset = findEndOfCentralDirectory(buffer);
  const disk = buffer.readUInt16LE(endOffset + 4);
  const centralDisk = buffer.readUInt16LE(endOffset + 6);
  const diskEntries = buffer.readUInt16LE(endOffset + 8);
  const totalEntries = buffer.readUInt16LE(endOffset + 10);
  const centralSize = buffer.readUInt32LE(endOffset + 12);
  const centralOffset = buffer.readUInt32LE(endOffset + 16);
  const commentLength = buffer.readUInt16LE(endOffset + 20);
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== 1 || totalEntries !== 1
      || commentLength !== 0 || centralOffset + centralSize !== endOffset
      || centralSize < 46 || centralOffset + 46 > buffer.length) {
    throw new Error('invalid central directory');
  }
  if (buffer.readUInt32LE(centralOffset) !== 0x02014b50) throw new Error('missing central entry');
  const madeBy = buffer.readUInt16LE(centralOffset + 4);
  const flags = buffer.readUInt16LE(centralOffset + 8);
  const method = buffer.readUInt16LE(centralOffset + 10);
  const expectedCrc = buffer.readUInt32LE(centralOffset + 16);
  const compressedSize = buffer.readUInt32LE(centralOffset + 20);
  const uncompressedSize = buffer.readUInt32LE(centralOffset + 24);
  const nameLength = buffer.readUInt16LE(centralOffset + 28);
  const extraLength = buffer.readUInt16LE(centralOffset + 30);
  const entryCommentLength = buffer.readUInt16LE(centralOffset + 32);
  const startDisk = buffer.readUInt16LE(centralOffset + 34);
  const externalAttributes = buffer.readUInt32LE(centralOffset + 38);
  const localOffset = buffer.readUInt32LE(centralOffset + 42);
  const centralEntryEnd = centralOffset + 46 + nameLength + extraLength + entryCommentLength;
  if (centralEntryEnd !== endOffset || entryCommentLength !== 0 || startDisk !== 0
      || nameLength < 1 || localOffset !== 0 || uncompressedSize > MAX_RECORD_BYTES
      || compressedSize > MAX_ARCHIVE_BYTES || (flags & 0x0001) !== 0
      || (flags & ~(0x0800 | 0x0008 | 0x0006)) !== 0
      || ![0, 8].includes(method) || (method === 0 && (flags & 0x0006) !== 0)) {
    throw new Error('unsafe central entry');
  }
  const platform = madeBy >>> 8;
  const mode = externalAttributes >>> 16;
  const fileType = mode & 0o170000;
  if ((externalAttributes & 0x10) !== 0
      || (platform === 3 && ![0, 0o100000].includes(fileType))
      || (mode & 0o111) !== 0) throw new Error('unsafe entry type');
  const centralNameStart = centralOffset + 46;
  const centralName = buffer.subarray(centralNameStart, centralNameStart + nameLength);
  decodeEntryName(centralName, flags);
  parseExtraFields(buffer, centralNameStart + nameLength, extraLength);

  if (buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error('missing local entry');
  const localFlags = buffer.readUInt16LE(localOffset + 6);
  const localMethod = buffer.readUInt16LE(localOffset + 8);
  const localCrc = buffer.readUInt32LE(localOffset + 14);
  const localCompressedSize = buffer.readUInt32LE(localOffset + 18);
  const localUncompressedSize = buffer.readUInt32LE(localOffset + 22);
  const localNameLength = buffer.readUInt16LE(localOffset + 26);
  const localExtraLength = buffer.readUInt16LE(localOffset + 28);
  const localNameStart = localOffset + 30;
  const localExtraStart = localNameStart + localNameLength;
  const dataStart = localExtraStart + localExtraLength;
  const dataEnd = dataStart + compressedSize;
  if (localFlags !== flags || localMethod !== method || localNameLength !== nameLength
      || dataStart > centralOffset || dataEnd > centralOffset
      || !buffer.subarray(localNameStart, localNameStart + localNameLength).equals(centralName)) {
    throw new Error('central and local entries disagree');
  }
  parseExtraFields(buffer, localExtraStart, localExtraLength);
  if ((flags & 0x0008) === 0) {
    if (localCrc !== expectedCrc || localCompressedSize !== compressedSize
        || localUncompressedSize !== uncompressedSize || dataEnd !== centralOffset) {
      throw new Error('invalid local sizes');
    }
  } else {
    if (![0, expectedCrc].includes(localCrc)
        || ![0, compressedSize].includes(localCompressedSize)
        || ![0, uncompressedSize].includes(localUncompressedSize)) {
      throw new Error('invalid streaming sizes');
    }
    const descriptorLength = centralOffset - dataEnd;
    const descriptorOffset = dataEnd;
    let valuesOffset;
    if (descriptorLength === 16 && buffer.readUInt32LE(descriptorOffset) === 0x08074b50) {
      valuesOffset = descriptorOffset + 4;
    } else if (descriptorLength === 12) {
      valuesOffset = descriptorOffset;
    } else {
      throw new Error('invalid data descriptor');
    }
    if (buffer.readUInt32LE(valuesOffset) !== expectedCrc
        || buffer.readUInt32LE(valuesOffset + 4) !== compressedSize
        || buffer.readUInt32LE(valuesOffset + 8) !== uncompressedSize) {
      throw new Error('data descriptor mismatch');
    }
  }
  if (method === 0 && compressedSize !== uncompressedSize) throw new Error('invalid stored sizes');
  const compressed = buffer.subarray(dataStart, dataEnd);
  const output = method === 0
    ? Buffer.from(compressed)
    : inflateRawSync(compressed, { maxOutputLength: MAX_RECORD_BYTES });
  if (output.length !== uncompressedSize || output.length > MAX_RECORD_BYTES
      || crc32(output) !== expectedCrc) throw new Error('record payload mismatch');
  return Uint8Array.from(output);
}

export function createGithubProductionReadonlyTransport(input = {}) {
  if (!exactObject(input, INPUT_KEYS)
      || typeof input.fetchImpl !== 'function'
      || !SHA.test(input.trustedControllerSha)) {
    throw blocked('GITHUB_PRODUCTION_READONLY_TRANSPORT_INPUT_INVALID');
  }
  const { fetchImpl, trustedControllerSha } = input;
  let provenArtifacts = new Map();

  async function githubJson(path, authorization, { paginated = false } = {}) {
    const response = await fetchImpl(`${API_ORIGIN}${path}`, {
      method: 'GET',
      redirect: 'error',
      headers: githubHeaders(authorization),
    });
    if (paginated) requireNoPagination(response);
    return readJson(response);
  }

  async function listDeployments(methodInput = {}) {
    if (!exactObject(methodInput, LIST_KEYS)
        || methodInput.repository !== REPOSITORY
        || methodInput.environment !== ENVIRONMENT
        || typeof methodInput.artifactId !== 'string'
        || !ID.test(methodInput.artifactId)
        || !validAuthorization(methodInput.authorization)) {
      throw blocked('GITHUB_PRODUCTION_READONLY_TRANSPORT_INPUT_INVALID');
    }
    const { authorization } = methodInput;
    try {
      const rawDeployments = await githubJson(
        `/repos/${REPOSITORY}/deployments?environment=${ENVIRONMENT}&per_page=100`,
        authorization,
        { paginated: true },
      );
      if (!Array.isArray(rawDeployments) || rawDeployments.length > 100) {
        throw new Error('invalid deployment list');
      }
      const nextArtifacts = new Map();
      const ambiguousArtifactIds = new Set();
      const normalized = [];
      for (const raw of rawDeployments) {
        const rawPayload = ownDataProperty(raw, 'payload');
        if (ownDataProperty(rawPayload, 'recordArtifactId') !== methodInput.artifactId) continue;
        const deploymentId = safeProviderId(raw?.id);
        if (deploymentId === null
            || raw.ref !== trustedControllerSha
            || raw.environment !== ENVIRONMENT
            || !validTimestamp(raw.created_at)) continue;
        try {
          validateProductionReleaseBinding(rawPayload);
        } catch {
          continue;
        }
        const proof = structuredClone(rawPayload);

        const runValue = await githubJson(
          `/repos/${REPOSITORY}/actions/runs/${proof.runId}/attempts/${proof.runAttempt}`,
          authorization,
        );
        if (!validRun(runValue, proof, trustedControllerSha)) continue;

        const jobsResponse = await fetchImpl(
          `${API_ORIGIN}/repos/${REPOSITORY}/actions/runs/${proof.runId}/attempts/${proof.runAttempt}/jobs?per_page=100`,
          { method: 'GET', redirect: 'error', headers: githubHeaders(authorization) },
        );
        requireNoPagination(jobsResponse);
        const jobsValue = await readJson(jobsResponse);
        if (!completeProviderCollection(jobsValue, 'jobs')) {
          throw new Error('incomplete job collection');
        }
        if (!validPublisherJobs(jobsValue, proof, trustedControllerSha)) continue;

        const approvalsResponse = await fetchImpl(
          `${API_ORIGIN}/repos/${REPOSITORY}/actions/runs/${proof.runId}/approvals`,
          { method: 'GET', redirect: 'error', headers: githubHeaders(authorization) },
        );
        requireNoPagination(approvalsResponse);
        const approvalsValue = await readJson(approvalsResponse);
        if (!Array.isArray(approvalsValue) || approvalsValue.length > 100) {
          throw new Error('invalid approval collection');
        }
        if (!validApprovalHistory(approvalsValue)) continue;

        const statusesResponse = await fetchImpl(
          `${API_ORIGIN}/repos/${REPOSITORY}/deployments/${deploymentId}/statuses?per_page=100`,
          { method: 'GET', redirect: 'error', headers: githubHeaders(authorization) },
        );
        requireNoPagination(statusesResponse);
        const statusesValue = await readJson(statusesResponse);
        if (!Array.isArray(statusesValue) || statusesValue.length > 100) {
          throw new Error('invalid status collection');
        }
        if (!validStatusHistory(statusesValue)) continue;

        const artifactsResponse = await fetchImpl(
          `${API_ORIGIN}/repos/${REPOSITORY}/actions/runs/${proof.runId}/artifacts?per_page=100`,
          { method: 'GET', redirect: 'error', headers: githubHeaders(authorization) },
        );
        requireNoPagination(artifactsResponse);
        const artifactsValue = await readJson(artifactsResponse);
        if (!completeProviderCollection(artifactsValue, 'artifacts')) {
          throw new Error('incomplete artifact collection');
        }
        const selectedArtifact = selectArtifact(artifactsValue, proof, trustedControllerSha);
        if (selectedArtifact === null) continue;
        if (nextArtifacts.has(proof.recordArtifactId)) {
          nextArtifacts.delete(proof.recordArtifactId);
          ambiguousArtifactIds.add(proof.recordArtifactId);
        } else if (!ambiguousArtifactIds.has(proof.recordArtifactId)) {
          nextArtifacts.set(proof.recordArtifactId, deepFreeze({
            artifactId: proof.recordArtifactId,
            name: selectedArtifact.name,
            revision: proof.revision,
            runId: proof.runId,
            runAttempt: proof.runAttempt,
            headSha: trustedControllerSha,
            archiveDownloadUrl: expectedArtifactUrl(proof),
          }));
        }
        normalized.push(deepFreeze({
          id: deploymentId,
          state: 'success',
          protected: true,
          createdAt: raw.created_at,
          payload: proof,
        }));
      }
      provenArtifacts = nextArtifacts;
      return Object.freeze(normalized);
    } catch {
      provenArtifacts = new Map();
      throw blocked('PRODUCTION_RELEASE_PROOF_INVALID');
    }
  }

  async function downloadArtifact(methodInput = {}) {
    if (!exactObject(methodInput, DOWNLOAD_KEYS)
        || methodInput.repository !== REPOSITORY
        || typeof methodInput.artifactId !== 'string'
        || !ID.test(methodInput.artifactId)
        || !validAuthorization(methodInput.authorization)) {
      throw blocked('GITHUB_PRODUCTION_READONLY_TRANSPORT_INPUT_INVALID');
    }
    const proof = provenArtifacts.get(methodInput.artifactId);
    if (!proof) throw blocked('PRODUCTION_RELEASE_ARTIFACT_INVALID');
    const { authorization } = methodInput;
    let archive;
    try {
      const metadata = await githubJson(
        `/repos/${REPOSITORY}/actions/artifacts/${proof.artifactId}`,
        authorization,
      );
      if (!validArtifact(metadata, {
        recordArtifactId: proof.artifactId,
        revision: proof.revision,
        runId: proof.runId,
      }, trustedControllerSha)) throw new Error('artifact metadata mismatch');
      const redirectResponse = await fetchImpl(proof.archiveDownloadUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: githubHeaders(authorization),
      });
      if (redirectResponse?.status !== 302) throw new Error('artifact redirect missing');
      const signedUrl = safeSignedArtifactUrl(header(redirectResponse, 'location'));
      if (signedUrl === null) throw new Error('artifact redirect unsafe');
      const archiveResponse = await fetchImpl(signedUrl, {
        method: 'GET',
        redirect: 'error',
        headers: {
          Accept: 'application/octet-stream',
          'User-Agent': 'appwritework-verification-controller',
        },
      });
      if (archiveResponse?.status !== 200) throw new Error('artifact download failed');
      archive = await readBoundedBytes(archiveResponse, MAX_ARCHIVE_BYTES);
    } catch {
      throw blocked('PRODUCTION_RELEASE_ARTIFACT_INVALID');
    }
    try {
      return extractReleaseRecord(archive);
    } catch {
      throw blocked('PRODUCTION_RELEASE_ARCHIVE_INVALID');
    }
  }

  return Object.freeze({ listDeployments, downloadArtifact });
}
