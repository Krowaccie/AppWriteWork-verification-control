import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { constants as zlibConstants, gzipSync } from 'node:zlib';

import {
  SOURCE_ARTIFACT_COMMAND_IDS,
  SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION,
} from '../../packages/verification-controller/src/source-artifact-launcher-contract.mjs';
import { buildFunctionArtifact } from './deployment-artifact.mjs';
import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import { createArtifactManifest } from './artifact-manifest.mjs';
import { createHostedArtifactHandoff } from './hosted-artifact-handoff.mjs';
import {
  computeHostedSitePayloadDigest,
  writeHostedSiteBuildIdentity,
} from '../write-hosted-site-build-identity.mjs';

const PROTOCOL = SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FULL_REVISION = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const ARG_KEYS = Object.freeze([
  'commandPort', 'github', 'inventorySource', 'revision', 'sourceTreeDigest',
]);
const GITHUB_KEYS = Object.freeze(['ref', 'repository', 'runAttempt', 'runId', 'workflow']);
const PORT_KEYS = Object.freeze(['identity', 'runCommand', 'workspace', 'writeOutputMember']);
const IDENTITY_KEYS = Object.freeze([
  'repository', 'sourceRef', 'sourceRevision', 'sourceTreeDigest',
  'verifierManifestDigest', 'workflow', 'workflowRunAttempt', 'workflowRunId',
]);
const WORKSPACE_KEYS = Object.freeze(['childTemp', 'exportRoot', 'outputRoot', 'siteOutput']);
const MESSAGES = Object.freeze({
  ARTIFACT_BUILD_FAILED: 'Verification artifacts could not be built.',
  ARTIFACT_CLEANUP_INCOMPLETE: 'Verification artifact cleanup could not be completed safely.',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'Trusted build network isolation is unavailable.',
  ARTIFACT_PATH_UNSAFE: 'Artifact source or output path is unsafe.',
  ARTIFACT_SCHEMA_INVALID: 'Artifact build input does not match the closed contract.',
});
const STATUS_BY_CODE = Object.freeze({
  ARTIFACT_BUILD_FAILED: 'FAIL',
  ARTIFACT_CLEANUP_INCOMPLETE: 'BLOCKED',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'BLOCKED',
  ARTIFACT_PATH_UNSAFE: 'BLOCKED',
  ARTIFACT_SCHEMA_INVALID: 'BLOCKED',
});

class SetBuildError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function closedRecord(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function result(status, value, code = null) {
  return closedRecord({
    status,
    value,
    diagnostics: code === null ? Object.freeze([]) : Object.freeze([closedRecord({
      code,
      safeMessage: MESSAGES[code],
      retryable: false,
    })]),
  });
}

function fail(status, code) {
  throw new SetBuildError(status, code);
}

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactDataObject(value, expectedKeys, expectedPrototype) {
  try {
    if (utilTypes.isProxy(value) || value === null || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    if (Object.getPrototypeOf(value) !== expectedPrototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== 'string')) return null;
    const actual = [...ownKeys].sort(ordinalCompare);
    const expected = [...expectedKeys].sort(ordinalCompare);
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      return null;
    }
    const copy = Object.create(null);
    for (const key of expectedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function exactOrdinary(value, expectedKeys) {
  return exactDataObject(value, expectedKeys, Object.prototype);
}

function exactTrusted(value, expectedKeys) {
  const copy = exactDataObject(value, expectedKeys, null);
  try {
    return copy !== null && Object.isFrozen(value) ? copy : null;
  } catch {
    return null;
  }
}

function exactFrozenArray(value, expectedLength) {
  try {
    if (!Array.isArray(value) || !Object.isFrozen(value) || value.length !== expectedLength) return null;
    const keys = Reflect.ownKeys(value);
    const expected = [...Array.from({ length: expectedLength }, (_, index) => `${index}`), 'length'];
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return null;
    const output = [];
    for (let index = 0; index < expectedLength; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      output.push(descriptor.value);
    }
    return output;
  } catch {
    return null;
  }
}

function contained(rootReal, candidateReal) {
  const relative = path.relative(rootReal, candidateReal);
  return relative === '' || (
    !path.isAbsolute(relative)
    && relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
  );
}

function safeName(value) {
  return typeof value === 'string'
    && value.length > 0
    && !value.includes('\\')
    && !/[\u0000-\u001f\u007f]/u.test(value)
    && !path.posix.isAbsolute(value)
    && !path.win32.isAbsolute(value)
    && value.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

function authenticateArgs(args) {
  const input = exactOrdinary(args, ARG_KEYS);
  if (input === null) fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
  const github = exactOrdinary(input.github, GITHUB_KEYS);
  if (
    github === null
    || input.inventorySource !== 'validated-repository-collector'
    || typeof input.revision !== 'string'
    || !FULL_REVISION.test(input.revision)
    || typeof input.sourceTreeDigest !== 'string'
    || !DIGEST.test(input.sourceTreeDigest)
    || github.repository !== 'Krowaccie/AppWriteWork'
    || github.workflow !== 'Verify Main'
    || github.ref !== 'refs/heads/main'
    || typeof github.runId !== 'string'
    || !RUN_ID.test(github.runId)
    || !Number.isSafeInteger(github.runAttempt)
    || github.runAttempt < 1
  ) fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');

  const port = exactTrusted(input.commandPort, PORT_KEYS);
  if (
    port === null
    || typeof port.runCommand !== 'function'
    || utilTypes.isProxy(port.runCommand)
    || typeof port.writeOutputMember !== 'function'
    || utilTypes.isProxy(port.writeOutputMember)
  ) fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
  const identity = exactTrusted(port.identity, IDENTITY_KEYS);
  const workspace = exactTrusted(port.workspace, WORKSPACE_KEYS);
  if (identity === null || workspace === null) fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
  for (const key of WORKSPACE_KEYS) {
    if (typeof workspace[key] !== 'string' || !path.isAbsolute(workspace[key]) || workspace[key].includes('\0')) {
      fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
    }
  }
  if (
    new Set(WORKSPACE_KEYS.map((key) => path.normalize(workspace[key]).toLowerCase())).size
      !== WORKSPACE_KEYS.length
    || identity.repository !== github.repository
    || identity.workflow !== github.workflow
    || identity.sourceRef !== github.ref
    || identity.sourceRevision !== input.revision
    || identity.sourceTreeDigest !== input.sourceTreeDigest
    || identity.workflowRunId !== github.runId
    || identity.workflowRunAttempt !== github.runAttempt
    || typeof identity.verifierManifestDigest !== 'string'
    || !DIGEST.test(identity.verifierManifestDigest)
    || path.basename(workspace.outputRoot) !== input.revision
    || path.basename(path.dirname(workspace.outputRoot)) !== 'artifacts'
    || path.basename(path.dirname(path.dirname(workspace.outputRoot))) !== '.verification'
  ) fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
  return { input, github, port, identity, workspace };
}

function recognizedHostedSitePathFailure(error) {
  try {
    if (utilTypes.isProxy(error) || error === null || typeof error !== 'object') return false;
    const name = Object.getOwnPropertyDescriptor(error, 'name');
    const code = Object.getOwnPropertyDescriptor(error, 'code');
    const safeMessage = Object.getOwnPropertyDescriptor(error, 'safeMessage');
    return name?.value === 'HostedSiteIdentityError'
      && code?.value === 'ARTIFACT_PATH_UNSAFE'
      && typeof safeMessage?.value === 'string';
  } catch {
    return false;
  }
}

function normalizeInternalFailure(candidate) {
  const envelope = exactOrdinary(candidate, ['diagnostics', 'status', 'value']);
  if (envelope !== null && envelope.value === null && envelope.status === 'BLOCKED') {
    const diagnostics = exactFrozenArray(envelope.diagnostics, 1);
    const diagnostic = diagnostics === null ? null : exactOrdinary(
      diagnostics[0],
      ['code', 'retryable', 'safeMessage'],
    );
    if (
      diagnostic !== null
      && diagnostic.code === 'ARTIFACT_PATH_UNSAFE'
      && diagnostic.retryable === false
      && typeof diagnostic.safeMessage === 'string'
    ) return { status: 'BLOCKED', code: 'ARTIFACT_PATH_UNSAFE' };
  }
  return { status: 'FAIL', code: 'ARTIFACT_BUILD_FAILED' };
}

function normalizePortFailure(candidate, fallbackStatus, fallbackCode) {
  const envelope = exactTrusted(candidate, ['diagnostics', 'status', 'value']);
  if (envelope !== null && envelope.value === null) {
    const diagnostics = exactFrozenArray(envelope.diagnostics, 1);
    const diagnostic = diagnostics === null ? null : exactTrusted(
      diagnostics[0],
      ['code', 'retryable', 'safeMessage'],
    );
    if (
      diagnostic !== null
      && Object.hasOwn(STATUS_BY_CODE, diagnostic.code)
      && STATUS_BY_CODE[diagnostic.code] === envelope.status
      && diagnostic.retryable === false
      && typeof diagnostic.safeMessage === 'string'
    ) return { status: envelope.status, code: diagnostic.code };
  }
  return { status: fallbackStatus, code: fallbackCode };
}

function validateCommandPass(candidate, commandId) {
  const envelope = exactTrusted(candidate, ['diagnostics', 'status', 'value']);
  const diagnostics = envelope === null ? null : exactFrozenArray(envelope.diagnostics, 0);
  const value = envelope === null ? null : exactTrusted(envelope.value, ['commandId']);
  return envelope !== null
    && envelope.status === 'PASS'
    && diagnostics !== null
    && value !== null
    && value.commandId === commandId;
}

function validateWritePass(candidate, memberId, bytes) {
  const envelope = exactTrusted(candidate, ['diagnostics', 'status', 'value']);
  const diagnostics = envelope === null ? null : exactFrozenArray(envelope.diagnostics, 0);
  const value = envelope === null ? null : exactTrusted(
    envelope.value,
    ['memberId', 'sizeBytes', 'transportDigest'],
  );
  return envelope !== null
    && envelope.status === 'PASS'
    && diagnostics !== null
    && value !== null
    && value.memberId === memberId
    && value.sizeBytes === bytes.byteLength
    && value.transportDigest === sha256Bytes(bytes);
}

async function invokeCommand(authenticated, commandId) {
  const request = Object.freeze({ protocolVersion: PROTOCOL, commandId });
  let candidate;
  try {
    candidate = await Reflect.apply(
      authenticated.port.runCommand,
      authenticated.input.commandPort,
      [request],
    );
  } catch {
    fail('FAIL', 'ARTIFACT_BUILD_FAILED');
  }
  if (validateCommandPass(candidate, commandId)) return;
  const normalized = normalizePortFailure(candidate, 'FAIL', 'ARTIFACT_BUILD_FAILED');
  fail(normalized.status, normalized.code);
}

async function invokeWrite(authenticated, memberId, bytes) {
  const request = Object.freeze({ protocolVersion: PROTOCOL, memberId, bytes });
  let candidate;
  try {
    candidate = await Reflect.apply(
      authenticated.port.writeOutputMember,
      authenticated.input.commandPort,
      [request],
    );
  } catch {
    fail('FAIL', 'ARTIFACT_BUILD_FAILED');
  }
  if (validateWritePass(candidate, memberId, bytes)) return;
  const normalized = normalizePortFailure(candidate, 'FAIL', 'ARTIFACT_BUILD_FAILED');
  fail(normalized.status, normalized.code);
}

function splitUstarPath(relativePath) {
  if (Buffer.byteLength(relativePath) <= 100) return { name: relativePath, prefix: '' };
  for (let index = relativePath.length - 1; index > 0; index -= 1) {
    if (relativePath[index] !== '/') continue;
    const prefix = relativePath.slice(0, index);
    const name = relativePath.slice(index + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) {
      return { name, prefix };
    }
  }
  fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
}

function writeString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > length) fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
  bytes.copy(header, offset);
}

function writeOctal(header, offset, length, value) {
  const text = value.toString(8);
  if (text.length > length - 1) fail('FAIL', 'ARTIFACT_BUILD_FAILED');
  header.write(`${text.padStart(length - 1, '0')}\0`, offset, length, 'ascii');
}

function tarHeader(relativePath, size) {
  const { name, prefix } = splitUstarPath(relativePath);
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  writeString(header, 345, 155, prefix);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

async function collectSiteFiles(root, current = '', rootReal = null) {
  const resolvedRoot = rootReal ?? await realpath(root);
  const absolute = current === '' ? root : path.join(root, ...current.split('/'));
  const directoryStat = await lstat(absolute);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
  }
  const files = [];
  const entries = await readdir(absolute, { withFileTypes: true });
  entries.sort((left, right) => ordinalCompare(left.name, right.name));
  const folded = new Set();
  for (const entry of entries) {
    if (!safeName(entry.name) || folded.has(entry.name.toLowerCase())) {
      fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
    }
    folded.add(entry.name.toLowerCase());
    const relativePath = current === '' ? entry.name : `${current}/${entry.name}`;
    const child = path.join(root, ...relativePath.split('/'));
    const before = await lstat(child);
    if (before.isSymbolicLink()) fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
    const resolved = await realpath(child);
    if (!contained(resolvedRoot, resolved)) fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
    if (before.isDirectory()) files.push(...await collectSiteFiles(root, relativePath, resolvedRoot));
    else if (before.isFile() && before.nlink === 1) {
      const bytes = await readFile(child);
      const after = await lstat(child);
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
        fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
      }
      files.push({ relativePath, bytes });
    } else fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
  }
  return files;
}

async function buildSiteArtifact(siteOutput, sitePayloadDigest) {
  const files = await collectSiteFiles(siteOutput);
  const chunks = [];
  for (const file of files) {
    chunks.push(tarHeader(file.relativePath, file.bytes.length), file.bytes);
    const padding = (512 - file.bytes.length % 512) % 512;
    if (padding !== 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  const tarBytes = Buffer.concat(chunks);
  const bytes = Uint8Array.from(gzipSync(tarBytes, {
    level: zlibConstants.Z_BEST_COMPRESSION,
    mtime: 0,
    portable: true,
  }));
  return Object.freeze({
    kind: 'site',
    logicalTarget: 'web',
    relativePath: 'site/site.tar.gz',
    canonicalContentDigest: sitePayloadDigest,
    transportDigest: sha256Bytes(bytes),
    sizeBytes: bytes.byteLength,
    bytes,
  });
}

export async function buildArtifactSetInternal(args, collectValidatedRepositoryUnits) {
  try {
    if (typeof collectValidatedRepositoryUnits !== 'function' || utilTypes.isProxy(collectValidatedRepositoryUnits)) {
      fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
    }
    const authenticated = authenticateArgs(args);
    const manifestPath = path.join(
      authenticated.workspace.exportRoot,
      'dev',
      'verification',
      'verification-manifest.v1.json',
    );
    let manifestBytes;
    let repositoryManifest;
    try {
      manifestBytes = await readFile(manifestPath);
      if (sha256Bytes(manifestBytes) !== authenticated.identity.verifierManifestDigest) {
        fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
      }
      repositoryManifest = JSON.parse(manifestBytes.toString('utf8'));
    } catch (error) {
      if (error instanceof SetBuildError) throw error;
      fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
    }
    const inventoryResult = collectValidatedRepositoryUnits(repositoryManifest);
    if (inventoryResult?.status !== 'PASS') fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');

    for (const commandId of SOURCE_ARTIFACT_COMMAND_IDS) {
      await invokeCommand(authenticated, commandId);
    }

    let sitePayloadDigest;
    try {
      sitePayloadDigest = await computeHostedSitePayloadDigest(authenticated.workspace.siteOutput);
    } catch (error) {
      if (recognizedHostedSitePathFailure(error)) {
        fail('BLOCKED', 'ARTIFACT_PATH_UNSAFE');
      }
      fail('FAIL', 'ARTIFACT_BUILD_FAILED');
    }
    const identityResult = await writeHostedSiteBuildIdentity({
      outputDir: authenticated.workspace.siteOutput,
      sourceRevision: authenticated.identity.sourceRevision,
      sitePayloadDigest,
      verifierManifestDigest: authenticated.identity.verifierManifestDigest,
    });
    if (identityResult.status !== 'PASS') {
      const normalized = normalizeInternalFailure(identityResult);
      fail(normalized.status, normalized.code);
    }
    const siteArtifact = await buildSiteArtifact(authenticated.workspace.siteOutput, sitePayloadDigest);

    const releaseFunctions = [];
    const testOnlyFunctions = [];
    for (const unit of [
      ...inventoryResult.value.releaseUnits,
      ...inventoryResult.value.testOnlyUnits,
    ]) {
      const artifactResult = await buildFunctionArtifact({
        exportRoot: authenticated.workspace.exportRoot,
        revision: authenticated.identity.sourceRevision,
        unit: {
          logicalId: unit.logicalId,
          sourcePath: unit.sourcePath,
          runtime: unit.runtime,
          entrypoint: unit.entrypoint,
        },
      });
      if (artifactResult.status !== 'PASS') {
        const normalized = normalizeInternalFailure(artifactResult);
        fail(normalized.status, normalized.code);
      }
      if (unit.testOnly) testOnlyFunctions.push(artifactResult.value);
      else releaseFunctions.push(artifactResult.value);
    }

    const allArtifacts = [...releaseFunctions, ...testOnlyFunctions, siteArtifact];
    const sourcePaths = new Map([
      ...inventoryResult.value.releaseUnits,
      ...inventoryResult.value.testOnlyUnits,
    ].map((unit) => [unit.logicalId, unit.sourcePath]));
    const manifestEntries = allArtifacts.map((artifact) => ({
      kind: artifact.kind,
      logicalTarget: artifact.logicalTarget,
      sourcePath: artifact.kind === 'site' ? 'src/web' : sourcePaths.get(artifact.logicalTarget),
      relativePath: artifact.relativePath,
      canonicalContentDigest: artifact.canonicalContentDigest,
      transportDigest: artifact.transportDigest,
      sizeBytes: artifact.sizeBytes,
    })).sort((left, right) => ordinalCompare(
      `${left.kind}\0${left.logicalTarget}`,
      `${right.kind}\0${right.logicalTarget}`,
    ));
    const artifactManifest = createArtifactManifest({
      candidateIdentity: {
        kind: 'git-revision',
        candidateRevision: authenticated.identity.sourceRevision,
        candidateSourceTreeDigest: authenticated.identity.sourceTreeDigest,
      },
      verificationManifestDigest: authenticated.identity.verifierManifestDigest,
      entries: manifestEntries,
    });
    const handoffResult = createHostedArtifactHandoff({
      revision: authenticated.identity.sourceRevision,
      manifest: artifactManifest,
      github: authenticated.github,
    });
    if (handoffResult.status !== 'PASS') fail('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');

    await invokeWrite(authenticated, 'site:web', siteArtifact.bytes);
    for (const artifact of releaseFunctions) {
      await invokeWrite(authenticated, `function:${artifact.logicalTarget}`, artifact.bytes);
    }
    for (const artifact of testOnlyFunctions) {
      await invokeWrite(authenticated, `function:${artifact.logicalTarget}`, artifact.bytes);
    }
    await invokeWrite(
      authenticated,
      'metadata:artifact-manifest',
      Buffer.from(`${canonicalJson(artifactManifest)}\n`, 'utf8'),
    );
    await invokeWrite(
      authenticated,
      'metadata:artifact-handoff',
      Buffer.from(`${canonicalJson(handoffResult.value)}\n`, 'utf8'),
    );
    return result('PASS', null);
  } catch (error) {
    if (error instanceof SetBuildError) return result(error.status, null, error.code);
    return result('FAIL', null, 'ARTIFACT_BUILD_FAILED');
  }
}
