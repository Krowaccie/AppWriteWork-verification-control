import { constants as fsConstants } from 'node:fs';
import {
  chmod as nodeChmod,
  lstat as nodeLstat,
  mkdir as nodeMkdir,
  mkdtemp as nodeMkdtemp,
  open as nodeOpen,
  readdir as nodeReaddir,
  realpath as nodeRealpath,
  rm as nodeRm,
} from 'node:fs/promises';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

const MEBIBYTE = 1024 * 1024;
const MEMBER_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ARTIFACT_NAME = /^verification-artifacts-[0-9a-f]{40}$/u;
const EMPTY_DIAGNOSTICS = Object.freeze([]);
const PASS = Object.freeze({ diagnostics: EMPTY_DIAGNOSTICS, status: 'PASS', value: null });
const FAIL = Object.freeze({ diagnostics: EMPTY_DIAGNOSTICS, status: 'FAIL', value: null });
const CHUNK_KEYS = Object.freeze([
  'bytes',
  'endOfArtifact',
  'endOfMember',
  'memberId',
  'offset',
]);
const DETAILS_KEYS = Object.freeze([
  'artifactManifestDigest',
  'artifactName',
  'memberCount',
]);
const RUNTIME_KEYS = Object.freeze([
  'assertAvailable',
  'operatingSystem',
  'protocolVersion',
]);
const FILESYSTEM_KEYS = Object.freeze([
  'chmod',
  'lstat',
  'mkdir',
  'mkdtemp',
  'open',
  'readdir',
  'realpath',
  'rm',
]);

export const SOURCE_ARTIFACT_UPLOAD_LIMITS = Object.freeze({
  maxArtifactBytes: 256 * MEBIBYTE,
  maxMemberBytes: 128 * MEBIBYTE,
});

const PRODUCT_FUNCTIONS = Object.freeze([
  'api-keys-py',
  'api-router-py',
  'billing-cron-py',
  'billing-py',
  'billing-webhook-py',
  'branch-py',
  'cache-cleanup-cron-py',
  'catalog-py',
  'chat-py',
  'cleanup-cron-py',
  'connections-py',
  'finance-sync-sec-py',
  'finance-sync-wb-py',
  'flowise-runner-py',
  'mcp-cleanup-cron-py',
  'mcp-gateway-py',
  'project-public-links-py',
  'project-public-read-py',
  'project-snapshots-py',
  'runs-cancel-py',
  'runs-clear-py',
  'runs-create-py',
  'runs-detail-py',
  'runs-list-py',
  'runs-status-py',
  'runs-steps-py',
  'sec-cache-builder-py',
  'sharing-py',
  'smtp-diagnostic-py',
  'telemetry-py',
  'usage-cron-py',
  'usage-py',
  'validate-py',
  'verification-email-py',
  'worker-cron-py',
]);

function member(memberId, relativePath) {
  return Object.freeze({ memberId, relativePath });
}

export const SOURCE_ARTIFACT_UPLOAD_MEMBERS = Object.freeze([
  member('site:web', 'site/site.tar.gz'),
  ...PRODUCT_FUNCTIONS.map((logicalId) => member(
    `function:${logicalId}`,
    `functions/${logicalId}.tar.gz`,
  )),
  member('function:verification-runner-py', 'functions/verification-runner-py.tar.gz'),
  member('metadata:artifact-manifest', 'artifact-manifest.v1.json'),
  member('metadata:artifact-handoff', 'artifact-handoff.v1.json'),
]);

const NODE_FILESYSTEM = Object.freeze({
  chmod: nodeChmod,
  lstat: nodeLstat,
  mkdir: nodeMkdir,
  mkdtemp: nodeMkdtemp,
  open: nodeOpen,
  readdir: nodeReaddir,
  realpath: nodeRealpath,
  rm: nodeRm,
});

function exactRecord(value, keys, { frozen = true } = {}) {
  if (
    value === null
    || typeof value !== 'object'
    || utilTypes.isProxy(value)
    || (frozen && !Object.isFrozen(value))
  ) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== 'string')) return false;
  const sorted = ownKeys.slice().sort();
  for (let index = 0; index < keys.length; index += 1) {
    if (sorted[index] !== keys[index]) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, sorted[index]);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}

function exactCapability(value, keys) {
  return exactRecord(value, keys)
    && keys.every((key) => typeof value[key] === 'function');
}

function validFilesystem(value) {
  return exactCapability(value, FILESYSTEM_KEYS);
}

function validOfficialArtifactClient(value) {
  return value !== null
    && typeof value === 'object'
    && Object.isFrozen(value)
    && !utilTypes.isProxy(value)
    && typeof value.uploadArtifact === 'function';
}

function validRuntimeBinding(value) {
  return exactRecord(value, RUNTIME_KEYS)
    && value.operatingSystem === 'linux'
    && value.protocolVersion === 'github-actions-artifact-runtime.v1'
    && typeof value.assertAvailable === 'function';
}

function available(result) {
  return exactRecord(result, ['diagnostics', 'status', 'value'])
    && result.status === 'PASS'
    && result.value === null
    && Array.isArray(result.diagnostics)
    && Object.isFrozen(result.diagnostics)
    && result.diagnostics.length === 0;
}

function exactDetails(value) {
  return exactRecord(value, DETAILS_KEYS)
    && DIGEST.test(value.artifactManifestDigest)
    && ARTIFACT_NAME.test(value.artifactName)
    && value.memberCount === SOURCE_ARTIFACT_UPLOAD_MEMBERS.length;
}

function exactChunk(value) {
  if (
    !exactRecord(value, CHUNK_KEYS)
    || !utilTypes.isUint8Array(value.bytes)
    || utilTypes.isProxy(value.bytes)
    || utilTypes.isSharedArrayBuffer(value.bytes.buffer)
    || !Number.isSafeInteger(value.offset)
    || value.offset < 0
    || typeof value.endOfArtifact !== 'boolean'
    || typeof value.endOfMember !== 'boolean'
    || typeof value.memberId !== 'string'
  ) return false;
  return value.bytes.byteLength > 0;
}

function within(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function directPrivateFile(fileSystem, target) {
  const stat = await fileSystem.lstat(target);
  if (stat.isSymbolicLink() || !stat.isFile() || (stat.mode & 0o777) !== MEMBER_MODE) return false;
  return path.resolve(await fileSystem.realpath(target)) === path.resolve(target);
}

async function closeHandle(state) {
  if (state.handle === null) return true;
  const handle = state.handle;
  state.handle = null;
  try {
    await handle.close();
    return true;
  } catch {
    return false;
  }
}

async function collectStageFiles(fileSystem, root, current = root, files = []) {
  const entries = await fileSystem.readdir(current, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  for (const entry of entries) {
    const target = path.join(current, entry.name);
    const stat = await fileSystem.lstat(target);
    if (stat.isSymbolicLink()) throw new TypeError('Linked artifact members are forbidden.');
    if (stat.isDirectory()) {
      await collectStageFiles(fileSystem, root, target, files);
    } else if (stat.isFile()) {
      files.push(path.relative(root, target).split(path.sep).join('/'));
    } else {
      throw new TypeError('Only direct regular artifact members are allowed.');
    }
  }
  return files;
}

function validUploadResult(value) {
  return exactRecord(value, ['digest', 'id', 'size'], { frozen: false })
    && DIGEST.test(value.digest)
    && Number.isSafeInteger(value.id)
    && value.id > 0
    && Number.isSafeInteger(value.size)
    && value.size > 0;
}

function createSession({
  artifactName,
  fileSystem,
  officialArtifactClient,
  stagingRoot,
}) {
  const expectedFiles = SOURCE_ARTIFACT_UPLOAD_MEMBERS.map(({ relativePath }) => (
    path.join(stagingRoot, ...relativePath.split('/'))
  ));
  const state = {
    abortPromise: null,
    cleanupPromise: null,
    cleanupSucceeded: false,
    completePromise: null,
    currentBytes: 0,
    currentPath: null,
    fileSystem,
    finalizedFiles: [],
    handle: null,
    memberIndex: 0,
    officialArtifactClient,
    poisoned: false,
    stagingRoot,
    totalBytes: 0,
    writeBusy: false,
  };

  function cleanup() {
    if (state.cleanupPromise !== null) return state.cleanupPromise;
    state.cleanupPromise = (async () => {
      const closed = await closeHandle(state);
      let removed = false;
      try {
        await state.fileSystem.rm(state.stagingRoot, { force: true, recursive: true });
        try {
          await state.fileSystem.lstat(state.stagingRoot);
        } catch (error) {
          removed = error !== null && typeof error === 'object' && error.code === 'ENOENT';
        }
      } catch {
        removed = false;
      }
      state.cleanupSucceeded = closed && removed;
      return state.cleanupSucceeded;
    })();
    return state.cleanupPromise;
  }

  async function poison() {
    state.poisoned = true;
    return FAIL;
  }

  async function openCurrentMember() {
    const target = expectedFiles[state.memberIndex];
    const parent = path.dirname(target);
    await state.fileSystem.mkdir(parent, { mode: DIRECTORY_MODE, recursive: true });
    const parentStat = await state.fileSystem.lstat(parent);
    if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) throw new TypeError('Unsafe artifact directory.');
    const noFollow = Number.isInteger(fsConstants.O_NOFOLLOW) ? fsConstants.O_NOFOLLOW : 0;
    state.handle = await state.fileSystem.open(
      target,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
      MEMBER_MODE,
    );
    state.currentPath = target;
    await state.fileSystem.chmod(target, MEMBER_MODE);
  }

  async function writeCopy(bytes, offset) {
    let written = 0;
    while (written < bytes.byteLength) {
      const result = await state.handle.write(
        bytes,
        written,
        bytes.byteLength - written,
        offset + written,
      );
      if (!Number.isSafeInteger(result.bytesWritten) || result.bytesWritten < 1) {
        throw new TypeError('Artifact member write did not advance.');
      }
      written += result.bytesWritten;
    }
  }

  async function writeMemberChunk(value) {
    if (
      state.writeBusy
      || state.poisoned
      || state.completePromise !== null
      || state.abortPromise !== null
      || state.memberIndex >= SOURCE_ARTIFACT_UPLOAD_MEMBERS.length
      || !exactChunk(value)
    ) return poison();
    const expected = SOURCE_ARTIFACT_UPLOAD_MEMBERS[state.memberIndex];
    const nextMemberBytes = state.currentBytes + value.bytes.byteLength;
    const nextTotalBytes = state.totalBytes + value.bytes.byteLength;
    const finalMember = state.memberIndex === SOURCE_ARTIFACT_UPLOAD_MEMBERS.length - 1;
    if (
      value.memberId !== expected.memberId
      || value.offset !== state.currentBytes
      || nextMemberBytes > SOURCE_ARTIFACT_UPLOAD_LIMITS.maxMemberBytes
      || nextTotalBytes > SOURCE_ARTIFACT_UPLOAD_LIMITS.maxArtifactBytes
      || value.endOfArtifact !== (value.endOfMember && finalMember)
    ) return poison();

    state.writeBusy = true;
    try {
      if (state.handle === null) await openCurrentMember();
      const copy = Uint8Array.from(value.bytes);
      await writeCopy(copy, state.currentBytes);
      state.currentBytes = nextMemberBytes;
      state.totalBytes = nextTotalBytes;
      if (value.endOfMember) {
        const target = state.currentPath;
        if (!(await closeHandle(state))) return poison();
        await state.fileSystem.chmod(target, MEMBER_MODE);
        if (!(await directPrivateFile(state.fileSystem, target))) return poison();
        state.finalizedFiles.push(target);
        state.currentBytes = 0;
        state.currentPath = null;
        state.memberIndex += 1;
      }
      return PASS;
    } catch {
      return poison();
    } finally {
      state.writeBusy = false;
    }
  }

  async function verifyStage() {
    if (
      state.poisoned
      || state.writeBusy
      || state.handle !== null
      || state.currentBytes !== 0
      || state.memberIndex !== SOURCE_ARTIFACT_UPLOAD_MEMBERS.length
      || state.finalizedFiles.length !== SOURCE_ARTIFACT_UPLOAD_MEMBERS.length
    ) return false;
    for (let index = 0; index < expectedFiles.length; index += 1) {
      if (
        path.resolve(state.finalizedFiles[index]) !== path.resolve(expectedFiles[index])
        || !(await directPrivateFile(state.fileSystem, expectedFiles[index]))
      ) return false;
    }
    const observedFiles = await collectStageFiles(state.fileSystem, state.stagingRoot);
    const expectedRelativePaths = SOURCE_ARTIFACT_UPLOAD_MEMBERS
      .map(({ relativePath }) => relativePath)
      .sort((left, right) => left.localeCompare(right, 'en'));
    return observedFiles.length === expectedRelativePaths.length
      && observedFiles.every((relativePath, index) => relativePath === expectedRelativePaths[index]);
  }

  function complete() {
    if (state.completePromise !== null) return state.completePromise;
    if (state.abortPromise !== null) return Promise.resolve(FAIL);
    state.completePromise = (async () => {
      let accepted = false;
      try {
        if (!(await verifyStage())) return FAIL;
        const result = await state.officialArtifactClient.uploadArtifact(
          artifactName,
          Object.freeze(expectedFiles.slice()),
          state.stagingRoot,
          Object.freeze({ compressionLevel: 0 }),
        );
        accepted = validUploadResult(result);
        return accepted ? PASS : FAIL;
      } catch {
        return FAIL;
      } finally {
        if (!(await cleanup())) accepted = false;
      }
    })().then((result) => (state.cleanupSucceeded && result === PASS ? PASS : FAIL));
    return state.completePromise;
  }

  function abortAndJoin() {
    if (state.abortPromise !== null) return state.abortPromise;
    state.abortPromise = (async () => {
      if (state.completePromise !== null) await state.completePromise;
      return (await cleanup()) ? PASS : FAIL;
    })();
    return state.abortPromise;
  }

  return Object.freeze({ abortAndJoin, complete, writeMemberChunk });
}

export function createValidatedArtifactUploadClient({
  candidateWorkspaceRoot,
  controllerTempRoot,
  fileSystem = NODE_FILESYSTEM,
  githubRuntimeBinding = null,
  officialArtifactClient,
} = {}) {
  if (
    typeof candidateWorkspaceRoot !== 'string'
    || !path.isAbsolute(candidateWorkspaceRoot)
    || typeof controllerTempRoot !== 'string'
    || !path.isAbsolute(controllerTempRoot)
    || !validFilesystem(fileSystem)
    || !validOfficialArtifactClient(officialArtifactClient)
  ) throw new TypeError('Validated artifact upload requires controller-owned dependencies.');

  async function openArtifact(details) {
    if (!exactDetails(details) || !validRuntimeBinding(githubRuntimeBinding)) return null;
    try {
      if (!available(await githubRuntimeBinding.assertAvailable())) return null;
      const candidateRoot = path.resolve(await fileSystem.realpath(candidateWorkspaceRoot));
      const tempRoot = path.resolve(await fileSystem.realpath(controllerTempRoot));
      const candidateStat = await fileSystem.lstat(candidateRoot);
      const tempStat = await fileSystem.lstat(tempRoot);
      if (
        candidateStat.isSymbolicLink()
        || !candidateStat.isDirectory()
        || tempStat.isSymbolicLink()
        || !tempStat.isDirectory()
      ) return null;
      const stagingRoot = path.resolve(await fileSystem.mkdtemp(
        path.join(tempRoot, 'source-artifact-upload-'),
      ));
      await fileSystem.chmod(stagingRoot, DIRECTORY_MODE);
      const stagingStat = await fileSystem.lstat(stagingRoot);
      if (
        stagingStat.isSymbolicLink()
        || !stagingStat.isDirectory()
        || within(candidateRoot, stagingRoot)
        || !within(tempRoot, stagingRoot)
        || path.dirname(stagingRoot) !== tempRoot
        || path.resolve(await fileSystem.realpath(stagingRoot)) !== stagingRoot
      ) {
        await fileSystem.rm(stagingRoot, { force: true, recursive: true });
        return null;
      }
      return createSession({
        artifactName: details.artifactName,
        fileSystem,
        officialArtifactClient,
        stagingRoot,
      });
    } catch {
      return null;
    }
  }

  return Object.freeze({ openArtifact });
}
