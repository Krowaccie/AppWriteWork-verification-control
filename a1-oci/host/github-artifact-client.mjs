import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  chown,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import { uploadArtifact as officialUploadArtifact } from '../vendor/actions-artifact/dist/official-client.bundle.mjs';
import { SOURCE_ARTIFACT_UPLOAD_MEMBERS } from './validated-artifact-upload.mjs';

const ARTIFACT_NAME = /^verification-artifacts-[0-9a-f]{40}$/u;
const DIRECTORY_MODE = 0o700;
const MEMBER_MODE = 0o600;

function fail() {
  throw new Error('ARTIFACT_UPLOAD_CLIENT_INVALID');
}

function validCall(artifactName, files, rootDirectory, options) {
  return ARTIFACT_NAME.test(artifactName)
    && Array.isArray(files)
    && files.length === SOURCE_ARTIFACT_UPLOAD_MEMBERS.length
    && typeof rootDirectory === 'string'
    && path.isAbsolute(rootDirectory)
    && options !== null
    && typeof options === 'object'
    && Reflect.ownKeys(options).length === 1
    && options.compressionLevel === 0;
}

function directPrivate(stat, mode) {
  const observedMode = stat.mode & 0o777;
  return !stat.isSymbolicLink()
    && stat.isFile()
    && stat.nlink === 1
    && (observedMode === mode || (process.platform === 'win32' && observedMode === 0o666));
}

function directPrivateDirectory(stat) {
  const observedMode = stat.mode & 0o777;
  return !stat.isSymbolicLink()
    && stat.isDirectory()
    && (observedMode === DIRECTORY_MODE || (process.platform === 'win32' && observedMode === 0o666));
}

async function exactDirectDirectory(directory) {
  const resolved = path.resolve(directory);
  const canonicalDirectory = path.resolve(await realpath(directory));
  return (canonicalDirectory === resolved || process.platform === 'win32')
    && directPrivateDirectory(await lstat(resolved));
}

function validOwner(ownerUid, ownerGid) {
  const bothNull = ownerUid === null && ownerGid === null;
  const bothIntegers = Number.isSafeInteger(ownerUid)
    && ownerUid > 0
    && ownerUid !== 1000
    && Number.isSafeInteger(ownerGid)
    && ownerGid > 0;
  return bothNull || bothIntegers;
}

async function assignOwner(target, ownerUid, ownerGid) {
  if (ownerUid !== null) await chown(target, ownerUid, ownerGid);
}

async function copyMember({ digest, ownerGid, ownerUid, relativePath, source, target }) {
  const noFollow = Number.isInteger(fsConstants.O_NOFOLLOW) ? fsConstants.O_NOFOLLOW : 0;
  const sourceHandle = await open(source, fsConstants.O_RDONLY | noFollow);
  let targetHandle = null;
  try {
    const before = await sourceHandle.stat();
    if (!directPrivate(before, MEMBER_MODE)) fail();
    targetHandle = await open(
      target,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
      MEMBER_MODE,
    );
    await assignOwner(target, ownerUid, ownerGid);
    await chmod(target, MEMBER_MODE);
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    digest.update(`${relativePath}\0${before.size}\0`, 'utf8');
    while (offset < before.size) {
      const { bytesRead } = await sourceHandle.read(
        buffer,
        0,
        Math.min(buffer.byteLength, before.size - offset),
        offset,
      );
      if (!Number.isSafeInteger(bytesRead) || bytesRead <= 0) fail();
      digest.update(buffer.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const result = await targetHandle.write(
          buffer,
          written,
          bytesRead - written,
          offset + written,
        );
        if (!Number.isSafeInteger(result.bytesWritten) || result.bytesWritten <= 0) fail();
        written += result.bytesWritten;
      }
      offset += bytesRead;
    }
    const after = await sourceHandle.stat();
    if (
      !directPrivate(after, MEMBER_MODE)
      || after.dev !== before.dev
      || after.ino !== before.ino
      || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs
    ) fail();
    await targetHandle.sync();
    await targetHandle.close();
    targetHandle = null;
    if (!directPrivate(await lstat(target), MEMBER_MODE)) fail();
    digest.update('\0', 'utf8');
    return before.size;
  } finally {
    await sourceHandle.close();
    if (targetHandle !== null) await targetHandle.close();
  }
}

export function createGithubArtifactClient({
  runtimeBinding,
  uploadOperation = null,
} = {}) {
  if (
    runtimeBinding === null
    || typeof runtimeBinding !== 'object'
    || !Object.isFrozen(runtimeBinding)
    || Reflect.ownKeys(runtimeBinding).length !== 1
    || typeof runtimeBinding.runUpload !== 'function'
    || (uploadOperation !== null && typeof uploadOperation !== 'function')
  ) fail();

  return Object.freeze({
    async uploadArtifact(artifactName, files, rootDirectory, options) {
      if (
        !validCall(artifactName, files, rootDirectory, options)
      ) fail();
      const args = { artifactName, files, rootDirectory };
      return runtimeBinding.runUpload(() => uploadOperation === null
        ? officialUploadArtifact(args)
        : uploadOperation(args));
    },
  });
}

export function createFilesystemArtifactClient({
  outputRoot,
  ownerUid = null,
  ownerGid = null,
} = {}) {
  if (typeof outputRoot !== 'string' || !path.isAbsolute(outputRoot) || !validOwner(ownerUid, ownerGid)) fail();

  return Object.freeze({
    async uploadArtifact(artifactName, files, rootDirectory, options) {
      if (!validCall(artifactName, files, rootDirectory, options)) fail();
      const sourceRoot = path.resolve(rootDirectory);
      const destinationRoot = path.resolve(outputRoot);
      if (
        sourceRoot === destinationRoot
        || sourceRoot.startsWith(`${destinationRoot}${path.sep}`)
        || destinationRoot.startsWith(`${sourceRoot}${path.sep}`)
        || !(await exactDirectDirectory(sourceRoot))
        || !(await exactDirectDirectory(destinationRoot))
        || (await readdir(destinationRoot)).length !== 0
      ) fail();

      const expectedSources = SOURCE_ARTIFACT_UPLOAD_MEMBERS.map(({ relativePath }) => (
        path.join(sourceRoot, ...relativePath.split('/'))
      ));
      for (let index = 0; index < expectedSources.length; index += 1) {
        if (path.resolve(files[index]) !== expectedSources[index]) fail();
        if (!directPrivate(await lstat(expectedSources[index]), MEMBER_MODE)) fail();
      }

      const digest = createHash('sha256');
      let totalBytes = 0;
      for (let index = 0; index < SOURCE_ARTIFACT_UPLOAD_MEMBERS.length; index += 1) {
        const { relativePath } = SOURCE_ARTIFACT_UPLOAD_MEMBERS[index];
        const target = path.join(destinationRoot, ...relativePath.split('/'));
        const parent = path.dirname(target);
        await mkdir(parent, { mode: DIRECTORY_MODE, recursive: true });
        await assignOwner(parent, ownerUid, ownerGid);
        await chmod(parent, DIRECTORY_MODE);
        if (!(await exactDirectDirectory(parent))) fail();
        totalBytes += await copyMember({
          digest,
          ownerGid,
          ownerUid,
          relativePath,
          source: expectedSources[index],
          target,
        });
      }
      if (!Number.isSafeInteger(totalBytes) || totalBytes <= 0) fail();
      return Object.freeze({
        digest: `sha256:${digest.digest('hex')}`,
        id: 1,
        size: totalBytes,
      });
    },
  });
}
