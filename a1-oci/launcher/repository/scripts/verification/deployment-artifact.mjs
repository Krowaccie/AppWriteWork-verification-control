import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { constants as zlibConstants, gzipSync } from 'node:zlib';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';

const FULL_REVISION = /^[0-9a-f]{40}$/u;
const LOGICAL_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const RUNNER_ID = 'verification-runner-py';
const RUNNER_IDENTITY_PATH = '.verification/runner-build-identity.v1.json';
const RUNNER_REQUIREMENTS_DIGEST =
  'sha256:4ac778533d3b8a0b44039593ee4289da885804f1c91ef5d5a8263843f44f8b31';
const RUNNER_REQUIRED_MEMBERS = Object.freeze([
  'bounded_transport.py',
  'fixture_cleanup.py',
  'fixture_provider.py',
  'main.py',
  'provider-contract/test-cloud.provider-contract.v1.json',
  'provider_contract.py',
  'protocol/request.v1.schema.json',
  'protocol/response.v1.schema.json',
  'protocol/scenarios.v1.schema.json',
  'requirements.txt',
]);
const RUNNER_FORBIDDEN_SOURCE = /\.(?:cjs|cmd|exe|js|jsx|mjs|ps1|ts|tsx)$/iu;
const ARG_KEYS = Object.freeze(['exportRoot', 'revision', 'unit']);
const UNIT_KEYS = Object.freeze(['entrypoint', 'logicalId', 'runtime', 'sourcePath']);
const DIAGNOSTIC_MESSAGES = Object.freeze({
  ARTIFACT_REVISION_INVALID: 'Function artifact requires an existing full immutable Git revision.',
  ARTIFACT_PATH_UNSAFE: 'Function artifact source contains an unsafe path, object, or archive collision.',
  ARTIFACT_BUILD_FAILED: 'Function artifact could not be built from the immutable Git revision.',
  ARTIFACT_SCHEMA_INVALID: 'Function artifact input does not match the closed contract.',
});

class ArtifactPathError extends Error {}
class ArtifactBuildError extends Error {}

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function operationResult(status, value, code = null) {
  const diagnostics = code === null
    ? Object.freeze([])
    : Object.freeze([Object.freeze({
      code,
      safeMessage: DIAGNOSTIC_MESSAGES[code],
      retryable: false,
    })]);
  return Object.freeze({ status, value, diagnostics });
}

function blocked(code) {
  return operationResult('BLOCKED', null, code);
}

function failed(code) {
  return operationResult('FAIL', null, code);
}

function exactDataObject(value, expectedKeys) {
  try {
    if (utilTypes.isProxy(value) || value === null || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== 'string')) return null;
    const actual = [...ownKeys].sort(ordinalCompare);
    const expected = [...expectedKeys].sort(ordinalCompare);
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      return null;
    }
    const copy = {};
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

function safeRepositoryPath(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 512
    || value.includes('\\')
    || /[\u0000-\u001f\u007f]/u.test(value)
    || path.posix.isAbsolute(value)
    || path.win32.isAbsolute(value)
  ) return false;
  const segments = value.split('/');
  return segments.every((segment) => segment !== '' && segment !== '.' && segment !== '..')
    && path.posix.normalize(value) === value;
}

function readInput(value) {
  const args = exactDataObject(value, ARG_KEYS);
  if (args === null) return { error: 'ARTIFACT_SCHEMA_INVALID' };
  if (
    typeof args.exportRoot !== 'string'
    || !path.isAbsolute(args.exportRoot)
    || args.exportRoot.includes('\0')
  ) return { error: 'ARTIFACT_SCHEMA_INVALID' };
  if (typeof args.revision !== 'string' || !FULL_REVISION.test(args.revision)) {
    return { error: 'ARTIFACT_REVISION_INVALID' };
  }
  const unit = exactDataObject(args.unit, UNIT_KEYS);
  if (unit === null) return { error: 'ARTIFACT_SCHEMA_INVALID' };
  if (
    typeof unit.logicalId !== 'string'
    || !LOGICAL_ID.test(unit.logicalId)
    || unit.runtime !== 'python-3.12'
    || unit.entrypoint !== 'main.py'
  ) return { error: 'ARTIFACT_SCHEMA_INVALID' };
  if (!safeRepositoryPath(unit.sourcePath)) return { error: 'ARTIFACT_PATH_UNSAFE' };
  if (unit.sourcePath !== `src/functions/${unit.logicalId}`) {
    return { error: 'ARTIFACT_SCHEMA_INVALID' };
  }
  return { exportRoot: args.exportRoot, revision: args.revision, unit: Object.freeze(unit) };
}

function contained(rootReal, candidateReal) {
  const relative = path.relative(rootReal, candidateReal);
  return relative === '' || (
    !path.isAbsolute(relative)
    && relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
  );
}

function sameFile(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.nlink === after.nlink
    && before.size === after.size
    && before.mtimeMs === after.mtimeMs;
}

async function collectDirectory(root, archivePrefix, exportReal) {
  const rootStat = await lstat(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new ArtifactPathError();
  const rootReal = await realpath(root);
  if (!contained(exportReal, rootReal)) throw new ArtifactPathError();
  const output = [];
  const foldedPaths = new Set();

  async function visit(directory, relativeDirectory) {
    const beforeDirectory = await lstat(directory);
    if (beforeDirectory.isSymbolicLink() || !beforeDirectory.isDirectory()) {
      throw new ArtifactPathError();
    }
    const directoryReal = await realpath(directory);
    if (!contained(rootReal, directoryReal) || !contained(exportReal, directoryReal)) {
      throw new ArtifactPathError();
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => ordinalCompare(left.name, right.name));
    const foldedNames = new Set();
    for (const entry of entries) {
      if (!safeRepositoryPath(entry.name)) throw new ArtifactPathError();
      const foldedName = entry.name.toLowerCase();
      if (foldedNames.has(foldedName)) throw new ArtifactPathError();
      foldedNames.add(foldedName);
      const relativePath = relativeDirectory === ''
        ? entry.name
        : `${relativeDirectory}/${entry.name}`;
      const absolute = path.join(root, ...relativePath.split('/'));
      const before = await lstat(absolute);
      if (before.isSymbolicLink()) throw new ArtifactPathError();
      const resolved = await realpath(absolute);
      if (!contained(rootReal, resolved) || !contained(exportReal, resolved)) {
        throw new ArtifactPathError();
      }
      if (before.isDirectory()) {
        await visit(absolute, relativePath);
        continue;
      }
      if (!before.isFile() || before.nlink !== 1) throw new ArtifactPathError();
      const bytes = await readFile(absolute);
      const after = await lstat(absolute);
      if (!sameFile(before, after)) throw new ArtifactPathError();
      const archivePath = archivePrefix === ''
        ? relativePath
        : `${archivePrefix}/${relativePath}`;
      if (!safeRepositoryPath(archivePath)) throw new ArtifactPathError();
      const foldedArchivePath = archivePath.toLowerCase();
      if (foldedPaths.has(foldedArchivePath)) throw new ArtifactPathError();
      foldedPaths.add(foldedArchivePath);
      output.push({ archivePath, content: bytes });
    }
  }

  await visit(root, '');
  return output;
}

function splitUstarPath(archivePath) {
  const full = Buffer.from(archivePath, 'utf8');
  if (full.length <= 100) return { name: archivePath, prefix: '' };
  for (let index = archivePath.length - 1; index > 0; index -= 1) {
    if (archivePath[index] !== '/') continue;
    const prefix = archivePath.slice(0, index);
    const name = archivePath.slice(index + 1);
    if (Buffer.byteLength(prefix, 'utf8') <= 155 && Buffer.byteLength(name, 'utf8') <= 100) {
      return { name, prefix };
    }
  }
  throw new ArtifactPathError();
}

function writeTarString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > length) throw new ArtifactPathError();
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  const digits = value.toString(8);
  if (digits.length > length - 1) throw new ArtifactBuildError();
  header.write(`${digits.padStart(length - 1, '0')}\0`, offset, length, 'ascii');
}

function createTarHeader(archivePath, size) {
  const { name, prefix } = splitUstarPath(archivePath);
  const header = Buffer.alloc(512);
  writeTarString(header, 0, 100, name);
  writeTarOctal(header, 100, 8, 0o644);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, size);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  writeTarString(header, 345, 155, prefix);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  const checksumDigits = checksum.toString(8);
  if (checksumDigits.length > 6) throw new ArtifactBuildError();
  header.write(`${checksumDigits.padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

function buildCanonicalTar(entries) {
  const chunks = [];
  for (const entry of entries) {
    chunks.push(createTarHeader(entry.archivePath, entry.content.length));
    chunks.push(entry.content);
    const padding = (512 - (entry.content.length % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function ensureArchiveNamespace(entries) {
  entries.sort((left, right) => ordinalCompare(left.archivePath, right.archivePath));
  const paths = new Set();
  const folded = new Set();
  for (const { archivePath } of entries) {
    const lower = archivePath.toLowerCase();
    if (paths.has(archivePath) || folded.has(lower)) throw new ArtifactPathError();
    const segments = archivePath.split('/');
    for (let length = 1; length < segments.length; length += 1) {
      const ancestor = segments.slice(0, length).join('/');
      if (paths.has(ancestor) || folded.has(ancestor.toLowerCase())) {
        throw new ArtifactPathError();
      }
    }
    paths.add(archivePath);
    folded.add(lower);
  }
}

function validateRunnerArchiveEntries(entries) {
  const byPath = new Map(entries.map(({ archivePath, content }) => [archivePath, content]));
  for (const required of RUNNER_REQUIRED_MEMBERS) {
    if (!byPath.has(required)) throw new ArtifactBuildError();
  }
  if (sha256Bytes(byPath.get('requirements.txt')) !== RUNNER_REQUIREMENTS_DIGEST) {
    throw new ArtifactBuildError();
  }
  for (const { archivePath } of entries) {
    if (RUNNER_FORBIDDEN_SOURCE.test(archivePath)) throw new ArtifactPathError();
  }
}

export async function buildFunctionArtifact(args) {
  const input = readInput(args);
  if (input.error) return blocked(input.error);
  try {
    const exportStat = await lstat(input.exportRoot);
    if (exportStat.isSymbolicLink() || !exportStat.isDirectory()) throw new ArtifactPathError();
    const exportReal = await realpath(input.exportRoot);
    const functionRoot = path.join(input.exportRoot, ...input.unit.sourcePath.split('/'));
    const sharedRoot = path.join(input.exportRoot, 'src', 'shared_py');
    const functionEntries = await collectDirectory(functionRoot, '', exportReal);
    const sharedEntries = await collectDirectory(sharedRoot, 'shared_py', exportReal);
    if (
      functionEntries.length === 0
      || sharedEntries.length === 0
      || !functionEntries.some(({ archivePath }) => archivePath === input.unit.entrypoint)
    ) throw new ArtifactBuildError();
    const entries = [...functionEntries, ...sharedEntries];
    if (
      input.unit.logicalId === RUNNER_ID
      && entries.some(({ archivePath }) => archivePath === RUNNER_IDENTITY_PATH)
    ) throw new ArtifactPathError();
    if (input.unit.logicalId === RUNNER_ID) {
      validateRunnerArchiveEntries(entries);
      entries.push({
        archivePath: RUNNER_IDENTITY_PATH,
        content: Buffer.from(`${canonicalJson({
          schemaVersion: 'verification-runner-build-identity.v1',
          sourceRevision: input.revision,
        })}\n`, 'utf8'),
      });
    }
    ensureArchiveNamespace(entries);
    const tarBytes = buildCanonicalTar(entries);
    const compressed = gzipSync(tarBytes, {
      level: zlibConstants.Z_BEST_COMPRESSION,
      mtime: 0,
      portable: true,
    });
    const bytes = Uint8Array.from(compressed);
    return operationResult('PASS', Object.freeze({
      kind: 'function',
      logicalTarget: input.unit.logicalId,
      relativePath: `functions/${input.unit.logicalId}.tar.gz`,
      canonicalContentDigest: sha256Bytes(tarBytes),
      transportDigest: sha256Bytes(bytes),
      sizeBytes: bytes.byteLength,
      bytes,
    }));
  } catch (error) {
    if (error instanceof ArtifactPathError) return blocked('ARTIFACT_PATH_UNSAFE');
    return failed('ARTIFACT_BUILD_FAILED');
  }
}
