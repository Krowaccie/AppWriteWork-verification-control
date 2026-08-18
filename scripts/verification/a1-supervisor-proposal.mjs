import { createHash } from 'node:crypto';
import { constants as fsConstants, promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';

const MODULE_PATH = fileURLToPath(import.meta.url);
const DESCRIPTOR_PATH = fileURLToPath(new URL(
  '../../dev/verification/proposals/a1-supervisor-proposal.v1.json',
  import.meta.url,
));
const SOURCE_PATHS = Object.freeze([
  '.cargo/config.toml',
  'Cargo.lock',
  'Cargo.toml',
  'src/main.rs',
  'src/policy.rs',
  'src/protocol.rs',
  'src/workspace.rs',
  'tests/containment.rs',
  'tests/policy.rs',
  'tests/protocol.rs',
  'tests/workspace.rs',
]);
const OUTPUT_PATHS = Object.freeze([
  'dist/verification-supervisor',
  'dist.manifest.json',
]);
const ALL_PATHS = Object.freeze([...SOURCE_PATHS, ...OUTPUT_PATHS]);
const PROTOCOLS = Object.freeze([
  'source-artifact-posix-supervisor.v1',
  'source-artifact-posix-workspace-kernel.v1',
]);
const SERIALIZATION = 'path NUL mode NUL decimal-byte-length NUL lowercase-hex-sha256 LF';
const DESCRIPTOR_KEYS = Object.freeze([
  'build',
  'outputs',
  'protocols',
  'schemaVersion',
  'sourceInventory',
]);
const ENTRY_KEYS = Object.freeze(['bytes', 'mode', 'path', 'sha256']);
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const EXPECTED_DIRECTORIES = new Set(['.cargo', 'dist', 'src', 'tests']);
const MAX_INVENTORY_ENTRIES = ALL_PATHS.length + EXPECTED_DIRECTORIES.size + 1;
const MAX_DESCRIPTOR_BYTES = 16 * 1024;
const MAX_PROPOSAL_FILE_BYTES = 1024 * 1024;
const DIRECTORY_BUFFER_SIZE = 4;

function ordinalCompare(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactDataObject(value, keys, label) {
  if (!isPlainObject(value)) throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} must be a plain object.`);
  const actual = Reflect.ownKeys(value);
  if (actual.some((key) => typeof key === 'symbol')) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} cannot have symbol keys.`);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} accepts only enumerable data properties.`);
    }
  }
  const sortedActual = Object.keys(value).sort(ordinalCompare);
  const sortedExpected = [...keys].sort(ordinalCompare);
  if (
    sortedActual.length !== sortedExpected.length
    || sortedActual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} has an invalid shape.`);
  }
}

function assertDenseArray(value, length, label) {
  if (!Array.isArray(value) || value.length !== length) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} has an invalid length.`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} must be dense.`);
    }
  }
  if (Object.keys(value).some((key) => !/^(0|[1-9][0-9]*)$/u.test(key))) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label} cannot have named properties.`);
  }
}

function failure(code, message, relativePath = null) {
  return new A1SupervisorProposalError(code, message, relativePath);
}

export class A1SupervisorProposalError extends Error {
  constructor(code, message, relativePath = null) {
    super(message);
    this.name = 'A1SupervisorProposalError';
    this.code = code;
    this.relativePath = relativePath;
  }
}

function validateEntry(entry, expectedPath, expectedMode, label) {
  assertExactDataObject(entry, ENTRY_KEYS, label);
  if (entry.path !== expectedPath) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label}.path is not canonical.`, expectedPath);
  }
  if (entry.mode !== expectedMode) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label}.mode is not canonical.`, expectedPath);
  }
  if (!Number.isSafeInteger(entry.bytes) || entry.bytes < 0) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label}.bytes is invalid.`, expectedPath);
  }
  if (typeof entry.sha256 !== 'string' || !DIGEST_PATTERN.test(entry.sha256)) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', `${label}.sha256 is invalid.`, expectedPath);
  }
}

function validateTrackedDescriptor(descriptor) {
  assertExactDataObject(descriptor, DESCRIPTOR_KEYS, 'A1 supervisor descriptor');
  if (descriptor.schemaVersion !== 'a1-supervisor-proposal.v1') {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The descriptor schemaVersion is invalid.');
  }
  assertDenseArray(descriptor.protocols, 2, 'protocols');
  if (descriptor.protocols.some((value, index) => value !== PROTOCOLS[index])) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The protocol closure is invalid.');
  }

  assertExactDataObject(
    descriptor.sourceInventory,
    ['entries', 'fileCount', 'serialization', 'serializedBytes', 'treeDigest'],
    'sourceInventory',
  );
  if (descriptor.sourceInventory.fileCount !== SOURCE_PATHS.length) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'sourceInventory.fileCount is invalid.');
  }
  if (descriptor.sourceInventory.serialization !== SERIALIZATION) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'sourceInventory.serialization is invalid.');
  }
  if (descriptor.sourceInventory.serializedBytes !== 1021) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'sourceInventory.serializedBytes is invalid.');
  }
  if (!DIGEST_PATTERN.test(descriptor.sourceInventory.treeDigest)) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'sourceInventory.treeDigest is invalid.');
  }
  assertDenseArray(descriptor.sourceInventory.entries, SOURCE_PATHS.length, 'sourceInventory.entries');
  descriptor.sourceInventory.entries.forEach((entry, index) => {
    validateEntry(entry, SOURCE_PATHS[index], '100644', `sourceInventory.entries[${index}]`);
  });

  assertExactDataObject(descriptor.outputs, ['binary', 'distManifest'], 'outputs');
  validateEntry(descriptor.outputs.binary, OUTPUT_PATHS[0], '100755', 'outputs.binary');
  validateEntry(descriptor.outputs.distManifest, OUTPUT_PATHS[1], '100644', 'outputs.distManifest');

  assertExactDataObject(descriptor.build, ['profile', 'staticEvidence', 'target'], 'build');
  if (descriptor.build.target !== 'x86_64-unknown-linux-musl' || descriptor.build.profile !== 'release') {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The build tuple is invalid.');
  }
  assertExactDataObject(
    descriptor.build.staticEvidence,
    ['endianness', 'format', 'linkerContract', 'machine', 'programInterpreter'],
    'build.staticEvidence',
  );
  const expectedStaticEvidence = {
    endianness: 'little',
    format: 'ELF64',
    linkerContract: 'rust-lld -static -pie --no-dynamic-linker',
    machine: 'x86_64',
    programInterpreter: false,
  };
  for (const [key, value] of Object.entries(expectedStaticEvidence)) {
    if (descriptor.build.staticEvidence[key] !== value) {
      throw failure('DESCRIPTOR_SCHEMA_INVALID', `build.staticEvidence.${key} is invalid.`);
    }
  }
}

async function readExactBytes(handle, byteLength, errorCode, relativePath) {
  const bytes = Buffer.allocUnsafe(byteLength);
  let offset = 0;
  while (offset < byteLength) {
    const { bytesRead } = await handle.read(bytes, offset, byteLength - offset, offset);
    if (bytesRead === 0) {
      throw failure(errorCode, 'The file ended before its declared byte length.', relativePath);
    }
    offset += bytesRead;
  }
  const probe = Buffer.allocUnsafe(1);
  const { bytesRead: trailingBytes } = await handle.read(probe, 0, 1, byteLength);
  if (trailingBytes !== 0) {
    throw failure(errorCode, 'The file exceeds its declared byte length.', relativePath);
  }
  return bytes;
}

function statMetadata(stat) {
  return Object.freeze({
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mode: stat.mode,
    nlink: stat.nlink,
    ctimeNs: stat.ctimeNs,
    mtimeNs: stat.mtimeNs,
  });
}

function sameMetadata(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.ctimeNs === right.ctimeNs
    && left.mtimeNs === right.mtimeNs;
}

async function readBoundedTrackedDescriptor() {
  const before = await fs.lstat(DESCRIPTOR_PATH, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The tracked descriptor must be a direct regular file.');
  }
  const noFollow = Number.isInteger(fsConstants.O_NOFOLLOW) ? fsConstants.O_NOFOLLOW : 0;
  const handle = await fs.open(DESCRIPTOR_PATH, fsConstants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameMetadata(
      statMetadata(before),
      statMetadata(opened),
    )) {
      throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The tracked descriptor identity is unstable.');
    }
    if (opened.size > BigInt(MAX_DESCRIPTOR_BYTES)) {
      throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The tracked descriptor exceeds its byte limit.');
    }
    const raw = await readExactBytes(
      handle,
      Number(opened.size),
      'DESCRIPTOR_SCHEMA_INVALID',
      null,
    );
    const after = await handle.stat({ bigint: true });
    const afterPath = await fs.lstat(DESCRIPTOR_PATH, { bigint: true });
    if (
      !sameMetadata(statMetadata(opened), statMetadata(after))
      || !sameMetadata(statMetadata(opened), statMetadata(afterPath))
      || afterPath.isSymbolicLink()
    ) {
      throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The tracked descriptor changed while being read.');
    }
    return raw;
  } finally {
    await handle.close();
  }
}

async function readTrackedDescriptor() {
  const raw = await readBoundedTrackedDescriptor();
  let descriptor;
  try {
    descriptor = JSON.parse(raw.toString('utf8'));
  } catch {
    throw failure('DESCRIPTOR_SCHEMA_INVALID', 'The tracked descriptor is not valid JSON.');
  }
  validateTrackedDescriptor(descriptor);
  const canonicalBytes = Buffer.from(`${canonicalJson(descriptor)}\n`, 'utf8');
  if (!raw.equals(canonicalBytes)) {
    throw failure('DESCRIPTOR_NOT_CANONICAL', 'The tracked descriptor bytes are not canonical JSON plus LF.');
  }
  return descriptor;
}

function relativePathFor(root, absolutePath) {
  return path.relative(root, absolutePath).split(path.sep).join('/');
}

function normalizedIdentityPath(value) {
  const normalized = path.normalize(value);
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function physicalMode(stat) {
  const permissions = typeof stat.mode === 'bigint'
    ? Number(stat.mode & 0o777n)
    : stat.mode & 0o777;
  return `100${permissions.toString(8).padStart(3, '0')}`;
}

async function captureRootIdentity(root) {
  let rootStat;
  try {
    rootStat = await fs.lstat(root, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') throw failure('PROPOSAL_ROOT_MISSING', 'The proposal root does not exist.');
    throw error;
  }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw failure('PROPOSAL_ROOT_LINKED', 'The proposal root must be a direct directory.');
  }
  const realRoot = await fs.realpath(root);
  const realStat = await fs.lstat(realRoot, { bigint: true });
  if (!realStat.isDirectory() || realStat.isSymbolicLink() || !sameMetadata(
    statMetadata(rootStat),
    statMetadata(realStat),
  )) {
    throw failure('PROPOSAL_ROOT_LINKED', 'The proposal root identity is unstable.');
  }
  return Object.freeze({
    metadata: statMetadata(rootStat),
    realPath: realRoot,
  });
}

async function assertRootIdentity(root, expected) {
  let current;
  let realRoot;
  try {
    current = await fs.lstat(root, { bigint: true });
    realRoot = await fs.realpath(root);
  } catch {
    throw failure('PROPOSAL_ROOT_LINKED', 'The proposal root identity cannot be read back.');
  }
  if (
    current.isSymbolicLink()
    || !current.isDirectory()
    || !sameMetadata(expected.metadata, statMetadata(current))
    || normalizedIdentityPath(realRoot) !== normalizedIdentityPath(expected.realPath)
  ) {
    throw failure('PROPOSAL_ROOT_LINKED', 'The proposal root identity changed during validation.');
  }
}

async function assertDirectResolution(rootIdentity, absolutePath, relativePath) {
  let realPath;
  try {
    realPath = await fs.realpath(absolutePath);
  } catch {
    throw failure('PROPOSAL_LINKED_ENTRY', 'The proposal entry cannot be resolved directly.', relativePath);
  }
  const expected = path.join(rootIdentity.realPath, ...relativePath.split('/'));
  if (normalizedIdentityPath(realPath) !== normalizedIdentityPath(expected)) {
    throw failure('PROPOSAL_LINKED_ENTRY', 'The proposal entry traverses a reparse point.', relativePath);
  }
}

async function scanClosedInventory(root, rootIdentity) {
  const expectedFiles = new Set(ALL_PATHS);
  const seenFiles = new Set();
  const caseKeys = new Map();
  let entryCount = 0;

  async function visit(directory) {
    await assertRootIdentity(root, rootIdentity);
    const directoryHandle = await fs.opendir(directory, { bufferSize: DIRECTORY_BUFFER_SIZE });
    try {
      await assertRootIdentity(root, rootIdentity);
      for await (const child of directoryHandle) {
        entryCount += 1;
        if (entryCount > MAX_INVENTORY_ENTRIES) {
          throw failure('PROPOSAL_EXTRA_ENTRY', 'The proposal inventory exceeds its closed entry limit.');
        }
        const absolutePath = path.join(directory, child.name);
        const relativePath = relativePathFor(root, absolutePath);
        const caseKey = relativePath.toLowerCase();
        const prior = caseKeys.get(caseKey);
        if (prior !== undefined && prior !== relativePath) {
          throw failure(
            'PROPOSAL_CASE_COLLISION',
            `Case-colliding entries ${prior} and ${relativePath} are not allowed.`,
            relativePath,
          );
        }
        caseKeys.set(caseKey, relativePath);

        const stat = await fs.lstat(absolutePath, { bigint: true });
        if (stat.isSymbolicLink()) {
          throw failure('PROPOSAL_LINKED_ENTRY', 'Linked entries are not allowed.', relativePath);
        }
        await assertDirectResolution(rootIdentity, absolutePath, relativePath);
        if (stat.isDirectory()) {
          if (!EXPECTED_DIRECTORIES.has(relativePath)) {
            throw failure('PROPOSAL_EXTRA_ENTRY', 'The proposal contains an extra directory.', relativePath);
          }
          await visit(absolutePath);
          continue;
        }
        if (!stat.isFile()) {
          throw failure('PROPOSAL_LINKED_ENTRY', 'Only direct regular files are allowed.', relativePath);
        }
        if (!expectedFiles.has(relativePath)) {
          throw failure('PROPOSAL_EXTRA_ENTRY', 'The proposal contains an extra file.', relativePath);
        }
        if (seenFiles.has(relativePath)) {
          throw failure('PROPOSAL_CASE_COLLISION', 'The proposal contains a duplicate path.', relativePath);
        }
        seenFiles.add(relativePath);
      }
    } finally {
      try {
        await directoryHandle.close();
      } catch (error) {
        if (error?.code !== 'ERR_DIR_CLOSED') throw error;
      }
    }
  }

  await visit(root);
  for (const expectedPath of ALL_PATHS) {
    if (!seenFiles.has(expectedPath)) {
      throw failure('PROPOSAL_MISSING_ENTRY', 'The proposal is missing a required file.', expectedPath);
    }
  }
  await assertRootIdentity(root, rootIdentity);
}

function assertDirectRegularStat(stat, entry) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) {
    throw failure('PROPOSAL_LINKED_ENTRY', 'The entry must be a direct single-link regular file.', entry.path);
  }
  if (process.platform !== 'win32' && physicalMode(stat) !== entry.mode) {
    throw failure('PROPOSAL_MODE_MISMATCH', 'The POSIX regular-file mode does not match.', entry.path);
  }
}

async function readDirectRegularFile(root, rootIdentity, entry) {
  if (entry.bytes > MAX_PROPOSAL_FILE_BYTES) {
    throw failure('PROPOSAL_SIZE_MISMATCH', 'The descriptor exceeds the per-file byte limit.', entry.path);
  }
  await assertRootIdentity(root, rootIdentity);
  const absolutePath = path.join(root, ...entry.path.split('/'));
  await assertDirectResolution(rootIdentity, absolutePath, entry.path);
  const before = await fs.lstat(absolutePath, { bigint: true });
  assertDirectRegularStat(before, entry);
  const beforeMetadata = statMetadata(before);

  const noFollow = Number.isInteger(fsConstants.O_NOFOLLOW) ? fsConstants.O_NOFOLLOW : 0;
  const handle = await fs.open(absolutePath, fsConstants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat({ bigint: true });
    assertDirectRegularStat(opened, entry);
    const openedMetadata = statMetadata(opened);
    if (!sameMetadata(beforeMetadata, openedMetadata)) {
      throw failure('PROPOSAL_LINKED_ENTRY', 'The opened file identity is not direct and stable.', entry.path);
    }
    if (opened.size !== BigInt(entry.bytes)) {
      throw failure('PROPOSAL_SIZE_MISMATCH', 'The file byte length does not match.', entry.path);
    }
    const bytes = await readExactBytes(
      handle,
      entry.bytes,
      'PROPOSAL_FILE_CHANGED',
      entry.path,
    );
    const after = await handle.stat({ bigint: true });
    const afterPath = await fs.lstat(absolutePath, { bigint: true });
    assertDirectRegularStat(after, entry);
    assertDirectRegularStat(afterPath, entry);
    if (
      !sameMetadata(openedMetadata, statMetadata(after))
      || !sameMetadata(openedMetadata, statMetadata(afterPath))
    ) {
      throw failure('PROPOSAL_FILE_CHANGED', 'The file changed while it was being read.', entry.path);
    }
    await assertDirectResolution(rootIdentity, absolutePath, entry.path);
    await assertRootIdentity(root, rootIdentity);
    return bytes;
  } finally {
    await handle.close();
  }
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function assertBytesMatchEntry(bytes, entry) {
  if (bytes.byteLength !== entry.bytes) {
    throw failure('PROPOSAL_SIZE_MISMATCH', 'The file byte length does not match.', entry.path);
  }
  if (`sha256:${sha256Hex(bytes)}` !== entry.sha256) {
    throw failure('PROPOSAL_DIGEST_MISMATCH', 'The file digest does not match.', entry.path);
  }
}

function serializeSourceEntries(entries) {
  return Buffer.from(entries.map((entry) => [
    entry.path,
    '\0',
    entry.mode,
    '\0',
    String(entry.bytes),
    '\0',
    entry.sha256.slice('sha256:'.length),
    '\n',
  ].join('')).join(''), 'utf8');
}

function assertExactDistManifest(manifest, descriptor) {
  assertExactDataObject(
    manifest,
    ['binary', 'profile', 'protocols', 'schemaVersion', 'source', 'staticEvidence', 'target'],
    'dist manifest',
  );
  if (
    manifest.schemaVersion !== 'verification-supervisor-dist.v1'
    || manifest.target !== descriptor.build.target
    || manifest.profile !== descriptor.build.profile
  ) {
    throw failure('DIST_MANIFEST_CONTRACT_MISMATCH', 'The dist manifest build tuple is invalid.');
  }
  assertDenseArray(manifest.protocols, 2, 'dist manifest protocols');
  if (manifest.protocols.some((value, index) => value !== descriptor.protocols[index])) {
    throw failure('DIST_MANIFEST_CONTRACT_MISMATCH', 'The dist manifest protocol closure is invalid.');
  }
  assertExactDataObject(manifest.source, ['fileCount', 'treeDigest'], 'dist manifest source');
  if (
    manifest.source.fileCount !== descriptor.sourceInventory.fileCount
    || manifest.source.treeDigest !== descriptor.sourceInventory.treeDigest
  ) {
    throw failure('DIST_MANIFEST_CONTRACT_MISMATCH', 'The dist manifest source binding is invalid.');
  }
  assertExactDataObject(manifest.binary, ENTRY_KEYS, 'dist manifest binary');
  for (const key of ENTRY_KEYS) {
    if (manifest.binary[key] !== descriptor.outputs.binary[key]) {
      const code = key === 'mode' ? 'PROPOSAL_MODE_MISMATCH' : 'DIST_MANIFEST_CONTRACT_MISMATCH';
      throw failure(code, `The dist manifest binary ${key} binding is invalid.`, manifest.binary.path ?? null);
    }
  }
  assertExactDataObject(
    manifest.staticEvidence,
    ['endianness', 'format', 'linkerContract', 'machine', 'programInterpreter'],
    'dist manifest staticEvidence',
  );
  for (const key of Object.keys(descriptor.build.staticEvidence)) {
    if (manifest.staticEvidence[key] !== descriptor.build.staticEvidence[key]) {
      throw failure('DIST_MANIFEST_CONTRACT_MISMATCH', `The dist manifest staticEvidence.${key} is invalid.`);
    }
  }
}

function assertElf64StaticX8664(bytes, relativePath) {
  if (
    bytes.byteLength < 64
    || bytes[0] !== 0x7f
    || bytes[1] !== 0x45
    || bytes[2] !== 0x4c
    || bytes[3] !== 0x46
    || bytes[4] !== 2
    || bytes[5] !== 1
    || bytes[6] !== 1
    || bytes.readUInt16LE(16) !== 3
    || bytes.readUInt16LE(18) !== 62
    || bytes.readUInt32LE(20) !== 1
    || bytes.readUInt16LE(52) !== 64
    || bytes.readUInt16LE(54) !== 56
  ) {
    throw failure('BINARY_ELF_CONTRACT_MISMATCH', 'The binary is not the required little-endian x86_64 ELF64 PIE.', relativePath);
  }
  const programOffset = Number(bytes.readBigUInt64LE(32));
  const programEntryBytes = bytes.readUInt16LE(54);
  const programCount = bytes.readUInt16LE(56);
  if (
    !Number.isSafeInteger(programOffset)
    || programCount === 0
    || programOffset < 64
    || programOffset + (programEntryBytes * programCount) > bytes.byteLength
  ) {
    throw failure('BINARY_ELF_CONTRACT_MISMATCH', 'The ELF program-header table is invalid.', relativePath);
  }
  for (let index = 0; index < programCount; index += 1) {
    const offset = programOffset + (index * programEntryBytes);
    const type = bytes.readUInt32LE(offset);
    if (type === 3) {
      throw failure('BINARY_ELF_INTERPRETER_PRESENT', 'The static binary cannot contain PT_INTERP.', relativePath);
    }
    if (type === 2) {
      const dynamicOffset = Number(bytes.readBigUInt64LE(offset + 8));
      const dynamicBytes = Number(bytes.readBigUInt64LE(offset + 32));
      if (
        !Number.isSafeInteger(dynamicOffset)
        || !Number.isSafeInteger(dynamicBytes)
        || dynamicOffset + dynamicBytes > bytes.byteLength
        || dynamicBytes % 16 !== 0
      ) {
        throw failure('BINARY_ELF_CONTRACT_MISMATCH', 'The ELF dynamic table is invalid.', relativePath);
      }
      for (let entryOffset = dynamicOffset; entryOffset < dynamicOffset + dynamicBytes; entryOffset += 16) {
        const tag = bytes.readBigInt64LE(entryOffset);
        if (tag === 0n) break;
        if (tag === 1n) {
          throw failure('BINARY_ELF_SHARED_DEPENDENCY', 'The static binary cannot contain DT_NEEDED.', relativePath);
        }
      }
    }
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export async function validateA1SupervisorProposal(options) {
  assertExactDataObject(options, ['proposalRoot'], 'options');
  if (typeof options.proposalRoot !== 'string' || !path.isAbsolute(options.proposalRoot)) {
    throw failure('PROPOSAL_ROOT_INVALID', 'proposalRoot must be an absolute path.');
  }
  const root = path.resolve(options.proposalRoot);
  const rootIdentity = await captureRootIdentity(root);
  const descriptor = await readTrackedDescriptor();
  await scanClosedInventory(root, rootIdentity);

  for (const entry of descriptor.sourceInventory.entries) {
    const bytes = await readDirectRegularFile(root, rootIdentity, entry);
    assertBytesMatchEntry(bytes, entry);
  }
  const serialized = serializeSourceEntries(descriptor.sourceInventory.entries);
  if (serialized.byteLength !== descriptor.sourceInventory.serializedBytes) {
    throw failure('SOURCE_TREE_SERIALIZATION_MISMATCH', 'The source inventory serialization length is invalid.');
  }
  if (`sha256:${sha256Hex(serialized)}` !== descriptor.sourceInventory.treeDigest) {
    throw failure('SOURCE_TREE_DIGEST_MISMATCH', 'The canonical source tree digest does not match.');
  }

  const binaryBytes = await readDirectRegularFile(root, rootIdentity, descriptor.outputs.binary);
  const manifestBytes = await readDirectRegularFile(
    root,
    rootIdentity,
    descriptor.outputs.distManifest,
  );
  assertBytesMatchEntry(binaryBytes, descriptor.outputs.binary);
  if (manifestBytes.byteLength !== descriptor.outputs.distManifest.bytes) {
    throw failure(
      'PROPOSAL_SIZE_MISMATCH',
      'The file byte length does not match.',
      descriptor.outputs.distManifest.path,
    );
  }

  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    throw failure('DIST_MANIFEST_CONTRACT_MISMATCH', 'The dist manifest is not valid JSON.');
  }
  assertExactDistManifest(manifest, descriptor);
  assertBytesMatchEntry(manifestBytes, descriptor.outputs.distManifest);
  assertElf64StaticX8664(binaryBytes, descriptor.outputs.binary.path);
  await scanClosedInventory(root, rootIdentity);
  await assertRootIdentity(root, rootIdentity);

  const canonicalDescriptor = JSON.parse(canonicalJson(descriptor));
  const result = {
    descriptor: canonicalDescriptor,
    descriptorDigest: sha256Bytes(Buffer.from(canonicalJson(canonicalDescriptor), 'utf8')),
  };
  return deepFreeze(result);
}

async function runCli() {
  if (process.argv.length !== 3) {
    throw failure('CLI_ARGUMENT_INVALID', 'Usage: node a1-supervisor-proposal.mjs <absolute-proposal-root>');
  }
  const result = await validateA1SupervisorProposal({ proposalRoot: process.argv[2] });
  process.stdout.write(`${canonicalJson(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(MODULE_PATH)) {
  runCli().catch((error) => {
    const code = error instanceof A1SupervisorProposalError ? error.code : 'A1_SUPERVISOR_PROPOSAL_INTERNAL';
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
