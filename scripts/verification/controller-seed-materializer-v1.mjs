import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { copyFile, lstat, mkdir, open, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { promisify } from 'node:util';

import { validateA1SupervisorProposal } from './a1-supervisor-proposal.mjs';
import { canonicalJson } from './canonical-json.mjs';
import { validateControllerBundleProposal } from './controller-bundle.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[\x21-\x7e]+$/u;
const SET_NAMES = Object.freeze(['overlay', 'controller', 'tooling', 'a1-supervisor']);
const SUPERVISOR_PATH = 'a1-oci/supervisor/verification-supervisor';
const INTERNAL_PATH = 'seed-content-manifest.v1.json';
const SOURCE_SET_DESCRIPTOR_PATH = 'packages/verification-controller/controller-seed-source-sets.v1.json';
const SOURCE_SET_DESCRIPTOR_SCHEMA_PATH = 'dev/verification/schemas/controller-seed-source-sets.v1.schema.json';
const PROPOSAL_PATH = 'packages/verification-controller/controller-bundle.proposal.json';
const OVERLAY_ROOT = 'packages/verification-controller/controller-repository-seed';
const A1 = Object.freeze({
  descriptorDigest: 'sha256:37ca56c9fd1bd638e1ee714578c6aab064312167e380bc4725faaa290f8a29c0',
  sourceTreeDigest: 'sha256:d0bdab8c6831f620272bafd6f1b5982e0236b1ef43b0e7e58758022836973161',
  binaryDigest: 'sha256:56bd8861336accf993cab6ff9da65659b9df832b03b993ef0deb342b4a89cfa5',
});
const WORKFLOWS = Object.freeze([
  {
    source: 'packages/verification-controller/workflows/collect-appwrite-test-readback.yml',
    destination: '.github/workflows/collect-appwrite-test-readback.yml',
  },
  {
    source: 'packages/verification-controller/workflows/publish-controller-bundle.yml',
    destination: '.github/workflows/publish-controller-bundle.yml',
  },
  {
    source: 'packages/verification-controller/workflows/verify-test-cloud.yml',
    destination: '.github/workflows/verify-test-cloud.yml',
  },
]);
const CONTROLLER_RELOCATIONS = Object.freeze([
  {
    source: 'packages/verification-controller/package-lock.json',
    destination: 'package-lock.json',
  },
  {
    source: 'packages/verification-controller/package.json',
    destination: 'package.json',
  },
  ...WORKFLOWS,
]);
const COMMIT = Object.freeze({
  schemaVersion: 'controller-seed-commit.v1',
  author: 'AppWriteWork Verification Controller <verification-controller@appwritework.invalid>',
  committer: 'AppWriteWork Verification Controller <verification-controller@appwritework.invalid>',
  timestamp: '0 +0000',
  message: 'AppWriteWork verification controller seed v1\n',
});
const execFile = promisify(execFileCallback);

function digest(algorithm, bytes) {
  return createHash(algorithm).update(bytes).digest();
}

function sha256(bytes) {
  return `sha256:${digest('sha256', bytes).toString('hex')}`;
}

function gitObjectId(type, bytes) {
  return digest('sha1', Buffer.concat([Buffer.from(`${type} ${bytes.length}\0`, 'ascii'), Buffer.from(bytes)])).toString('hex');
}

function result(status, value, code = null) {
  return Object.freeze({
    status,
    value,
    diagnostics: code === null ? [] : Object.freeze([Object.freeze({ code, retryable: false, safeMessage: 'Controller seed input is invalid.' })]),
  });
}

function exactObject(value, keys, optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const allowed = new Set([...keys, ...optional]);
    const names = Object.keys(value);
    if (keys.some((key) => !names.includes(key)) || names.some((key) => !allowed.has(key))) return null;
    return value;
  } catch {
    return null;
  }
}

function snapshotBytes(value) {
  try {
    if (!utilTypes.isUint8Array(value) || utilTypes.isProxy(value)) return null;
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  } catch {
    return null;
  }
}

function safePath(value) {
  return typeof value === 'string'
    && SAFE_PATH.test(value)
    && !value.startsWith('/')
    && !value.endsWith('/')
    && !value.split('/').some((segment) => (
      segment === '.'
      || segment === '..'
      || segment.endsWith('.')
      || segment.endsWith(' ')
    ));
}

function sourceInventoryPath(value) {
  return typeof value === 'string'
    && value.length > 0
    && !value.includes('\0')
    && !value.startsWith('/')
    && !value.endsWith('/')
    && Buffer.from(value, 'utf8').toString('utf8') === value
    && !value.split('/').some((segment) => (
      segment === ''
      || segment === '.'
      || segment === '..'
    ));
}

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function joinSourcePath(sourceRoot, filePath) {
  return sourceRoot === '' ? filePath : `${sourceRoot}/${filePath}`;
}

function hasCanonicalSourceOwnership(sets) {
  const owners = new Map();
  for (const sourceSet of sets) {
    for (const { sourcePath } of sourceSet.mappings) {
      const identity = sourcePath.toLowerCase();
      const owner = owners.get(identity);
      if (owner !== undefined && owner !== sourceSet.name) return false;
      owners.set(identity, sourceSet.name);
    }
  }
  return true;
}

function validateSourceSetDescriptor(value) {
  const input = exactObject(value, ['schemaVersion', 'sets']);
  if (
    input === null
    || input.schemaVersion !== 'controller-seed-source-sets.v1'
    || !Array.isArray(input.sets)
    || input.sets.length !== 3
  ) return null;
  const expectedRoots = [OVERLAY_ROOT, '', ''];
  const sets = [];
  const allMappings = [];
  for (let index = 0; index < input.sets.length; index += 1) {
    const sourceSet = exactObject(input.sets[index], ['name', 'sourceRoot', 'files', 'relocations']);
    if (
      sourceSet === null
      || sourceSet.name !== SET_NAMES[index]
      || sourceSet.sourceRoot !== expectedRoots[index]
      || !Array.isArray(sourceSet.files)
      || sourceSet.files.length === 0
      || sourceSet.files.some((filePath) => !safePath(filePath))
      || sourceSet.files.some((filePath, fileIndex) => (
        fileIndex > 0 && ordinal(sourceSet.files[fileIndex - 1], filePath) >= 0
      ))
      || !Array.isArray(sourceSet.relocations)
    ) return null;
    const relocations = [];
    for (const candidate of sourceSet.relocations) {
      const relocation = exactObject(candidate, ['source', 'destination']);
      if (
        relocation === null
        || !safePath(relocation.source)
        || !safePath(relocation.destination)
        || !sourceSet.files.includes(relocation.source)
      ) return null;
      relocations.push({ source: relocation.source, destination: relocation.destination });
    }
    if (
      (index !== 1 && relocations.length !== 0)
      || (index === 1 && canonicalJson(relocations) !== canonicalJson(CONTROLLER_RELOCATIONS))
    ) return null;
    const mappings = [
      ...sourceSet.files.map((filePath) => ({
        sourcePath: joinSourcePath(sourceSet.sourceRoot, filePath),
        destinationPath: filePath,
      })),
      ...relocations.map(({ source, destination }) => ({
        sourcePath: joinSourcePath(sourceSet.sourceRoot, source),
        destinationPath: destination,
      })),
    ];
    sets.push({
      name: sourceSet.name,
      sourceRoot: sourceSet.sourceRoot,
      files: [...sourceSet.files],
      relocations,
      mappings,
    });
    allMappings.push(...mappings);
  }
  const identities = allMappings.map(({ destinationPath }) => destinationPath.toLowerCase());
  if (new Set(identities).size !== identities.length || !hasCanonicalSourceOwnership(sets)) return null;
  return { schemaVersion: input.schemaVersion, sets };
}

function validateSourceRootRecords(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const records = [];
  for (const candidate of value) {
    const record = exactObject(candidate, ['path', 'mode', 'sha256']);
    if (
      record === null
      || !sourceInventoryPath(record.path)
      || !['100644', '100755'].includes(record.mode)
      || !DIGEST.test(record.sha256 ?? '')
    ) return null;
    records.push({ path: record.path, mode: record.mode, sha256: record.sha256 });
  }
  if (records.some((record, index) => index > 0 && ordinal(records[index - 1].path, record.path) >= 0)) {
    return null;
  }
  if (new Set(records.map(({ path: filePath }) => filePath.toLowerCase())).size !== records.length) {
    return null;
  }
  return records;
}

function sourceSetMatchesDescriptor(sourceSet, descriptorSet) {
  const actual = sourceSet.files.map(({ sourcePath, destinationPath }) => `${sourcePath}\0${destinationPath}`).sort();
  const expected = descriptorSet.mappings.map(({ sourcePath, destinationPath }) => `${sourcePath}\0${destinationPath}`).sort();
  return actual.length === expected.length
    && actual.every((identity, index) => identity === expected[index]);
}

function cloneEvidence(value) {
  const evidence = exactObject(value, ['descriptorDigest', 'sourceTreeDigest', 'binaryDigest']);
  if (evidence === null || Object.entries(A1).some(([key, expected]) => evidence[key] !== expected)) return null;
  return { ...evidence };
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

function tarOctal(value, width) {
  const text = value.toString(8);
  if (text.length > width - 1) throw new RangeError('ustar field overflow');
  return `${text.padStart(width - 1, '0')}\0`;
}

function writeAscii(buffer, offset, width, value) {
  const bytes = Buffer.from(value, 'ascii');
  if (bytes.length > width) throw new RangeError('ustar field overflow');
  bytes.copy(buffer, offset);
}

function splitUstarPath(value) {
  if (Buffer.byteLength(value, 'ascii') <= 100) return { name: value, prefix: '' };
  let separator = value.lastIndexOf('/');
  while (separator > 0) {
    const prefix = value.slice(0, separator);
    const name = value.slice(separator + 1);
    if (Buffer.byteLength(prefix, 'ascii') <= 155 && Buffer.byteLength(name, 'ascii') <= 100) {
      return { name, prefix };
    }
    separator = value.lastIndexOf('/', separator - 1);
  }
  throw new RangeError('ustar path overflow');
}

function ustarHeader(entry) {
  const header = Buffer.alloc(512);
  const archivePath = splitUstarPath(entry.path);
  writeAscii(header, 0, 100, archivePath.name);
  writeAscii(header, 100, 8, tarOctal(entry.mode === '100755' ? 0o755 : 0o644, 8));
  writeAscii(header, 108, 8, tarOctal(0, 8));
  writeAscii(header, 116, 8, tarOctal(0, 8));
  writeAscii(header, 124, 12, tarOctal(entry.bytes.length, 12));
  writeAscii(header, 136, 12, tarOctal(0, 12));
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeAscii(header, 257, 6, 'ustar\0');
  writeAscii(header, 263, 2, '00');
  writeAscii(header, 345, 155, archivePath.prefix);
  const checksum = header.reduce((total, byte) => total + byte, 0);
  writeAscii(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

function createUstar(entries) {
  const chunks = [];
  for (const entry of entries) {
    chunks.push(ustarHeader(entry), entry.bytes);
    const padding = (512 - (entry.bytes.length % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function buildTree(entries) {
  const root = { files: new Map(), directories: new Map() };
  for (const entry of entries) {
    const parts = entry.path.split('/');
    const name = parts.pop();
    let node = root;
    for (const segment of parts) {
      if (!node.directories.has(segment)) node.directories.set(segment, { files: new Map(), directories: new Map() });
      node = node.directories.get(segment);
    }
    node.files.set(name, entry);
  }
  function hashNode(node) {
    const rows = [];
    for (const [name, child] of node.directories) rows.push({ name, mode: '40000', oid: hashNode(child) });
    for (const [name, entry] of node.files) rows.push({ name, mode: entry.mode, oid: gitObjectId('blob', entry.bytes) });
    rows.sort((left, right) => {
      const leftName = left.mode === '40000' ? `${left.name}/` : left.name;
      const rightName = right.mode === '40000' ? `${right.name}/` : right.name;
      return Buffer.compare(Buffer.from(leftName), Buffer.from(rightName));
    });
    const body = Buffer.concat(rows.map((row) => Buffer.concat([
      Buffer.from(`${row.mode} ${row.name}\0`, 'utf8'),
      Buffer.from(row.oid, 'hex'),
    ])));
    return gitObjectId('tree', body);
  }
  return hashNode(root);
}

function parentlessCommit(treeOid) {
  const body = Buffer.from(
    `tree ${treeOid}\nauthor ${COMMIT.author} ${COMMIT.timestamp}\ncommitter ${COMMIT.committer} ${COMMIT.timestamp}\n\n${COMMIT.message}`,
    'utf8',
  );
  return gitObjectId('commit', body);
}

export function buildDeterministicControllerSeed(args) {
  try {
    const input = exactObject(args, [
      'sourceRepository', 'sourceRepositoryRevision', 'sourceRootRecords',
      'sourceSetDescriptor', 'sourceSets', 'a1SupervisorEvidence',
    ]);
    const a1Evidence = input === null ? null : cloneEvidence(input.a1SupervisorEvidence);
    const sourceSetDescriptor = input === null ? null : validateSourceSetDescriptor(input.sourceSetDescriptor);
    const sourceRootRecords = input === null ? null : validateSourceRootRecords(input.sourceRootRecords);
    if (
      input === null
      || input.sourceRepository !== 'Krowaccie/AppWriteWork'
      || !SHA.test(input.sourceRepositoryRevision ?? '')
      || !Array.isArray(input.sourceSets)
      || input.sourceSets.length !== 4
      || a1Evidence === null
      || sourceSetDescriptor === null
      || sourceRootRecords === null
    ) return result('BLOCKED', null, 'SEED_INPUT_INVALID');
    const rootPaths = new Set(sourceRootRecords.map(({ path: filePath }) => filePath));
    if (sourceSetDescriptor.sets.some(({ mappings }) => mappings.some(({ sourcePath }) => !rootPaths.has(sourcePath)))) {
      return result('BLOCKED', null, 'SEED_INPUT_INVALID');
    }
    const sourceRootDigest = sha256(canonicalBytes(sourceRootRecords));

    const entries = [];
    for (let setIndex = 0; setIndex < input.sourceSets.length; setIndex += 1) {
      const sourceSet = exactObject(input.sourceSets[setIndex], ['name', 'files']);
      if (sourceSet === null || sourceSet.name !== SET_NAMES[setIndex] || !Array.isArray(sourceSet.files) || sourceSet.files.length === 0) {
        return result('BLOCKED', null, 'SEED_SOURCE_SET_INVALID');
      }
      if (setIndex < 3 && !sourceSetMatchesDescriptor(sourceSet, sourceSetDescriptor.sets[setIndex])) {
        return result('BLOCKED', null, 'SEED_SOURCE_SET_INVALID');
      }
      for (const candidate of sourceSet.files) {
        const record = exactObject(candidate, ['sourcePath', 'destinationPath', 'mode', 'bytes'], ['sha256']);
        const fileBytes = record === null ? null : snapshotBytes(record.bytes);
        if (
          record === null
          || fileBytes === null
          || !safePath(record.sourcePath)
          || !safePath(record.destinationPath)
          || !['100644', '100755'].includes(record.mode)
          || (record.destinationPath === SUPERVISOR_PATH) !== (record.mode === '100755')
          || (record.sha256 !== undefined && record.sha256 !== sha256(fileBytes))
        ) return result('BLOCKED', null, 'SEED_FILE_INVALID');
        entries.push({
          owner: sourceSet.name,
          sourcePath: record.sourcePath,
          path: record.destinationPath,
          mode: record.mode,
          bytes: Buffer.from(fileBytes),
          sha256: sha256(fileBytes),
        });
      }
    }
    const sourceIdentities = new Map();
    for (const entry of entries) {
      const identity = `${entry.mode}\0${entry.sha256}`;
      const sourceIdentity = entry.sourcePath.toLowerCase();
      const prior = sourceIdentities.get(sourceIdentity);
      if (prior !== undefined && (prior.identity !== identity || prior.owner !== entry.owner)) {
        return result('BLOCKED', null, 'SEED_FILE_INVALID');
      }
      sourceIdentities.set(sourceIdentity, { identity, owner: entry.owner });
    }
    const supervisorEntries = entries.filter(({ owner }) => owner === 'a1-supervisor');
    if (
      supervisorEntries.length !== 2
      || supervisorEntries[0].path !== 'a1-oci/supervisor/dist.manifest.json'
      || supervisorEntries[0].mode !== '100644'
      || supervisorEntries[1].path !== SUPERVISOR_PATH
      || supervisorEntries[1].mode !== '100755'
      || supervisorEntries[1].sha256 !== A1.binaryDigest
    ) return result('BLOCKED', null, 'SEED_A1_SUPERVISOR_INVALID');
    entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    const identities = entries.map(({ path: filePath }) => filePath.toLowerCase());
    if (new Set(identities).size !== identities.length) return result('BLOCKED', null, 'SEED_PATH_COLLISION');
    for (let left = 0; left < identities.length; left += 1) {
      for (let right = left + 1; right < identities.length; right += 1) {
        if (identities[left].startsWith(`${identities[right]}/`) || identities[right].startsWith(`${identities[left]}/`)) {
          return result('BLOCKED', null, 'SEED_PATH_COLLISION');
        }
      }
    }

    const fileRecords = entries.map(({ path: filePath, mode, sha256: fileDigest, owner }) => ({
      path: filePath,
      mode,
      sha256: fileDigest,
      owner,
    }));
    const closureDigest = sha256(canonicalBytes(fileRecords));
    const internalManifest = {
      schemaVersion: 'seed-content-manifest.v1',
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      files: fileRecords,
      closureDigest,
      workflowMappings: WORKFLOWS,
      a1SupervisorEvidence: a1Evidence,
    };
    const internalManifestBytes = canonicalBytes(internalManifest);
    const treeEntries = [...entries, {
      path: INTERNAL_PATH,
      mode: '100644',
      bytes: internalManifestBytes,
    }].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    const seedTreeDigest = sha256(canonicalBytes(fileRecords.map(({ path: filePath, mode, sha256: fileDigest }) => ({
      path: filePath, mode, sha256: fileDigest,
    }))));
    const gitTreeOid = buildTree(treeEntries);
    const controllerSeedSha = parentlessCommit(gitTreeOid);
    const archiveBytes = createUstar(treeEntries);
    const archiveDigest = sha256(archiveBytes);
    const externalManifest = {
      schemaVersion: 'seed-provenance-manifest.v1',
      sourceRepository: input.sourceRepository,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      sourceRootDigest,
      gitTreeOid,
      seedTreeDigest,
      controllerSeedSha,
      internalManifestDigest: sha256(internalManifestBytes),
      archiveDigest,
      commitContract: COMMIT,
    };
    return result('PASS', Object.freeze({
      seedFiles: Object.freeze(treeEntries.map(({ path: filePath, mode, bytes: fileBytes }) => Object.freeze({
        path: filePath,
        mode,
        bytes: new Uint8Array(fileBytes),
      }))),
      internalManifest,
      internalManifestBytes: new Uint8Array(internalManifestBytes),
      externalManifest,
      externalManifestBytes: new Uint8Array(canonicalBytes(externalManifest)),
      archiveBytes: new Uint8Array(archiveBytes),
      archiveDigest,
      gitTreeOid,
      seedTreeDigest,
      controllerSeedSha,
    }));
  } catch {
    return result('BLOCKED', null, 'SEED_INPUT_INVALID');
  }
}

async function writeNewFile(filePath, bytes, mode = 0o644) {
  await mkdir(path.dirname(filePath), { recursive: true });
  const handle = await open(filePath, 'wx', mode);
  try {
    await handle.writeFile(bytes);
  } finally {
    await handle.close();
  }
}

export async function writeControllerSeedArtifacts(args) {
  try {
    const input = exactObject(args, ['materialization', 'outputRoot']);
    if (
      input === null
      || typeof input.outputRoot !== 'string'
      || !path.isAbsolute(input.outputRoot)
      || !Array.isArray(input.materialization?.seedFiles)
    ) return result('BLOCKED', null, 'SEED_OUTPUT_INVALID');
    const outputRoot = await realpath(path.resolve(input.outputRoot));
    if ((await readdir(outputRoot)).length !== 0) return result('BLOCKED', null, 'SEED_OUTPUT_INVALID');
    const seedRoot = path.join(outputRoot, 'seed');
    await mkdir(seedRoot);
    for (const file of input.materialization.seedFiles) {
      if (!safePath(file.path) || !['100644', '100755'].includes(file.mode)) return result('BLOCKED', null, 'SEED_OUTPUT_INVALID');
      await writeNewFile(
        path.join(seedRoot, ...file.path.split('/')),
        file.bytes,
        file.mode === '100755' ? 0o755 : 0o644,
      );
    }
    await writeNewFile(path.join(outputRoot, 'controller-seed.v1.tar'), input.materialization.archiveBytes);
    await writeNewFile(path.join(outputRoot, 'seed-provenance-manifest.v1.json'), input.materialization.externalManifestBytes);
    const evidence = canonicalBytes({
      schemaVersion: 'controller-seed-validation.v1',
      status: 'PROVISIONAL_TASK_4A',
      controllerSeedSha: input.materialization.controllerSeedSha,
      gitTreeOid: input.materialization.gitTreeOid,
      seedTreeDigest: input.materialization.seedTreeDigest,
      internalManifestDigest: input.materialization.externalManifest.internalManifestDigest,
      archiveDigest: input.materialization.archiveDigest,
    });
    await writeNewFile(path.join(outputRoot, 'controller-seed-validation.v1.json'), evidence);
    return result('PASS', {
      controllerSeedSha: input.materialization.controllerSeedSha,
      archiveDigest: input.materialization.archiveDigest,
      outputPaths: [
        'controller-seed-validation.v1.json',
        'controller-seed.v1.tar',
        'seed',
        'seed-provenance-manifest.v1.json',
      ],
    });
  } catch {
    return result('BLOCKED', null, 'SEED_OUTPUT_INVALID');
  }
}

function validSourceOrigin(value) {
  return value === 'https://github.com/Krowaccie/AppWriteWork.git'
    || value === 'git@github.com:Krowaccie/AppWriteWork.git'
    || value === 'ssh://git@github.com/Krowaccie/AppWriteWork.git';
}

async function readCommittedSourceRoot(sourceRepositoryRevision, gitOptions) {
  const treeBytes = (await execFile(
    'git',
    ['ls-tree', '-r', '-z', '--full-tree', sourceRepositoryRevision],
    gitOptions,
  )).stdout;
  if (treeBytes.length === 0 || treeBytes[treeBytes.length - 1] !== 0) {
    throw new TypeError('invalid source root framing');
  }
  const rows = [];
  let rowStart = 0;
  for (let index = 0; index < treeBytes.length; index += 1) {
    if (treeBytes[index] !== 0) continue;
    if (index === rowStart) throw new TypeError('empty source root entry');
    rows.push(treeBytes.subarray(rowStart, index));
    rowStart = index + 1;
  }
  if (rows.length === 0) throw new TypeError('empty source root');
  const records = [];
  const bytesByPath = new Map();
  for (const row of rows) {
    const separator = row.indexOf(0x09);
    const metadata = separator < 0 ? '' : row.subarray(0, separator).toString('ascii');
    const match = /^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40})$/u.exec(metadata);
    const pathBytes = separator < 0 ? Buffer.alloc(0) : row.subarray(separator + 1);
    const sourcePath = pathBytes.toString('utf8');
    if (
      match === null
      || !['100644', '100755'].includes(match[1])
      || match[2] !== 'blob'
      || !Buffer.from(sourcePath, 'utf8').equals(pathBytes)
      || !sourceInventoryPath(sourcePath)
    ) throw new TypeError('invalid source root entry');
    const blob = (await execFile('git', ['cat-file', 'blob', match[3]], gitOptions)).stdout;
    const bytesValue = Buffer.from(blob);
    records.push({ path: sourcePath, mode: match[1], sha256: sha256(bytesValue) });
    bytesByPath.set(sourcePath, bytesValue);
  }
  records.sort((left, right) => ordinal(left.path, right.path));
  if (new Set(records.map(({ path: filePath }) => filePath.toLowerCase())).size !== records.length) {
    throw new TypeError('source root collision');
  }
  return { records, bytesByPath };
}

export async function buildDeterministicControllerSeedFromGit(args) {
  try {
    const input = exactObject(args, [
      'repositoryRoot', 'sourceRepositoryRevision', 'a1SupervisorRoot',
      'a1SupervisorEvidence',
    ]);
    if (
      input === null
      || typeof input.repositoryRoot !== 'string'
      || typeof input.a1SupervisorRoot !== 'string'
      || !path.isAbsolute(input.repositoryRoot)
      || !path.isAbsolute(input.a1SupervisorRoot)
      || !SHA.test(input.sourceRepositoryRevision ?? '')
    ) return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    const repositoryRoot = await realpath(path.resolve(input.repositoryRoot));
    const a1Root = await realpath(path.resolve(input.a1SupervisorRoot));
    const gitOptions = { cwd: repositoryRoot, encoding: 'buffer', maxBuffer: 80 * 1024 * 1024 };
    const origin = (await execFile('git', ['remote', 'get-url', 'origin'], gitOptions)).stdout.toString('utf8').trim();
    if (!validSourceOrigin(origin)) return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    if ((await execFile('git', ['status', '--porcelain=v1', '-uall'], gitOptions)).stdout.length !== 0) {
      return result('BLOCKED', null, 'SEED_GIT_DIRTY');
    }
    const resolved = (await execFile('git', ['rev-parse', `${input.sourceRepositoryRevision}^{commit}`], gitOptions)).stdout.toString('ascii').trim();
    if (resolved !== input.sourceRepositoryRevision) return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    const sourceRoot = await readCommittedSourceRoot(input.sourceRepositoryRevision, gitOptions);
    const descriptorBytes = sourceRoot.bytesByPath.get(SOURCE_SET_DESCRIPTOR_PATH);
    const proposalBytes = sourceRoot.bytesByPath.get(PROPOSAL_PATH);
    if (descriptorBytes === undefined || proposalBytes === undefined) {
      return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    }
    const sourceSetDescriptor = validateSourceSetDescriptor(JSON.parse(descriptorBytes.toString('utf8')));
    const proposalResult = validateControllerBundleProposal(JSON.parse(proposalBytes.toString('utf8')));
    if (sourceSetDescriptor === null || proposalResult.status !== 'PASS') {
      return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    }
    const proposal = proposalResult.value;
    if (
      proposal.seedSourceSets.path !== SOURCE_SET_DESCRIPTOR_PATH
      || proposal.seedSourceSets.schemaPath !== SOURCE_SET_DESCRIPTOR_SCHEMA_PATH
      || !hasCanonicalSourceOwnership(sourceSetDescriptor.sets)
    ) return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');

    const proposalInventory = [...proposal.files, ...proposal.schemaDigests]
      .map(({ path: filePath }) => filePath)
      .sort(ordinal);
    const controllerInventory = [...sourceSetDescriptor.sets[1].files];
    const toolingInventory = [...sourceSetDescriptor.sets[2].files];
    const ownedInventory = [...controllerInventory, ...toolingInventory].sort(ordinal);
    if (
      new Set(ownedInventory.map((filePath) => filePath.toLowerCase())).size !== ownedInventory.length
      || proposalInventory.some((filePath) => !ownedInventory.includes(filePath))
      || controllerInventory.some((filePath) => !proposalInventory.includes(filePath))
      || toolingInventory.some((filePath) => !proposalInventory.includes(filePath))
    ) return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    const overlayPrefix = `${OVERLAY_ROOT}/`;
    const committedOverlayInventory = sourceRoot.records
      .map(({ path: filePath }) => filePath)
      .filter((filePath) => filePath.startsWith(overlayPrefix))
      .map((filePath) => filePath.slice(overlayPrefix.length));
    if (canonicalJson(committedOverlayInventory) !== canonicalJson(sourceSetDescriptor.sets[0].files)) {
      return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
    }

    const sourceSets = sourceSetDescriptor.sets.map((sourceSet) => ({
      name: sourceSet.name,
      files: sourceSet.mappings.map(({ sourcePath, destinationPath }) => {
        const sourceRecord = sourceRoot.records.find(({ path: filePath }) => filePath === sourcePath);
        const fileBytes = sourceRoot.bytesByPath.get(sourcePath);
        if (sourceRecord === undefined || fileBytes === undefined) throw new TypeError('missing descriptor source');
        return {
          sourcePath,
          destinationPath,
          mode: sourceRecord.mode,
          sha256: sourceRecord.sha256,
          bytes: new Uint8Array(fileBytes),
        };
      }),
    }));

    const a1Inventory = (await readdir(a1Root)).sort();
    if (a1Inventory.join('\0') !== 'dist\0dist.manifest.json' || (await readdir(path.join(a1Root, 'dist'))).join('\0') !== 'verification-supervisor') {
      return result('BLOCKED', null, 'SEED_A1_SUPERVISOR_INVALID');
    }
    const manifestPath = path.join(a1Root, 'dist.manifest.json');
    const binaryPath = path.join(a1Root, 'dist', 'verification-supervisor');
    const manifestInfo = await lstat(manifestPath);
    const binaryInfo = await lstat(binaryPath);
    if (!manifestInfo.isFile() || manifestInfo.isSymbolicLink() || !binaryInfo.isFile() || binaryInfo.isSymbolicLink()) {
      return result('BLOCKED', null, 'SEED_A1_SUPERVISOR_INVALID');
    }
    sourceSets.push({ name: 'a1-supervisor', files: [
      { sourcePath: 'dist.manifest.json', destinationPath: 'a1-oci/supervisor/dist.manifest.json', mode: '100644', bytes: new Uint8Array(await readFile(manifestPath)) },
      { sourcePath: 'dist/verification-supervisor', destinationPath: SUPERVISOR_PATH, mode: '100755', bytes: new Uint8Array(await readFile(binaryPath)), sha256: A1.binaryDigest },
    ] });
    return buildDeterministicControllerSeed({
      sourceRepository: 'Krowaccie/AppWriteWork',
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      sourceRootRecords: sourceRoot.records,
      sourceSetDescriptor: {
        schemaVersion: sourceSetDescriptor.schemaVersion,
        sets: sourceSetDescriptor.sets.map(({ name, sourceRoot: setRoot, files, relocations }) => ({
          name,
          sourceRoot: setRoot,
          files,
          relocations,
        })),
      },
      sourceSets,
      a1SupervisorEvidence: input.a1SupervisorEvidence,
    });
  } catch {
    return result('BLOCKED', null, 'SEED_GIT_INPUT_INVALID');
  }
}

function parseOctal(buffer, offset, length) {
  const text = buffer.subarray(offset, offset + length).toString('ascii').replace(/\0.*$/u, '').trim();
  return text === '' ? 0 : Number.parseInt(text, 8);
}

export function inspectUstarArchive(value) {
  const bytes = snapshotBytes(value);
  if (bytes === null || bytes.length < 1024 || bytes.length % 512 !== 0) throw new TypeError('Invalid ustar archive');
  const entries = [];
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/u, '');
    const path = prefix === '' ? name : `${prefix}/${name}`;
    const size = parseOctal(header, 124, 12);
    entries.push(Object.freeze({
      path,
      mode: parseOctal(header, 100, 8),
      uid: parseOctal(header, 108, 8),
      gid: parseOctal(header, 116, 8),
      mtime: parseOctal(header, 136, 12),
      type: header[156] === 0x30 ? 'file' : 'other',
      owner: header.subarray(265, 297).toString('ascii').replace(/\0.*$/u, ''),
      group: header.subarray(297, 329).toString('ascii').replace(/\0.*$/u, ''),
    }));
    offset += 512 + (Math.ceil(size / 512) * 512);
  }
  return Object.freeze(entries);
}

export async function revalidateAndRelocateA1Supervisor(args) {
  try {
    const input = exactObject(args, ['proposalRoot', 'outputRoot']);
    if (
      input === null
      || typeof input.proposalRoot !== 'string'
      || typeof input.outputRoot !== 'string'
      || !path.isAbsolute(input.proposalRoot)
      || !path.isAbsolute(input.outputRoot)
    ) return result('BLOCKED', null, 'A1_SUP_RELOCATION_INVALID');
    const proposalRoot = await realpath(path.resolve(input.proposalRoot));
    const outputRoot = await realpath(path.resolve(input.outputRoot));
    if ((await readdir(outputRoot)).length !== 0) {
      return result('BLOCKED', null, 'A1_SUP_RELOCATION_INVALID');
    }
    const before = await validateA1SupervisorProposal({ proposalRoot });
    if (
      before.descriptorDigest !== A1.descriptorDigest
      || before.descriptor.sourceInventory.treeDigest !== A1.sourceTreeDigest
      || before.descriptor.outputs.binary.sha256 !== A1.binaryDigest
    ) return result('BLOCKED', null, 'A1_SUP_RELOCATION_INVALID');
    const sourceBinary = path.join(proposalRoot, 'dist', 'verification-supervisor');
    const sourceManifest = path.join(proposalRoot, 'dist.manifest.json');
    const destinationBinary = path.join(outputRoot, 'dist', 'verification-supervisor');
    const destinationManifest = path.join(outputRoot, 'dist.manifest.json');
    await mkdir(path.dirname(destinationBinary), { recursive: true });
    await copyFile(sourceBinary, destinationBinary);
    await copyFile(sourceManifest, destinationManifest);
    const binaryBytes = await readFile(destinationBinary);
    const manifestBytes = await readFile(destinationManifest);
    const after = await validateA1SupervisorProposal({ proposalRoot });
    if (
      after.descriptorDigest !== before.descriptorDigest
      || sha256(binaryBytes) !== A1.binaryDigest
      || sha256(manifestBytes) !== before.descriptor.outputs.distManifest.sha256
      || (await readdir(outputRoot)).sort().join('\0') !== 'dist\0dist.manifest.json'
      || (await readdir(path.join(outputRoot, 'dist'))).join('\0') !== 'verification-supervisor'
    ) return result('BLOCKED', null, 'A1_SUP_RELOCATION_INVALID');
    return result('PASS', {
      descriptorDigest: before.descriptorDigest,
      sourceTreeDigest: before.descriptor.sourceInventory.treeDigest,
      binaryDigest: before.descriptor.outputs.binary.sha256,
      outputPaths: ['dist.manifest.json', 'dist/verification-supervisor'],
    });
  } catch {
    return result('BLOCKED', null, 'A1_SUP_RELOCATION_INVALID');
  }
}
