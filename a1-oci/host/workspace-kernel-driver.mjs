import { constants as fsConstants } from 'node:fs';
import { lstat as nodeLstat, open as nodeOpen } from 'node:fs/promises';

import {
  A1_SUPERVISOR_CONSTANTS,
  createA1SupervisorSession,
} from './a1-supervisor-client.mjs';

const SOURCE_ROOT = '/work/source';
const OUTPUT_ROOT = '/work/output';
const MAX_WORKSPACE_BYTES = 268_435_456;
const MAX_PATH_BYTES = 4_096;
const OPEN_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_CLOEXEC;
const EMPTY_DIAGNOSTICS = Object.freeze([]);
const FUNCTION_NAMES = Object.freeze([
  'api-keys-py', 'api-router-py', 'billing-cron-py', 'billing-py',
  'billing-webhook-py', 'branch-py', 'cache-cleanup-cron-py', 'catalog-py',
  'chat-py', 'cleanup-cron-py', 'connections-py', 'finance-sync-sec-py',
  'finance-sync-wb-py', 'flowise-runner-py', 'mcp-cleanup-cron-py',
  'mcp-gateway-py', 'project-public-links-py', 'project-public-read-py',
  'project-snapshots-py', 'runs-cancel-py', 'runs-clear-py', 'runs-create-py',
  'runs-detail-py', 'runs-list-py', 'runs-status-py', 'runs-steps-py',
  'sec-cache-builder-py', 'sharing-py', 'smtp-diagnostic-py', 'telemetry-py',
  'usage-cron-py', 'usage-py', 'validate-py', 'verification-email-py',
  'worker-cron-py', 'verification-runner-py',
]);
const MEMBER_PATHS = Object.freeze([
  'site/site.tar.gz',
  ...FUNCTION_NAMES.map((name) => `functions/${name}.tar.gz`),
  'artifact-manifest.v1.json',
  'artifact-handoff.v1.json',
]);
const TREE_PATHS = Object.freeze([
  'artifact-handoff.v1.json',
  'artifact-manifest.v1.json',
  'functions',
  ...FUNCTION_NAMES.map((name) => `functions/${name}.tar.gz`),
  'site',
  'site/site.tar.gz',
]);
const abortGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;

function closed(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function pass(value = null) {
  return closed({ diagnostics: EMPTY_DIAGNOSTICS, status: 'PASS', value });
}

function blocked(code, safeMessage) {
  return closed({
    diagnostics: Object.freeze([closed({ code, retryable: false, safeMessage })]),
    status: 'BLOCKED',
    value: null,
  });
}

const PATH_UNSAFE = () => blocked(
  'ARTIFACT_PATH_UNSAFE',
  'Trusted artifact storage rejected the requested operation.',
);

function workspaceError(code = 'A1_WORKSPACE_PROTOCOL') {
  const error = new Error(code);
  error.code = code;
  return error;
}

function ownData(value, keys) {
  if (
    value === null || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
  ) return null;
  const copy = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      return null;
    }
    copy[key] = descriptor.value;
  }
  return copy;
}

function signalState(signal) {
  if (signal === undefined || signal === null) return 'active';
  try { return Reflect.apply(abortGetter, signal, []) ? 'aborted' : 'active'; } catch { return 'invalid'; }
}

function tokenBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) throw workspaceError('A1_WORKSPACE_TOKEN');
  const copy = Buffer.from(value);
  if (copy.every((byte) => byte === 0)) throw workspaceError('A1_WORKSPACE_TOKEN');
  return copy;
}

function tokenKey(value) {
  return tokenBytes(value).toString('hex');
}

function safeRelativePath(value) {
  if (
    typeof value !== 'string' || value.length === 0 || value.startsWith('/')
    || value.includes('\\') || value.includes('\0') || Buffer.byteLength(value) > MAX_PATH_BYTES
  ) return false;
  const components = value.split('/');
  return components.length <= 32
    && components.every((component) => component !== '' && component !== '.' && component !== '..' && Buffer.byteLength(component) <= 255);
}

function encodeIdentity(bytes, expectedRoot) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 28) throw workspaceError('A1_WORKSPACE_IDENTITY');
  const buffer = Buffer.from(bytes);
  const root = buffer[0] === 1 ? 'source' : buffer[0] === 2 ? 'output' : null;
  const device = buffer.readBigUInt64BE(1);
  const inode = buffer.readBigUInt64BE(9);
  const linkCount = buffer.readBigUInt64BE(17);
  const symbolicLink = buffer[25];
  const caseCollision = buffer[26];
  const componentMatchesRoot = buffer[27];
  if (
    root === null || root !== expectedRoot || device === 0n || inode === 0n || linkCount !== 1n
    || symbolicLink !== 0 || caseCollision !== 0 || componentMatchesRoot !== 1
  ) throw workspaceError('A1_WORKSPACE_IDENTITY');
  const scalar = (value) => value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);
  return closed({
    caseCollision: false,
    component: root,
    device: scalar(device),
    inode: scalar(inode),
    linkCount: 1,
    normalizedComponent: root,
    reparsePoint: false,
    root,
    symbolicLink: false,
    type: 'directory',
  });
}

function sameStat(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.nlink === right.nlink
    && left.mode === right.mode
    && left.size === right.size;
}

function safeRegularStat(value, maximum) {
  return value !== null
    && typeof value === 'object'
    && typeof value.isFile === 'function'
    && value.isFile() === true
    && Number.isSafeInteger(value.dev) && value.dev >= 0
    && Number.isSafeInteger(value.ino) && value.ino > 0
    && value.nlink === 1
    && Number.isSafeInteger(value.mode)
    && (value.mode & 0o170000) === 0o100000
    && (value.mode & 0o777) === 0o600
    && Number.isSafeInteger(value.size) && value.size > 0 && value.size <= maximum;
}

function memberLimit(relativePath) {
  if (relativePath === 'artifact-manifest.v1.json' || relativePath === 'artifact-handoff.v1.json') {
    return 1_048_576;
  }
  return 128 * 1024 * 1024;
}

function absoluteMemberPath(outputRoot, relativePath) {
  return `${outputRoot}/${relativePath}`;
}

function defaultFilesystem() {
  return Object.freeze({ lstat: nodeLstat, open: nodeOpen });
}

function validateFilesystem(value) {
  const fields = ownData(value, ['lstat', 'open']);
  if (fields === null || typeof fields.lstat !== 'function' || typeof fields.open !== 'function') {
    throw new TypeError('Workspace snapshot filesystem is invalid.');
  }
  return { lstat: fields.lstat, open: fields.open, receiver: value };
}

async function closeAll(records) {
  let complete = true;
  for (let index = records.length - 1; index >= 0; index -= 1) {
    try { await records[index].handle.close(); } catch { complete = false; }
  }
  return complete;
}

async function readExact(handle, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(bytes, offset, Math.min(64 * 1024, size - offset), offset);
    if (result === null || !Number.isSafeInteger(result.bytesRead) || result.bytesRead <= 0) {
      throw workspaceError('A1_WORKSPACE_SNAPSHOT');
    }
    offset += result.bytesRead;
  }
  return new Uint8Array(bytes);
}

async function captureRetainedOutput(filesystem, outputRoot) {
  const records = [];
  let totalBytes = 0;
  try {
    for (const relativePath of MEMBER_PATHS) {
      const absolutePath = absoluteMemberPath(outputRoot, relativePath);
      let handle = null;
      try {
        handle = await Reflect.apply(filesystem.open, filesystem.receiver, [absolutePath, OPEN_FLAGS]);
        const stat = await handle.stat();
        const pathStat = await Reflect.apply(filesystem.lstat, filesystem.receiver, [absolutePath]);
        const maximum = memberLimit(relativePath);
        if (!safeRegularStat(stat, maximum) || !safeRegularStat(pathStat, maximum) || !sameStat(stat, pathStat)) {
          throw workspaceError('A1_WORKSPACE_PATH');
        }
        totalBytes += stat.size;
        if (totalBytes > MAX_WORKSPACE_BYTES) throw workspaceError('A1_WORKSPACE_PATH');
        const bytes = await readExact(handle, stat.size);
        const after = await handle.stat();
        const afterPath = await Reflect.apply(filesystem.lstat, filesystem.receiver, [absolutePath]);
        if (!safeRegularStat(after, maximum) || !safeRegularStat(afterPath, maximum) || !sameStat(stat, after) || !sameStat(stat, afterPath)) {
          throw workspaceError('A1_WORKSPACE_PATH');
        }
        records.push({ absolutePath, bytes, handle, identity: {
          dev: stat.dev, ino: stat.ino, mode: stat.mode, nlink: stat.nlink, size: stat.size,
        }, relativePath });
        handle = null;
      } finally {
        if (handle !== null) {
          try { await handle.close(); } catch { /* The operation remains failed closed. */ }
        }
      }
    }
  } catch (error) {
    await closeAll(records);
    throw error;
  }

  let closedState = false;
  let closePromise = null;
  async function validateRecord(record) {
    const stat = await record.handle.stat();
    const pathStat = await Reflect.apply(filesystem.lstat, filesystem.receiver, [record.absolutePath]);
    const maximum = memberLimit(record.relativePath);
    return safeRegularStat(stat, maximum)
      && safeRegularStat(pathStat, maximum)
      && sameStat(record.identity, stat)
      && sameStat(record.identity, pathStat);
  }
  async function revalidate() {
    if (closedState) return PATH_UNSAFE();
    try {
      for (const record of records) if (!(await validateRecord(record))) return PATH_UNSAFE();
      return pass();
    } catch {
      return PATH_UNSAFE();
    }
  }
  async function readMember(request) {
    const fields = ownData(request, ['length', 'offset', 'relativePath']);
    if (
      closedState || fields === null || !Number.isSafeInteger(fields.length) || fields.length <= 0
      || !Number.isSafeInteger(fields.offset) || fields.offset < 0
    ) return PATH_UNSAFE();
    const record = records.find(({ relativePath }) => relativePath === fields.relativePath);
    if (record === undefined || fields.offset + fields.length > record.identity.size) return PATH_UNSAFE();
    try {
      if (!(await validateRecord(record))) return PATH_UNSAFE();
      const bytes = Buffer.alloc(fields.length);
      const read = await record.handle.read(bytes, 0, fields.length, fields.offset);
      if (read.bytesRead !== fields.length || !(await validateRecord(record))) return PATH_UNSAFE();
      return pass(closed({ bytes: new Uint8Array(bytes) }));
    } catch {
      return PATH_UNSAFE();
    }
  }
  function close() {
    if (closePromise !== null) return closePromise;
    closedState = true;
    closePromise = (async () => (
      await closeAll(records)
        ? pass()
        : blocked('ARTIFACT_CLEANUP_INCOMPLETE', 'Trusted artifact cleanup could not be completed.')
    ))();
    return closePromise;
  }
  const retainedOutput = closed({ close, readMember, revalidate });
  const snapshot = closed({
    entries: Object.freeze(records.map(({ bytes, relativePath }) => closed({
      bytes: new Uint8Array(bytes),
      relativePath,
    }))),
  });
  return closed({ retainedOutput, snapshot });
}

export function createWorkspaceKernelDriver(config = {}) {
  const fields = ownData(config, ['filesystem', 'paths', 'spawnProcess'])
    ?? ownData(config, ['paths', 'spawnProcess'])
    ?? ownData(config, ['filesystem', 'paths'])
    ?? ownData(config, ['paths'])
    ?? ownData(config, ['filesystem', 'spawnProcess'])
    ?? ownData(config, ['spawnProcess'])
    ?? ownData(config, []);
  if (fields === null || (fields.spawnProcess !== undefined && typeof fields.spawnProcess !== 'function')) {
    throw new TypeError('Workspace kernel driver configuration is invalid.');
  }
  const paths = fields.paths === undefined
    ? { outputRoot: OUTPUT_ROOT, sourceRoot: SOURCE_ROOT }
    : ownData(fields.paths, ['outputRoot', 'sourceRoot']);
  if (
    paths === null
    || ![paths.outputRoot, paths.sourceRoot].every((value) => (
      typeof value === 'string' && value.startsWith('/') && value.length <= MAX_PATH_BYTES
      && !value.includes('//')
      && !value.split('/').some((component) => component === '.' || component === '..')
    ))
    || paths.outputRoot === paths.sourceRoot
    || paths.outputRoot.startsWith(`${paths.sourceRoot}/`)
    || paths.sourceRoot.startsWith(`${paths.outputRoot}/`)
  ) throw new TypeError('Workspace kernel driver paths are invalid.');
  const filesystem = validateFilesystem(fields.filesystem ?? defaultFilesystem());
  const session = createA1SupervisorSession({
    args: [A1_SUPERVISOR_CONSTANTS.workspaceProtocol, paths.sourceRoot, paths.outputRoot],
    maxResponseBytes: 4 * 1024 * 1024,
    mode: A1_SUPERVISOR_CONSTANTS.modeWorkspace,
    ...(fields.spawnProcess === undefined ? {} : { spawnProcess: fields.spawnProcess }),
  });
  const tokenRoots = new Map();
  let serial = Promise.resolve();
  let terminal = null;

  async function terminate(error) {
    if (terminal === null) terminal = error instanceof Error ? error : workspaceError();
    try { await session.terminate(); } catch (joinError) { terminal = joinError; }
    throw terminal;
  }

  function enqueue(operation) {
    const run = serial.then(async () => {
      if (terminal !== null) throw terminal;
      return operation();
    });
    serial = run.catch(() => {});
    return run;
  }

  async function invoke(payload, signal = null) {
    if (terminal !== null) throw terminal;
    if (signalState(signal) !== 'active') return terminate(workspaceError('A1_WORKSPACE_ABORTED'));
    try {
      const result = await session.request(payload, { abortMode: 'kill', signal });
      if (result.status !== 0 || result.start.length !== 0) throw workspaceError();
      return Buffer.concat(result.chunks);
    } catch (error) {
      return terminate(error);
    }
  }

  function rootFor(token) {
    const root = tokenRoots.get(tokenKey(token));
    if (root === undefined) throw workspaceError('A1_WORKSPACE_TOKEN');
    return root;
  }

  async function inspectHandleNow(token) {
    const native = tokenBytes(token);
    const root = rootFor(native);
    return encodeIdentity(await invoke(Buffer.concat([Buffer.from([5]), native])), root);
  }

  function createRoot(kind) {
    return enqueue(async () => {
      if (kind !== 'source' && kind !== 'output') throw workspaceError('A1_WORKSPACE_PATH');
      const token = tokenBytes(await invoke(Buffer.from([1, kind === 'source' ? 1 : 2])));
      tokenRoots.set(token.toString('hex'), kind);
      const identity = await inspectHandleNow(token);
      return closed({ identity, native: new Uint8Array(token) });
    });
  }

  function openRoot(rootToken) {
    return enqueue(async () => {
      const rootBytes = tokenBytes(rootToken);
      const root = rootFor(rootBytes);
      const token = tokenBytes(await invoke(Buffer.concat([Buffer.from([2]), rootBytes])));
      tokenRoots.set(token.toString('hex'), root);
      const identity = await inspectHandleNow(token);
      return closed({ identity, native: new Uint8Array(token) });
    });
  }

  function inspectHandle(token) {
    return enqueue(() => inspectHandleNow(token));
  }

  function createCache(token) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      const value = await invoke(Buffer.concat([Buffer.from([3]), native]));
      if (value.length !== 0) return terminate(workspaceError());
    });
  }

  function exportArchive(token, bytes, _options, signal) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_WORKSPACE_BYTES) throw workspaceError('A1_WORKSPACE_PATH');
      const value = await invoke(Buffer.concat([Buffer.from([4]), native, Buffer.from(bytes)]), signal);
      if (value.length !== 0) return terminate(workspaceError());
    });
  }

  function makeImmutable(token, signal) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      const value = await invoke(Buffer.concat([Buffer.from([7]), native]), signal);
      if (value.length !== 0) return terminate(workspaceError());
    });
  }

  function rollbackExport(token, signal) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      const value = await invoke(Buffer.concat([Buffer.from([9]), native]), signal);
      if (value.length !== 0) return terminate(workspaceError());
    });
  }

  function writeMemberAtomically(token, relativePath, bytes, _options, signal) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      if (!safeRelativePath(relativePath) || !(bytes instanceof Uint8Array) || bytes.byteLength > MAX_WORKSPACE_BYTES) {
        throw workspaceError('A1_WORKSPACE_PATH');
      }
      const pathBytes = Buffer.from(relativePath);
      const length = Buffer.alloc(2);
      length.writeUInt16BE(pathBytes.length);
      const value = await invoke(Buffer.concat([
        Buffer.from([10]), native, length, pathBytes, Buffer.from(bytes),
      ]), signal);
      if (value.length !== 0) return terminate(workspaceError());
    });
  }

  function inspectTreeAtomically(token) {
    return enqueue(async () => {
      const native = tokenBytes(token);
      if (rootFor(native) !== 'output') throw workspaceError('A1_WORKSPACE_PATH');
      const value = await invoke(Buffer.concat([Buffer.from([6]), native]));
      const treePaths = value.length === 0 ? [] : value.toString('utf8').split('\n');
      if (treePaths.length !== TREE_PATHS.length || treePaths.some((entry, index) => entry !== TREE_PATHS[index])) {
        return terminate(workspaceError('A1_WORKSPACE_PATH'));
      }
      try {
        return await captureRetainedOutput(filesystem, paths.outputRoot);
      } catch (error) {
        return terminate(error);
      }
    });
  }

  function closeHandle(token) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      const value = await invoke(Buffer.concat([Buffer.from([11]), native]));
      if (value.length !== 0) return terminate(workspaceError());
      tokenRoots.delete(native.toString('hex'));
    });
  }

  function removeRoot(token) {
    return enqueue(async () => {
      const native = tokenBytes(token); rootFor(native);
      const value = await invoke(Buffer.concat([Buffer.from([8]), native]));
      if (value.length !== 0) return terminate(workspaceError());
      tokenRoots.delete(native.toString('hex'));
      if (tokenRoots.size === 0) {
        session.closeInput();
        const close = await session.waitForClose();
        if (close.code !== 0 || close.signal !== null) return terminate(workspaceError());
      }
    });
  }

  return closed({
    closeHandle,
    createCache,
    createRoot,
    exportArchive,
    inspectHandle,
    inspectTreeAtomically,
    makeImmutable,
    openRoot,
    removeRoot,
    rollbackExport,
    writeMemberAtomically,
  });
}
