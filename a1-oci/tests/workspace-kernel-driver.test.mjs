import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { createWorkspaceKernelDriver } from '../host/workspace-kernel-driver.mjs';

const MEMBER_PATHS = Object.freeze([
  'site/site.tar.gz',
  ...[
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
  ].map((name) => `functions/${name}.tar.gz`),
  'artifact-manifest.v1.json',
  'artifact-handoff.v1.json',
]);
const TREE_PATHS = Object.freeze([
  'artifact-handoff.v1.json', 'artifact-manifest.v1.json', 'functions',
  ...MEMBER_PATHS.filter((value) => value.startsWith('functions/')).sort(),
  'site', 'site/site.tar.gz',
]);
const SUPERVISOR_TREE_PATHS = Object.freeze([...TREE_PATHS].sort());

function closed(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function frame(mode, kind, sequence, payload = Buffer.alloc(0)) {
  const header = Buffer.alloc(20);
  header.write('A1SV', 0, 'ascii');
  header.writeUInt16BE(1, 4);
  header[6] = mode;
  header[7] = kind;
  header.writeBigUInt64BE(BigInt(sequence), 8);
  header.writeUInt32BE(payload.length, 16);
  return Buffer.concat([header, payload]);
}

function identity(root) {
  const value = Buffer.alloc(28);
  value[0] = root === 'source' ? 1 : 2;
  value.writeBigUInt64BE(7n, 1);
  value.writeBigUInt64BE(root === 'source' ? 11n : 12n, 9);
  value.writeBigUInt64BE(2n, 17);
  value.set([0, 0, 1], 25);
  return value;
}

function fakeWorkspaceSupervisor(dispatch) {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;
  child.kill = () => {
    child.killed = true;
    queueMicrotask(() => child.emit('close', null, 'SIGKILL'));
    return true;
  };
  let input = Buffer.alloc(0);
  let request = [];
  let outputSequence = 1n;
  child.stdin.on('data', (chunk) => {
    input = Buffer.concat([input, chunk]);
    while (input.length >= 20) {
      const length = input.readUInt32BE(16);
      if (input.length < 20 + length) break;
      const current = {
        kind: input[7],
        mode: input[6],
        payload: input.subarray(20, 20 + length),
        sequence: input.readBigUInt64BE(8),
      };
      input = input.subarray(20 + length);
      request.push(current);
      if (current.kind === 3) {
        const frames = request;
        request = [];
        void Promise.resolve(dispatch(frames, child)).then((response) => {
          if (response === undefined) return;
          child.stdout.write(frame(2, 5, outputSequence, Buffer.from([0])));
          outputSequence += 1n;
          if (response.length > 0) {
            child.stdout.write(frame(2, 6, outputSequence, response));
            outputSequence += 1n;
          }
          child.stdout.write(frame(2, 7, outputSequence));
          outputSequence += 1n;
        });
      }
    }
  });
  child.stdin.on('end', () => {
    child.stdout.end();
    queueMicrotask(() => child.emit('close', 0, null));
  });
  return child;
}

function fakeFilesystem() {
  const records = new Map(MEMBER_PATHS.map((relativePath, index) => [relativePath, {
    bytes: Buffer.from(`member-${index}`),
    identity: { dev: 7, ino: 100 + index, mode: 0o100600, nlink: 1 },
  }]));
  const opened = [];
  const filesystem = Object.freeze({
    async lstat(filePath) {
      const relativePath = filePath.slice('/work/output/'.length);
      const record = records.get(relativePath);
      if (record === undefined) throw new Error('missing');
      return { ...record.identity, size: record.bytes.length, isFile: () => true };
    },
    async open(filePath, flags) {
      const relativePath = filePath.slice('/work/output/'.length);
      const record = records.get(relativePath);
      if (record === undefined) throw new Error('missing');
      const handle = {
        closed: false,
        async close() { this.closed = true; },
        async read(buffer, offset, length, position) {
          const bytes = record.bytes.subarray(position, position + length);
          buffer.set(bytes, offset);
          return { bytesRead: bytes.length, buffer };
        },
        async stat() {
          return { ...record.identity, size: record.bytes.length, isFile: () => true };
        },
      };
      opened.push({ filePath, flags, handle });
      return handle;
    },
  });
  return { filesystem, opened, records };
}

function createFixture(dispatch) {
  const spawns = [];
  const fs = fakeFilesystem();
  let child;
  const driver = createWorkspaceKernelDriver({
    filesystem: fs.filesystem,
    spawnProcess(executable, args, options) {
      child = fakeWorkspaceSupervisor(dispatch);
      spawns.push({ executable, args, options });
      return child;
    },
  });
  return { child: () => child, driver, fs, spawns };
}

function normalDispatch(log) {
  const roots = new Map();
  return (frames) => {
    const payload = Buffer.concat(frames.filter(({ kind }) => kind === 2).map(({ payload }) => payload));
    const opcode = payload[0];
    log.push({ frames, opcode, payload });
    if (opcode === 1) {
      const token = Buffer.alloc(32, payload[1] === 1 ? 1 : 2);
      roots.set(token.toString('hex'), payload[1] === 1 ? 'source' : 'output');
      return token;
    }
    if (opcode === 2) {
      const source = payload.subarray(1, 33);
      const token = Buffer.alloc(32, source[0] + 2);
      roots.set(token.toString('hex'), roots.get(source.toString('hex')));
      return token;
    }
    if (opcode === 5) return identity(roots.get(payload.subarray(1, 33).toString('hex')));
    if (opcode === 6) return Buffer.from(SUPERVISOR_TREE_PATHS.join('\n'));
    return Buffer.alloc(0);
  };
}

test('persistent workspace driver exposes exactly 11 methods and maps every opcode serially', async () => {
  const log = [];
  const fixture = createFixture(normalDispatch(log));
  assert.deepEqual(Reflect.ownKeys(fixture.driver).sort(), [
    'closeHandle', 'createCache', 'createRoot', 'exportArchive', 'inspectHandle',
    'inspectTreeAtomically', 'makeImmutable', 'openRoot', 'removeRoot',
    'rollbackExport', 'writeMemberAtomically',
  ]);
  assert.equal(fixture.spawns.length, 1);
  assert.equal(fixture.spawns[0].executable, '/opt/appwritework/verification-a1/supervisor/verification-supervisor');
  assert.deepEqual(fixture.spawns[0].args, [
    'source-artifact-posix-workspace-kernel.v1', '/work/source', '/work/output',
  ]);
  assert.deepEqual(fixture.spawns[0].options.env, { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC' });
  assert.equal(fixture.spawns[0].options.uid, 1000);
  assert.equal(fixture.spawns[0].options.gid, 1000);

  const root = await fixture.driver.createRoot('output');
  const handle = await fixture.driver.openRoot(root.native);
  await fixture.driver.inspectHandle(handle.native);
  await fixture.driver.createCache(handle.native);
  await fixture.driver.exportArchive(handle.native, new Uint8Array([1, 2]));
  await fixture.driver.makeImmutable(handle.native);
  await fixture.driver.rollbackExport(handle.native);
  await fixture.driver.writeMemberAtomically(handle.native, 'site/site.tar.gz', new Uint8Array([3]));
  const inspected = await fixture.driver.inspectTreeAtomically(handle.native);
  await fixture.driver.closeHandle(handle.native);
  await fixture.driver.removeRoot(root.native);

  assert.deepEqual([...new Set(log.map(({ opcode }) => opcode))].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  assert.equal(root.identity.root, 'output');
  assert.equal(root.native instanceof Uint8Array, true);
  assert.equal(root.native.byteLength, 32);
  assert.equal(Object.isFrozen(root), true);
  assert.equal(inspected.snapshot.entries.length, 39);
  assert.deepEqual(inspected.snapshot.entries.map(({ relativePath }) => relativePath), MEMBER_PATHS);
  assert.equal(fixture.fs.opened.length, 39);
  assert.equal(fixture.fs.opened.every(({ filePath }) => filePath.startsWith('/work/output/')), true);

  const read = await inspected.retainedOutput.readMember(closed({
    length: 4, offset: 0, relativePath: MEMBER_PATHS[0],
  }));
  assert.equal(read.status, 'PASS');
  assert.equal(Buffer.from(read.value.bytes).toString(), 'memb');
  assert.equal((await inspected.retainedOutput.revalidate()).status, 'PASS');
  assert.equal((await inspected.retainedOutput.close()).status, 'PASS');
  assert.equal(fixture.fs.opened.every(({ handle: opened }) => opened.closed), true);
});

test('workspace operations are serialized behind one persistent session', async () => {
  let release;
  let calls = 0;
  const gate = new Promise((resolve) => { release = resolve; });
  const fixture = createFixture(async (frames) => {
    const payload = Buffer.concat(frames.filter(({ kind }) => kind === 2).map(({ payload }) => payload));
    calls += 1;
    if (calls === 1) await gate;
    return payload[0] === 1 ? Buffer.alloc(32, payload[1]) : identity('source');
  });
  const first = fixture.driver.createRoot('source');
  const second = fixture.driver.createRoot('source');
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 1);
  release();
  await first;
  await second;
  assert.equal(calls, 4);
});

test('path and retained identity tamper fail closed and terminate the supervisor', async () => {
  const badPaths = [...SUPERVISOR_TREE_PATHS];
  badPaths[0] = '../escape';
  const log = [];
  const fixture = createFixture((frames) => {
    const payload = Buffer.concat(frames.filter(({ kind }) => kind === 2).map(({ payload }) => payload));
    const opcode = payload[0];
    log.push(opcode);
    if (opcode === 1) return Buffer.alloc(32, 2);
    if (opcode === 2) return Buffer.alloc(32, 4);
    if (opcode === 5) return identity('output');
    if (opcode === 6) return Buffer.from(badPaths.join('\n'));
    return Buffer.alloc(0);
  });
  const root = await fixture.driver.createRoot('output');
  const handle = await fixture.driver.openRoot(root.native);
  await assert.rejects(fixture.driver.inspectTreeAtomically(handle.native), /A1_WORKSPACE_PATH/u);
  assert.equal(fixture.child().killed, true);

  const healthy = createFixture(normalDispatch([]));
  const healthyRoot = await healthy.driver.createRoot('output');
  const healthyHandle = await healthy.driver.openRoot(healthyRoot.native);
  const inspected = await healthy.driver.inspectTreeAtomically(healthyHandle.native);
  healthy.fs.records.get(MEMBER_PATHS[0]).identity.ino += 1;
  const revalidated = await inspected.retainedOutput.revalidate();
  assert.equal(revalidated.status, 'BLOCKED');
  assert.equal(revalidated.diagnostics[0].code, 'ARTIFACT_PATH_UNSAFE');
  assert.equal((await inspected.retainedOutput.close()).status, 'PASS');
});

test('abort terminates and joins the persistent workspace supervisor', async () => {
  const controller = new AbortController();
  const baseDispatch = normalDispatch([]);
  const fixture = createFixture((frames, child) => {
    const payload = Buffer.concat(frames.filter(({ kind }) => kind === 2).map(({ payload: value }) => value));
    return payload[0] === 4 ? undefined : baseDispatch(frames, child);
  });
  const root = await fixture.driver.createRoot('output');
  const handle = await fixture.driver.openRoot(root.native);
  const pending = fixture.driver.exportArchive(
    handle.native,
    new Uint8Array([1]),
    Object.freeze({}),
    controller.signal,
  );
  controller.abort();
  await assert.rejects(pending, /A1_WORKSPACE_ABORTED/u);
  assert.equal(fixture.child().killed, true);
});
