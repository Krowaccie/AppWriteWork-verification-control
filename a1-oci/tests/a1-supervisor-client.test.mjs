import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

import { createA1SupervisorClient } from '../host/a1-supervisor-client.mjs';
import { createA1NetworkPolicyProbe } from '../host/network-policy-probe.mjs';

const REVISION = '0123456789abcdef0123456789abcdef01234567';
const PREFIX = Object.freeze([
  '--no-replace-objects', '-c', 'core.fsmonitor=false', '-c',
  'protocol.allow=never', '-c', 'submodule.recurse=false',
  '-c', 'safe.directory=/work/source',
]);

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

function parseFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 20) {
    const length = buffer.readUInt32BE(offset + 16);
    if (buffer.length - offset < 20 + length) break;
    frames.push({
      mode: buffer[offset + 6],
      kind: buffer[offset + 7],
      sequence: buffer.readBigUInt64BE(offset + 8),
      payload: buffer.subarray(offset + 20, offset + 20 + length),
    });
    offset += 20 + length;
  }
  return { frames, remainder: buffer.subarray(offset) };
}

function fakeProcess(handler) {
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
  let encoded = Buffer.alloc(0);
  let handled = false;
  let requestFrames = [];
  child.stdin.on('data', (chunk) => {
    encoded = Buffer.concat([encoded, chunk]);
    const parsed = parseFrames(encoded);
    encoded = parsed.remainder;
    requestFrames.push(...parsed.frames);
    if (!handled && requestFrames.some(({ kind }) => kind === 3)) {
      handled = true;
      const complete = requestFrames;
      requestFrames = [];
      void handler(child, complete);
    } else if (handled) {
      const complete = requestFrames;
      requestFrames = [];
      if (complete.length > 0) void handler(child, complete);
    }
  });
  return child;
}

function processRequest() {
  return closed({
    containment: closed({ joinBeforeReturn: true, terminateDescendantsOnAbort: true }),
    networkPolicy: closed({ mode: 'deny' }),
    platform: closed({ architecture: 'x64', operatingSystem: 'linux', runnerImage: 'ubuntu-24.04' }),
    process: closed({
      args: Object.freeze([...PREFIX, 'rev-parse', '--verify', '--quiet', `${REVISION}^{commit}`]),
      cwd: '/work/source',
      env: closed({
        LANG: 'C', LC_ALL: 'C', TZ: 'UTC', GIT_ATTR_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
        GIT_NO_LAZY_FETCH: '1', GIT_NO_REPLACE_OBJECTS: '1',
        GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0',
      }),
      executable: '/usr/bin/git',
      network: 'deny',
      retry: false,
      shell: false,
      stderrLimitBytes: 64,
      stdin: null,
      stdoutLimitBytes: 64,
      timeoutMs: 600_000,
    }),
    protocolVersion: 'source-artifact-posix-supervisor.v1',
  });
}

function clientFixture(handler, probeResult = true) {
  const spawns = [];
  const probeCalls = [];
  const client = createA1SupervisorClient({
    networkPolicyProbe: Object.freeze({
      async run(request) {
        probeCalls.push(request);
        return closed({
          enforced: probeResult,
          policy: request.policy,
          protocolVersion: 'source-artifact-posix-network-probe.v1',
        });
      },
    }),
    spawnProcess(executable, args, options) {
      spawns.push({ executable, args, options });
      return fakeProcess(handler);
    },
  });
  return { client, probeCalls, spawns };
}

test('process adapter emits exact A1SV request and a fixed sanitized spawn', async () => {
  let requestFrames;
  const fixture = clientFixture((child, frames) => {
    requestFrames = frames;
    const start = Buffer.alloc(9);
    start[0] = 0;
    start.writeInt32BE(0, 1);
    start.set([0, 0, 0, 1], 5);
    child.stdout.write(frame(1, 5, 1, start));
    child.stdout.write(frame(1, 6, 2, Buffer.from([1, 7, 8])));
    child.stdout.write(frame(1, 6, 3, Buffer.from([2, 9])));
    child.stdout.write(frame(1, 7, 4));
    child.stdout.end();
    queueMicrotask(() => child.emit('close', 0, null));
  });

  const policy = closed({ mode: 'deny' });
  assert.equal(await fixture.client.proveNetworkPolicy(policy), true);
  const result = await fixture.client.run(processRequest(), new AbortController().signal);

  assert.equal(result.status, 'PASS');
  assert.deepEqual([...result.value.stdout], [7, 8]);
  assert.deepEqual([...result.value.stderr], [9]);
  assert.equal(result.value.containment.joined, true);
  assert.deepEqual(requestFrames.map(({ mode, kind, sequence }) => [mode, kind, sequence]), [
    [1, 1, 1n], [1, 2, 2n], [1, 3, 3n],
  ]);
  assert.deepEqual([...requestFrames[1].payload], [1, ...Buffer.from(REVISION)]);

  assert.equal(fixture.spawns.length, 1);
  assert.equal(fixture.spawns[0].executable, '/opt/appwritework/verification-a1/supervisor/verification-supervisor');
  assert.deepEqual(fixture.spawns[0].args, [
    'source-artifact-posix-supervisor.v1', 'source-git', '/usr/local/bin/node',
    '/usr/local/bin/npm', '/usr/bin/git', '/work/source', '/work/command-temp',
    '/work/config', '/work/npm-cache', '/work/output/site',
  ]);
  assert.deepEqual(fixture.spawns[0].options.env, { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC' });
  assert.equal(Object.hasOwn(fixture.spawns[0].options, 'uid'), false);
  assert.equal(Object.hasOwn(fixture.spawns[0].options, 'gid'), false);
  assert.equal(Object.hasOwn(fixture.spawns[0].options.env, 'ACTIONS_RUNTIME_TOKEN'), false);
  assert.equal(Object.hasOwn(fixture.spawns[0].options.env, 'ACTIONS_RESULTS_URL'), false);
});

test('process adapter accepts the transport hardened null-prototype argv', async () => {
  const fixture = clientFixture((child) => {
    const start = Buffer.alloc(9);
    start[0] = 0;
    start.writeInt32BE(0, 1);
    start.set([0, 0, 0, 1], 5);
    child.stdout.write(frame(1, 5, 1, start));
    child.stdout.write(frame(1, 7, 2));
    child.stdout.end();
    queueMicrotask(() => child.emit('close', 0, null));
  });
  const request = processRequest();
  const hardenedArgs = [...request.process.args];
  Object.setPrototypeOf(hardenedArgs, null);
  Object.freeze(hardenedArgs);
  const hardenedRequest = closed({
    ...request,
    process: closed({ ...request.process, args: hardenedArgs }),
  });

  const result = await fixture.client.run(hardenedRequest, new AbortController().signal);

  assert.equal(result.status, 'PASS');
  assert.equal(fixture.spawns.length, 1);
});

test('network proof is an exact controller-owned probe call, never a constant success', async () => {
  const fixture = clientFixture(() => {}, false);
  const policy = closed({
    host: 'registry.npmjs.org', mode: 'registry-only', port: 443, protocol: 'tls',
  });
  assert.equal(await fixture.client.proveNetworkPolicy(policy), false);
  assert.equal(fixture.probeCalls.length, 1);
  assert.deepEqual(fixture.probeCalls[0], closed({
    policy,
    protocolVersion: 'source-artifact-posix-network-probe.v1',
  }));
  assert.equal(fixture.spawns.length, 0);
  assert.equal(await fixture.client.proveNetworkPolicy(closed({ mode: 'open' })), false);
  assert.equal(fixture.probeCalls.length, 1);
});

test('abort writes the next cancel frame and kills then joins on malformed completion', async () => {
  const observed = [];
  const controller = new AbortController();
  let child;
  const fixture = clientFixture((candidate, frames) => {
    child = candidate;
    observed.push(...frames);
    if (frames.some(({ kind }) => kind === 3)) controller.abort();
  });

  await assert.rejects(
    fixture.client.run(processRequest(), controller.signal),
    /A1_SUPERVISOR_ABORTED/u,
  );
  assert.equal(child.killed, true);
  assert.deepEqual(observed.map(({ kind, sequence }) => [kind, sequence]), [
    [1, 1n], [2, 2n], [3, 3n], [4, 4n],
  ]);
});

test('cross-mode, sequence, status and output-bound violations kill and join', async () => {
  for (const response of [
    [frame(2, 5, 1, Buffer.from([0]))],
    [frame(1, 5, 2, Buffer.from([0]))],
    [frame(1, 5, 1, Buffer.from([7])), frame(1, 7, 2)],
    [
      frame(1, 5, 1, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 1])),
      frame(1, 6, 2, Buffer.concat([Buffer.from([1]), Buffer.alloc(65)])),
      frame(1, 7, 3),
    ],
  ]) {
    let child;
    const fixture = clientFixture((candidate) => {
      child = candidate;
      for (const encoded of response) candidate.stdout.write(encoded);
    });
    await assert.rejects(
      fixture.client.run(processRequest(), new AbortController().signal),
      /A1_SUPERVISOR_PROTOCOL/u,
    );
    assert.equal(child.killed, true);
  }
});

test('network policy probe executes both policies through the physical A1 supervisor', async () => {
  const spawns = [];
  const probe = createA1NetworkPolicyProbe({
    spawnProcess(executable, args, options) {
      spawns.push({ executable, args, options });
      return fakeProcess((child) => {
        const start = Buffer.alloc(9);
        start[0] = 0;
        start[8] = 1;
        child.stdout.write(frame(1, 5, 1, start));
        child.stdout.write(frame(1, 7, 2));
        child.stdout.end();
        queueMicrotask(() => child.emit('close', 0, null));
      });
    },
  });
  const deny = closed({ mode: 'deny' });
  const registry = closed({
    host: 'registry.npmjs.org', mode: 'registry-only', port: 443, protocol: 'tls',
  });

  assert.equal((await probe.run(closed({
    policy: deny,
    protocolVersion: 'source-artifact-posix-network-probe.v1',
  }))).enforced, true);
  assert.equal((await probe.run(closed({
    policy: registry,
    protocolVersion: 'source-artifact-posix-network-probe.v1',
  }))).enforced, true);
  assert.equal(spawns.length, 2);
  assert.equal(spawns[0].args[1], 'bundle-catalog');
  assert.equal(spawns[1].args[1], 'root-npm-ci');
  assert.equal(spawns.every(({ options }) => Object.hasOwn(options.env, 'ACTIONS_RUNTIME_TOKEN') === false), true);
});

test('process adapter accepts one exact fixed path tuple for the candidate checkout', async () => {
  const paths = closed({
    commandTemp: '/work/launcher/child',
    configHome: '/work/launcher/child/config-home',
    exportRoot: '/github/workspace',
    git: '/usr/bin/git',
    node: '/usr/local/bin/node',
    npm: '/usr/local/bin/npm',
    npmCache: '/work/launcher/child/npm-cache',
    siteOutput: '/work/launcher/site',
  });
  const spawns = [];
  const networkPolicyProbe = Object.freeze({
    async run(request) {
      return closed({
        enforced: true,
        policy: request.policy,
        protocolVersion: 'source-artifact-posix-network-probe.v1',
      });
    },
  });
  const client = createA1SupervisorClient({
    networkPolicyProbe,
    paths,
    spawnProcess(executable, args, options) {
      spawns.push({ executable, args, options });
      return fakeProcess((child) => {
        const start = Buffer.alloc(9);
        start[0] = 0;
        start[8] = 1;
        child.stdout.write(frame(1, 5, 1, start));
        child.stdout.write(frame(1, 7, 2));
        child.stdout.end();
        queueMicrotask(() => child.emit('close', 0, null));
      });
    },
  });
  const request = processRequest();
  const relocated = closed({
    ...request,
    process: closed({
      ...request.process,
      args: Object.freeze([
        ...request.process.args.slice(0, PREFIX.length - 1),
        `safe.directory=${paths.exportRoot}`,
        ...request.process.args.slice(PREFIX.length),
      ]),
      cwd: paths.exportRoot,
    }),
  });
  assert.equal((await client.run(relocated, new AbortController().signal)).status, 'PASS');
  assert.equal(spawns[0].args[5], '/github/workspace');
  assert.deepEqual(spawns[0].options.env, { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC' });
});
