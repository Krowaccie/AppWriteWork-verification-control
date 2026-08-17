import { spawn as nodeSpawn } from 'node:child_process';

const SUPERVISOR_PATH = '/opt/appwritework/verification-a1/supervisor/verification-supervisor';
const PROCESS_PROTOCOL = 'source-artifact-posix-supervisor.v1';
const NETWORK_PROBE_PROTOCOL = 'source-artifact-posix-network-probe.v1';
const MAX_FRAME_PAYLOAD = 1_048_576;
const MAX_PROCESS_BYTES = 268_435_456;
const MAX_STDERR_BYTES = 65_536;
const JOIN_TIMEOUT_MS = 2_000;
const MODE_PROCESS = 1;
const MODE_WORKSPACE = 2;
const KIND_START = 1;
const KIND_DATA = 2;
const KIND_END = 3;
const KIND_CANCEL = 4;
const KIND_RESULT_START = 5;
const KIND_RESULT_DATA = 6;
const KIND_RESULT_END = 7;
const KIND_ERROR = 8;
const REVISION = /^[0-9a-f]{40}$/u;
const GIT_PREFIX = Object.freeze([
  '--no-replace-objects', '-c', 'core.fsmonitor=false', '-c',
  'protocol.allow=never', '-c', 'submodule.recurse=false',
]);
const CHILD_ENVIRONMENT = Object.freeze(Object.assign(Object.create(null), {
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  TZ: 'UTC',
}));
const PROCESS_PATHS = Object.freeze(Object.assign(Object.create(null), {
  commandTemp: '/work/command-temp',
  configHome: '/work/config',
  exportRoot: '/work/source',
  git: '/usr/bin/git',
  node: '/usr/local/bin/node',
  npm: '/usr/local/bin/npm',
  npmCache: '/work/npm-cache',
  siteOutput: '/work/output/site',
}));
const PROCESS_PATH_KEYS = Object.freeze([
  'commandTemp', 'configHome', 'exportRoot', 'git', 'node', 'npm', 'npmCache', 'siteOutput',
]);
const EMPTY_DIAGNOSTICS = Object.freeze([]);
const abortGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const addEventListener = EventTarget.prototype.addEventListener;
const removeEventListener = EventTarget.prototype.removeEventListener;

function closed(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function failure(status, code, safeMessage) {
  return closed({
    diagnostics: Object.freeze([closed({ code, retryable: false, safeMessage })]),
    status,
    value: null,
  });
}

function pass(value) {
  return closed({ diagnostics: EMPTY_DIAGNOSTICS, status: 'PASS', value });
}

function protocolError(code = 'A1_SUPERVISOR_PROTOCOL') {
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

function exactRecord(value, expected) {
  const fields = ownData(value, Object.keys(expected));
  if (fields === null) return false;
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (fields[key] !== expectedValue) return false;
  }
  return true;
}

function exactArray(value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length || Reflect.ownKeys(value).length !== value.length + 1) {
    return false;
  }
  for (let index = 0; index < expected.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !descriptor.enumerable || descriptor.value !== expected[index]) return false;
  }
  return true;
}

function abortState(signal) {
  try {
    return Reflect.apply(abortGetter, signal, []) ? 'aborted' : 'active';
  } catch {
    return 'invalid';
  }
}

function encodeFrame(mode, kind, sequence, payload = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
  if (payload.length > MAX_FRAME_PAYLOAD || sequence <= 0n) throw protocolError();
  const header = Buffer.alloc(20);
  header.write('A1SV', 0, 'ascii');
  header.writeUInt16BE(1, 4);
  header[6] = mode;
  header[7] = kind;
  header.writeBigUInt64BE(sequence, 8);
  header.writeUInt32BE(payload.length, 16);
  return Buffer.concat([header, payload]);
}

function spawnOptions() {
  return {
    cwd: '/',
    env: { LANG: CHILD_ENVIRONMENT.LANG, LC_ALL: CHILD_ENVIRONMENT.LC_ALL, TZ: CHILD_ENVIRONMENT.TZ },
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  };
}

function validateChild(child) {
  if (
    child === null || typeof child !== 'object'
    || child.stdin === null || typeof child.stdin?.write !== 'function'
    || child.stdout === null || typeof child.stdout?.on !== 'function'
    || child.stderr === null || typeof child.stderr?.on !== 'function'
    || typeof child.on !== 'function' || typeof child.kill !== 'function'
  ) throw protocolError('A1_SUPERVISOR_SPAWN');
}

export function createA1SupervisorSession({
  args,
  maxResponseBytes,
  mode,
  spawnProcess = nodeSpawn,
}) {
  if (
    (mode !== MODE_PROCESS && mode !== MODE_WORKSPACE)
    || !Array.isArray(args) || !args.every((value) => typeof value === 'string')
    || !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0
    || maxResponseBytes > MAX_PROCESS_BYTES + 4_096 || typeof spawnProcess !== 'function'
  ) throw new TypeError('A1 supervisor session configuration is invalid.');

  const child = spawnProcess(SUPERVISOR_PATH, [...args], spawnOptions());
  validateChild(child);
  let inputSequence = 1n;
  let outputSequence = 1n;
  let outputBuffer = Buffer.alloc(0);
  let stderrBytes = 0;
  let terminalError = null;
  let pending = null;
  let closedState = false;
  let closeInfo = null;
  let settleClose;
  const closePromise = new Promise((resolve) => { settleClose = resolve; });

  function fail(error) {
    if (terminalError === null) terminalError = error;
    if (pending !== null) {
      const current = pending;
      pending = null;
      current.reject(error);
    }
  }

  child.on('error', () => {
    fail(protocolError('A1_SUPERVISOR_SPAWN'));
    if (!closedState) {
      closedState = true;
      closeInfo = { code: null, signal: null };
      settleClose(closeInfo);
    }
  });
  child.on('close', (code, signal) => {
    if (!closedState) {
      closedState = true;
      closeInfo = { code, signal };
      settleClose(closeInfo);
    }
    if (pending !== null) fail(protocolError('A1_SUPERVISOR_EARLY_EXIT'));
  });
  child.stderr.on('data', (chunk) => {
    stderrBytes += Buffer.byteLength(chunk);
    if (stderrBytes > MAX_STDERR_BYTES) fail(protocolError());
  });

  function acceptFrame(frameMode, kind, sequence, payload) {
    if (frameMode !== mode || sequence !== outputSequence || pending === null) {
      fail(protocolError());
      return;
    }
    outputSequence += 1n;
    if (kind === KIND_ERROR) {
      fail(protocolError());
      return;
    }
    if (pending.state === 'start') {
      if (kind !== KIND_RESULT_START || payload.length < 1) {
        fail(protocolError());
        return;
      }
      pending.status = payload[0];
      pending.start = Buffer.from(payload.subarray(1));
      pending.state = 'data';
      return;
    }
    if (pending.state !== 'data') {
      fail(protocolError());
      return;
    }
    if (kind === KIND_RESULT_DATA) {
      if (payload.length === 0) {
        fail(protocolError());
        return;
      }
      pending.total += payload.length;
      if (pending.total > maxResponseBytes) {
        fail(protocolError());
        return;
      }
      pending.chunks.push(Buffer.from(payload));
      return;
    }
    if (kind !== KIND_RESULT_END || payload.length !== 0) {
      fail(protocolError());
      return;
    }
    const current = pending;
    pending = null;
    current.resolve(closed({
      chunks: Object.freeze(current.chunks),
      start: current.start,
      status: current.status,
    }));
  }

  child.stdout.on('data', (chunk) => {
    if (terminalError !== null) return;
    outputBuffer = Buffer.concat([outputBuffer, Buffer.from(chunk)]);
    while (outputBuffer.length >= 20) {
      if (
        outputBuffer.subarray(0, 4).toString('ascii') !== 'A1SV'
        || outputBuffer.readUInt16BE(4) !== 1
      ) {
        fail(protocolError());
        return;
      }
      const length = outputBuffer.readUInt32BE(16);
      if (length > MAX_FRAME_PAYLOAD) {
        fail(protocolError());
        return;
      }
      if (outputBuffer.length < 20 + length) return;
      const frameMode = outputBuffer[6];
      const kind = outputBuffer[7];
      const sequence = outputBuffer.readBigUInt64BE(8);
      const payload = outputBuffer.subarray(20, 20 + length);
      outputBuffer = outputBuffer.subarray(20 + length);
      acceptFrame(frameMode, kind, sequence, payload);
      if (terminalError !== null) return;
    }
  });
  child.stdout.on('end', () => {
    if (outputBuffer.length !== 0) fail(protocolError());
  });

  async function write(encoded) {
    if (terminalError !== null || closedState) throw terminalError ?? protocolError('A1_SUPERVISOR_EARLY_EXIT');
    await new Promise((resolve, reject) => {
      child.stdin.write(encoded, (error) => error ? reject(protocolError()) : resolve());
    });
  }

  async function terminate() {
    if (!closedState) {
      try { child.kill('SIGKILL'); } catch { fail(protocolError('A1_SUPERVISOR_JOIN')); }
    }
    const joined = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), JOIN_TIMEOUT_MS);
      closePromise.then(() => {
        clearTimeout(timer);
        resolve(true);
      });
    });
    if (!joined) throw protocolError('A1_SUPERVISOR_JOIN');
    return closeInfo;
  }

  async function request(payload, { abortMode = 'kill', signal = null } = {}) {
    if (!(payload instanceof Uint8Array) || payload.byteLength > MAX_PROCESS_BYTES || pending !== null) {
      throw protocolError();
    }
    if (signal !== null && abortState(signal) !== 'active') {
      if (abortState(signal) === 'aborted') throw protocolError(mode === MODE_PROCESS ? 'A1_SUPERVISOR_ABORTED' : 'A1_WORKSPACE_ABORTED');
      throw protocolError();
    }
    let resolveResult;
    let rejectResult;
    const response = new Promise((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });
    pending = {
      chunks: [],
      reject: rejectResult,
      resolve: resolveResult,
      start: null,
      state: 'start',
      status: null,
      total: 0,
    };
    let aborting = false;
    const abortCode = mode === MODE_PROCESS ? 'A1_SUPERVISOR_ABORTED' : 'A1_WORKSPACE_ABORTED';
    const onAbort = () => {
      if (aborting || pending === null) return;
      aborting = true;
      const cancelSequence = inputSequence;
      inputSequence += 1n;
      void (async () => {
        try {
          if (abortMode === 'cancel') await write(encodeFrame(mode, KIND_CANCEL, cancelSequence));
        } catch {
          // The terminal abort result below remains authoritative.
        }
        fail(protocolError(abortCode));
      })();
    };
    if (signal !== null) Reflect.apply(addEventListener, signal, ['abort', onAbort, { once: true }]);
    try {
      let sequence = inputSequence;
      inputSequence += 1n;
      await write(encodeFrame(mode, KIND_START, sequence));
      const bytes = Buffer.from(payload);
      for (let offset = 0; offset < bytes.length; offset += MAX_FRAME_PAYLOAD) {
        sequence = inputSequence;
        inputSequence += 1n;
        await write(encodeFrame(
          mode,
          KIND_DATA,
          sequence,
          bytes.subarray(offset, Math.min(bytes.length, offset + MAX_FRAME_PAYLOAD)),
        ));
      }
      sequence = inputSequence;
      inputSequence += 1n;
      await write(encodeFrame(mode, KIND_END, sequence));
      if (signal !== null && abortState(signal) === 'aborted') onAbort();
      return await response;
    } catch (error) {
      fail(error instanceof Error ? error : protocolError());
      await terminate();
      throw terminalError ?? error;
    } finally {
      if (signal !== null) {
        try { Reflect.apply(removeEventListener, signal, ['abort', onAbort]); } catch { /* branded above */ }
      }
    }
  }

  return closed({
    child,
    closeInput() {
      try { child.stdin.end(); } catch { fail(protocolError()); }
    },
    request,
    terminate,
    waitForClose() { return closePromise; },
  });
}

function networkPolicy(value) {
  if (exactRecord(value, { mode: 'deny' })) return closed({ mode: 'deny' });
  if (exactRecord(value, {
    host: 'registry.npmjs.org', mode: 'registry-only', port: 443, protocol: 'tls',
  })) return closed({
    host: 'registry.npmjs.org', mode: 'registry-only', port: 443, protocol: 'tls',
  });
  return null;
}

function sameEnvironment(value, expected) {
  return exactRecord(value, expected);
}

function validateProcessPaths(value) {
  const fields = ownData(value, PROCESS_PATH_KEYS);
  if (fields === null) return null;
  for (const path of Object.values(fields)) {
    if (
      typeof path !== 'string' || !path.startsWith('/') || path.length > 4_096
      || path.includes('//') || path.split('/').some((segment) => segment === '.' || segment === '..')
    ) return null;
  }
  return closed(fields);
}

function baseEnvironment(paths = PROCESS_PATHS) {
  return {
    CI: '1', HOME: paths.configHome, LC_ALL: 'C.UTF-8',
    PATH: '/usr/local/bin', SOURCE_DATE_EPOCH: '0', TEMP: paths.commandTemp,
    TMP: paths.commandTemp, TMPDIR: paths.commandTemp, TZ: 'UTC',
    USERPROFILE: paths.configHome, XDG_CONFIG_HOME: paths.configHome,
  };
}

function installEnvironment(paths = PROCESS_PATHS) {
  return {
    ...baseEnvironment(paths),
    NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_CACHE: paths.npmCache,
    NPM_CONFIG_FETCH_RETRIES: '0', NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT: '0',
    NPM_CONFIG_FETCH_RETRY_MINTIMEOUT: '0', NPM_CONFIG_FUND: 'false',
    NPM_CONFIG_IGNORE_SCRIPTS: 'true', NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/',
  };
}

function fixedProfiles(paths) {
  return Object.freeze({
    'bundle-catalog': Object.freeze({
      args: ['scripts/bundle-catalog.mjs'], cwd: paths.exportRoot,
      env: baseEnvironment(paths), executable: paths.node, network: 'deny',
    }),
    'root-npm-ci': Object.freeze({
      args: ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd: paths.exportRoot,
      env: installEnvironment(paths), executable: paths.npm, network: 'registry-only',
    }),
    typecheck: Object.freeze({
      args: ['exec', '--', 'tsc', '-b', '--pretty', 'false'], cwd: `${paths.exportRoot}/src/web`,
      env: baseEnvironment(paths), executable: paths.npm, network: 'deny',
    }),
    'vite-build': Object.freeze({
      args: ['exec', '--', 'vite', 'build', '--outDir', paths.siteOutput, '--emptyOutDir'],
      cwd: `${paths.exportRoot}/src/web`, env: baseEnvironment(paths),
      executable: paths.npm, network: 'deny',
    }),
    'web-npm-ci': Object.freeze({
      args: ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd: `${paths.exportRoot}/src/web`,
      env: installEnvironment(paths), executable: paths.npm, network: 'registry-only',
    }),
  });
}

function parseGit(process, paths) {
  const fields = ownData(process, [
    'args', 'cwd', 'env', 'executable', 'network', 'retry', 'shell',
    'stderrLimitBytes', 'stdin', 'stdoutLimitBytes', 'timeoutMs',
  ]);
  if (
    fields === null || fields.executable !== paths.git
    || fields.cwd !== paths.exportRoot || fields.network !== 'deny'
    || fields.retry !== false || fields.shell !== false || fields.timeoutMs !== 600_000
    || !Number.isSafeInteger(fields.stdoutLimitBytes) || fields.stdoutLimitBytes <= 0
    || !Number.isSafeInteger(fields.stderrLimitBytes) || fields.stderrLimitBytes <= 0
    || fields.stdoutLimitBytes > MAX_PROCESS_BYTES || fields.stderrLimitBytes > MAX_PROCESS_BYTES
    || !sameEnvironment(fields.env, {
      LANG: 'C', LC_ALL: 'C', TZ: 'UTC', GIT_ATTR_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_NO_LAZY_FETCH: '1',
      GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0',
    })
    || !Array.isArray(fields.args) || !exactArray(fields.args.slice(0, GIT_PREFIX.length), GIT_PREFIX)
  ) return null;
  const tail = fields.args.slice(GIT_PREFIX.length);
  let opcode;
  let body;
  if (tail.length === 4 && tail[0] === 'rev-parse' && tail[1] === '--verify' && tail[2] === '--quiet' && tail[3].endsWith('^{commit}')) {
    opcode = 1; body = tail[3].slice(0, -9);
  } else if (tail.length === 5 && exactArray(tail.slice(0, 4), ['ls-tree', '-r', '-z', '--full-tree'])) {
    opcode = 2; body = tail[4];
  } else if (tail.length === 2 && exactArray(tail, ['cat-file', '--batch']) && fields.stdin instanceof Uint8Array && fields.stdin.byteLength > 0) {
    return closed({ limits: fields, payload: Buffer.concat([Buffer.from([3]), Buffer.from(fields.stdin)]), profile: 'source-git' });
  } else if (tail.length === 2 && tail[0] === 'show' && tail[1].endsWith(':dev/verification/verification-manifest.v1.json')) {
    opcode = 4; body = tail[1].slice(0, 40);
    if (tail[1] !== `${body}:dev/verification/verification-manifest.v1.json`) return null;
  } else if (tail.length === 3 && tail[0] === 'archive' && tail[1] === '--format=tar') {
    opcode = 5; body = tail[2];
  } else return null;
  if (!REVISION.test(body) || fields.stdin !== null) return null;
  return closed({ limits: fields, payload: Buffer.concat([Buffer.from([opcode]), Buffer.from(body)]), profile: 'source-git' });
}

function parseFixed(process, profiles) {
  const fields = ownData(process, [
    'args', 'commandId', 'cwd', 'env', 'executable', 'network', 'retry', 'shell',
    'stderrLimitBytes', 'stdoutLimitBytes', 'timeoutMs',
  ]);
  const profile = fields === null ? null : profiles[fields.commandId];
  if (
    profile === undefined || fields.executable !== profile.executable || fields.cwd !== profile.cwd
    || fields.network !== profile.network || fields.retry !== false || fields.shell !== false
    || fields.timeoutMs !== 600_000 || !exactArray(fields.args, profile.args)
    || !sameEnvironment(fields.env, profile.env)
    || !Number.isSafeInteger(fields.stdoutLimitBytes) || fields.stdoutLimitBytes <= 0
    || !Number.isSafeInteger(fields.stderrLimitBytes) || fields.stderrLimitBytes <= 0
    || fields.stdoutLimitBytes > MAX_PROCESS_BYTES || fields.stderrLimitBytes > MAX_PROCESS_BYTES
  ) return null;
  return closed({ limits: fields, payload: Buffer.alloc(0), profile: fields.commandId });
}

function parseRunRequest(value, paths, profiles) {
  const request = ownData(value, [
    'containment', 'networkPolicy', 'platform', 'process', 'protocolVersion',
  ]);
  if (
    request === null || request.protocolVersion !== PROCESS_PROTOCOL
    || !exactRecord(request.containment, { joinBeforeReturn: true, terminateDescendantsOnAbort: true })
    || !exactRecord(request.platform, { architecture: 'x64', operatingSystem: 'linux', runnerImage: 'ubuntu-24.04' })
  ) return null;
  const policy = networkPolicy(request.networkPolicy);
  if (policy === null) return null;
  const process = parseGit(request.process, paths) ?? parseFixed(request.process, profiles);
  if (process === null || process.limits.network !== policy.mode) return null;
  return process;
}

function processResult(response, limits) {
  if (response.status !== 0 || response.start.length !== 8) {
    if (response.status === 1 && response.start.length === 0) {
      return failure('BLOCKED', 'ARTIFACT_NETWORK_POLICY_UNAVAILABLE', 'Trusted artifact network isolation is unavailable.');
    }
    if (response.status === 3 && response.start.length === 0) {
      return failure('BLOCKED', 'ARTIFACT_CLEANUP_INCOMPLETE', 'Trusted artifact cleanup could not be completed.');
    }
    if (response.status === 2 && response.start.length === 0) {
      return failure('FAIL', 'ARTIFACT_BUILD_FAILED', 'Trusted artifact process execution failed.');
    }
    throw protocolError();
  }
  const rawExitCode = response.start.readInt32BE(0);
  const timedOut = response.start[4];
  const cancelled = response.start[5];
  const descendantsTerminated = response.start[6];
  const joined = response.start[7];
  if (
    ![timedOut, cancelled, descendantsTerminated, joined].every((value) => value === 0 || value === 1)
    || joined !== 1 || cancelled !== 0
  ) throw protocolError();
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  for (const chunk of response.chunks) {
    const tag = chunk[0];
    const bytes = chunk.subarray(1);
    if (bytes.length === 0 || (tag !== 1 && tag !== 2)) throw protocolError();
    if (tag === 1) {
      stdoutBytes += bytes.length;
      if (stdoutBytes > limits.stdoutLimitBytes) throw protocolError();
      stdout.push(bytes);
    } else {
      stderrBytes += bytes.length;
      if (stderrBytes > limits.stderrLimitBytes) throw protocolError();
      stderr.push(bytes);
    }
  }
  return pass(closed({
    containment: closed({
      descendantsTerminated: descendantsTerminated === 1,
      joined: true,
    }),
    exitCode: rawExitCode === -2_147_483_648 ? null : rawExitCode,
    stderr: new Uint8Array(Buffer.concat(stderr)),
    stdout: new Uint8Array(Buffer.concat(stdout)),
    timedOut: timedOut === 1,
  }));
}

export function createA1SupervisorClient(config) {
  const fields = ownData(config, ['networkPolicyProbe', 'paths', 'spawnProcess'])
    ?? ownData(config, ['networkPolicyProbe', 'paths'])
    ?? ownData(config, ['networkPolicyProbe', 'spawnProcess'])
    ?? ownData(config, ['networkPolicyProbe']);
  const probe = fields === null ? null : ownData(fields.networkPolicyProbe, ['run']);
  const spawnProcess = fields?.spawnProcess ?? nodeSpawn;
  const paths = fields?.paths === undefined ? PROCESS_PATHS : validateProcessPaths(fields.paths);
  if (
    probe === null || typeof probe.run !== 'function' || typeof spawnProcess !== 'function'
    || paths === null
  ) {
    throw new TypeError('A1 supervisor client configuration is invalid.');
  }
  const profiles = fixedProfiles(paths);
  const probeReceiver = fields.networkPolicyProbe;
  const probeRun = probe.run;

  async function proveNetworkPolicy(value) {
    const policy = networkPolicy(value);
    if (policy === null) return false;
    try {
      const request = closed({ policy, protocolVersion: NETWORK_PROBE_PROTOCOL });
      const evidence = await Reflect.apply(probeRun, probeReceiver, [request]);
      const result = ownData(evidence, ['enforced', 'policy', 'protocolVersion']);
      return result !== null
        && result.enforced === true
        && result.protocolVersion === NETWORK_PROBE_PROTOCOL
        && networkPolicy(result.policy) !== null
        && JSON.stringify(result.policy) === JSON.stringify(policy);
    } catch {
      return false;
    }
  }

  async function run(request, signal) {
    const parsed = parseRunRequest(request, paths, profiles);
    if (parsed === null || abortState(signal) !== 'active') throw protocolError('A1_SUPERVISOR_REQUEST');
    const session = createA1SupervisorSession({
      args: [
        PROCESS_PROTOCOL, parsed.profile, paths.node, paths.npm,
        paths.git, paths.exportRoot, paths.commandTemp,
        paths.configHome, paths.npmCache, paths.siteOutput,
      ],
      maxResponseBytes: Math.min(
        MAX_PROCESS_BYTES + 4_096,
        parsed.limits.stdoutLimitBytes + parsed.limits.stderrLimitBytes + 4_096,
      ),
      mode: MODE_PROCESS,
      spawnProcess,
    });
    try {
      const response = await session.request(parsed.payload, { abortMode: 'cancel', signal });
      const result = processResult(response, parsed.limits);
      session.closeInput();
      const close = await session.waitForClose();
      if (close.code !== 0 || close.signal !== null) throw protocolError();
      return result;
    } catch (error) {
      await session.terminate();
      throw error;
    }
  }

  return closed({ proveNetworkPolicy, run });
}

export const A1_SUPERVISOR_CONSTANTS = closed({
  childEnvironment: CHILD_ENVIRONMENT,
  modeProcess: MODE_PROCESS,
  modeWorkspace: MODE_WORKSPACE,
  supervisorPath: SUPERVISOR_PATH,
  workspaceProtocol: 'source-artifact-posix-workspace-kernel.v1',
});
