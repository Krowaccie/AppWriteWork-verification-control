const PROTOCOL_VERSION = 'source-artifact-posix-supervisor.v1';
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 268_435_456;
const SOURCE_REVISION = /^[0-9a-f]{40}$/;
const ABORTED_GETTER = Object.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  'aborted',
).get;

function closed(value) {
  return Object.freeze(Object.assign(Object.create(null), value));
}

function frozenArgv(values) {
  const result = new Array(values.length);
  Object.setPrototypeOf(result, null);
  for (let index = 0; index < values.length; index += 1) {
    Object.defineProperty(result, String(index), {
      configurable: false,
      enumerable: true,
      value: values[index],
      writable: false,
    });
  }
  return Object.freeze(result);
}

const GIT_PREFIX = frozenArgv([
  '--no-replace-objects',
  '-c',
  'core.fsmonitor=false',
  '-c',
  'protocol.allow=never',
  '-c',
  'submodule.recurse=false',
]);
const GIT_ENVIRONMENT = closed({
  LANG: 'C',
  LC_ALL: 'C',
  TZ: 'UTC',
  GIT_ATTR_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
});
const PLATFORM = closed({
  architecture: 'x64',
  operatingSystem: 'linux',
  runnerImage: 'ubuntu-24.04',
});
const CONTAINMENT = closed({
  joinBeforeReturn: true,
  terminateDescendantsOnAbort: true,
});

function diagnostic(code, safeMessage) {
  return closed({ code, retryable: false, safeMessage });
}

function operation(status, code, safeMessage) {
  return closed({
    diagnostics: Object.freeze([diagnostic(code, safeMessage)]),
    status,
    value: null,
  });
}

function pass(value) {
  return closed({ diagnostics: Object.freeze([]), status: 'PASS', value });
}

const NETWORK_UNAVAILABLE = operation(
  'BLOCKED',
  'ARTIFACT_NETWORK_POLICY_UNAVAILABLE',
  'Trusted artifact network isolation is unavailable.',
);
const BUILD_FAILED = operation(
  'FAIL',
  'ARTIFACT_BUILD_FAILED',
  'Trusted artifact process execution failed.',
);

function ownData(value, expectedKeys) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    return null;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors).sort();
  const expected = [...expectedKeys].sort();
  if (names.length !== expected.length) return null;
  for (let index = 0; index < names.length; index += 1) {
    if (names[index] !== expected[index]) return null;
    const descriptor = descriptors[names[index]];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
  }
  const result = Object.create(null);
  for (let index = 0; index < names.length; index += 1) {
    result[names[index]] = descriptors[names[index]].value;
  }
  return result;
}

function posixAbsolute(value) {
  return typeof value === 'string' &&
    value.startsWith('/') &&
    !value.includes('\0') &&
    !value.includes('\\');
}

function boundedInteger(value, maximum) {
  return Number.isInteger(value) && value > 0 && value <= maximum;
}

function readDenseArgv(value) {
  if (!Array.isArray(value) || value.length > 4_096) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors);
  if (
    Object.getOwnPropertySymbols(value).length !== 0 ||
    names.length !== value.length + 1 ||
    !Object.hasOwn(descriptors, 'length')
  ) {
    return null;
  }
  const result = new Array(value.length);
  Object.setPrototypeOf(result, null);
  let retainedBytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value') ||
      typeof descriptor.value !== 'string' ||
      descriptor.value.includes('\0')
    ) {
      return null;
    }
    retainedBytes += Buffer.byteLength(descriptor.value, 'utf8');
    if (retainedBytes > 1_048_576) return null;
    Object.defineProperty(result, String(index), {
      configurable: false,
      enumerable: true,
      value: descriptor.value,
      writable: false,
    });
  }
  return Object.freeze(result);
}

function sameArgv(left, right) {
  const candidate = readDenseArgv(left);
  if (candidate === null || candidate.length !== right.length) return null;
  for (let index = 0; index < right.length; index += 1) {
    if (candidate[index] !== right[index]) return null;
  }
  return candidate;
}

function cloneEnvironment(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    return null;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = Object.create(null);
  for (const name of Object.keys(descriptors).sort()) {
    const descriptor = descriptors[name];
    if (
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value') ||
      name.length === 0 ||
      name.includes('=') ||
      name.includes('\0') ||
      typeof descriptor.value !== 'string' ||
      descriptor.value.includes('\0')
    ) {
      return null;
    }
    result[name] = descriptor.value;
  }
  return Object.freeze(result);
}

function sameEnvironment(candidate, expected) {
  const cloned = cloneEnvironment(candidate);
  if (cloned === null) return null;
  const left = Object.keys(cloned).sort();
  const right = Object.keys(expected).sort();
  if (left.length !== right.length) return null;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index] || cloned[left[index]] !== expected[right[index]]) {
      return null;
    }
  }
  return cloned;
}

function sourceGitArgv(args) {
  const candidate = readDenseArgv(args);
  if (candidate === null || candidate.length < GIT_PREFIX.length + 2) return null;
  for (let index = 0; index < GIT_PREFIX.length; index += 1) {
    if (candidate[index] !== GIT_PREFIX[index]) return null;
  }
  const offset = GIT_PREFIX.length;
  const command = candidate[offset];
  const tailLength = candidate.length - offset;
  if (command === 'cat-file') {
    return tailLength === 2 && candidate[offset + 1] === '--batch'
      ? candidate
      : null;
  }
  if (command === 'rev-parse') {
    const peeledRevision = candidate[offset + 3];
    const suffix = '^{commit}';
    const revision = typeof peeledRevision === 'string' &&
      peeledRevision.endsWith(suffix)
      ? peeledRevision.slice(0, -suffix.length)
      : '';
    return tailLength === 4 &&
      candidate[offset + 1] === '--verify' &&
      candidate[offset + 2] === '--quiet' &&
      SOURCE_REVISION.test(revision)
      ? candidate
      : null;
  }
  if (command === 'ls-tree') {
    return tailLength === 5 &&
      candidate[offset + 1] === '-r' &&
      candidate[offset + 2] === '-z' &&
      candidate[offset + 3] === '--full-tree' &&
      SOURCE_REVISION.test(candidate[offset + 4])
      ? candidate
      : null;
  }
  if (command === 'show') {
    const value = candidate[offset + 1];
    const delimiter = typeof value === 'string' ? value.indexOf(':') : -1;
    return tailLength === 2 &&
      delimiter === 40 &&
      SOURCE_REVISION.test(value.slice(0, delimiter)) &&
      value.slice(delimiter + 1) === 'dev/verification/verification-manifest.v1.json'
      ? candidate
      : null;
  }
  if (command === 'archive') {
    return tailLength === 3 &&
      candidate[offset + 1] === '--format=tar' &&
      SOURCE_REVISION.test(candidate[offset + 2])
      ? candidate
      : null;
  }
  return null;
}

function readSupervisor(value) {
  const fields = ownData(value, ['proveNetworkPolicy', 'run']);
  if (
    fields === null ||
    typeof fields.proveNetworkPolicy !== 'function' ||
    typeof fields.run !== 'function'
  ) {
    return null;
  }
  return closed({
    proveNetworkPolicy: fields.proveNetworkPolicy,
    receiver: value,
    run: fields.run,
  });
}

function readConfiguration(config) {
  const source = ownData(config, [
    'gitExecutable',
    'sourceCheckoutRoot',
    'supervisor',
  ]);
  if (source !== null) {
    const supervisor = readSupervisor(source.supervisor);
    if (
      supervisor === null ||
      !posixAbsolute(source.gitExecutable) ||
      !posixAbsolute(source.sourceCheckoutRoot)
    ) {
      throw new TypeError('source-git transport configuration is invalid');
    }
    return closed({
      executable: source.gitExecutable,
      expectedArgs: null,
      expectedCommandId: null,
      expectedEnvironment: GIT_ENVIRONMENT,
      mode: 'source-git',
      network: 'deny',
      sourceCheckoutRoot: source.sourceCheckoutRoot,
      supervisor,
    });
  }

  const fixed = ownData(config, [
    'args',
    'commandId',
    'cwd',
    'env',
    'executable',
    'network',
    'profile',
    'supervisor',
  ]);
  const supervisor = fixed === null ? null : readSupervisor(fixed.supervisor);
  const args = fixed === null ? null : readDenseArgv(fixed.args);
  const env = fixed === null ? null : cloneEnvironment(fixed.env);
  if (
    fixed === null ||
    fixed.profile !== 'fixed-command' ||
    supervisor === null ||
    typeof fixed.commandId !== 'string' ||
    !posixAbsolute(fixed.executable) ||
    !posixAbsolute(fixed.cwd) ||
    args === null ||
    env === null ||
    (fixed.network !== 'deny' && fixed.network !== 'registry-only')
  ) {
    throw new TypeError('fixed-command transport configuration is invalid');
  }
  return closed({
    executable: fixed.executable,
    expectedArgs: args,
    expectedCommandId: fixed.commandId,
    expectedEnvironment: env,
    mode: 'fixed-command',
    network: fixed.network,
    sourceCheckoutRoot: fixed.cwd,
    supervisor,
  });
}

function cloneInput(value, maximumBytes) {
  if (value === null) return null;
  if (!(value instanceof Uint8Array) || value.byteLength > maximumBytes) return undefined;
  return new Uint8Array(value);
}

function normalizeProcessSpec(value, configuration) {
  const fixed = configuration.mode === 'fixed-command';
  const keys = fixed
    ? [
        'args',
        'commandId',
        'cwd',
        'env',
        'executable',
        'network',
        'retry',
        'shell',
        'stderrLimitBytes',
        'stdoutLimitBytes',
        'timeoutMs',
      ]
    : [
        'args',
        'cwd',
        'env',
        'executable',
        'network',
        'retry',
        'shell',
        'stderrLimitBytes',
        'stdin',
        'stdoutLimitBytes',
        'timeoutMs',
      ];
  const fields = ownData(value, keys);
  if (fields === null) return null;
  const args = fixed
    ? sameArgv(fields.args, configuration.expectedArgs)
    : sourceGitArgv(fields.args);
  const env = sameEnvironment(fields.env, configuration.expectedEnvironment);
  if (
    fields.executable !== configuration.executable ||
    fields.cwd !== configuration.sourceCheckoutRoot ||
    fields.network !== configuration.network ||
    fields.retry !== false ||
    fields.shell !== false ||
    fields.timeoutMs !== MAX_TIMEOUT_MS ||
    !boundedInteger(fields.stdoutLimitBytes, MAX_OUTPUT_BYTES) ||
    !boundedInteger(fields.stderrLimitBytes, MAX_OUTPUT_BYTES) ||
    args === null ||
    env === null ||
    (fixed && fields.commandId !== configuration.expectedCommandId)
  ) {
    return null;
  }
  let stdin;
  if (!fixed) {
    stdin = cloneInput(fields.stdin, MAX_OUTPUT_BYTES);
    if (stdin === undefined) return null;
    const offset = GIT_PREFIX.length;
    const isBatch = args[offset] === 'cat-file';
    if ((isBatch && !(stdin instanceof Uint8Array)) || (!isBatch && stdin !== null)) {
      return null;
    }
  }
  const process = {
    executable: configuration.executable,
    args,
    cwd: configuration.sourceCheckoutRoot,
    env,
    shell: false,
    timeoutMs: MAX_TIMEOUT_MS,
    retry: false,
    network: configuration.network,
    stdoutLimitBytes: fields.stdoutLimitBytes,
    stderrLimitBytes: fields.stderrLimitBytes,
  };
  if (fixed) process.commandId = configuration.expectedCommandId;
  else process.stdin = stdin;
  return closed(process);
}

function networkPolicy(network) {
  return network === 'deny'
    ? closed({ mode: 'deny' })
    : closed({
        host: 'registry.npmjs.org',
        mode: 'registry-only',
        port: 443,
        protocol: 'tls',
      });
}

function abortState(signal) {
  try {
    return Reflect.apply(ABORTED_GETTER, signal, [])
      ? 'aborted'
      : 'active';
  } catch {
    return 'invalid';
  }
}

function normalizeSupervisorResult(candidate, processSpec, aborted) {
  const envelope = ownData(candidate, ['diagnostics', 'status', 'value']);
  if (
    envelope === null ||
    envelope.status !== 'PASS' ||
    !Array.isArray(envelope.diagnostics) ||
    envelope.diagnostics.length !== 0
  ) {
    return null;
  }
  const value = ownData(envelope.value, [
    'containment',
    'exitCode',
    'stderr',
    'stdout',
    'timedOut',
  ]);
  const containment = value === null
    ? null
    : ownData(value.containment, ['descendantsTerminated', 'joined']);
  if (
    value === null ||
    containment === null ||
    containment.joined !== true ||
    typeof containment.descendantsTerminated !== 'boolean' ||
    (!Number.isInteger(value.exitCode) && value.exitCode !== null) ||
    typeof value.timedOut !== 'boolean' ||
    !(value.stdout instanceof Uint8Array) ||
    !(value.stderr instanceof Uint8Array) ||
    value.stdout.byteLength > processSpec.stdoutLimitBytes ||
    value.stderr.byteLength > processSpec.stderrLimitBytes ||
    ((aborted || value.timedOut) && containment.descendantsTerminated !== true)
  ) {
    return null;
  }
  return closed({
    exitCode: value.exitCode,
    stderr: new Uint8Array(value.stderr),
    stdout: new Uint8Array(value.stdout),
    timedOut: value.timedOut,
  });
}

export function createBoundedPosixProcessTransport(config) {
  const configuration = readConfiguration(config);
  return closed({
    async run(processSpec, abortSignal) {
      let signalState = abortState(abortSignal);
      if (signalState === 'invalid') return NETWORK_UNAVAILABLE;
      if (signalState === 'aborted') return BUILD_FAILED;
      let process;
      try {
        process = normalizeProcessSpec(processSpec, configuration);
      } catch {
        return NETWORK_UNAVAILABLE;
      }
      if (process === null) return NETWORK_UNAVAILABLE;
      const policy = networkPolicy(configuration.network);
      let proven;
      try {
        proven = await Reflect.apply(
          configuration.supervisor.proveNetworkPolicy,
          configuration.supervisor.receiver,
          [policy],
        );
      } catch {
        return NETWORK_UNAVAILABLE;
      }
      if (proven !== true) return NETWORK_UNAVAILABLE;
      signalState = abortState(abortSignal);
      if (signalState !== 'active') return BUILD_FAILED;
      const request = closed({
        containment: CONTAINMENT,
        networkPolicy: policy,
        platform: PLATFORM,
        process,
        protocolVersion: PROTOCOL_VERSION,
      });
      let candidate;
      try {
        candidate = await Reflect.apply(
          configuration.supervisor.run,
          configuration.supervisor.receiver,
          [request, abortSignal],
        );
      } catch {
        return BUILD_FAILED;
      }
      signalState = abortState(abortSignal);
      let result;
      try {
        result = normalizeSupervisorResult(
          candidate,
          process,
          signalState === 'aborted',
        );
      } catch {
        return BUILD_FAILED;
      }
      signalState = abortState(abortSignal);
      if (signalState !== 'active') return BUILD_FAILED;
      return result === null ? BUILD_FAILED : pass(result);
    },
  });
}
