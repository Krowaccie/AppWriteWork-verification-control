import path from 'node:path';

import {
  createBoundedPosixProcessTransport,
} from './source-artifact-posix-process-transport.mjs';

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
    !value.includes('\\') &&
    path.posix.normalize(value) === value;
}

function readConfiguration(config) {
  const fields = ownData(config, [
    'nodeExecutable',
    'npmExecutable',
    'supervisor',
    'workspace',
  ]);
  const workspace = fields === null
    ? null
    : ownData(fields.workspace, [
        'commandTemp',
        'configHome',
        'exportRoot',
        'npmCache',
        'siteOutput',
      ]);
  if (
    fields === null ||
    workspace === null ||
    !posixAbsolute(fields.nodeExecutable) ||
    !posixAbsolute(fields.npmExecutable) ||
    !posixAbsolute(workspace.commandTemp) ||
    !posixAbsolute(workspace.configHome) ||
    !posixAbsolute(workspace.exportRoot) ||
    !posixAbsolute(workspace.npmCache) ||
    !posixAbsolute(workspace.siteOutput)
  ) {
    throw new TypeError('sandbox transport configuration is invalid');
  }
  const roots = [
    workspace.commandTemp,
    workspace.configHome,
    workspace.exportRoot,
    workspace.npmCache,
    workspace.siteOutput,
  ];
  if (new Set(roots).size !== roots.length) {
    throw new TypeError('sandbox workspace paths must be pairwise distinct');
  }
  return closed({
    nodeExecutable: fields.nodeExecutable,
    npmExecutable: fields.npmExecutable,
    supervisor: fields.supervisor,
    workspace: closed(workspace),
  });
}

function environment(configuration, install) {
  const nodeDirectory = path.posix.dirname(configuration.nodeExecutable);
  const npmDirectory = path.posix.dirname(configuration.npmExecutable);
  const pathValue = nodeDirectory === npmDirectory
    ? nodeDirectory
    : nodeDirectory + ':' + npmDirectory;
  const result = {
    CI: '1',
    HOME: configuration.workspace.configHome,
    LC_ALL: 'C.UTF-8',
    PATH: pathValue,
    SOURCE_DATE_EPOCH: '0',
    TEMP: configuration.workspace.commandTemp,
    TMP: configuration.workspace.commandTemp,
    TMPDIR: configuration.workspace.commandTemp,
    TZ: 'UTC',
    USERPROFILE: configuration.workspace.configHome,
    XDG_CONFIG_HOME: configuration.workspace.configHome,
  };
  if (install) {
    result.NPM_CONFIG_CACHE = configuration.workspace.npmCache;
    result.NPM_CONFIG_REGISTRY = 'https://registry.npmjs.org/';
    result.NPM_CONFIG_AUDIT = 'false';
    result.NPM_CONFIG_FUND = 'false';
    result.NPM_CONFIG_IGNORE_SCRIPTS = 'true';
    result.NPM_CONFIG_FETCH_RETRIES = '0';
    result.NPM_CONFIG_FETCH_RETRY_MINTIMEOUT = '0';
    result.NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT = '0';
  }
  return closed(result);
}

function fixedTransport(configuration, command) {
  return createBoundedPosixProcessTransport({
    args: command.args,
    commandId: command.commandId,
    cwd: command.cwd,
    env: command.env,
    executable: command.executable,
    network: command.network,
    profile: 'fixed-command',
    supervisor: configuration.supervisor,
  });
}

function buildTransports(configuration) {
  const webRoot = path.posix.join(
    configuration.workspace.exportRoot,
    'src',
    'web',
  );
  const baseEnvironment = environment(configuration, false);
  const installEnvironment = environment(configuration, true);
  const transports = Object.create(null);
  transports['root-npm-ci'] = fixedTransport(configuration, closed({
    args: frozenArgv(['ci', '--ignore-scripts', '--no-audit', '--no-fund']),
    commandId: 'root-npm-ci',
    cwd: configuration.workspace.exportRoot,
    env: installEnvironment,
    executable: configuration.npmExecutable,
    network: 'registry-only',
  }));
  transports['web-npm-ci'] = fixedTransport(configuration, closed({
    args: frozenArgv(['ci', '--ignore-scripts', '--no-audit', '--no-fund']),
    commandId: 'web-npm-ci',
    cwd: webRoot,
    env: installEnvironment,
    executable: configuration.npmExecutable,
    network: 'registry-only',
  }));
  transports['bundle-catalog'] = fixedTransport(configuration, closed({
    args: frozenArgv(['scripts/bundle-catalog.mjs']),
    commandId: 'bundle-catalog',
    cwd: configuration.workspace.exportRoot,
    env: baseEnvironment,
    executable: configuration.nodeExecutable,
    network: 'deny',
  }));
  transports.typecheck = fixedTransport(configuration, closed({
    args: frozenArgv(['exec', '--', 'tsc', '-b', '--pretty', 'false']),
    commandId: 'typecheck',
    cwd: webRoot,
    env: baseEnvironment,
    executable: configuration.npmExecutable,
    network: 'deny',
  }));
  transports['vite-build'] = fixedTransport(configuration, closed({
    args: frozenArgv([
      'exec',
      '--',
      'vite',
      'build',
      '--outDir',
      configuration.workspace.siteOutput,
      '--emptyOutDir',
    ]),
    commandId: 'vite-build',
    cwd: webRoot,
    env: baseEnvironment,
    executable: configuration.npmExecutable,
    network: 'deny',
  }));
  return Object.freeze(transports);
}

function failure(status, code, safeMessage) {
  return closed({
    diagnostics: Object.freeze([
      closed({ code, retryable: false, safeMessage }),
    ]),
    status,
    value: null,
  });
}

const NETWORK_UNAVAILABLE = failure(
  'BLOCKED',
  'ARTIFACT_NETWORK_POLICY_UNAVAILABLE',
  'Trusted artifact network isolation is unavailable.',
);
const BUILD_FAILED = failure(
  'FAIL',
  'ARTIFACT_BUILD_FAILED',
  'Trusted artifact build command failed.',
);
const PASS = closed({ diagnostics: Object.freeze([]), status: 'PASS', value: null });

function commandIdFromSpec(value) {
  const fields = ownData(value, [
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
  ]);
  return fields !== null && typeof fields.commandId === 'string'
    ? fields.commandId
    : null;
}

function successfulProcessResult(result) {
  if (
    result === null ||
    typeof result !== 'object' ||
    result.status !== 'PASS' ||
    result.value === null ||
    result.value.exitCode !== 0 ||
    result.value.timedOut !== false
  ) {
    return false;
  }
  return result.value.stdout instanceof Uint8Array &&
    result.value.stderr instanceof Uint8Array;
}

export function createBoundedPosixSandboxTransport(config) {
  const configuration = readConfiguration(config);
  const transports = buildTransports(configuration);
  return closed({
    async run(processSpec, abortSignal) {
      let commandId;
      try {
        commandId = commandIdFromSpec(processSpec);
      } catch {
        return NETWORK_UNAVAILABLE;
      }
      if (commandId === null || !Object.hasOwn(transports, commandId)) {
        return NETWORK_UNAVAILABLE;
      }
      const result = await Reflect.apply(
        transports[commandId].run,
        transports[commandId],
        [processSpec, abortSignal],
      );
      if (result.status === 'BLOCKED') return result;
      return successfulProcessResult(result) ? PASS : BUILD_FAILED;
    },
  });
}
