import { types as utilTypes } from 'node:util';

const applyIntrinsic = Reflect.apply;
const freezeIntrinsic = Object.freeze;
const objectCreateIntrinsic = Object.create;
const objectGetOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOfIntrinsic = Object.getPrototypeOf;
const objectHasOwnIntrinsic = Object.hasOwn;
const objectIsFrozenIntrinsic = Object.isFrozen;
const reflectOwnKeysIntrinsic = Reflect.ownKeys;
const numberIsSafeIntegerIntrinsic = Number.isSafeInteger;
const stringToLowerCaseIntrinsic = String.prototype.toLowerCase;
const stringSplitIntrinsic = String.prototype.split;
const stringStartsWithIntrinsic = String.prototype.startsWith;
const uint8ArrayFromIntrinsic = Uint8Array.from;
const weakMapGetIntrinsic = WeakMap.prototype.get;
const weakMapSetIntrinsic = WeakMap.prototype.set;
const isProxyIntrinsic = utilTypes.isProxy;
const NativeWeakMap = WeakMap;
const hostStates = new NativeWeakMap();
const rootStates = new NativeWeakMap();
const handleStates = new NativeWeakMap();
const ObjectPrototype = Object.prototype;
const DRIVER_METHODS = Object.freeze([
  'closeHandle', 'createCache', 'createRoot', 'exportArchive', 'inspectHandle',
  'inspectTreeAtomically', 'makeImmutable', 'openRoot', 'removeRoot',
  'rollbackExport', 'writeMemberAtomically',
]);
const IDENTITY_KEYS = Object.freeze([
  'caseCollision', 'component', 'device', 'inode', 'linkCount',
  'normalizedComponent', 'reparsePoint', 'root', 'symbolicLink', 'type',
]);

function freeze(value) { return applyIntrinsic(freezeIntrinsic, Object, [value]); }
function weakGet(map, key) { return applyIntrinsic(weakMapGetIntrinsic, map, [key]); }
function weakSet(map, key, value) { applyIntrinsic(weakMapSetIntrinsic, map, [key, value]); }

function closedRecord(fields) {
  const value = applyIntrinsic(objectCreateIntrinsic, Object, [null]);
  const keys = applyIntrinsic(reflectOwnKeysIntrinsic, Reflect, [fields]);
  for (let index = 0; index < keys.length; index += 1) value[keys[index]] = fields[keys[index]];
  return freeze(value);
}

function result(status, value = null, code = null) {
  return closedRecord({
    status,
    value,
    diagnostics: code === null ? freeze([]) : freeze([closedRecord({
      code,
      retryable: false,
      safeMessage: code === 'ARTIFACT_CLEANUP_INCOMPLETE'
        ? 'Trusted artifact cleanup could not be completed.'
        : code === 'ARTIFACT_PATH_UNSAFE'
          ? 'Trusted artifact storage rejected the requested operation.'
          : 'Trusted artifact construction could not be completed.',
    })]),
  });
}

const unsafe = () => result('BLOCKED', null, 'ARTIFACT_PATH_UNSAFE');
const failed = () => result('FAIL', null, 'ARTIFACT_BUILD_FAILED');
const cleanupIncomplete = () => result('BLOCKED', null, 'ARTIFACT_CLEANUP_INCOMPLETE');

function exactData(value, keys, requireFrozen = false) {
  try {
    if (
      value === null || typeof value !== 'object' || isProxyIntrinsic(value)
      || (requireFrozen && !applyIntrinsic(objectIsFrozenIntrinsic, Object, [value]))
    ) return null;
    const prototype = applyIntrinsic(objectGetPrototypeOfIntrinsic, Object, [value]);
    if (prototype !== ObjectPrototype && prototype !== null) return null;
    const ownKeys = applyIntrinsic(reflectOwnKeysIntrinsic, Reflect, [value]);
    if (ownKeys.length !== keys.length) return null;
    const copy = applyIntrinsic(objectCreateIntrinsic, Object, [null]);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = applyIntrinsic(
        objectGetOwnPropertyDescriptorIntrinsic, Object, [value, key],
      );
      if (
        descriptor === undefined
        || !applyIntrinsic(objectHasOwnIntrinsic, undefined, [descriptor, 'value'])
      ) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function scalarIdentity(value) {
  return (typeof value === 'string' && value.length > 0)
    || (applyIntrinsic(numberIsSafeIntegerIntrinsic, Number, [value]) && value >= 0);
}

function snapshotIdentity(value) {
  const identity = exactData(value, IDENTITY_KEYS, true);
  if (identity === null) return null;
  const normalized = typeof identity.component === 'string'
    ? applyIntrinsic(stringToLowerCaseIntrinsic, identity.component, [])
    : null;
  if (
    identity.caseCollision !== false || identity.reparsePoint !== false
    || identity.symbolicLink !== false || identity.linkCount !== 1
    || identity.type !== 'directory' || !scalarIdentity(identity.device)
    || !scalarIdentity(identity.inode)
    || (identity.root !== 'source' && identity.root !== 'output')
    || identity.component !== identity.root || identity.normalizedComponent !== normalized
    || identity.normalizedComponent !== identity.component
  ) return null;
  return closedRecord(identity);
}

function sameIdentity(left, right) {
  for (let index = 0; index < IDENTITY_KEYS.length; index += 1) {
    const key = IDENTITY_KEYS[index];
    if (left[key] !== right[key]) return false;
  }
  return true;
}

function captureConfiguration(config) {
  const input = exactData(config, ['driver', 'platform']);
  if (input === null || input.platform !== 'linux') return null;
  const methods = exactData(input.driver, DRIVER_METHODS, true);
  if (methods === null) return null;
  for (let index = 0; index < DRIVER_METHODS.length; index += 1) {
    const method = methods[DRIVER_METHODS[index]];
    if (typeof method !== 'function' || isProxyIntrinsic(method)) return null;
  }
  return { methods, receiver: input.driver };
}

function opaqueToken() { return freeze(applyIntrinsic(objectCreateIntrinsic, Object, [null])); }

export function createPosixSourceArtifactKernelHost(config) {
  const driver = captureConfiguration(config);
  if (driver === null) {
    throw new TypeError('Authenticated POSIX kernel host configuration is invalid.');
  }
  const owner = opaqueToken();

  async function inspectNative(native, expected) {
    try {
      const observed = snapshotIdentity(await applyIntrinsic(
        driver.methods.inspectHandle, driver.receiver, [native],
      ));
      return observed !== null && sameIdentity(observed, expected);
    } catch {
      return false;
    }
  }

  async function inspectToken(token, states) {
    const state = weakGet(states, token);
    if (state === undefined || state.owner !== owner || state.closed) return null;
    return await inspectNative(state.native, state.identity) ? state : null;
  }

  async function createRoot(kind) {
    if (kind !== 'source' && kind !== 'output') return unsafe();
    try {
      const raw = exactData(await applyIntrinsic(
        driver.methods.createRoot, driver.receiver, [kind],
      ), ['identity', 'native'], true);
      const identity = raw === null ? null : snapshotIdentity(raw.identity);
      if (
        identity === null || identity.root !== kind
        || !await inspectNative(raw.native, identity)
      ) return unsafe();
      const token = opaqueToken();
      weakSet(rootStates, token, {
        closed: false, identity, native: raw.native, owner, terminalPromise: null,
      });
      return result('PASS', token);
    } catch {
      return failed();
    }
  }

  async function openRoot(rootToken) {
    const root = await inspectToken(rootToken, rootStates);
    if (root === null) return unsafe();
    try {
      const raw = exactData(await applyIntrinsic(
        driver.methods.openRoot, driver.receiver, [root.native],
      ), ['identity', 'native'], true);
      const identity = raw === null ? null : snapshotIdentity(raw.identity);
      if (identity === null || !sameIdentity(identity, root.identity)) return unsafe();
      const handleValid = await inspectNative(raw.native, identity);
      const rootValid = await inspectNative(root.native, root.identity);
      if (!handleValid || !rootValid) {
        if (raw.native !== root.native) {
          try {
            await applyIntrinsic(driver.methods.closeHandle, driver.receiver, [raw.native]);
          } catch {
            return cleanupIncomplete();
          }
        }
        return unsafe();
      }
      const token = opaqueToken();
      weakSet(handleStates, token, {
        closed: false, identity, native: raw.native, owner, terminalPromise: null,
      });
      return result('PASS', token);
    } catch {
      return failed();
    }
  }

  async function invokeHandle(
    handleToken,
    method,
    args = [],
    operationFailure = failed,
    identityFailure = unsafe,
  ) {
    const handle = await inspectToken(handleToken, handleStates);
    if (handle === null) return unsafe();
    try {
      const value = await applyIntrinsic(
        driver.methods[method], driver.receiver, [handle.native, ...args],
      );
      if (!await inspectNative(handle.native, handle.identity)) return identityFailure();
      return result('PASS', value ?? null);
    } catch {
      return operationFailure();
    }
  }

  async function createCache(handleToken) {
    return invokeHandle(handleToken, 'createCache');
  }

  async function exportArchive(handleToken, archiveBytes, options, signal) {
    if (!(archiveBytes instanceof Uint8Array)) return unsafe();
    return invokeHandle(handleToken, 'exportArchive', [
      applyIntrinsic(uint8ArrayFromIntrinsic, Uint8Array, [archiveBytes]), options, signal,
    ]);
  }

  async function makeImmutable(handleToken, signal) {
    return invokeHandle(handleToken, 'makeImmutable', [signal]);
  }

  async function rollbackExport(handleToken, signal) {
    return invokeHandle(
      handleToken, 'rollbackExport', [signal], cleanupIncomplete, cleanupIncomplete,
    );
  }

  async function writeMemberAtomically(handleToken, relativePath, bytes, options, signal) {
    const optionData = exactData(options, ['exclusiveCreate'], true);
    if (
      typeof relativePath !== 'string' || relativePath.length === 0
      || applyIntrinsic(stringStartsWithIntrinsic, relativePath, ['/'])
      || !(bytes instanceof Uint8Array)
      || optionData === null || optionData.exclusiveCreate !== true
    ) return unsafe();
    for (let index = 0; index < relativePath.length; index += 1) {
      if (relativePath[index] === '\\') return unsafe();
    }
    const parts = applyIntrinsic(stringSplitIntrinsic, relativePath, ['/']);
    for (let index = 0; index < parts.length; index += 1) {
      if (parts[index] === '' || parts[index] === '.' || parts[index] === '..') return unsafe();
    }
    return invokeHandle(handleToken, 'writeMemberAtomically', [
      relativePath,
      applyIntrinsic(uint8ArrayFromIntrinsic, Uint8Array, [bytes]),
      options,
      signal,
    ]);
  }

  async function inspectTreeAtomically(handleToken) {
    return invokeHandle(handleToken, 'inspectTreeAtomically');
  }

  function closeHandle(handleToken) {
    const handle = weakGet(handleStates, handleToken);
    if (handle === undefined || handle.owner !== owner) {
      return (async () => cleanupIncomplete())();
    }
    if (handle.terminalPromise !== null) return handle.terminalPromise;
    handle.terminalPromise = (async () => {
      if (handle.closed || !await inspectNative(handle.native, handle.identity)) {
        return cleanupIncomplete();
      }
      try {
        await applyIntrinsic(driver.methods.closeHandle, driver.receiver, [handle.native]);
        handle.closed = true;
        return result('PASS');
      } catch {
        return cleanupIncomplete();
      }
    })();
    return handle.terminalPromise;
  }

  function removeRoot(rootToken) {
    const root = weakGet(rootStates, rootToken);
    if (root === undefined || root.owner !== owner) {
      return (async () => cleanupIncomplete())();
    }
    if (root.terminalPromise !== null) return root.terminalPromise;
    root.terminalPromise = (async () => {
      if (root.closed || !await inspectNative(root.native, root.identity)) {
        return cleanupIncomplete();
      }
      try {
        await applyIntrinsic(driver.methods.removeRoot, driver.receiver, [root.native]);
        root.closed = true;
        return result('PASS');
      } catch {
        return cleanupIncomplete();
      }
    })();
    return root.terminalPromise;
  }

  const host = closedRecord({
    closeHandle,
    createCache,
    createRoot,
    exportArchive,
    inspectTreeAtomically,
    makeImmutable,
    openRoot,
    removeRoot,
    rollbackExport,
    writeMemberAtomically,
  });
  weakSet(hostStates, host, host);
  return host;
}

export function bindPosixSourceArtifactKernelHost(candidate) {
  return weakGet(hostStates, candidate) ?? null;
}
