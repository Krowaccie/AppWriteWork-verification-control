import { types as utilTypes } from 'node:util';

const applyIntrinsic = Reflect.apply;
const freezeIntrinsic = Object.freeze;
const objectCreateIntrinsic = Object.create;
const objectDefinePropertyIntrinsic = Object.defineProperty;
const objectGetOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOfIntrinsic = Object.getPrototypeOf;
const objectHasOwnIntrinsic = Object.hasOwn;
const objectIsFrozenIntrinsic = Object.isFrozen;
const reflectOwnKeysIntrinsic = Reflect.ownKeys;
const regexpExecIntrinsic = RegExp.prototype.exec;
const weakMapGetIntrinsic = WeakMap.prototype.get;
const weakMapHasIntrinsic = WeakMap.prototype.has;
const weakMapSetIntrinsic = WeakMap.prototype.set;
const isProxyIntrinsic = utilTypes.isProxy;
const NativeWeakMap = WeakMap;
const ObjectPrototype = Object.prototype;
const SOURCE_REVISION = /^[0-9a-f]{40}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const issuerStates = new NativeWeakMap();
const claimerStates = new NativeWeakMap();

function freeze(value) { return applyIntrinsic(freezeIntrinsic, Object, [value]); }
function weakGet(map, key) { return applyIntrinsic(weakMapGetIntrinsic, map, [key]); }
function weakHas(map, key) { return applyIntrinsic(weakMapHasIntrinsic, map, [key]); }
function weakSet(map, key, value) { applyIntrinsic(weakMapSetIntrinsic, map, [key, value]); }

function closedRecord(fields) {
  const value = applyIntrinsic(objectCreateIntrinsic, Object, [null]);
  const keys = applyIntrinsic(reflectOwnKeysIntrinsic, Reflect, [fields]);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const field = applyIntrinsic(objectGetOwnPropertyDescriptorIntrinsic, Object, [fields, key]);
    applyIntrinsic(objectDefinePropertyIntrinsic, Object, [value, key, {
      configurable: false,
      enumerable: true,
      value: field.value,
      writable: false,
    }]);
  }
  return freeze(value);
}

function exactFrozenRecord(value, keys) {
  try {
    if (
      value === null || typeof value !== 'object' || isProxyIntrinsic(value)
      || !applyIntrinsic(objectIsFrozenIntrinsic, Object, [value])
      || applyIntrinsic(reflectOwnKeysIntrinsic, Reflect, [value]).length !== keys.length
    ) return null;
    const prototype = applyIntrinsic(objectGetPrototypeOfIntrinsic, Object, [value]);
    if (prototype !== ObjectPrototype && prototype !== null) return null;
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

function validLease(value) {
  const lease = exactFrozenRecord(value, ['close', 'exportSnapshot', 'identity']);
  if (
    lease === null || typeof lease.close !== 'function' || isProxyIntrinsic(lease.close)
    || typeof lease.exportSnapshot !== 'function' || isProxyIntrinsic(lease.exportSnapshot)
  ) return false;
  const identity = exactFrozenRecord(lease.identity, [
    'sourceRevision', 'sourceTreeDigest', 'verifierManifestDigest',
  ]);
  return identity !== null
    && applyIntrinsic(regexpExecIntrinsic, SOURCE_REVISION, [identity.sourceRevision]) !== null
    && applyIntrinsic(regexpExecIntrinsic, SHA256, [identity.sourceTreeDigest]) !== null
    && applyIntrinsic(regexpExecIntrinsic, SHA256, [identity.verifierManifestDigest]) !== null;
}

export function createSourceArtifactSourceLeaseAuthority() {
  const state = {
    claimerCaptured: false,
    issuerCaptured: false,
    leases: new NativeWeakMap(),
  };
  const sourceControl = freeze(applyIntrinsic(objectCreateIntrinsic, Object, [null]));
  const workspace = freeze(applyIntrinsic(objectCreateIntrinsic, Object, [null]));
  weakSet(issuerStates, sourceControl, state);
  weakSet(claimerStates, workspace, state);
  return closedRecord({ sourceControl, workspace });
}

export function captureSourceArtifactSourceLeaseIssuer(candidate) {
  const state = weakGet(issuerStates, candidate);
  if (state === undefined || state.issuerCaptured) return null;
  state.issuerCaptured = true;
  return closedRecord({
    issueSourceLease(sourceLease) {
      if (!validLease(sourceLease) || weakHas(state.leases, sourceLease)) return null;
      weakSet(state.leases, sourceLease, { claimed: false });
      return sourceLease;
    },
  });
}

export function captureSourceArtifactSourceLeaseClaimer(candidate) {
  const state = weakGet(claimerStates, candidate);
  if (state === undefined || state.claimerCaptured) return null;
  state.claimerCaptured = true;
  return closedRecord({
    claimSourceLease(sourceLease) {
      const leaseState = weakGet(state.leases, sourceLease);
      if (leaseState === undefined || leaseState.claimed) return null;
      leaseState.claimed = true;
      return sourceLease;
    },
  });
}
