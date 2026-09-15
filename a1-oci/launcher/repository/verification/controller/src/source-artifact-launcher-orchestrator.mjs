import { types as utilTypes } from 'node:util';

import {
  isTrustedPromiseBootstrapReady,
  observeTrustedOperation,
} from './trusted-promise-bootstrap.mjs';
import {
  SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION,
  validateSourceArtifactPublication,
} from './source-artifact-launcher-contract.mjs';

const NativeArray = Array;
const ObjectPrototype = Object.prototype;
const ArrayPrototype = Array.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const jsonStringify = JSON.stringify;
const textEncoderEncode = TextEncoder.prototype.encode;
const isProxy = utilTypes.isProxy;

const ARGUMENT_KEYS = objectFreeze(['launcher', 'publishValidatedOutput', 'runCandidate']);
const ARGUMENT_KEYS_WITH_DEFAULT_MODE = objectFreeze(['launcher', 'runCandidate']);
const MESSAGES = objectFreeze({
  ARTIFACT_BUILD_FAILED: 'Trusted artifact construction could not be completed.',
  ARTIFACT_CLEANUP_INCOMPLETE: 'Trusted artifact cleanup could not be completed.',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'Trusted artifact network isolation is unavailable.',
  ARTIFACT_OUTPUT_VALIDATOR_UNAVAILABLE: 'Trusted artifact output validation is unavailable.',
  ARTIFACT_PATH_UNSAFE: 'Trusted artifact storage rejected the requested operation.',
  ARTIFACT_PUBLICATION_FAILED: 'Trusted artifact publication could not be completed.',
  ARTIFACT_SCHEMA_INVALID: 'Trusted artifact session data does not match the closed contract.',
});
const STATUS_BY_CODE = objectFreeze({
  ARTIFACT_BUILD_FAILED: 'FAIL',
  ARTIFACT_CLEANUP_INCOMPLETE: 'BLOCKED',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'BLOCKED',
  ARTIFACT_OUTPUT_VALIDATOR_UNAVAILABLE: 'BLOCKED',
  ARTIFACT_PATH_UNSAFE: 'BLOCKED',
  ARTIFACT_PUBLICATION_FAILED: 'FAIL',
  ARTIFACT_SCHEMA_INVALID: 'BLOCKED',
});
const CANDIDATE_SESSION_DEADLINE_MS = 3_600_000;
const scheduleTimeout = globalThis.setTimeout;
const cancelTimeout = globalThis.clearTimeout;
const NativePromise = Promise;
const publicationEncoder = new TextEncoder();

function jsonString(value) {
  return reflectApply(jsonStringify, undefined, [value]);
}

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortOrdinally(values) {
  return reflectApply(arraySort, values, [ordinalCompare]);
}

function hasOwn(value, key) {
  return reflectApply(objectHasOwn, undefined, [value, key]);
}

function dataDescriptor(value, {
  configurable = true,
  enumerable = true,
  writable = true,
} = {}) {
  const descriptor = objectCreate(null);
  objectDefineProperty(descriptor, 'configurable', {
    configurable: true,
    enumerable: true,
    value: configurable,
    writable: true,
  });
  objectDefineProperty(descriptor, 'enumerable', {
    configurable: true,
    enumerable: true,
    value: enumerable,
    writable: true,
  });
  objectDefineProperty(descriptor, 'value', {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
  objectDefineProperty(descriptor, 'writable', {
    configurable: true,
    enumerable: true,
    value: writable,
    writable: true,
  });
  return descriptor;
}

function defineData(object, key, value, options) {
  objectDefineProperty(object, key, dataDescriptor(value, options));
}

function copyArray(values) {
  const copy = new NativeArray(values.length);
  for (let index = 0; index < values.length; index += 1) {
    defineData(copy, `${index}`, values[index]);
  }
  return copy;
}

function closedRecord(fields) {
  const record = objectCreate(null);
  const keys = reflectOwnKeys(fields);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = objectGetOwnPropertyDescriptor(fields, key);
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) {
      throw new TypeError('Trusted records require own data properties.');
    }
    defineData(record, key, descriptor.value, {
      configurable: false,
      enumerable: true,
      writable: false,
    });
  }
  return objectFreeze(record);
}

function result(status, value, code = null) {
  return closedRecord({
    status,
    value,
    diagnostics: code === null
      ? objectFreeze([])
      : objectFreeze([closedRecord({
        code,
        safeMessage: MESSAGES[code],
        retryable: false,
      })]),
  });
}

const PASS_NULL = result('PASS', null);
const INVALID = result('BLOCKED', null, 'ARTIFACT_SCHEMA_INVALID');
const BUILD_FAILED = result('FAIL', null, 'ARTIFACT_BUILD_FAILED');
const PUBLICATION_FAILED = result('FAIL', null, 'ARTIFACT_PUBLICATION_FAILED');
const CLEANUP_INCOMPLETE = result('BLOCKED', null, 'ARTIFACT_CLEANUP_INCOMPLETE');

function exactDataObject(value, expectedKeys) {
  try {
    if (
      isProxy(value)
      || value === null
      || typeof value !== 'object'
      || arrayIsArray(value)
      || objectGetPrototypeOf(value) !== ObjectPrototype
    ) return null;
    const ownKeys = reflectOwnKeys(value);
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
    }
    const actual = sortOrdinally(copyArray(ownKeys));
    const expected = sortOrdinally(copyArray(expectedKeys));
    if (actual.length !== expected.length) return null;
    for (let index = 0; index < actual.length; index += 1) {
      if (actual[index] !== expected[index]) return null;
    }
    const copy = objectCreate(null);
    for (let index = 0; index < expectedKeys.length; index += 1) {
      const key = expectedKeys[index];
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || !hasOwn(descriptor, 'enumerable')
        || descriptor.enumerable !== true
        || !hasOwn(descriptor, 'value')
      ) return null;
      defineData(copy, key, descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function exactTrustedDataObject(value, expectedKeys) {
  try {
    if (
      isProxy(value)
      || value === null
      || typeof value !== 'object'
      || arrayIsArray(value)
      || objectGetPrototypeOf(value) !== null
      || !objectIsFrozen(value)
    ) return null;
    const ownKeys = reflectOwnKeys(value);
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
    }
    const actual = sortOrdinally(copyArray(ownKeys));
    const expected = sortOrdinally(copyArray(expectedKeys));
    if (actual.length !== expected.length) return null;
    for (let index = 0; index < actual.length; index += 1) {
      if (actual[index] !== expected[index]) return null;
    }
    const copy = objectCreate(null);
    for (let index = 0; index < expectedKeys.length; index += 1) {
      const key = expectedKeys[index];
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || !hasOwn(descriptor, 'enumerable')
        || descriptor.enumerable !== true
        || !hasOwn(descriptor, 'value')
      ) return null;
      defineData(copy, key, descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function exactArray(value, expectedLength) {
  try {
    if (
      isProxy(value)
      || !arrayIsArray(value)
      || objectGetPrototypeOf(value) !== ArrayPrototype
      || !numberIsSafeInteger(expectedLength)
      || expectedLength < 0
    ) return null;

    const ownKeys = reflectOwnKeys(value);
    if (ownKeys.length !== expectedLength + 1) return null;
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
    }

    const lengthDescriptor = objectGetOwnPropertyDescriptor(value, 'length');
    if (
      lengthDescriptor === undefined
      || !hasOwn(lengthDescriptor, 'enumerable')
      || lengthDescriptor.enumerable !== false
      || !hasOwn(lengthDescriptor, 'value')
      || lengthDescriptor.value !== expectedLength
    ) return null;

    const copy = new NativeArray(expectedLength);
    for (let index = 0; index < expectedLength; index += 1) {
      const key = `${index}`;
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || !hasOwn(descriptor, 'enumerable')
        || descriptor.enumerable !== true
        || !hasOwn(descriptor, 'value')
      ) return null;
      defineData(copy, key, descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function exactTrustedArray(value, expectedLength) {
  const copy = exactArray(value, expectedLength);
  try {
    return copy !== null && objectIsFrozen(value) ? copy : null;
  } catch {
    return null;
  }
}

function exactCapability(value, methodNames) {
  const copy = exactDataObject(value, methodNames);
  if (copy === null) return null;
  try {
    if (!objectIsFrozen(value)) return null;
    for (let index = 0; index < methodNames.length; index += 1) {
      const name = methodNames[index];
      if (typeof copy[name] !== 'function' || isProxy(copy[name])) return null;
    }
    const capability = objectCreate(null);
    defineData(capability, 'receiver', value);
    for (let index = 0; index < methodNames.length; index += 1) {
      const name = methodNames[index];
      defineData(capability, name, copy[name]);
    }
    return objectFreeze(capability);
  } catch {
    return null;
  }
}

function exactTrustedCapability(value, methodNames) {
  const copy = exactTrustedDataObject(value, methodNames);
  if (copy === null) return null;
  try {
    for (let index = 0; index < methodNames.length; index += 1) {
      const name = methodNames[index];
      if (typeof copy[name] !== 'function' || isProxy(copy[name])) return null;
    }
    const capability = objectCreate(null);
    defineData(capability, 'receiver', value);
    for (let index = 0; index < methodNames.length; index += 1) {
      const name = methodNames[index];
      defineData(capability, name, copy[name]);
    }
    return objectFreeze(capability);
  } catch {
    return null;
  }
}

function normalizeClosedResult(candidate, fallback) {
  const envelope = exactTrustedDataObject(candidate, ['diagnostics', 'status', 'value']);
  if (envelope === null) return fallback;
  if (envelope.status === 'PASS' && exactTrustedArray(envelope.diagnostics, 0) !== null) {
    if (envelope.value === null) return PASS_NULL;
    const descriptor = exactTrustedDataObject(envelope.value, [
      'artifactManifestDigest', 'artifactName', 'artifactPath',
    ]);
    if (
      descriptor === null
      || typeof descriptor.artifactManifestDigest !== 'string'
      || typeof descriptor.artifactName !== 'string'
      || typeof descriptor.artifactPath !== 'string'
    ) return fallback;
    const bytes = reflectApply(textEncoderEncode, publicationEncoder, [
      `{"artifactManifestDigest":${jsonString(descriptor.artifactManifestDigest)},"artifactName":${jsonString(descriptor.artifactName)},"artifactPath":${jsonString(descriptor.artifactPath)}}`,
    ]);
    const validated = validateSourceArtifactPublication(bytes);
    if (validated.status !== 'PASS') return fallback;
    return result('PASS', closedRecord({
      artifactManifestDigest: descriptor.artifactManifestDigest,
      artifactName: descriptor.artifactName,
      artifactPath: descriptor.artifactPath,
    }));
  }
  if (envelope.value !== null) return fallback;
  const diagnostics = exactTrustedArray(envelope.diagnostics, 1);
  if (diagnostics === null) return fallback;
  const diagnostic = exactTrustedDataObject(diagnostics[0], ['code', 'retryable', 'safeMessage']);
  const code = diagnostic?.code;
  if (
    diagnostic === null
    || typeof code !== 'string'
    || !hasOwn(STATUS_BY_CODE, code)
    || !hasOwn(MESSAGES, code)
    || STATUS_BY_CODE[code] !== envelope.status
    || diagnostic.retryable !== false
    || typeof diagnostic.safeMessage !== 'string'
  ) return fallback;
  return result(envelope.status, null, code);
}

function authenticateOpenedSession(candidate) {
  const envelope = exactTrustedDataObject(candidate, ['diagnostics', 'status', 'value']);
  if (
    envelope === null
    || envelope.status !== 'PASS'
    || exactTrustedArray(envelope.diagnostics, 0) === null
  ) return closedRecord({ error: normalizeClosedResult(candidate, INVALID) });
  const ports = exactTrustedDataObject(envelope.value, ['candidatePort', 'parentPort']);
  if (ports === null) return closedRecord({ error: INVALID });
  try {
    if (
      ports.candidatePort === null
      || typeof ports.candidatePort !== 'object'
      || isProxy(ports.candidatePort)
      || !objectIsFrozen(ports.candidatePort)
    ) return closedRecord({ error: INVALID });
  } catch {
    return closedRecord({ error: INVALID });
  }
  const parentPort = exactTrustedCapability(ports.parentPort, [
    'close', 'publishValidatedOutput', 'validateOutput',
  ]);
  if (parentPort === null || ports.candidatePort === ports.parentPort) {
    return closedRecord({ error: INVALID });
  }
  return closedRecord({
    candidatePort: ports.candidatePort,
    parentPort,
  });
}

function hardenPromiseForAwait(promise) {
  objectDefineProperty(promise, 'constructor', dataDescriptor(NativePromise, {
    configurable: false,
    enumerable: false,
    writable: false,
  }));
  return promise;
}

function prepareAwaitable(value) {
  return observeTrustedOperation(value);
}

function observedValue(observation) {
  return observation?.fulfilled === true ? observation.value : null;
}

function invokeClosed(operation, fallback) {
  const deferred = createDeferred();
  let candidate;
  try {
    candidate = prepareAwaitable(operation());
  } catch {
    deferred.settle(fallback);
    return deferred.promise;
  }
  void (async () => {
    let outcome = fallback;
    try {
      const observed = await candidate;
      outcome = normalizeClosedResult(observedValue(observed), fallback);
    } catch {
      outcome = fallback;
    }
    deferred.settle(outcome);
  })();
  return deferred.promise;
}

function createDeferred() {
  let settle;
  const promise = new NativePromise((resolve) => {
    settle = resolve;
  });
  hardenPromiseForAwait(promise);
  return closedRecord({ promise, settle });
}

function invokeCandidateWithDeadline(runCandidate, candidatePort) {
  const deferred = createDeferred();
  let complete = false;
  let timer;
  function finish(candidate) {
    if (complete) return;
    complete = true;
    try {
      if (timer !== undefined) reflectApply(cancelTimeout, globalThis, [timer]);
    } finally {
      deferred.settle(candidate);
    }
  }
  try {
    timer = reflectApply(scheduleTimeout, globalThis, [
      () => finish(BUILD_FAILED),
      CANDIDATE_SESSION_DEADLINE_MS,
    ]);
  } catch {
    finish(BUILD_FAILED);
    return deferred.promise;
  }

  let operation;
  try {
    operation = prepareAwaitable(reflectApply(runCandidate, undefined, [candidatePort]));
  } catch {
    finish(BUILD_FAILED);
    return deferred.promise;
  }
  void (async () => {
    let candidate;
    try {
      const observed = await operation;
      candidate = observedValue(observed);
    } catch {
      finish(BUILD_FAILED);
      return;
    }
    if (complete) return;
    try {
      finish(normalizeClosedResult(candidate, BUILD_FAILED));
    } catch {
      finish(BUILD_FAILED);
    }
  })();
  return deferred.promise;
}

async function runReadyTrustedSourceArtifactSession(args) {
  let expectedKeys;
  try {
    expectedKeys = args !== null
      && typeof args === 'object'
      && !isProxy(args)
      && hasOwn(args, 'publishValidatedOutput')
      ? ARGUMENT_KEYS
      : ARGUMENT_KEYS_WITH_DEFAULT_MODE;
  } catch {
    throw new TypeError('Trusted source artifact session configuration is invalid.');
  }
  const input = exactDataObject(args, expectedKeys);
  if (input === null) throw new TypeError('Trusted source artifact session configuration is invalid.');
  const launcher = exactCapability(input.launcher, ['openSession']);
  if (
    launcher === null
    || typeof input.runCandidate !== 'function'
    || isProxy(input.runCandidate)
    || (hasOwn(input, 'publishValidatedOutput')
      && typeof input.publishValidatedOutput !== 'boolean')
  ) throw new TypeError('Trusted source artifact session configuration is invalid.');
  const publicationMode = hasOwn(input, 'publishValidatedOutput')
    ? input.publishValidatedOutput
    : false;
  const runCandidate = input.runCandidate;

  let openedCandidate;
  try {
    const observed = await prepareAwaitable(
      reflectApply(launcher.openSession, launcher.receiver, []),
    );
    openedCandidate = observedValue(observed);
  } catch {
    return BUILD_FAILED;
  }
  const opened = authenticateOpenedSession(openedCandidate);
  if (opened.error) return opened.error;

  let primaryResult = BUILD_FAILED;
  try {
    const candidateResult = await invokeCandidateWithDeadline(
      runCandidate,
      opened.candidatePort,
    );
    if (candidateResult.status !== 'PASS') {
      primaryResult = candidateResult;
    } else {
      const request = objectFreeze({
        protocolVersion: SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION,
      });
      const validationResult = await invokeClosed(
        () => reflectApply(opened.parentPort.validateOutput, opened.parentPort.receiver, [request]),
        INVALID,
      );
      if (validationResult.status !== 'PASS') {
        primaryResult = validationResult;
      } else if (publicationMode) {
        primaryResult = await invokeClosed(
          () => reflectApply(
            opened.parentPort.publishValidatedOutput,
            opened.parentPort.receiver,
            [request],
          ),
          PUBLICATION_FAILED,
        );
      } else {
        primaryResult = validationResult;
      }
    }
  } finally {
    const cleanupResult = await invokeClosed(
      () => reflectApply(opened.parentPort.close, opened.parentPort.receiver, []),
      CLEANUP_INCOMPLETE,
    );
    if (cleanupResult.status !== 'PASS') primaryResult = CLEANUP_INCOMPLETE;
  }
  return primaryResult;
}

export function runTrustedSourceArtifactSession(args) {
  return isTrustedPromiseBootstrapReady()
    ? runReadyTrustedSourceArtifactSession(args)
    : INVALID;
}
