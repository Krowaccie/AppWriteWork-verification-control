import { createHash } from 'node:crypto';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

import {
  isTrustedPromiseBootstrapReady,
  observeTrustedOperation,
} from './trusted-promise-bootstrap.mjs';
import {
  SOURCE_ARTIFACT_COMMAND_IDS,
  SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION,
  validateSourceArtifactLauncherRequest,
} from './source-artifact-launcher-contract.mjs';
import { validateSourceArtifactOutputSnapshot } from './source-artifact-output-validator.mjs';
import {
  isPublicationLeaseLauncherAuthority,
  issuePublicationLease,
  registerPublicationLauncher,
  verifyPublicationLeaseCompletion,
} from './source-artifact-publication-lease-authority.mjs';

const NativeArray = Array;
const NativeBuffer = Buffer;
const NativeUint8Array = Uint8Array;
const ObjectPrototype = Object.prototype;
const ArrayPrototype = NativeArray.prototype;
const BufferPrototype = NativeBuffer.prototype;
const Uint8ArrayPrototype = NativeUint8Array.prototype;
const PathPosix = path.posix;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const bufferByteLength = Buffer.byteLength;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectSetPrototypeOf = Object.setPrototypeOf;
const cryptoCreateHash = createHash;
const HashPrototype = objectGetPrototypeOf(reflectApply(
  cryptoCreateHash,
  undefined,
  ['sha256'],
));
const hashUpdate = HashPrototype.update;
const hashDigest = HashPrototype.digest;
const regexpExec = RegExp.prototype.exec;
const setHas = Set.prototype.has;
const stringIncludes = String.prototype.includes;
const stringSlice = String.prototype.slice;
const stringStartsWith = String.prototype.startsWith;
const textDecoderDecode = TextDecoder.prototype.decode;
const textEncoderEncode = TextEncoder.prototype.encode;
const uint8ArraySet = Uint8Array.prototype.set;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const pathPosixDirname = PathPosix.dirname;
const pathPosixIsAbsolute = PathPosix.isAbsolute;
const pathPosixJoin = PathPosix.join;
const pathPosixNormalize = PathPosix.normalize;
const isProxy = utilTypes.isProxy;
const isSharedArrayBuffer = utilTypes.isSharedArrayBuffer;
const isUint8Array = utilTypes.isUint8Array;

const FULL_REVISION = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const EXPECTED_PROVIDER_CONTRACT_DIGEST =
  'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8';
const RUN_ID = /^[1-9][0-9]*$/u;
const CONSTRUCTOR_KEYS = objectFreeze([
  'filesystem',
  'limits',
  'parentConfiguration',
  'sandboxTransport',
  'sourceSnapshotHost',
  'validatedOutputSink',
  'workspaceHost',
]);
const CONSTRUCTOR_KEYS_WITH_PUBLICATION_AUTHORITY = objectFreeze([
  'filesystem',
  'limits',
  'parentConfiguration',
  'publicationLeaseAuthority',
  'sandboxTransport',
  'sourceSnapshotHost',
  'validatedOutputSink',
  'workspaceHost',
]);
const CONFIGURATION_KEYS = objectFreeze([
  'artifactOutputRoot',
  'launcherTempRoot',
  'nodeExecutable',
  'npmExecutable',
  'repository',
  'sourceCheckoutRoot',
  'sourceRef',
  'sourceRevision',
  'sourceTreeDigest',
  'trustedInventoryBytes',
  'workflow',
  'workflowRunAttempt',
  'workflowRunId',
]);
const LIMIT_KEYS = objectFreeze([
  'artifactArchiveMemberBytes',
  'artifactHandoffBytes',
  'artifactManifestBytes',
  'canonicalAbsolutePathBytes',
  'outputFileMembers',
  'outputTreeBytes',
  'sourceGitArchiveBytes',
  'stderrBytes',
  'stdoutBytes',
  'trustedInventoryBytes',
  'verifierManifestBytes',
]);
const QUIESCENCE_GRACE_MS = 5_000;
const scheduleTimeout = globalThis.setTimeout;
const cancelTimeout = globalThis.clearTimeout;
const NativeAbortController = AbortController;
const abortControllerAbort = AbortController.prototype.abort;
const getAbortSignal = objectGetOwnPropertyDescriptor(AbortController.prototype, 'signal').get;
const NativePromise = Promise;
const LIMIT_VALUES = objectFreeze({
  trustedInventoryBytes: 1024 * 1024,
  verifierManifestBytes: 1024 * 1024,
  artifactManifestBytes: 1024 * 1024,
  artifactHandoffBytes: 1024 * 1024,
  artifactArchiveMemberBytes: 128 * 1024 * 1024,
  outputTreeBytes: 256 * 1024 * 1024,
  outputFileMembers: 39,
  canonicalAbsolutePathBytes: 4096,
  sourceGitArchiveBytes: 256 * 1024 * 1024,
  stdoutBytes: 16 * 1024 * 1024,
  stderrBytes: 16 * 1024 * 1024,
});
const PRODUCT_IDS = objectFreeze([
  'api-keys-py',
  'api-router-py',
  'billing-cron-py',
  'billing-py',
  'billing-webhook-py',
  'branch-py',
  'cache-cleanup-cron-py',
  'catalog-py',
  'chat-py',
  'cleanup-cron-py',
  'connections-py',
  'finance-sync-sec-py',
  'finance-sync-wb-py',
  'flowise-runner-py',
  'mcp-cleanup-cron-py',
  'mcp-gateway-py',
  'project-public-links-py',
  'project-public-read-py',
  'project-snapshots-py',
  'runs-cancel-py',
  'runs-clear-py',
  'runs-create-py',
  'runs-detail-py',
  'runs-list-py',
  'runs-status-py',
  'runs-steps-py',
  'sec-cache-builder-py',
  'sharing-py',
  'smtp-diagnostic-py',
  'telemetry-py',
  'usage-cron-py',
  'usage-py',
  'validate-py',
  'verification-email-py',
  'worker-cron-py',
]);
const MEMBER_IDS = objectFreeze([
  'site:web',
  ...PRODUCT_IDS.map((logicalId) => `function:${logicalId}`),
  'function:verification-runner-py',
  'metadata:artifact-manifest',
  'metadata:artifact-handoff',
]);
const INVENTORY_KEYS = objectFreeze([
  'control',
  'credentialVariables',
  'deploymentModes',
  'environment',
  'environmentClass',
  'identityVariables',
  'productFunctions',
  'providerContractDigest',
  'productionDenylist',
  'schemaVersion',
  'sourceBranch',
  'testOnlyFunctions',
]);
const FUNCTION_KEYS = objectFreeze([
  'entrypoint',
  'functionId',
  'logicalId',
  'runtime',
  'sourcePath',
]);
const MESSAGES = objectFreeze({
  ARTIFACT_BUILD_FAILED: 'Trusted artifact construction could not be completed.',
  ARTIFACT_CLEANUP_INCOMPLETE: 'Trusted artifact cleanup could not be completed.',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'Trusted artifact network isolation is unavailable.',
  ARTIFACT_OUTPUT_VALIDATOR_UNAVAILABLE: 'Trusted artifact output validation is unavailable.',
  ARTIFACT_PATH_UNSAFE: 'Trusted artifact storage rejected the requested operation.',
  ARTIFACT_PUBLICATION_FAILED: 'Trusted artifact publication could not be completed.',
  ARTIFACT_SCHEMA_INVALID: 'Trusted artifact launcher data does not match the closed contract.',
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
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const typedArrayPrototype = objectGetPrototypeOf(Uint8ArrayPrototype);
const getByteLength = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const getByteOffset = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const getBuffer = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const getArrayBufferByteLength = objectGetOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const getResizable = objectGetOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;
const launcherStates = new WeakMap();
const portStates = new WeakMap();

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortOrdinally(values) {
  return reflectApply(arraySort, values, [ordinalCompare]);
}

function hasOwn(value, key) {
  return reflectApply(objectHasOwn, undefined, [value, key]);
}

function dataDescriptor(value, writable, configurable, enumerable = false) {
  const descriptor = objectCreate(null);
  descriptor.configurable = configurable;
  descriptor.enumerable = enumerable;
  descriptor.value = value;
  descriptor.writable = writable;
  return objectFreeze(descriptor);
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
    objectDefineProperty(
      record,
      key,
      dataDescriptor(descriptor.value, false, false, true),
    );
  }
  return objectFreeze(record);
}

function copyArray(values) {
  const copy = new NativeArray(values.length);
  for (let index = 0; index < values.length; index += 1) {
    objectDefineProperty(
      copy,
      index,
      dataDescriptor(values[index], true, true, true),
    );
  }
  return copy;
}

function transportArgv(values) {
  const args = copyArray(values);
  reflectApply(objectSetPrototypeOf, Object, [args, null]);
  return objectFreeze(args);
}

function regexpMatches(pattern, value) {
  return reflectApply(regexpExec, pattern, [value]) !== null;
}

function encodeCanonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    const encoded = reflectApply(jsonStringify, undefined, [value]);
    if (encoded === undefined) throw new TypeError('Value is outside the canonical JSON domain.');
    return encoded;
  }
  if (arrayIsArray(value)) {
    let encoded = '[';
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
      if (descriptor === undefined || !hasOwn(descriptor, 'value')) {
        throw new TypeError('Canonical arrays must be dense data arrays.');
      }
      if (index > 0) encoded += ',';
      encoded += encodeCanonicalJson(descriptor.value);
    }
    return `${encoded}]`;
  }
  if (objectGetPrototypeOf(value) !== ObjectPrototype) {
    throw new TypeError('Canonical JSON accepts only plain objects.');
  }
  const keys = reflectOwnKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== 'string') {
      throw new TypeError('Canonical JSON accepts only string keys.');
    }
  }
  const sorted = sortOrdinally(copyArray(keys));
  let encoded = '{';
  for (let index = 0; index < sorted.length; index += 1) {
    const key = sorted[index];
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) {
      throw new TypeError('Canonical JSON accepts only data properties.');
    }
    if (index > 0) encoded += ',';
    encoded += `${reflectApply(jsonStringify, undefined, [key])}:${encodeCanonicalJson(descriptor.value)}`;
  }
  return `${encoded}}`;
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

function pass(value) {
  return result('PASS', value === null ? null : closedRecord(value));
}

function blocked(code) {
  return result('BLOCKED', null, code);
}

function failed(code) {
  return result('FAIL', null, code);
}

const INVALID = blocked('ARTIFACT_SCHEMA_INVALID');
const BOOTSTRAP_UNAVAILABLE_LAUNCHER = objectFreeze({
  openSession() {
    return INVALID;
  },
});
const OUTPUT_VALIDATOR_UNAVAILABLE = blocked('ARTIFACT_OUTPUT_VALIDATOR_UNAVAILABLE');
const PASS_NULL = pass(null);

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
      if (!descriptor?.enumerable || !hasOwn(descriptor, 'value')) return null;
      objectDefineProperty(
        copy,
        key,
        dataDescriptor(descriptor.value, true, true, true),
      );
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
      if (!descriptor?.enumerable || !hasOwn(descriptor, 'value')) return null;
      objectDefineProperty(
        copy,
        key,
        dataDescriptor(descriptor.value, true, true, true),
      );
    }
    return copy;
  } catch {
    return null;
  }
}

function exactCapability(value, methodNames) {
  const copy = exactDataObject(value, methodNames);
  if (copy === null || !objectIsFrozen(value)) return null;
  for (let index = 0; index < methodNames.length; index += 1) {
    const method = copy[methodNames[index]];
    if (typeof method !== 'function' || isProxy(method)) return null;
  }
  return objectFreeze({ receiver: value, ...copy });
}

function exactTrustedCapability(value, methodNames) {
  const copy = exactTrustedDataObject(value, methodNames);
  if (copy === null) return null;
  for (let index = 0; index < methodNames.length; index += 1) {
    const method = copy[methodNames[index]];
    if (typeof method !== 'function' || isProxy(method)) return null;
  }
  return objectFreeze({ receiver: value, ...copy });
}

function exactLimits(value) {
  const copy = exactDataObject(value, LIMIT_KEYS);
  if (copy === null || !objectIsFrozen(value)) return null;
  for (let index = 0; index < LIMIT_KEYS.length; index += 1) {
    const key = LIMIT_KEYS[index];
    if (copy[key] !== LIMIT_VALUES[key]) return null;
  }
  return objectFreeze(copy);
}

function canonicalAbsolutePosixPath(value, maximumBytes) {
  return (
    typeof value === 'string'
    && value.length > 1
    && reflectApply(bufferByteLength, NativeBuffer, [value, 'utf8']) <= maximumBytes
    && !reflectApply(stringIncludes, value, ['\\'])
    && !regexpMatches(/[\u0000-\u001f\u007f]/u, value)
    && reflectApply(pathPosixIsAbsolute, PathPosix, [value])
    && reflectApply(pathPosixNormalize, PathPosix, [value]) === value
  );
}

function isDescendant(root, candidate) {
  return reflectApply(stringStartsWith, candidate, [`${root}/`]);
}

function disjointRoots(roots) {
  for (let index = 0; index < roots.length; index += 1) {
    for (let otherIndex = 0; otherIndex < roots.length; otherIndex += 1) {
      if (index === otherIndex) continue;
      const root = roots[index];
      const other = roots[otherIndex];
      if (
        root === other
        || isDescendant(root, other)
        || isDescendant(other, root)
      ) return false;
    }
  }
  return true;
}

function snapshotBytes(value, maximumBytes, allowEmpty = false) {
  try {
    if (isProxy(value) || !isUint8Array(value)) return null;
    const prototype = objectGetPrototypeOf(value);
    if (prototype !== Uint8ArrayPrototype && prototype !== BufferPrototype) return null;
    const byteLength = reflectApply(getByteLength, value, []);
    const byteOffset = reflectApply(getByteOffset, value, []);
    if (
      !numberIsSafeInteger(byteLength)
      || byteLength < (allowEmpty ? 0 : 1)
      || byteLength > maximumBytes
      || !numberIsSafeInteger(byteOffset)
      || byteOffset < 0
    ) return null;
    const backing = reflectApply(getBuffer, value, []);
    if (
      isSharedArrayBuffer(backing)
      || (getResizable && reflectApply(getResizable, backing, []) === true)
      || byteOffset + byteLength > reflectApply(getArrayBufferByteLength, backing, [])
    ) return null;
    const copy = new NativeUint8Array(byteLength);
    reflectApply(uint8ArraySet, copy, [value]);
    if (
      reflectApply(getByteLength, value, []) !== byteLength
      || reflectApply(getByteOffset, value, []) !== byteOffset
    ) return null;
    return copy;
  } catch {
    return null;
  }
}

function copyBytes(value, byteLength) {
  const copy = new NativeUint8Array(byteLength);
  reflectApply(uint8ArraySet, copy, [value]);
  return copy;
}

function sha256TransportBytes(value) {
  if (
    isProxy(value)
    || !isUint8Array(value)
    || objectGetPrototypeOf(value) !== Uint8ArrayPrototype
  ) throw new TypeError('Transport bytes are invalid.');
  const byteLength = reflectApply(getByteLength, value, []);
  const byteOffset = reflectApply(getByteOffset, value, []);
  const backing = reflectApply(getBuffer, value, []);
  if (
    !numberIsSafeInteger(byteLength)
    || byteLength < 1
    || !numberIsSafeInteger(byteOffset)
    || byteOffset < 0
    || isSharedArrayBuffer(backing)
    || (getResizable && reflectApply(getResizable, backing, []) === true)
    || byteOffset + byteLength > reflectApply(getArrayBufferByteLength, backing, [])
  ) throw new TypeError('Transport bytes are invalid.');
  const hash = reflectApply(cryptoCreateHash, undefined, ['sha256']);
  reflectApply(hashUpdate, hash, [value]);
  const digest = reflectApply(hashDigest, hash, ['hex']);
  if (
    reflectApply(getByteLength, value, []) !== byteLength
    || reflectApply(getByteOffset, value, []) !== byteOffset
    || reflectApply(getBuffer, value, []) !== backing
  ) throw new TypeError('Transport bytes changed during hashing.');
  return `sha256:${digest}`;
}

function sameBytes(left, right) {
  const leftLength = reflectApply(getByteLength, left, []);
  const rightLength = reflectApply(getByteLength, right, []);
  if (leftLength !== rightLength) return false;
  for (let index = 0; index < leftLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function exactArray(value, expectedLength = null) {
  try {
    if (
      isProxy(value)
      || !arrayIsArray(value)
      || objectGetPrototypeOf(value) !== ArrayPrototype
    ) return null;
    const lengthDescriptor = objectGetOwnPropertyDescriptor(value, 'length');
    if (!hasOwn(lengthDescriptor ?? objectCreate(null), 'value')) return null;
    const length = lengthDescriptor.value;
    if (!numberIsSafeInteger(length) || length < 0 || (expectedLength !== null && length !== expectedLength)) {
      return null;
    }
    const ownKeys = reflectOwnKeys(value);
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
    }
    const expectedKeys = new NativeArray(length + 1);
    objectDefineProperty(
      expectedKeys,
      0,
      dataDescriptor('length', true, true, true),
    );
    for (let index = 0; index < length; index += 1) {
      objectDefineProperty(
        expectedKeys,
        index + 1,
        dataDescriptor(`${index}`, true, true, true),
      );
    }
    sortOrdinally(expectedKeys);
    const actualKeys = sortOrdinally(copyArray(ownKeys));
    if (actualKeys.length !== expectedKeys.length) return null;
    for (let index = 0; index < actualKeys.length; index += 1) {
      if (actualKeys[index] !== expectedKeys[index]) return null;
    }
    const copy = new NativeArray(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor?.enumerable || !hasOwn(descriptor, 'value')) return null;
      objectDefineProperty(
        copy,
        index,
        dataDescriptor(descriptor.value, true, true, true),
      );
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

function stringArray(value, expected = null) {
  const copy = exactArray(value, expected?.length ?? null);
  if (copy === null) return null;
  for (let index = 0; index < copy.length; index += 1) {
    if (typeof copy[index] !== 'string' || copy[index].length === 0) return null;
    if (expected && copy[index] !== expected[index]) return null;
  }
  return copy;
}

function validFunctionEntry(candidate, expectedLogicalId) {
  const entry = exactDataObject(candidate, FUNCTION_KEYS);
  return entry !== null
    && entry.logicalId === expectedLogicalId
    && entry.sourcePath === `src/functions/${expectedLogicalId}`
    && entry.entrypoint === 'main.py'
    && entry.runtime === 'python-3.12'
    && typeof entry.functionId === 'string'
    && entry.functionId.length > 0
    && !regexpMatches(/[\u0000-\u001f\u007f\\/]/u, entry.functionId);
}

function validateClosedInventory(parsed) {
  const inventory = exactDataObject(parsed, INVENTORY_KEYS);
  if (
    inventory === null
    || inventory.schemaVersion !== 'test-cloud-inventory.v1'
    || inventory.environmentClass !== 'appwrite-cloud-test'
    || inventory.providerContractDigest !== EXPECTED_PROVIDER_CONTRACT_DIGEST
    || inventory.sourceBranch !== 'main'
  ) return false;

  const environmentKeys = ['endpoint', 'projectId', 'publicOrigin', 'siteId'];
  const environment = exactDataObject(inventory.environment, environmentKeys);
  const modes = exactDataObject(inventory.deploymentModes, ['function', 'site']);
  const denylist = exactDataObject(inventory.productionDenylist, [
    'credentialVariableNames', 'endpoints', 'originHostSuffixes', 'origins', 'projectIds', 'siteIds',
  ]);
  const control = exactDataObject(inventory.control, [
    'auditTableId', 'databaseId', 'intentTableId', 'leaseRowId', 'leaseTableId',
    'primaryExecutionRetentionMaxSeconds', 'runnerFunctionId',
  ]);
  if (environment === null) return false;
  for (let index = 0; index < environmentKeys.length; index += 1) {
    const value = environment[environmentKeys[index]];
    if (typeof value !== 'string' || value.length === 0) return false;
  }
  if (
    modes === null
    || modes.site !== 'artifact-upload'
    || modes.function !== 'artifact-upload'
    || denylist === null
    || stringArray(denylist.endpoints) === null
    || stringArray(denylist.projectIds) === null
    || stringArray(denylist.siteIds) === null
    || stringArray(denylist.origins) === null
    || stringArray(denylist.originHostSuffixes) === null
    || stringArray(denylist.credentialVariableNames) === null
    || control === null
    || control.runnerFunctionId !== 'verification-runner-py'
    || !numberIsSafeInteger(control.primaryExecutionRetentionMaxSeconds)
    || control.primaryExecutionRetentionMaxSeconds < 1
  ) return false;
  const controlKeys = ['auditTableId', 'databaseId', 'intentTableId', 'leaseRowId', 'leaseTableId'];
  for (let index = 0; index < controlKeys.length; index += 1) {
    const value = control[controlKeys[index]];
    if (typeof value !== 'string' || value.length === 0) return false;
  }

  const credentials = exactDataObject(inventory.credentialVariables, ['fixture', 'operator', 'recovery']);
  if (credentials === null) return false;
  const credentialNames = ['operator', 'fixture', 'recovery'];
  const credentialClasses = ['test-operator', 'test-fixture', 'test-recovery'];
  for (let index = 0; index < credentialNames.length; index += 1) {
    const credential = exactDataObject(
      credentials[credentialNames[index]],
      ['credentialClass', 'scopes', 'variableName'],
    );
    if (
      credential === null
      || credential.credentialClass !== credentialClasses[index]
      || typeof credential.variableName !== 'string'
      || !regexpMatches(/^[A-Z][A-Z0-9_]*$/u, credential.variableName)
      || stringArray(credential.scopes) === null
    ) return false;
  }

  const identities = exactDataObject(inventory.identityVariables, ['editor', 'owner', 'viewer']);
  if (identities === null) return false;
  const roles = ['owner', 'editor', 'viewer'];
  for (let index = 0; index < roles.length; index += 1) {
    const identity = exactDataObject(identities[roles[index]], ['email', 'password']);
    if (
      identity === null
      || typeof identity.email !== 'string'
      || !regexpMatches(/^[A-Z][A-Z0-9_]*$/u, identity.email)
      || typeof identity.password !== 'string'
      || !regexpMatches(/^[A-Z][A-Z0-9_]*$/u, identity.password)
    ) return false;
  }

  const products = exactArray(inventory.productFunctions, PRODUCT_IDS.length);
  const testOnly = exactArray(inventory.testOnlyFunctions, 1);
  if (products === null || testOnly === null) return false;
  const functionIds = new NativeArray(products.length + testOnly.length);
  for (let index = 0; index < products.length; index += 1) {
    if (!validFunctionEntry(products[index], PRODUCT_IDS[index])) return false;
    objectDefineProperty(
      functionIds,
      index,
      dataDescriptor(products[index].functionId, true, true, true),
    );
  }
  if (!validFunctionEntry(testOnly[0], 'verification-runner-py')) return false;
  objectDefineProperty(
    functionIds,
    products.length,
    dataDescriptor(testOnly[0].functionId, true, true, true),
  );
  for (let index = 0; index < functionIds.length; index += 1) {
    for (let otherIndex = index + 1; otherIndex < functionIds.length; otherIndex += 1) {
      if (functionIds[index] === functionIds[otherIndex]) return false;
    }
  }
  return true;
}

function parseInventoryBytes(value, maximumBytes) {
  const copy = snapshotBytes(value, maximumBytes);
  if (copy === null) return null;
  try {
    const parsed = reflectApply(
      jsonParse,
      undefined,
      [reflectApply(textDecoderDecode, decoder, [copy])],
    );
    const canonicalBytes = reflectApply(
      textEncoderEncode,
      encoder,
      [encodeCanonicalJson(parsed)],
    );
    if (!sameBytes(copy, canonicalBytes) || !validateClosedInventory(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function snapshotConfiguration(value, limits) {
  const input = exactDataObject(value, CONFIGURATION_KEYS);
  if (input === null) return null;
  const pathKeys = [
    'artifactOutputRoot', 'launcherTempRoot', 'nodeExecutable', 'npmExecutable', 'sourceCheckoutRoot',
  ];
  for (let index = 0; index < pathKeys.length; index += 1) {
    if (!canonicalAbsolutePosixPath(input[pathKeys[index]], limits.canonicalAbsolutePathBytes)) return null;
  }
  if (!disjointRoots([input.sourceCheckoutRoot, input.artifactOutputRoot, input.launcherTempRoot])) return null;
  const inventory = parseInventoryBytes(input.trustedInventoryBytes, limits.trustedInventoryBytes);
  if (
    input.repository !== 'Krowaccie/AppWriteWork'
    || input.workflow !== 'Verify Main'
    || input.sourceRef !== 'refs/heads/main'
    || typeof input.sourceRevision !== 'string'
    || !regexpMatches(FULL_REVISION, input.sourceRevision)
    || typeof input.sourceTreeDigest !== 'string'
    || !regexpMatches(DIGEST, input.sourceTreeDigest)
    || typeof input.workflowRunId !== 'string'
    || !regexpMatches(RUN_ID, input.workflowRunId)
    || !numberIsSafeInteger(input.workflowRunAttempt)
    || input.workflowRunAttempt < 1
    || inventory === null
  ) return null;
  const functionUnits = new NativeArray(PRODUCT_IDS.length + 1);
  for (let index = 0; index < PRODUCT_IDS.length; index += 1) {
    objectDefineProperty(functionUnits, index, dataDescriptor(closedRecord({
      logicalId: inventory.productFunctions[index].logicalId,
      sourcePath: inventory.productFunctions[index].sourcePath,
      testOnly: false,
    }), true, true, true));
  }
  objectDefineProperty(functionUnits, PRODUCT_IDS.length, dataDescriptor(closedRecord({
    logicalId: inventory.testOnlyFunctions[0].logicalId,
    sourcePath: inventory.testOnlyFunctions[0].sourcePath,
    testOnly: true,
  }), true, true, true));
  objectFreeze(functionUnits);
  return objectFreeze({
    sourceCheckoutRoot: input.sourceCheckoutRoot,
    artifactOutputRoot: input.artifactOutputRoot,
    launcherTempRoot: input.launcherTempRoot,
    nodeExecutable: input.nodeExecutable,
    npmExecutable: input.npmExecutable,
    repository: input.repository,
    workflow: input.workflow,
    sourceRef: input.sourceRef,
    sourceRevision: input.sourceRevision,
    sourceTreeDigest: input.sourceTreeDigest,
    workflowRunId: input.workflowRunId,
    workflowRunAttempt: input.workflowRunAttempt,
    functionUnits,
  });
}

function readPassEnvelope(candidate) {
  const envelope = exactTrustedDataObject(candidate, ['diagnostics', 'status', 'value']);
  if (
    envelope === null
    || envelope.status !== 'PASS'
    || exactTrustedArray(envelope.diagnostics, 0) === null
  ) return null;
  return envelope;
}

function validNullPass(candidate) {
  return readPassEnvelope(candidate)?.value === null;
}

function normalizeFailure(candidate, allowedCodes, fallbackStatus, fallbackCode) {
  const envelope = exactTrustedDataObject(candidate, ['diagnostics', 'status', 'value']);
  const diagnostics = envelope === null ? null : exactTrustedArray(envelope.diagnostics, 1);
  if (
    envelope !== null
    && envelope.value === null
    && (envelope.status === 'BLOCKED' || envelope.status === 'FAIL')
    && diagnostics !== null
  ) {
    const diagnostic = exactTrustedDataObject(diagnostics[0], ['code', 'retryable', 'safeMessage']);
    if (
      diagnostic !== null
      && reflectApply(setHas, allowedCodes, [diagnostic.code])
      && STATUS_BY_CODE[diagnostic.code] === envelope.status
      && diagnostic.retryable === false
      && typeof diagnostic.safeMessage === 'string'
    ) {
      return envelope.status === 'FAIL' ? failed(diagnostic.code) : blocked(diagnostic.code);
    }
  }
  return fallbackStatus === 'FAIL' ? failed(fallbackCode) : blocked(fallbackCode);
}

function memberPath(memberId) {
  if (memberId === 'site:web') return 'site/site.tar.gz';
  if (memberId === 'metadata:artifact-manifest') return 'artifact-manifest.v1.json';
  if (memberId === 'metadata:artifact-handoff') return 'artifact-handoff.v1.json';
  return `functions/${reflectApply(stringSlice, memberId, ['function:'.length])}.tar.gz`;
}

function memberMaximumBytes(memberId, limits) {
  if (memberId === 'metadata:artifact-manifest') return limits.artifactManifestBytes;
  if (memberId === 'metadata:artifact-handoff') return limits.artifactHandoffBytes;
  return limits.artifactArchiveMemberBytes;
}

function poison(state, failure) {
  if (state.firstFailure === null) state.firstFailure = failure;
  state.phase = 'POISONED';
  return state.firstFailure;
}

const SOURCE_FAILURE_CODES = new Set([
  'ARTIFACT_BUILD_FAILED',
  'ARTIFACT_CLEANUP_INCOMPLETE',
  'ARTIFACT_NETWORK_POLICY_UNAVAILABLE',
  'ARTIFACT_PATH_UNSAFE',
  'ARTIFACT_SCHEMA_INVALID',
]);
const WORKSPACE_FAILURE_CODES = new Set([
  'ARTIFACT_CLEANUP_INCOMPLETE',
  'ARTIFACT_PATH_UNSAFE',
  'ARTIFACT_SCHEMA_INVALID',
]);
const WRITE_FAILURE_CODES = new Set([
  'ARTIFACT_BUILD_FAILED',
  'ARTIFACT_CLEANUP_INCOMPLETE',
  'ARTIFACT_PATH_UNSAFE',
  'ARTIFACT_SCHEMA_INVALID',
]);

function authenticateSourceLease(candidate, configuration) {
  const lease = exactDataObject(candidate, ['close', 'exportSnapshot', 'identity']);
  if (
    lease === null
    || !objectIsFrozen(candidate)
    || typeof lease.close !== 'function'
    || isProxy(lease.close)
    || typeof lease.exportSnapshot !== 'function'
    || isProxy(lease.exportSnapshot)
  ) return null;
  const identity = exactDataObject(lease.identity, [
    'sourceRevision', 'sourceTreeDigest', 'verifierManifestDigest',
  ]);
  if (
    identity === null
    || !objectIsFrozen(lease.identity)
    || identity.sourceRevision !== configuration.sourceRevision
    || identity.sourceTreeDigest !== configuration.sourceTreeDigest
    || typeof identity.verifierManifestDigest !== 'string'
    || !regexpMatches(DIGEST, identity.verifierManifestDigest)
  ) return null;
  return objectFreeze({
    lease: candidate,
    identity: objectFreeze(identity),
    close: lease.close,
  });
}

function validOpaqueHandle(value) {
  try {
    return value !== null
      && (typeof value === 'object' || typeof value === 'function')
      && !isProxy(value)
      && objectIsFrozen(value);
  } catch {
    return false;
  }
}

function authenticateWorkspaceLease(candidate, configuration) {
  const lease = exactDataObject(candidate, [
    'close', 'outputRootHandle', 'sourceRootHandle', 'workspace',
  ]);
  if (
    lease === null
    || !objectIsFrozen(candidate)
    || typeof lease.close !== 'function'
    || isProxy(lease.close)
    || !validOpaqueHandle(lease.sourceRootHandle)
    || !validOpaqueHandle(lease.outputRootHandle)
    || lease.sourceRootHandle === lease.outputRootHandle
  ) return null;
  const workspaceKeys = ['childTemp', 'exportRoot', 'outputRoot', 'siteOutput'];
  const workspace = exactDataObject(lease.workspace, workspaceKeys);
  if (workspace === null) return null;
  for (let index = 0; index < workspaceKeys.length; index += 1) {
    if (
      !canonicalAbsolutePosixPath(
        workspace[workspaceKeys[index]],
        configuration.limits.canonicalAbsolutePathBytes,
      )
    ) return null;
  }
  const expectedOutputRoot = reflectApply(pathPosixJoin, PathPosix, [
    configuration.artifactOutputRoot,
    '.verification',
    'artifacts',
    configuration.sourceRevision,
  ]);
  if (
    workspace.outputRoot !== expectedOutputRoot
    || !isDescendant(configuration.launcherTempRoot, workspace.exportRoot)
    || !isDescendant(configuration.launcherTempRoot, workspace.siteOutput)
    || !isDescendant(configuration.launcherTempRoot, workspace.childTemp)
    || !disjointRoots([
      workspace.exportRoot,
      workspace.siteOutput,
      workspace.childTemp,
      workspace.outputRoot,
    ])
  ) return null;
  return objectFreeze({
    lease: candidate,
    close: lease.close,
    sourceRootHandle: lease.sourceRootHandle,
    outputRootHandle: lease.outputRootHandle,
    workspace: closedRecord({
      childTemp: workspace.childTemp,
      exportRoot: workspace.exportRoot,
      outputRoot: workspace.outputRoot,
      siteOutput: workspace.siteOutput,
    }),
  });
}

async function closeAuthenticatedSource(source) {
  try {
    const observed = await prepareAwaitable(
      reflectApply(source.close, source.lease, []),
    );
    return validNullPass(observedValue(observed));
  } catch {
    return false;
  }
}

function getPortState(receiver, role) {
  const context = reflectApply(weakMapGet, portStates, [receiver]);
  return context?.role === role ? context.state : null;
}

function closedOrPoisoned(state) {
  if (state.closed) return INVALID;
  if (state.firstFailure !== null) return state.firstFailure;
  return null;
}

function validateCommandObject(request) {
  const input = exactDataObject(request, ['commandId', 'protocolVersion']);
  if (input === null) return null;
  try {
    const text = `{"commandId":${reflectApply(jsonStringify, undefined, [input.commandId])},"protocolVersion":${reflectApply(jsonStringify, undefined, [input.protocolVersion])}}`;
    const validated = validateSourceArtifactLauncherRequest(
      reflectApply(textEncoderEncode, encoder, [text]),
    );
    return validated.status === 'PASS' ? validated.value : null;
  } catch {
    return null;
  }
}

function hardenPromiseForAwait(promise) {
  objectDefineProperty(
    promise,
    'constructor',
    dataDescriptor(NativePromise, false, false),
  );
  return promise;
}

function prepareAwaitable(value) {
  return observeTrustedOperation(value);
}

function observedValue(observation) {
  return observation?.fulfilled === true ? observation.value : null;
}

async function runTrackedOperation(state, operation) {
  state.busy = true;
  const deferred = createDeferred();
  const pending = deferred.promise;
  state.inFlight = pending;
  try {
    try {
      return await prepareAwaitable(operation());
    } catch {
      return null;
    }
  } finally {
    deferred.settle(null);
    if (state.inFlight === pending) state.inFlight = null;
    state.busy = false;
  }
}

function createDeferred() {
  let settle;
  const promise = new NativePromise((resolve) => {
    settle = resolve;
  });
  hardenPromiseForAwait(promise);
  return closedRecord({ promise, settle });
}

function resolvedClosedResult(value) {
  const deferred = createDeferred();
  deferred.settle(value);
  return deferred.promise;
}

function waitForQuiescence(pending) {
  const deferred = createDeferred();
  let complete = false;
  let timer;
  function finish(quiescent) {
    if (complete) return;
    complete = true;
    try {
      if (timer !== undefined) reflectApply(cancelTimeout, globalThis, [timer]);
    } finally {
      deferred.settle(quiescent);
    }
  }
  try {
    timer = reflectApply(scheduleTimeout, globalThis, [
      () => finish(false),
      QUIESCENCE_GRACE_MS,
    ]);
  } catch {
    finish(false);
    return deferred.promise;
  }
  void (async () => {
    try {
      await pending;
    } catch {
      // Settlement, not success, defines adapter quiescence.
    }
    finish(true);
  })();
  return deferred.promise;
}

const VALIDATION_FAILURE_CODES = new Set([
  'ARTIFACT_PATH_UNSAFE',
  'ARTIFACT_SCHEMA_INVALID',
]);

const COMMAND_FAILURE_CODES = new Set([
  'ARTIFACT_BUILD_FAILED',
  'ARTIFACT_NETWORK_POLICY_UNAVAILABLE',
]);

function commandEnvironment(state, install) {
  const workspace = state.workspace.workspace;
  const childTemp = workspace.childTemp;
  const configHome = reflectApply(pathPosixJoin, PathPosix, [childTemp, 'config-home']);
  const nodeDirectory = reflectApply(
    pathPosixDirname,
    PathPosix,
    [state.configuration.nodeExecutable],
  );
  const npmDirectory = reflectApply(
    pathPosixDirname,
    PathPosix,
    [state.configuration.npmExecutable],
  );
  const environment = objectCreate(null);
  const baseEnvironment = {
    CI: '1',
    TZ: 'UTC',
    LC_ALL: 'C.UTF-8',
    SOURCE_DATE_EPOCH: '0',
    TMP: childTemp,
    TEMP: childTemp,
    TMPDIR: childTemp,
    HOME: configHome,
    USERPROFILE: configHome,
    XDG_CONFIG_HOME: configHome,
    PATH: nodeDirectory === npmDirectory
      ? nodeDirectory
      : `${nodeDirectory}:${npmDirectory}`,
  };
  const baseKeys = reflectOwnKeys(baseEnvironment);
  for (let index = 0; index < baseKeys.length; index += 1) {
    const key = baseKeys[index];
    const descriptor = objectGetOwnPropertyDescriptor(baseEnvironment, key);
    objectDefineProperty(
      environment,
      key,
      dataDescriptor(descriptor.value, false, false, true),
    );
  }
  if (install) {
    const installEnvironment = {
      NPM_CONFIG_CACHE: reflectApply(pathPosixJoin, PathPosix, [childTemp, 'npm-cache']),
      NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/',
      NPM_CONFIG_AUDIT: 'false',
      NPM_CONFIG_FUND: 'false',
      NPM_CONFIG_IGNORE_SCRIPTS: 'true',
      NPM_CONFIG_FETCH_RETRIES: '0',
      NPM_CONFIG_FETCH_RETRY_MINTIMEOUT: '0',
      NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT: '0',
    };
    const keys = reflectOwnKeys(installEnvironment);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = objectGetOwnPropertyDescriptor(installEnvironment, key);
      objectDefineProperty(
        environment,
        key,
        dataDescriptor(descriptor.value, false, false, true),
      );
    }
  }
  return objectFreeze(environment);
}

function createCommandSpec(state, commandId) {
  const workspace = state.workspace.workspace;
  const webRoot = reflectApply(pathPosixJoin, PathPosix, [workspace.exportRoot, 'src', 'web']);
  let executable;
  let args;
  let cwd;
  let network;
  let install = false;
  switch (commandId) {
    case 'root-npm-ci':
      executable = state.configuration.npmExecutable;
      args = ['ci', '--ignore-scripts', '--no-audit', '--no-fund'];
      cwd = workspace.exportRoot;
      network = 'registry-only';
      install = true;
      break;
    case 'web-npm-ci':
      executable = state.configuration.npmExecutable;
      args = ['ci', '--ignore-scripts', '--no-audit', '--no-fund'];
      cwd = webRoot;
      network = 'registry-only';
      install = true;
      break;
    case 'bundle-catalog':
      executable = state.configuration.nodeExecutable;
      args = ['scripts/bundle-catalog.mjs'];
      cwd = workspace.exportRoot;
      network = 'deny';
      break;
    case 'typecheck':
      executable = state.configuration.nodeExecutable;
      args = [
        '/opt/appwritework/verification-a1/host/typecheck-driver.mjs',
        webRoot,
      ];
      cwd = webRoot;
      network = 'deny';
      break;
    case 'vite-build':
      executable = state.configuration.nodeExecutable;
      args = [
        reflectApply(pathPosixJoin, PathPosix, [
          webRoot, 'node_modules', 'vite', 'bin', 'vite.js',
        ]),
        'build', '--configLoader', 'runner', '--outDir', workspace.siteOutput, '--emptyOutDir',
      ];
      cwd = webRoot;
      network = 'deny';
      break;
    default:
      return null;
  }
  return closedRecord({
    commandId,
    executable,
    args: transportArgv(args),
    cwd,
    env: commandEnvironment(state, install),
    network,
    retry: false,
    shell: false,
    stderrLimitBytes: state.limits.stderrBytes,
    stdoutLimitBytes: state.limits.stdoutBytes,
    timeoutMs: 600_000,
  });
}

async function runCommand(request) {
  const state = getPortState(this, 'candidate');
  if (state === null) return INVALID;
  const terminal = closedOrPoisoned(state);
  if (terminal !== null) return terminal;
  if (state.busy || state.phase !== 'COMMANDS') return poison(state, INVALID);
  const validated = validateCommandObject(request);
  const expectedCommandId = SOURCE_ARTIFACT_COMMAND_IDS[state.commandIndex];
  if (validated === null || validated.commandId !== expectedCommandId) return poison(state, INVALID);
  const spec = createCommandSpec(state, validated.commandId);
  if (spec === null) return poison(state, INVALID);

  const observed = await runTrackedOperation(state, () => reflectApply(
    state.sandboxTransport.run,
    state.sandboxTransport.receiver,
    [spec, state.abortSignal],
  ));
  const candidate = observedValue(observed);
  const terminalAfterRun = closedOrPoisoned(state);
  if (terminalAfterRun !== null) return terminalAfterRun;
  if (!validNullPass(candidate)) {
    return poison(state, normalizeFailure(
      candidate,
      COMMAND_FAILURE_CODES,
      'BLOCKED',
      'ARTIFACT_NETWORK_POLICY_UNAVAILABLE',
    ));
  }
  state.commandIndex += 1;
  if (state.commandIndex === SOURCE_ARTIFACT_COMMAND_IDS.length) state.phase = 'WRITES';
  return pass({ commandId: validated.commandId });
}

function snapshotMemberRequest(request, state) {
  const input = exactDataObject(request, ['bytes', 'memberId', 'protocolVersion']);
  if (
    input === null
    || input.protocolVersion !== SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION
    || typeof input.memberId !== 'string'
    || input.memberId !== MEMBER_IDS[state.memberIndex]
  ) return null;
  const bytes = snapshotBytes(input.bytes, memberMaximumBytes(input.memberId, state.limits));
  if (bytes === null) return null;
  const sizeBytes = reflectApply(getByteLength, bytes, []);
  if (state.totalBytes + sizeBytes > state.limits.outputTreeBytes) return null;
  return objectFreeze({ memberId: input.memberId, bytes, sizeBytes });
}

async function writeOutputMember(request) {
  const state = getPortState(this, 'candidate');
  if (state === null) return INVALID;
  const terminal = closedOrPoisoned(state);
  if (terminal !== null) return terminal;
  if (state.busy || state.phase !== 'WRITES') return poison(state, INVALID);
  const member = snapshotMemberRequest(request, state);
  if (member === null) return poison(state, INVALID);
  const relativePath = memberPath(member.memberId);
  const options = closedRecord({ exclusiveCreate: true });
  let transportBytes;
  let digest;
  try {
    transportBytes = copyBytes(member.bytes, member.sizeBytes);
    digest = sha256TransportBytes(transportBytes);
  } catch {
    return poison(state, failed('ARTIFACT_BUILD_FAILED'));
  }

  const observed = await runTrackedOperation(state, () => reflectApply(
    state.filesystem.writeMemberAtomically,
    state.filesystem.receiver,
    [
      state.outputRootHandle,
      relativePath,
      transportBytes,
      options,
      state.abortSignal,
    ],
  ));
  const candidate = observedValue(observed);
  const terminalAfterWrite = closedOrPoisoned(state);
  if (terminalAfterWrite !== null) return terminalAfterWrite;
  if (!validNullPass(candidate)) {
    return poison(state, normalizeFailure(
      candidate,
      WRITE_FAILURE_CODES,
      'BLOCKED',
      'ARTIFACT_PATH_UNSAFE',
    ));
  }
  state.memberIndex += 1;
  state.totalBytes += member.sizeBytes;
  if (state.memberIndex === MEMBER_IDS.length) state.phase = 'READY_TO_VALIDATE';
  return pass({
    memberId: member.memberId,
    sizeBytes: member.sizeBytes,
    transportDigest: digest,
  });
}

function validationExpected(state) {
  return closedRecord({
    artifactName: `verification-artifacts-${state.configuration.sourceRevision}`,
    functionUnits: state.configuration.functionUnits,
    limits: closedRecord({
      archiveMemberBytes: state.limits.artifactArchiveMemberBytes,
      handoffBytes: state.limits.artifactHandoffBytes,
      manifestBytes: state.limits.artifactManifestBytes,
      outputFileMembers: state.limits.outputFileMembers,
      outputTreeBytes: state.limits.outputTreeBytes,
    }),
    repository: state.configuration.repository,
    sourceRef: state.configuration.sourceRef,
    sourceRevision: state.configuration.sourceRevision,
    sourceTreeDigest: state.configuration.sourceTreeDigest,
    verifierManifestDigest: state.source.identity.verifierManifestDigest,
    workflow: state.configuration.workflow,
    workflowRunAttempt: state.configuration.workflowRunAttempt,
    workflowRunId: state.configuration.workflowRunId,
  });
}

function authenticateInspectedOutput(candidate) {
  const envelope = readPassEnvelope(candidate);
  if (envelope === null) return null;
  const value = exactTrustedDataObject(envelope.value, ['retainedOutput', 'snapshot']);
  if (value === null) return null;
  const retainedOutput = exactTrustedCapability(
    value.retainedOutput,
    ['close', 'readMember', 'revalidate'],
  );
  if (retainedOutput === null) return null;
  return objectFreeze({ retainedOutput, snapshot: value.snapshot });
}

async function revalidateRetainedOutput(state) {
  const invoke = () => reflectApply(
    state.retainedOutput.revalidate,
    state.retainedOutput.receiver,
    [],
  );
  const observed = state.phase === 'PUBLISHING' && state.busy
    ? await prepareAwaitable(invoke())
    : await runTrackedOperation(state, invoke);
  return validNullPass(observedValue(observed));
}

function validateParentRequest(request) {
  const input = exactDataObject(request, ['protocolVersion']);
  return input !== null && input.protocolVersion === SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION;
}

async function validateOutput(request) {
  const state = getPortState(this, 'parent');
  if (state === null) return INVALID;
  const terminal = closedOrPoisoned(state);
  if (terminal !== null) return terminal;
  if (
    state.busy
    || state.phase !== 'READY_TO_VALIDATE'
    || !validateParentRequest(request)
  ) return poison(state, INVALID);
  state.phase = 'VALIDATING';
  const observed = await runTrackedOperation(state, () => reflectApply(
    state.filesystem.inspectTreeAtomically,
    state.filesystem.receiver,
    [state.outputRootHandle],
  ));
  const inspectedCandidate = observedValue(observed);
  const terminalAfterInspect = closedOrPoisoned(state);
  if (terminalAfterInspect !== null) return terminalAfterInspect;
  const inspected = authenticateInspectedOutput(inspectedCandidate);
  if (inspected === null) {
    return poison(state, normalizeFailure(
      inspectedCandidate,
      VALIDATION_FAILURE_CODES,
      'BLOCKED',
      'ARTIFACT_PATH_UNSAFE',
    ));
  }
  state.retainedOutput = inspected.retainedOutput;
  const validation = validateSourceArtifactOutputSnapshot({
    snapshot: inspected.snapshot,
    expected: validationExpected(state),
  });
  if (validation.status !== 'PASS') {
    return poison(state, validation.diagnostics[0]?.code === 'ARTIFACT_PATH_UNSAFE'
      ? blocked('ARTIFACT_PATH_UNSAFE')
      : INVALID);
  }
  state.validatedData = validation.value;
  if (!(await revalidateRetainedOutput(state))) {
    return poison(state, blocked('ARTIFACT_PATH_UNSAFE'));
  }
  const descriptor = closedRecord({
    artifactManifestDigest: validation.value.artifactManifest.artifactManifestDigest,
    artifactName: validation.value.handoff.artifactName,
    artifactPath: state.workspace.workspace.outputRoot,
  });
  state.descriptor = descriptor;
  state.phase = 'VALIDATED';
  return pass(descriptor);
}

function createValidatedStream(state) {
  const stream = {
    closed: false,
    closeCount: 0,
    closeResult: null,
    memberIndex: 0,
    offset: 0,
    hash: reflectApply(cryptoCreateHash, undefined, ['sha256']),
    poisoned: false,
    reading: false,
  };
  const members = state.validatedData.memberDigests;
  function publicationFailure() {
    stream.poisoned = true;
    return failed('ARTIFACT_PUBLICATION_FAILED');
  }
  async function readNext(request) {
    if (
      stream.closed
      || stream.poisoned
      || stream.reading
      || stream.memberIndex >= members.length
      || !validateParentRequest(request)
    ) return publicationFailure();
    stream.reading = true;
    try {
      if (!(await revalidateRetainedOutput(state)) || stream.poisoned || stream.closed) {
        return publicationFailure();
      }
      const member = members[stream.memberIndex];
      const remaining = member.sizeBytes - stream.offset;
      const length = remaining < 64 * 1024 ? remaining : 64 * 1024;
      if (length <= 0) return publicationFailure();
      const candidate = await prepareAwaitable(reflectApply(
        state.retainedOutput.readMember,
        state.retainedOutput.receiver,
        [closedRecord({
          length,
          offset: stream.offset,
          relativePath: member.relativePath,
        })],
      ));
      const envelope = readPassEnvelope(observedValue(candidate));
      const value = envelope === null ? null : exactTrustedDataObject(envelope.value, ['bytes']);
      const bytes = value === null ? null : snapshotBytes(value.bytes, length);
      if (bytes === null || reflectApply(getByteLength, bytes, []) !== length) {
        return publicationFailure();
      }
      if (!(await revalidateRetainedOutput(state)) || stream.poisoned || stream.closed) {
        return publicationFailure();
      }
      reflectApply(hashUpdate, stream.hash, [bytes]);
      const offset = stream.offset;
      stream.offset += length;
      const endOfMember = stream.offset === member.sizeBytes;
      const endOfArtifact = endOfMember && stream.memberIndex === members.length - 1;
      if (endOfMember) {
        const digest = `sha256:${reflectApply(hashDigest, stream.hash, ['hex'])}`;
        if (digest !== member.transportDigest) return publicationFailure();
        stream.memberIndex += 1;
        stream.offset = 0;
        if (!endOfArtifact) stream.hash = reflectApply(cryptoCreateHash, undefined, ['sha256']);
      }
      return pass({
        memberId: member.memberId,
        offset,
        bytes: copyBytes(bytes, length),
        endOfMember,
        endOfArtifact,
      });
    } catch {
      return publicationFailure();
    } finally {
      stream.reading = false;
    }
  }
  function publicClose() {
    stream.closeCount += 1;
    if (stream.closeResult !== null) return stream.closeResult;
    stream.closed = true;
    stream.closeResult = !stream.poisoned && stream.memberIndex === members.length && stream.offset === 0
      ? PASS_NULL
      : publicationFailure();
    return stream.closeResult;
  }
  const capability = closedRecord({ readNext, close: publicClose });
  return objectFreeze({
    capability,
    forceClose() { stream.closed = true; },
    accepted() {
      return !stream.poisoned
        && stream.memberIndex === members.length
        && stream.offset === 0
        && stream.closeCount === 1
        && stream.closeResult === PASS_NULL;
    },
  });
}

async function publishValidatedOutput(request) {
  const state = getPortState(this, 'parent');
  if (state === null) return INVALID;
  const terminal = closedOrPoisoned(state);
  if (terminal !== null) return terminal;
  if (
    state.busy
    || state.phase !== 'VALIDATED'
    || !validateParentRequest(request)
    || state.validatedOutputSink === null
  ) return poison(state, INVALID);
  state.phase = 'PUBLISHING';
  if (!(await revalidateRetainedOutput(state))) {
    return poison(state, failed('ARTIFACT_PUBLICATION_FAILED'));
  }
  if (state.publicationLeaseAuthority === null) {
    const stream = createValidatedStream(state);
    let accepted = false;
    try {
      const observed = await runTrackedOperation(state, () => reflectApply(
        state.validatedOutputSink.streamValidatedArtifact,
        state.validatedOutputSink.receiver,
        [closedRecord({
          protocolVersion: SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION,
          artifactName: state.descriptor.artifactName,
          artifactManifestDigest: state.descriptor.artifactManifestDigest,
          streamCapability: stream.capability,
        })],
      ));
      accepted = validNullPass(observedValue(observed)) && stream.accepted();
    } catch {
      accepted = false;
    } finally {
      stream.forceClose();
    }
    if (!accepted) return poison(state, failed('ARTIFACT_PUBLICATION_FAILED'));
    state.phase = 'PUBLISHED';
    return PASS_NULL;
  }
  const publicationLease = issuePublicationLease(
    state.publicationLeaseAuthority,
    state.launcher,
    state.validatedOutputSink.receiver,
    objectFreeze({
    artifactManifestDigest: state.descriptor.artifactManifestDigest,
    artifactName: state.descriptor.artifactName,
    members: state.validatedData.memberDigests,
    publisher: state.validatedOutputSink.receiver,
    retainedOutput: state.retainedOutput.receiver,
    session: state.sessionIdentity,
    workspaceOutput: state.workspaceOutputIdentity,
    }),
  );
  if (publicationLease === null) return poison(state, failed('ARTIFACT_PUBLICATION_FAILED'));
  let accepted = false;
  try {
    const observed = await runTrackedOperation(state, () => reflectApply(
      state.validatedOutputSink.streamValidatedArtifact,
      state.validatedOutputSink.receiver,
      [publicationLease],
    ));
    accepted = validNullPass(observedValue(observed))
      && verifyPublicationLeaseCompletion(
        state.publicationLeaseAuthority,
        publicationLease,
        state.launcher,
        state.validatedOutputSink.receiver,
      );
  } catch {
    accepted = false;
  }
  if (!accepted) return poison(state, failed('ARTIFACT_PUBLICATION_FAILED'));
  state.phase = 'PUBLISHED';
  return PASS_NULL;
}

function releaseSessionState(state) {
  state.abortController = null;
  state.abortSignal = null;
  state.configuration = null;
  state.filesystem = null;
  state.inFlight = null;
  state.limits = null;
  state.launcher = null;
  state.outputRootHandle = null;
  state.publicationLeaseAuthority = null;
  state.retainedOutput = null;
  state.validatedData = null;
  state.validatedOutputSink = null;
  state.descriptor = null;
  state.sandboxTransport = null;
  state.source = null;
  state.workspace = null;
}

async function executeClose(state, pendingOperation, preserveValidatedOutput, settle) {
  let outcome = blocked('ARTIFACT_CLEANUP_INCOMPLETE');
  let safeToRelease = false;
  try {
    reflectApply(abortControllerAbort, state.abortController, []);
    if (pendingOperation !== null && !(await waitForQuiescence(pendingOperation))) {
      return;
    }
    safeToRelease = true;
    let retainedClean = state.retainedOutput === null;
    let workspaceClean = false;
    let sourceClean = false;
    if (state.retainedOutput !== null) {
      try {
        const observed = await prepareAwaitable(reflectApply(
          state.retainedOutput.close,
          state.retainedOutput.receiver,
          [],
        ));
        retainedClean = validNullPass(observedValue(observed));
      } catch {
        retainedClean = false;
      }
    }
    try {
      const observed = await prepareAwaitable(reflectApply(
        state.workspace.close,
        state.workspace.lease,
        [objectFreeze({ preserveValidatedOutput: preserveValidatedOutput && retainedClean })],
      ));
      workspaceClean = validNullPass(observedValue(observed));
    } catch {
      workspaceClean = false;
    }
    try {
      const observed = await prepareAwaitable(
        reflectApply(state.source.close, state.source.lease, []),
      );
      sourceClean = validNullPass(observedValue(observed));
    } catch {
      sourceClean = false;
    }
    outcome = retainedClean && workspaceClean && sourceClean
      ? PASS_NULL
      : blocked('ARTIFACT_CLEANUP_INCOMPLETE');
  } catch {
    outcome = blocked('ARTIFACT_CLEANUP_INCOMPLETE');
  } finally {
    if (safeToRelease) releaseSessionState(state);
    settle(outcome);
  }
}

function close() {
  const state = getPortState(this, 'parent');
  if (state === null) return INVALID;
  if (state.closePromise !== null) return state.closePromise;
  const pendingOperation = state.inFlight;
  const preserveValidatedOutput = state.firstFailure === null
    && (state.phase === 'VALIDATED' || state.phase === 'PUBLISHED');
  const deferred = createDeferred();
  state.closed = true;
  state.phase = 'CLOSED';
  state.closePromise = deferred.promise;
  void executeClose(state, pendingOperation, preserveValidatedOutput, deferred.settle);
  return state.closePromise;
}

async function openSession(...args) {
  const launcherState = reflectApply(weakMapGet, launcherStates, [this]);
  if (launcherState === undefined || args.length !== 0) return INVALID;
  if (launcherState.openAttempted) return INVALID;
  launcherState.openAttempted = true;

  const request = objectFreeze({
    sourceCheckoutRoot: launcherState.configuration.sourceCheckoutRoot,
    sourceRevision: launcherState.configuration.sourceRevision,
    sourceTreeDigest: launcherState.configuration.sourceTreeDigest,
  });
  let sourceCandidate;
  try {
    const observed = await prepareAwaitable(reflectApply(
      launcherState.sourceSnapshotHost.openSnapshot,
      launcherState.sourceSnapshotHost.receiver,
      [request],
    ));
    sourceCandidate = observedValue(observed);
  } catch {
    return failed('ARTIFACT_BUILD_FAILED');
  }
  const sourceEnvelope = readPassEnvelope(sourceCandidate);
  if (sourceEnvelope === null) {
    return normalizeFailure(
      sourceCandidate,
      SOURCE_FAILURE_CODES,
      'FAIL',
      'ARTIFACT_BUILD_FAILED',
    );
  }
  const source = authenticateSourceLease(sourceEnvelope.value, launcherState.configuration);
  if (source === null) return INVALID;

  let workspaceCandidate;
  try {
    const observed = await prepareAwaitable(reflectApply(
      launcherState.workspaceHost.openWorkspace,
      launcherState.workspaceHost.receiver,
      [source.lease],
    ));
    workspaceCandidate = observedValue(observed);
  } catch {
    workspaceCandidate = null;
  }
  const workspaceEnvelope = readPassEnvelope(workspaceCandidate);
  if (workspaceEnvelope === null) {
    const clean = await closeAuthenticatedSource(source);
    if (!clean) return blocked('ARTIFACT_CLEANUP_INCOMPLETE');
    return normalizeFailure(
      workspaceCandidate,
      WORKSPACE_FAILURE_CODES,
      'BLOCKED',
      'ARTIFACT_PATH_UNSAFE',
    );
  }
  const workspaceConfiguration = objectFreeze({
    ...launcherState.configuration,
    limits: launcherState.limits,
  });
  const workspace = authenticateWorkspaceLease(workspaceEnvelope.value, workspaceConfiguration);
  if (workspace === null) {
    const clean = await closeAuthenticatedSource(source);
    return clean ? INVALID : blocked('ARTIFACT_CLEANUP_INCOMPLETE');
  }

  const identity = closedRecord({
    repository: launcherState.configuration.repository,
    workflow: launcherState.configuration.workflow,
    sourceRef: launcherState.configuration.sourceRef,
    sourceRevision: source.identity.sourceRevision,
    sourceTreeDigest: source.identity.sourceTreeDigest,
    verifierManifestDigest: source.identity.verifierManifestDigest,
    workflowRunId: launcherState.configuration.workflowRunId,
    workflowRunAttempt: launcherState.configuration.workflowRunAttempt,
  });
  const abortController = new NativeAbortController();
  const state = {
    abortController,
    abortSignal: reflectApply(getAbortSignal, abortController, []),
    busy: false,
    closePromise: null,
    closed: false,
    commandIndex: 0,
    configuration: launcherState.configuration,
    filesystem: launcherState.filesystem,
    firstFailure: null,
    inFlight: null,
    limits: launcherState.limits,
    memberIndex: 0,
    outputRootHandle: workspace.outputRootHandle,
    phase: 'COMMANDS',
    descriptor: null,
    retainedOutput: null,
    validatedData: null,
    validatedOutputSink: launcherState.validatedOutputSink,
    sandboxTransport: launcherState.sandboxTransport,
    launcher: launcherState.launcher,
    publicationLeaseAuthority: launcherState.publicationLeaseAuthority,
    sessionIdentity: objectFreeze(objectCreate(null)),
    source,
    totalBytes: 0,
    workspace,
    workspaceOutputIdentity: closedRecord({
      outputRootHandle: workspace.outputRootHandle,
      workspaceLease: workspace.lease,
    }),
  };
  let candidatePort;
  function sessionRunCommand(...methodArgs) {
    if (this !== candidatePort || methodArgs.length !== 1) return resolvedClosedResult(INVALID);
    return reflectApply(runCommand, candidatePort, methodArgs);
  }
  function sessionWriteOutputMember(...methodArgs) {
    if (this !== candidatePort || methodArgs.length !== 1) return resolvedClosedResult(INVALID);
    return reflectApply(writeOutputMember, candidatePort, methodArgs);
  }
  candidatePort = closedRecord({
    identity,
    runCommand: sessionRunCommand,
    workspace: workspace.workspace,
    writeOutputMember: sessionWriteOutputMember,
  });

  let parentPort;
  function sessionClose(...methodArgs) {
    if (this !== parentPort || methodArgs.length !== 0) return INVALID;
    return reflectApply(close, parentPort, methodArgs);
  }
  function sessionPublishValidatedOutput(...methodArgs) {
    if (this !== parentPort || methodArgs.length !== 1) return resolvedClosedResult(INVALID);
    return reflectApply(publishValidatedOutput, parentPort, methodArgs);
  }
  function sessionValidateOutput(...methodArgs) {
    if (this !== parentPort || methodArgs.length !== 1) return resolvedClosedResult(INVALID);
    return reflectApply(validateOutput, parentPort, methodArgs);
  }
  parentPort = closedRecord({
    close: sessionClose,
    publishValidatedOutput: sessionPublishValidatedOutput,
    validateOutput: sessionValidateOutput,
  });
  reflectApply(weakMapSet, portStates, [
    candidatePort,
    objectFreeze({ role: 'candidate', state }),
  ]);
  reflectApply(weakMapSet, portStates, [
    parentPort,
    objectFreeze({ role: 'parent', state }),
  ]);
  return pass({ candidatePort, parentPort });
}

export function createTrustedSourceArtifactLauncher(args) {
  if (!isTrustedPromiseBootstrapReady()) return BOOTSTRAP_UNAVAILABLE_LAUNCHER;
  let constructorKeys;
  try {
    constructorKeys = args !== null
      && typeof args === 'object'
      && !isProxy(args)
      && hasOwn(args, 'publicationLeaseAuthority')
      ? CONSTRUCTOR_KEYS_WITH_PUBLICATION_AUTHORITY
      : CONSTRUCTOR_KEYS;
  } catch {
    throw new TypeError('Trusted source artifact launcher configuration is invalid.');
  }
  const input = exactDataObject(args, constructorKeys);
  if (input === null) throw new TypeError('Trusted source artifact launcher configuration is invalid.');
  const limits = exactLimits(input.limits);
  if (limits === null) throw new TypeError('Trusted source artifact launcher configuration is invalid.');
  const configuration = snapshotConfiguration(input.parentConfiguration, limits);
  const sourceSnapshotHost = exactCapability(input.sourceSnapshotHost, ['openSnapshot']);
  const workspaceHost = exactCapability(input.workspaceHost, ['openWorkspace']);
  const sandboxTransport = exactCapability(input.sandboxTransport, ['run']);
  const filesystem = exactCapability(input.filesystem, [
    'inspectTreeAtomically', 'writeMemberAtomically',
  ]);
  const validatedOutputSink = input.validatedOutputSink === null
    ? null
    : exactCapability(input.validatedOutputSink, ['streamValidatedArtifact']);
  const publicationLeaseAuthority = constructorKeys === CONSTRUCTOR_KEYS_WITH_PUBLICATION_AUTHORITY
    && isPublicationLeaseLauncherAuthority(input.publicationLeaseAuthority)
    ? input.publicationLeaseAuthority
    : null;
  const capabilities = new NativeArray(5);
  let capabilityCount = 0;
  const candidates = [
    sourceSnapshotHost,
    workspaceHost,
    sandboxTransport,
    filesystem,
    validatedOutputSink,
  ];
  for (let index = 0; index < candidates.length; index += 1) {
    if (candidates[index] !== null) {
      objectDefineProperty(
        capabilities,
        capabilityCount,
        dataDescriptor(candidates[index], true, true, true),
      );
      capabilityCount += 1;
    }
  }
  let aliasedCapability = false;
  for (let index = 0; index < capabilityCount; index += 1) {
    for (let otherIndex = index + 1; otherIndex < capabilityCount; otherIndex += 1) {
      if (capabilities[index].receiver === capabilities[otherIndex].receiver) {
        aliasedCapability = true;
      }
    }
  }
  if (
    configuration === null
    || sourceSnapshotHost === null
    || workspaceHost === null
    || sandboxTransport === null
    || filesystem === null
    || (input.validatedOutputSink !== null && validatedOutputSink === null)
    || (constructorKeys === CONSTRUCTOR_KEYS_WITH_PUBLICATION_AUTHORITY
      && publicationLeaseAuthority === null)
    || aliasedCapability
  ) throw new TypeError('Trusted source artifact launcher configuration is invalid.');

  const state = {
    configuration,
    filesystem,
    limits,
    openAttempted: false,
    publicationLeaseAuthority,
    sandboxTransport,
    sourceSnapshotHost,
    validatedOutputSink,
    workspaceHost,
  };
  const launcher = objectFreeze({ openSession });
  if (
    publicationLeaseAuthority !== null
    && !registerPublicationLauncher(publicationLeaseAuthority, launcher)
  ) throw new TypeError('Trusted source artifact launcher configuration is invalid.');
  state.launcher = launcher;
  reflectApply(weakMapSet, launcherStates, [launcher, state]);
  return launcher;
}
