import { createHash } from 'node:crypto';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

import {
  isTrustedPromiseBootstrapReady,
  observeTrustedOperation,
} from './trusted-promise-bootstrap.mjs';
import {
  captureSourceArtifactSourceLeaseIssuer,
} from './source-artifact-source-lease-authority.mjs';

const apply = Reflect.apply;
const isProxy = utilTypes.isProxy;
const isSharedArrayBuffer = utilTypes.isSharedArrayBuffer;
const isUint8Array = utilTypes.isUint8Array;
const freezeObject = Object.freeze;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectSetPrototypeOf = Object.setPrototypeOf;
const reflectOwnKeys = Reflect.ownKeys;
const createHashIntrinsic = createHash;
const hashProbe = apply(createHashIntrinsic, undefined, ['sha256']);
const hashPrototype = apply(objectGetPrototypeOf, Object, [hashProbe]);
const hashDigest = hashPrototype.digest;
const hashUpdate = hashPrototype.update;
const NativeArray = Array;
const NativeMap = Map;
const NativeNumber = Number;
const NativeSet = Set;
const NativeString = String;
const NativeTextDecoder = TextDecoder;
const NativeTextEncoder = TextEncoder;
const NativeUint8Array = Uint8Array;
const ArrayPrototype = Array.prototype;
const MapPrototype = Map.prototype;
const SetPrototype = Set.prototype;
const StringPrototype = String.prototype;
const arrayIsArray = Array.isArray;
const arrayPush = ArrayPrototype.push;
const arraySort = ArrayPrototype.sort;
const mapGet = MapPrototype.get;
const mapHas = MapPrototype.has;
const mapSet = MapPrototype.set;
const getMapSize = apply(objectGetOwnPropertyDescriptor, Object, [MapPrototype, 'size']).get;
const setHas = SetPrototype.has;
const stringCharCodeAt = StringPrototype.charCodeAt;
const stringEndsWith = StringPrototype.endsWith;
const stringIncludes = StringPrototype.includes;
const stringIndexOf = StringPrototype.indexOf;
const stringSlice = StringPrototype.slice;
const stringSplit = StringPrototype.split;
const stringStartsWith = StringPrototype.startsWith;
const stringToLowerCase = StringPrototype.toLowerCase;
const NativeBuffer = Buffer;
const bufferByteLength = NativeBuffer.byteLength;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const mathCeil = Math.ceil;
const numberIsSafeInteger = Number.isSafeInteger;
const numberParseInt = Number.parseInt;
const regexpExec = RegExp.prototype.exec;
const stringFromCharCode = String.fromCharCode;
const textDecoderDecode = TextDecoder.prototype.decode;
const textEncoderEncode = TextEncoder.prototype.encode;
const cloneStructured = structuredClone;
const posixIsAbsolute = path.posix.isAbsolute;
const posixNormalize = path.posix.normalize;
const win32IsAbsolute = path.win32.isAbsolute;
const NativeURL = URL;
const URLPrototype = NativeURL.prototype;
const urlGetHash = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'hash']).get;
const urlGetHostname = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'hostname']).get;
const urlGetHref = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'href']).get;
const urlGetOrigin = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'origin']).get;
const urlGetPassword = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'password']).get;
const urlGetPathname = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'pathname']).get;
const urlGetPort = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'port']).get;
const urlGetProtocol = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'protocol']).get;
const urlGetSearch = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'search']).get;
const urlGetUsername = apply(objectGetOwnPropertyDescriptor, Object, [URLPrototype, 'username']).get;
const ObjectPrototype = Object.prototype;
const ArrayPrototypeIntrinsic = Array.prototype;
const Uint8ArrayPrototype = Uint8Array.prototype;
const BufferPrototype = Buffer.prototype;
const freeze = (value) => apply(freezeObject, null, [value]);

function closedRecord(fields) {
  const record = objectCreate(null);
  const keys = reflectOwnKeys(fields);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const field = objectGetOwnPropertyDescriptor(fields, key);
    const descriptor = objectCreate(null);
    descriptor.configurable = false;
    descriptor.enumerable = true;
    descriptor.value = field.value;
    descriptor.writable = false;
    objectDefineProperty(record, key, descriptor);
  }
  return freeze(record);
}

function ownArrayLength(value) {
  if (!arrayIsArray(value)) throw new TypeError('Trusted argv source must be an array.');
  const descriptor = objectGetOwnPropertyDescriptor(value, 'length');
  if (
    descriptor === undefined
    || !apply(objectHasOwn, undefined, [descriptor, 'value'])
    || !apply(numberIsSafeInteger, NativeNumber, [descriptor.value])
    || descriptor.value < 0
  ) throw new TypeError('Trusted argv source length is invalid.');
  return descriptor.value;
}

function copyOwnArrayData(source, target, offset) {
  const length = ownArrayLength(source);
  for (let index = 0; index < length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(source, index);
    if (
      descriptor === undefined
      || descriptor.enumerable !== true
      || !apply(objectHasOwn, undefined, [descriptor, 'value'])
    ) throw new TypeError('Trusted argv source must contain only indexed data.');
    target[offset + index] = descriptor.value;
  }
  return length;
}

function frozenPrototypeFreeArgv(prefix, suffix) {
  const prefixLength = ownArrayLength(prefix);
  const suffixLength = ownArrayLength(suffix);
  const argv = new NativeArray(prefixLength + suffixLength);
  copyOwnArrayData(prefix, argv, 0);
  copyOwnArrayData(suffix, argv, prefixLength);
  apply(objectSetPrototypeOf, undefined, [argv, null]);
  return freeze(argv);
}

function frozenPrototypeFreeGitArgv(prefix, safeDirectory, suffix) {
  const prefixLength = ownArrayLength(prefix);
  const suffixLength = ownArrayLength(suffix);
  const argv = new NativeArray(prefixLength + 2 + suffixLength);
  copyOwnArrayData(prefix, argv, 0);
  argv[prefixLength] = '-c';
  argv[prefixLength + 1] = safeDirectory;
  copyOwnArrayData(suffix, argv, prefixLength + 2);
  apply(objectSetPrototypeOf, undefined, [argv, null]);
  return freeze(argv);
}

function pushOwn(target, value) {
  apply(arrayPush, target, [value]);
}

function sortOwn(target, compare) {
  apply(arraySort, target, [compare]);
  return target;
}

function mapGetOwn(target, key) {
  return apply(mapGet, target, [key]);
}

function mapHasOwn(target, key) {
  return apply(mapHas, target, [key]);
}

function mapSetOwn(target, key, value) {
  apply(mapSet, target, [key, value]);
}

function setHasOwn(target, value) {
  return apply(setHas, target, [value]);
}

function stringEndsWithOwn(value, suffix) {
  return apply(stringEndsWith, value, [suffix]);
}

function stringIncludesOwn(value, search) {
  return apply(stringIncludes, value, [search]);
}

function stringSliceOwn(value, start, end) {
  return end === undefined
    ? apply(stringSlice, value, [start])
    : apply(stringSlice, value, [start, end]);
}

function stringSplitOwn(value, separator) {
  return apply(stringSplit, value, [separator]);
}

function stringStartsWithOwn(value, prefix, position = 0) {
  return apply(stringStartsWith, value, [prefix, position]);
}

function stringToLowerCaseOwn(value) {
  return apply(stringToLowerCase, value, []);
}
const fillBytes = Uint8ArrayPrototype.fill;
const setAdd = SetPrototype.add;
const setDelete = SetPrototype.delete;
const getSetSize = apply(objectGetOwnPropertyDescriptor, Object, [SetPrototype, 'size']).get;
const FULL_REVISION = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const OBJECT_ID = /^[0-9a-f]{40,64}$/u;
const SOURCE_REQUEST_KEYS = freeze([
  'sourceCheckoutRoot',
  'sourceRevision',
  'sourceTreeDigest',
]);
const CONSTRUCTOR_KEYS = freeze([
  'filesystem',
  'gitExecutable',
  'limits',
  'processTransport',
  'sourceLeaseIssuer',
]);
const LIMIT_KEYS = freeze([
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
const LOCKFILE_BYTE_LIMIT = 512 * 1024;
const LOCKFILE_JSON_MAX_NESTING = 64;
const LOCKFILE_JSON_TOKEN_LIMIT = 65_536;
const LIMIT_VALUES = freeze({
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
const FIXED_PREFIX = freeze([
  '--no-replace-objects',
  '-c',
  'core.fsmonitor=false',
  '-c',
  'protocol.allow=never',
  '-c',
  'submodule.recurse=false',
]);
const GIT_ENVIRONMENT = closedRecord({
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
const MANIFEST_PATH = 'dev/verification/verification-manifest.v1.json';
const ROOT_LOCKFILE_PATH = 'package-lock.json';
const WEB_LOCKFILE_PATH = 'src/web/package-lock.json';
const OPERATION_DEADLINE_MS = 600_000;
const QUIESCENCE_GRACE_MS = 5_000;
const EXCLUDED_SEGMENTS = new NativeSet(['node_modules', 'dist', '.verification']);
const typedArrayPrototype = apply(objectGetPrototypeOf, Object, [Uint8ArrayPrototype]);
const getByteLength = apply(objectGetOwnPropertyDescriptor, Object, [typedArrayPrototype, 'byteLength']).get;
const getByteOffset = apply(objectGetOwnPropertyDescriptor, Object, [typedArrayPrototype, 'byteOffset']).get;
const getBuffer = apply(objectGetOwnPropertyDescriptor, Object, [typedArrayPrototype, 'buffer']).get;
const getLength = apply(objectGetOwnPropertyDescriptor, Object, [typedArrayPrototype, 'length']).get;
const typedArraySet = typedArrayPrototype.set;
const getArrayBufferByteLength = apply(
  objectGetOwnPropertyDescriptor,
  Object,
  [ArrayBuffer.prototype, 'byteLength'],
).get;
const getResizable = apply(
  objectGetOwnPropertyDescriptor,
  Object,
  [ArrayBuffer.prototype, 'resizable'],
)?.get;
const scheduleTimeout = globalThis.setTimeout;
const cancelTimeout = globalThis.clearTimeout;
const NativeAbortController = AbortController;
const abortControllerAbort = AbortController.prototype.abort;
const getAbortSignal = apply(
  objectGetOwnPropertyDescriptor,
  Object,
  [AbortController.prototype, 'signal'],
).get;
const getSignalAborted = apply(
  objectGetOwnPropertyDescriptor,
  Object,
  [AbortSignal.prototype, 'aborted'],
).get;
const addEventListener = EventTarget.prototype.addEventListener;
const removeEventListener = EventTarget.prototype.removeEventListener;
const NativePromise = Promise;

function typedArrayBacking(value) {
  return apply(getBuffer, value, []);
}

function typedArrayByteLength(value) {
  return apply(getByteLength, value, []);
}

function typedArrayByteOffset(value) {
  return apply(getByteOffset, value, []);
}

function typedArrayLength(value) {
  return apply(getLength, value, []);
}

function retainedByteView(value, start = 0, end = undefined) {
  const length = typedArrayLength(value);
  const finalOffset = end === undefined ? length : end;
  return new NativeUint8Array(
    typedArrayBacking(value),
    typedArrayByteOffset(value) + start,
    finalOffset - start,
  );
}

function decodeUtf8(bytes) {
  const decoder = new NativeTextDecoder('utf-8', { fatal: true });
  return apply(textDecoderDecode, decoder, [bytes]);
}

function encodeUtf8(value) {
  const encoder = new NativeTextEncoder();
  return apply(textEncoderEncode, encoder, [value]);
}

function bytesEqual(left, right) {
  const length = typedArrayLength(left);
  if (length !== typedArrayLength(right)) return false;
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function indexOfByte(bytes, byte, offset) {
  const length = typedArrayLength(bytes);
  for (let index = offset; index < length; index += 1) {
    if (bytes[index] === byte) return index;
  }
  return -1;
}

function sha256Retained(bytes) {
  const hash = apply(createHashIntrinsic, undefined, ['sha256']);
  apply(hashUpdate, hash, [retainedByteView(bytes)]);
  return `sha256:${apply(hashDigest, hash, ['hex'])}`;
}

const MESSAGES = freeze({
  ARTIFACT_SCHEMA_INVALID: 'Trusted source input does not match the closed contract.',
  ARTIFACT_PATH_UNSAFE: 'Trusted source revision or tree identity is unsafe.',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'Trusted source isolation is unavailable.',
  ARTIFACT_BUILD_FAILED: 'Trusted source verification could not be completed.',
  ARTIFACT_CLEANUP_INCOMPLETE: 'Trusted source cleanup could not be completed.',
});

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function result(status, value, code = null) {
  return closedRecord({
    status,
    value,
    diagnostics: code === null
      ? freeze([])
      : freeze([closedRecord({
        code,
        safeMessage: MESSAGES[code],
        retryable: false,
      })]),
  });
}

function pass(value) {
  return result('PASS', value);
}

function blocked(code) {
  return result('BLOCKED', null, code);
}

function failed(code) {
  return result('FAIL', null, code);
}

const BOOTSTRAP_UNAVAILABLE = blocked('ARTIFACT_SCHEMA_INVALID');
const BOOTSTRAP_UNAVAILABLE_HOST = closedRecord({
  openSnapshot() {
    return BOOTSTRAP_UNAVAILABLE;
  },
});

function exactDataObject(value, expectedKeys, expectedPrototype = ObjectPrototype) {
  try {
    if (
      apply(isProxy, utilTypes, [value])
      || value === null
      || typeof value !== 'object'
      || arrayIsArray(value)
      || objectGetPrototypeOf(value) !== expectedPrototype
    ) return null;
    const ownKeys = reflectOwnKeys(value);
    const expectedLength = ownArrayLength(expectedKeys);
    if (ownKeys.length !== expectedLength) return null;
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
    }
    const copy = objectCreate(null);
    for (let index = 0; index < expectedLength; index += 1) {
      const expectedDescriptor = objectGetOwnPropertyDescriptor(expectedKeys, index);
      if (
        expectedDescriptor === undefined
        || !apply(objectHasOwn, undefined, [expectedDescriptor, 'value'])
      ) return null;
      const key = expectedDescriptor.value;
      let found = false;
      for (let candidateIndex = 0; candidateIndex < ownKeys.length; candidateIndex += 1) {
        if (ownKeys[candidateIndex] === key) {
          found = true;
          break;
        }
      }
      if (!found) return null;
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || descriptor.enumerable !== true
        || !apply(objectHasOwn, undefined, [descriptor, 'value'])
      ) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function exactOperationDataObject(value, expectedKeys) {
  const copy = exactDataObject(value, expectedKeys, null);
  return copy !== null && apply(objectIsFrozen, undefined, [value])
    ? copy
    : null;
}

function exactArray(value, expectedLength = null) {
  try {
    if (
      apply(isProxy, utilTypes, [value])
      || !apply(arrayIsArray, NativeArray, [value])
      || apply(objectGetPrototypeOf, Object, [value]) !== ArrayPrototypeIntrinsic
    ) return null;
    const lengthDescriptor = apply(objectGetOwnPropertyDescriptor, Object, [value, 'length']);
    if (
      lengthDescriptor === undefined
      || !apply(objectHasOwn, Object, [lengthDescriptor, 'value'])
    ) return null;
    const length = lengthDescriptor.value;
    if (
      !apply(numberIsSafeInteger, NativeNumber, [length])
      || length < 0
      || (expectedLength !== null && length !== expectedLength)
    ) return null;

    const ownKeys = apply(reflectOwnKeys, Reflect, [value]);
    if (ownKeys.length !== length + 1) return null;
    const expectedKeys = new NativeArray(length + 1);
    expectedKeys[0] = 'length';
    for (let index = 0; index < length; index += 1) {
      expectedKeys[index + 1] = apply(NativeString, undefined, [index]);
    }
    const actualKeys = new NativeArray(ownKeys.length);
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
      actualKeys[index] = ownKeys[index];
    }
    sortOwn(expectedKeys, ordinalCompare);
    sortOwn(actualKeys, ordinalCompare);
    for (let index = 0; index < actualKeys.length; index += 1) {
      if (actualKeys[index] !== expectedKeys[index]) return null;
    }

    const copy = new NativeArray(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = apply(
        objectGetOwnPropertyDescriptor,
        Object,
        [value, apply(NativeString, undefined, [index])],
      );
      if (
        descriptor === undefined
        || descriptor.enumerable !== true
        || !apply(objectHasOwn, Object, [descriptor, 'value'])
      ) return null;
      copy[index] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function exactCapability(value, methodNames) {
  const copy = exactDataObject(value, methodNames);
  if (copy === null || !apply(objectIsFrozen, Object, [value])) return null;
  const methodCount = ownArrayLength(methodNames);
  for (let index = 0; index < methodCount; index += 1) {
    const descriptor = apply(objectGetOwnPropertyDescriptor, Object, [methodNames, index]);
    if (descriptor === undefined || !apply(objectHasOwn, Object, [descriptor, 'value'])) return null;
    const name = descriptor.value;
    if (typeof copy[name] !== 'function' || apply(isProxy, utilTypes, [copy[name]])) return null;
  }
  return freeze({ receiver: value, ...copy });
}

function exactLimits(value) {
  const copy = exactDataObject(value, LIMIT_KEYS);
  if (copy === null || !apply(objectIsFrozen, Object, [value])) return null;
  const keyCount = ownArrayLength(LIMIT_KEYS);
  for (let index = 0; index < keyCount; index += 1) {
    const descriptor = apply(objectGetOwnPropertyDescriptor, Object, [LIMIT_KEYS, index]);
    if (descriptor === undefined || !apply(objectHasOwn, Object, [descriptor, 'value'])) return null;
    const key = descriptor.value;
    if (copy[key] !== LIMIT_VALUES[key]) return null;
  }
  return freeze(copy);
}

function canonicalAbsolutePosixPath(value, maximumBytes) {
  return (
    typeof value === 'string'
    && value.length > 1
    && apply(bufferByteLength, Buffer, [value, 'utf8']) <= maximumBytes
    && !stringIncludesOwn(value, '\\')
    && apply(regexpExec, /[\u0000-\u001f\u007f]/u, [value]) === null
    && apply(posixIsAbsolute, path.posix, [value])
    && apply(posixNormalize, path.posix, [value]) === value
  );
}

function safeRepositoryPath(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || stringIncludesOwn(value, '\\')
    || apply(regexpExec, /[\u0000-\u001f\u007f]/u, [value]) !== null
    || apply(posixIsAbsolute, path.posix, [value])
    || apply(win32IsAbsolute, path.win32, [value])
    || apply(posixNormalize, path.posix, [value]) !== value
  ) return false;
  const segments = stringSplitOwn(value, '/');
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === '' || segment === '.' || segment === '..') return false;
  }
  return true;
}

function excludedRepositoryPath(repositoryPath) {
  const segments = stringSplitOwn(repositoryPath, '/');
  for (let index = 0; index < segments.length; index += 1) {
    if (setHasOwn(EXCLUDED_SEGMENTS, segments[index])) return true;
  }
  return false;
}

function snapshotBytes(value, maximumBytes, allowEmpty = true) {
  let copy = null;
  try {
    if (apply(isProxy, utilTypes, [value]) || !apply(isUint8Array, utilTypes, [value])) return null;
    const prototype = apply(objectGetPrototypeOf, Object, [value]);
    if (prototype !== Uint8ArrayPrototype && prototype !== BufferPrototype) return null;
    const byteLength = apply(getByteLength, value, []);
    const byteOffset = apply(getByteOffset, value, []);
    if (
      !apply(numberIsSafeInteger, NativeNumber, [byteLength])
      || byteLength < (allowEmpty ? 0 : 1)
      || byteLength > maximumBytes
      || !apply(numberIsSafeInteger, NativeNumber, [byteOffset])
      || byteOffset < 0
    ) return null;
    const backing = apply(getBuffer, value, []);
    if (
      apply(isSharedArrayBuffer, utilTypes, [backing])
      || (getResizable && apply(getResizable, backing, []) === true)
      || byteOffset + byteLength > apply(getArrayBufferByteLength, backing, [])
    ) return null;
    copy = new NativeUint8Array(byteLength);
    apply(typedArraySet, copy, [value]);
    if (
      apply(getByteLength, value, []) !== byteLength
      || apply(getByteOffset, value, []) !== byteOffset
    ) {
      apply(fillBytes, copy, [0]);
      return null;
    }
    return copy;
  } catch {
    if (copy !== null) {
      try { apply(fillBytes, copy, [0]); } catch { /* the retained intrinsic is best-effort here */ }
    }
    return null;
  }
}

function takeOwnedBytes(value, maximumBytes) {
  let ownedBytes = null;
  try {
    if (apply(isProxy, utilTypes, [value]) || !apply(isUint8Array, utilTypes, [value])) return null;
    const prototype = apply(objectGetPrototypeOf, Object, [value]);
    if (prototype !== Uint8ArrayPrototype && prototype !== BufferPrototype) return null;
    const byteLength = apply(getByteLength, value, []);
    const byteOffset = apply(getByteOffset, value, []);
    if (
      !apply(numberIsSafeInteger, NativeNumber, [byteLength])
      || byteLength < 1
      || byteLength > maximumBytes
      || byteOffset !== 0
    ) return null;
    const backing = apply(getBuffer, value, []);
    const backingLength = apply(getArrayBufferByteLength, backing, []);
    if (
      apply(isSharedArrayBuffer, utilTypes, [backing])
      || (getResizable && apply(getResizable, backing, []) === true)
      || backingLength !== byteLength
    ) return null;
    const transferred = apply(cloneStructured, globalThis, [backing, { transfer: [backing] }]);
    ownedBytes = new NativeUint8Array(transferred);
    if (
      apply(getArrayBufferByteLength, backing, []) !== 0
      || apply(getArrayBufferByteLength, transferred, []) !== byteLength
    ) {
      apply(fillBytes, ownedBytes, [0]);
      return null;
    }
    return ownedBytes;
  } catch {
    if (ownedBytes !== null) {
      try { apply(fillBytes, ownedBytes, [0]); } catch { /* the retained intrinsic is best-effort here */ }
    }
    return null;
  }
}

function parseResolvedRevision(bytes) {
  const buffer = retainedByteView(bytes);
  const text = decodeUtf8(buffer);
  if (apply(regexpExec, /^([0-9a-f]{40})\n$/u, [text]) === null) return null;
  return stringSliceOwn(text, 0, -1);
}

function splitNulUtf8(bytes) {
  const buffer = retainedByteView(bytes);
  const length = typedArrayLength(buffer);
  if (length === 0 || buffer[length - 1] !== 0) return null;
  const text = decodeUtf8(buffer);
  const encoded = encodeUtf8(text);
  if (!bytesEqual(encoded, buffer)) return null;
  return stringSplitOwn(stringSliceOwn(text, 0, -1), '\0');
}

function parseTree(bytes) {
  const records = splitNulUtf8(bytes);
  if (records === null) return null;
  const authenticatedTree = new NativeArray();
  const candidateTree = new NativeArray();
  const paths = new NativeSet();
  const foldedPaths = new NativeSet();
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const match = apply(
      regexpExec,
      /^([0-7]{6}) ([^ ]+) ([0-9a-f]{40,64})\t([\s\S]+)$/u,
      [record],
    );
    if (match === null) return null;
    const mode = match[1];
    const type = match[2];
    const objectId = match[3];
    const repositoryPath = match[4];
    const folded = stringToLowerCaseOwn(repositoryPath);
    if (
      (mode !== '100644' && mode !== '100755')
      || type !== 'blob'
      || apply(regexpExec, OBJECT_ID, [objectId]) === null
      || !safeRepositoryPath(repositoryPath)
      || setHasOwn(paths, repositoryPath)
      || setHasOwn(foldedPaths, folded)
    ) return null;
    apply(setAdd, paths, [repositoryPath]);
    apply(setAdd, foldedPaths, [folded]);
    const entry = { path: repositoryPath, mode, objectId };
    pushOwn(authenticatedTree, entry);
    if (!excludedRepositoryPath(repositoryPath)) pushOwn(candidateTree, entry);
  }
  sortOwn(authenticatedTree, (left, right) => ordinalCompare(left.path, right.path));
  sortOwn(candidateTree, (left, right) => ordinalCompare(left.path, right.path));
  return { authenticatedTree, candidateTree };
}

function findLockfileObjectIds(authenticatedTree) {
  let rootObjectId = null;
  let webObjectId = null;
  for (let index = 0; index < authenticatedTree.length; index += 1) {
    const entry = authenticatedTree[index];
    if (entry.path === ROOT_LOCKFILE_PATH) rootObjectId = entry.objectId;
    else if (entry.path === WEB_LOCKFILE_PATH) webObjectId = entry.objectId;
  }
  if (rootObjectId === null || webObjectId === null) return null;
  const objectIds = new NativeSet();
  apply(setAdd, objectIds, [rootObjectId]);
  apply(setAdd, objectIds, [webObjectId]);
  return objectIds;
}

function strictJsonParse(source) {
  try {
    if (typeof source !== 'string') return null;
    let index = 0;
    const length = source.length;
    const frames = new NativeArray(LOCKFILE_JSON_MAX_NESTING);
    let depth = 0;
    let tokenCount = 0;
    let rootComplete = false;

    function skipWhitespace() {
      while (index < length) {
        const character = source[index];
        if (
          character !== ' '
          && character !== '\t'
          && character !== '\r'
          && character !== '\n'
        ) break;
        index += 1;
      }
    }

    function consumeToken() {
      tokenCount += 1;
      if (tokenCount > LOCKFILE_JSON_TOKEN_LIMIT) {
        throw new TypeError('JSON token budget exceeded');
      }
    }

    function isHexCharacter(character) {
      const code = apply(stringCharCodeAt, character, [0]);
      return (code >= 0x30 && code <= 0x39)
        || (code >= 0x41 && code <= 0x46)
        || (code >= 0x61 && code <= 0x66);
    }

    function scanString(decode) {
      if (source[index] !== '"') throw new TypeError('invalid JSON string');
      const start = index;
      index += 1;
      while (index < length) {
        const character = source[index];
        if (character === '"') {
          index += 1;
          return decode
            ? apply(jsonParse, JSON, [stringSliceOwn(source, start, index)])
            : null;
        }
        if (character === '\\') {
          index += 1;
          if (index >= length) throw new TypeError('invalid JSON escape');
          const escape = source[index];
          if (escape === 'u') {
            if (
              index + 4 >= length
              || !isHexCharacter(source[index + 1])
              || !isHexCharacter(source[index + 2])
              || !isHexCharacter(source[index + 3])
              || !isHexCharacter(source[index + 4])
            ) throw new TypeError('invalid JSON escape');
            index += 5;
            continue;
          }
          if (
            escape !== '"'
            && escape !== '\\'
            && escape !== '/'
            && escape !== 'b'
            && escape !== 'f'
            && escape !== 'n'
            && escape !== 'r'
            && escape !== 't'
          ) throw new TypeError('invalid JSON escape');
          index += 1;
          continue;
        }
        if (apply(stringCharCodeAt, character, [0]) < 0x20) {
          throw new TypeError('invalid JSON control character');
        }
        index += 1;
      }
      throw new TypeError('unterminated JSON string');
    }

    function isDigitAt(position) {
      if (position >= length) return false;
      const code = apply(stringCharCodeAt, source[position], [0]);
      return code >= 0x30 && code <= 0x39;
    }

    function scanNumber() {
      let cursor = index;
      if (source[cursor] === '-') cursor += 1;
      if (source[cursor] === '0') {
        cursor += 1;
        if (isDigitAt(cursor)) throw new TypeError('invalid JSON number');
      } else {
        const firstCode = cursor < length
          ? apply(stringCharCodeAt, source[cursor], [0])
          : -1;
        if (firstCode < 0x31 || firstCode > 0x39) {
          throw new TypeError('invalid JSON number');
        }
        cursor += 1;
        while (isDigitAt(cursor)) cursor += 1;
      }
      if (source[cursor] === '.') {
        cursor += 1;
        if (!isDigitAt(cursor)) throw new TypeError('invalid JSON number');
        while (isDigitAt(cursor)) cursor += 1;
      }
      if (source[cursor] === 'e' || source[cursor] === 'E') {
        cursor += 1;
        if (source[cursor] === '+' || source[cursor] === '-') cursor += 1;
        if (!isDigitAt(cursor)) throw new TypeError('invalid JSON number');
        while (isDigitAt(cursor)) cursor += 1;
      }
      index = cursor;
    }

    function finishValue() {
      if (depth === 0) {
        rootComplete = true;
        return;
      }
      const parent = frames[depth - 1];
      if (parent.kind === 'object') {
        if (parent.phase !== 'value') throw new TypeError('invalid JSON object');
      } else if (parent.phase !== 'value' && parent.phase !== 'valueOrEnd') {
        throw new TypeError('invalid JSON array');
      }
      parent.phase = 'afterValue';
    }

    function pushFrame(kind) {
      if (depth >= LOCKFILE_JSON_MAX_NESTING) {
        throw new TypeError('JSON nesting budget exceeded');
      }
      frames[depth] = kind === 'object'
        ? { kind, phase: 'keyOrEnd', keys: new NativeSet() }
        : { kind, phase: 'valueOrEnd' };
      depth += 1;
    }

    function closeFrame(expectedKind) {
      const frame = frames[depth - 1];
      if (frame === undefined || frame.kind !== expectedKind) {
        throw new TypeError('invalid JSON container');
      }
      depth -= 1;
      frames[depth] = null;
      index += 1;
      finishValue();
    }

    function scanValue() {
      consumeToken();
      const character = source[index];
      if (character === '{') {
        index += 1;
        pushFrame('object');
        return;
      }
      if (character === '[') {
        index += 1;
        pushFrame('array');
        return;
      }
      if (character === '"') {
        scanString(false);
        finishValue();
        return;
      }
      if (stringStartsWithOwn(source, 'true', index)) {
        index += 4;
        finishValue();
        return;
      }
      if (stringStartsWithOwn(source, 'false', index)) {
        index += 5;
        finishValue();
        return;
      }
      if (stringStartsWithOwn(source, 'null', index)) {
        index += 4;
        finishValue();
        return;
      }
      scanNumber();
      finishValue();
    }

    while (!rootComplete) {
      skipWhitespace();
      if (depth === 0) {
        scanValue();
        continue;
      }
      const frame = frames[depth - 1];
      if (frame.kind === 'object') {
        if (frame.phase === 'keyOrEnd' || frame.phase === 'key') {
          if (source[index] === '}' && frame.phase === 'keyOrEnd') {
            closeFrame('object');
            continue;
          }
          consumeToken();
          const key = scanString(true);
          if (setHasOwn(frame.keys, key)) throw new TypeError('duplicate JSON key');
          apply(setAdd, frame.keys, [key]);
          frame.phase = 'colon';
          continue;
        }
        if (frame.phase === 'colon') {
          if (source[index] !== ':') throw new TypeError('invalid JSON object');
          index += 1;
          frame.phase = 'value';
          continue;
        }
        if (frame.phase === 'value') {
          scanValue();
          continue;
        }
        if (source[index] === '}') {
          closeFrame('object');
          continue;
        }
        if (source[index] !== ',') throw new TypeError('invalid JSON object');
        index += 1;
        frame.phase = 'key';
        continue;
      }

      if (frame.phase === 'valueOrEnd' || frame.phase === 'value') {
        if (source[index] === ']' && frame.phase === 'valueOrEnd') {
          closeFrame('array');
          continue;
        }
        scanValue();
        continue;
      }
      if (source[index] === ']') {
        closeFrame('array');
        continue;
      }
      if (source[index] !== ',') throw new TypeError('invalid JSON array');
      index += 1;
      frame.phase = 'value';
    }

    skipWhitespace();
    if (index !== length || depth !== 0) return null;
    return apply(jsonParse, JSON, [source]);
  } catch {
    return null;
  }
}

function ordinaryJsonObject(value) {
  return value !== null
    && typeof value === 'object'
    && !arrayIsArray(value)
    && apply(objectGetPrototypeOf, Object, [value]) === ObjectPrototype;
}

function ownJsonField(value, key) {
  const descriptor = apply(objectGetOwnPropertyDescriptor, Object, [value, key]);
  if (descriptor === undefined) return { present: false, value: undefined };
  if (
    descriptor.enumerable !== true
    || !apply(objectHasOwn, undefined, [descriptor, 'value'])
  ) return null;
  return { present: true, value: descriptor.value };
}

function validLockfilePackagePath(value) {
  return safeRepositoryPath(value) && stringStartsWithOwn(value, 'node_modules/');
}

function ownStringElement(value, index) {
  const descriptor = apply(objectGetOwnPropertyDescriptor, Object, [value, index]);
  if (
    descriptor === undefined
    || descriptor.enumerable !== true
    || !apply(objectHasOwn, undefined, [descriptor, 'value'])
    || typeof descriptor.value !== 'string'
  ) return null;
  return descriptor.value;
}

function validRegistryNameSegment(value) {
  return apply(regexpExec, /^[a-z0-9][a-z0-9._~-]*$/u, [value]) !== null;
}

function validRegistryVersion(value) {
  return typeof value === 'string'
    && apply(
      regexpExec,
      /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u,
      [value],
    ) !== null;
}

function validRegistryTarballPath(pathname, version) {
  if (
    typeof pathname !== 'string'
    || !validRegistryVersion(version)
    || stringIncludesOwn(pathname, '%')
    || stringIncludesOwn(pathname, '\\')
  ) return false;
  const segments = stringSplitOwn(pathname, '/');
  const length = ownArrayLength(segments);
  if (length !== 4 && length !== 5) return false;
  const root = ownStringElement(segments, 0);
  const first = ownStringElement(segments, 1);
  if (root !== '' || first === null) return false;

  let packageName;
  let separator;
  let tarballName;
  if (length === 4) {
    packageName = first;
    separator = ownStringElement(segments, 2);
    tarballName = ownStringElement(segments, 3);
  } else {
    const scope = first;
    packageName = ownStringElement(segments, 2);
    separator = ownStringElement(segments, 3);
    tarballName = ownStringElement(segments, 4);
    if (
      !stringStartsWithOwn(scope, '@')
      || !validRegistryNameSegment(stringSliceOwn(scope, 1))
    ) return false;
  }
  return packageName !== null
    && tarballName !== null
    && validRegistryNameSegment(packageName)
    && separator === '-'
    && tarballName === `${packageName}-${version}.tgz`;
}

function validResolvedUrl(value, version) {
  if (
    typeof value !== 'string'
    || !stringStartsWithOwn(value, 'https://registry.npmjs.org/')
  ) return false;
  try {
    const parsed = new NativeURL(value);
    return apply(urlGetProtocol, parsed, []) === 'https:'
      && apply(urlGetHostname, parsed, []) === 'registry.npmjs.org'
      && apply(urlGetOrigin, parsed, []) === 'https://registry.npmjs.org'
      && apply(urlGetPort, parsed, []) === ''
      && apply(urlGetUsername, parsed, []) === ''
      && apply(urlGetPassword, parsed, []) === ''
      && apply(urlGetSearch, parsed, []) === ''
      && apply(urlGetHash, parsed, []) === ''
      && apply(urlGetHref, parsed, []) === value
      && validRegistryTarballPath(apply(urlGetPathname, parsed, []), version);
  } catch {
    return false;
  }
}

function validSha512Integrity(value) {
  if (typeof value !== 'string') return false;
  const match = apply(regexpExec, /^sha512-([A-Za-z0-9+/]{86}==)$/u, [value]);
  if (match === null) return false;
  const finalSextet = apply(
    stringIndexOf,
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    [match[1][85]],
  );
  return finalSextet >= 0 && finalSextet % 16 === 0;
}

function validateExternalPackageRecord(record) {
  if (!ordinaryJsonObject(record)) return false;
  const link = ownJsonField(record, 'link');
  const version = ownJsonField(record, 'version');
  const resolved = ownJsonField(record, 'resolved');
  const integrity = ownJsonField(record, 'integrity');
  return link !== null
    && version !== null
    && resolved !== null
    && integrity !== null
    && !link.present
    && version.present
    && resolved.present
    && integrity.present
    && validResolvedUrl(resolved.value, version.value)
    && validSha512Integrity(integrity.value);
}

function validateRootPackageRecord(record) {
  if (!ordinaryJsonObject(record)) return false;
  const link = ownJsonField(record, 'link');
  const version = ownJsonField(record, 'version');
  const resolved = ownJsonField(record, 'resolved');
  const integrity = ownJsonField(record, 'integrity');
  if (
    link === null
    || version === null
    || resolved === null
    || integrity === null
    || link.present
  ) return false;
  if (!resolved.present && !integrity.present) return true;
  return version.present
    && resolved.present
    && integrity.present
    && validResolvedUrl(resolved.value, version.value)
    && validSha512Integrity(integrity.value);
}

function validateLockfileBytes(bytes) {
  try {
    if (typedArrayByteLength(bytes) > LOCKFILE_BYTE_LIMIT) return false;
    const parsed = strictJsonParse(decodeUtf8(retainedByteView(bytes)));
    if (!ordinaryJsonObject(parsed)) return false;
    const version = ownJsonField(parsed, 'lockfileVersion');
    const packagesField = ownJsonField(parsed, 'packages');
    if (
      version === null
      || packagesField === null
      || !version.present
      || version.value !== 3
      || !packagesField.present
      || !ordinaryJsonObject(packagesField.value)
    ) return false;
    const packages = packagesField.value;
    const packageKeys = reflectOwnKeys(packages);
    const foldedKeys = new NativeSet();
    let rootSeen = false;
    for (let index = 0; index < packageKeys.length; index += 1) {
      const key = packageKeys[index];
      if (typeof key !== 'string') return false;
      const folded = stringToLowerCaseOwn(key);
      if (setHasOwn(foldedKeys, folded)) return false;
      apply(setAdd, foldedKeys, [folded]);
      const record = ownJsonField(packages, key);
      if (record === null || !record.present) return false;
      if (key === '') {
        rootSeen = true;
        if (!validateRootPackageRecord(record.value)) return false;
      } else if (
        !validLockfilePackagePath(key)
        || !validateExternalPackageRecord(record.value)
      ) return false;
    }
    return rootSeen;
  } catch {
    return false;
  }
}

function parseBatch(bytes, requests, maximumBytes, lockfileObjectIds) {
  const buffer = retainedByteView(bytes);
  const bufferLength = typedArrayLength(buffer);
  const contents = new NativeMap();
  const validatedLockfileObjects = new NativeSet();
  let offset = 0;
  for (let index = 0; index < requests.length; index += 1) {
    const request = requests[index];
    const newline = indexOfByte(buffer, 0x0a, offset);
    if (newline < 0) return null;
    const headerBytes = retainedByteView(buffer, offset, newline);
    const header = decodeUtf8(headerBytes);
    const match = apply(regexpExec, /^([0-9a-f]{40,64}) blob ([0-9]+)$/u, [header]);
    if (match === null || match[1] !== request.objectId) return null;
    const size = apply(NativeNumber, undefined, [match[2]]);
    const isLockfileObject = setHasOwn(lockfileObjectIds, request.objectId);
    if (
      !apply(numberIsSafeInteger, NativeNumber, [size])
      || size < 0
      || size > maximumBytes
      || (isLockfileObject && size > LOCKFILE_BYTE_LIMIT)
    ) return null;
    const start = newline + 1;
    const end = start + size;
    if (end >= bufferLength || buffer[end] !== 0x0a) return null;
    const content = retainedByteView(buffer, start, end);
    if (isLockfileObject) {
      if (!validateLockfileBytes(content)) return null;
      apply(setAdd, validatedLockfileObjects, [request.objectId]);
    }
    mapSetOwn(contents, request.objectId, freeze({
      sizeBytes: size,
      contentDigest: sha256Retained(content),
    }));
    offset = end + 1;
  }
  return offset === bufferLength
    && apply(getSetSize, validatedLockfileObjects, []) === apply(getSetSize, lockfileObjectIds, [])
    ? contents
    : null;
}

function allZero(bytes) {
  const length = typedArrayByteLength(bytes);
  for (let index = 0; index < length; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return true;
}

function decodeTarText(bytes) {
  const length = typedArrayByteLength(bytes);
  let end = length;
  for (let index = 0; index < length; index += 1) {
    if (bytes[index] === 0) {
      end = index;
      break;
    }
  }
  if (!allZero(retainedByteView(bytes, end))) return null;
  try {
    const content = retainedByteView(bytes, 0, end);
    const text = decodeUtf8(content);
    return bytesEqual(encodeUtf8(text), content) ? text : null;
  } catch {
    return null;
  }
}

function parseTarOctal(bytes, checksum = false) {
  const byteLength = typedArrayByteLength(bytes);
  const digitLength = checksum
    ? (bytes[byteLength - 1] === 0
      ? byteLength - 1
      : (bytes[byteLength - 2] === 0 && bytes[byteLength - 1] === 0x20
        ? byteLength - 2
        : -1))
    : byteLength - 1;
  if (
    digitLength < 1
    || bytes[digitLength] !== 0
    || (checksum && digitLength === byteLength - 2 && bytes[digitLength + 1] !== 0x20)
  ) return null;
  for (let index = 0; index < digitLength; index += 1) {
    if (bytes[index] < 0x30 || bytes[index] > 0x37) return null;
  }
  const encoded = retainedByteView(bytes, 0, digitLength);
  const text = decodeUtf8(encoded);
  const value = apply(numberParseInt, NativeNumber, [text, 8]);
  return apply(numberIsSafeInteger, NativeNumber, [value]) && value >= 0 ? value : null;
}

function parseTarHeader(header) {
  const headerByteLength = typedArrayByteLength(header);
  if (headerByteLength !== 512 || allZero(header)) return null;
  const slice = (start, end) => retainedByteView(header, start, end);
  const storedChecksum = parseTarOctal(slice(148, 156), true);
  if (storedChecksum === null) return null;
  let computedChecksum = 0;
  for (let index = 0; index < headerByteLength; index += 1) {
    computedChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (storedChecksum !== computedChecksum) return null;
  const ustar = encodeUtf8('ustar\0');
  const version = encodeUtf8('00');
  if (
    !bytesEqual(slice(257, 263), ustar)
    || !bytesEqual(slice(263, 265), version)
    || !allZero(slice(157, 257))
    || !allZero(slice(500, 512))
  ) return null;
  const name = decodeTarText(slice(0, 100));
  const prefix = decodeTarText(slice(345, 500));
  const user = decodeTarText(slice(265, 297));
  const group = decodeTarText(slice(297, 329));
  const mode = parseTarOctal(slice(100, 108));
  const userId = parseTarOctal(slice(108, 116));
  const groupId = parseTarOctal(slice(116, 124));
  const size = parseTarOctal(slice(124, 136));
  const modifiedAt = parseTarOctal(slice(136, 148));
  const deviceMajor = parseTarOctal(slice(329, 337));
  const deviceMinor = parseTarOctal(slice(337, 345));
  if (
    name === null
    || name.length === 0
    || prefix === null
    || user !== 'root'
    || group !== 'root'
    || mode === null
    || userId !== 0
    || groupId !== 0
    || size === null
    || modifiedAt === null
    || deviceMajor !== 0
    || deviceMinor !== 0
  ) return null;
  return {
    path: prefix.length === 0 ? name : `${prefix}/${name}`,
    type: apply(stringFromCharCode, NativeString, [header[156]]),
    mode,
    size,
  };
}

function reconcileTarDirectories(tree, seenDirectories) {
  let previousParts = new NativeArray();
  let previousDirectoryCount = 0;
  const prefixPathByDepth = new NativeArray();
  for (let treeIndex = 0; treeIndex < tree.length; treeIndex += 1) {
    const repositoryPath = tree[treeIndex].path;
    const parts = stringSplitOwn(repositoryPath, '/');
    const directoryCount = parts.length - 1;
    let commonPrefixLength = 0;
    while (
      commonPrefixLength < previousDirectoryCount
      && commonPrefixLength < directoryCount
      && previousParts[commonPrefixLength] === parts[commonPrefixLength]
    ) commonPrefixLength += 1;

    prefixPathByDepth.length = commonPrefixLength;
    let prefix = commonPrefixLength === 0
      ? ''
      : prefixPathByDepth[commonPrefixLength - 1];
    for (let index = commonPrefixLength; index < directoryCount; index += 1) {
      prefix = prefix.length === 0 ? parts[index] : `${prefix}/${parts[index]}`;
      pushOwn(prefixPathByDepth, prefix);
      const directory = `${prefix}/`;
      if (!setHasOwn(seenDirectories, directory)) return false;
      apply(setDelete, seenDirectories, [directory]);
    }

    previousParts = parts;
    previousDirectoryCount = directoryCount;
  }
  return apply(getSetSize, seenDirectories, []) === 0;
}

function reconcileTarArchive(bytes, revision, tree, contents) {
  const buffer = retainedByteView(bytes);
  const bufferByteCount = typedArrayByteLength(buffer);
  if (bufferByteCount < 2048 || bufferByteCount % 512 !== 0) return false;
  const expectedFiles = new NativeMap();
  for (let index = 0; index < tree.length; index += 1) {
    mapSetOwn(expectedFiles, tree[index].path, tree[index]);
  }
  const seenFiles = new NativeSet();
  const seenDirectories = new NativeSet();
  const seenPaths = new NativeSet();
  const seenFoldedPaths = new NativeSet();
  let offset = 0;
  let firstRecord = true;

  while (offset < bufferByteCount) {
    const headerBytes = retainedByteView(buffer, offset, offset + 512);
    if (allZero(headerBytes)) {
      if (
        bufferByteCount - offset < 1024
        || !allZero(retainedByteView(buffer, offset))
      ) return false;
      return (
        !firstRecord
        && apply(getSetSize, seenFiles, []) === apply(getMapSize, expectedFiles, [])
        && reconcileTarDirectories(tree, seenDirectories)
      );
    }
    const header = parseTarHeader(headerBytes);
    if (header === null || header.size > bufferByteCount - offset - 512) return false;
    const contentStart = offset + 512;
    const contentEnd = contentStart + header.size;
    const paddedEnd = contentStart + apply(mathCeil, Math, [header.size / 512]) * 512;
    if (
      paddedEnd > bufferByteCount
      || !allZero(retainedByteView(buffer, contentEnd, paddedEnd))
    ) return false;
    const content = retainedByteView(buffer, contentStart, contentEnd);
    offset = paddedEnd;

    if (firstRecord) {
      firstRecord = false;
      const expectedPax = encodeUtf8(`52 comment=${revision}\n`);
      if (
        header.path !== 'pax_global_header'
        || header.type !== 'g'
        || header.mode !== 0o666
        || header.size !== typedArrayByteLength(expectedPax)
        || !bytesEqual(content, expectedPax)
      ) return false;
      continue;
    }

    const directory = header.type === '5';
    const regularFile = header.type === '0';
    if (!directory && !regularFile) return false;
    const hasTrailingSlash = stringEndsWithOwn(header.path, '/');
    const repositoryPath = directory && hasTrailingSlash
      ? stringSliceOwn(header.path, 0, -1)
      : header.path;
    const foldedPath = stringToLowerCaseOwn(repositoryPath);
    if (
      !safeRepositoryPath(repositoryPath)
      || (directory && !hasTrailingSlash)
      || (regularFile && hasTrailingSlash)
      || setHasOwn(seenPaths, repositoryPath)
      || setHasOwn(seenFoldedPaths, foldedPath)
    ) return false;
    apply(setAdd, seenPaths, [repositoryPath]);
    apply(setAdd, seenFoldedPaths, [foldedPath]);

    if (directory) {
      if (header.mode !== 0o775 || header.size !== 0) return false;
      apply(setAdd, seenDirectories, [header.path]);
      continue;
    }

    const expected = mapGetOwn(expectedFiles, header.path);
    const expectedContent = expected === undefined
      ? null
      : mapGetOwn(contents, expected.objectId);
    if (
      expected === undefined
      || expectedContent === undefined
      || header.mode !== (expected.mode === '100755' ? 0o775 : 0o664)
      || header.size !== expectedContent.sizeBytes
      || sha256Retained(content) !== expectedContent.contentDigest
    ) return false;
    apply(setAdd, seenFiles, [header.path]);
  }
  return false;
}

function treeDigest(revision, tree, contents) {
  const entries = new NativeArray(tree.length);
  for (let index = 0; index < tree.length; index += 1) {
    const entry = tree[index];
    entries[index] = {
      path: entry.path,
      mode: entry.mode,
      contentDigest: mapGetOwn(contents, entry.objectId).contentDigest,
    };
  }
  const canonical = apply(jsonStringify, JSON, [{
    schemaVersion: 'candidate-source-tree.v1',
    baseRef: revision,
    entries,
    statusRecords: [],
  }]);
  return sha256Retained(encodeUtf8(canonical));
}

function readPassEnvelope(candidate) {
  const envelope = exactOperationDataObject(candidate, ['diagnostics', 'status', 'value']);
  if (
    envelope === null
    || envelope.status !== 'PASS'
    || exactArray(envelope.diagnostics, 0) === null
  ) return null;
  return envelope;
}

function validNullPass(candidate) {
  return readPassEnvelope(candidate)?.value === null;
}

function normalizeTransportFailure(candidate) {
  const envelope = exactOperationDataObject(candidate, ['diagnostics', 'status', 'value']);
  const diagnostics = envelope === null ? null : exactArray(envelope.diagnostics, 1);
  if (
    envelope !== null
    && envelope.value === null
    && (envelope.status === 'BLOCKED' || envelope.status === 'FAIL')
    && diagnostics !== null
  ) {
    const diagnostic = exactOperationDataObject(diagnostics[0], ['code', 'retryable', 'safeMessage']);
    if (
      diagnostic !== null
      && diagnostic.retryable === false
      && typeof diagnostic.safeMessage === 'string'
    ) {
      if (diagnostic.code === 'ARTIFACT_BUILD_FAILED') return failed('ARTIFACT_BUILD_FAILED');
      if (diagnostic.code === 'ARTIFACT_NETWORK_POLICY_UNAVAILABLE') {
        return blocked('ARTIFACT_NETWORK_POLICY_UNAVAILABLE');
      }
    }
  }
  return blocked('ARTIFACT_NETWORK_POLICY_UNAVAILABLE');
}

function resolvedPromise(value) {
  return new NativePromise((resolve) => resolve(value));
}

function lifecycleSignal(lifecycle) {
  return apply(getAbortSignal, lifecycle.controller, []);
}

function signalAborted(signal) {
  return apply(getSignalAborted, signal, []);
}

function createDeferred() {
  let resolve;
  const promise = new NativePromise((settle) => { resolve = settle; });
  return closedRecord({ promise, resolve });
}

function scheduleNotice(milliseconds, notify) {
  let handle;
  try {
    handle = apply(scheduleTimeout, globalThis, [notify, milliseconds]);
  } catch {
    notify();
  }
  return () => {
    if (handle !== undefined) apply(cancelTimeout, globalThis, [handle]);
  };
}

function observeAbort(signal, notify) {
  if (signalAborted(signal)) {
    notify();
    return () => {};
  }
  let active = true;
  const listener = () => {
    if (!active) return;
    active = false;
    notify();
  };
  try {
    apply(addEventListener, signal, ['abort', listener, { once: true }]);
  } catch {
    active = false;
    notify();
  }
  return () => {
    if (!active) return;
    active = false;
    apply(removeEventListener, signal, ['abort', listener]);
  };
}

async function invokeBounded(lifecycle, operation) {
  const signal = lifecycleSignal(lifecycle);
  if (signalAborted(signal)) {
    return closedRecord({ state: 'aborted', outcome: null });
  }

  const first = createDeferred();
  const activeToken = objectCreate(null);
  let firstKind = null;
  let operationSettled = false;
  let operationOutcome = null;
  let quiescenceNotify = null;
  const settleFirst = (kind) => {
    if (firstKind !== null) return;
    firstKind = kind;
    first.resolve(kind);
  };
  const settleOperation = (outcome) => {
    if (operationSettled) return;
    operationSettled = true;
    operationOutcome = outcome;
    apply(setDelete, lifecycle.activeOperations, [activeToken]);
    settleFirst('operation');
    if (quiescenceNotify !== null) quiescenceNotify();
    const notifyLifecycle = lifecycle.onQuiescent;
    if (typeof notifyLifecycle === 'function') {
      try { notifyLifecycle(); } catch { /* lifecycle notifications fail closed at their caller */ }
    }
  };

  apply(setAdd, lifecycle.activeOperations, [activeToken]);
  void (async () => {
    try {
      const observation = await observeTrustedOperation(operation());
      settleOperation(observation.fulfilled === true
        ? closedRecord({ kind: 'fulfilled', value: observation.value })
        : closedRecord({ kind: 'rejected', value: null }));
    } catch {
      settleOperation(closedRecord({ kind: 'rejected', value: null }));
    }
  })();

  const cancelDeadline = scheduleNotice(
    OPERATION_DEADLINE_MS,
    () => settleFirst('deadline'),
  );
  const cancelAbortNotice = observeAbort(signal, () => settleFirst('abort'));
  await first.promise;
  cancelDeadline();
  cancelAbortNotice();

  if (firstKind === 'operation') {
    return closedRecord({ state: 'settled', outcome: operationOutcome });
  }
  if (firstKind === 'deadline') {
    try { apply(abortControllerAbort, lifecycle.controller, []); } catch { /* fail closed below */ }
  }
  if (operationSettled) {
    return closedRecord({ state: firstKind, outcome: operationOutcome });
  }

  const grace = createDeferred();
  let graceKind = null;
  const settleGrace = (kind) => {
    if (graceKind !== null) return;
    graceKind = kind;
    grace.resolve(kind);
  };
  quiescenceNotify = () => settleGrace('settled');
  const cancelGrace = scheduleNotice(
    QUIESCENCE_GRACE_MS,
    () => settleGrace('grace-expired'),
  );
  if (operationSettled) settleGrace('settled');
  await grace.promise;
  cancelGrace();
  quiescenceNotify = null;
  if (graceKind === 'grace-expired') {
    return closedRecord({ state: 'unquiescent', outcome: null });
  }
  return closedRecord({ state: firstKind, outcome: operationOutcome });
}

function createProcessSpec({ gitExecutable, sourceCheckoutRoot, args, stdin, stdoutLimitBytes, stderrLimitBytes }) {
  return closedRecord({
    executable: gitExecutable,
    args: frozenPrototypeFreeGitArgv(
      FIXED_PREFIX,
      `safe.directory=${sourceCheckoutRoot}`,
      args,
    ),
    cwd: sourceCheckoutRoot,
    env: GIT_ENVIRONMENT,
    shell: false,
    timeoutMs: 600_000,
    retry: false,
    network: 'deny',
    stdin,
    stdoutLimitBytes,
    stderrLimitBytes,
  });
}

async function runFixedGit(state, args, { stdin = null, stdoutLimitBytes, consumeStdout = false }) {
  const spec = createProcessSpec({
    gitExecutable: state.gitExecutable,
    sourceCheckoutRoot: state.sourceCheckoutRoot,
    args,
    stdin,
    stdoutLimitBytes,
    stderrLimitBytes: state.limits.stderrBytes,
  });
  const invocation = await invokeBounded(
    state.lifecycle,
    () => apply(
      state.processTransport.run,
      state.processTransport.receiver,
      [spec, lifecycleSignal(state.lifecycle)],
    ),
  );
  if (invocation.state === 'unquiescent') {
    return closedRecord({ error: blocked('ARTIFACT_CLEANUP_INCOMPLETE') });
  }
  if (invocation.state !== 'settled') return closedRecord({ error: failed('ARTIFACT_BUILD_FAILED') });
  if (invocation.outcome.kind === 'rejected') {
    return closedRecord({ error: blocked('ARTIFACT_NETWORK_POLICY_UNAVAILABLE') });
  }
  const candidate = invocation.outcome.value;
  const envelope = readPassEnvelope(candidate);
  if (envelope === null) return closedRecord({ error: normalizeTransportFailure(candidate) });
  const value = exactOperationDataObject(envelope.value, ['exitCode', 'stderr', 'stdout', 'timedOut']);
  if (value === null || value.exitCode !== 0 || value.timedOut !== false) {
    return closedRecord({ error: failed('ARTIFACT_BUILD_FAILED') });
  }
  const stderr = snapshotBytes(value.stderr, state.limits.stderrBytes);
  if (stderr === null) return closedRecord({ error: failed('ARTIFACT_BUILD_FAILED') });
  const stdout = consumeStdout
    ? takeOwnedBytes(value.stdout, stdoutLimitBytes)
    : snapshotBytes(value.stdout, stdoutLimitBytes);
  if (stdout === null) return closedRecord({ error: failed('ARTIFACT_BUILD_FAILED') });
  return closedRecord({ stdout });
}

async function readAuthenticatedBatchContents(state, requests, stdin, lockfileObjectIds) {
  const batchResult = await runFixedGit(state, ['cat-file', '--batch'], {
    stdin,
    stdoutLimitBytes: state.limits.sourceGitArchiveBytes,
  });
  if (batchResult.error) return batchResult;

  let batchStdout = batchResult.stdout;
  let contents = null;
  try {
    contents = parseBatch(
      batchStdout,
      requests,
      state.limits.sourceGitArchiveBytes,
      lockfileObjectIds,
    );
  } catch {
    contents = null;
  } finally {
    try {
      apply(fillBytes, batchStdout, [0]);
    } finally {
      batchStdout = null;
    }
  }
  return contents === null
    ? closedRecord({ error: blocked('ARTIFACT_PATH_UNSAFE') })
    : closedRecord({ contents });
}

function createSnapshotLease(state, identity, archiveBytes) {
  let filesystemCapability = state.filesystem;
  let lifecycle = state.lifecycle;
  let exported = false;
  let exportActive = false;
  let exportFinished = false;
  let closed = false;
  let closePromise = null;
  let closeResult = null;
  let closeQuiescenceNotify = null;
  let cleanupPoisoned = false;
  let activeRollbackController = null;
  let privateArchive = archiveBytes;

  function activeOperationCount() {
    return lifecycle === null
      ? 0
      : apply(getSetSize, lifecycle.activeOperations, []);
  }

  function releaseSafeReferences() {
    if (
      privateArchive !== null
      || exportActive
      || activeOperationCount() !== 0
    ) return;
    activeRollbackController = null;
    if (lifecycle !== null) lifecycle.onQuiescent = null;
    filesystemCapability = null;
    lifecycle = null;
    closeQuiescenceNotify = null;
  }

  function wipeIfSafe() {
    if (
      privateArchive !== null
      && activeOperationCount() === 0
      && (closed || exportFinished)
    ) {
      apply(fillBytes, privateArchive, [0]);
      privateArchive = null;
    }
    releaseSafeReferences();
  }

  function notifyQuiescence() {
    if (activeOperationCount() === 0) activeRollbackController = null;
    wipeIfSafe();
    if (closeQuiescenceNotify !== null && activeOperationCount() === 0) {
      closeQuiescenceNotify();
    }
  }
  lifecycle.onQuiescent = notifyQuiescence;

  function waitForQuiescence(milliseconds) {
    if (activeOperationCount() === 0) return resolvedPromise('quiescent');
    const deferred = createDeferred();
    let settled = false;
    let cancelGrace = () => {};
    const settle = (kind) => {
      if (settled) return;
      settled = true;
      closeQuiescenceNotify = null;
      cancelGrace();
      deferred.resolve(kind);
    };
    closeQuiescenceNotify = () => {
      if (activeOperationCount() === 0) settle('quiescent');
    };
    cancelGrace = scheduleNotice(milliseconds, () => settle('grace-expired'));
    if (activeOperationCount() === 0) closeQuiescenceNotify();
    return deferred.promise;
  }

  async function invokeFilesystem(methodName, args) {
    const currentFilesystem = filesystemCapability;
    const currentLifecycle = lifecycle;
    if (currentFilesystem === null || currentLifecycle === null) {
      return closedRecord({ state: 'aborted', outcome: null });
    }
    const callArgs = new NativeArray(args.length + 1);
    for (let index = 0; index < args.length; index += 1) callArgs[index] = args[index];
    callArgs[args.length] = lifecycleSignal(currentLifecycle);
    return invokeBounded(
      currentLifecycle,
      () => apply(
        currentFilesystem[methodName],
        currentFilesystem.receiver,
        callArgs,
      ),
    );
  }

  async function rollback(destinationRootHandle) {
    const currentFilesystem = filesystemCapability;
    const currentLifecycle = lifecycle;
    if (currentFilesystem === null || currentLifecycle === null) {
      return closedRecord({ state: 'aborted', outcome: null });
    }
    const rollbackController = new NativeAbortController();
    activeRollbackController = rollbackController;
    const rollbackLifecycle = {
      controller: rollbackController,
      activeOperations: currentLifecycle.activeOperations,
      onQuiescent: currentLifecycle.onQuiescent,
    };
    const invocation = await invokeBounded(
      rollbackLifecycle,
      () => apply(
        currentFilesystem.rollbackExport,
        currentFilesystem.receiver,
        [destinationRootHandle, lifecycleSignal(rollbackLifecycle)],
      ),
    );
    if (
      invocation.state !== 'unquiescent'
      && activeRollbackController === rollbackController
    ) activeRollbackController = null;
    return invocation;
  }

  async function failedExport(destinationRootHandle) {
    if (closed) return blocked('ARTIFACT_CLEANUP_INCOMPLETE');
    const rollbackInvocation = await rollback(destinationRootHandle);
    if (rollbackInvocation.state === 'unquiescent') {
      cleanupPoisoned = true;
      return blocked('ARTIFACT_CLEANUP_INCOMPLETE');
    }
    const rolledBack = (
      rollbackInvocation.state === 'settled'
      && rollbackInvocation.outcome.kind === 'fulfilled'
      && validNullPass(rollbackInvocation.outcome.value)
    );
    if (!rolledBack) cleanupPoisoned = true;
    return rolledBack
      ? blocked('ARTIFACT_PATH_UNSAFE')
      : blocked('ARTIFACT_CLEANUP_INCOMPLETE');
  }

  function unquiescentExport() {
    cleanupPoisoned = true;
    return blocked('ARTIFACT_CLEANUP_INCOMPLETE');
  }

  function exportSnapshot(destinationRootHandle) {
    if (closed || exported || privateArchive === null) {
      return resolvedPromise(blocked('ARTIFACT_SCHEMA_INVALID'));
    }
    exported = true;
    exportActive = true;
    const archiveForExport = privateArchive;
    const options = closedRecord({
      sourceRevision: identity.sourceRevision,
      sourceTreeDigest: identity.sourceTreeDigest,
      verifierManifestDigest: identity.verifierManifestDigest,
    });
    const exportPromise = (async () => {
      try {
        const exportedInvocation = await invokeFilesystem(
          'exportArchive',
          [destinationRootHandle, archiveForExport, options],
        );
        if (exportedInvocation.state === 'unquiescent') return unquiescentExport();
        if (
          exportedInvocation.state !== 'settled'
          || exportedInvocation.outcome.kind !== 'fulfilled'
        ) return failedExport(destinationRootHandle);
        if (!validNullPass(exportedInvocation.outcome.value)) {
          return failedExport(destinationRootHandle);
        }
        if (
          closed
          || lifecycle === null
          || signalAborted(lifecycleSignal(lifecycle))
        ) return failedExport(destinationRootHandle);
        const immutableInvocation = await invokeFilesystem(
          'makeImmutable',
          [destinationRootHandle],
        );
        if (immutableInvocation.state === 'unquiescent') return unquiescentExport();
        if (
          immutableInvocation.state !== 'settled'
          || immutableInvocation.outcome.kind !== 'fulfilled'
        ) return failedExport(destinationRootHandle);
        if (!validNullPass(immutableInvocation.outcome.value)) {
          return failedExport(destinationRootHandle);
        }
        if (
          closed
          || lifecycle === null
          || signalAborted(lifecycleSignal(lifecycle))
        ) return failedExport(destinationRootHandle);
        return pass(null);
      } catch {
        return failedExport(destinationRootHandle);
      } finally {
        exportFinished = true;
        exportActive = false;
        wipeIfSafe();
      }
    })();
    return exportPromise;
  }

  function close() {
    if (closePromise !== null) return closePromise;
    const interrupted = exportActive || activeOperationCount() !== 0;
    closed = true;
    if (lifecycle !== null) apply(abortControllerAbort, lifecycle.controller, []);
    if (activeRollbackController !== null) {
      apply(abortControllerAbort, activeRollbackController, []);
    }
    closePromise = (async () => {
      if (cleanupPoisoned) {
        closeResult = blocked('ARTIFACT_CLEANUP_INCOMPLETE');
        return closeResult;
      }
      if (interrupted && activeOperationCount() !== 0) {
        const waited = await waitForQuiescence(QUIESCENCE_GRACE_MS);
        if (waited === 'grace-expired' || activeOperationCount() !== 0) {
          closeResult = blocked('ARTIFACT_CLEANUP_INCOMPLETE');
          return closeResult;
        }
      }
      wipeIfSafe();
      closeResult = interrupted
        ? blocked('ARTIFACT_CLEANUP_INCOMPLETE')
        : pass(null);
      return closeResult;
    })();
    return closePromise;
  }

  return freeze({
    identity,
    exportSnapshot,
    close,
  });
}

export function createTrustedSourceSnapshotHost(args) {
  if (!isTrustedPromiseBootstrapReady()) return BOOTSTRAP_UNAVAILABLE_HOST;
  const input = exactDataObject(args, CONSTRUCTOR_KEYS);
  if (input === null) throw new TypeError('Trusted source host configuration is invalid.');
  const processTransport = exactCapability(input.processTransport, ['run']);
  const filesystem = exactCapability(input.filesystem, [
    'exportArchive',
    'makeImmutable',
    'rollbackExport',
  ]);
  const limits = exactLimits(input.limits);
  if (
    processTransport === null
    || filesystem === null
    || limits === null
    || !canonicalAbsolutePosixPath(input.gitExecutable, limits.canonicalAbsolutePathBytes)
  ) throw new TypeError('Trusted source host configuration is invalid.');
  const sourceLeaseIssuer = captureSourceArtifactSourceLeaseIssuer(input.sourceLeaseIssuer);
  if (sourceLeaseIssuer === null) {
    throw new TypeError('Trusted source host configuration is invalid.');
  }

  const baseState = freeze({
    gitExecutable: input.gitExecutable,
    processTransport,
    filesystem,
    limits,
    sourceLeaseIssuer,
  });

  async function openSnapshot(request) {
    const inputRequest = exactDataObject(request, SOURCE_REQUEST_KEYS);
    if (
      inputRequest === null
      || !apply(objectIsFrozen, Object, [request])
      || !canonicalAbsolutePosixPath(
        inputRequest.sourceCheckoutRoot,
        limits.canonicalAbsolutePathBytes,
      )
      || typeof inputRequest.sourceRevision !== 'string'
      || apply(regexpExec, FULL_REVISION, [inputRequest.sourceRevision]) === null
      || typeof inputRequest.sourceTreeDigest !== 'string'
      || apply(regexpExec, DIGEST, [inputRequest.sourceTreeDigest]) === null
    ) return blocked('ARTIFACT_SCHEMA_INVALID');

    const lifecycle = {
      controller: new NativeAbortController(),
      activeOperations: new NativeSet(),
      onQuiescent: null,
    };
    const state = freeze({
      ...baseState,
      sourceCheckoutRoot: inputRequest.sourceCheckoutRoot,
      lifecycle,
    });
    const resolvedResult = await runFixedGit(state, [
      'rev-parse',
      '--verify',
      '--quiet',
      `${inputRequest.sourceRevision}^{commit}`,
    ], { stdoutLimitBytes: limits.stdoutBytes });
    if (resolvedResult.error) return resolvedResult.error;
    const resolvedRevision = parseResolvedRevision(resolvedResult.stdout);
    if (resolvedRevision !== inputRequest.sourceRevision) return blocked('ARTIFACT_PATH_UNSAFE');

    const treeResult = await runFixedGit(state, [
      'ls-tree',
      '-r',
      '-z',
      '--full-tree',
      inputRequest.sourceRevision,
    ], { stdoutLimitBytes: limits.stdoutBytes });
    if (treeResult.error) return treeResult.error;
    const parsedTree = parseTree(treeResult.stdout);
    if (parsedTree === null) return blocked('ARTIFACT_PATH_UNSAFE');
    const { authenticatedTree, candidateTree } = parsedTree;
    const lockfileObjectIds = findLockfileObjectIds(authenticatedTree);
    if (lockfileObjectIds === null) return blocked('ARTIFACT_PATH_UNSAFE');

    const requestByObjectId = new NativeMap();
    const requests = new NativeArray();
    for (let index = 0; index < authenticatedTree.length; index += 1) {
      const objectId = authenticatedTree[index].objectId;
      if (!mapHasOwn(requestByObjectId, objectId)) {
        const request = { objectId };
        mapSetOwn(requestByObjectId, objectId, request);
        pushOwn(requests, request);
      }
    }
    sortOwn(requests, (left, right) => ordinalCompare(left.objectId, right.objectId));
    let objectIds = '';
    for (let index = 0; index < requests.length; index += 1) {
      objectIds += `${requests[index].objectId}\n`;
    }
    const stdin = encodeUtf8(objectIds);
    const batchContentsResult = await readAuthenticatedBatchContents(
      state,
      requests,
      stdin,
      lockfileObjectIds,
    );
    if (batchContentsResult.error) return batchContentsResult.error;
    const { contents } = batchContentsResult;
    const computedTreeDigest = treeDigest(
      inputRequest.sourceRevision,
      candidateTree,
      contents,
    );
    if (computedTreeDigest !== inputRequest.sourceTreeDigest) return blocked('ARTIFACT_PATH_UNSAFE');

    const manifestResult = await runFixedGit(state, [
      'show',
      `${inputRequest.sourceRevision}:${MANIFEST_PATH}`,
    ], { stdoutLimitBytes: limits.verifierManifestBytes });
    if (manifestResult.error) return manifestResult.error;
    if (typedArrayByteLength(manifestResult.stdout) === 0) {
      return blocked('ARTIFACT_PATH_UNSAFE');
    }
    const verifierManifestDigest = sha256Retained(manifestResult.stdout);

    const archiveResult = await runFixedGit(state, [
      'archive',
      '--format=tar',
      inputRequest.sourceRevision,
    ], {
      stdoutLimitBytes: limits.sourceGitArchiveBytes,
      consumeStdout: true,
    });
    if (archiveResult.error) return archiveResult.error;
    let archiveMatches = false;
    try {
      archiveMatches = reconcileTarArchive(
        archiveResult.stdout,
        inputRequest.sourceRevision,
        authenticatedTree,
        contents,
      );
    } catch {
      archiveMatches = false;
    }
    if (!archiveMatches) {
      apply(fillBytes, archiveResult.stdout, [0]);
      return blocked('ARTIFACT_PATH_UNSAFE');
    }

    const identity = freeze({
      sourceRevision: inputRequest.sourceRevision,
      sourceTreeDigest: computedTreeDigest,
      verifierManifestDigest,
    });
    const sourceLease = createSnapshotLease(state, identity, archiveResult.stdout);
    const registered = state.sourceLeaseIssuer.issueSourceLease(sourceLease);
    if (registered === null) {
      const closed = await sourceLease.close();
      return validNullPass(closed)
        ? blocked('ARTIFACT_SCHEMA_INVALID')
        : blocked('ARTIFACT_CLEANUP_INCOMPLETE');
    }
    return pass(registered);
  }

  return freeze({ openSnapshot });
}
