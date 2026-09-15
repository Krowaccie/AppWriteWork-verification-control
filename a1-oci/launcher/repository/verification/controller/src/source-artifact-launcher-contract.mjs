import path from 'node:path';
import { types as utilTypes } from 'node:util';

const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const NativeArray = Array;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const bufferByteLength = Buffer.byteLength;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const regexpExec = RegExp.prototype.exec;
const setHas = Set.prototype.has;
const stringEndsWith = String.prototype.endsWith;
const stringIncludes = String.prototype.includes;
const textDecoderDecode = TextDecoder.prototype.decode;
const textEncoderEncode = TextEncoder.prototype.encode;
const uint8ArraySet = Uint8Array.prototype.set;
const PathPosix = path.posix;
const PathWin32 = path.win32;
const pathPosixIsAbsolute = PathPosix.isAbsolute;
const pathPosixNormalize = PathPosix.normalize;
const pathWin32IsAbsolute = PathWin32.isAbsolute;
const pathWin32Normalize = PathWin32.normalize;
const isProxy = utilTypes.isProxy;
const isSharedArrayBuffer = utilTypes.isSharedArrayBuffer;
const isUint8Array = utilTypes.isUint8Array;
const NativeBuffer = Buffer;
const NativeUint8Array = Uint8Array;
const ObjectPrototype = Object.prototype;
const BufferPrototype = NativeBuffer.prototype;
const Uint8ArrayPrototype = NativeUint8Array.prototype;

export const SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION = 'source-artifact-launcher.v1';
export const SOURCE_ARTIFACT_COMMAND_IDS = Object.freeze([
  'root-npm-ci',
  'web-npm-ci',
  'bundle-catalog',
  'typecheck',
  'vite-build',
]);

const REQUEST_MAX_BYTES = 128;
const PUBLICATION_MAX_BYTES = 8 * 1024;
const ABSOLUTE_PATH_MAX_BYTES = 4 * 1024;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const ARTIFACT_NAME_PATTERN = /^verification-artifacts-([0-9a-f]{40})$/u;
const REQUEST_KEYS = Object.freeze(['commandId', 'protocolVersion']);
const PUBLICATION_KEYS = Object.freeze([
  'artifactManifestDigest',
  'artifactName',
  'artifactPath',
]);
const COMMAND_SET = new Set(SOURCE_ARTIFACT_COMMAND_IDS);
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const typedArrayPrototype = objectGetPrototypeOf(Uint8ArrayPrototype);
const getByteLength = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const getByteOffset = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const getBuffer = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const getArrayBufferByteLength = objectGetOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const getResizable = objectGetOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;

const INVALID = Object.freeze({
  status: 'BLOCKED',
  value: null,
  diagnostics: Object.freeze([Object.freeze({
    code: 'ARTIFACT_SCHEMA_INVALID',
    safeMessage: 'Source artifact launcher data does not match the closed contract.',
    retryable: false,
  })]),
});

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortOrdinally(values) {
  return reflectApply(arraySort, values, [ordinalCompare]);
}

function hasOwn(value, key) {
  return reflectApply(objectHasOwn, undefined, [value, key]);
}

function copyArray(values) {
  const copy = new NativeArray(values.length);
  for (let index = 0; index < values.length; index += 1) {
    copy[index] = values[index];
  }
  return copy;
}

function exactPlainDataObject(value, expectedKeys) {
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
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function snapshotBytePayload(value, maximumBytes) {
  try {
    if (isProxy(value) || !isUint8Array(value)) return null;
    const prototype = objectGetPrototypeOf(value);
    if (prototype !== Uint8ArrayPrototype && prototype !== BufferPrototype) return null;
    const byteLength = reflectApply(getByteLength, value, []);
    const byteOffset = reflectApply(getByteOffset, value, []);
    if (!numberIsSafeInteger(byteLength) || byteLength < 1 || byteLength > maximumBytes) return null;
    if (!numberIsSafeInteger(byteOffset) || byteOffset < 0) return null;
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

function sameBytes(left, right) {
  const leftLength = reflectApply(getByteLength, left, []);
  const rightLength = reflectApply(getByteLength, right, []);
  if (leftLength !== rightLength) return false;
  for (let index = 0; index < leftLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function parseJsonBytes(value, maximumBytes) {
  const copy = snapshotBytePayload(value, maximumBytes);
  if (copy === null) return null;
  try {
    const text = reflectApply(textDecoderDecode, decoder, [copy]);
    return {
      bytes: copy,
      value: reflectApply(jsonParse, undefined, [text]),
    };
  } catch {
    return null;
  }
}

function jsonString(value) {
  return reflectApply(jsonStringify, undefined, [value]);
}

function canonicalRequestText(value) {
  return `{"commandId":${jsonString(value.commandId)},"protocolVersion":${jsonString(value.protocolVersion)}}`;
}

function canonicalPublicationText(value) {
  return `{"artifactManifestDigest":${jsonString(value.artifactManifestDigest)},"artifactName":${jsonString(value.artifactName)},"artifactPath":${jsonString(value.artifactPath)}}`;
}

function hasCanonicalBytes(bytes, text) {
  try {
    return sameBytes(
      bytes,
      reflectApply(textEncoderEncode, encoder, [text]),
    );
  } catch {
    return false;
  }
}

function pass(value) {
  return objectFreeze({
    status: 'PASS',
    value: objectFreeze(value),
    diagnostics: objectFreeze([]),
  });
}

function validPublicationPath(value, revision) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || reflectApply(bufferByteLength, NativeBuffer, [value, 'utf8']) > ABSOLUTE_PATH_MAX_BYTES
    || reflectApply(regexpExec, /[\u0000-\u001f\u007f]/u, [value]) !== null
  ) return false;

  if (reflectApply(stringIncludes, value, ['\\'])) {
    const suffix = `\\.verification\\artifacts\\${revision}`;
    return (
      !reflectApply(stringIncludes, value, ['/'])
      && reflectApply(pathWin32IsAbsolute, PathWin32, [value])
      && reflectApply(pathWin32Normalize, PathWin32, [value]) === value
      && reflectApply(stringEndsWith, value, [suffix])
    );
  }

  const suffix = `/.verification/artifacts/${revision}`;
  return (
    reflectApply(pathPosixIsAbsolute, PathPosix, [value])
    && reflectApply(pathPosixNormalize, PathPosix, [value]) === value
    && reflectApply(stringEndsWith, value, [suffix])
  );
}

export function validateSourceArtifactLauncherRequest(bytes) {
  const parsed = parseJsonBytes(bytes, REQUEST_MAX_BYTES);
  const input = exactPlainDataObject(parsed?.value, REQUEST_KEYS);
  if (
    input === null
    || input.protocolVersion !== SOURCE_ARTIFACT_LAUNCHER_PROTOCOL_VERSION
    || typeof input.commandId !== 'string'
    || !reflectApply(setHas, COMMAND_SET, [input.commandId])
    || !hasCanonicalBytes(parsed.bytes, canonicalRequestText(input))
  ) return INVALID;

  return pass({
    commandId: input.commandId,
    protocolVersion: input.protocolVersion,
  });
}

export function validateSourceArtifactPublication(bytes) {
  const parsed = parseJsonBytes(bytes, PUBLICATION_MAX_BYTES);
  const input = exactPlainDataObject(parsed?.value, PUBLICATION_KEYS);
  if (
    input === null
    || typeof input.artifactManifestDigest !== 'string'
    || reflectApply(regexpExec, DIGEST_PATTERN, [input.artifactManifestDigest]) === null
    || typeof input.artifactName !== 'string'
    || typeof input.artifactPath !== 'string'
    || !hasCanonicalBytes(parsed.bytes, canonicalPublicationText(input))
  ) return INVALID;

  const nameMatch = reflectApply(regexpExec, ARTIFACT_NAME_PATTERN, [input.artifactName]);
  if (nameMatch === null || !validPublicationPath(input.artifactPath, nameMatch[1])) return INVALID;

  return pass({
    artifactManifestDigest: input.artifactManifestDigest,
    artifactName: input.artifactName,
    artifactPath: input.artifactPath,
  });
}
