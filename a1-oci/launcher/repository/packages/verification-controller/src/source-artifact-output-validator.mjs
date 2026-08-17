import { createHash as importedCreateHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import {
  constants as importedZlibConstants,
  gzipSync as importedGzipSync,
  gunzipSync as importedGunzipSync,
} from 'node:zlib';

import { validateHostedArtifactHandoff } from '../../../scripts/verification/hosted-artifact-handoff.mjs';

const NativeArray = Array;
const NativeMap = Map;
const NativeMath = Math;
const NativeNumber = Number;
const NativeObject = Object;
const NativeReflect = Reflect;
const NativeSet = Set;
const NativeTypeError = TypeError;
const NativeUint8Array = Uint8Array;
const ObjectPrototype = Object.prototype;
const ArrayPrototype = Array.prototype;
const MapPrototype = Map.prototype;
const SetPrototype = Set.prototype;
const StringPrototype = String.prototype;
const TypedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arrayJoin = ArrayPrototype.join;
const arrayPop = ArrayPrototype.pop;
const arrayPush = ArrayPrototype.push;
const arraySort = ArrayPrototype.sort;
const mapGet = MapPrototype.get;
const mapSet = MapPrototype.set;
const mapSizeGetter = Object.getOwnPropertyDescriptor(MapPrototype, 'size').get;
const setAdd = SetPrototype.add;
const setDelete = SetPrototype.delete;
const setHas = SetPrototype.has;
const stringIncludes = StringPrototype.includes;
const stringPadStart = StringPrototype.padStart;
const stringSlice = StringPrototype.slice;
const stringSplit = StringPrototype.split;
const stringStartsWith = StringPrototype.startsWith;
const stringToLowerCase = StringPrototype.toLowerCase;
const stringTrim = StringPrototype.trim;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const numberIsFinite = Number.isFinite;
const numberIsSafeInteger = Number.isSafeInteger;
const numberParseInt = Number.parseInt;
const numberToString = Number.prototype.toString;
const mathCeil = Math.ceil;
const mathFloor = Math.floor;
const mathMin = Math.min;
const regExpExec = RegExp.prototype.exec;
const jsonObject = JSON;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const textDecoderDecode = TextDecoder.prototype.decode;
const textEncoderEncode = TextEncoder.prototype.encode;
const uint8ArrayBufferGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'buffer').get;
const uint8ArrayByteLengthGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'byteLength').get;
const uint8ArraySet = Uint8Array.prototype.set;
const uint8ArraySubarray = Uint8Array.prototype.subarray;
const isProxy = utilTypes.isProxy;
const isSharedArrayBuffer = utilTypes.isSharedArrayBuffer;
const isUint8Array = utilTypes.isUint8Array;
const createHash = importedCreateHash;
const gzipSync = importedGzipSync;
const gunzipSync = importedGunzipSync;
const zBestCompression = importedZlibConstants.Z_BEST_COMPRESSION;
const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
const hashProbe = reflectApply(createHash, undefined, ['sha256']);
const hashUpdate = hashProbe.update;
const hashDigest = hashProbe.digest;
reflectApply(hashDigest, hashProbe, ['hex']);

function freeze(value) {
  return reflectApply(objectFreeze, NativeObject, [value]);
}

function ownKeys(value) {
  return reflectApply(reflectOwnKeys, NativeReflect, [value]);
}

function createObject(prototype) {
  return reflectApply(objectCreate, NativeObject, [prototype]);
}

const EXPECTED_KEYS = freeze([
  'artifactName', 'functionUnits', 'limits', 'repository', 'sourceRef',
  'sourceRevision', 'sourceTreeDigest', 'verifierManifestDigest', 'workflow',
  'workflowRunAttempt', 'workflowRunId',
]);
const LIMIT_KEYS = freeze([
  'archiveMemberBytes', 'handoffBytes', 'manifestBytes', 'outputFileMembers',
  'outputTreeBytes',
]);
const UNIT_KEYS = freeze(['logicalId', 'sourcePath', 'testOnly']);
const SNAPSHOT_KEYS = freeze(['entries']);
const ENTRY_KEYS = freeze(['bytes', 'relativePath']);
const MANIFEST_KEYS = freeze([
  'artifactManifestDigest', 'artifacts', 'schemaVersion', 'sourceRevision',
  'sourceTreeDigest', 'verifierManifestDigest',
]);
const MANIFEST_ENTRY_KEYS = freeze([
  'canonicalContentDigest', 'kind', 'logicalTarget', 'relativePath', 'sizeBytes',
  'sourcePath', 'transportDigest',
]);
const SITE_IDENTITY_KEYS = freeze([
  'schemaVersion', 'sitePayloadDigest', 'sourceRevision', 'verifierManifestDigest',
]);
const RUNNER_IDENTITY_KEYS = freeze(['schemaVersion', 'sourceRevision']);
const FULL_REVISION = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const LOGICAL_ID = /^[a-z0-9][a-z0-9-]*$/u;
const MANIFEST_LOGICAL_TARGET = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const WINDOWS_DRIVE_PATH = /^[A-Za-z]:\//u;
const TAR_OCTAL = /^[0-7]+$/u;
const RUNNER_ID = 'verification-runner-py';
const SITE_IDENTITY_PATH = 'build-identity.json';
const RUNNER_IDENTITY_PATH = '.verification/runner-build-identity.v1.json';
const TAR_BLOCK_BYTES = 512;
const TAR_TERMINATOR_BYTES = 1024;
const EMPTY_DIAGNOSTICS = freeze([]);
const EMPTY_FILES = freeze([]);
const PATH_UNSAFE_FAILURE = freeze(createObject(null));
const CANONICAL_GZIP_OPTIONS = closed({
  level: zBestCompression,
  mtime: 0,
  portable: true,
});

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function hasOwn(value, key) {
  return reflectApply(objectHasOwn, NativeObject, [value, key]);
}

function defineData(target, key, value) {
  const descriptor = createObject(null);
  descriptor.value = value;
  descriptor.enumerable = true;
  descriptor.configurable = false;
  descriptor.writable = false;
  reflectApply(objectDefineProperty, NativeObject, [target, key, descriptor]);
}

function dataRecord(fields) {
  const record = createObject(null);
  const keys = ownKeys(fields);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = reflectApply(objectGetOwnPropertyDescriptor, NativeObject, [fields, keys[index]]);
    defineData(record, keys[index], descriptor.value);
  }
  return record;
}

function closed(fields) {
  return freeze(dataRecord(fields));
}

function frozenArray(values) {
  return freeze(values);
}

function result(status, value, code = null) {
  const diagnostics = code === null ? EMPTY_DIAGNOSTICS : frozenArray([closed({
    code,
    safeMessage: code === 'ARTIFACT_PATH_UNSAFE'
      ? 'Artifact source or output path is unsafe.'
      : 'Artifact build input does not match the closed contract.',
    retryable: false,
  })]);
  return closed({ status, value, diagnostics });
}

function blocked(code = 'ARTIFACT_SCHEMA_INVALID') {
  return result('BLOCKED', null, code);
}

function keysMatch(actual, expected) {
  if (actual.length !== expected.length) return false;
  for (let index = 0; index < actual.length; index += 1) {
    if (typeof actual[index] !== 'string') return false;
  }
  for (let expectedIndex = 0; expectedIndex < expected.length; expectedIndex += 1) {
    let found = false;
    for (let actualIndex = 0; actualIndex < actual.length; actualIndex += 1) {
      if (actual[actualIndex] === expected[expectedIndex]) {
        found = true;
        break;
      }
    }
    if (!found) return false;
  }
  return true;
}

function copyExactRecord(value, keys, frozen = false, ordinaryOnly = false) {
  try {
    if (
      reflectApply(isProxy, utilTypes, [value])
      || value === null
      || typeof value !== 'object'
      || reflectApply(arrayIsArray, NativeArray, [value])
    ) return null;
    const prototype = reflectApply(objectGetPrototypeOf, NativeObject, [value]);
    if (ordinaryOnly ? prototype !== ObjectPrototype : prototype !== ObjectPrototype && prototype !== null) {
      return null;
    }
    if (frozen && !reflectApply(objectIsFrozen, NativeObject, [value])) return null;
    const observedKeys = ownKeys(value);
    if (!keysMatch(observedKeys, keys)) return null;
    const copy = createObject(null);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = reflectApply(objectGetOwnPropertyDescriptor, NativeObject, [value, key]);
      if (descriptor === undefined || descriptor.enumerable !== true || !hasOwn(descriptor, 'value')) {
        return null;
      }
      defineData(copy, key, descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function exactOuterArguments(value) {
  return copyExactRecord(value, ['snapshot', 'expected'], false, true);
}

function exactFrozenRecord(value, keys) {
  const copy = copyExactRecord(value, keys, true);
  if (copy === null) return null;
  try {
    return reflectApply(objectGetPrototypeOf, NativeObject, [value]) === null ? copy : null;
  } catch {
    return null;
  }
}

function exactJsonRecord(value, keys) {
  return copyExactRecord(value, keys);
}

function copyDenseArray(value, length, frozen) {
  try {
    if (
      reflectApply(isProxy, utilTypes, [value])
      || !reflectApply(arrayIsArray, NativeArray, [value])
      || (frozen && !reflectApply(objectIsFrozen, NativeObject, [value]))
      || (length !== null && value.length !== length)
    ) return null;
    const observedKeys = ownKeys(value);
    if (observedKeys.length !== value.length + 1) return null;
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = reflectApply(objectGetOwnPropertyDescriptor, NativeObject, [value, `${index}`]);
      if (descriptor === undefined || descriptor.enumerable !== true || !hasOwn(descriptor, 'value')) {
        return null;
      }
      reflectApply(arrayPush, copy, [descriptor.value]);
    }
    return copy;
  } catch {
    return null;
  }
}

function denseFrozenArray(value, length = null) {
  return copyDenseArray(value, length, true);
}

function denseJsonArray(value, length = null) {
  return copyDenseArray(value, length, false);
}

function testPattern(pattern, value) {
  return reflectApply(regExpExec, pattern, [value]) !== null;
}

function safePath(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || reflectApply(stringIncludes, value, ['\\'])
    || reflectApply(stringStartsWith, value, ['/'])
    || testPattern(CONTROL_CHARACTER, value)
    || testPattern(WINDOWS_DRIVE_PATH, value)
  ) return false;
  const segments = reflectApply(stringSplit, value, ['/']);
  for (let index = 0; index < segments.length; index += 1) {
    if (segments[index] === '' || segments[index] === '.' || segments[index] === '..') return false;
  }
  return true;
}

function inspectExpected(value) {
  const expected = exactFrozenRecord(value, EXPECTED_KEYS);
  if (expected === null) return null;
  const limits = exactFrozenRecord(expected.limits, LIMIT_KEYS);
  const units = denseFrozenArray(expected.functionUnits, 36);
  if (limits === null || units === null) return null;
  if (
    expected.repository !== 'Krowaccie/AppWriteWork'
    || expected.workflow !== 'Verify Main'
    || expected.sourceRef !== 'refs/heads/main'
    || typeof expected.sourceRevision !== 'string'
    || !testPattern(FULL_REVISION, expected.sourceRevision)
    || typeof expected.sourceTreeDigest !== 'string'
    || !testPattern(DIGEST, expected.sourceTreeDigest)
    || typeof expected.verifierManifestDigest !== 'string'
    || !testPattern(DIGEST, expected.verifierManifestDigest)
    || typeof expected.workflowRunId !== 'string'
    || !testPattern(RUN_ID, expected.workflowRunId)
    || !reflectApply(numberIsSafeInteger, NativeNumber, [expected.workflowRunAttempt])
    || expected.workflowRunAttempt <= 0
    || expected.artifactName !== `verification-artifacts-${expected.sourceRevision}`
  ) return null;
  if (
    limits.archiveMemberBytes !== 128 * 1024 * 1024
    || limits.handoffBytes !== 1024 * 1024
    || limits.manifestBytes !== 1024 * 1024
    || limits.outputFileMembers !== 39
    || limits.outputTreeBytes !== 256 * 1024 * 1024
  ) return null;
  let previous = null;
  const normalizedUnits = [];
  for (let index = 0; index < units.length; index += 1) {
    const unit = exactFrozenRecord(units[index], UNIT_KEYS);
    if (
      unit === null
      || typeof unit.logicalId !== 'string'
      || !testPattern(LOGICAL_ID, unit.logicalId)
      || !safePath(unit.sourcePath)
      || typeof unit.testOnly !== 'boolean'
      || (index === 35) !== unit.testOnly
      || (index === 35 && unit.logicalId !== RUNNER_ID)
      || (index < 35 && unit.logicalId === RUNNER_ID)
      || (index < 35 && previous !== null && ordinalCompare(previous, unit.logicalId) >= 0)
    ) return null;
    if (index < 35) previous = unit.logicalId;
    reflectApply(arrayPush, normalizedUnits, [closed({
      logicalId: unit.logicalId,
      sourcePath: unit.sourcePath,
      testOnly: unit.testOnly,
    })]);
  }
  return closed({
    artifactName: expected.artifactName,
    functionUnits: frozenArray(normalizedUnits),
    limits: closed({
      archiveMemberBytes: limits.archiveMemberBytes,
      handoffBytes: limits.handoffBytes,
      manifestBytes: limits.manifestBytes,
      outputFileMembers: limits.outputFileMembers,
      outputTreeBytes: limits.outputTreeBytes,
    }),
    repository: expected.repository,
    sourceRef: expected.sourceRef,
    sourceRevision: expected.sourceRevision,
    sourceTreeDigest: expected.sourceTreeDigest,
    verifierManifestDigest: expected.verifierManifestDigest,
    workflow: expected.workflow,
    workflowRunAttempt: expected.workflowRunAttempt,
    workflowRunId: expected.workflowRunId,
  });
}

function expectedMembers(units) {
  const members = [closed({ memberId: 'site:web', relativePath: 'site/site.tar.gz' })];
  for (let index = 0; index < units.length; index += 1) {
    const logicalId = units[index].logicalId;
    reflectApply(arrayPush, members, [closed({
      memberId: `function:${logicalId}`,
      relativePath: `functions/${logicalId}.tar.gz`,
    })]);
  }
  reflectApply(arrayPush, members, [
    closed({ memberId: 'metadata:artifact-manifest', relativePath: 'artifact-manifest.v1.json' }),
    closed({ memberId: 'metadata:artifact-handoff', relativePath: 'artifact-handoff.v1.json' }),
  ]);
  return frozenArray(members);
}

function byteLengthOf(bytes) {
  return reflectApply(uint8ArrayByteLengthGetter, bytes, []);
}

function copyBytes(bytes, byteLength) {
  const copy = new NativeUint8Array(byteLength);
  reflectApply(uint8ArraySet, copy, [bytes]);
  return copy;
}

function sha256Bytes(bytes) {
  const hash = reflectApply(createHash, undefined, ['sha256']);
  reflectApply(hashUpdate, hash, [bytes]);
  return `sha256:${reflectApply(hashDigest, hash, ['hex'])}`;
}

function inspectSnapshot(value, expected) {
  const snapshot = exactFrozenRecord(value, SNAPSHOT_KEYS);
  const entries = snapshot === null ? null : denseFrozenArray(snapshot.entries, 39);
  if (entries === null) return closed({ error: 'ARTIFACT_SCHEMA_INVALID' });
  const members = expectedMembers(expected.functionUnits);
  const buffers = new NativeSet();
  const normalized = [];
  let total = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = exactFrozenRecord(entries[index], ENTRY_KEYS);
    if (entry === null || entry.relativePath !== members[index].relativePath || !safePath(entry.relativePath)) {
      return closed({ error: 'ARTIFACT_PATH_UNSAFE' });
    }
    try {
      if (
        reflectApply(isProxy, utilTypes, [entry.bytes])
        || !reflectApply(isUint8Array, utilTypes, [entry.bytes])
      ) return closed({ error: 'ARTIFACT_SCHEMA_INVALID' });
      const byteLength = byteLengthOf(entry.bytes);
      const backing = reflectApply(uint8ArrayBufferGetter, entry.bytes, []);
      if (reflectApply(isSharedArrayBuffer, utilTypes, [backing])) {
        return closed({ error: 'ARTIFACT_PATH_UNSAFE' });
      }
      if (reflectApply(setHas, buffers, [backing])) return closed({ error: 'ARTIFACT_PATH_UNSAFE' });
      reflectApply(setAdd, buffers, [backing]);
      const limit = index === 37
        ? expected.limits.manifestBytes
        : index === 38
          ? expected.limits.handoffBytes
          : expected.limits.archiveMemberBytes;
      if (byteLength <= 0 || byteLength > limit) return closed({ error: 'ARTIFACT_PATH_UNSAFE' });
      total += byteLength;
      if (total > expected.limits.outputTreeBytes) return closed({ error: 'ARTIFACT_PATH_UNSAFE' });
      const snapshotBytes = copyBytes(entry.bytes, byteLength);
      reflectApply(arrayPush, normalized, [closed({
        memberId: members[index].memberId,
        relativePath: entry.relativePath,
        bytes: snapshotBytes,
        sizeBytes: byteLength,
        transportDigest: sha256Bytes(snapshotBytes),
      })]);
    } catch {
      return closed({ error: 'ARTIFACT_SCHEMA_INVALID' });
    }
  }
  return closed({ entries: frozenArray(normalized) });
}

function encodeText(value) {
  return reflectApply(textEncoderEncode, encoder, [value]);
}

function encodeCanonical(value, ancestors, budget) {
  budget.remaining -= 1;
  if (budget.remaining < 0) throw new NativeTypeError('canonical');
  if (value === null) return 'null';
  const kind = typeof value;
  if (kind === 'boolean') return value ? 'true' : 'false';
  if (kind === 'string') return reflectApply(jsonStringify, jsonObject, [value]);
  if (kind === 'number') {
    if (!reflectApply(numberIsFinite, NativeNumber, [value])) throw new NativeTypeError('canonical');
    return reflectApply(jsonStringify, jsonObject, [value]);
  }
  if (kind !== 'object' || reflectApply(isProxy, utilTypes, [value])) {
    throw new NativeTypeError('canonical');
  }
  if (reflectApply(setHas, ancestors, [value])) throw new NativeTypeError('canonical');
  reflectApply(setAdd, ancestors, [value]);
  try {
    if (reflectApply(arrayIsArray, NativeArray, [value])) {
      const values = denseJsonArray(value);
      if (values === null) throw new NativeTypeError('canonical');
      const encoded = [];
      for (let index = 0; index < values.length; index += 1) {
        reflectApply(arrayPush, encoded, [encodeCanonical(values[index], ancestors, budget)]);
      }
      return `[${reflectApply(arrayJoin, encoded, [','])}]`;
    }
    const prototype = reflectApply(objectGetPrototypeOf, NativeObject, [value]);
    if (prototype !== ObjectPrototype && prototype !== null) throw new NativeTypeError('canonical');
    const observedKeys = ownKeys(value);
    for (let index = 0; index < observedKeys.length; index += 1) {
      if (typeof observedKeys[index] !== 'string') throw new NativeTypeError('canonical');
      const descriptor = reflectApply(objectGetOwnPropertyDescriptor, NativeObject, [value, observedKeys[index]]);
      if (descriptor === undefined || descriptor.enumerable !== true || !hasOwn(descriptor, 'value')) {
        throw new NativeTypeError('canonical');
      }
    }
    reflectApply(arraySort, observedKeys, [ordinalCompare]);
    const encoded = [];
    for (let index = 0; index < observedKeys.length; index += 1) {
      const key = observedKeys[index];
      const descriptor = reflectApply(objectGetOwnPropertyDescriptor, NativeObject, [value, key]);
      reflectApply(arrayPush, encoded, [
        `${reflectApply(jsonStringify, jsonObject, [key])}:${encodeCanonical(descriptor.value, ancestors, budget)}`,
      ]);
    }
    return `{${reflectApply(arrayJoin, encoded, [','])}}`;
  } finally {
    reflectApply(setDelete, ancestors, [value]);
  }
}

function canonicalJson(value, maximumNodes) {
  return encodeCanonical(value, new NativeSet(), { remaining: maximumNodes });
}

function parseCanonicalJson(bytes) {
  const byteLength = byteLengthOf(bytes);
  const text = reflectApply(textDecoderDecode, decoder, [bytes]);
  const value = reflectApply(jsonParse, jsonObject, [text]);
  if (text !== `${canonicalJson(value, byteLength + 1)}\n`) throw new NativeTypeError('noncanonical');
  return value;
}

function deepFreeze(value, maximumNodes) {
  const pending = [value];
  const ordered = [];
  const seen = new NativeSet();
  let observed = 0;
  while (pending.length > 0) {
    const current = reflectApply(arrayPop, pending, []);
    if (current === null || typeof current !== 'object') continue;
    if (reflectApply(isProxy, utilTypes, [current]) || reflectApply(setHas, seen, [current])) {
      throw new NativeTypeError('freeze');
    }
    reflectApply(setAdd, seen, [current]);
    observed += 1;
    if (observed > maximumNodes) throw new NativeTypeError('freeze');
    reflectApply(arrayPush, ordered, [current]);
    const keys = ownKeys(current);
    const isArray = reflectApply(arrayIsArray, NativeArray, [current]);
    for (let index = 0; index < keys.length; index += 1) {
      if (isArray && keys[index] === 'length') continue;
      const descriptor = reflectApply(objectGetOwnPropertyDescriptor, NativeObject, [current, keys[index]]);
      if (descriptor !== undefined && hasOwn(descriptor, 'value')) {
        reflectApply(arrayPush, pending, [descriptor.value]);
      }
    }
  }
  while (ordered.length > 0) freeze(reflectApply(arrayPop, ordered, []));
  return value;
}

function validateManifest(value, expected, maximumNodes) {
  const manifest = exactJsonRecord(value, MANIFEST_KEYS);
  if (
    manifest === null
    || manifest.schemaVersion !== 1
    || typeof manifest.sourceRevision !== 'string'
    || !testPattern(FULL_REVISION, manifest.sourceRevision)
    || typeof manifest.sourceTreeDigest !== 'string'
    || !testPattern(DIGEST, manifest.sourceTreeDigest)
    || typeof manifest.verifierManifestDigest !== 'string'
    || !testPattern(DIGEST, manifest.verifierManifestDigest)
    || typeof manifest.artifactManifestDigest !== 'string'
    || !testPattern(DIGEST, manifest.artifactManifestDigest)
    || manifest.sourceRevision !== expected.sourceRevision
    || manifest.sourceTreeDigest !== expected.sourceTreeDigest
    || manifest.verifierManifestDigest !== expected.verifierManifestDigest
  ) return null;
  const artifacts = denseJsonArray(manifest.artifacts, 37);
  if (artifacts === null) return null;
  const normalizedArtifacts = [];
  let previous = null;
  for (let index = 0; index < artifacts.length; index += 1) {
    const artifact = exactJsonRecord(artifacts[index], MANIFEST_ENTRY_KEYS);
    if (
      artifact === null
      || (artifact.kind !== 'function' && artifact.kind !== 'site')
      || typeof artifact.logicalTarget !== 'string'
      || !testPattern(MANIFEST_LOGICAL_TARGET, artifact.logicalTarget)
      || !safePath(artifact.sourcePath)
      || !safePath(artifact.relativePath)
      || typeof artifact.canonicalContentDigest !== 'string'
      || !testPattern(DIGEST, artifact.canonicalContentDigest)
      || typeof artifact.transportDigest !== 'string'
      || !testPattern(DIGEST, artifact.transportDigest)
      || !reflectApply(numberIsSafeInteger, NativeNumber, [artifact.sizeBytes])
      || artifact.sizeBytes < 0
    ) return null;
    const key = `${artifact.kind}\u0000${artifact.logicalTarget}`;
    if (previous !== null && ordinalCompare(previous, key) >= 0) return null;
    previous = key;
    reflectApply(arrayPush, normalizedArtifacts, [dataRecord({
      canonicalContentDigest: artifact.canonicalContentDigest,
      kind: artifact.kind,
      logicalTarget: artifact.logicalTarget,
      relativePath: artifact.relativePath,
      sizeBytes: artifact.sizeBytes,
      sourcePath: artifact.sourcePath,
      transportDigest: artifact.transportDigest,
    })]);
  }
  const core = dataRecord({
    schemaVersion: 1,
    sourceRevision: manifest.sourceRevision,
    sourceTreeDigest: manifest.sourceTreeDigest,
    verifierManifestDigest: manifest.verifierManifestDigest,
    artifacts: normalizedArtifacts,
  });
  const calculatedDigest = sha256Bytes(encodeText(canonicalJson(core, maximumNodes)));
  if (calculatedDigest !== manifest.artifactManifestDigest) return null;
  return deepFreeze(dataRecord({
    artifactManifestDigest: manifest.artifactManifestDigest,
    artifacts: normalizedArtifacts,
    schemaVersion: 1,
    sourceRevision: manifest.sourceRevision,
    sourceTreeDigest: manifest.sourceTreeDigest,
    verifierManifestDigest: manifest.verifierManifestDigest,
  }), maximumNodes);
}

function validateSiteIdentity(value, maximumNodes) {
  const identity = exactJsonRecord(value, SITE_IDENTITY_KEYS);
  if (
    identity === null
    || identity.schemaVersion !== 'hosted-site-build-identity.v1'
    || typeof identity.sourceRevision !== 'string'
    || !testPattern(FULL_REVISION, identity.sourceRevision)
    || typeof identity.sitePayloadDigest !== 'string'
    || !testPattern(DIGEST, identity.sitePayloadDigest)
    || typeof identity.verifierManifestDigest !== 'string'
    || !testPattern(DIGEST, identity.verifierManifestDigest)
  ) return null;
  return deepFreeze(dataRecord({
    schemaVersion: identity.schemaVersion,
    sitePayloadDigest: identity.sitePayloadDigest,
    sourceRevision: identity.sourceRevision,
    verifierManifestDigest: identity.verifierManifestDigest,
  }), maximumNodes);
}

function validateRunnerIdentity(value, maximumNodes) {
  const identity = exactJsonRecord(value, RUNNER_IDENTITY_KEYS);
  if (
    identity === null
    || identity.schemaVersion !== 'verification-runner-build-identity.v1'
    || typeof identity.sourceRevision !== 'string'
    || !testPattern(FULL_REVISION, identity.sourceRevision)
  ) return null;
  return deepFreeze(dataRecord({
    schemaVersion: identity.schemaVersion,
    sourceRevision: identity.sourceRevision,
  }), maximumNodes);
}

function normalizeValidatedHandoff(handoff, maximumNodes) {
  return deepFreeze(dataRecord({
    artifactManifestDigest: handoff.artifactManifestDigest,
    artifactName: handoff.artifactName,
    schemaVersion: handoff.schemaVersion,
    sourceRef: handoff.sourceRef,
    sourceRepository: handoff.sourceRepository,
    sourceRevision: handoff.sourceRevision,
    sourceWorkflow: handoff.sourceWorkflow,
    sourceWorkflowRunAttempt: handoff.sourceWorkflowRunAttempt,
    sourceWorkflowRunId: handoff.sourceWorkflowRunId,
    verifierManifestDigest: handoff.verifierManifestDigest,
  }), maximumNodes);
}

function subarray(bytes, start, end = undefined) {
  return end === undefined
    ? reflectApply(uint8ArraySubarray, bytes, [start])
    : reflectApply(uint8ArraySubarray, bytes, [start, end]);
}

function allZero(bytes) {
  const length = byteLengthOf(bytes);
  for (let index = 0; index < length; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return true;
}

function bytesEqual(left, right) {
  const leftLength = byteLengthOf(left);
  if (leftLength !== byteLengthOf(right)) return false;
  for (let index = 0; index < leftLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function throwPathUnsafe() {
  throw PATH_UNSAFE_FAILURE;
}

function splitUstarPath(archivePath) {
  if (byteLengthOf(encodeText(archivePath)) <= 100) {
    return closed({ name: archivePath, prefix: '' });
  }
  for (let index = archivePath.length - 1; index > 0; index -= 1) {
    if (archivePath[index] !== '/') continue;
    const prefix = reflectApply(stringSlice, archivePath, [0, index]);
    const name = reflectApply(stringSlice, archivePath, [index + 1]);
    if (byteLengthOf(encodeText(prefix)) <= 155 && byteLengthOf(encodeText(name)) <= 100) {
      return closed({ name, prefix });
    }
  }
  return throwPathUnsafe();
}

function writeTarString(target, offset, length, value) {
  const bytes = encodeText(value);
  if (byteLengthOf(bytes) > length) return throwPathUnsafe();
  reflectApply(uint8ArraySet, target, [bytes, offset]);
}

function writeTarOctal(target, offset, length, value) {
  const digits = reflectApply(numberToString, value, [8]);
  if (digits.length > length - 1) throw new NativeTypeError('tar');
  const padded = reflectApply(stringPadStart, digits, [length - 1, '0']);
  const bytes = encodeText(`${padded}\0`);
  reflectApply(uint8ArraySet, target, [bytes, offset]);
}

function canonicalTarHeader(archivePath, size) {
  const split = splitUstarPath(archivePath);
  const header = new NativeUint8Array(TAR_BLOCK_BYTES);
  writeTarString(header, 0, 100, split.name);
  writeTarOctal(header, 100, 8, 0o644);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, size);
  writeTarOctal(header, 136, 12, 0);
  for (let index = 148; index < 156; index += 1) header[index] = 0x20;
  header[156] = 0x30;
  writeTarString(header, 257, 6, 'ustar\0');
  writeTarString(header, 263, 2, '00');
  writeTarString(header, 345, 155, split.prefix);
  let checksum = 0;
  for (let index = 0; index < TAR_BLOCK_BYTES; index += 1) checksum += header[index];
  const digits = reflectApply(numberToString, checksum, [8]);
  if (digits.length > 6) throw new NativeTypeError('tar');
  const padded = reflectApply(stringPadStart, digits, [6, '0']);
  writeTarString(header, 148, 8, `${padded}\0 `);
  return header;
}

function readTarString(bytes) {
  const length = byteLengthOf(bytes);
  let end = 0;
  while (end < length && bytes[end] !== 0) end += 1;
  return reflectApply(textDecoderDecode, decoder, [subarray(bytes, 0, end)]);
}

function readTarOctal(bytes) {
  const text = reflectApply(stringTrim, readTarString(bytes), []);
  if (!testPattern(TAR_OCTAL, text)) throw new NativeTypeError('tar');
  const value = reflectApply(numberParseInt, NativeNumber, [text, 8]);
  if (!reflectApply(numberIsSafeInteger, NativeNumber, [value]) || value < 0) {
    throw new NativeTypeError('tar');
  }
  return value;
}

function parseArchive(bytes, maximum, capture) {
  if (!reflectApply(numberIsSafeInteger, NativeNumber, [maximum]) || maximum <= 0) {
    throw new NativeTypeError('archive-budget');
  }
  const tar = reflectApply(gunzipSync, undefined, [bytes, closed({ maxOutputLength: maximum })]);
  if (
    reflectApply(isProxy, utilTypes, [tar])
    || !reflectApply(isUint8Array, utilTypes, [tar])
  ) throw new NativeTypeError('tar');
  const tarLength = byteLengthOf(tar);
  if (tarLength <= 0 || tarLength > maximum) throw new NativeTypeError('archive-budget');
  const recompressed = reflectApply(gzipSync, undefined, [tar, CANONICAL_GZIP_OPTIONS]);
  if (
    reflectApply(isProxy, utilTypes, [recompressed])
    || !reflectApply(isUint8Array, utilTypes, [recompressed])
    || !bytesEqual(recompressed, bytes)
  ) throw new NativeTypeError('gzip');
  const canonicalContentDigest = sha256Bytes(tar);
  const fileDigests = [];
  const paths = new NativeSet();
  const folded = new NativeSet();
  const prefixes = new NativeSet();
  const foldedPrefixes = new NativeSet();
  const maximumFiles = reflectApply(mathFloor, NativeMath, [tarLength / TAR_BLOCK_BYTES]);
  let fileCount = 0;
  let offset = 0;
  let previousPath = null;
  let terminated = false;
  let siteIdentity = null;
  let runnerIdentity = null;
  while (offset + TAR_BLOCK_BYTES <= tarLength) {
    const header = subarray(tar, offset, offset + TAR_BLOCK_BYTES);
    if (allZero(header)) {
      if (
        offset + TAR_TERMINATOR_BYTES !== tarLength
        || !allZero(subarray(tar, offset, offset + TAR_TERMINATOR_BYTES))
      ) throw new NativeTypeError('tar');
      terminated = true;
      break;
    }
    fileCount += 1;
    if (fileCount > maximumFiles) throw new NativeTypeError('tar');
    const name = readTarString(subarray(header, 0, 100));
    const prefix = readTarString(subarray(header, 345, 500));
    const archivePath = prefix === '' ? name : `${prefix}/${name}`;
    if (!safePath(archivePath)) return throwPathUnsafe();
    const size = readTarOctal(subarray(header, 124, 136));
    if (!bytesEqual(header, canonicalTarHeader(archivePath, size))) {
      throw new NativeTypeError('tar');
    }
    const foldedPath = reflectApply(stringToLowerCase, archivePath, []);
    if (
      reflectApply(setHas, paths, [archivePath])
      || reflectApply(setHas, folded, [foldedPath])
      || reflectApply(setHas, prefixes, [archivePath])
      || reflectApply(setHas, foldedPrefixes, [foldedPath])
    ) return throwPathUnsafe();
    const segments = reflectApply(stringSplit, archivePath, ['/']);
    let ancestor = '';
    for (let segmentIndex = 0; segmentIndex < segments.length - 1; segmentIndex += 1) {
      ancestor = segmentIndex === 0 ? segments[0] : `${ancestor}/${segments[segmentIndex]}`;
      const foldedAncestor = reflectApply(stringToLowerCase, ancestor, []);
      if (
        reflectApply(setHas, paths, [ancestor])
        || reflectApply(setHas, folded, [foldedAncestor])
      ) return throwPathUnsafe();
      reflectApply(setAdd, prefixes, [ancestor]);
      reflectApply(setAdd, foldedPrefixes, [foldedAncestor]);
    }
    if (previousPath !== null && ordinalCompare(previousPath, archivePath) >= 0) {
      throw new NativeTypeError('tar');
    }
    previousPath = archivePath;
    reflectApply(setAdd, paths, [archivePath]);
    reflectApply(setAdd, folded, [foldedPath]);
    const start = offset + TAR_BLOCK_BYTES;
    const end = start + size;
    const paddedEnd = start
      + reflectApply(mathCeil, NativeMath, [size / TAR_BLOCK_BYTES]) * TAR_BLOCK_BYTES;
    if (
      !reflectApply(numberIsSafeInteger, NativeNumber, [end])
      || !reflectApply(numberIsSafeInteger, NativeNumber, [paddedEnd])
      || end > tarLength
      || paddedEnd > tarLength
      || !allZero(subarray(tar, end, paddedEnd))
    ) throw new NativeTypeError('tar');
    const payload = subarray(tar, start, end);
    if (capture === 'site') {
      reflectApply(arrayPush, fileDigests, [closed({
        contentDigest: sha256Bytes(payload), mode: '100644', path: archivePath,
      })]);
      if (archivePath === SITE_IDENTITY_PATH) {
        siteIdentity = validateSiteIdentity(parseCanonicalJson(payload), size + 1);
        if (siteIdentity === null) throw new NativeTypeError('site-identity');
      }
    } else if (capture === 'runner' && archivePath === RUNNER_IDENTITY_PATH) {
      runnerIdentity = validateRunnerIdentity(parseCanonicalJson(payload), size + 1);
      if (runnerIdentity === null) throw new NativeTypeError('runner-identity');
    }
    offset = paddedEnd;
  }
  if (!terminated || fileCount === 0) throw new NativeTypeError('tar');
  if (capture === 'site' && siteIdentity === null) throw new NativeTypeError('site-identity');
  if (capture === 'runner' && runnerIdentity === null) throw new NativeTypeError('runner-identity');
  if (capture === 'site') {
    reflectApply(arraySort, fileDigests, [(left, right) => ordinalCompare(left.path, right.path)]);
  }
  return closed({
    canonicalContentDigest,
    expandedBytes: tarLength,
    fileDigests: capture === 'site' ? frozenArray(fileDigests) : EMPTY_FILES,
    runnerIdentity,
    siteIdentity,
    transportDigest: sha256Bytes(bytes),
  });
}

function digestSitePayload(fileDigests) {
  const included = [];
  for (let index = 0; index < fileDigests.length; index += 1) {
    if (fileDigests[index].path !== SITE_IDENTITY_PATH) {
      reflectApply(arrayPush, included, [fileDigests[index]]);
    }
  }
  return sha256Bytes(encodeText(canonicalJson(included, included.length * 4 + 1)));
}

function validateArchives(manifest, entries, expected) {
  const byPath = new NativeMap();
  for (let index = 0; index < manifest.artifacts.length; index += 1) {
    const artifact = manifest.artifacts[index];
    reflectApply(mapSet, byPath, [artifact.relativePath, artifact]);
  }
  if (reflectApply(mapSizeGetter, byPath, []) !== 37) return false;
  let expandedArchiveBytes = 0;
  for (let index = 0; index < 37; index += 1) {
    const snapshotEntry = entries[index];
    const artifact = reflectApply(mapGet, byPath, [snapshotEntry.relativePath]);
    if (artifact === undefined) return false;
    if (
      artifact.sizeBytes !== snapshotEntry.sizeBytes
      || artifact.transportDigest !== snapshotEntry.transportDigest
    ) return false;
    let capture = 'function';
    if (index === 0) {
      capture = 'site';
      if (
        artifact.kind !== 'site'
        || artifact.logicalTarget !== 'web'
        || artifact.sourcePath !== 'src/web'
      ) return false;
    } else {
      const unit = expected.functionUnits[index - 1];
      if (
        artifact.kind !== 'function'
        || artifact.logicalTarget !== unit.logicalId
        || artifact.sourcePath !== unit.sourcePath
      ) return false;
      if (index === 36) capture = 'runner';
    }
    const remaining = expected.limits.outputTreeBytes - expandedArchiveBytes;
    if (remaining <= 0) return false;
    const maximum = reflectApply(mathMin, NativeMath, [expected.limits.archiveMemberBytes, remaining]);
    const summary = parseArchive(snapshotEntry.bytes, maximum, capture);
    expandedArchiveBytes += summary.expandedBytes;
    if (expandedArchiveBytes > expected.limits.outputTreeBytes) return false;
    if (capture === 'site') {
      const sitePayloadDigest = digestSitePayload(summary.fileDigests);
      if (
        summary.siteIdentity.sourceRevision !== expected.sourceRevision
        || summary.siteIdentity.verifierManifestDigest !== expected.verifierManifestDigest
        || summary.siteIdentity.sitePayloadDigest !== sitePayloadDigest
        || artifact.canonicalContentDigest !== sitePayloadDigest
      ) return false;
    } else if (artifact.canonicalContentDigest !== summary.canonicalContentDigest) {
      return false;
    }
    if (capture === 'runner' && summary.runnerIdentity.sourceRevision !== expected.sourceRevision) {
      return false;
    }
  }
  return true;
}

export function validateSourceArtifactOutputSnapshot(args) {
  try {
    const input = exactOuterArguments(args);
    if (input === null) return blocked();
    const normalizedExpected = inspectExpected(input.expected);
    if (normalizedExpected === null) return blocked();
    const normalizedSnapshot = inspectSnapshot(input.snapshot, normalizedExpected);
    if (hasOwn(normalizedSnapshot, 'error')) return blocked(normalizedSnapshot.error);
    const entries = normalizedSnapshot.entries;
    const manifestBytes = entries[37].bytes;
    const manifest = validateManifest(
      parseCanonicalJson(manifestBytes), normalizedExpected, byteLengthOf(manifestBytes) + 1,
    );
    if (manifest === null) return blocked();
    if (!validateArchives(manifest, entries, normalizedExpected)) return blocked();
    const handoffBytes = entries[38].bytes;
    const handoffValidation = validateHostedArtifactHandoff({
      handoff: parseCanonicalJson(handoffBytes),
      manifest,
      trustedSource: closed({
        repository: normalizedExpected.repository,
        workflow: normalizedExpected.workflow,
        workflowRunId: normalizedExpected.workflowRunId,
        workflowRunAttempt: normalizedExpected.workflowRunAttempt,
        sourceRef: normalizedExpected.sourceRef,
        sourceRevision: normalizedExpected.sourceRevision,
      }),
    });
    if (handoffValidation.status !== 'PASS') return blocked();
    const handoff = normalizeValidatedHandoff(
      handoffValidation.value,
      byteLengthOf(handoffBytes) + 1,
    );
    const memberDigests = [];
    for (let index = 0; index < entries.length; index += 1) {
      reflectApply(arrayPush, memberDigests, [closed({
        memberId: entries[index].memberId,
        relativePath: entries[index].relativePath,
        sizeBytes: entries[index].sizeBytes,
        transportDigest: entries[index].transportDigest,
      })]);
    }
    return result('PASS', closed({
      artifactManifest: manifest,
      handoff,
      memberDigests: frozenArray(memberDigests),
    }));
  } catch (error) {
    return blocked(error === PATH_UNSAFE_FAILURE ? 'ARTIFACT_PATH_UNSAFE' : 'ARTIFACT_SCHEMA_INVALID');
  }
}
