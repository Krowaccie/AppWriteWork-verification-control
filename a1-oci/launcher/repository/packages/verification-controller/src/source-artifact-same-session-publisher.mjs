import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import {
  completePublicationLease,
  consumePublicationLease,
} from './source-artifact-publication-lease-authority.mjs';
import { claimSameSessionSourceArtifactUploadHost } from './source-artifact-same-session-upload-host.mjs';

const PASS_NULL = result('PASS');
const NativePromise = Promise;
const NativeUint8Array = Uint8Array;
const nativeMin = Math.min;
const isProxy = utilTypes.isProxy;
const isPromise = utilTypes.isPromise;
const isSharedArrayBuffer = utilTypes.isSharedArrayBuffer;
const isUint8Array = utilTypes.isUint8Array;
const objectCreate = Object.create;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const speciesSymbol = Symbol.species;
const nativePromisePrototype = NativePromise.prototype;
const nativePromiseConstructorDescriptor = objectGetOwnPropertyDescriptor(
  nativePromisePrototype,
  'constructor',
);
const nativePromiseSpeciesDescriptor = objectGetOwnPropertyDescriptor(
  NativePromise,
  speciesSymbol,
);
const typedArrayPrototype = objectGetPrototypeOf(NativeUint8Array.prototype);
const getByteLength = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const getByteOffset = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const getBuffer = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const typedArraySet = objectGetOwnPropertyDescriptor(typedArrayPrototype, 'set').value;
const getArrayBufferByteLength = objectGetOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const getResizable = objectGetOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;
const hashPrototype = objectGetPrototypeOf(createHash('sha256'));
const hashUpdate = objectGetOwnPropertyDescriptor(hashPrototype, 'update').value;
const hashDigest = objectGetOwnPropertyDescriptor(hashPrototype, 'digest').value;
const promiseThen = NativePromise.prototype.then;
const PASS_RESULT_KEYS = objectFreeze(['diagnostics', 'status', 'value']);
const PASS_BYTES_KEYS = objectFreeze(['bytes']);
const INVALID_DATA = objectFreeze(objectCreate(null));

function result(status, code = null) {
  const value = Object.create(null);
  value.status = status;
  value.value = null;
  value.diagnostics = code === null
    ? Object.freeze([])
    : Object.freeze([Object.freeze(Object.assign(Object.create(null), {
      code,
      retryable: false,
      safeMessage: code === 'ARTIFACT_CLEANUP_INCOMPLETE'
        ? 'Trusted artifact cleanup could not be completed.'
        : code === 'ARTIFACT_SCHEMA_INVALID'
          ? 'Source artifact launcher data does not match the closed contract.'
          : 'Trusted artifact publication could not be completed.',
    }))]);
  return Object.freeze(value);
}

function validLimits(value) {
  return value !== null
    && typeof value === 'object'
    && Object.isFrozen(value)
    && Reflect.ownKeys(value).length === 3
    && ['maxArtifactBytes', 'maxChunkBytes', 'maxMemberBytes'].every((key) => (
      Object.hasOwn(value, key) && Number.isSafeInteger(value[key]) && value[key] > 0
    ));
}

function snapshotBytes(value, expectedLength) {
  try {
    if (isProxy(value) || !isUint8Array(value)) return null;
    const byteLength = reflectApply(getByteLength, value, []);
    const byteOffset = reflectApply(getByteOffset, value, []);
    const backing = reflectApply(getBuffer, value, []);
    if (
      byteLength !== expectedLength
      || !Number.isSafeInteger(byteOffset)
      || byteOffset < 0
      || isSharedArrayBuffer(backing)
      || (getResizable && reflectApply(getResizable, backing, []) === true)
      || byteOffset + byteLength > reflectApply(getArrayBufferByteLength, backing, [])
    ) return null;
    const copy = new NativeUint8Array(byteLength);
    reflectApply(typedArraySet, copy, [value]);
    if (
      reflectApply(getByteLength, value, []) !== byteLength
      || reflectApply(getByteOffset, value, []) !== byteOffset
      || reflectApply(getBuffer, value, []) !== backing
    ) return null;
    return copy;
  } catch {
    return null;
  }
}

function exactFrozenData(value, keys) {
  try {
    if (
      isProxy(value)
      || value === null
      || typeof value !== 'object'
      || !objectIsFrozen(value)
    ) return null;
    const actual = reflectOwnKeys(value);
    if (actual.length !== keys.length) return null;
    const snapshot = objectCreate(null);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || !objectHasOwn(descriptor, 'value')
        || !descriptor.enumerable
      ) return null;
      snapshot[key] = descriptor.value;
    }
    return snapshot;
  } catch {
    return null;
  }
}

function passValue(value) {
  const resultValue = exactFrozenData(value, PASS_RESULT_KEYS);
  return resultValue !== null && resultValue.status === 'PASS'
    ? resultValue.value
    : INVALID_DATA;
}

function isNullPass(value) {
  return passValue(value) === null;
}

function passBytes(value, length) {
  const payload = passValue(value);
  const bytesValue = payload === INVALID_DATA
    ? null
    : exactFrozenData(payload, PASS_BYTES_KEYS);
  return bytesValue === null ? null : snapshotBytes(bytesValue.bytes, length);
}

function closedValue(value) {
  const wrapper = objectCreate(null);
  wrapper.value = value;
  return objectFreeze(wrapper);
}

function sameDescriptor(actual, expected) {
  if (actual === undefined || expected === undefined) return false;
  const actualIsData = objectHasOwn(actual, 'value');
  const expectedIsData = objectHasOwn(expected, 'value');
  if (actualIsData !== expectedIsData) return false;
  return actual.configurable === expected.configurable
    && actual.enumerable === expected.enumerable
    && (actualIsData
      ? actual.value === expected.value && actual.writable === expected.writable
      : actual.get === expected.get && actual.set === expected.set);
}

function trustedNativePromise(value) {
  try {
    return reflectOwnKeys(value).length === 0
      && objectGetPrototypeOf(value) === nativePromisePrototype
      && sameDescriptor(
        objectGetOwnPropertyDescriptor(nativePromisePrototype, 'constructor'),
        nativePromiseConstructorDescriptor,
      )
      && sameDescriptor(
        objectGetOwnPropertyDescriptor(NativePromise, speciesSymbol),
        nativePromiseSpeciesDescriptor,
      );
  } catch {
    return false;
  }
}

function settleNativePromise(promise) {
  return new NativePromise((resolve) => {
    try {
      reflectApply(promiseThen, promise, [
        (value) => resolve(closedValue(value)),
        () => resolve(null),
      ]);
    } catch {
      resolve(null);
    }
  });
}

async function observeRetainedResult(retainedOutput, operation, args) {
  let candidate;
  try {
    candidate = reflectApply(
      operation,
      retainedOutput.receiver,
      args,
    );
  } catch {
    return null;
  }
  if (isProxy(candidate)) return null;
  let promise;
  try {
    promise = isPromise(candidate);
  } catch {
    return null;
  }
  return promise
    ? (trustedNativePromise(candidate) ? settleNativePromise(candidate) : null)
    : closedValue(candidate);
}

async function revalidate(retainedOutput) {
  const observed = await observeRetainedResult(
    retainedOutput,
    retainedOutput.revalidate,
    [],
  );
  return observed !== null && isNullPass(observed.value);
}

export function createSameSessionSourceArtifactPublisher({ artifactUploadHost, limits } = {}) {
  if (!validLimits(limits)) {
    throw new TypeError('Same-session publisher requires a controller-owned upload host and limits.');
  }
  let active = false;
  let publisher;
  let publicationPublisherAuthority;

  async function streamValidatedArtifact(lease) {
    const publication = consumePublicationLease(
      publicationPublisherAuthority,
      lease,
      publisher,
    );
    if (publication === null) return result('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
    if (active) return result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
    active = true;
    let token = null;
    try {
      token = await artifactUploadHost.openArtifact(Object.freeze({
        artifactManifestDigest: publication.artifactManifestDigest,
        artifactName: publication.artifactName,
        memberCount: publication.members.length,
      }));
      if (token === null) return result('BLOCKED', 'ARTIFACT_CLEANUP_INCOMPLETE');

      let failure = null;
      let totalBytes = 0;
      for (let memberIndex = 0; memberIndex < publication.members.length; memberIndex += 1) {
        const member = publication.members[memberIndex];
        if (member.sizeBytes > limits.maxMemberBytes || totalBytes + member.sizeBytes > limits.maxArtifactBytes) {
          failure = result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
          break;
        }
        let offset = 0;
        const hash = createHash('sha256');
        while (offset < member.sizeBytes) {
          const length = nativeMin(limits.maxChunkBytes, member.sizeBytes - offset);
          if (!(await revalidate(publication.retainedOutput))) {
            failure = result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
            break;
          }
          const observed = await observeRetainedResult(
            publication.retainedOutput,
            publication.retainedOutput.readMember,
            [Object.freeze({ length, offset, relativePath: member.relativePath })],
          );
          const bytes = observed === null ? null : passBytes(observed.value, length);
          if (bytes === null || !(await revalidate(publication.retainedOutput))) {
            failure = result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
            break;
          }
          if (!(await artifactUploadHost.writeMemberChunk(token, Object.freeze({
            bytes,
            endOfArtifact: offset + length === member.sizeBytes && memberIndex === publication.members.length - 1,
            endOfMember: offset + length === member.sizeBytes,
            memberId: member.memberId,
            offset,
          })))) {
            failure = result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
            break;
          }
          reflectApply(hashUpdate, hash, [bytes]);
          offset += length;
        }
        if (failure !== null) break;
        if (`sha256:${reflectApply(hashDigest, hash, ['hex'])}` !== member.transportDigest) {
          failure = result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
          break;
        }
        totalBytes += member.sizeBytes;
      }

      if (failure === null) {
        const completed = await artifactUploadHost.complete(token);
        if (
          completed
          && completePublicationLease(publicationPublisherAuthority, lease, publisher)
        ) return PASS_NULL;
        failure = result('FAIL', 'ARTIFACT_PUBLICATION_FAILED');
      }

      let clean = false;
      try { clean = await artifactUploadHost.abortAndJoin(token); } catch { clean = false; }
      return clean ? failure : result('BLOCKED', 'ARTIFACT_CLEANUP_INCOMPLETE');
    } catch {
      if (token === null) return result('BLOCKED', 'ARTIFACT_CLEANUP_INCOMPLETE');
      let clean = false;
      try { clean = await artifactUploadHost.abortAndJoin(token); } catch { clean = false; }
      return clean
        ? result('FAIL', 'ARTIFACT_PUBLICATION_FAILED')
        : result('BLOCKED', 'ARTIFACT_CLEANUP_INCOMPLETE');
    } finally {
      active = false;
    }
  }

  publisher = Object.freeze({ streamValidatedArtifact });
  publicationPublisherAuthority = claimSameSessionSourceArtifactUploadHost(
    artifactUploadHost,
    publisher,
  );
  if (publicationPublisherAuthority === null) {
    throw new TypeError('Same-session publisher requires a controller-owned upload host and limits.');
  }
  return publisher;
}
