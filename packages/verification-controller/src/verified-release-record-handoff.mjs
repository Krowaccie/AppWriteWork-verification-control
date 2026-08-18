import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import {
  validateProductionReleaseBinding,
  validateReleaseRecord,
} from './release-record-contract.mjs';

const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const PRODUCER_WORKFLOW = 'Production Readonly';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[1-9][0-9]*$/;
const SHA = /^[0-9a-f]{40}$/;
const HANDOFF_KEYS = Object.freeze([
  'controller',
  'handoffDigest',
  'producer',
  'releaseBinding',
  'releaseRecord',
  'schemaVersion',
].sort());
const CONTROLLER_KEYS = Object.freeze([
  'artifactId',
  'bundleDigest',
  'repository',
  'revision',
].sort());
const PRODUCER_KEYS = Object.freeze([
  'repository',
  'runAttempt',
  'runId',
  'workflow',
].sort());

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function snapshotCanonicalData(value, seen = new WeakSet()) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (value === null || typeof value !== 'object' || utilTypes.isProxy(value) || seen.has(value)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  }
  seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
    }
    const keys = Reflect.ownKeys(value);
    const expected = [
      ...Array.from({ length: value.length }, (_, index) => String(index)),
      'length',
    ];
    if (keys.length !== expected.length || expected.some((key) => !keys.includes(key))) {
      throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || lengthDescriptor.enumerable || !Object.hasOwn(lengthDescriptor, 'value')) {
      throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
    }
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
      }
      copy.push(snapshotCanonicalData(descriptor.value, seen));
    }
    return copy;
  }

  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  }
  const copy = {};
  for (const key of [...keys].sort(ordinal)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
    }
    Object.defineProperty(copy, key, {
      configurable: true,
      enumerable: true,
      value: snapshotCanonicalData(descriptor.value, seen),
      writable: true,
    });
  }
  return copy;
}

function exactKeys(value, expected) {
  return JSON.stringify(Object.keys(value).sort(ordinal)) === JSON.stringify(expected);
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort(ordinal).map(
    (key) => `${JSON.stringify(key)}:${canonical(value[key])}`,
  ).join(',')}}`;
}

function digestCore(snapshot) {
  const core = { ...snapshot };
  delete core.handoffDigest;
  return `sha256:${createHash('sha256').update(canonical(core), 'utf8').digest('hex')}`;
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) deepFreeze(descriptor.value, seen);
  }
  return Object.freeze(value);
}

function assertInternal(snapshot) {
  if (!exactKeys(snapshot, HANDOFF_KEYS)
      || snapshot.schemaVersion !== 'verified-release-record-handoff.v1'
      || !DIGEST.test(snapshot.handoffDigest ?? '')
      || !exactKeys(snapshot.controller ?? {}, CONTROLLER_KEYS)
      || snapshot.controller.repository !== CONTROLLER_REPOSITORY
      || !SHA.test(snapshot.controller.revision ?? '')
      || !ID.test(snapshot.controller.artifactId ?? '')
      || !DIGEST.test(snapshot.controller.bundleDigest ?? '')
      || !exactKeys(snapshot.producer ?? {}, PRODUCER_KEYS)
      || snapshot.producer.repository !== CONTROLLER_REPOSITORY
      || snapshot.producer.workflow !== PRODUCER_WORKFLOW
      || !ID.test(snapshot.producer.runId ?? '')
      || !Number.isSafeInteger(snapshot.producer.runAttempt)
      || snapshot.producer.runAttempt < 1) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  }

  try {
    validateProductionReleaseBinding(snapshot.releaseBinding);
    validateReleaseRecord(snapshot.releaseRecord);
  } catch {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  }
  const binding = snapshot.releaseBinding;
  const record = snapshot.releaseRecord;
  if (binding.repository !== snapshot.controller.repository
      || binding.repository !== snapshot.producer.repository
      || binding.recordDigest !== record.recordDigest
      || binding.revision !== record.sourceRevision
      || binding.artifactManifestDigest !== record.artifactManifestDigest
      || binding.repository !== record.github.repository
      || binding.workflow !== record.github.workflow
      || binding.runId !== record.github.runId
      || binding.runAttempt !== record.github.runAttempt
      || binding.environment !== record.github.environment) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  }
  if (snapshot.handoffDigest !== digestCore(snapshot)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_DIGEST_MISMATCH');
  }
}

function validateExpected(value, keys) {
  const snapshot = snapshotCanonicalData(value);
  if (!exactKeys(snapshot, keys)) throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_INVALID');
  return snapshot;
}

export function buildVerifiedReleaseRecordHandoff({
  controller,
  producer,
  releaseBinding,
  releaseRecord,
} = {}) {
  const core = snapshotCanonicalData({
    schemaVersion: 'verified-release-record-handoff.v1',
    controller,
    producer,
    releaseBinding,
    releaseRecord,
  });
  const handoff = { ...core, handoffDigest: digestCore(core) };
  const snapshot = snapshotCanonicalData(handoff);
  assertInternal(snapshot);
  return deepFreeze(snapshot);
}

export function validateVerifiedReleaseRecordHandoff({
  handoff,
  expectedController,
  expectedProducer,
} = {}) {
  const snapshot = snapshotCanonicalData(handoff);
  assertInternal(snapshot);
  const controller = validateExpected(expectedController, CONTROLLER_KEYS);
  const producer = validateExpected(expectedProducer, PRODUCER_KEYS);
  if (canonical(snapshot.controller) !== canonical(controller)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_CONTROLLER_MISMATCH');
  }
  if (canonical(snapshot.producer) !== canonical(producer)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_PRODUCER_MISMATCH');
  }
  return deepFreeze(snapshot);
}

export function canonicalVerifiedReleaseRecordHandoffBytes(handoff) {
  const snapshot = snapshotCanonicalData(handoff);
  assertInternal(snapshot);
  return Buffer.from(`${canonical(snapshot)}\n`, 'utf8');
}

export function parseVerifiedReleaseRecordHandoffBytes({
  bytes,
  expectedController,
  expectedProducer,
} = {}) {
  if (!(bytes instanceof Uint8Array)) {
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_BYTES_INVALID');
  }
  try {
    const snapshotBytes = Buffer.from(bytes);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(snapshotBytes);
    const parsed = JSON.parse(text);
    const snapshot = snapshotCanonicalData(parsed);
    const expectedBytes = Buffer.from(`${canonical(snapshot)}\n`, 'utf8');
    if (!snapshotBytes.equals(expectedBytes)) {
      throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_BYTES_INVALID');
    }
    validateVerifiedReleaseRecordHandoff({
      handoff: snapshot,
      expectedController,
      expectedProducer,
    });
    return deepFreeze(snapshot);
  } catch (error) {
    if (error?.code === 'VERIFIED_RELEASE_RECORD_HANDOFF_CONTROLLER_MISMATCH'
        || error?.code === 'VERIFIED_RELEASE_RECORD_HANDOFF_PRODUCER_MISMATCH'
        || error?.code === 'VERIFIED_RELEASE_RECORD_HANDOFF_DIGEST_MISMATCH') throw error;
    throw blocked('VERIFIED_RELEASE_RECORD_HANDOFF_BYTES_INVALID');
  }
}
