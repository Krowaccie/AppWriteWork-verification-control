import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from './canonical-json.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ATTESTATION_KEYS = Object.freeze([
  'executionObservationPolicyDigest',
  'expiresAtEpochSeconds',
  'hostedSetupReadbackDigest',
  'issuedAtEpochSeconds',
  'primaryExecutionRetentionMaxSeconds',
  'providerSetupReadbackDigest',
  'schemaVersion',
]);
const ARGUMENT_KEYS = Object.freeze([
  'attestation',
  'attestationDigest',
  'clock',
  'expectedExecutionObservationPolicyDigest',
  'expectedHostedSetupReadbackDigest',
  'expectedPrimaryExecutionRetentionMaxSeconds',
  'expectedProviderSetupReadbackDigest',
]);

function exactDataObject(value, keys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return null;
    const names = Object.getOwnPropertyNames(value).sort();
    const expected = [...keys].sort();
    if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
      return null;
    }
    const snapshot = {};
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
        return null;
      }
      snapshot[name] = descriptor.value;
    }
    return snapshot;
  } catch {
    return null;
  }
}

function digestJson(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function result(status, value, code = null) {
  return Object.freeze({
    status,
    value,
    diagnostics: code === null ? Object.freeze([]) : Object.freeze([Object.freeze({
      code,
      retryable: false,
      safeMessage: code === 'TEST_HOSTED_SETUP_ATTESTATION_STALE'
        ? 'Hosted test-cloud setup attestation is outside its validity window.'
        : 'Hosted test-cloud setup attestation is invalid or untrusted.',
    })]),
  });
}

export function validateTestCloudHostedSetupAttestationDocument(args) {
  try {
    const input = exactDataObject(args, ARGUMENT_KEYS);
    const attestation = input === null ? null : exactDataObject(
      input.attestation,
      ATTESTATION_KEYS,
    );
    if (
      input === null
      || attestation === null
      || attestation.schemaVersion !== 'test-cloud.hosted-setup-attestation.v1'
      || !DIGEST.test(input.attestationDigest ?? '')
      || digestJson(attestation) !== input.attestationDigest
      || !DIGEST.test(input.expectedProviderSetupReadbackDigest ?? '')
      || !DIGEST.test(input.expectedHostedSetupReadbackDigest ?? '')
      || !DIGEST.test(input.expectedExecutionObservationPolicyDigest ?? '')
      || attestation.providerSetupReadbackDigest !== input.expectedProviderSetupReadbackDigest
      || attestation.hostedSetupReadbackDigest !== input.expectedHostedSetupReadbackDigest
      || attestation.executionObservationPolicyDigest
        !== input.expectedExecutionObservationPolicyDigest
      || !Number.isSafeInteger(input.expectedPrimaryExecutionRetentionMaxSeconds)
      || input.expectedPrimaryExecutionRetentionMaxSeconds < 1
      || input.expectedPrimaryExecutionRetentionMaxSeconds > 86_400
      || attestation.primaryExecutionRetentionMaxSeconds
        !== input.expectedPrimaryExecutionRetentionMaxSeconds
      || !Number.isSafeInteger(attestation.issuedAtEpochSeconds)
      || !Number.isSafeInteger(attestation.expiresAtEpochSeconds)
      || attestation.issuedAtEpochSeconds < 0
      || attestation.expiresAtEpochSeconds < 0
      || attestation.issuedAtEpochSeconds >= attestation.expiresAtEpochSeconds
      || typeof input.clock?.nowEpochSeconds !== 'function'
    ) return result('BLOCKED', null, 'TEST_HOSTED_SETUP_ATTESTATION_INVALID');
    const now = Reflect.apply(input.clock.nowEpochSeconds, input.clock, []);
    if (
      !Number.isSafeInteger(now)
      || now < 0
      || attestation.issuedAtEpochSeconds > now
      || now >= attestation.expiresAtEpochSeconds
    ) return result('BLOCKED', null, 'TEST_HOSTED_SETUP_ATTESTATION_STALE');
    return result('PASS', Object.freeze({ ...attestation }));
  } catch {
    return result('BLOCKED', null, 'TEST_HOSTED_SETUP_ATTESTATION_INVALID');
  }
}
