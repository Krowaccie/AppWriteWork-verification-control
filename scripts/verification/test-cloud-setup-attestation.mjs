import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from './canonical-json.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ATTESTATION_KEYS = Object.freeze([
  'credentialScopeReadbackDigest',
  'environmentDigest',
  'executionObservationPolicyDigest',
  'expiresAtEpochSeconds',
  'fixedLeaseIdentityDigest',
  'functionConfigurationsDigest',
  'globalCleanupReadbackDigest',
  'identityBindingsDigest',
  'issuedAtEpochSeconds',
  'primaryExecutionRetentionMaxSeconds',
  'projectReadbackDigest',
  'providerContractDigest',
  'providerSetupReadbackDigest',
  'runnerVariableReadbackDigest',
  'schemaVersion',
  'siteConfigurationDigest',
]);
const ARGUMENT_KEYS = Object.freeze([
  'attestation',
  'attestationDigest',
  'clock',
  'expectedEnvironmentDigest',
  'expectedIdentityBindingsDigest',
  'expectedPrimaryExecutionRetentionMaxSeconds',
  'expectedProviderContractDigest',
  'expectedProviderSetupReadbackDigest',
  'maximumRetentionSeconds',
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
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
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
      safeMessage: code === 'TEST_SETUP_ATTESTATION_STALE'
        ? 'Test-cloud setup attestation is outside its validity window.'
        : 'Test-cloud setup attestation is invalid or untrusted.',
    })]),
  });
}

export function validateTestCloudSetupAttestationDocument(args) {
  try {
    const input = exactDataObject(args, ARGUMENT_KEYS);
    const attestation = input === null ? null : exactDataObject(input.attestation, ATTESTATION_KEYS);
    if (
      input === null
      || attestation === null
      || attestation.schemaVersion !== 'test-cloud-setup-attestation.v1'
      || !DIGEST.test(input.attestationDigest ?? '')
      || digestJson(attestation) !== input.attestationDigest
      || !ATTESTATION_KEYS.filter((key) => key.endsWith('Digest'))
        .every((key) => DIGEST.test(attestation[key] ?? ''))
      || !DIGEST.test(input.expectedEnvironmentDigest ?? '')
      || !DIGEST.test(input.expectedProviderContractDigest ?? '')
      || !DIGEST.test(input.expectedIdentityBindingsDigest ?? '')
      || !DIGEST.test(input.expectedProviderSetupReadbackDigest ?? '')
      || attestation.environmentDigest !== input.expectedEnvironmentDigest
      || attestation.providerContractDigest !== input.expectedProviderContractDigest
      || attestation.identityBindingsDigest !== input.expectedIdentityBindingsDigest
      || attestation.providerSetupReadbackDigest !== input.expectedProviderSetupReadbackDigest
      || !Number.isSafeInteger(input.expectedPrimaryExecutionRetentionMaxSeconds)
      || !Number.isSafeInteger(input.maximumRetentionSeconds)
      || input.maximumRetentionSeconds < 1
      || attestation.primaryExecutionRetentionMaxSeconds
        !== input.expectedPrimaryExecutionRetentionMaxSeconds
      || attestation.primaryExecutionRetentionMaxSeconds < 1
      || attestation.primaryExecutionRetentionMaxSeconds > input.maximumRetentionSeconds
      || !Number.isSafeInteger(attestation.issuedAtEpochSeconds)
      || !Number.isSafeInteger(attestation.expiresAtEpochSeconds)
      || attestation.issuedAtEpochSeconds < 0
      || attestation.expiresAtEpochSeconds < 0
      || attestation.issuedAtEpochSeconds >= attestation.expiresAtEpochSeconds
      || typeof input.clock?.nowEpochSeconds !== 'function'
    ) return result('BLOCKED', null, 'TEST_SETUP_ATTESTATION_INVALID');
    const now = Reflect.apply(input.clock.nowEpochSeconds, input.clock, []);
    if (
      !Number.isSafeInteger(now)
      || now < 0
      || attestation.issuedAtEpochSeconds > now
      || now >= attestation.expiresAtEpochSeconds
    ) return result('BLOCKED', null, 'TEST_SETUP_ATTESTATION_STALE');
    return result('PASS', Object.freeze({ ...attestation }));
  } catch {
    return result('BLOCKED', null, 'TEST_SETUP_ATTESTATION_INVALID');
  }
}
