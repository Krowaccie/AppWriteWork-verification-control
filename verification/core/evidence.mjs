import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { redactSafeDiagnostic } from './redaction.mjs';

const INPUT_KEYS = Object.freeze([
  'bootstrapQualification',
  'candidateArtifactDigest',
  'candidateRevision',
  'candidateSourceTreeDigest',
  'checks',
  'cleanup',
  'completedAt',
  'deploymentReadback',
  'environmentClass',
  'environmentIdentityDigest',
  'lane',
  'manifestDigest',
  'observedDeployment',
  'selectedChecks',
  'startedAt',
  'verifierRevision',
]);

const RESULT_KEYS = Object.freeze([
  ...INPUT_KEYS,
  'evidenceDigest',
  'resultId',
  'schemaVersion',
  'status',
].sort());

const CHECK_KEYS = Object.freeze([
  'attempts',
  'checkId',
  'completedAt',
  'diagnostics',
  'durationMs',
  'startedAt',
  'status',
]);

const DIAGNOSTIC_KEYS = Object.freeze(['code', 'message', 'path']);
const OBSERVED_DEPLOYMENT_KEYS = Object.freeze([
  'artifactDigest',
  'readbackSource',
  'releaseRecordDigest',
  'releaseRecordId',
  'revision',
]);
const BOOTSTRAP_KEYS = Object.freeze(['bundleDigest', 'status', 'verifierRevision']);
const READBACK_KEYS = Object.freeze(['diagnostics', 'status']);
const CLEANUP_KEYS = Object.freeze([
  'absenceProven',
  'diagnostics',
  'ownedResourceCount',
  'removedResourceCount',
  'status',
]);

const STATUS_VALUES = Object.freeze(['BLOCKED', 'FAIL', 'PASS']);
const LANE_ENVIRONMENT = Object.freeze({
  local: 'local',
  'production-readonly': 'production',
  'test-cloud': 'test',
});
const READBACK_SOURCES = Object.freeze([
  'appwrite-deployment',
  'none',
  'public-build-identity',
]);

const ID_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const DIAGNOSTIC_CODE_PATTERN = /^[A-Z][A-Z0-9_]*$/;
const RELEASE_RECORD_ID_PATTERN = /^[1-9][0-9]*$/;
const SECRET_MARKER_PATTERN = /(?:Bearer\s|(?:token|secret|authorization|api[_-]?key)\s*[:=]|\bgh[pousr]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{16,}|\bstandard_[A-Za-z0-9_-]{20,})/iu;
const SCHEMA_ERROR_MESSAGE = 'Verification evidence does not match the required schema.';

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function ownStringKeys(value) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) return null;
  return keys.sort(lexicalCompare);
}

function hasExactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = ownStringKeys(value);
  return actual !== null &&
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]) &&
    actual.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}

function isClosedArray(value) {
  if (!Array.isArray(value) || utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const expected = [
    ...Array.from({ length: value.length }, (_, index) => String(index)),
    'length',
  ];
  if (keys.length !== expected.length || expected.some((key) => !keys.includes(key))) return false;
  return expected.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value') &&
      (key === 'length'
        ? descriptor.enumerable === false
        : descriptor.enumerable === true);
  });
}

function snapshotCanonicalData(value, ancestors = new Set()) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (value === null || typeof value !== 'object' || ancestors.has(value)) {
    throw schemaInputError();
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    if (!isClosedArray(value)) throw schemaInputError();
    const snapshot = [];
    for (let index = 0; index < value.length; index += 1) {
      snapshot.push(snapshotCanonicalData(
        Object.getOwnPropertyDescriptor(value, String(index)).value,
        ancestors,
      ));
    }
    ancestors.delete(value);
    return snapshot;
  }
  if (!isRecord(value)) throw schemaInputError();
  const keys = ownStringKeys(value);
  if (keys === null || keys.some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value');
  })) throw schemaInputError();
  const snapshot = Object.create(null);
  for (const key of keys) {
    Object.defineProperty(snapshot, key, {
      enumerable: true,
      configurable: true,
      writable: true,
      value: snapshotCanonicalData(
        Object.getOwnPropertyDescriptor(value, key).value,
        ancestors,
      ),
    });
  }
  ancestors.delete(value);
  return snapshot;
}

function containsSecretMarker(value) {
  if (typeof value === 'string') return SECRET_MARKER_PATTERN.test(value);
  if (Array.isArray(value)) return value.some(containsSecretMarker);
  if (value !== null && typeof value === 'object') {
    return Object.values(value).some(containsSecretMarker);
  }
  return false;
}

function canonicalJson(value, ancestors = new Set()) {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError('cyclic value');
    ancestors.add(value);
    const serialized = `[${value.map((entry) => canonicalJson(entry, ancestors)).join(',')}]`;
    ancestors.delete(value);
    return serialized;
  }
  if (typeof value === 'object') {
    if (ancestors.has(value)) throw new TypeError('cyclic value');
    ancestors.add(value);
    const serialized = `{${Object.keys(value)
      .sort(lexicalCompare)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], ancestors)}`)
      .join(',')}}`;
    ancestors.delete(value);
    return serialized;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError('non-finite number');
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError('non-JSON value');
  return serialized;
}

function digestCanonical(value) {
  const hex = createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
  return `sha256:${hex}`;
}

function diagnosticKey(value) {
  return `${value.path}\0${value.code}\0${value.message}`;
}

function compareDiagnostics(left, right) {
  return lexicalCompare(diagnosticKey(left), diagnosticKey(right));
}

function uniqueSortedDiagnostics(diagnostics) {
  const sorted = [...diagnostics].sort(compareDiagnostics);
  return sorted.filter(
    (diagnostic, index) => index === 0 || diagnosticKey(diagnostic) !== diagnosticKey(sorted[index - 1]),
  );
}

function normalizeDiagnostics(values) {
  return uniqueSortedDiagnostics(values.map((value) => redactSafeDiagnostic(value)));
}

function deriveStatus({ lane, checks, bootstrapQualification, deploymentReadback, cleanup }) {
  const statuses = [
    ...checks.map(({ status }) => status),
    bootstrapQualification.status,
    deploymentReadback.status,
    cleanup.status,
  ];
  const cleanupDebt = cleanup.ownedResourceCount > cleanup.removedResourceCount;
  const cleanupUnproven = cleanup.absenceProven !== true &&
    (cleanup.status === 'PASS' || lane !== 'local');
  if (statuses.includes('BLOCKED') || cleanupDebt || cleanupUnproven) return 'BLOCKED';
  if (statuses.includes('FAIL')) return 'FAIL';
  return 'PASS';
}

function schemaInputError() {
  const error = new TypeError(SCHEMA_ERROR_MESSAGE);
  error.code = 'EVIDENCE_SCHEMA_INVALID';
  return error;
}

function assertCreatorShape(input) {
  if (!hasExactKeys(input, INPUT_KEYS)) throw schemaInputError();
  if (!isClosedArray(input.selectedChecks) ||
      input.selectedChecks.some((value) => typeof value !== 'string')) {
    throw schemaInputError();
  }
  if (!isClosedArray(input.checks)) throw schemaInputError();
  for (const check of input.checks) {
    if (!hasExactKeys(check, CHECK_KEYS) ||
        typeof check.checkId !== 'string' ||
        !isClosedArray(check.diagnostics)) {
      throw schemaInputError();
    }
  }
  if (!hasExactKeys(input.observedDeployment, OBSERVED_DEPLOYMENT_KEYS) ||
      !hasExactKeys(input.bootstrapQualification, BOOTSTRAP_KEYS) ||
      !hasExactKeys(input.deploymentReadback, READBACK_KEYS) ||
      !hasExactKeys(input.cleanup, CLEANUP_KEYS) ||
      !isClosedArray(input.deploymentReadback.diagnostics) ||
      !isClosedArray(input.cleanup.diagnostics)) {
    throw schemaInputError();
  }
}

function copyCheck(check) {
  return {
    checkId: check.checkId,
    status: check.status,
    startedAt: check.startedAt,
    completedAt: check.completedAt,
    durationMs: check.durationMs,
    attempts: check.attempts,
    diagnostics: normalizeDiagnostics(check.diagnostics),
  };
}

function buildVerificationResult(input) {
  assertCreatorShape(input);

  const selectedChecks = [...new Set(input.selectedChecks)].sort(lexicalCompare);
  const checks = input.checks.map(copyCheck).sort((left, right) =>
    lexicalCompare(left.checkId, right.checkId));
  if (checks.some((check, index) => index > 0 && check.checkId === checks[index - 1].checkId)) {
    throw schemaInputError();
  }

  const observedDeployment = {
    revision: input.observedDeployment.revision,
    artifactDigest: input.observedDeployment.artifactDigest,
    releaseRecordId: input.observedDeployment.releaseRecordId,
    releaseRecordDigest: input.observedDeployment.releaseRecordDigest,
    readbackSource: input.observedDeployment.readbackSource,
  };
  const bootstrapQualification = {
    verifierRevision: input.bootstrapQualification.verifierRevision,
    bundleDigest: input.bootstrapQualification.bundleDigest,
    status: input.bootstrapQualification.status,
  };
  const deploymentReadback = {
    status: input.deploymentReadback.status,
    diagnostics: normalizeDiagnostics(input.deploymentReadback.diagnostics),
  };
  const cleanup = {
    status: input.cleanup.status,
    ownedResourceCount: input.cleanup.ownedResourceCount,
    removedResourceCount: input.cleanup.removedResourceCount,
    absenceProven: input.cleanup.absenceProven,
    diagnostics: normalizeDiagnostics(input.cleanup.diagnostics),
  };

  const status = deriveStatus({
    lane: input.lane,
    checks,
    bootstrapQualification,
    deploymentReadback,
    cleanup,
  });
  const payload = {
    schemaVersion: 1,
    verifierRevision: input.verifierRevision,
    candidateRevision: input.candidateRevision,
    candidateSourceTreeDigest: input.candidateSourceTreeDigest,
    candidateArtifactDigest: input.candidateArtifactDigest,
    manifestDigest: input.manifestDigest,
    lane: input.lane,
    environmentClass: input.environmentClass,
    environmentIdentityDigest: input.environmentIdentityDigest,
    selectedChecks,
    checks,
    status,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    observedDeployment,
    bootstrapQualification,
    deploymentReadback,
    cleanup,
  };
  const digest = digestCanonical(payload);
  const result = {
    schemaVersion: 1,
    resultId: digest,
    verifierRevision: payload.verifierRevision,
    candidateRevision: payload.candidateRevision,
    candidateSourceTreeDigest: payload.candidateSourceTreeDigest,
    candidateArtifactDigest: payload.candidateArtifactDigest,
    manifestDigest: payload.manifestDigest,
    lane: payload.lane,
    environmentClass: payload.environmentClass,
    environmentIdentityDigest: payload.environmentIdentityDigest,
    selectedChecks: payload.selectedChecks,
    checks: payload.checks,
    status: payload.status,
    startedAt: payload.startedAt,
    completedAt: payload.completedAt,
    observedDeployment: payload.observedDeployment,
    bootstrapQualification: payload.bootstrapQualification,
    deploymentReadback: payload.deploymentReadback,
    cleanup: payload.cleanup,
    evidenceDigest: digest,
  };

  const validation = validateVerificationResult(result);
  if (!validation.ok) throw schemaInputError();
  return result;
}

export function createVerificationResult(input) {
  try {
    return buildVerificationResult(input);
  } catch (error) {
    if (error?.code === 'EVIDENCE_SCHEMA_INVALID' && error?.message === SCHEMA_ERROR_MESSAGE) {
      throw error;
    }
    throw schemaInputError();
  }
}

function validationError(path) {
  return {
    code: 'EVIDENCE_SCHEMA_INVALID',
    path,
    message: SCHEMA_ERROR_MESSAGE,
  };
}

function addError(errors, path) {
  errors.push(validationError(path));
}

function isStatus(value) {
  return STATUS_VALUES.includes(value);
}

function isNullableStatus(value) {
  return value === null || isStatus(value);
}

function isDigest(value) {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function isNullableDigest(value) {
  return value === null || isDigest(value);
}

function isGitSha(value) {
  return typeof value === 'string' && SHA_PATTERN.test(value);
}

function isNullableGitSha(value) {
  return value === null || isGitSha(value);
}

function isTimestamp(value) {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function validateRecord(value, keys, path, errors) {
  if (!hasExactKeys(value, keys)) {
    addError(errors, path);
    return false;
  }
  return true;
}

function validateDiagnostics(value, path, errors) {
  if (!isClosedArray(value)) {
    addError(errors, path);
    return;
  }

  let previousKey = null;
  value.forEach((diagnostic, index) => {
    const itemPath = `${path}[${index}]`;
    if (!validateRecord(diagnostic, DIAGNOSTIC_KEYS, itemPath, errors)) return;
    if (typeof diagnostic.code !== 'string' || !DIAGNOSTIC_CODE_PATTERN.test(diagnostic.code) ||
        typeof diagnostic.path !== 'string' || diagnostic.path.length > 512 ||
        typeof diagnostic.message !== 'string' || diagnostic.message.length > 512) {
      addError(errors, itemPath);
      return;
    }
    const canonical = redactSafeDiagnostic(diagnostic);
    if (canonical.code !== diagnostic.code ||
        canonical.path !== diagnostic.path ||
        canonical.message !== diagnostic.message) {
      addError(errors, itemPath);
    }
    const key = diagnosticKey(diagnostic);
    if (previousKey !== null && lexicalCompare(previousKey, key) >= 0) {
      addError(errors, path);
    }
    previousKey = key;
  });
}

function validateChecks(value, selectedChecks, errors) {
  if (!isClosedArray(value)) {
    addError(errors, 'checks');
    return [];
  }

  const ids = [];
  let previousId = null;
  value.forEach((check, index) => {
    const itemPath = `checks[${index}]`;
    if (!validateRecord(check, CHECK_KEYS, itemPath, errors)) return;
    ids.push(check.checkId);
    if (typeof check.checkId !== 'string' || !ID_PATTERN.test(check.checkId)) {
      addError(errors, `${itemPath}.checkId`);
    }
    if (previousId !== null && lexicalCompare(previousId, check.checkId) >= 0) {
      addError(errors, 'checks');
    }
    previousId = check.checkId;
    if (!isStatus(check.status)) addError(errors, `${itemPath}.status`);
    if (!isTimestamp(check.startedAt)) addError(errors, `${itemPath}.startedAt`);
    if (!isTimestamp(check.completedAt)) addError(errors, `${itemPath}.completedAt`);
    if (isTimestamp(check.startedAt) && isTimestamp(check.completedAt) &&
        Date.parse(check.completedAt) < Date.parse(check.startedAt)) {
      addError(errors, itemPath);
    }
    if (!Number.isInteger(check.durationMs) || check.durationMs < 0) {
      addError(errors, `${itemPath}.durationMs`);
    }
    if (!Number.isInteger(check.attempts) || check.attempts < 0 || check.attempts > 4) {
      addError(errors, `${itemPath}.attempts`);
    }
    validateDiagnostics(check.diagnostics, `${itemPath}.diagnostics`, errors);
  });

  if (isClosedArray(selectedChecks) &&
      (ids.length !== selectedChecks.length || ids.some((id, index) => id !== selectedChecks[index]))) {
    addError(errors, 'selectedChecks');
  }
  return value;
}

function validateSelectedChecks(value, errors) {
  if (!isClosedArray(value)) {
    addError(errors, 'selectedChecks');
    return;
  }
  let previous = null;
  value.forEach((id, index) => {
    if (typeof id !== 'string' || !ID_PATTERN.test(id)) {
      addError(errors, `selectedChecks[${index}]`);
      return;
    }
    if (previous !== null && lexicalCompare(previous, id) >= 0) {
      addError(errors, 'selectedChecks');
    }
    previous = id;
  });
}

function validateObservedDeployment(value, errors) {
  if (!validateRecord(value, OBSERVED_DEPLOYMENT_KEYS, 'observedDeployment', errors)) return;
  if (!isNullableGitSha(value.revision)) addError(errors, 'observedDeployment.revision');
  if (!isNullableDigest(value.artifactDigest)) addError(errors, 'observedDeployment.artifactDigest');
  if (!(value.releaseRecordId === null ||
        (typeof value.releaseRecordId === 'string' &&
          RELEASE_RECORD_ID_PATTERN.test(value.releaseRecordId)))) {
    addError(errors, 'observedDeployment.releaseRecordId');
  }
  if (!isNullableDigest(value.releaseRecordDigest)) {
    addError(errors, 'observedDeployment.releaseRecordDigest');
  }
  if (!READBACK_SOURCES.includes(value.readbackSource)) {
    addError(errors, 'observedDeployment.readbackSource');
  }
}

function validateBootstrap(value, errors) {
  if (!validateRecord(value, BOOTSTRAP_KEYS, 'bootstrapQualification', errors)) return;
  if (!isNullableGitSha(value.verifierRevision)) {
    addError(errors, 'bootstrapQualification.verifierRevision');
  }
  if (!isNullableDigest(value.bundleDigest)) addError(errors, 'bootstrapQualification.bundleDigest');
  if (!isNullableStatus(value.status)) addError(errors, 'bootstrapQualification.status');
}

function validateReadback(value, errors) {
  if (!validateRecord(value, READBACK_KEYS, 'deploymentReadback', errors)) return;
  if (!isNullableStatus(value.status)) addError(errors, 'deploymentReadback.status');
  validateDiagnostics(value.diagnostics, 'deploymentReadback.diagnostics', errors);
}

function validateCleanup(value, errors) {
  if (!validateRecord(value, CLEANUP_KEYS, 'cleanup', errors)) return;
  if (!isNullableStatus(value.status)) addError(errors, 'cleanup.status');
  if (!Number.isInteger(value.ownedResourceCount) || value.ownedResourceCount < 0) {
    addError(errors, 'cleanup.ownedResourceCount');
  }
  if (!Number.isInteger(value.removedResourceCount) || value.removedResourceCount < 0) {
    addError(errors, 'cleanup.removedResourceCount');
  } else if (Number.isInteger(value.ownedResourceCount) &&
      value.removedResourceCount > value.ownedResourceCount) {
    addError(errors, 'cleanup.removedResourceCount');
  }
  if (typeof value.absenceProven !== 'boolean') addError(errors, 'cleanup.absenceProven');
  validateDiagnostics(value.diagnostics, 'cleanup.diagnostics', errors);
}

function sortedUniqueErrors(errors) {
  return uniqueSortedDiagnostics(errors);
}

function validateVerificationResultInternal(value) {
  const errors = [];
  if (!isRecord(value)) {
    return { ok: false, errors: [validationError('verification')] };
  }
  if (!hasExactKeys(value, RESULT_KEYS)) addError(errors, 'verification');

  if (value.schemaVersion !== 1) addError(errors, 'schemaVersion');
  if (!isDigest(value.resultId)) addError(errors, 'resultId');
  if (!isGitSha(value.verifierRevision)) addError(errors, 'verifierRevision');
  if (!isNullableGitSha(value.candidateRevision)) addError(errors, 'candidateRevision');
  if (!isNullableDigest(value.candidateSourceTreeDigest)) {
    addError(errors, 'candidateSourceTreeDigest');
  }
  if (!isNullableDigest(value.candidateArtifactDigest)) {
    addError(errors, 'candidateArtifactDigest');
  }
  if (!isDigest(value.manifestDigest)) addError(errors, 'manifestDigest');
  if (!Object.hasOwn(LANE_ENVIRONMENT, value.lane)) addError(errors, 'lane');
  if (LANE_ENVIRONMENT[value.lane] !== value.environmentClass) {
    addError(errors, 'environmentClass');
  }
  if (!isDigest(value.environmentIdentityDigest)) addError(errors, 'environmentIdentityDigest');

  validateSelectedChecks(value.selectedChecks, errors);
  const checks = validateChecks(value.checks, value.selectedChecks, errors);
  if (!isStatus(value.status)) addError(errors, 'status');
  if (!isTimestamp(value.startedAt)) addError(errors, 'startedAt');
  if (!isTimestamp(value.completedAt)) addError(errors, 'completedAt');
  if (isTimestamp(value.startedAt) && isTimestamp(value.completedAt) &&
      Date.parse(value.completedAt) < Date.parse(value.startedAt)) {
    addError(errors, 'completedAt');
  }

  validateObservedDeployment(value.observedDeployment, errors);
  validateBootstrap(value.bootstrapQualification, errors);
  validateReadback(value.deploymentReadback, errors);
  validateCleanup(value.cleanup, errors);
  if (containsSecretMarker(value)) addError(errors, 'verification');

  if (Array.isArray(checks) && isRecord(value.bootstrapQualification) &&
      isRecord(value.deploymentReadback) && isRecord(value.cleanup)) {
    const expectedStatus = deriveStatus({
      lane: value.lane,
      checks,
      bootstrapQualification: value.bootstrapQualification,
      deploymentReadback: value.deploymentReadback,
      cleanup: value.cleanup,
    });
    if (value.status !== expectedStatus) addError(errors, 'status');
  }

  if (!isDigest(value.evidenceDigest)) addError(errors, 'evidenceDigest');
  if (errors.length === 0) {
    try {
      const payload = {};
      for (const [key, entry] of Object.entries(value)) {
        if (key !== 'resultId' && key !== 'evidenceDigest') payload[key] = entry;
      }
      const expectedDigest = digestCanonical(payload);
      if (value.resultId !== expectedDigest) addError(errors, 'resultId');
      if (value.evidenceDigest !== expectedDigest) addError(errors, 'evidenceDigest');
    } catch {
      addError(errors, 'evidenceDigest');
    }
  }

  const safeErrors = sortedUniqueErrors(errors);
  return safeErrors.length === 0
    ? { ok: true, errors: [] }
    : { ok: false, errors: safeErrors };
}

export function validateVerificationResult(value) {
  try {
    return validateVerificationResultInternal(snapshotCanonicalData(value));
  } catch {
    return { ok: false, errors: [validationError('verification')] };
  }
}

export function canonicalVerificationResultBytes(value) {
  let snapshot;
  try {
    snapshot = snapshotCanonicalData(value);
  } catch {
    throw schemaInputError();
  }
  const validation = validateVerificationResult(snapshot);
  if (!validation.ok) throw schemaInputError();
  if (containsSecretMarker(snapshot)) throw schemaInputError();
  try {
    return Buffer.from(`${canonicalJson(snapshot)}\n`, 'utf8');
  } catch {
    throw schemaInputError();
  }
}
