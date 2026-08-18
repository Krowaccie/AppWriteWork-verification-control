const REDACTED_DIAGNOSTIC = Object.freeze({
  code: 'REDACTED_ERROR',
  path: 'verification',
  message: 'Verification failed with a redacted error.',
});

const SAFE_DIAGNOSTICS = Object.freeze({
  ADAPTER_CONTRACT_INVALID: Object.freeze({
    code: 'ADAPTER_CONTRACT_INVALID',
    path: 'adapter',
    message: 'Verification adapter contract is invalid.',
  }),
  BUILD_REVISION_BLOCKED: Object.freeze({
    code: 'BUILD_REVISION_BLOCKED',
    path: 'candidateRevision',
    message: 'An immutable candidate revision is required.',
  }),
  CHECK_BLOCKED: Object.freeze({
    code: 'CHECK_BLOCKED',
    path: 'checks',
    message: 'Verification check blocked.',
  }),
  CHECK_FAILED: Object.freeze({
    code: 'CHECK_FAILED',
    path: 'checks',
    message: 'Verification check failed.',
  }),
  CHECK_TIMEOUT: Object.freeze({
    code: 'CHECK_TIMEOUT',
    path: 'checks',
    message: 'Verification check timed out.',
  }),
  EVIDENCE_OUTPUT_UNSAFE: Object.freeze({
    code: 'EVIDENCE_OUTPUT_UNSAFE',
    path: 'evidence',
    message: 'Verification evidence output is not safely contained.',
  }),
  EVIDENCE_SCHEMA_INVALID: Object.freeze({
    code: 'EVIDENCE_SCHEMA_INVALID',
    path: 'evidence',
    message: 'Verification evidence does not match the required schema.',
  }),
  EVIDENCE_WRITE_BLOCKED: Object.freeze({
    code: 'EVIDENCE_WRITE_BLOCKED',
    path: 'evidence',
    message: 'Verification evidence could not be written safely.',
  }),
  LOCAL_COMMAND_BLOCKED: Object.freeze({
    code: 'LOCAL_COMMAND_BLOCKED',
    path: 'local',
    message: 'Local verification command was blocked.',
  }),
  LOCAL_COMMAND_FAILED: Object.freeze({
    code: 'LOCAL_COMMAND_FAILED',
    path: 'local',
    message: 'Local verification command failed.',
  }),
  LOCAL_PREFLIGHT_BLOCKED: Object.freeze({
    code: 'LOCAL_PREFLIGHT_BLOCKED',
    path: 'local',
    message: 'Local verification preflight was blocked.',
  }),
  REDACTED_ERROR: REDACTED_DIAGNOSTIC,
});

function readPlainDataCode(value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return null;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'code');
    return descriptor && 'value' in descriptor && typeof descriptor.value === 'string'
      ? descriptor.value
      : null;
  } catch {
    return null;
  }
}

function copyDiagnostic(diagnostic) {
  return {
    code: diagnostic.code,
    path: diagnostic.path,
    message: diagnostic.message,
  };
}

export function redactSafeDiagnostic(value) {
  const code = readPlainDataCode(value);
  const safe = code !== null && Object.hasOwn(SAFE_DIAGNOSTICS, code)
    ? SAFE_DIAGNOSTICS[code]
    : undefined;
  return copyDiagnostic(safe ?? REDACTED_DIAGNOSTIC);
}
