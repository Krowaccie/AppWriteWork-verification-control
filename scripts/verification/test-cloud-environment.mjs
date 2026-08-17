import { types as utilTypes } from 'node:util';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import { readExecutionObservationQualification } from './test-cloud-setup-check.mjs';
import closedInventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};

const FULL_GIT_SHA_PATTERN = /^[0-9a-f]{40}$/;
const POSITIVE_DECIMAL_PATTERN = /^[1-9][0-9]*$/;
const PRODUCT_FUNCTIONS_DIGEST =
  'sha256:2547cdffd4074e1a312120ab0b9f4d7ffd80afc19d7eea8d9f13d7306db22d88';

const CONTEXT_KEYS = Object.freeze([
  'candidateRevision',
  'endpoint',
  'environmentClass',
  'environmentDigest',
  'projectId',
  'publicOrigin',
  'runId',
  'siteId',
]);
const ARGUMENT_KEYS = Object.freeze([
  'candidateRevision',
  'credentialHandles',
  'environment',
  'inventory',
  'runId',
]);
const RECOVERY_ARGUMENT_KEYS = Object.freeze([
  'approvalRef',
  'controllerBundleSha',
  'environment',
  'executionObservationQualification',
  'originalWorkflowRunId',
  'recoveryHandle',
]);
const RECOVERY_CONTEXT_KEYS = Object.freeze([
  'approvalRef',
  'controllerBundleSha',
  'endpoint',
  'environmentClass',
  'originalWorkflowRunId',
  'projectId',
  'publicOrigin',
  'siteId',
]);
const ENVIRONMENT_KEYS = Object.freeze(['endpoint', 'origin', 'projectId', 'siteId']);
const HANDLE_KEYS = Object.freeze(['credentialClass', 'readSecret', 'scopes', 'variableName']);

const TEST_ENVIRONMENT = Object.freeze({
  endpoint: 'https://fra.cloud.appwrite.io/v1',
  projectId: '69137c5d003952a36d4c',
  publicOrigin: 'https://appwritework.appwrite.network',
  siteId: '694579860016df0d2d3c',
});

const PRODUCTION_DENYLIST = Object.freeze({
  endpoint: 'https://api.salmora.net/v1',
  projectId: '69eb4818000afa64a7fa',
  siteId: '69eb4a020024c520642e',
  origin: 'https://salmora.net',
  originHost: 'salmora.net',
});

const CREDENTIAL_DEFINITIONS = Object.freeze({
  operator: Object.freeze({
    credentialClass: 'test-operator',
    scopes: Object.freeze([
      'execution.write',
      'functions.read',
      'functions.write',
      'sites.read',
      'sites.write',
    ]),
    variableName: 'APPWRITE_TEST_OPERATOR_API_KEY',
  }),
  fixture: Object.freeze({
    credentialClass: 'test-fixture',
    scopes: Object.freeze(['rows.read', 'rows.write', 'users.read', 'users.write']),
    variableName: 'APPWRITE_TEST_FIXTURE_API_KEY',
  }),
  recovery: Object.freeze({
    credentialClass: 'test-recovery',
    scopes: Object.freeze([
      'rows.read',
      'rows.write',
      'users.read',
      'users.write',
      'files.read',
      'files.write',
    ]),
    variableName: 'APPWRITE_TEST_RECOVERY_API_KEY',
  }),
});

const FIXED_INVENTORY_PROJECTION = Object.freeze({
  schemaVersion: 'test-cloud-inventory.v1',
  environmentClass: 'appwrite-cloud-test',
  providerContractDigest:
    'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8',
  sourceBranch: 'main',
  environment: TEST_ENVIRONMENT,
  deploymentModes: Object.freeze({ function: 'artifact-upload', site: 'artifact-upload' }),
  productionDenylist: Object.freeze({
    credentialVariableNames: Object.freeze([
      'APPWRITE_API_KEY',
      'APPWRITE_PRODUCTION_READONLY_API_KEY',
      'APPWRITE_PRODUCTION_RELEASE_API_KEY',
    ]),
    endpoints: Object.freeze([PRODUCTION_DENYLIST.endpoint]),
    originHostSuffixes: Object.freeze(['.salmora.net']),
    origins: Object.freeze([PRODUCTION_DENYLIST.origin]),
    projectIds: Object.freeze([PRODUCTION_DENYLIST.projectId]),
    siteIds: Object.freeze([PRODUCTION_DENYLIST.siteId]),
  }),
  control: Object.freeze({
    auditTableId: 'verification_audit_events',
    databaseId: 'verification_control',
    intentTableId: 'verification_intents',
    leaseRowId: 'appwrite_test_verification',
    leaseTableId: 'verification_leases',
    primaryExecutionRetentionMaxSeconds: 86400,
    runnerFunctionId: 'verification-runner-py',
  }),
  credentialVariables: CREDENTIAL_DEFINITIONS,
  identityVariables: Object.freeze({
    editor: Object.freeze({ email: 'E2E_EDITOR_EMAIL', password: 'E2E_EDITOR_PASSWORD' }),
    owner: Object.freeze({ email: 'E2E_OWNER_EMAIL', password: 'E2E_OWNER_PASSWORD' }),
    viewer: Object.freeze({ email: 'E2E_VIEWER_EMAIL', password: 'E2E_VIEWER_PASSWORD' }),
  }),
});

const RUNNER_FUNCTION = Object.freeze({
  entrypoint: 'main.py',
  functionId: 'verification-runner-py',
  logicalId: 'verification-runner-py',
  runtime: 'python-3.12',
  sourcePath: 'src/functions/verification-runner-py',
});

const testEnvironmentBrand = Object.freeze(Object.create(null));
const AUTHENTIC_CONTEXTS = new WeakSet();
const AUTHENTIC_RECOVERY_CONTEXTS = new WeakMap();
const CONTEXT_CREDENTIAL_HANDLES = new WeakMap();

function ordinalCompare(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function isPlainObject(value) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || utilTypes.isProxy(value)
      || Array.isArray(value)
    ) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function readExactDataObject(value, expectedKeys) {
  if (!isPlainObject(value)) return null;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.getOwnPropertySymbols(value).length !== 0) return null;
    const actualKeys = Object.keys(descriptors).sort(ordinalCompare);
    const sortedExpected = [...expectedKeys].sort(ordinalCompare);
    if (
      actualKeys.length !== sortedExpected.length
      || actualKeys.some((key, index) => key !== sortedExpected[index])
    ) {
      return null;
    }
    const output = Object.create(null);
    for (const key of sortedExpected) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      output[key] = descriptor.value;
    }
    return output;
  } catch {
    return null;
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function blocked(code) {
  const safeMessages = {
    TEST_INVENTORY_INVALID: 'Test inventory does not match the closed allowlist.',
    TEST_IDENTITY_MISMATCH: 'Requested environment does not match the Appwrite test identity.',
    TEST_PRODUCTION_DENYLIST: 'Requested environment matches the production denylist.',
    TEST_REVISION_INVALID: 'Candidate revision must be one full lowercase Git SHA.',
    TEST_RUN_ID_INVALID: 'Verification run identity is invalid.',
    TEST_CREDENTIAL_CLASS_INVALID: 'Credential handles do not match the closed test classes.',
    TEST_RECOVERY_SCOPE_INVALID: 'Recovery identity does not match the closed test scope.',
    TEST_SCOPE_ATTESTATION_MISMATCH: 'Credential scope attestation does not match exactly.',
  };
  const diagnostics = Object.freeze([
    Object.freeze({ code, safeMessage: safeMessages[code], retryable: false }),
  ]);
  return Object.freeze({ status: 'BLOCKED', value: null, diagnostics });
}

function pass(value) {
  return Object.freeze({ status: 'PASS', value, diagnostics: Object.freeze([]) });
}

function sha256Canonical(value) {
  return sha256Bytes(new TextEncoder().encode(canonicalJson(value)));
}

function inventoryProjection(value) {
  const fields = readExactDataObject(value, [
    'control',
    'credentialVariables',
    'deploymentModes',
    'environment',
    'environmentClass',
    'identityVariables',
    'providerContractDigest',
    'productFunctions',
    'productionDenylist',
    'schemaVersion',
    'sourceBranch',
    'testOnlyFunctions',
  ]);
  if (fields === null) return null;
  return {
    fixed: {
      schemaVersion: fields.schemaVersion,
      environmentClass: fields.environmentClass,
      sourceBranch: fields.sourceBranch,
      environment: fields.environment,
      deploymentModes: fields.deploymentModes,
      productionDenylist: fields.productionDenylist,
      control: fields.control,
      credentialVariables: fields.credentialVariables,
      identityVariables: fields.identityVariables,
      providerContractDigest: fields.providerContractDigest,
    },
    productFunctions: fields.productFunctions,
    testOnlyFunctions: fields.testOnlyFunctions,
  };
}

function hasSupportedTestOnlyFunctions(value) {
  try {
    const encoded = canonicalJson(value);
    return encoded === '[]' || encoded === canonicalJson([RUNNER_FUNCTION]);
  } catch {
    return false;
  }
}

function validateClosedInventory(value) {
  try {
    const projection = inventoryProjection(value);
    if (projection === null) return false;
    if (canonicalJson(projection.fixed) !== canonicalJson(FIXED_INVENTORY_PROJECTION)) return false;
    if (sha256Canonical(projection.productFunctions) !== PRODUCT_FUNCTIONS_DIGEST) return false;
    if (!hasSupportedTestOnlyFunctions(projection.testOnlyFunctions)) return false;
    return canonicalJson(value) === CLOSED_INVENTORY_CANONICAL;
  } catch {
    return false;
  }
}

function assertClosedSourceInventory() {
  const projection = inventoryProjection(closedInventory);
  if (
    projection === null
    || canonicalJson(projection.fixed) !== canonicalJson(FIXED_INVENTORY_PROJECTION)
    || sha256Canonical(projection.productFunctions) !== PRODUCT_FUNCTIONS_DIGEST
    || !hasSupportedTestOnlyFunctions(projection.testOnlyFunctions)
  ) {
    throw new TypeError('Repository test-cloud inventory is outside the closed v1 contract.');
  }
}

assertClosedSourceInventory();
deepFreeze(closedInventory);
const CLOSED_INVENTORY_CANONICAL = canonicalJson(closedInventory);
const ENVIRONMENT_DIGEST = sha256Bytes(new TextEncoder().encode(CLOSED_INVENTORY_CANONICAL));

function hostnameOf(value) {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    if (url.username !== '' || url.password !== '') return null;
    return url.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function matchesProductionDenylist(environment) {
  if (
    environment.endpoint === PRODUCTION_DENYLIST.endpoint
    || environment.projectId === PRODUCTION_DENYLIST.projectId
    || environment.siteId === PRODUCTION_DENYLIST.siteId
    || environment.origin === PRODUCTION_DENYLIST.origin
  ) {
    return true;
  }
  for (const value of [environment.endpoint, environment.origin]) {
    const hostname = hostnameOf(value);
    if (
      hostname === PRODUCTION_DENYLIST.originHost
      || hostname?.endsWith(`.${PRODUCTION_DENYLIST.originHost}`)
    ) {
      return true;
    }
  }
  return false;
}

function matchesTestIdentity(environment) {
  return (
    environment.endpoint === TEST_ENVIRONMENT.endpoint
    && environment.projectId === TEST_ENVIRONMENT.projectId
    && environment.siteId === TEST_ENVIRONMENT.siteId
    && environment.origin === TEST_ENVIRONMENT.publicOrigin
  );
}

function readCredentialHandles(value) {
  try {
    if (!isPlainObject(value) || !Object.isFrozen(value)) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key === 'symbol')) return null;
    const names = ownKeys.sort(ordinalCompare);
    const ordinary = ['fixture', 'operator'];
    const expected = ordinary;
    if (names.length !== ordinary.length || names.some((name, index) => name !== ordinary[index])) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const handles = Object.create(null);
    for (const name of expected) {
      const descriptor = descriptors[name];
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      handles[name] = descriptor.value;
    }
    return handles;
  } catch {
    return null;
  }
}

function readCredentialHandle(value) {
  try {
    if (!Object.isFrozen(value)) return { kind: 'class' };
    const fields = readExactDataObject(value, HANDLE_KEYS);
    if (fields === null || typeof fields.readSecret !== 'function') return { kind: 'class' };
    if (!Array.isArray(fields.scopes) || !Object.isFrozen(fields.scopes)) {
      return { kind: 'scope' };
    }
    canonicalJson(fields.scopes);
    return { kind: 'valid', fields };
  } catch {
    return { kind: 'class' };
  }
}

function validateCredentialHandles(value) {
  const handles = readCredentialHandles(value);
  if (handles === null) return { code: 'TEST_CREDENTIAL_CLASS_INVALID' };
  for (const role of Object.keys(handles)) {
    const parsed = readCredentialHandle(handles[role]);
    const expected = CREDENTIAL_DEFINITIONS[role];
    if (parsed.kind === 'scope') return { code: 'TEST_SCOPE_ATTESTATION_MISMATCH' };
    if (
      parsed.kind !== 'valid'
      || parsed.fields.credentialClass !== expected.credentialClass
      || parsed.fields.variableName !== expected.variableName
    ) {
      return { code: 'TEST_CREDENTIAL_CLASS_INVALID' };
    }
    if (canonicalJson(parsed.fields.scopes) !== canonicalJson(expected.scopes)) {
      return { code: 'TEST_SCOPE_ATTESTATION_MISMATCH' };
    }
  }
  return null;
}

function validRecoveryApprovalRef(approvalRef, originalWorkflowRunId) {
  if (
    typeof approvalRef !== 'string'
    || typeof originalWorkflowRunId !== 'string'
    || !POSITIVE_DECIMAL_PATTERN.test(originalWorkflowRunId)
    || approvalRef.includes('%')
  ) return false;
  const expected =
    `https://github.com/Krowaccie/AppWriteWork-verification-control/actions/runs/${originalWorkflowRunId}`;
  if (approvalRef !== expected) return false;
  try {
    const url = new URL(approvalRef);
    return url.protocol === 'https:'
      && url.hostname === 'github.com'
      && url.username === ''
      && url.password === ''
      && url.port === ''
      && url.search === ''
      && url.hash === '';
  } catch {
    return false;
  }
}

function validRecoveryHandle(value) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || utilTypes.isProxy(value)
      || !Object.isFrozen(value)
    ) return false;
    const fields = readExactDataObject(value, HANDLE_KEYS);
    const expected = CREDENTIAL_DEFINITIONS.recovery;
    return fields !== null
      && fields.credentialClass === expected.credentialClass
      && fields.variableName === expected.variableName
      && typeof fields.readSecret === 'function'
      && Array.isArray(fields.scopes)
      && !utilTypes.isProxy(fields.scopes)
      && Object.isFrozen(fields.scopes)
      && canonicalJson(fields.scopes) === canonicalJson(expected.scopes);
  } catch {
    return false;
  }
}

function validRunId(runId, candidateRevision) {
  if (typeof runId !== 'string') return false;
  const match = /^verify-([0-9a-f]{12})-([0-9]+)-([0-9]+)$/.exec(runId);
  return (
    match !== null
    && match[1] === candidateRevision.slice(0, 12)
    && POSITIVE_DECIMAL_PATTERN.test(match[2])
    && POSITIVE_DECIMAL_PATTERN.test(match[3])
  );
}

export function isAuthenticTestEnvironmentContext(value) {
  try {
    return AUTHENTIC_CONTEXTS.has(value);
  } catch {
    return false;
  }
}

export function isAuthenticTestRecoveryEnvironmentContext(value) {
  try {
    return AUTHENTIC_RECOVERY_CONTEXTS.has(value);
  } catch {
    return false;
  }
}

export function isTestEnvironmentContextBoundToCredentialHandles(context, credentialHandles) {
  try {
    if (CONTEXT_CREDENTIAL_HANDLES.get(context) === credentialHandles) return true;
    return AUTHENTIC_RECOVERY_CONTEXTS.get(context)?.recoveryHandle === credentialHandles;
  } catch {
    return false;
  }
}

export function createTestEnvironmentContext(args) {
  const fields = readExactDataObject(args, ARGUMENT_KEYS);
  if (fields === null || !validateClosedInventory(fields.inventory)) {
    return blocked('TEST_INVENTORY_INVALID');
  }

  const environment = readExactDataObject(fields.environment, ENVIRONMENT_KEYS);
  if (environment === null) return blocked('TEST_IDENTITY_MISMATCH');
  if (matchesProductionDenylist(environment)) return blocked('TEST_PRODUCTION_DENYLIST');
  if (!matchesTestIdentity(environment)) return blocked('TEST_IDENTITY_MISMATCH');

  if (
    typeof fields.candidateRevision !== 'string'
    || !FULL_GIT_SHA_PATTERN.test(fields.candidateRevision)
  ) {
    return blocked('TEST_REVISION_INVALID');
  }
  if (!validRunId(fields.runId, fields.candidateRevision)) {
    return blocked('TEST_RUN_ID_INVALID');
  }

  const credentialError = validateCredentialHandles(fields.credentialHandles);
  if (credentialError !== null) return blocked(credentialError.code);

  const context = {
    environmentClass: 'appwrite-cloud-test',
    endpoint: TEST_ENVIRONMENT.endpoint,
    projectId: TEST_ENVIRONMENT.projectId,
    siteId: TEST_ENVIRONMENT.siteId,
    publicOrigin: TEST_ENVIRONMENT.publicOrigin,
    candidateRevision: fields.candidateRevision,
    runId: fields.runId,
    environmentDigest: ENVIRONMENT_DIGEST,
  };
  Object.defineProperty(context, 'brand', {
    value: testEnvironmentBrand,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  const contextKeys = Object.keys(context).sort(ordinalCompare);
  if (contextKeys.some((key, index) => key !== CONTEXT_KEYS[index])) {
    return blocked('TEST_INVENTORY_INVALID');
  }
  deepFreeze(context);
  AUTHENTIC_CONTEXTS.add(context);
  CONTEXT_CREDENTIAL_HANDLES.set(context, fields.credentialHandles);
  return pass(context);
}

export function createTestRecoveryEnvironmentContext(args) {
  try {
    const fields = readExactDataObject(args, RECOVERY_ARGUMENT_KEYS);
    if (fields === null) return blocked('TEST_RECOVERY_SCOPE_INVALID');

    const environment = readExactDataObject(fields.environment, ENVIRONMENT_KEYS);
    if (
      environment === null
      || matchesProductionDenylist(environment)
      || !matchesTestIdentity(environment)
      || typeof fields.controllerBundleSha !== 'string'
      || !FULL_GIT_SHA_PATTERN.test(fields.controllerBundleSha)
      || !validRecoveryApprovalRef(fields.approvalRef, fields.originalWorkflowRunId)
      || !validRecoveryHandle(fields.recoveryHandle)
    ) return blocked('TEST_RECOVERY_SCOPE_INVALID');

    const observation = readExecutionObservationQualification(
      fields.executionObservationQualification,
    );
    if (observation === null) return blocked('TEST_RECOVERY_SCOPE_INVALID');

    const context = {
      environmentClass: 'appwrite-cloud-test-recovery',
      endpoint: TEST_ENVIRONMENT.endpoint,
      projectId: TEST_ENVIRONMENT.projectId,
      siteId: TEST_ENVIRONMENT.siteId,
      publicOrigin: TEST_ENVIRONMENT.publicOrigin,
      controllerBundleSha: fields.controllerBundleSha,
      approvalRef: fields.approvalRef,
      originalWorkflowRunId: fields.originalWorkflowRunId,
    };
    const contextKeys = Object.keys(context).sort(ordinalCompare);
    if (contextKeys.some((key, index) => key !== RECOVERY_CONTEXT_KEYS[index])) {
      return blocked('TEST_RECOVERY_SCOPE_INVALID');
    }
    deepFreeze(context);
    AUTHENTIC_RECOVERY_CONTEXTS.set(context, Object.freeze({
      primaryExecutionRetentionMaxSeconds: observation.maximumRetentionSeconds,
      recoveryHandle: fields.recoveryHandle,
    }));
    return pass(context);
  } catch {
    return blocked('TEST_RECOVERY_SCOPE_INVALID');
  }
}
