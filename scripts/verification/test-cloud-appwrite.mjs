import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { TextDecoder, types as utilTypes } from 'node:util';

import { canonicalJson } from './canonical-json.mjs';
import {
  isAuthenticTestEnvironmentContext,
  isAuthenticTestRecoveryEnvironmentContext,
  isTestEnvironmentContextBoundToCredentialHandles,
} from './test-cloud-environment.mjs';
import {
  authenticateTestCloudRuntimeActive,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from './test-cloud-provider-contract.mjs';
import {
  consumeRecoveryAccountSessionDeletePermit,
  consumeRecoveryAccountSessionListHandle,
  consumeRecoveryMutationPermit,
  consumeRecoveryStepHandle,
  recordRecoveryAccountSessionDeleteDisposition,
  recordRecoveryAccountSessionListObservation,
} from './test-cloud-control-store.mjs';
import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_EXECUTION_BODY_BYTES = 16 * 1024;
const MAX_EXECUTION_RESPONSE_BODY_BYTES = 64 * 1024;
const DIGEST_ID_PATTERN = /^h[A-Za-z0-9_-]{35}$/;
const PROVIDER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const EXECUTION_MODEL_KEYS = Object.freeze([
  '$createdAt',
  '$id',
  '$permissions',
  '$updatedAt',
  'deploymentId',
  'duration',
  'errors',
  'functionId',
  'logs',
  'requestHeaders',
  'requestMethod',
  'requestPath',
  'responseBody',
  'responseHeaders',
  'responseStatusCode',
  'scheduledAt',
  'status',
  'trigger',
]);
const EXECUTION_STATUSES = Object.freeze([
  'completed',
  'failed',
  'processing',
  'scheduled',
  'waiting',
]);
const ERROR_CARRIER_KEYS = Object.freeze([
  'code',
  'message',
  'name',
  'response',
  'stack',
  'type',
]);
const ARGUMENT_KEYS = Object.freeze(['context', 'credentialHandles', 'fetch']);
const RECOVERY_ARGUMENT_KEYS = Object.freeze(['context', 'fetch', 'recoveryHandle']);
const HANDLE_KEYS = Object.freeze(['credentialClass', 'readSecret', 'scopes', 'variableName']);
const AUTHENTIC_CONTROL_CLIENTS = new WeakMap();
const AUTHENTIC_OPERATOR_CLIENTS = new WeakMap();
const AUTHENTIC_RECOVERY_CONTROL_CLIENTS = new WeakMap();
const AUTHENTIC_RECOVERY_PRODUCT_CLIENTS = new WeakMap();
const RECOVERY_PROJECTION_DIGESTS = new WeakMap();
const RECOVERY_CONTROL_KEYS = Object.freeze([
  'commitOrRollbackTransaction',
  'createTransaction',
  'createTransactionOperations',
  'getRow',
]);
const RECOVERY_PRODUCT_KEYS = Object.freeze([
  'deleteBoundAccountSession',
  'convergeBoundFileOwnerPermissions',
  'convergeBoundRowOwnerPermissions',
  'deleteBoundFile',
  'deleteBoundRow',
  'getBoundFile',
  'getBoundRow',
  'listBoundAccountSessions',
  'queryBoundProjectArtifactReferences',
  'queryBoundProjectArtifactVersionsExactSet',
  'queryBoundProjectArtifactsExactSet',
  'queryBoundProjectShares',
  'queryBoundProjectSnapshots',
]);
const RUNNER_VARIABLE_REQUEST_QUALIFICATIONS = new WeakMap();
const RUNNER_VARIABLE_OPERATORS = new WeakMap();
const AUTHENTIC_RUNNER_VARIABLE_RESULTS = new WeakMap();
const RUNNER_VARIABLE_KEYS = Object.freeze([
  'VERIFICATION_AUDIT_TABLE_ID',
  'VERIFICATION_CONTROL_DATABASE_ID',
  'VERIFICATION_ENDPOINT_ORIGIN',
  'VERIFICATION_ENVIRONMENT_CLASS',
  'VERIFICATION_ENVIRONMENT_DIGEST',
  'VERIFICATION_IDENTITY_BINDINGS_DIGEST',
  'VERIFICATION_INTENT_TABLE_ID',
  'VERIFICATION_LEASE_ROW_ID',
  'VERIFICATION_LEASE_TABLE_ID',
  'VERIFICATION_PRIMARY_DATABASE_ID',
  'VERIFICATION_PROJECTS_TABLE_ID',
  'VERIFICATION_PROJECT_FILES_BUCKET_ID',
  'VERIFICATION_PROJECT_ID',
  'VERIFICATION_PROVIDER_CONTRACT_DIGEST',
  'VERIFICATION_SHARES_TABLE_ID',
  'VERIFICATION_WORKER_FUNCTION_ID',
]);
const RUNNER_VARIABLE_KEY_SET = new Set(RUNNER_VARIABLE_KEYS);
const RUNNER_VARIABLE_OBSERVATION_KEYS = Object.freeze([
  'bytes',
  'expectedEnvironmentDigest',
  'expectedProviderContractDigest',
  'expectedSetupReadbackDigest',
  'expectedRunnerVariableExpectationDigest',
]);
const RUNNER_VARIABLE_REQUEST_KEYS = Object.freeze([
  'runtimeQualification',
  'context',
  'credentialHandles',
  'providerContract',
  'identityBindings',
  'providerSetupReadback',
]);
const RUNNER_VARIABLE_RESULT_EXPECTED_KEYS = Object.freeze([
  'runtimeQualification',
  'context',
  'providerContractQualification',
  'identityBindingsQualification',
  'providerSetupReadbackQualification',
]);
const RUNNER_VARIABLE_RAW_KEYS = Object.freeze([
  '$id', '$createdAt', '$updatedAt', 'key', 'value', 'secret', 'resourceType', 'resourceId',
]);
const PROVIDER_PASS_KEYS = Object.freeze(['qualification', 'providerContractDigest']);
const IDENTITY_PASS_KEYS = Object.freeze(['qualification', 'identityBindingsDigest']);
const SETUP_PASS_KEYS = Object.freeze([
  'qualification',
  'identityBindingsDigest',
  'providerSetupReadbackDigest',
  'runnerVariableExpectationDigest',
]);
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const VARIABLE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$/;
const VARIABLE_TIMESTAMP_PATTERN =
  /^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}(?:Z|\+00:00)$/;
const INTENT_LOGICAL_RETENTION_KEY = 'cleanupRunnerExecutionRetentionExpiresAt';
const INTENT_STORAGE_RETENTION_KEY = 'cleanupRunnerExecutionRetentionAt';
const AUDIT_RECOVERY_STORAGE_KEYS = Object.freeze([
  'recoveryCheckpointDigest',
  'recoveryCheckpointJson',
  'recoveryPreviousCheckpointDigest',
]);
const INTENT_V2_STORAGE_ARM_KEYS = Object.freeze([
  'providerAggregateJson',
  'providerAggregateDigest',
  'cleanupCursor',
  'cleanupProgressDigest',
  'cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest',
  'cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson',
  'cleanupRunnerExecutionRecordDigest',
  INTENT_LOGICAL_RETENTION_KEY,
]);
const INTENT_V1_STORAGE_ARM_KEYS = Object.freeze(['providerResourceIds']);
const INTENT_RECOVERY_STORAGE_KEYS = Object.freeze(['recoveryCheckpointDigest']);
const LEASE_DATETIME_STORAGE_KEYS = Object.freeze([
  'acquiredAt',
  'renewedAt',
  'expiresAt',
]);
const INTENT_DATETIME_STORAGE_KEYS = Object.freeze([
  'retentionExpiresAt',
  INTENT_LOGICAL_RETENTION_KEY,
  'createdAt',
  'updatedAt',
]);
const RUNNER_VARIABLE_QUERY_PATH =
  '/functions/verification-runner-py/variables?queries%5B%5D=%7B%22method%22%3A%22limit%22%2C%22values%22%3A%5B17%5D%7D&total=true';
const RUNNER_VARIABLE_AUTHORITY_PROPERTY = '__registerTestCloudRunnerVariableAuthorityV1__';
const RUNNER_VARIABLE_BOOTSTRAP_HUB_PROPERTY =
  '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const RUNNER_VARIABLE_PROVIDER_MODULE_URL = new URL(
  './test-cloud-provider-contract.mjs',
  import.meta.url,
).href;
const CAPTURED_FETCH = globalThis.fetch;
const CAPTURED_ABORT_TIMEOUT = typeof AbortSignal === 'function'
  && typeof AbortSignal.timeout === 'function'
  ? AbortSignal.timeout.bind(AbortSignal)
  : undefined;
const CAPTURED_TEXT_DECODER = TextDecoder;
const CAPTURED_REFLECT_APPLY = Reflect.apply;
const CAPTURED_IS_PROXY = utilTypes.isProxy;
const CAPTURED_EMPTY_ARGUMENTS = Object.freeze([]);
const CAPTURED_FUNCTION_TO_STRING = Function.prototype.toString;
const DEDICATED_CAPTURE_VALID = typeof CAPTURED_FETCH === 'function'
  && typeof CAPTURED_ABORT_TIMEOUT === 'function'
  && typeof CAPTURED_TEXT_DECODER === 'function'
  && typeof CAPTURED_REFLECT_APPLY === 'function'
  && typeof CAPTURED_IS_PROXY === 'function'
  && !CAPTURED_IS_PROXY(CAPTURED_FETCH)
  && !CAPTURED_IS_PROXY(CAPTURED_REFLECT_APPLY)
  && /\[native code\]/u.test(CAPTURED_REFLECT_APPLY(
    CAPTURED_FUNCTION_TO_STRING,
    CAPTURED_REFLECT_APPLY,
    [],
  ));

let runnerVariableRequestRecord = Object.freeze({ state: 'EMPTY', version: 0 });
let authenticateRunnerVariableReadbackRequestEvidence;
let authenticateRunnerVariableReadbackRequestEvidenceReceiver;

const {
  auditTableId: AUDIT_TABLE_ID,
  databaseId: DATABASE_ID,
  intentTableId: INTENT_TABLE_ID,
  leaseRowId: LEASE_ROW_ID,
  leaseTableId: LEASE_TABLE_ID,
  runnerFunctionId: RUNNER_FUNCTION_ID,
} = inventory.control;

const FUNCTION_RECORDS = new Map(inventory.productFunctions.map((record) => [record.functionId, record]));
FUNCTION_RECORDS.set(RUNNER_FUNCTION_ID, Object.freeze({
  functionId: RUNNER_FUNCTION_ID,
  entrypoint: 'main.py',
  runtime: 'python-3.12',
}));

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
    const actual = Object.keys(descriptors).sort(ordinalCompare);
    const expected = [...expectedKeys].sort(ordinalCompare);
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      return null;
    }
    const result = Object.create(null);
    for (const key of expected) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    return result;
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
  const messages = {
    TEST_CLIENT_OPERATION_FORBIDDEN: 'Operation is outside the closed Appwrite test client.',
    TEST_CREDENTIAL_CLASS_INVALID: 'Credential handle does not match the closed test class.',
    TEST_RESPONSE_INVALID: 'Appwrite returned an invalid bounded response.',
    TEST_SETUP_READBACK_MISMATCH: 'One or more exact test-cloud setup prerequisites have not been read back.',
    TEST_COMMIT_UNKNOWN: 'The Appwrite transaction commit result is unknown.',
  };
  return Object.freeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: Object.freeze([
      Object.freeze({ code, safeMessage: messages[code], retryable: false }),
    ]),
  });
}

function pass(value) {
  return Object.freeze({
    status: 'PASS',
    value: deepFreeze(value),
    diagnostics: Object.freeze([]),
  });
}

function validateCredentialHandles(value) {
  try {
    if (!isPlainObject(value) || !Object.isFrozen(value)) return null;
    const names = Reflect.ownKeys(value);
    if (names.some((name) => typeof name === 'symbol')) return null;
    names.sort(ordinalCompare);
    const expectedNames = ['fixture', 'operator'];
    if (
      names.length !== expectedNames.length
      || names.some((name, index) => name !== expectedNames[index])
    ) {
      return null;
    }
    const handles = Object.create(null);
    const outerDescriptors = Object.getOwnPropertyDescriptors(value);
    for (const role of expectedNames) {
      const outer = outerDescriptors[role];
      if (!outer?.enumerable || !Object.hasOwn(outer, 'value')) return null;
      const handle = outer.value;
      if (!Object.isFrozen(handle)) return null;
      const fields = readExactDataObject(handle, HANDLE_KEYS);
      const expected = inventory.credentialVariables[role];
      if (
        fields === null
        || fields.credentialClass !== expected.credentialClass
        || fields.variableName !== expected.variableName
        || typeof fields.readSecret !== 'function'
        || !Array.isArray(fields.scopes)
        || !Object.isFrozen(fields.scopes)
        || canonicalJson(fields.scopes) !== canonicalJson(expected.scopes)
      ) {
        return null;
      }
      handles[role] = handle;
    }
    return handles;
  } catch {
    return null;
  }
}

function validateRecoveryHandle(value) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || utilTypes.isProxy(value)
      || !Object.isFrozen(value)
    ) return false;
    const fields = readExactDataObject(value, HANDLE_KEYS);
    const expected = inventory.credentialVariables.recovery;
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

function isProviderId(value) {
  return typeof value === 'string' && PROVIDER_ID_PATTERN.test(value);
}

function rowLocationAllowed(tableId, rowId) {
  if (tableId === LEASE_TABLE_ID) return rowId === LEASE_ROW_ID;
  return (
    (tableId === INTENT_TABLE_ID || tableId === AUDIT_TABLE_ID)
    && typeof rowId === 'string'
    && DIGEST_ID_PATTERN.test(rowId)
  );
}

function encodePath(value) {
  return encodeURIComponent(value);
}

function safeCanonical(value) {
  try {
    return canonicalJson(value);
  } catch {
    return null;
  }
}

function remapIntentRowData(tableId, data, sourceKey, targetKey) {
  if (tableId !== INTENT_TABLE_ID) return data;
  if (!isPlainObject(data) || Object.hasOwn(data, targetKey)) return null;
  if (!Object.hasOwn(data, sourceKey)) return data;
  return Object.fromEntries(Object.entries(data).map(([key, value]) => [
    key === sourceKey ? targetKey : key,
    value,
  ]));
}

function storageRowData(tableId, data) {
  return remapIntentRowData(
    tableId,
    data,
    INTENT_LOGICAL_RETENTION_KEY,
    INTENT_STORAGE_RETENTION_KEY,
  );
}

function stripNullStorageArm(data, keys) {
  if (!isPlainObject(data)) return data;
  const present = keys.filter((key) => Object.hasOwn(data, key));
  if (present.length === 0) return data;
  if (present.length !== keys.length || present.some((key) => data[key] !== null)) return data;
  return Object.fromEntries(Object.entries(data).filter(([key]) => !keys.includes(key)));
}

function canonicalizeStorageDatetimes(tableId, data) {
  if (!isPlainObject(data)) return data;
  const keys = tableId === LEASE_TABLE_ID
    ? LEASE_DATETIME_STORAGE_KEYS
    : tableId === INTENT_TABLE_ID
      ? INTENT_DATETIME_STORAGE_KEYS
      : [];
  let changed = false;
  const normalized = Object.fromEntries(Object.entries(data).map(([key, value]) => {
    if (
      keys.includes(key)
      && typeof value === 'string'
      && value.endsWith('+00:00')
      && VARIABLE_TIMESTAMP_PATTERN.test(value)
    ) {
      changed = true;
      return [key, `${value.slice(0, -6)}Z`];
    }
    return [key, value];
  }));
  return changed ? normalized : data;
}

function logicalRowData(tableId, data) {
  let logical = remapIntentRowData(
    tableId,
    data,
    INTENT_STORAGE_RETENTION_KEY,
    INTENT_LOGICAL_RETENTION_KEY,
  );
  if (logical === null) return null;
  logical = canonicalizeStorageDatetimes(tableId, logical);
  if (tableId === AUDIT_TABLE_ID) {
    return stripNullStorageArm(logical, AUDIT_RECOVERY_STORAGE_KEYS);
  }
  if (tableId !== INTENT_TABLE_ID || !isPlainObject(logical)) return logical;
  if (logical.schemaVersion === 'verification-intent-snapshot.v1') {
    logical = stripNullStorageArm(logical, INTENT_V2_STORAGE_ARM_KEYS);
  } else if (logical.schemaVersion === 'verification-intent-snapshot.v2') {
    logical = stripNullStorageArm(logical, INTENT_V1_STORAGE_ARM_KEYS);
  }
  return stripNullStorageArm(logical, INTENT_RECOVERY_STORAGE_KEYS);
}

async function readBoundedBytes(response) {
  const rawLength = response.headers.get('content-length');
  if (rawLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(rawLength)) throw new TypeError('invalid length');
    if (Number(rawLength) > MAX_RESPONSE_BYTES) throw new TypeError('response too large');
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) throw new TypeError('invalid response chunk');
    length += value.byteLength;
    if (length > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {});
      throw new TypeError('response too large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function responseObject(value) {
  if (!isPlainObject(value)) throw new TypeError('response must be an object');
  return value;
}

function safeOwnDescriptors(value) {
  if (
    value === null
    || typeof value !== 'object'
    || utilTypes.isProxy(value)
    || Array.isArray(value)
  ) return null;
  try {
    if (Object.getOwnPropertySymbols(value).length !== 0) return null;
    return Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
}

function readExecutionObservation(
  value,
  {
    allowAdditionalKeys = false,
    includeResponseBody = false,
    secret,
  },
) {
  const descriptors = safeOwnDescriptors(value);
  if (descriptors === null) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
  } catch {
    return null;
  }
  const keys = Object.keys(descriptors);
  if (!allowAdditionalKeys && keys.some((key) => !EXECUTION_MODEL_KEYS.includes(key))) {
    return null;
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
  }
  const idDescriptor = descriptors.$id;
  const executionId = idDescriptor?.value;
  if (
    !idDescriptor?.enumerable
    || !Object.hasOwn(idDescriptor, 'value')
    || !isProviderId(executionId)
    || executionId.includes(secret)
  ) return null;

  const statusValue = descriptors.status?.value;
  const status = typeof statusValue === 'string'
    && EXECUTION_STATUSES.includes(statusValue)
    && !statusValue.includes(secret)
    ? statusValue
    : null;
  const statusCodeValue = descriptors.responseStatusCode?.value;
  const responseStatusCode = Number.isSafeInteger(statusCodeValue)
    && statusCodeValue >= 0
    && statusCodeValue <= 599
    ? statusCodeValue
    : null;
  const bodyValue = descriptors.responseBody?.value;
  const responseBody = includeResponseBody
    && typeof bodyValue === 'string'
    && !bodyValue.includes(secret)
    && new TextEncoder().encode(bodyValue).byteLength <= MAX_EXECUTION_RESPONSE_BODY_BYTES
    ? bodyValue
    : null;
  return {
    executionId,
    responseBody,
    responseStatusCode,
    status,
  };
}

function projectExecutionResponse(value, transportStatus, secret) {
  const execution = readExecutionObservation(value, {
    allowAdditionalKeys: true,
    includeResponseBody: transportStatus === 201,
    secret,
  });
  if (execution === null && transportStatus === 201) {
    throw new TypeError('invalid execution response');
  }
  return { transportStatus, execution };
}

function readExceptionExecution(error, secret) {
  const direct = readExecutionObservation(error, {
    allowAdditionalKeys: false,
    includeResponseBody: false,
    secret,
  });
  if (direct !== null) return direct;

  const descriptors = safeOwnDescriptors(error);
  if (descriptors === null || !Object.hasOwn(descriptors, 'response')) return null;
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!ERROR_CARRIER_KEYS.includes(key)) return null;
    if (key === 'stack') {
      if (descriptor.enumerable) return null;
      continue;
    }
    if (!Object.hasOwn(descriptor, 'value')) return null;
    if (key !== 'message' && !descriptor.enumerable) return null;
  }
  const responseDescriptor = descriptors.response;
  if (!responseDescriptor.enumerable || !Object.hasOwn(responseDescriptor, 'value')) return null;
  const response = responseDescriptor.value;
  if (typeof response === 'string') {
    if (new TextEncoder().encode(response).byteLength > MAX_EXECUTION_RESPONSE_BODY_BYTES) {
      return null;
    }
    try {
      return readExecutionObservation(JSON.parse(response), {
        allowAdditionalKeys: true,
        includeResponseBody: false,
        secret,
      });
    } catch {
      return null;
    }
  }
  return readExecutionObservation(response, {
    allowAdditionalKeys: false,
    includeResponseBody: false,
    secret,
  });
}

function projectExecutionException(error, secret) {
  const execution = readExceptionExecution(error, secret);
  return execution === null ? null : { transportStatus: null, execution };
}

function deploymentProjection(value, expectedId = null) {
  const object = responseObject(value);
  if (!isProviderId(object.$id) || (expectedId !== null && object.$id !== expectedId)) {
    throw new TypeError('invalid deployment id');
  }
  if (typeof object.status !== 'string' || object.status.length === 0) {
    throw new TypeError('invalid deployment status');
  }
  return { deploymentId: object.$id, status: object.status };
}

function transactionProjection(value, expectedId = null) {
  const object = responseObject(value);
  if (!isProviderId(object.$id) || (expectedId !== null && object.$id !== expectedId)) {
    throw new TypeError('invalid transaction id');
  }
  if (typeof object.status !== 'string' || object.status.length === 0) {
    throw new TypeError('invalid transaction status');
  }
  return { status: object.status, transactionId: object.$id };
}

function rowProjection(value, expectedRowId, tableId) {
  const object = responseObject(value);
  if (object.$id !== expectedRowId) throw new TypeError('invalid row id');
  const data = logicalRowData(tableId, Object.fromEntries(
    Object.entries(object).filter(([key]) => !key.startsWith('$')),
  ));
  if (data === null || safeCanonical(data) === null) throw new TypeError('invalid row data');
  return { data, rowId: expectedRowId };
}

function exactFunctionProjection(value, functionId) {
  const object = responseObject(value);
  const expected = FUNCTION_RECORDS.get(functionId);
  const activeDeploymentId = object.deploymentId === '' ? null : object.deploymentId;
  if (
    expected === undefined
    || object.$id !== functionId
    || object.runtime !== expected.runtime
    || object.entrypoint !== expected.entrypoint
    || typeof object.commands !== 'string'
    || typeof object.providerRootDirectory !== 'string'
    || typeof object.name !== 'string'
    || object.name.length === 0
    || !Array.isArray(object.execute)
    || Object.keys(object.execute).length !== object.execute.length
    || !object.execute.every((entry) => typeof entry === 'string')
    || !Array.isArray(object.events)
    || Object.keys(object.events).length !== object.events.length
    || !object.events.every((entry) => typeof entry === 'string')
    || typeof object.schedule !== 'string'
    || !Number.isSafeInteger(object.timeout)
    || object.timeout < 1
    || typeof object.enabled !== 'boolean'
    || typeof object.logging !== 'boolean'
    || !Array.isArray(object.scopes)
    || Object.keys(object.scopes).length !== object.scopes.length
    || !object.scopes.every((entry) => typeof entry === 'string')
    || !(activeDeploymentId === null || isProviderId(activeDeploymentId))
  ) {
    throw new TypeError('invalid function response');
  }
  return {
    activeDeploymentId,
    commands: object.commands,
    entrypoint: object.entrypoint,
    functionId,
    providerRootDirectory: object.providerRootDirectory,
    runtime: object.runtime,
    enabled: object.enabled,
    events: [...object.events],
    execute: [...object.execute],
    logging: object.logging,
    name: object.name,
    schedule: object.schedule,
    scopes: [...object.scopes],
    timeout: object.timeout,
  };
}

function createRequest(handle, context, fetchDependency) {
  return async function request({
    bodyText,
    expectedStatus,
    formBody,
    method,
    path,
    project,
    projectException = null,
    projectSafeResponse = null,
    observeStatus = false,
    responseKind = 'json',
    unknownCommit = false,
  }) {
    let secret;
    try {
      secret = handle.readSecret();
    } catch {
      return blocked('TEST_CREDENTIAL_CLASS_INVALID');
    }
    if (typeof secret !== 'string' || secret.length === 0 || secret.length > 8192) {
      return blocked('TEST_CREDENTIAL_CLASS_INVALID');
    }

    const headers = {
      Accept: 'application/json',
      'X-Appwrite-Project': context.projectId,
      'X-Appwrite-Key': secret,
    };
    const options = { method, headers, redirect: 'error' };
    if (bodyText !== undefined) {
      headers['Content-Type'] = 'application/json';
      options.body = bodyText;
    } else if (formBody !== undefined) {
      options.body = formBody;
    }

    let response;
    try {
      response = await fetchDependency(`${context.endpoint}${path}`, options);
    } catch (error) {
      if (typeof projectException === 'function') {
        try {
          const projected = projectException(error, secret);
          if (projected !== null) return pass(projected);
        } catch {
          // Exception observations are optional and never replace the closed failure.
        }
      }
      return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
    }

    try {
      if (
        response === null
        || typeof response !== 'object'
        || !Number.isSafeInteger(response.status)
        || response.status < 100
        || response.status > 599
        || response.headers === null
        || typeof response.headers?.get !== 'function'
      ) {
        return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
      }
      if (!observeStatus && response.status !== expectedStatus) {
        const definiteRejection = response.status >= 400 && response.status < 500;
        return blocked(unknownCommit && !definiteRejection
          ? 'TEST_COMMIT_UNKNOWN'
          : 'TEST_RESPONSE_INVALID');
      }
      const bytes = await readBoundedBytes(response);
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      if (observeStatus && response.status !== expectedStatus) {
        if (typeof projectSafeResponse === 'function') {
          const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
          if (contentType.startsWith('application/json')) {
            try {
              return pass(projectSafeResponse(JSON.parse(text), response.status, secret));
            } catch {
              // A non-JSON or non-projectable failure still has a safe transport observation.
            }
          }
          return pass(project(null, response.status));
        }
        if (text.includes(secret)) {
          return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
        }
        return pass(project(null, response.status));
      }
      if (responseKind === 'empty') {
        if (text !== '') {
          return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
        }
        return pass(project());
      }
      const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
      if (!contentType.startsWith('application/json')) {
        return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
      }
      const parsed = JSON.parse(text);
      if (typeof projectSafeResponse === 'function') {
        return pass(projectSafeResponse(parsed, response.status, secret));
      }
      if (text.includes(secret)) {
        return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
      }
      return pass(project(parsed, response.status));
    } catch {
      return blocked(unknownCommit ? 'TEST_COMMIT_UNKNOWN' : 'TEST_RESPONSE_INVALID');
    }
  };
}

function operation(handler) {
  return async (...args) => {
    try {
      if (args.length !== 1) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return await handler(args[0]);
    } catch {
      return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
    }
  };
}

function makeOperator(handle, context, fetchDependency) {
  const request = createRequest(handle, context, fetchDependency);
  const siteDeploymentIds = new Set();
  const functionDeploymentIds = new Map();

  const functionIdsFor = (functionId) => {
    if (!functionDeploymentIds.has(functionId)) functionDeploymentIds.set(functionId, new Set());
    return functionDeploymentIds.get(functionId);
  };

  const operator = {
    getSite: operation(async (args) => {
      if (readExactDataObject(args, []) === null) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'GET',
        path: `/sites/${encodePath(context.siteId)}`,
        expectedStatus: 200,
        project(value) {
          const object = responseObject(value);
          if (
            object.$id !== context.siteId
            || !isProviderId(object.installationId)
            || !isProviderId(object.providerRepositoryId)
            || typeof object.providerRootDirectory !== 'string'
            || typeof object.providerBranch !== 'string'
            || typeof object.installCommand !== 'string'
            || typeof object.buildCommand !== 'string'
            || typeof object.outputDirectory !== 'string'
            || !(object.deploymentId === null || isProviderId(object.deploymentId))
          ) throw new TypeError('invalid site response');
          if (object.deploymentId !== null) siteDeploymentIds.add(object.deploymentId);
          return {
            activeDeploymentId: object.deploymentId,
            buildCommand: object.buildCommand,
            installCommand: object.installCommand,
            installationId: object.installationId,
            outputDirectory: object.outputDirectory,
            providerBranch: object.providerBranch,
            providerRepositoryId: object.providerRepositoryId,
            providerRootDirectory: object.providerRootDirectory,
            siteId: context.siteId,
          };
        },
      });
    }),

    createSiteDeployment: operation(async (args) => {
      const fields = readExactDataObject(args, ['activate', 'code']);
      if (
        fields === null
        || fields.activate !== false
        || !(fields.code instanceof Uint8Array)
        || fields.code.byteLength === 0
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      const formBody = new FormData();
      formBody.append('code', new Blob([fields.code]), 'code.tar.gz');
      formBody.append('activate', 'false');
      return request({
        method: 'POST',
        path: `/sites/${encodePath(context.siteId)}/deployments`,
        expectedStatus: 202,
        formBody,
        project(value) {
          const projected = deploymentProjection(value);
          siteDeploymentIds.add(projected.deploymentId);
          return projected;
        },
      });
    }),

    getSiteDeployment: operation(async (args) => {
      const fields = readExactDataObject(args, ['deploymentId']);
      if (fields === null || !siteDeploymentIds.has(fields.deploymentId)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'GET',
        path: `/sites/${encodePath(context.siteId)}/deployments/${encodePath(fields.deploymentId)}`,
        expectedStatus: 200,
        project: (value) => deploymentProjection(value, fields.deploymentId),
      });
    }),

    activateSiteDeployment: operation(async (args) => {
      const fields = readExactDataObject(args, ['deploymentId']);
      if (fields === null || !siteDeploymentIds.has(fields.deploymentId)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'PATCH',
        path: `/sites/${encodePath(context.siteId)}/deployment`,
        expectedStatus: 200,
        bodyText: canonicalJson({ deploymentId: fields.deploymentId }),
        project(value) {
          const object = responseObject(value);
          if (object.$id !== context.siteId || object.deploymentId !== fields.deploymentId) {
            throw new TypeError('invalid activation response');
          }
          return { activeDeploymentId: fields.deploymentId, siteId: context.siteId };
        },
      });
    }),

    getFunction: operation(async (args) => {
      const fields = readExactDataObject(args, ['functionId']);
      if (fields === null || !FUNCTION_RECORDS.has(fields.functionId)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'GET',
        path: `/functions/${encodePath(fields.functionId)}`,
        expectedStatus: 200,
        project(value) {
          const projected = exactFunctionProjection(value, fields.functionId);
          if (projected.activeDeploymentId !== null) {
            functionIdsFor(fields.functionId).add(projected.activeDeploymentId);
          }
          return projected;
        },
      });
    }),

    createFunctionDeployment: operation(async (args) => {
      const fields = readExactDataObject(args, ['activate', 'code', 'functionId']);
      if (
        fields === null
        || !FUNCTION_RECORDS.has(fields.functionId)
        || fields.activate !== false
        || !(fields.code instanceof Uint8Array)
        || fields.code.byteLength === 0
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      const formBody = new FormData();
      formBody.append('code', new Blob([fields.code]), 'code.tar.gz');
      formBody.append('activate', 'false');
      return request({
        method: 'POST',
        path: `/functions/${encodePath(fields.functionId)}/deployments`,
        expectedStatus: 202,
        formBody,
        project(value) {
          const projected = deploymentProjection(value);
          functionIdsFor(fields.functionId).add(projected.deploymentId);
          return projected;
        },
      });
    }),

    getFunctionDeployment: operation(async (args) => {
      const fields = readExactDataObject(args, ['deploymentId', 'functionId']);
      if (
        fields === null
        || !FUNCTION_RECORDS.has(fields.functionId)
        || !functionIdsFor(fields.functionId).has(fields.deploymentId)
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'GET',
        path: `/functions/${encodePath(fields.functionId)}/deployments/${encodePath(fields.deploymentId)}`,
        expectedStatus: 200,
        project: (value) => deploymentProjection(value, fields.deploymentId),
      });
    }),

    activateFunctionDeployment: operation(async (args) => {
      const fields = readExactDataObject(args, ['deploymentId', 'functionId']);
      if (
        fields === null
        || !FUNCTION_RECORDS.has(fields.functionId)
        || !functionIdsFor(fields.functionId).has(fields.deploymentId)
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'PATCH',
        path: `/functions/${encodePath(fields.functionId)}/deployment`,
        expectedStatus: 200,
        bodyText: canonicalJson({ deploymentId: fields.deploymentId }),
        project(value) {
          const projected = exactFunctionProjection(value, fields.functionId);
          if (projected.activeDeploymentId !== fields.deploymentId) {
            throw new TypeError('invalid active deployment');
          }
          return projected;
        },
      });
    }),

    createFunctionExecution: operation(async (args) => {
      const fields = readExactDataObject(args, ['body', 'functionId']);
      const body = fields === null ? null : readExactDataObject(fields.body, ['async', 'body']);
      if (
        fields === null
        || fields.functionId !== RUNNER_FUNCTION_ID
        || body === null
        || body.async !== false
        || typeof body.body !== 'string'
        || body.body.length === 0
        || new TextEncoder().encode(body.body).byteLength > MAX_EXECUTION_BODY_BYTES
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      try {
        if (canonicalJson(JSON.parse(body.body)) !== body.body) {
          return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        }
      } catch {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'POST',
        path: `/functions/${encodePath(RUNNER_FUNCTION_ID)}/executions`,
        expectedStatus: 201,
        observeStatus: true,
        bodyText: canonicalJson({ async: false, body: body.body }),
        project(_value, transportStatus) {
          if (transportStatus !== 201) return { transportStatus, execution: null };
          throw new TypeError('missing execution response');
        },
        projectException: projectExecutionException,
        projectSafeResponse: projectExecutionResponse,
      });
    }),
  };
  const frozen = Object.freeze(operator);
  AUTHENTIC_OPERATOR_CLIENTS.set(frozen, context);
  return frozen;
}

export function isAuthenticTestCloudOperatorClient(value, context) {
  return AUTHENTIC_OPERATOR_CLIENTS.get(value) === context;
}

function makeControlSurface(handle, context, fetchDependency) {
  const request = createRequest(handle, context, fetchDependency);
  const rows = new Set();
  const transactions = new Set();
  const users = new Set();
  const sessions = new Set();
  const rowKey = (tableId, rowId) => `${tableId}\u0000${rowId}`;
  const sessionKey = (userId, sessionId) => `${userId}\u0000${sessionId}`;

  const control = {
    getRow: operation(async (args) => {
      const fields = readExactDataObject(args, ['rowId', 'tableId']);
      if (fields === null || !rowLocationAllowed(fields.tableId, fields.rowId)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'GET',
        path: `/tablesdb/${DATABASE_ID}/tables/${encodePath(fields.tableId)}/rows/${encodePath(fields.rowId)}`,
        expectedStatus: 200,
        observeStatus: true,
        project(value, status) {
          if (status === 404) return { data: null, rowId: fields.rowId };
          if (status !== 200) throw new TypeError('invalid row response status');
          const projected = rowProjection(value, fields.rowId, fields.tableId);
          rows.add(rowKey(fields.tableId, fields.rowId));
          if (
            fields.tableId === LEASE_TABLE_ID
            && fields.rowId === LEASE_ROW_ID
            && isProviderId(projected.data.userId)
          ) users.add(projected.data.userId);
          return projected;
        },
      });
    }),

    upsertRow: operation(async (args) => {
      const fields = readExactDataObject(args, ['data', 'rowId', 'tableId']);
      const dataText = fields === null ? null : safeCanonical(fields.data);
      const storageData = fields === null ? null : storageRowData(fields.tableId, fields.data);
      if (fields === null || !rowLocationAllowed(fields.tableId, fields.rowId)
        || dataText === null || storageData === null) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'PUT',
        path: `/tablesdb/${DATABASE_ID}/tables/${encodePath(fields.tableId)}/rows/${encodePath(fields.rowId)}`,
        expectedStatus: 201,
        bodyText: canonicalJson({ data: storageData }),
        project(value) {
          const projected = rowProjection(value, fields.rowId, fields.tableId);
          rows.add(rowKey(fields.tableId, fields.rowId));
          return projected;
        },
      });
    }),

    updateRow: operation(async (args) => {
      const fields = readExactDataObject(args, ['data', 'rowId', 'tableId']);
      const storageData = fields === null ? null : storageRowData(fields.tableId, fields.data);
      if (
        fields === null
        || !rows.has(rowKey(fields.tableId, fields.rowId))
        || safeCanonical(fields.data) === null
        || storageData === null
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'PATCH',
        path: `/tablesdb/${DATABASE_ID}/tables/${encodePath(fields.tableId)}/rows/${encodePath(fields.rowId)}`,
        expectedStatus: 200,
        bodyText: canonicalJson({ data: storageData }),
        project: (value) => rowProjection(value, fields.rowId, fields.tableId),
      });
    }),

    deleteRow: operation(async (args) => {
      const fields = readExactDataObject(args, ['rowId', 'tableId']);
      const key = fields === null ? null : rowKey(fields.tableId, fields.rowId);
      if (fields === null || !rows.has(key)) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'DELETE',
        path: `/tablesdb/${DATABASE_ID}/tables/${encodePath(fields.tableId)}/rows/${encodePath(fields.rowId)}`,
        expectedStatus: 204,
        responseKind: 'empty',
        project() {
          rows.delete(key);
          return { deleted: true, rowId: fields.rowId };
        },
      });
    }),

    incrementRowColumn: operation(async (args) => {
      const fields = readExactDataObject(args, ['column', 'max', 'rowId', 'tableId', 'value']);
      if (
        fields === null
        || fields.tableId !== LEASE_TABLE_ID
        || fields.rowId !== LEASE_ROW_ID
        || fields.column !== 'leaseVersion'
        || !Number.isSafeInteger(fields.value)
        || !Number.isSafeInteger(fields.max)
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'PATCH',
        path: `/tablesdb/${DATABASE_ID}/tables/${LEASE_TABLE_ID}/rows/${LEASE_ROW_ID}/leaseVersion/increment`,
        expectedStatus: 200,
        bodyText: canonicalJson({ max: fields.max, value: fields.value }),
        project(value) {
          const projected = rowProjection(value, LEASE_ROW_ID, LEASE_TABLE_ID);
          rows.add(rowKey(LEASE_TABLE_ID, LEASE_ROW_ID));
          return projected;
        },
      });
    }),

    createTransaction: operation(async (args) => {
      const fields = readExactDataObject(args, ['ttl']);
      if (fields === null || !Number.isSafeInteger(fields.ttl) || fields.ttl < 1 || fields.ttl > 3600) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'POST',
        path: '/tablesdb/transactions',
        expectedStatus: 201,
        bodyText: canonicalJson({ ttl: fields.ttl }),
        project(value) {
          const projected = transactionProjection(value);
          transactions.add(projected.transactionId);
          return projected;
        },
      });
    }),

    getTransaction: operation(async (args) => {
      const fields = readExactDataObject(args, ['transactionId']);
      if (fields === null || !transactions.has(fields.transactionId)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'GET',
        path: `/tablesdb/transactions/${encodePath(fields.transactionId)}`,
        expectedStatus: 200,
        project: (value) => transactionProjection(value, fields.transactionId),
      });
    }),

    createTransactionOperations: operation(async (args) => {
      const fields = readExactDataObject(args, ['operations', 'transactionId']);
      if (
        fields === null
        || !transactions.has(fields.transactionId)
        || !Array.isArray(fields.operations)
        || fields.operations.length === 0
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      const wire = [];
      const createdRows = [];
      for (const operationValue of fields.operations) {
        if (!isPlainObject(operationValue)) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        if (operationValue.action === 'createRow') {
          const item = readExactDataObject(operationValue, ['action', 'data', 'rowId', 'tableId']);
          const storageData = item === null ? null : storageRowData(item.tableId, item.data);
          if (item === null || !rowLocationAllowed(item.tableId, item.rowId)
            || safeCanonical(item.data) === null || storageData === null) {
            return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
          }
          wire.push({
            action: 'create',
            databaseId: DATABASE_ID,
            tableId: item.tableId,
            rowId: item.rowId,
            data: storageData,
          });
          createdRows.push(rowKey(item.tableId, item.rowId));
        } else if (operationValue.action === 'upsertRow') {
          const item = readExactDataObject(operationValue, ['action', 'data', 'rowId', 'tableId']);
          const storageData = item === null ? null : storageRowData(item.tableId, item.data);
          if (item === null || !rowLocationAllowed(item.tableId, item.rowId)
            || safeCanonical(item.data) === null || storageData === null) {
            return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
          }
          wire.push({
            action: 'upsert',
            databaseId: DATABASE_ID,
            tableId: item.tableId,
            rowId: item.rowId,
            data: storageData,
          });
          createdRows.push(rowKey(item.tableId, item.rowId));
        } else if (operationValue.action === 'updateRow') {
          const item = readExactDataObject(operationValue, ['action', 'data', 'rowId', 'tableId']);
          const storageData = item === null ? null : storageRowData(item.tableId, item.data);
          if (
            item === null
            || !rows.has(rowKey(item.tableId, item.rowId))
            || safeCanonical(item.data) === null
            || storageData === null
          ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
          wire.push({
            action: 'update',
            databaseId: DATABASE_ID,
            tableId: item.tableId,
            rowId: item.rowId,
            data: storageData,
          });
        } else if (operationValue.action === 'incrementRowColumn') {
          const item = readExactDataObject(
            operationValue,
            ['action', 'column', 'max', 'rowId', 'tableId', 'value'],
          );
          if (
            item === null
            || item.tableId !== LEASE_TABLE_ID
            || item.rowId !== LEASE_ROW_ID
            || item.column !== 'leaseVersion'
            || !Number.isSafeInteger(item.value)
            || !Number.isSafeInteger(item.max)
          ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
          wire.push({
            action: 'increment',
            databaseId: DATABASE_ID,
            tableId: LEASE_TABLE_ID,
            rowId: LEASE_ROW_ID,
            data: {
              column: 'leaseVersion',
              value: item.value,
              max: item.max,
            },
          });
        } else {
          return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        }
      }
      return request({
        method: 'POST',
        path: `/tablesdb/transactions/${encodePath(fields.transactionId)}/operations`,
        expectedStatus: 201,
        bodyText: canonicalJson({ operations: wire }),
        project(value) {
          const projected = transactionProjection(value, fields.transactionId);
          for (const key of createdRows) rows.add(key);
          return projected;
        },
      });
    }),

    commitOrRollbackTransaction: operation(async (args) => {
      const fields = readExactDataObject(args, ['action', 'transactionId']);
      if (
        fields === null
        || !transactions.has(fields.transactionId)
        || !['commit', 'rollback'].includes(fields.action)
      ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      return request({
        method: 'PATCH',
        path: `/tablesdb/transactions/${encodePath(fields.transactionId)}`,
        expectedStatus: 200,
        bodyText: canonicalJson({ [fields.action]: true }),
        unknownCommit: fields.action === 'commit',
        project: (value) => transactionProjection(value, fields.transactionId),
      });
    }),

    listFixedUserSessions: operation(async (args) => {
      const fields = readExactDataObject(args, ['userId']);
      if (fields === null || !users.has(fields.userId)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'GET',
        path: `/users/${encodePath(fields.userId)}/sessions`,
        expectedStatus: 200,
        project(value) {
          const object = responseObject(value);
          if (!Number.isSafeInteger(object.total) || !Array.isArray(object.sessions)) {
            throw new TypeError('invalid sessions response');
          }
          const projected = object.sessions.map((session) => {
            const candidate = responseObject(session);
            if (!isProviderId(candidate.$id) || candidate.userId !== fields.userId) {
              throw new TypeError('invalid session');
            }
            sessions.add(sessionKey(fields.userId, candidate.$id));
            return { sessionId: candidate.$id, userId: fields.userId };
          });
          if (object.total !== projected.length) throw new TypeError('invalid session total');
          return { sessions: projected, total: object.total };
        },
      });
    }),

    deleteFixedUserSession: operation(async (args) => {
      const fields = readExactDataObject(args, ['sessionId', 'userId']);
      const key = fields === null ? null : sessionKey(fields.userId, fields.sessionId);
      if (fields === null || !users.has(fields.userId) || !sessions.has(key)) {
        return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
      }
      return request({
        method: 'DELETE',
        path: `/users/${encodePath(fields.userId)}/sessions/${encodePath(fields.sessionId)}`,
        expectedStatus: 204,
        responseKind: 'empty',
        project() {
          sessions.delete(key);
          return { deleted: true, sessionId: fields.sessionId, userId: fields.userId };
        },
      });
    }),
  };
  return Object.freeze(control);
}

function makeControl(handle, context, fetchDependency) {
  const control = makeControlSurface(handle, context, fetchDependency);
  AUTHENTIC_CONTROL_CLIENTS.set(control, context);
  return control;
}

export function isAuthenticTestCloudControlClient(value, context) {
  return AUTHENTIC_CONTROL_CLIENTS.get(value) === context;
}

function makeRecoveryControl(handle, context, fetchDependency) {
  const receiver = makeControlSurface(handle, context, fetchDependency);
  const control = Object.freeze(Object.fromEntries(
    RECOVERY_CONTROL_KEYS.map((key) => [key, receiver[key]]),
  ));
  AUTHENTIC_RECOVERY_CONTROL_CLIENTS.set(control, context);
  return control;
}

function recoveryProjectionDigest(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function projectRecoveryRow(value, status, secret, authorization) {
  let state;
  let ownerOnlyProjectionDigest = null;
  if (status === 404) {
    state = { schemaVersion: 'tablesdb-row-state.v1', presence: 'absent',
      dataDigest: null, permissionsDigest: null };
  } else {
    if (status !== 200) throw new TypeError('invalid recovery row response');
    const object = responseObject(value);
    if (object.$id !== authorization.target.rowId
      || !Array.isArray(object.$permissions)
      || Object.keys(object.$permissions).length !== object.$permissions.length
      || !object.$permissions.every((entry) => typeof entry === 'string')
      || canonicalJson(object).includes(secret)) throw new TypeError('invalid recovery row response');
    const permissions = [...object.$permissions].sort();
    const data = Object.fromEntries(Object.entries(object)
      .filter(([key]) => key !== '$permissions')
      .sort(([left], [right]) => left.localeCompare(right)));
    state = { schemaVersion: 'tablesdb-row-state.v1', presence: 'present',
      dataDigest: recoveryProjectionDigest(data),
      permissionsDigest: recoveryProjectionDigest(permissions) };
    ownerOnlyProjectionDigest = recoveryProjectionDigest({
      ...state,
      permissionsDigest: recoveryProjectionDigest([...authorization.target.ownerPermissions].sort()),
    });
  }
  const projectionDigest = recoveryProjectionDigest(state);
  const projection = state.presence === 'absent' ? 'absent'
    : projectionDigest === authorization.desiredProjectionDigest ? 'desired'
      : projectionDigest === authorization.oldProjectionDigest ? 'old' : 'invalid';
  const projected = Object.freeze({ projection, projectionDigest });
  if (ownerOnlyProjectionDigest !== null) {
    RECOVERY_PROJECTION_DIGESTS.set(projected, Object.freeze({ ownerOnlyProjectionDigest }));
  }
  return projected;
}

function projectRecoveryFile(value, status, secret, authorization) {
  let state;
  let ownerOnlyProjectionDigest = null;
  if (status === 404) {
    state = { schemaVersion: 'storage-file-metadata-state.v1', presence: 'absent',
      metadataDigest: null, permissionsDigest: null };
  } else {
    if (status !== 200) throw new TypeError('invalid recovery file response');
    const object = responseObject(value);
    if (object.$id !== authorization.target.fileId
      || object.bucketId !== authorization.target.bucketId
      || !Array.isArray(object.$permissions)
      || Object.keys(object.$permissions).length !== object.$permissions.length
      || !object.$permissions.every((entry) => typeof entry === 'string')
      || canonicalJson(object).includes(secret)) throw new TypeError('invalid recovery file response');
    const permissions = [...object.$permissions].sort();
    const metadata = Object.fromEntries(Object.entries(object)
      .filter(([key]) => key !== '$permissions')
      .sort(([left], [right]) => left.localeCompare(right)));
    state = { schemaVersion: 'storage-file-metadata-state.v1', presence: 'present',
      metadataDigest: recoveryProjectionDigest(metadata),
      permissionsDigest: recoveryProjectionDigest(permissions) };
    ownerOnlyProjectionDigest = recoveryProjectionDigest({
      ...state,
      permissionsDigest: recoveryProjectionDigest([...authorization.target.ownerPermissions].sort()),
    });
  }
  const projectionDigest = recoveryProjectionDigest(state);
  const projection = state.presence === 'absent' ? 'absent'
    : projectionDigest === authorization.desiredProjectionDigest ? 'desired'
      : projectionDigest === authorization.oldProjectionDigest ? 'old' : 'invalid';
  const projected = Object.freeze({ projection, projectionDigest });
  if (ownerOnlyProjectionDigest !== null) {
    RECOVERY_PROJECTION_DIGESTS.set(projected, Object.freeze({ ownerOnlyProjectionDigest }));
  }
  return projected;
}

function projectRecoveryQueryRows(rows) {
  const projected = [];
  for (const row of rows) {
    const descriptors = safeOwnDescriptors(row);
    const id = descriptors?.$id;
    const projectId = descriptors?.projectId;
    if (id?.enumerable !== true || !Object.hasOwn(id, 'value') || typeof id.value !== 'string'
      || projectId?.enumerable !== true || !Object.hasOwn(projectId, 'value')
      || typeof projectId.value !== 'string') {
      throw new TypeError('invalid recovery query response');
    }
    projected.push(Object.freeze({ $id: id.value, projectId: projectId.value }));
  }
  return Object.freeze(projected.sort((left, right) => ordinalCompare(left.$id, right.$id)));
}

function projectRecoveryQuery(value, authorization) {
  const object = responseObject(value);
  if (!Number.isSafeInteger(object.total) || object.total < 0
    || !Array.isArray(object.rows)
    || Object.keys(object.rows).length !== object.rows.length
    || !object.rows.every((row) => isPlainObject(row)))
    throw new TypeError('invalid recovery query response');
  const rows = projectRecoveryQueryRows(object.rows);
  const projectionDigest = recoveryProjectionDigest({
    schemaVersion: 'tablesdb-query-state.v1', total: object.total,
    rowsDigest: recoveryProjectionDigest(rows),
  });
  const exactTarget = object.total === authorization.target.expectedTotal
    && object.rows.length === object.total
    && rows.every((row) => row.projectId === authorization.target.projectId);
  const projection = exactTarget && projectionDigest === authorization.desiredProjectionDigest
    ? 'desired' : exactTarget && projectionDigest === authorization.oldProjectionDigest
      ? 'old' : 'invalid';
  return Object.freeze({ projection, projectionDigest });
}

function recoveryReadTargetPath(target) {
  if (target?.kind === 'file') return `/storage/buckets/${encodePath(target.bucketId)}`
    + `/files/${encodePath(target.fileId)}`;
  throw new TypeError('invalid recovery read target');
}

function recoveryRowTargetPath(target) {
  if (target?.kind !== 'row') throw new TypeError('invalid recovery row target');
  return `/tablesdb/${encodePath(target.databaseId)}/tables/${encodePath(target.tableId)}`
    + `/rows/${encodePath(target.rowId)}`;
}

function requestRecoveryProjection(request, authorization) {
  const target = authorization.target;
  const project = target?.kind === 'row' ? projectRecoveryRow
    : target?.kind === 'file' ? projectRecoveryFile : null;
  const path = target?.kind === 'row' ? recoveryRowTargetPath(target)
    : target?.kind === 'file' ? recoveryReadTargetPath(target) : null;
  if (project === null || path === null) throw new TypeError('invalid recovery target');
  return request({
    method: 'GET', path, expectedStatus: 200, observeStatus: true,
    project(value, status) { return project(value, status, '', authorization); },
    projectSafeResponse(value, status, secret) {
      return project(value, status, secret, authorization);
    },
  });
}

async function mutateRecoveryTarget({authorization, method, request}) {
  const before = await requestRecoveryProjection(request, authorization);
  if (before.status !== 'PASS') return before;
  if (before.value.projectionDigest === authorization.desiredProjectionDigest) {
    return pass({write: 'not-required', projectionDigest: before.value.projectionDigest});
  }
  if (before.value.projection !== 'old') return blocked('TEST_RESPONSE_INVALID');

  const target = authorization.target;
  const path = target.kind === 'row' ? recoveryRowTargetPath(target)
    : recoveryReadTargetPath(target);
  const deleting = method === 'deleteBoundRow' || method === 'deleteBoundFile';
  const write = await request({
    method: deleting ? 'DELETE' : 'PATCH',
    path,
    bodyText: deleting ? undefined : canonicalJson({permissions: target.ownerPermissions}),
    expectedStatus: deleting ? 204 : 200,
    responseKind: deleting ? 'empty' : 'json',
    unknownCommit: true,
    project() { return {acknowledged: true}; },
  });
  const after = await requestRecoveryProjection(request, authorization);
  if (after.status === 'PASS'
    && after.value.projectionDigest === authorization.desiredProjectionDigest) {
    return pass({
      write: write.status === 'PASS' ? 'acknowledged' : 'reconciled',
      projectionDigest: after.value.projectionDigest,
    });
  }
  return write.status === 'BLOCKED' ? write : blocked('TEST_COMMIT_UNKNOWN');
}

function makeRecoveryProduct(handle, context, fetchDependency) {
  const request = createRequest(handle, context, fetchDependency);
  const unavailable = () => operation(async () => blocked('TEST_CLIENT_OPERATION_FORBIDDEN'));
  const product = Object.fromEntries(RECOVERY_PRODUCT_KEYS.map((key) => [key, unavailable()]));
  product.listBoundAccountSessions = operation(async (listHandle) => {
    const authorization = consumeRecoveryAccountSessionListHandle({
      context, handle: listHandle, operation: 'listBoundAccountSessions',
    });
    const target = authorization.target;
    return request({
      method: 'GET',
      path: `/users/${encodePath(target.userId)}/sessions`,
      expectedStatus: 200,
      project(value) {
        const response = responseObject(value);
        if (!Number.isSafeInteger(response.total) || !Array.isArray(response.sessions)
          || response.total !== response.sessions.length) throw new TypeError('invalid sessions response');
        const boundIds = new Set(target.sessionIds);
        const sessionIds=[];
        for (const session of response.sessions) {
          const candidate = responseObject(session);
          if (!isProviderId(candidate.$id) || candidate.userId !== target.userId
            || !boundIds.has(candidate.$id)) throw new TypeError('unbound account session');
          sessionIds.push(candidate.$id);
        }
        const observation=recordRecoveryAccountSessionListObservation({
          context,handle:listHandle,sessionIds,
        });
        return { observedCount: response.total, observation };
      },
    });
  });
  product.deleteBoundAccountSession = operation(async (mutationPermit) => {
    const authorization = consumeRecoveryAccountSessionDeletePermit({
      context, permit: mutationPermit, operation: 'deleteBoundAccountSession',
    });
    const target = authorization.target;
    const outcome=await request({
      method: 'DELETE',
      path: `/users/${encodePath(target.userId)}/sessions/${encodePath(target.sessionId)}`,
      expectedStatus: 204,
      responseKind: 'empty',
      unknownCommit: true,
      project() { return { write: 'acknowledged' }; },
    });
    const code=outcome.diagnostics[0]?.code??null;
    recordRecoveryAccountSessionDeleteDisposition({
      context,permit:mutationPermit,
      disposition:outcome.status==='PASS'?'acknowledged'
        :code==='TEST_COMMIT_UNKNOWN'?'unknown':'blocked',
    });
    return outcome;
  });
  product.getBoundRow = operation(async (stepHandle) => {
    const authorization = consumeRecoveryStepHandle({
      context, handle: stepHandle, operation: 'getBoundRow',
    });
    return requestRecoveryProjection(request, authorization);
  });
  product.getBoundFile = operation(async (stepHandle) => {
    const authorization = consumeRecoveryStepHandle({
      context, handle: stepHandle, operation: 'getBoundFile',
    });
    return requestRecoveryProjection(request, authorization);
  });
  for (const method of [
    'deleteBoundRow',
    'deleteBoundFile',
    'convergeBoundRowOwnerPermissions',
    'convergeBoundFileOwnerPermissions',
  ]) {
    product[method] = operation(async (mutationPermit) => {
      const authorization = consumeRecoveryMutationPermit({
        context, permit: mutationPermit, operation: method,
      });
      return mutateRecoveryTarget({authorization, method, request});
    });
  }
  const queryLimits = Object.freeze({
    queryBoundProjectShares: 3,
    queryBoundProjectSnapshots: 1,
    queryBoundProjectArtifactReferences: 1,
    queryBoundProjectArtifactsExactSet: 4,
    queryBoundProjectArtifactVersionsExactSet: 6,
  });
  for (const [method, limit] of Object.entries(queryLimits)) {
    product[method] = operation(async (stepHandle) => {
      const authorization = consumeRecoveryStepHandle({context, handle: stepHandle, operation: method});
      const target = authorization.target;
      const equality = encodeURIComponent(canonicalJson({attribute: 'projectId', method: 'equal',
        values: [target.projectId]}));
      const bounded = encodeURIComponent(canonicalJson({method: 'limit', values: [limit]}));
      return request({
        method: 'GET', expectedStatus: 200,
        path: `/tablesdb/${encodePath(target.databaseId)}/tables/${encodePath(target.tableId)}`
          + `/rows?queries%5B%5D=${equality}&queries%5B%5D=${bounded}&total=true`,
        project(value) { return projectRecoveryQuery(value, authorization); },
      });
    });
  }
  Object.freeze(product);
  AUTHENTIC_RECOVERY_PRODUCT_CLIENTS.set(product, context);
  return product;
}

export function isAuthenticTestCloudRecoveryControlClient(value, context) {
  try {
    return AUTHENTIC_RECOVERY_CONTROL_CLIENTS.get(value) === context;
  } catch {
    return false;
  }
}

export function isAuthenticTestCloudRecoveryProductClient(value, context) {
  try {
    return AUTHENTIC_RECOVERY_PRODUCT_CLIENTS.get(value) === context;
  } catch {
    return false;
  }
}

export function readRecoveryOwnerOnlyProjectionDigest(value) {
  try {
    const record = RECOVERY_PROJECTION_DIGESTS.get(value);
    return typeof record?.ownerOnlyProjectionDigest === 'string'
      && SHA256_PATTERN.test(record.ownerOnlyProjectionDigest)
      ? record.ownerOnlyProjectionDigest
      : null;
  } catch {
    return null;
  }
}

export function createTestCloudClients(args) {
  const fields = readExactDataObject(args, ARGUMENT_KEYS);
  if (
    fields === null
    || !isAuthenticTestEnvironmentContext(fields.context)
    || typeof fields.fetch !== 'function'
  ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');

  if (!isTestEnvironmentContextBoundToCredentialHandles(
    fields.context,
    fields.credentialHandles,
  )) return blocked('TEST_CREDENTIAL_CLASS_INVALID');

  const handles = validateCredentialHandles(fields.credentialHandles);
  if (handles === null) return blocked('TEST_CREDENTIAL_CLASS_INVALID');

  return pass(Object.freeze({
    operator: makeOperator(handles.operator, fields.context, fields.fetch),
    fixture: makeControl(handles.fixture, fields.context, fields.fetch),
  }));
}

export function createTestCloudRecoveryClients(args) {
  const fields = readExactDataObject(args, RECOVERY_ARGUMENT_KEYS);
  if (
    fields === null
    || !isAuthenticTestRecoveryEnvironmentContext(fields.context)
    || typeof fields.fetch !== 'function'
    || utilTypes.isProxy(fields.fetch)
  ) return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');

  if (!isTestEnvironmentContextBoundToCredentialHandles(
    fields.context,
    fields.recoveryHandle,
  )) return blocked('TEST_CREDENTIAL_CLASS_INVALID');
  if (!validateRecoveryHandle(fields.recoveryHandle)) {
    return blocked('TEST_CREDENTIAL_CLASS_INVALID');
  }

  return pass(Object.freeze({
    control: makeRecoveryControl(fields.recoveryHandle, fields.context, fields.fetch),
    product: makeRecoveryProduct(fields.recoveryHandle, fields.context, fields.fetch),
  }));
}


class RunnerVariableResponseError extends Error {}
class RunnerVariableExpectationError extends Error {}

function runnerDigest(value) {
  return 'sha256:' + createHash('sha256').update(value).digest('hex');
}

function isRunnerDigest(value) {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function exactNominalRunnerToken(value) {
  try {
    return value !== null && typeof value === 'object' && !CAPTURED_IS_PROXY(value)
      && Object.getPrototypeOf(value) === null && Object.isFrozen(value)
      && Reflect.ownKeys(value).length === 0;
  } catch {
    return false;
  }
}

function readDedicatedRunnerObject(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || CAPTURED_IS_PROXY(value)) return null;
    return readExactDataObject(value, keys);
  } catch {
    return null;
  }
}

function exactRunnerReadSecret(value) {
  try {
    if (
      typeof value !== 'function' || CAPTURED_IS_PROXY(value)
      || value.name !== 'readSecret' || value.length !== 0
    ) return false;
    const source = CAPTURED_REFLECT_APPLY(CAPTURED_FUNCTION_TO_STRING, value, []);
    return typeof source === 'string' && !/\[native code\]/u.test(source);
  } catch {
    return false;
  }
}

function readRunnerPass(value, valueKeys) {
  const outer = readDedicatedRunnerObject(value, ['status', 'value', 'diagnostics']);
  if (
    outer === null || outer.status !== 'PASS' || !Object.isFrozen(value)
    || !Array.isArray(outer.diagnostics) || !Object.isFrozen(outer.diagnostics)
    || outer.diagnostics.length !== 0 || Reflect.ownKeys(outer.diagnostics).length !== 1
  ) return null;
  const fields = readDedicatedRunnerObject(outer.value, valueKeys);
  if (fields === null || !Object.isFrozen(outer.value)) return null;
  return Object.freeze({ result: value, value: outer.value, fields });
}

function assertRunnerScalar(value) {
  if (typeof value !== 'string' || value.length === 0) throw new RunnerVariableResponseError();
  let scalars = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const trailing = value.charCodeAt(index + 1);
      if (!(trailing >= 0xdc00 && trailing <= 0xdfff)) throw new RunnerVariableResponseError();
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new RunnerVariableResponseError();
    }
    scalars += 1;
    if (scalars > 8192) throw new RunnerVariableResponseError();
  }
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length < 1 || bytes.length > 8192) throw new RunnerVariableResponseError();
  return bytes;
}

function normalizedRunnerTimestamp(value) {
  if (typeof value !== 'string') throw new RunnerVariableResponseError();
  const match = VARIABLE_TIMESTAMP_PATTERN.exec(value);
  if (match === null) throw new RunnerVariableResponseError();
  const normalized = value.endsWith('+00:00') ? value.slice(0, -6) + 'Z' : value;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const hour = Number(value.slice(11, 13));
  const minute = Number(value.slice(14, 16));
  const second = Number(value.slice(17, 19));
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1]
    || hour > 23 || minute > 59 || second > 59
  ) throw new RunnerVariableResponseError();
  return normalized;
}

function exactDenseRunnerArray(value, length) {
  if (!Array.isArray(value) || CAPTURED_IS_PROXY(value) || value.length !== length) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1 || keys[length] !== 'length') return false;
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      keys[index] !== String(index) || descriptor === undefined
      || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable
    ) return false;
  }
  return true;
}

function projectRunnerVariableObservation(raw, expected) {
  const root = readDedicatedRunnerObject(raw, ['total', 'variables']);
  if (
    root === null || root.total !== 16 || !Number.isSafeInteger(root.total)
    || !exactDenseRunnerArray(root.variables, 16)
  ) throw new RunnerVariableResponseError();
  const ids = new Set();
  const digests = new Map();
  for (const candidate of root.variables) {
    const fields = readDedicatedRunnerObject(candidate, RUNNER_VARIABLE_RAW_KEYS);
    if (
      fields === null || typeof fields.$id !== 'string'
      || !VARIABLE_ID_PATTERN.test(fields.$id) || ids.has(fields.$id)
      || typeof fields.key !== 'string' || !RUNNER_VARIABLE_KEY_SET.has(fields.key)
      || digests.has(fields.key) || fields.secret !== false
      || fields.resourceType !== 'function' || fields.resourceId !== RUNNER_FUNCTION_ID
    ) throw new RunnerVariableResponseError();
    const createdAt = normalizedRunnerTimestamp(fields.$createdAt);
    const updatedAt = normalizedRunnerTimestamp(fields.$updatedAt);
    if (createdAt > updatedAt) throw new RunnerVariableResponseError();
    ids.add(fields.$id);
    digests.set(fields.key, runnerDigest(assertRunnerScalar(fields.value)));
  }
  if (digests.size !== RUNNER_VARIABLE_KEYS.length) throw new RunnerVariableResponseError();
  if (
    Object.hasOwn(expected, 'identityBindingsDigest')
    && (
      !isRunnerDigest(expected.identityBindingsDigest)
      || digests.get('VERIFICATION_IDENTITY_BINDINGS_DIGEST')
        !== runnerDigest(Buffer.from(expected.identityBindingsDigest, 'utf8'))
    )
  ) throw new RunnerVariableExpectationError();
  const variables = RUNNER_VARIABLE_KEYS.map((key) => Object.freeze({
    key, valueDigest: digests.get(key),
  }));
  const expectationDigest = runnerDigest(Buffer.from(canonicalJson({
    total: 16,
    staticTotal: 15,
    identityQualifiedKey: 'VERIFICATION_IDENTITY_BINDINGS_DIGEST',
    variables,
  }), 'utf8'));
  if (expected.expectationDigest !== expectationDigest) throw new RunnerVariableExpectationError();
  const runnerVariableReadbackDigest = runnerDigest(Buffer.from(canonicalJson({
    schemaVersion: 'test-cloud.runner-variable-readback.v1',
    environmentDigest: expected.environmentDigest,
    providerContractDigest: expected.providerContractDigest,
    functionIdDigest: runnerDigest(Buffer.from(RUNNER_FUNCTION_ID, 'utf8')),
    variables,
  }), 'utf8'));
  return deepFreeze({ total: 16, variables, runnerVariableReadbackDigest });
}

function assertNoDuplicateRunnerJsonKeys(text) {
  let cursor = 0;
  const whitespace = () => {
    while (cursor < text.length && /[\x20\x09\x0a\x0d]/u.test(text[cursor])) cursor += 1;
  };
  const stringToken = () => {
    if (text[cursor] !== '"') throw new RunnerVariableResponseError();
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      const code = text.charCodeAt(cursor);
      if (code === 0x22) {
        cursor += 1;
        try {
          return JSON.parse(text.slice(start, cursor));
        } catch {
          throw new RunnerVariableResponseError();
        }
      }
      if (code < 0x20) throw new RunnerVariableResponseError();
      if (code === 0x5c) {
        cursor += 1;
        if (cursor >= text.length || !/["\\/bfnrtu]/u.test(text[cursor])) {
          throw new RunnerVariableResponseError();
        }
        if (text[cursor] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(cursor + 1, cursor + 5))) {
            throw new RunnerVariableResponseError();
          }
          cursor += 4;
        }
      }
      cursor += 1;
    }
    throw new RunnerVariableResponseError();
  };
  const numberToken = () => {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      text.slice(cursor),
    );
    if (match === null) throw new RunnerVariableResponseError();
    cursor += match[0].length;
  };
  const valueToken = () => {
    whitespace();
    if (text[cursor] === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set();
      if (text[cursor] === '}') {
        cursor += 1;
        return;
      }
      while (true) {
        const key = stringToken();
        if (keys.has(key)) throw new RunnerVariableResponseError();
        keys.add(key);
        whitespace();
        if (text[cursor] !== ':') throw new RunnerVariableResponseError();
        cursor += 1;
        valueToken();
        whitespace();
        if (text[cursor] === '}') {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ',') throw new RunnerVariableResponseError();
        cursor += 1;
        whitespace();
      }
    }
    if (text[cursor] === '[') {
      cursor += 1;
      whitespace();
      if (text[cursor] === ']') {
        cursor += 1;
        return;
      }
      while (true) {
        valueToken();
        whitespace();
        if (text[cursor] === ']') {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ',') throw new RunnerVariableResponseError();
        cursor += 1;
      }
    }
    if (text[cursor] === '"') {
      stringToken();
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, cursor)) {
        cursor += literal.length;
        return;
      }
    }
    numberToken();
  };
  whitespace();
  valueToken();
  whitespace();
  if (cursor !== text.length) throw new RunnerVariableResponseError();
}

function decodeRunnerObservation(bytes) {
  if (
    !(bytes instanceof Uint8Array) || CAPTURED_IS_PROXY(bytes)
    || bytes.byteLength < 1 || bytes.byteLength > MAX_RESPONSE_BYTES
  ) throw new RunnerVariableResponseError();
  const stable = new Uint8Array(bytes.byteLength);
  stable.set(bytes);
  let text;
  try {
    text = new CAPTURED_TEXT_DECODER('utf-8', { fatal: true }).decode(stable);
  } catch {
    throw new RunnerVariableResponseError();
  }
  assertNoDuplicateRunnerJsonKeys(text);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new RunnerVariableResponseError();
  }
  return parsed;
}

function parityRunnerObservationDigest(fields, projection) {
  return runnerDigest(Buffer.from(canonicalJson({
    schemaVersion: 'verification-parity-output.v1',
    operation: 'validate-runner-variable-observation',
    value: {
      expectedEnvironmentDigest: fields.expectedEnvironmentDigest,
      expectedProviderContractDigest: fields.expectedProviderContractDigest,
      expectedSetupReadbackDigest: fields.expectedSetupReadbackDigest,
      runnerVariableReadbackDigest: projection.runnerVariableReadbackDigest,
      total: projection.total,
      variables: projection.variables,
    },
  }), 'utf8'));
}

function terminalRunnerRequestBlock() {
  const prior = runnerVariableRequestRecord;
  if (prior.state === 'BLOCKED') return prior;
  const successor = Object.freeze({
    state: 'BLOCKED', version: prior.version + 1, qualification: prior.qualification,
  });
  runnerVariableRequestRecord = successor;
  if (exactNominalRunnerToken(prior.qualification)) {
    RUNNER_VARIABLE_REQUEST_QUALIFICATIONS.set(prior.qualification, successor);
  }
  return successor;
}

function activeRunnerQualification(runtimeQualification) {
  try {
    return readTestCloudRuntimeLifecycle() === 'ACTIVE'
      && authenticateTestCloudRuntimeActive(Object.freeze({ runtimeQualification })) === true;
  } catch {
    return false;
  }
}

function requestRecordIsCurrent(record) {
  return runnerVariableRequestRecord === record
    && RUNNER_VARIABLE_REQUEST_QUALIFICATIONS.get(record.qualification) === record
    && activeRunnerQualification(record.runtimeQualification);
}

function registerTestCloudRunnerVariableAuthority(registration) {
  try {
    const lifecycle = readTestCloudRuntimeLifecycle();
    const hubDescriptor = Object.getOwnPropertyDescriptor(
      globalThis, RUNNER_VARIABLE_BOOTSTRAP_HUB_PROPERTY,
    );
    const descriptor = Object.getOwnPropertyDescriptor(
      qualifyTestCloudRunnerVariableReadbackRequest, RUNNER_VARIABLE_AUTHORITY_PROPERTY,
    );
    if (
      arguments.length !== 1 || this !== qualifyTestCloudRunnerVariableReadbackRequest
      || lifecycle !== 'BOOTSTRAPPING'
      || hubDescriptor === undefined
      || !Object.hasOwn(hubDescriptor, 'value')
      || hubDescriptor.enumerable !== false
      || hubDescriptor.configurable !== true
      || hubDescriptor.writable !== false
      || descriptor?.value !== registerTestCloudRunnerVariableAuthority
      || descriptor.enumerable !== false
      || descriptor.configurable !== true
      || descriptor.writable !== false
      || isAuthenticTestCloudBootstrapHub(hubDescriptor.value) !== true
    ) return false;
    const fields = readDedicatedRunnerObject(registration, [
      'receiver', 'authenticateRunnerVariableReadbackRequestEvidence', 'moduleUrl',
    ]);
    if (
      fields === null || !Object.isFrozen(registration)
      || !exactNominalRunnerToken(fields.receiver)
      || typeof fields.authenticateRunnerVariableReadbackRequestEvidence !== 'function'
      || CAPTURED_IS_PROXY(fields.authenticateRunnerVariableReadbackRequestEvidence)
      || fields.authenticateRunnerVariableReadbackRequestEvidence.length !== 1
      || fields.authenticateRunnerVariableReadbackRequestEvidence.name
        !== 'authenticateRunnerVariableReadbackRequestEvidence'
      || utilTypes.isAsyncFunction(fields.authenticateRunnerVariableReadbackRequestEvidence)
      || fields.moduleUrl !== RUNNER_VARIABLE_PROVIDER_MODULE_URL
      || !Reflect.deleteProperty(
        qualifyTestCloudRunnerVariableReadbackRequest, RUNNER_VARIABLE_AUTHORITY_PROPERTY,
      )
      || Object.hasOwn(
        qualifyTestCloudRunnerVariableReadbackRequest, RUNNER_VARIABLE_AUTHORITY_PROPERTY,
      )
    ) return false;
    authenticateRunnerVariableReadbackRequestEvidence =
      fields.authenticateRunnerVariableReadbackRequestEvidence;
    authenticateRunnerVariableReadbackRequestEvidenceReceiver = fields.receiver;
    return true;
  } catch {
    return false;
  }
}

export function validateTestCloudRunnerVariableObservation(args) {
  try {
    if (arguments.length !== 1) return blocked('TEST_RESPONSE_INVALID');
    const fields = readDedicatedRunnerObject(args, RUNNER_VARIABLE_OBSERVATION_KEYS);
    if (
      fields === null || !isRunnerDigest(fields.expectedEnvironmentDigest)
      || !isRunnerDigest(fields.expectedProviderContractDigest)
      || !isRunnerDigest(fields.expectedSetupReadbackDigest)
      || !isRunnerDigest(fields.expectedRunnerVariableExpectationDigest)
    ) return blocked('TEST_RESPONSE_INVALID');
    const projection = projectRunnerVariableObservation(
      decodeRunnerObservation(fields.bytes),
      Object.freeze({
        environmentDigest: fields.expectedEnvironmentDigest,
        providerContractDigest: fields.expectedProviderContractDigest,
        expectationDigest: fields.expectedRunnerVariableExpectationDigest,
      }),
    );
    return pass({ outputDigest: parityRunnerObservationDigest(fields, projection) });
  } catch (error) {
    return blocked(error instanceof RunnerVariableExpectationError
      ? 'TEST_SETUP_READBACK_MISMATCH' : 'TEST_RESPONSE_INVALID');
  }
}

export function qualifyTestCloudRunnerVariableReadbackRequest(args) {
  try {
    if (
      arguments.length !== 1 || runnerVariableRequestRecord.state !== 'EMPTY'
      || !DEDICATED_CAPTURE_VALID
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
    }
    const fields = readDedicatedRunnerObject(args, RUNNER_VARIABLE_REQUEST_KEYS);
    const provider = fields === null ? null
      : readRunnerPass(fields.providerContract, PROVIDER_PASS_KEYS);
    const identity = fields === null ? null
      : readRunnerPass(fields.identityBindings, IDENTITY_PASS_KEYS);
    const setup = fields === null ? null
      : readRunnerPass(fields.providerSetupReadback, SETUP_PASS_KEYS);
    if (
      fields === null || provider === null || identity === null || setup === null
      || !exactNominalRunnerToken(provider.fields.qualification)
      || !exactNominalRunnerToken(identity.fields.qualification)
      || !exactNominalRunnerToken(setup.fields.qualification)
      || !isRunnerDigest(provider.fields.providerContractDigest)
      || !isRunnerDigest(identity.fields.identityBindingsDigest)
      || setup.fields.identityBindingsDigest !== identity.fields.identityBindingsDigest
      || !isRunnerDigest(setup.fields.providerSetupReadbackDigest)
      || !isRunnerDigest(setup.fields.runnerVariableExpectationDigest)
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_SETUP_READBACK_MISMATCH');
    }
    if (runnerVariableRequestRecord.state !== 'EMPTY') {
      terminalRunnerRequestBlock();
      return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
    }
    const reservation = Object.freeze({
      state: 'RESERVING', version: 1,
      runtimeQualification: fields.runtimeQualification, context: fields.context,
    });
    runnerVariableRequestRecord = reservation;
    if (
      !isAuthenticTestEnvironmentContext(fields.context)
      || !isTestEnvironmentContextBoundToCredentialHandles(
        fields.context, fields.credentialHandles,
      )
      || !activeRunnerQualification(fields.runtimeQualification)
      || runnerVariableRequestRecord !== reservation
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_SETUP_READBACK_MISMATCH');
    }
    const environmentDigestDescriptor = Object.getOwnPropertyDescriptor(
      fields.context, 'environmentDigest',
    );
    if (
      environmentDigestDescriptor === undefined
      || !Object.hasOwn(environmentDigestDescriptor, 'value')
      || !isRunnerDigest(environmentDigestDescriptor.value)
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_SETUP_READBACK_MISMATCH');
    }
    const environmentDigest = environmentDigestDescriptor.value;
    if (
      fields.credentialHandles === null
      || typeof fields.credentialHandles !== 'object'
      || CAPTURED_IS_PROXY(fields.credentialHandles)
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_CREDENTIAL_CLASS_INVALID');
    }
    const handles = validateCredentialHandles(fields.credentialHandles);
    const operator = handles?.operator;
    const operatorFields = operator === undefined ? null
      : readDedicatedRunnerObject(operator, HANDLE_KEYS);
    const evidenceArgs = Object.freeze({
      runtimeQualification: fields.runtimeQualification,
      context: fields.context,
      providerContract: fields.providerContract,
      identityBindings: fields.identityBindings,
      providerSetupReadback: fields.providerSetupReadback,
    });
    const evidenceAuthentic = typeof authenticateRunnerVariableReadbackRequestEvidence === 'function'
      && CAPTURED_REFLECT_APPLY(
        authenticateRunnerVariableReadbackRequestEvidence,
        authenticateRunnerVariableReadbackRequestEvidenceReceiver,
        [evidenceArgs],
      ) === true;
    if (
      !evidenceAuthentic || runnerVariableRequestRecord !== reservation
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_SETUP_READBACK_MISMATCH');
    }
    if (
      operatorFields === null || operatorFields.credentialClass !== 'test-operator'
      || operatorFields.variableName !== 'APPWRITE_TEST_OPERATOR_API_KEY'
      || canonicalJson(operatorFields.scopes)
        !== canonicalJson(inventory.credentialVariables.operator.scopes)
      || !exactRunnerReadSecret(operatorFields.readSecret)
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_CREDENTIAL_CLASS_INVALID');
    }
    const recipe = deepFreeze({
      endpoint: fields.context.endpoint, projectId: fields.context.projectId,
      functionId: RUNNER_FUNCTION_ID, path: RUNNER_VARIABLE_QUERY_PATH,
      responseFormat: '1.9.5', maximumResponseBytes: MAX_RESPONSE_BYTES,
      timeoutMilliseconds: 10_000, method: 'GET', redirect: 'error',
    });
    const requestQualification = Object.freeze(Object.create(null));
    const qualified = Object.freeze({
      state: 'QUALIFIED', version: 2,
      runtimeQualification: fields.runtimeQualification, context: fields.context,
      environmentDigest,
      providerContractResult: fields.providerContract,
      identityBindingsResult: fields.identityBindings,
      providerSetupReadbackResult: fields.providerSetupReadback,
      providerContractQualification: provider.fields.qualification,
      identityBindingsQualification: identity.fields.qualification,
      providerSetupReadbackQualification: setup.fields.qualification,
      providerContractDigest: provider.fields.providerContractDigest,
      identityBindingsDigest: identity.fields.identityBindingsDigest,
      providerSetupReadbackDigest: setup.fields.providerSetupReadbackDigest,
      runnerVariableExpectationDigest: setup.fields.runnerVariableExpectationDigest,
      operatorHandle: operator, readSecret: operatorFields.readSecret,
      recipe, qualification: requestQualification,
    });
    runnerVariableRequestRecord = qualified;
    RUNNER_VARIABLE_REQUEST_QUALIFICATIONS.set(requestQualification, qualified);
    if (!requestRecordIsCurrent(qualified)) {
      terminalRunnerRequestBlock();
      return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
    }
    return pass({ requestQualification });
  } catch {
    terminalRunnerRequestBlock();
    return blocked('TEST_SETUP_READBACK_MISMATCH');
  }
}

async function readDedicatedRunnerBytes(response, current) {
  const rawLength = response.headers.get('content-length');
  if (
    rawLength !== null
    && (!/^(0|[1-9][0-9]*)$/u.test(rawLength) || Number(rawLength) > MAX_RESPONSE_BYTES)
  ) throw new RunnerVariableResponseError();
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const observation = await reader.read();
    if (!requestRecordIsCurrent(current)) throw new RunnerVariableResponseError();
    if (observation.done) break;
    if (!(observation.value instanceof Uint8Array) || CAPTURED_IS_PROXY(observation.value)) {
      throw new RunnerVariableResponseError();
    }
    length += observation.value.byteLength;
    if (length > MAX_RESPONSE_BYTES) throw new RunnerVariableResponseError();
    const copied = new Uint8Array(observation.value.byteLength);
    copied.set(observation.value);
    chunks.push(copied);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export function createTestCloudRunnerVariableReadbackOperator(args) {
  try {
    if (
      arguments.length !== 1 || runnerVariableRequestRecord.state !== 'QUALIFIED'
      || !DEDICATED_CAPTURE_VALID
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
    }
    const fields = readDedicatedRunnerObject(
      args, ['runtimeQualification', 'requestQualification'],
    );
    const current = fields === null ? undefined
      : RUNNER_VARIABLE_REQUEST_QUALIFICATIONS.get(fields.requestQualification);
    if (
      fields === null || current === undefined || current !== runnerVariableRequestRecord
      || current.state !== 'QUALIFIED'
      || current.runtimeQualification !== fields.runtimeQualification
      || !requestRecordIsCurrent(current)
    ) {
      terminalRunnerRequestBlock();
      return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
    }
    const consumed = Object.freeze({ ...current, state: 'CONSUMED', version: 3 });
    runnerVariableRequestRecord = consumed;
    RUNNER_VARIABLE_REQUEST_QUALIFICATIONS.set(fields.requestQualification, consumed);
    let operator;
    async function getRunnerVariableDigests(methodArgs) {
      let secret;
      let credentialHeaderValue;
      const credentialHeaderSlot = { value: undefined };
      let headers;
      let secretReadAttempted = false;
      let fetchStarted = false;
      try {
        const methodFields = readDedicatedRunnerObject(
          methodArgs, ['runtimeQualification'],
        );
        const operatorRecord = RUNNER_VARIABLE_OPERATORS.get(operator);
        if (
          arguments.length !== 1 || this !== operator || methodFields === null
          || methodFields.runtimeQualification !== consumed.runtimeQualification
          || operatorRecord?.state !== 'UNUSED'
          || runnerVariableRequestRecord !== consumed
          || RUNNER_VARIABLE_REQUEST_QUALIFICATIONS.get(consumed.qualification) !== consumed
          || !activeRunnerQualification(consumed.runtimeQualification)
        ) {
          terminalRunnerRequestBlock();
          return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        }
        RUNNER_VARIABLE_OPERATORS.set(operator, Object.freeze({
          state: 'USED', version: operatorRecord.version + 1, request: consumed,
        }));
        const signal = CAPTURED_ABORT_TIMEOUT(consumed.recipe.timeoutMilliseconds);
        secretReadAttempted = true;
        secret = CAPTURED_REFLECT_APPLY(
          consumed.readSecret, consumed.operatorHandle, CAPTURED_EMPTY_ARGUMENTS,
        );
        if (typeof secret !== 'string' || !/^[\x21-\x7e]{1,8192}$/u.test(secret)) {
          return blocked('TEST_CREDENTIAL_CLASS_INVALID');
        }
        if (!requestRecordIsCurrent(consumed)) {
          return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        }
        credentialHeaderValue = secret;
        credentialHeaderSlot.value = credentialHeaderValue;
        headers = {
          Accept: 'application/json',
          'X-Appwrite-Project': consumed.recipe.projectId,
          'X-Appwrite-Response-Format': consumed.recipe.responseFormat,
          'X-Appwrite-Key': credentialHeaderSlot.value,
        };
        fetchStarted = true;
        const fetchPromise = CAPTURED_REFLECT_APPLY(CAPTURED_FETCH, globalThis, [
          consumed.recipe.endpoint + consumed.recipe.path,
          {
            method: consumed.recipe.method, headers,
            redirect: consumed.recipe.redirect, signal,
          },
        ]);
        if (!utilTypes.isPromise(fetchPromise) || CAPTURED_IS_PROXY(fetchPromise)) {
          return blocked('TEST_RESPONSE_INVALID');
        }
        const response = await fetchPromise;
        if (!requestRecordIsCurrent(consumed)) {
          return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        }
        if (
          response === null || typeof response !== 'object' || CAPTURED_IS_PROXY(response)
          || response.status !== 200 || response.redirected !== false
          || response.headers === null || typeof response.headers?.get !== 'function'
        ) return blocked('TEST_RESPONSE_INVALID');
        const contentType = response.headers.get('content-type');
        if (
          typeof contentType !== 'string'
          || contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json'
        ) return blocked('TEST_RESPONSE_INVALID');
        const bytes = await readDedicatedRunnerBytes(response, consumed);
        if (!requestRecordIsCurrent(consumed)) {
          return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
        }
        const projection = projectRunnerVariableObservation(
          decodeRunnerObservation(bytes),
          Object.freeze({
            environmentDigest: consumed.environmentDigest,
            providerContractDigest: consumed.providerContractDigest,
            identityBindingsDigest: consumed.identityBindingsDigest,
            expectationDigest: consumed.runnerVariableExpectationDigest,
          }),
        );
        const result = pass({
          total: projection.total, variables: projection.variables,
          runnerVariableReadbackDigest: projection.runnerVariableReadbackDigest,
        });
        AUTHENTIC_RUNNER_VARIABLE_RESULTS.set(result, Object.freeze({
          result, requestRecord: consumed,
          runtimeQualification: consumed.runtimeQualification,
          context: consumed.context,
          providerContractQualification: consumed.providerContractQualification,
          identityBindingsQualification: consumed.identityBindingsQualification,
          providerSetupReadbackQualification: consumed.providerSetupReadbackQualification,
          runnerVariableReadbackDigest: projection.runnerVariableReadbackDigest,
        }));
        return result;
      } catch (error) {
        if (error instanceof RunnerVariableExpectationError) {
          return blocked('TEST_SETUP_READBACK_MISMATCH');
        }
        if (error instanceof RunnerVariableResponseError || fetchStarted) {
          return blocked('TEST_RESPONSE_INVALID');
        }
        return blocked(secretReadAttempted
          ? 'TEST_CREDENTIAL_CLASS_INVALID' : 'TEST_CLIENT_OPERATION_FORBIDDEN');
      } finally {
        if (headers !== undefined) headers['X-Appwrite-Key'] = undefined;
        credentialHeaderSlot.value = undefined;
        credentialHeaderValue = undefined;
        secret = undefined;
      }
    }
    operator = Object.freeze({ getRunnerVariableDigests });
    RUNNER_VARIABLE_OPERATORS.set(operator, Object.freeze({
      state: 'UNUSED', version: 1, request: consumed,
    }));
    return pass(operator);
  } catch {
    terminalRunnerRequestBlock();
    return blocked('TEST_CLIENT_OPERATION_FORBIDDEN');
  }
}

export function isAuthenticTestCloudRunnerVariableReadbackResult(result, expected) {
  try {
    if (arguments.length !== 2 || readTestCloudRuntimeLifecycle() !== 'ACTIVE') return false;
    const resultFields = readDedicatedRunnerObject(result, ['status', 'value', 'diagnostics']);
    const fields = readDedicatedRunnerObject(
      expected, RUNNER_VARIABLE_RESULT_EXPECTED_KEYS,
    );
    if (resultFields === null || fields === null || resultFields.status !== 'PASS') return false;
    const record = AUTHENTIC_RUNNER_VARIABLE_RESULTS.get(result);
    return record !== undefined && record.result === result
      && record.requestRecord === runnerVariableRequestRecord
      && activeRunnerQualification(fields.runtimeQualification)
      && record.runtimeQualification === fields.runtimeQualification
      && record.context === fields.context
      && record.providerContractQualification === fields.providerContractQualification
      && record.identityBindingsQualification === fields.identityBindingsQualification
      && record.providerSetupReadbackQualification === fields.providerSetupReadbackQualification;
  } catch {
    return false;
  }
}

Object.defineProperty(
  qualifyTestCloudRunnerVariableReadbackRequest,
  RUNNER_VARIABLE_AUTHORITY_PROPERTY,
  {
    value: registerTestCloudRunnerVariableAuthority,
    enumerable: false,
    configurable: true,
    writable: false,
  },
);
