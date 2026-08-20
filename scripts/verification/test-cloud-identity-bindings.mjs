import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { isPromise, isProxy } from 'node:util/types';

import {
  isAuthenticTestEnvironmentContext,
  isTestEnvironmentContextBoundToCredentialHandles,
} from './test-cloud-environment.mjs';
import {
  authenticateTestCloudRuntimeActive,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from './test-cloud-provider-contract.mjs';

const ARRAY_IS_ARRAY = Array.isArray;
const JSON_PARSE = JSON.parse;
const JSON_STRINGIFY = JSON.stringify;
const OBJECT_CREATE = Object.create;
const OBJECT_DEFINE_PROPERTIES = Object.defineProperties;
const OBJECT_FREEZE = Object.freeze;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const OBJECT_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const OBJECT_HAS_OWN = Object.hasOwn;
const OBJECT_IS = Object.is;
const OBJECT_IS_FROZEN = Object.isFrozen;
const REFLECT_APPLY = Reflect.apply;
const REFLECT_CONSTRUCT = Reflect.construct;
const REFLECT_OWN_KEYS = Reflect.ownKeys;
const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const GLOBAL_THIS = globalThis;
const CAPTURED_PROMISE = Promise;
const CAPTURED_PROMISE_PROTOTYPE = Promise.prototype;
const CAPTURED_ARRAY_BUFFER = ArrayBuffer;
const CAPTURED_ARRAY_BUFFER_PROTOTYPE = ArrayBuffer.prototype;
const CAPTURED_UINT8_ARRAY = Uint8Array;
const CAPTURED_UINT8_ARRAY_PROTOTYPE = Uint8Array.prototype;
const CAPTURED_TYPED_ARRAY_PROTOTYPE = OBJECT_GET_PROTOTYPE_OF(Uint8Array.prototype);

function ownDataValue(owner, key) {
  if (owner === null || (typeof owner !== 'object' && typeof owner !== 'function')
    || isProxy(owner)) return undefined;
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(owner, key);
  return descriptor !== undefined && OBJECT_HAS_OWN(descriptor, 'value')
    ? descriptor.value : undefined;
}

function ownMethod(owner, key) {
  const value = ownDataValue(owner, key);
  return typeof value === 'function' && !isProxy(value) ? value : undefined;
}
const CAPTURED_TEXT_ENCODER_ENCODE = ownMethod(
  OBJECT_GET_PROTOTYPE_OF(TEXT_ENCODER), 'encode',
);
const CAPTURED_TEXT_DECODER_DECODE = ownMethod(
  OBJECT_GET_PROTOTYPE_OF(UTF8_DECODER), 'decode',
);

function ownGetter(owner, key) {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(owner, key);
  return descriptor !== undefined && typeof descriptor.get === 'function'
    && descriptor.set === undefined ? descriptor.get : undefined;
}
const CAPTURED_ARRAY_MAP = ownMethod(Array.prototype, 'map');
const CAPTURED_ARRAY_SOME = ownMethod(Array.prototype, 'some');
const CAPTURED_ARRAY_EVERY = ownMethod(Array.prototype, 'every');
const CAPTURED_ARRAY_INCLUDES = ownMethod(Array.prototype, 'includes');
const CAPTURED_ARRAY_SORT = ownMethod(Array.prototype, 'sort');
const CAPTURED_ARRAY_SLICE = ownMethod(Array.prototype, 'slice');
const CAPTURED_ARRAY_JOIN = ownMethod(Array.prototype, 'join');
const CAPTURED_SET = ownDataValue(GLOBAL_THIS, 'Set');
const CAPTURED_SET_PROTOTYPE = typeof CAPTURED_SET === 'function'
  ? ownDataValue(CAPTURED_SET, 'prototype') : undefined;
const CAPTURED_SET_HAS = ownMethod(CAPTURED_SET_PROTOTYPE, 'has');
const CAPTURED_SET_ADD = ownMethod(CAPTURED_SET_PROTOTYPE, 'add');
const CAPTURED_SET_DELETE = ownMethod(CAPTURED_SET_PROTOTYPE, 'delete');
const CAPTURED_STRING_ITERATOR = ownMethod(String.prototype, Symbol.iterator);
const CAPTURED_STRING_CODE_POINT_AT = ownMethod(String.prototype, 'codePointAt');
const CAPTURED_STRING_SLICE = ownMethod(String.prototype, 'slice');
const CAPTURED_STRING_ITERATOR_PROTOTYPE = typeof CAPTURED_STRING_ITERATOR === 'function'
  ? OBJECT_GET_PROTOTYPE_OF(REFLECT_APPLY(CAPTURED_STRING_ITERATOR, '', []))
  : undefined;
const CAPTURED_STRING_ITERATOR_NEXT = ownMethod(
  CAPTURED_STRING_ITERATOR_PROTOTYPE, 'next',
);
const CAPTURED_DATE = ownDataValue(GLOBAL_THIS, 'Date');
const CAPTURED_DATE_PROTOTYPE = typeof CAPTURED_DATE === 'function'
  ? ownDataValue(CAPTURED_DATE, 'prototype') : undefined;
const CAPTURED_DATE_PARSE = ownMethod(CAPTURED_DATE, 'parse');
const CAPTURED_DATE_TO_ISO_STRING = ownMethod(CAPTURED_DATE_PROTOTYPE, 'toISOString');

function arrayMap(value, callback) {
  return REFLECT_APPLY(CAPTURED_ARRAY_MAP, value, [callback]);
}

function arraySome(value, callback) {
  return REFLECT_APPLY(CAPTURED_ARRAY_SOME, value, [callback]);
}

function arrayEvery(value, callback) {
  return REFLECT_APPLY(CAPTURED_ARRAY_EVERY, value, [callback]);
}

function arrayIncludes(value, candidate) {
  return REFLECT_APPLY(CAPTURED_ARRAY_INCLUDES, value, [candidate]);
}

function arraySort(value) {
  return REFLECT_APPLY(CAPTURED_ARRAY_SORT, value, []);
}

function arraySlice(value, start) {
  return REFLECT_APPLY(CAPTURED_ARRAY_SLICE, value, [start]);
}

function arrayJoin(value, separator) {
  return REFLECT_APPLY(CAPTURED_ARRAY_JOIN, value, [separator]);
}

function capturedIdentityIntrinsicsAvailable() {
  return typeof REFLECT_CONSTRUCT === 'function'
    && typeof CAPTURED_SET === 'function' && !isProxy(CAPTURED_SET)
    && CAPTURED_SET_PROTOTYPE !== null && typeof CAPTURED_SET_PROTOTYPE === 'object'
    && !isProxy(CAPTURED_SET_PROTOTYPE)
    && typeof CAPTURED_SET_HAS === 'function'
    && typeof CAPTURED_SET_ADD === 'function'
    && typeof CAPTURED_SET_DELETE === 'function'
    && typeof CAPTURED_STRING_ITERATOR === 'function'
    && typeof CAPTURED_STRING_ITERATOR_NEXT === 'function'
    && typeof CAPTURED_STRING_CODE_POINT_AT === 'function'
    && typeof CAPTURED_STRING_SLICE === 'function'
    && typeof CAPTURED_DATE === 'function' && !isProxy(CAPTURED_DATE)
    && CAPTURED_DATE_PROTOTYPE !== null && typeof CAPTURED_DATE_PROTOTYPE === 'object'
    && !isProxy(CAPTURED_DATE_PROTOTYPE)
    && typeof CAPTURED_DATE_PARSE === 'function'
    && typeof CAPTURED_DATE_TO_ISO_STRING === 'function';
}

function createCapturedSet() {
  if (!capturedIdentityIntrinsicsAvailable()) forbidden();
  const value = REFLECT_CONSTRUCT(CAPTURED_SET, []);
  if (value === null || typeof value !== 'object' || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== CAPTURED_SET_PROTOTYPE) forbidden();
  return value;
}

function capturedSetHas(set, value) {
  const result = REFLECT_APPLY(CAPTURED_SET_HAS, set, [value]);
  if (typeof result !== 'boolean') forbidden();
  return result;
}

function capturedSetAdd(set, value) {
  if (!OBJECT_IS(REFLECT_APPLY(CAPTURED_SET_ADD, set, [value]), set)) forbidden();
}

function capturedSetDelete(set, value) {
  const result = REFLECT_APPLY(CAPTURED_SET_DELETE, set, [value]);
  if (typeof result !== 'boolean') forbidden();
  return result;
}

function valuesAreUnique(values) {
  const seen = createCapturedSet();
  for (let index = 0; index < values.length; index += 1) {
    if (capturedSetHas(seen, values[index])) return false;
    capturedSetAdd(seen, values[index]);
  }
  return true;
}

const CAPTURED_ARRAY_BUFFER_SLICE = ownMethod(CAPTURED_ARRAY_BUFFER_PROTOTYPE, 'slice');
const CAPTURED_ARRAY_BUFFER_BYTE_LENGTH =
  ownGetter(CAPTURED_ARRAY_BUFFER_PROTOTYPE, 'byteLength');
const CAPTURED_TYPED_ARRAY_BUFFER = ownGetter(CAPTURED_TYPED_ARRAY_PROTOTYPE, 'buffer');
const CAPTURED_TYPED_ARRAY_BYTE_OFFSET =
  ownGetter(CAPTURED_TYPED_ARRAY_PROTOTYPE, 'byteOffset');
const CAPTURED_TYPED_ARRAY_BYTE_LENGTH =
  ownGetter(CAPTURED_TYPED_ARRAY_PROTOTYPE, 'byteLength');
const CAPTURED_UINT8_ARRAY_SET = ownMethod(CAPTURED_TYPED_ARRAY_PROTOTYPE, 'set');
const CAPTURED_READABLE_STREAM = ownDataValue(GLOBAL_THIS, 'ReadableStream');
const CAPTURED_READER = ownDataValue(GLOBAL_THIS, 'ReadableStreamDefaultReader');
const CAPTURED_RESPONSE = ownDataValue(GLOBAL_THIS, 'Response');
const CAPTURED_HEADERS = ownDataValue(GLOBAL_THIS, 'Headers');
const CAPTURED_STREAM_GET_READER = CAPTURED_READABLE_STREAM === undefined
  ? undefined : ownMethod(CAPTURED_READABLE_STREAM.prototype, 'getReader');
const CAPTURED_READER_READ = CAPTURED_READER === undefined
  ? undefined : ownMethod(CAPTURED_READER.prototype, 'read');
const CAPTURED_READER_CANCEL = CAPTURED_READER === undefined
  ? undefined : ownMethod(CAPTURED_READER.prototype, 'cancel');
const CAPTURED_READER_RELEASE = CAPTURED_READER === undefined
  ? undefined : ownMethod(CAPTURED_READER.prototype, 'releaseLock');
const CAPTURED_HEADERS_GET = CAPTURED_HEADERS === undefined
  ? undefined : ownMethod(CAPTURED_HEADERS.prototype, 'get');
const CAPTURED_RESPONSE_GETTERS = CAPTURED_RESPONSE === undefined
  ? undefined
  : OBJECT_FREEZE({
      body: ownGetter(CAPTURED_RESPONSE.prototype, 'body'),
      headers: ownGetter(CAPTURED_RESPONSE.prototype, 'headers'),
      redirected: ownGetter(CAPTURED_RESPONSE.prototype, 'redirected'),
      status: ownGetter(CAPTURED_RESPONSE.prototype, 'status'),
      url: ownGetter(CAPTURED_RESPONSE.prototype, 'url'),
    });

const BOOTSTRAP_HUB = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const ENDPOINT = 'https://fra.cloud.appwrite.io/v1';
const CAPTURED_URL_SEARCH_PARAMS = ownDataValue(GLOBAL_THIS, 'URLSearchParams');
const CAPTURED_URL_SEARCH_PARAMS_APPEND = CAPTURED_URL_SEARCH_PARAMS === undefined
  ? undefined : ownMethod(CAPTURED_URL_SEARCH_PARAMS.prototype, 'append');
const CAPTURED_URL_SEARCH_PARAMS_TO_STRING = CAPTURED_URL_SEARCH_PARAMS === undefined
  ? undefined : ownMethod(CAPTURED_URL_SEARCH_PARAMS.prototype, 'toString');
const RESPONSE_FORMAT = '1.9.5';
const MAX_IDENTITY_BYTES = 16_384;
const MAX_RESPONSE_BYTES = 262_144;
const REQUEST_TIMEOUT_MILLISECONDS = 10_000;
const APPROVED_PROVIDER_CONTRACT_DIGEST =
  'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8';
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$/;
const PRINTABLE_ASCII_PATTERN = /^[\x20-\x7e]+$/;

const ROOT_KEYS = OBJECT_FREEZE([
  'schemaVersion', 'responseFormat', 'environmentDigest',
  'providerContractDigest', 'roles', 'identityBindingsDigest',
]);
const ROLE_KEYS = OBJECT_FREEZE([
  'role', 'userId', 'email', 'name', 'active', 'configuredEmailDigest',
  'fixturePreferencesDigest', 'identityCriticalProjectionDigest',
  'sessionSetDigest', 'identityDigest',
]);
const ROLE_ORDER = OBJECT_FREEZE(['editor', 'owner', 'viewer']);
const LOAD_KEYS = OBJECT_FREEZE([
  'runtimeQualification', 'context', 'credentialHandles', 'providerContractQualification',
  'configuredEmails',
]);
const VALIDATE_KEYS = OBJECT_FREEZE([
  'bytes', 'expectedEnvironmentDigest', 'expectedProviderContractDigest',
]);
const QUALIFIED_KEYS = OBJECT_FREEZE([
  'runtimeQualification', 'qualification', 'context', 'providerContractQualification',
  'expectedEnvironmentDigest', 'expectedProviderContractDigest',
  'expectedIdentityBindingsDigest',
]);
const DIGEST_KEYS = OBJECT_FREEZE([
  'runtimeQualification', 'shareBindingQualification', 'expectedProjectIdentityDigest',
  'ownerSlot', 'mutationOrdinal',
]);
const HANDOFF_KEYS = OBJECT_FREEZE([
  'runtimeQualification', 'context', 'identityBindingsQualification', 'ownerSlot',
]);
const BIND_KEYS = OBJECT_FREEZE(['runtimeQualification', 'handoff']);
const HANDLE_KEYS = OBJECT_FREEZE([
  'credentialClass', 'readSecret', 'scopes', 'variableName',
]);
const FIXTURE_SCOPES = OBJECT_FREEZE([
  'rows.read', 'rows.write', 'users.read', 'users.write',
]);
const USER_REQUIRED_KEYS = OBJECT_FREEZE([
  '$id', '$createdAt', '$updatedAt', 'name', 'registration', 'passwordUpdate',
  'email', 'phone', 'accessedAt', 'status', 'emailVerification',
  'phoneVerification', 'mfa', 'labels', 'targets', 'prefs',
]);
const USER_OPTIONAL_KEYS = OBJECT_FREEZE([
  'password', 'hash', 'hashOptions', 'emailCanonical', 'impersonator',
  'impersonatorUserId', 'emailIsFree', 'emailIsDisposable',
  'emailIsCorporate', 'emailIsCanonical',
]);
const TARGET_KEYS = OBJECT_FREEZE([
  '$id', '$createdAt', '$updatedAt', 'name', 'userId', 'providerId',
  'providerType', 'identifier', 'expired',
]);
const FIXTURE_PREFERENCES = OBJECT_FREEZE({
  onboardingCompletedAt: '2026-08-01T00:00:00.000Z',
  onboardingHintsEnabled: false,
});

const CAPTURED_FETCH = ownMethod(GLOBAL_THIS, 'fetch');
const CAPTURED_ABORT_SIGNAL = ownDataValue(GLOBAL_THIS, 'AbortSignal');
const CAPTURED_ABORT_TIMEOUT = CAPTURED_ABORT_SIGNAL === undefined
  ? undefined : ownMethod(CAPTURED_ABORT_SIGNAL, 'timeout');

const QUALIFIED_IDENTITIES = new WeakMap();
const FINAL_IDENTITY_BY_HANDOFF = new WeakMap();
const LOAD_RECORDS = new WeakMap();
const SHARE_BINDINGS = new WeakMap();
const HANDOFFS = new WeakMap();
const FINAL_IDENTITIES = new WeakMap();
const identityBridgeReceiver = OBJECT_FREEZE(OBJECT_CREATE(null));

let registrationState = 'EMPTY';
let registrationObject;
let providerAuthenticator;
let prepareShareValuesTransition;
let abortShareValuesTransition;
let commitShareValuesTransition;
let finalizeShareValuesTransition;

const SAFE_IDENTITY_VALIDATION_CODES = OBJECT_FREEZE([
  'TEST_IDENTITY_BINDINGS_INVALID',
  'TEST_IDENTITY_HTTP_RESPONSE_INVALID',
  'TEST_IDENTITY_LIST_CARDINALITY_INVALID',
  'TEST_IDENTITY_SESSION_SET_INVALID',
  'TEST_IDENTITY_USER_CORE_INVALID',
  'TEST_IDENTITY_USER_KEYS_INVALID',
  'TEST_IDENTITY_USER_LABELS_INVALID',
  'TEST_IDENTITY_USER_OPTIONALS_INVALID',
  'TEST_IDENTITY_USER_PASSWORD_INVALID',
  'TEST_IDENTITY_USER_PREFS_INVALID',
  'TEST_IDENTITY_USER_READBACK_MISMATCH',
  'TEST_IDENTITY_USER_TARGETS_INVALID',
  'TEST_IDENTITY_USER_TIMESTAMPS_INVALID',
  'TEST_IDENTITY_USER_UNIQUENESS_INVALID',
]);

class IdentityValidationError extends Error {
  constructor(code = 'TEST_IDENTITY_BINDINGS_INVALID') {
    super();
    this.code = arrayIncludes(SAFE_IDENTITY_VALIDATION_CODES, code)
      ? code : 'TEST_IDENTITY_BINDINGS_INVALID';
  }
}
class IdentityCredentialError extends Error {}
class IdentityOperationError extends Error {}

function invalidCredential() {
  throw new IdentityCredentialError();
}


function forbidden() {
  throw new IdentityOperationError();
}
function invalid(code) {
  throw new IdentityValidationError(code);
}

function deepFreeze(value, seen) {
  if (value === null || typeof value !== 'object') return value;
  if (seen === undefined) seen = createCapturedSet();
  if (isProxy(value) || capturedSetHas(seen, value)) invalid();
  capturedSetAdd(seen, value);
  for (const key of REFLECT_OWN_KEYS(value)) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')) invalid();
    deepFreeze(descriptor.value, seen);
  }
  return OBJECT_FREEZE(value);
}

function result(status, value, code, safeMessage) {
  const diagnostics = status === 'PASS'
    ? OBJECT_FREEZE([])
    : OBJECT_FREEZE([OBJECT_FREEZE({ code, retryable: false, safeMessage })]);
  return OBJECT_FREEZE({ status, value: value === null ? null : deepFreeze(value), diagnostics });
}

function pass(value) {
  return result('PASS', value);
}

function blockedBindings(code = 'TEST_IDENTITY_BINDINGS_INVALID') {
  const safeCode = arrayIncludes(SAFE_IDENTITY_VALIDATION_CODES, code)
    ? code : 'TEST_IDENTITY_BINDINGS_INVALID';
  return result('BLOCKED', null, safeCode,
    'Protected test-cloud identity bindings could not be qualified.');
}

function blockedCredential() {
  return result('BLOCKED', null, 'TEST_IDENTITY_CREDENTIAL_INVALID',
    'The test-cloud fixture credential is invalid for protected identity readback.');
}

function blockedOperation() {
  return result('BLOCKED', null, 'TEST_IDENTITY_OPERATION_FORBIDDEN',
    'The protected identity operation is not authorized.');
}

function exactObject(value, keys, prototype = Object.prototype) {
  if (value === null || typeof value !== 'object' || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== prototype) return null;
  const ownKeys = REFLECT_OWN_KEYS(value);
  if (ownKeys.length !== keys.length
    || arraySome(ownKeys,
      (key) => typeof key !== 'string' || !arrayIncludes(keys, key))) return null;
  const fields = OBJECT_CREATE(null);
  for (const key of keys) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')
      || descriptor.enumerable !== true) return null;
    if (descriptor.value !== null && typeof descriptor.value === 'object'
      && isProxy(descriptor.value)) return null;
    fields[key] = descriptor.value;
  }
  return fields;
}

function canonicalJson(value, ancestors) {
  if (ancestors === undefined) ancestors = createCapturedSet();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON_STRINGIFY(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) invalid();
    return String(value);
  }
  if (typeof value !== 'object' || isProxy(value) || capturedSetHas(ancestors, value)) invalid();
  capturedSetAdd(ancestors, value);
  let encoded;
  if (ARRAY_IS_ARRAY(value)) {
    const keys = REFLECT_OWN_KEYS(value);
    if (arraySome(keys,
      (key) => key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key))) invalid();
    for (let index = 0; index < value.length; index += 1) {
      if (!OBJECT_HAS_OWN(value, String(index))) invalid();
    }
    encoded = `[${arrayJoin(
      arrayMap(value, (entry) => canonicalJson(entry, ancestors)),
      ',',
    )}]`;
  } else {
    const prototype = OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== Object.prototype && prototype !== null) invalid();
    const keys = REFLECT_OWN_KEYS(value);
    if (arraySome(keys, (key) => typeof key !== 'string')) invalid();
    arraySort(keys);
    encoded = `{${arrayJoin(arrayMap(keys, (key) => {
      const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')
        || descriptor.enumerable !== true) invalid();
      return `${JSON_STRINGIFY(key)}:${canonicalJson(descriptor.value, ancestors)}`;
    }), ',')}}`;
  }
  capturedSetDelete(ancestors, value);
  return encoded;
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function isDigest(value) {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function isValidEmail(value) {
  return typeof value === 'string' && value.length >= 3 && value.length <= 320
    && PRINTABLE_ASCII_PATTERN.test(value) && !/\s/.test(value)
    && value.trim().toLowerCase() === value
    && value.indexOf('@') > 0 && value.indexOf('@') === value.lastIndexOf('@')
    && !value.endsWith('@');
}

function validateRole(value, expectedRole) {
  const fields = exactObject(value, ROLE_KEYS);
  if (fields === null || fields.role !== expectedRole || !ID_PATTERN.test(fields.userId)
    || !isValidEmail(fields.email) || typeof fields.name !== 'string'
    || !validScalarString(fields.name, 128, 512) || fields.active !== true
    || !isDigest(fields.configuredEmailDigest) || !isDigest(fields.fixturePreferencesDigest)
    || !isDigest(fields.identityCriticalProjectionDigest) || !isDigest(fields.sessionSetDigest)
    || !isDigest(fields.identityDigest) || fields.configuredEmailDigest !== sha256(fields.email)
    || fields.fixturePreferencesDigest !== sha256(canonicalJson(FIXTURE_PREFERENCES))) invalid();
  const criticalDigest = sha256(canonicalJson({
    schemaVersion: 'test-cloud.identity-critical-projection.v1', role: expectedRole,
    userId: fields.userId, email: fields.email, name: fields.name, active: true,
  }));
  const sessionSetDigest = sha256(canonicalJson({
    schemaVersion: 'test-cloud.identity-session-set.v1', role: expectedRole, total: 0,
  }));
  const identityDigest = sha256(canonicalJson({
    schemaVersion: 'test-cloud.identity-role-binding.v1', role: expectedRole,
    configuredEmailDigest: fields.configuredEmailDigest,
    fixturePreferencesDigest: fields.fixturePreferencesDigest,
    identityCriticalProjectionDigest: fields.identityCriticalProjectionDigest,
    sessionSetDigest: fields.sessionSetDigest,
  }));
  if (fields.identityCriticalProjectionDigest !== criticalDigest
    || fields.sessionSetDigest !== sessionSetDigest || fields.identityDigest !== identityDigest) invalid();
  return OBJECT_FREEZE({ ...fields });
}

function validateRecord(value, expectedEnvironmentDigest, expectedProviderContractDigest) {
  const fields = exactObject(value, ROOT_KEYS);
  if (fields === null || fields.schemaVersion !== 'test-cloud.identity-bindings.v1'
    || fields.responseFormat !== RESPONSE_FORMAT
    || fields.environmentDigest !== expectedEnvironmentDigest
    || fields.providerContractDigest !== expectedProviderContractDigest
    || !isDigest(fields.environmentDigest) || !isDigest(fields.providerContractDigest)
    || !isDigest(fields.identityBindingsDigest) || !ARRAY_IS_ARRAY(fields.roles)
    || fields.roles.length !== 3 || REFLECT_OWN_KEYS(fields.roles).length !== 4) invalid();
  const roles = arrayMap(fields.roles,
    (role, index) => validateRole(role, ROLE_ORDER[index]));
  if (!valuesAreUnique(arrayMap(roles, (role) => role.userId))
    || !valuesAreUnique(arrayMap(roles, (role) => role.email))) invalid();
  const withoutSelf = {
    schemaVersion: 'test-cloud.identity-bindings.v1', responseFormat: RESPONSE_FORMAT,
    environmentDigest: fields.environmentDigest,
    providerContractDigest: fields.providerContractDigest, roles,
  };
  if (fields.identityBindingsDigest !== sha256(canonicalJson(withoutSelf))) invalid();
  const record = { ...withoutSelf, identityBindingsDigest: fields.identityBindingsDigest };
  if (utf8Length(canonicalJson(record)) > MAX_IDENTITY_BYTES) invalid();
  return deepFreeze(record);
}

function typedArrayObservation(value) {
  if (value === null || typeof value !== 'object' || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== CAPTURED_UINT8_ARRAY_PROTOTYPE
    || typeof CAPTURED_TYPED_ARRAY_BUFFER !== 'function'
    || typeof CAPTURED_TYPED_ARRAY_BYTE_OFFSET !== 'function'
    || typeof CAPTURED_TYPED_ARRAY_BYTE_LENGTH !== 'function') invalid();
  const buffer = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BUFFER, value, []);
  const byteOffset = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BYTE_OFFSET, value, []);
  const byteLength = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BYTE_LENGTH, value, []);
  if (buffer === null || typeof buffer !== 'object' || isProxy(buffer)
    || OBJECT_GET_PROTOTYPE_OF(buffer) !== CAPTURED_ARRAY_BUFFER_PROTOTYPE
    || typeof CAPTURED_ARRAY_BUFFER_BYTE_LENGTH !== 'function'
    || REFLECT_APPLY(CAPTURED_ARRAY_BUFFER_BYTE_LENGTH, buffer, []) !== byteLength
    || byteOffset !== 0) invalid();
  return { buffer, byteOffset, byteLength };
}

function copyIdentityBytes(value) {
  const before = typedArrayObservation(value);
  if (before.byteLength < 1 || before.byteLength > MAX_IDENTITY_BYTES
    || arraySome(REFLECT_OWN_KEYS(value), (key) =>
      typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key))) invalid();
  if (typeof CAPTURED_ARRAY_BUFFER_SLICE !== 'function') invalid();
  const copiedBuffer = REFLECT_APPLY(
    CAPTURED_ARRAY_BUFFER_SLICE,
    before.buffer,
    [0, before.byteLength],
  );
  const after = typedArrayObservation(value);
  if (!OBJECT_IS(after.buffer, before.buffer)
    || after.byteOffset !== before.byteOffset
    || after.byteLength !== before.byteLength
    || OBJECT_GET_PROTOTYPE_OF(copiedBuffer) !== CAPTURED_ARRAY_BUFFER_PROTOTYPE
    || REFLECT_APPLY(CAPTURED_ARRAY_BUFFER_BYTE_LENGTH, copiedBuffer, []) !== before.byteLength) invalid();
  return new CAPTURED_UINT8_ARRAY(copiedBuffer);
}

function parseIdentityBytes(bytes, expectedEnvironmentDigest, expectedProviderContractDigest) {
  const copy = copyIdentityBytes(bytes);
  const text = REFLECT_APPLY(CAPTURED_TEXT_DECODER_DECODE, UTF8_DECODER, [copy]);
  const parsed = JSON_PARSE(text);
  if (canonicalJson(parsed) !== text) invalid();
  return validateRecord(parsed, expectedEnvironmentDigest, expectedProviderContractDigest);
}

export function validateTestCloudIdentityBindings(args) {
  try {
    const lifecycle = readTestCloudRuntimeLifecycle();
    if ((lifecycle !== 'EMPTY' && lifecycle !== 'ACTIVE') || arguments.length !== 1) return blockedBindings();
    const fields = exactObject(args, VALIDATE_KEYS);
    if (fields === null || !isDigest(fields.expectedEnvironmentDigest)
      || !isDigest(fields.expectedProviderContractDigest)) return blockedBindings();
    const record = parseIdentityBytes(fields.bytes, fields.expectedEnvironmentDigest,
      fields.expectedProviderContractDigest);
    return pass({ identityBindingsDigest: record.identityBindingsDigest });
  } catch (error) {
    return error instanceof IdentityValidationError || error instanceof SyntaxError
      || error instanceof TypeError ? blockedBindings() : blockedOperation();
  }
}
function assertActive(runtimeQualification) {
  if (readTestCloudRuntimeLifecycle() !== 'ACTIVE'
    || authenticateTestCloudRuntimeActive(OBJECT_FREEZE({ runtimeQualification })) !== true) forbidden();
}

function makeToken() {
  return OBJECT_FREEZE(OBJECT_CREATE(null));
}

function getLoadMap(context) {
  let map = LOAD_RECORDS.get(context);
  if (map === undefined) {
    map = new WeakMap();
    LOAD_RECORDS.set(context, map);
  }
  return map;
}

function reserveLoad(context, providerContractQualification, runtimeQualification, fixtureHandle) {
  const map = getLoadMap(context);
  const existing = map.get(providerContractQualification);
  if (existing !== undefined) {
    const blocked = OBJECT_FREEZE({
      state: 'BLOCKED',
      version: existing.version + 1,
      context,
      providerContractQualification,
    });
    map.set(providerContractQualification, blocked);
    if (existing.qualification !== undefined) QUALIFIED_IDENTITIES.delete(existing.qualification);
    forbidden();
  }
  const record = OBJECT_FREEZE({
    state: 'LOADING',
    version: 1,
    context,
    providerContractQualification,
    runtimeQualification,
    fixtureHandle,
  });
  map.set(providerContractQualification, record);
  if (!OBJECT_IS(map.get(providerContractQualification), record)) forbidden();
  return record;
}

function isCurrentLoad(record, expectedState = 'LOADING') {
  return record !== undefined
    && record.state === expectedState
    && OBJECT_IS(
      getLoadMap(record.context).get(record.providerContractQualification),
      record,
    );
}

function assertCurrentLoad(record, runtimeQualification) {
  assertActive(runtimeQualification);
  if (!isCurrentLoad(record) || !OBJECT_IS(record.runtimeQualification, runtimeQualification)) forbidden();
}

function blockLoad(record) {
  if (record === undefined || record.context === undefined
    || record.providerContractQualification === undefined) return;
  const map = getLoadMap(record.context);
  const current = map.get(record.providerContractQualification);
  if (current === undefined || current.state === 'BLOCKED') return;
  const blocked = OBJECT_FREEZE({
    state: 'BLOCKED',
    version: current.version + 1,
    context: record.context,
    providerContractQualification: record.providerContractQualification,
  });
  map.set(record.providerContractQualification, blocked);
  if (current.qualification !== undefined) QUALIFIED_IDENTITIES.delete(current.qualification);
}

function readFixtureHandle(credentialHandles) {
  try {
    if (credentialHandles === null || typeof credentialHandles !== 'object'
      || isProxy(credentialHandles) || !OBJECT_IS_FROZEN(credentialHandles)) invalidCredential();
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(credentialHandles, 'fixture');
    if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')) invalidCredential();
    const handle = descriptor.value;
    const fields = exactObject(handle, HANDLE_KEYS);
    if (fields === null || !OBJECT_IS_FROZEN(handle)
      || fields.credentialClass !== 'test-fixture'
      || fields.variableName !== 'APPWRITE_TEST_FIXTURE_API_KEY'
      || typeof fields.readSecret !== 'function' || isProxy(fields.readSecret)
      || fields.readSecret.length !== 0 || !ARRAY_IS_ARRAY(fields.scopes)
      || !OBJECT_IS_FROZEN(fields.scopes)
      || canonicalJson(fields.scopes) !== canonicalJson(FIXTURE_SCOPES)) invalidCredential();
    return OBJECT_FREEZE({ handle, readSecret: fields.readSecret });
  } catch (error) {
    if (error instanceof IdentityCredentialError) throw error;
    invalidCredential();
  }
}

function providerQualificationIsCurrent(runtimeQualification, context, providerContractQualification) {
  if (typeof providerAuthenticator !== 'function') return false;
  return REFLECT_APPLY(providerAuthenticator, identityBridgeReceiver, [{
    runtimeQualification,
    context,
    providerContractQualification,
    expectedEnvironmentDigest: context.environmentDigest,
    expectedProviderContractDigest: APPROVED_PROVIDER_CONTRACT_DIGEST,
  }]) === true;
}

function snapshotConfiguredEmails(value) {
  const fields = exactObject(value, ROLE_ORDER);
  if (fields === null
    || !arrayEvery(ROLE_ORDER, (role) => isValidEmail(fields[role]))
    || !valuesAreUnique(arrayMap(ROLE_ORDER, (role) => fields[role]))) return null;
  return deepFreeze({
    editor: fields.editor,
    owner: fields.owner,
    viewer: fields.viewer,
  });
}

function nonSecretHeaders(projectId) {
  if (typeof projectId !== 'string' || !ID_PATTERN.test(projectId)) invalid();
  return deepFreeze({
    Accept: 'application/json',
    'Accept-Encoding': 'identity',
    'X-Appwrite-Project': projectId,
    'X-Appwrite-Response-Format': RESPONSE_FORMAT,
  });
}

function listRecipe(role, email, ordinal, headers) {
  if (typeof CAPTURED_URL_SEARCH_PARAMS !== 'function'
    || typeof CAPTURED_URL_SEARCH_PARAMS_APPEND !== 'function'
    || typeof CAPTURED_URL_SEARCH_PARAMS_TO_STRING !== 'function') invalid();
  const equal = JSON_STRINGIFY({ method: 'equal', attribute: 'email', values: [email] });
  const query = new CAPTURED_URL_SEARCH_PARAMS();
  REFLECT_APPLY(CAPTURED_URL_SEARCH_PARAMS_APPEND, query, ['queries[0]', equal]);
  REFLECT_APPLY(CAPTURED_URL_SEARCH_PARAMS_APPEND, query,
    ['queries[1]', '{"method":"limit","values":[2]}']);
  REFLECT_APPLY(CAPTURED_URL_SEARCH_PARAMS_APPEND, query, ['total', 'true']);
  const relativePathAndQuery = '/users?'
    + REFLECT_APPLY(CAPTURED_URL_SEARCH_PARAMS_TO_STRING, query, []);
  return deepFreeze({
    schemaVersion: 'test-cloud.identity-http-request-recipe.v1',
    ordinal,
    role,
    operation: 'users.list',
    method: 'GET',
    endpoint: ENDPOINT,
    relativePathAndQuery,
    finalUrl: ENDPOINT + relativePathAndQuery,
    redirect: 'error',
    timeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
    responseByteLimit: MAX_RESPONSE_BYTES,
    responseFormat: RESPONSE_FORMAT,
    nonSecretHeaders: headers,
  });
}

function routeTemplate(role, ordinal, operation, headers) {
  const sessions = operation === 'users.sessions.list';
  return deepFreeze({
    schemaVersion: 'test-cloud.identity-http-route-template.v1',
    ordinal,
    role,
    operation,
    method: 'GET',
    endpoint: ENDPOINT,
    pathPrefix: '/users/',
    pathSuffix: sessions ? '/sessions' : '',
    query: sessions ? '?total=true' : '',
    redirect: 'error',
    timeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
    responseByteLimit: MAX_RESPONSE_BYTES,
    responseFormat: RESPONSE_FORMAT,
    nonSecretHeaders: headers,
  });
}

function buildRequestPlan(projectId, configuredEmails) {
  const listRecipes = [];
  const routeTemplates = [];
  for (let index = 0; index < ROLE_ORDER.length; index += 1) {
    const role = ROLE_ORDER[index];
    listRecipes.push(listRecipe(
      role, configuredEmails[role], index * 3, nonSecretHeaders(projectId),
    ));
    routeTemplates.push(OBJECT_FREEZE([
      routeTemplate(role, index * 3 + 1, 'users.get', nonSecretHeaders(projectId)),
      routeTemplate(
        role, index * 3 + 2, 'users.sessions.list', nonSecretHeaders(projectId),
      ),
    ]));
  }
  return deepFreeze({ listRecipes, routeTemplates });
}

function materializeRoleRecipe(template, userId) {
  if (!ID_PATTERN.test(userId)) invalid();
  const relativePathAndQuery =
    template.pathPrefix + userId + template.pathSuffix + template.query;
  return deepFreeze({
    schemaVersion: 'test-cloud.identity-http-request-recipe.v1',
    ordinal: template.ordinal,
    role: template.role,
    operation: template.operation,
    method: template.method,
    endpoint: template.endpoint,
    relativePathAndQuery,
    finalUrl: template.endpoint + relativePathAndQuery,
    redirect: template.redirect,
    timeoutMilliseconds: template.timeoutMilliseconds,
    responseByteLimit: template.responseByteLimit,
    responseFormat: template.responseFormat,
    nonSecretHeaders: template.nonSecretHeaders,
  });
}

function assertLocalPromise(value) {
  if (value === null || typeof value !== 'object' || isProxy(value)
    || !isPromise(value) || OBJECT_GET_PROTOTYPE_OF(value) !== CAPTURED_PROMISE_PROTOTYPE
    || REFLECT_OWN_KEYS(value).length !== 0) forbidden();
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    CAPTURED_PROMISE_PROTOTYPE,
    'constructor',
  );
  if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.value !== CAPTURED_PROMISE || descriptor.writable !== true
    || descriptor.enumerable !== false || descriptor.configurable !== true) forbidden();
}

function responseField(response, field) {
  const getter = CAPTURED_RESPONSE_GETTERS?.[field];
  if (typeof getter !== 'function') forbidden();
  return REFLECT_APPLY(getter, response, []);
}

function responseChunkObservation(value) {
  if (value === null || typeof value !== 'object' || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== CAPTURED_UINT8_ARRAY_PROTOTYPE) invalid();
  const buffer = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BUFFER, value, []);
  const byteOffset = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BYTE_OFFSET, value, []);
  const byteLength = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BYTE_LENGTH, value, []);
  if (buffer === null || typeof buffer !== 'object' || isProxy(buffer)
    || OBJECT_GET_PROTOTYPE_OF(buffer) !== CAPTURED_ARRAY_BUFFER_PROTOTYPE
    || byteLength < 1 || byteOffset < 0
    || byteOffset + byteLength > REFLECT_APPLY(CAPTURED_ARRAY_BUFFER_BYTE_LENGTH, buffer, [])) invalid();
  return { byteLength };
}

async function boundedResponseJson(response, recipe, runtimeQualification, loadRecord) {
  let reader;
  let primaryError;
  try {
    assertCurrentLoad(loadRecord, runtimeQualification);
    if (CAPTURED_RESPONSE === undefined || CAPTURED_READABLE_STREAM === undefined
      || CAPTURED_HEADERS === undefined || CAPTURED_READER === undefined) forbidden();
    if (response === null || typeof response !== 'object' || isProxy(response)
      || OBJECT_GET_PROTOTYPE_OF(response) !== CAPTURED_RESPONSE.prototype) invalid();
    const redirected = responseField(response, 'redirected');
    const status = responseField(response, 'status');
    const finalUrl = responseField(response, 'url');
    const body = responseField(response, 'body');
    const headers = responseField(response, 'headers');
    if (typeof CAPTURED_HEADERS_GET !== 'function') forbidden();
    if (redirected !== false || status !== 200 || finalUrl !== recipe.finalUrl || body === null
      || OBJECT_GET_PROTOTYPE_OF(body) !== CAPTURED_READABLE_STREAM.prototype
      || headers === null || typeof headers !== 'object' || isProxy(headers)
      || OBJECT_GET_PROTOTYPE_OF(headers) !== CAPTURED_HEADERS.prototype) {
      invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
    }
    const contentType = REFLECT_APPLY(CAPTURED_HEADERS_GET, headers, ['content-type']);
    if (typeof contentType !== 'string'
      || contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
    }
    const contentLength = REFLECT_APPLY(CAPTURED_HEADERS_GET, headers, ['content-length']);
    let expectedLength;
    if (contentLength !== null) {
      if (!/^[1-9][0-9]*$/.test(contentLength)) {
        invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
      }
      expectedLength = Number(contentLength);
      if (!Number.isSafeInteger(expectedLength)
        || expectedLength > recipe.responseByteLimit) {
        invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
      }
    }
    if (typeof CAPTURED_STREAM_GET_READER !== 'function'
      || typeof CAPTURED_READER_READ !== 'function'
      || typeof CAPTURED_READER_RELEASE !== 'function') forbidden();
    reader = REFLECT_APPLY(CAPTURED_STREAM_GET_READER, body, []);
    if (reader === null || typeof reader !== 'object' || isProxy(reader)
      || OBJECT_GET_PROTOTYPE_OF(reader) !== CAPTURED_READER.prototype) {
      invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
    }
    const bytes = new CAPTURED_UINT8_ARRAY(recipe.responseByteLimit);
    let offset = 0;
    while (true) {
      const readPromise = REFLECT_APPLY(CAPTURED_READER_READ, reader, []);
      assertLocalPromise(readPromise);
      const part = await readPromise;
      assertCurrentLoad(loadRecord, runtimeQualification);
      const fields = exactObject(part, ['done', 'value']);
      if (fields === null || typeof fields.done !== 'boolean') {
        invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
      }
      if (fields.done) {
        if (fields.value !== undefined) invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
        break;
      }
      const chunk = responseChunkObservation(fields.value);
      if (offset + chunk.byteLength > recipe.responseByteLimit) {
        invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
      }
      REFLECT_APPLY(CAPTURED_UINT8_ARRAY_SET, bytes, [fields.value, offset]);
      offset += chunk.byteLength;
    }
    if (offset < 1 || (expectedLength !== undefined && offset !== expectedLength)) {
      invalid('TEST_IDENTITY_HTTP_RESPONSE_INVALID');
    }
    const buffer = REFLECT_APPLY(CAPTURED_TYPED_ARRAY_BUFFER, bytes, []);
    const snapshotBuffer = REFLECT_APPLY(CAPTURED_ARRAY_BUFFER_SLICE, buffer, [0, offset]);
    const snapshot = new CAPTURED_UINT8_ARRAY(snapshotBuffer);
    const text = REFLECT_APPLY(CAPTURED_TEXT_DECODER_DECODE, UTF8_DECODER, [snapshot]);
    const value = JSON_PARSE(text);
    canonicalJson(value);
    return value;
  } catch (error) {
    primaryError = error;
    blockLoad(loadRecord);
    if (reader !== undefined && typeof CAPTURED_READER_CANCEL === 'function') {
      try {
        const cancelPromise = REFLECT_APPLY(CAPTURED_READER_CANCEL, reader, []);
        assertLocalPromise(cancelPromise);
        await cancelPromise;
      } catch { /* The original terminal failure remains authoritative. */ }
    }
    throw error;
  } finally {
    const ownedReader = reader;
    reader = undefined;
    if (ownedReader !== undefined) {
      try {
        if (typeof CAPTURED_READER_RELEASE !== 'function') forbidden();
        REFLECT_APPLY(CAPTURED_READER_RELEASE, ownedReader, []);
      } catch (releaseError) {
        blockLoad(loadRecord);
        if (primaryError === undefined) throw releaseError;
      }
    }
  }
}

async function fetchIdentity(recipe, secret, runtimeQualification, loadRecord) {
  if (typeof CAPTURED_FETCH !== 'function' || isProxy(CAPTURED_FETCH)
    || typeof CAPTURED_ABORT_TIMEOUT !== 'function') forbidden();
  assertCurrentLoad(loadRecord, runtimeQualification);
  const credentialHeaders = {
    ...recipe.nonSecretHeaders,
    'X-Appwrite-Key': secret,
  };
  const requestInit = {
    method: recipe.method,
    headers: credentialHeaders,
    redirect: recipe.redirect,
    signal: REFLECT_APPLY(
      CAPTURED_ABORT_TIMEOUT,
      CAPTURED_ABORT_SIGNAL,
      [recipe.timeoutMilliseconds],
    ),
  };
  const responsePromise = REFLECT_APPLY(
    CAPTURED_FETCH,
    GLOBAL_THIS,
    [recipe.finalUrl, requestInit],
  );
  assertLocalPromise(responsePromise);
  const response = await responsePromise;
  assertCurrentLoad(loadRecord, runtimeQualification);
  const bodyPromise = boundedResponseJson(response, recipe, runtimeQualification, loadRecord);
  assertLocalPromise(bodyPromise);
  const value = await bodyPromise;
  assertCurrentLoad(loadRecord, runtimeQualification);
  return value;
}

const RFC3339_MILLISECONDS =
  /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}(?:Z|\+00:00)$/;

function utf8Length(value) {
  return REFLECT_APPLY(CAPTURED_TEXT_ENCODER_ENCODE, TEXT_ENCODER, [value]).byteLength;
}

function validScalarString(value, maxScalars, maxBytes) {
  if (typeof value !== 'string' || utf8Length(value) > maxBytes) return false;
  if (!capturedIdentityIntrinsicsAvailable()) forbidden();
  const iterator = REFLECT_APPLY(CAPTURED_STRING_ITERATOR, value, []);
  if (iterator === null || typeof iterator !== 'object' || isProxy(iterator)
    || OBJECT_GET_PROTOTYPE_OF(iterator) !== CAPTURED_STRING_ITERATOR_PROTOTYPE) forbidden();
  let scalars = 0;
  while (true) {
    const step = REFLECT_APPLY(CAPTURED_STRING_ITERATOR_NEXT, iterator, []);
    const fields = exactObject(step, ['value', 'done']);
    if (fields === null || typeof fields.done !== 'boolean') forbidden();
    if (fields.done) {
      if (fields.value !== undefined) forbidden();
      break;
    }
    if (typeof fields.value !== 'string') forbidden();
    const codePoint = REFLECT_APPLY(CAPTURED_STRING_CODE_POINT_AT, fields.value, [0]);
    if (!Number.isSafeInteger(codePoint)) forbidden();
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) return false;
    scalars += 1;
    if (scalars > maxScalars) return false;
  }
  return true;
}

function isExactTimestamp(value) {
  if (typeof value !== 'string' || !RFC3339_MILLISECONDS.test(value)) return false;
  if (!capturedIdentityIntrinsicsAvailable()) forbidden();
  const time = REFLECT_APPLY(CAPTURED_DATE_PARSE, CAPTURED_DATE, [value]);
  if (!Number.isFinite(time)) return false;
  const date = REFLECT_CONSTRUCT(CAPTURED_DATE, [time]);
  if (date === null || typeof date !== 'object' || isProxy(date)
    || OBJECT_GET_PROTOTYPE_OF(date) !== CAPTURED_DATE_PROTOTYPE) forbidden();
  const normalizedValue = value[value.length - 1] === 'Z'
    ? value
    : `${REFLECT_APPLY(CAPTURED_STRING_SLICE, value, [0, -6])}Z`;
  return REFLECT_APPLY(CAPTURED_DATE_TO_ISO_STRING, date, []) === normalizedValue;
}

function isExactAccessedAtTimestamp(value) {
  return value === '' || isExactTimestamp(value);
}

function isDenseArray(value, maximum) {
  if (!ARRAY_IS_ARRAY(value)
    || (maximum !== undefined && value.length > maximum)
    || REFLECT_OWN_KEYS(value).length !== value.length + 1) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!OBJECT_HAS_OWN(value, String(index))) return false;
  }
  return true;
}

function validateTarget(value) {
  const fields = exactObject(value, TARGET_KEYS);
  if (fields === null || !ID_PATTERN.test(fields.$id) || !ID_PATTERN.test(fields.userId)
    || !isExactTimestamp(fields.$createdAt) || !isExactTimestamp(fields.$updatedAt)
    || !validScalarString(fields.name, 128, 512)
    || typeof fields.providerId !== 'string' || utf8Length(fields.providerId) > 512
    || typeof fields.providerType !== 'string' || utf8Length(fields.providerType) > 512
    || typeof fields.identifier !== 'string' || utf8Length(fields.identifier) > 1024
    || typeof fields.expired !== 'boolean') invalid('TEST_IDENTITY_USER_TARGETS_INVALID');
}

function validatePasswordArm(value) {
  const names = ['password', 'hash', 'hashOptions'];
  const presence = arrayMap(names, (key) => OBJECT_HAS_OWN(value, key));
  if (arraySome(presence, Boolean) && !arrayEvery(presence, Boolean)) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
  if (!arrayEvery(presence, Boolean)) return;
  if (typeof value.password !== 'string' || value.password.length < 1
    || utf8Length(value.password) > 8192 || /[\x00-\x1f\x7f]/.test(value.password)
    || !arrayIncludes(
      ['argon2', 'scrypt', 'scryptMod', 'bcrypt', 'md5'], value.hash)) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
  let keys;
  if (value.hash === 'argon2') keys = ['type', 'memoryCost', 'timeCost', 'threads'];
  else if (value.hash === 'scrypt') keys = ['type', 'costCpu', 'costMemory', 'costParallel', 'length'];
  else if (value.hash === 'scryptMod') keys = ['type', 'salt', 'saltSeparator', 'signerKey'];
  else keys = ['type'];
  const options = exactObject(value.hashOptions, keys);
  if (options === null || options.type !== value.hash) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
  if (value.hash === 'argon2' || value.hash === 'scrypt') {
    for (const key of arraySlice(keys, 1)) {
      if (!Number.isSafeInteger(options[key]) || options[key] < 1
        || options[key] > 2_147_483_647) invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
    }
  }
  if (value.hash === 'scryptMod') {
    for (const key of arraySlice(keys, 1)) {
      if (typeof options[key] !== 'string' || utf8Length(options[key]) > 8192
        || (options[key] !== '' && !PRINTABLE_ASCII_PATTERN.test(options[key]))) {
        invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
      }
    }
  }
  if (value.hash === 'argon2' && !/^\$argon2(i|id)\$/.test(value.password)) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
  if (value.hash === 'bcrypt' && !/^\$2[aby]\$/.test(value.password)) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
  if (value.hash === 'md5' && !/^[0-9A-Fa-f]{32}$/.test(value.password)) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
  if ((value.hash === 'scrypt' || value.hash === 'scryptMod')
    && !PRINTABLE_ASCII_PATTERN.test(value.password)) {
    invalid('TEST_IDENTITY_USER_PASSWORD_INVALID');
  }
}

function validateUser(value, role, expectedEmail) {
  if (value === null || typeof value !== 'object' || isProxy(value)
    || OBJECT_GET_PROTOTYPE_OF(value) !== Object.prototype) {
    invalid('TEST_IDENTITY_USER_KEYS_INVALID');
  }
  const keys = REFLECT_OWN_KEYS(value);
  if (arraySome(keys, (key) => typeof key !== 'string'
    || (!arrayIncludes(USER_REQUIRED_KEYS, key)
      && !arrayIncludes(USER_OPTIONAL_KEYS, key)))) {
    invalid('TEST_IDENTITY_USER_KEYS_INVALID');
  }
  if (arraySome(USER_REQUIRED_KEYS, (key) => !OBJECT_HAS_OWN(value, key))) {
    invalid('TEST_IDENTITY_USER_KEYS_INVALID');
  }
  for (const key of keys) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')
      || descriptor.enumerable !== true) invalid('TEST_IDENTITY_USER_KEYS_INVALID');
    if (descriptor.value !== null && typeof descriptor.value === 'object'
      && isProxy(descriptor.value)) invalid('TEST_IDENTITY_USER_KEYS_INVALID');
  }
  if (!isExactTimestamp(value.$createdAt) || !isExactTimestamp(value.$updatedAt)
    || !isExactTimestamp(value.registration) || !isExactTimestamp(value.passwordUpdate)
    || !isExactAccessedAtTimestamp(value.accessedAt)) {
    invalid('TEST_IDENTITY_USER_TIMESTAMPS_INVALID');
  }
  if (!ID_PATTERN.test(value.$id)
    || !validScalarString(value.name, 128, 512)
    || value.email !== expectedEmail || !isValidEmail(value.email)
    || typeof value.phone !== 'string' || utf8Length(value.phone) > 128
    || value.status !== true || typeof value.emailVerification !== 'boolean'
    || typeof value.phoneVerification !== 'boolean' || typeof value.mfa !== 'boolean') {
    invalid('TEST_IDENTITY_USER_CORE_INVALID');
  }
  if (!isDenseArray(value.labels, 32) || !valuesAreUnique(value.labels)
    || arraySome(value.labels, (label) => typeof label !== 'string')) {
    invalid('TEST_IDENTITY_USER_LABELS_INVALID');
  }
  if (!isDenseArray(value.targets)) invalid('TEST_IDENTITY_USER_TARGETS_INVALID');
  const targetIdentities = createCapturedSet();
  for (const target of value.targets) {
    if (capturedSetHas(targetIdentities, target)) {
      invalid('TEST_IDENTITY_USER_TARGETS_INVALID');
    }
    capturedSetAdd(targetIdentities, target);
    validateTarget(target);
  }
  const prefs = exactObject(value.prefs, ['onboardingCompletedAt', 'onboardingHintsEnabled']);
  if (prefs === null || prefs.onboardingCompletedAt !== FIXTURE_PREFERENCES.onboardingCompletedAt
    || prefs.onboardingHintsEnabled !== false
    || sha256(canonicalJson(value.prefs)) !== sha256(canonicalJson(FIXTURE_PREFERENCES))) {
    invalid('TEST_IDENTITY_USER_PREFS_INVALID');
  }
  validatePasswordArm(value);
  if (OBJECT_HAS_OWN(value, 'emailCanonical')
    && typeof value.emailCanonical !== 'string') invalid('TEST_IDENTITY_USER_OPTIONALS_INVALID');
  if (OBJECT_HAS_OWN(value, 'impersonatorUserId')
    && typeof value.impersonatorUserId !== 'string') {
    invalid('TEST_IDENTITY_USER_OPTIONALS_INVALID');
  }
  if (OBJECT_HAS_OWN(value, 'impersonator') && typeof value.impersonator !== 'boolean') {
    invalid('TEST_IDENTITY_USER_OPTIONALS_INVALID');
  }
  for (const key of ['emailIsFree', 'emailIsDisposable', 'emailIsCorporate', 'emailIsCanonical']) {
    if (OBJECT_HAS_OWN(value, key) && value[key] !== null && typeof value[key] !== 'boolean') {
      invalid('TEST_IDENTITY_USER_OPTIONALS_INVALID');
    }
  }
  return OBJECT_FREEZE({
    role,
    userId: value.$id,
    email: value.email,
    name: value.name,
    active: true,
    fixturePreferencesDigest: sha256(canonicalJson(FIXTURE_PREFERENCES)),
  });
}

function roleBinding(role, user) {
  const configuredEmailDigest = sha256(user.email);
  const identityCriticalProjectionDigest = sha256(canonicalJson({
    schemaVersion: 'test-cloud.identity-critical-projection.v1',
    role,
    userId: user.userId,
    email: user.email,
    name: user.name,
    active: true,
  }));
  const sessionSetDigest = sha256(canonicalJson({
    schemaVersion: 'test-cloud.identity-session-set.v1',
    role,
    total: 0,
  }));
  const identityDigest = sha256(canonicalJson({
    schemaVersion: 'test-cloud.identity-role-binding.v1',
    role,
    configuredEmailDigest,
    fixturePreferencesDigest: user.fixturePreferencesDigest,
    identityCriticalProjectionDigest,
    sessionSetDigest,
  }));
  return OBJECT_FREEZE({ ...user, configuredEmailDigest,
    identityCriticalProjectionDigest, sessionSetDigest, identityDigest });
}

function identityFor(qualification) {
  const record = QUALIFIED_IDENTITIES.get(qualification);
  if (record === undefined || record.state !== 'QUALIFIED') return undefined;
  const current = getLoadMap(record.context).get(record.providerContractQualification);
  return OBJECT_IS(current, record) && OBJECT_IS(record.qualification, qualification)
    ? record : undefined;
}

export async function loadQualifiedTestCloudIdentityBindings(args) {
  let loadRecord;
  let secret;
  let credentialHeaderValue;
  const credentialHeaderSlot = { value: undefined };
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) {
      return blockedOperation();
    }
    const fields = exactObject(args, LOAD_KEYS);
    if (fields === null) return blockedBindings();
    const configuredEmails = snapshotConfiguredEmails(fields.configuredEmails);
    assertActive(fields.runtimeQualification);
    if (!capturedIdentityIntrinsicsAvailable()) forbidden();
    if (!isAuthenticTestEnvironmentContext(fields.context)
      || !isTestEnvironmentContextBoundToCredentialHandles(fields.context, fields.credentialHandles)
      || fields.context.endpoint !== ENDPOINT || configuredEmails === null
      || !providerQualificationIsCurrent(fields.runtimeQualification, fields.context,
        fields.providerContractQualification)) return blockedBindings();
    const fixture = readFixtureHandle(fields.credentialHandles);
    loadRecord = reserveLoad(
      fields.context,
      fields.providerContractQualification,
      fields.runtimeQualification,
      fixture.handle,
    );
    const requestPlan = buildRequestPlan(fields.context.projectId, configuredEmails);
    if (sha256(canonicalJson(FIXTURE_PREFERENCES))
      !== sha256(canonicalJson({
        onboardingCompletedAt: '2026-08-01T00:00:00.000Z',
        onboardingHintsEnabled: false,
      }))) invalid();
    try {
      secret = REFLECT_APPLY(fixture.readSecret, fixture.handle, []);
    } catch {
      invalidCredential();
    }
    if (typeof secret !== 'string' || secret.length < 1
      || utf8Length(secret) > 8192 || !PRINTABLE_ASCII_PATTERN.test(secret)) invalidCredential();
    assertCurrentLoad(loadRecord, fields.runtimeQualification);
    if (!OBJECT_IS(loadRecord.fixtureHandle, fixture.handle)) forbidden();
    credentialHeaderValue = secret;
    credentialHeaderSlot.value = credentialHeaderValue;
    const roles = [];
    for (let index = 0; index < ROLE_ORDER.length; index += 1) {
      const role = ROLE_ORDER[index];
      const email = configuredEmails[role];
      const list = await fetchIdentity(
        requestPlan.listRecipes[index],
        credentialHeaderSlot.value,
        fields.runtimeQualification,
        loadRecord,
      );
      const listFields = exactObject(list, ['total', 'users']);
      if (listFields === null || listFields.total !== 1
        || !isDenseArray(listFields.users, 1) || listFields.users.length !== 1) {
        invalid('TEST_IDENTITY_LIST_CARDINALITY_INVALID');
      }
      const listUser = listFields.users[0];
      const qualified = validateUser(listUser, role, email);
      const getRecipe = materializeRoleRecipe(
        requestPlan.routeTemplates[index][0],
        qualified.userId,
      );
      const getUser = await fetchIdentity(
        getRecipe,
        credentialHeaderSlot.value,
        fields.runtimeQualification,
        loadRecord,
      );
      validateUser(getUser, role, email);
      if (canonicalJson(listUser) !== canonicalJson(getUser)) {
        invalid('TEST_IDENTITY_USER_READBACK_MISMATCH');
      }
      const sessionRecipe = materializeRoleRecipe(
        requestPlan.routeTemplates[index][1],
        qualified.userId,
      );
      const sessions = await fetchIdentity(
        sessionRecipe,
        credentialHeaderSlot.value,
        fields.runtimeQualification,
        loadRecord,
      );
      const sessionFields = exactObject(sessions, ['total', 'sessions']);
      if (sessionFields === null || sessionFields.total !== 0
        || !isDenseArray(sessionFields.sessions, 0)
        || sessionFields.sessions.length !== 0) {
        invalid('TEST_IDENTITY_SESSION_SET_INVALID');
      }
      roles.push(roleBinding(role, qualified));
    }
    if (!valuesAreUnique(arrayMap(roles, (role) => role.userId))
      || !valuesAreUnique(arrayMap(roles, (role) => role.email))) {
      invalid('TEST_IDENTITY_USER_UNIQUENESS_INVALID');
    }
    const withoutSelf = {
      schemaVersion: 'test-cloud.identity-bindings.v1',
      responseFormat: RESPONSE_FORMAT,
      environmentDigest: fields.context.environmentDigest,
      providerContractDigest: APPROVED_PROVIDER_CONTRACT_DIGEST,
      roles,
    };
    const protectedRecord = validateRecord({
      ...withoutSelf,
      identityBindingsDigest: sha256(canonicalJson(withoutSelf)),
    }, fields.context.environmentDigest, APPROVED_PROVIDER_CONTRACT_DIGEST);
    assertCurrentLoad(loadRecord, fields.runtimeQualification);
    const qualification = makeToken();
    const successor = OBJECT_FREEZE({
      state: 'QUALIFIED',
      version: loadRecord.version + 1,
      qualification,
      runtimeQualification: fields.runtimeQualification,
      context: fields.context,
      providerContractQualification: fields.providerContractQualification,
      record: protectedRecord,
    });
    const map = getLoadMap(fields.context);
    if (!OBJECT_IS(map.get(fields.providerContractQualification), loadRecord)) forbidden();
    map.set(fields.providerContractQualification, successor);
    if (!OBJECT_IS(map.get(fields.providerContractQualification), successor)) forbidden();
    QUALIFIED_IDENTITIES.set(qualification, successor);
    return pass({ qualification, identityBindingsDigest: protectedRecord.identityBindingsDigest });
  } catch (error) {
    blockLoad(loadRecord);
    if (error instanceof IdentityCredentialError) return blockedCredential();
    return error instanceof IdentityValidationError
      ? blockedBindings(error.code) : blockedOperation();
  } finally {
    credentialHeaderSlot.value = undefined;
    credentialHeaderValue = undefined;
    secret = undefined;
  }
}

export function isQualifiedTestCloudIdentityBindings(args) {
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return false;
    const fields = exactObject(args, QUALIFIED_KEYS);
    if (fields === null) return false;
    assertActive(fields.runtimeQualification);
    const current = identityFor(fields.qualification);
    return current !== undefined
      && OBJECT_IS(current.runtimeQualification, fields.runtimeQualification)
      && OBJECT_IS(current.context, fields.context)
      && OBJECT_IS(current.providerContractQualification, fields.providerContractQualification)
      && current.record.environmentDigest === fields.expectedEnvironmentDigest
      && current.record.providerContractDigest === fields.expectedProviderContractDigest
      && current.record.identityBindingsDigest === fields.expectedIdentityBindingsDigest;
  } catch {
    return false;
  }
}

function exactNominalToken(value) {
  return value !== null
    && typeof value === 'object'
    && !isProxy(value)
    && OBJECT_GET_PROTOTYPE_OF(value) === null
    && OBJECT_IS_FROZEN(value)
    && REFLECT_OWN_KEYS(value).length === 0;
}

function closedNullRecord(keys, values) {
  const record = OBJECT_CREATE(null);
  const descriptors = OBJECT_CREATE(null);
  for (const key of keys) {
    descriptors[key] = {
      value: values[key],
      enumerable: true,
      configurable: false,
      writable: false,
    };
  }
  OBJECT_DEFINE_PROPERTIES(record, descriptors);
  return deepFreeze(record);
}

function sharePair(ownerSlot) {
  if (ownerSlot === 'editorShare') {
    return OBJECT_FREEZE({ targetIndex: 0, targetRole: 'editor', ownerOrdinal: 0,
      issueOrdinal: 0, mutationOrdinal: 17, canRun: true });
  }
  if (ownerSlot === 'viewerShare') {
    return OBJECT_FREEZE({ targetIndex: 2, targetRole: 'viewer', ownerOrdinal: 1,
      issueOrdinal: 1, mutationOrdinal: 18, canRun: false });
  }
  invalid();
}

function sortedPermissions(ownerUserId, targetUserId) {
  return OBJECT_FREEZE(arraySort([
    `read("user:${ownerUserId}")`,
    `update("user:${ownerUserId}")`,
    `delete("user:${ownerUserId}")`,
    `read("user:${targetUserId}")`,
  ]));
}

function createShareBinding(identity, identityBindingsQualification, ownerSlot, pair) {
  const owner = identity.record.roles[1];
  const target = identity.record.roles[pair.targetIndex];
  if (owner.role !== 'owner' || target.role !== pair.targetRole) invalid();
  const permissions = sortedPermissions(owner.userId, target.userId);
  const sharePermissionsDigest = sha256(canonicalJson(permissions));
  const targetIdentityDigest = sha256(canonicalJson({
    schemaVersion: 'verification-share-target-identity.v1',
    identityRole: pair.targetRole,
    userIdDigest: sha256(target.userId),
    canonicalEmailDigest: sha256(target.email),
  }));
  return OBJECT_FREEZE({
    state: 'UNPREPARED',
    version: 1,
    runtimeQualification: identity.runtimeQualification,
    context: identity.context,
    identityBindingsQualification,
    identity,
    ownerSlot,
    pair,
    ownerUserId: owner.userId,
    targetUserId: target.userId,
    canonicalTargetEmail: target.email,
    sharePermissionsDigest,
    targetIdentityDigest,
  });
}

function casShareBinding(qualification, expected, nextState, additions = {}) {
  if (!exactNominalToken(qualification)
    || !OBJECT_IS(SHARE_BINDINGS.get(qualification), expected)) invalid();
  const successor = OBJECT_FREEZE({
    ...expected,
    ...additions,
    state: nextState,
    version: expected.version + 1,
  });
  SHARE_BINDINGS.set(qualification, successor);
  if (!OBJECT_IS(SHARE_BINDINGS.get(qualification), successor)) invalid();
  return successor;
}

function blockShareBinding(qualification) {
  if (!exactNominalToken(qualification)) return;
  const current = SHARE_BINDINGS.get(qualification);
  if (current === undefined || current.state === 'BLOCKED' || current.state === 'CONSUMED') return;
  const blocked = OBJECT_FREEZE({
    state: 'BLOCKED',
    version: current.version + 1,
  });
  SHARE_BINDINGS.set(qualification, blocked);
}

function casHandoff(handoff, expected, nextState, additions = {}) {
  if (!exactNominalToken(handoff) || !OBJECT_IS(HANDOFFS.get(handoff), expected)) invalid();
  const successor = OBJECT_FREEZE({
    ...expected,
    ...additions,
    state: nextState,
    version: expected.version + 1,
  });
  HANDOFFS.set(handoff, successor);
  if (!OBJECT_IS(HANDOFFS.get(handoff), successor)) invalid();
  return successor;
}

function blockHandoff(handoff) {
  if (!exactNominalToken(handoff)) return;
  const current = HANDOFFS.get(handoff);
  if (current === undefined || current.state === 'BLOCKED' || current.state === 'CONSUMED') return;
  HANDOFFS.set(handoff, OBJECT_FREEZE({ state: 'BLOCKED', version: current.version + 1 }));
  blockShareBinding(current.shareBindingQualification);
}

function safeProjection(record, projectIdentityDigest, tupleDigest, boundValuesDigest) {
  return closedNullRecord([
    'schemaVersion', 'identityBindingsDigest', 'ownerSlot', 'projectIdentityDigest',
    'targetIdentityDigest', 'tupleDigest', 'boundValuesDigest',
  ], {
    schemaVersion: 'verification-share-identity-handoff-projection.v1',
    identityBindingsDigest: record.identity.record.identityBindingsDigest,
    ownerSlot: record.ownerSlot,
    projectIdentityDigest,
    targetIdentityDigest: record.targetIdentityDigest,
    tupleDigest,
    boundValuesDigest,
  });
}

function identityForCurrentShare(share) {
  const current = identityFor(share.identityBindingsQualification);
  return current !== undefined && OBJECT_IS(current, share.identity) ? current : undefined;
}

function readShareBindingDigestsCore(args) {
  let shareBindingQualification;
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) invalid();
    const fields = exactObject(args, DIGEST_KEYS);
    if (fields === null) invalid();
    shareBindingQualification = fields.shareBindingQualification;
    assertActive(fields.runtimeQualification);
    if (!exactNominalToken(shareBindingQualification)
      || !isDigest(fields.expectedProjectIdentityDigest)) invalid();
    const current = SHARE_BINDINGS.get(shareBindingQualification);
    if (current === undefined || current.state !== 'UNPREPARED'
      || !OBJECT_IS(current.runtimeQualification, fields.runtimeQualification)
      || current.ownerSlot !== fields.ownerSlot
      || current.pair.mutationOrdinal !== fields.mutationOrdinal
      || identityForCurrentShare(current) === undefined) invalid();
    const tupleDigest = sha256(canonicalJson({
      schemaVersion: 'verification-share-runtime-tuple.v1',
      ownerSlot: current.ownerSlot,
      ownerOrdinal: current.pair.ownerOrdinal,
      issueOrdinal: current.pair.issueOrdinal,
      mutationOrdinal: current.pair.mutationOrdinal,
      projectIdentityDigest: fields.expectedProjectIdentityDigest,
      targetIdentityDigest: current.targetIdentityDigest,
      canonicalTargetEmailDigest: sha256(current.canonicalTargetEmail),
      role: current.pair.targetRole,
      canRun: current.pair.canRun,
      sharedByDigest: sha256(current.ownerUserId),
      sharePermissionsDigest: current.sharePermissionsDigest,
    }));
    const bindingNames = OBJECT_FREEZE([
      'canonicalTargetEmail', 'sharePermissionsDigest', 'sharedByUserId',
      'targetIdentityDigest', 'targetUserId', 'tupleDigest',
    ]);
    const boundValues = OBJECT_FREEZE([
      current.canonicalTargetEmail, current.sharePermissionsDigest, current.ownerUserId,
      current.targetIdentityDigest, current.targetUserId, tupleDigest,
    ]);
    const boundValuesDigest = sha256(canonicalJson(arrayMap(
      bindingNames,
      (name, index) => ({ name, valueDigest: sha256(boundValues[index]) }),
    )));
    const successor = casShareBinding(
      shareBindingQualification,
      current,
      'DIGESTS_READ',
      {
        projectIdentityDigest: fields.expectedProjectIdentityDigest,
        tupleDigest,
        boundValuesDigest,
        bindingNames,
        boundValues,
      },
    );
    return closedNullRecord(['targetIdentityDigest', 'tupleDigest'], {
      targetIdentityDigest: successor.targetIdentityDigest,
      tupleDigest: successor.tupleDigest,
    });
  } catch (error) {
    blockShareBinding(shareBindingQualification);
    throw error;
  }
}

export function readAuthenticatedShareBindingDigests(args) {
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return blockedOperation();
    return pass(readShareBindingDigestsCore(args));
  } catch {
    return blockedOperation();
  }
}

export async function createShareIdentityBindingHandoff(args) {
  let shareBindingQualification;
  let preparation;
  let runtimeQualification;
  let prepared = false;
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return blockedOperation();
    const fields = exactObject(args, HANDOFF_KEYS);
    if (fields === null || registrationState !== 'REGISTERED') return blockedOperation();
    runtimeQualification = fields.runtimeQualification;
    assertActive(runtimeQualification);
    if (!isAuthenticTestEnvironmentContext(fields.context)
      || !exactNominalToken(fields.identityBindingsQualification)) return blockedBindings();
    const identity = identityFor(fields.identityBindingsQualification);
    if (identity === undefined || !OBJECT_IS(identity.runtimeQualification, runtimeQualification)
      || !OBJECT_IS(identity.context, fields.context)) return blockedBindings();
    const pair = sharePair(fields.ownerSlot);
    shareBindingQualification = makeToken();
    const unprepared = createShareBinding(
      identity,
      fields.identityBindingsQualification,
      fields.ownerSlot,
      pair,
    );
    SHARE_BINDINGS.set(shareBindingQualification, unprepared);
    if (!OBJECT_IS(SHARE_BINDINGS.get(shareBindingQualification), unprepared)) forbidden();
    const preparePromise = REFLECT_APPLY(prepareShareValuesTransition,
      registrationObject.receiver, [{
        runtimeQualification,
        context: fields.context,
        identityBindingsQualification: fields.identityBindingsQualification,
        shareBindingQualification,
        ownerSlot: fields.ownerSlot,
        mutationOrdinal: pair.mutationOrdinal,
      }]);
    assertLocalPromise(preparePromise);
    const preparedValue = await preparePromise;
    preparation = ownDataValue(preparedValue, 'preparation');
    prepared = exactNominalToken(preparation);
    assertActive(runtimeQualification);
    if (identityFor(fields.identityBindingsQualification) !== identity) forbidden();
    const preparedFields = exactObject(preparedValue,
      ['preparation', 'projectIdentityDigest', 'targetIdentityDigest', 'tupleDigest'], null);
    if (preparedFields === null || !prepared
      || !OBJECT_IS(preparedFields.preparation, preparation)) invalid();
    const current = SHARE_BINDINGS.get(shareBindingQualification);
    if (current === undefined || current.state !== 'DIGESTS_READ') forbidden();
    if (preparedFields.projectIdentityDigest !== current.projectIdentityDigest
      || preparedFields.targetIdentityDigest !== current.targetIdentityDigest
      || preparedFields.tupleDigest !== current.tupleDigest) invalid();
    const projection = safeProjection(current, current.projectIdentityDigest,
      current.tupleDigest, current.boundValuesDigest);
    casShareBinding(shareBindingQualification, current, 'PREPARED');
    const handoff = makeToken();
    const handoffRecord = OBJECT_FREEZE({
      state: 'UNUSED',
      version: 1,
      runtimeQualification,
      identity,
      shareBindingQualification,
      preparation,
      ownerSlot: fields.ownerSlot,
      safeDigestProjection: projection,
    });
    HANDOFFS.set(handoff, handoffRecord);
    if (!OBJECT_IS(HANDOFFS.get(handoff), handoffRecord)) forbidden();
    return pass(closedNullRecord(['handoff', 'safeDigestProjection'], {
      handoff,
      safeDigestProjection: projection,
    }));
  } catch (error) {
    if (prepared) {
      try {
        if (REFLECT_APPLY(abortShareValuesTransition, registrationObject.receiver, [{
          runtimeQualification,
          preparation,
        }]) !== true) forbidden();
      } catch { /* The original terminal failure remains authoritative. */ }
    }
    blockShareBinding(shareBindingQualification);
    return error instanceof IdentityValidationError ? blockedBindings() : blockedOperation();
  }
}

export async function bindQualifiedShareIdentityValues(args) {
  let handoff;
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return blockedOperation();
    const fields = exactObject(args, BIND_KEYS);
    if (fields === null || registrationState !== 'REGISTERED') return blockedOperation();
    assertActive(fields.runtimeQualification);
    handoff = fields.handoff;
    if (!exactNominalToken(handoff)) invalid();
    const unusedHandoff = HANDOFFS.get(handoff);
    if (unusedHandoff === undefined || unusedHandoff.state !== 'UNUSED'
      || !OBJECT_IS(unusedHandoff.runtimeQualification, fields.runtimeQualification)) invalid();
    const preparedShare = SHARE_BINDINGS.get(unusedHandoff.shareBindingQualification);
    if (preparedShare === undefined || preparedShare.state !== 'PREPARED'
      || identityForCurrentShare(preparedShare) === undefined) invalid();
    const committingHandoff = casHandoff(handoff, unusedHandoff, 'COMMITTING');
    const committingShare = casShareBinding(
      unusedHandoff.shareBindingQualification,
      preparedShare,
      'COMMITTING',
    );
    const commitPromise = REFLECT_APPLY(commitShareValuesTransition,
      registrationObject.receiver, [{
        runtimeQualification: fields.runtimeQualification,
        preparation: committingHandoff.preparation,
        bindingNames: committingShare.bindingNames,
        boundValues: committingShare.boundValues,
      }]);
    assertLocalPromise(commitPromise);
    const committed = await commitPromise;
    assertActive(fields.runtimeQualification);
    if (!OBJECT_IS(HANDOFFS.get(handoff), committingHandoff)
      || !OBJECT_IS(SHARE_BINDINGS.get(committingHandoff.shareBindingQualification), committingShare)
      || identityForCurrentShare(committingShare) === undefined) invalid();
    const commitFields = exactObject(committed, ['commitReceipt'], null);
    if (commitFields === null || !exactNominalToken(commitFields.commitReceipt)) invalid();
    const finalizingHandoff = casHandoff(
      handoff,
      committingHandoff,
      'FINALIZING',
      { commitReceipt: commitFields.commitReceipt },
    );
    if (REFLECT_APPLY(finalizeShareValuesTransition, registrationObject.receiver, [{
      runtimeQualification: fields.runtimeQualification,
      preparation: finalizingHandoff.preparation,
      commitReceipt: commitFields.commitReceipt,
      handoff,
    }]) !== true) invalid();
    assertActive(fields.runtimeQualification);
    if (!OBJECT_IS(HANDOFFS.get(handoff), finalizingHandoff)
      || !OBJECT_IS(SHARE_BINDINGS.get(finalizingHandoff.shareBindingQualification), committingShare)
      || identityForCurrentShare(committingShare) === undefined) invalid();
    const finalToken = FINAL_IDENTITY_BY_HANDOFF.get(handoff);
    const finalRecord = exactNominalToken(finalToken) ? FINAL_IDENTITIES.get(finalToken) : undefined;
    if (finalRecord === undefined || finalRecord.state !== 'PENDING'
      || !OBJECT_IS(finalRecord.handoff, handoff)
      || !OBJECT_IS(finalRecord.commitReceipt, commitFields.commitReceipt)) invalid();
    const activeFinalRecord = OBJECT_FREEZE({
      ...finalRecord,
      state: 'ACTIVE',
      version: finalRecord.version + 1,
    });
    FINAL_IDENTITIES.set(finalToken, activeFinalRecord);
    if (!OBJECT_IS(FINAL_IDENTITIES.get(finalToken), activeFinalRecord)) invalid();
    const consumedHandoff = OBJECT_FREEZE({
      state: 'CONSUMED',
      version: finalizingHandoff.version + 1,
    });
    const consumedShare = OBJECT_FREEZE({
      state: 'CONSUMED',
      version: committingShare.version + 1,
    });
    HANDOFFS.set(handoff, consumedHandoff);
    SHARE_BINDINGS.set(finalizingHandoff.shareBindingQualification, consumedShare);
    if (!OBJECT_IS(HANDOFFS.get(handoff), consumedHandoff)
      || !OBJECT_IS(SHARE_BINDINGS.get(finalizingHandoff.shareBindingQualification), consumedShare)) {
      invalid();
    }
    return pass(closedNullRecord(['safeDigestProjection'], {
      safeDigestProjection: closedNullRecord(
        ['schemaVersion', 'identityBindingsDigest', 'ownerSlot', 'projectIdentityDigest',
          'targetIdentityDigest', 'tupleDigest', 'boundValuesDigest'],
        finalizingHandoff.safeDigestProjection,
      ),
    }));
  } catch {
    blockHandoff(handoff);
    return blockedOperation();
  }
}

function ownerAuthenticator(args) {
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return false;
    const fields = exactObject(args, [
      'runtimeQualification', 'identityBindingsQualification', 'observedOwnerProjection',
      'expectedEnvironmentDigest', 'expectedProviderContractDigest',
    ]);
    if (fields === null || !exactNominalToken(fields.identityBindingsQualification)) return false;
    assertActive(fields.runtimeQualification);
    const identity = identityFor(fields.identityBindingsQualification);
    const observed = exactObject(fields.observedOwnerProjection, ['$id', 'email', 'name', 'status']);
    if (identity === undefined || observed === null
      || !OBJECT_IS(identity.runtimeQualification, fields.runtimeQualification)
      || identity.record.environmentDigest !== fields.expectedEnvironmentDigest
      || identity.record.providerContractDigest !== fields.expectedProviderContractDigest) return false;
    const owner = identity.record.roles[1];
    return observed.$id === owner.userId && observed.email === owner.email
      && observed.name === owner.name && observed.status === true;
  } catch {
    return false;
  }
}

function readAuthenticatedBrowserIdentityEmail(args) {
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return false;
    const fields = exactObject(args, [
      'runtimeQualification', 'context', 'identityBindingsQualification', 'role',
    ]);
    if (fields === null || !exactNominalToken(fields.identityBindingsQualification)) return false;
    assertActive(fields.runtimeQualification);
    const identity = identityFor(fields.identityBindingsQualification);
    const index = ROLE_ORDER.indexOf(fields.role);
    if (identity === undefined || index < 0 || !OBJECT_IS(identity.context, fields.context)
      || !OBJECT_IS(identity.runtimeQualification, fields.runtimeQualification)) return false;
    return identity.record.roles[index].email;
  } catch {
    return false;
  }
}

function authenticateBrowserArtifactIdentityQualification(args) {
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return false;
    const fields = exactObject(args, [
      'runtimeQualification', 'context', 'identityBindingsQualification',
      'expectedIdentityBindingsDigest',
    ]);
    if (fields === null || !exactNominalToken(fields.identityBindingsQualification)) return false;
    assertActive(fields.runtimeQualification);
    const identity = identityFor(fields.identityBindingsQualification);
    return identity !== undefined
      && OBJECT_IS(identity.runtimeQualification, fields.runtimeQualification)
      && OBJECT_IS(identity.context, fields.context)
      && identity.record.identityBindingsDigest === fields.expectedIdentityBindingsDigest;
  } catch {
    return false;
  }
}

function authenticateShareIdentityFinalState(args) {
  let handoff;
  try {
    if (readTestCloudRuntimeLifecycle() !== 'ACTIVE' || arguments.length !== 1) return false;
    const fields = exactObject(args,
      ['runtimeQualification', 'handoff', 'commitReceipt', 'ownerSlot']);
    if (fields === null || !exactNominalToken(fields.handoff)
      || !exactNominalToken(fields.commitReceipt)) return false;
    handoff = fields.handoff;
    assertActive(fields.runtimeQualification);
    const current = HANDOFFS.get(handoff);
    if (current === undefined || current.state !== 'FINALIZING'
      || !OBJECT_IS(current.runtimeQualification, fields.runtimeQualification)
      || !OBJECT_IS(current.commitReceipt, fields.commitReceipt)
      || current.ownerSlot !== fields.ownerSlot
      || FINAL_IDENTITY_BY_HANDOFF.has(handoff)) return false;
    const finalIdentity = makeToken();
    const finalRecord = OBJECT_FREEZE({
      state: 'PENDING',
      version: 1,
      runtimeQualification: fields.runtimeQualification,
      handoff,
      commitReceipt: fields.commitReceipt,
      ownerSlot: fields.ownerSlot,
    });
    FINAL_IDENTITIES.set(finalIdentity, finalRecord);
    FINAL_IDENTITY_BY_HANDOFF.set(handoff, finalIdentity);
    if (!OBJECT_IS(FINAL_IDENTITIES.get(finalIdentity), finalRecord)
      || !OBJECT_IS(FINAL_IDENTITY_BY_HANDOFF.get(handoff), finalIdentity)) invalid();
    return finalIdentity;
  } catch {
    blockHandoff(handoff);
    return false;
  }
}

function createIdentityRegistration() {
  return closedNullRecord([
    'receiver', 'ownerAuthenticator', 'authenticateShareIdentityFinalState',
    'readAuthenticatedShareBindingDigests', 'readAuthenticatedBrowserIdentityEmail',
    'authenticateBrowserArtifactIdentityQualification',
  ], {
    receiver: identityBridgeReceiver,
    ownerAuthenticator,
    authenticateShareIdentityFinalState,
    readAuthenticatedShareBindingDigests: readShareBindingDigestsCore,
    readAuthenticatedBrowserIdentityEmail,
    authenticateBrowserArtifactIdentityQualification,
  });
}

registrationObject = createIdentityRegistration();

function blockIdentityBootstrap() {
  registrationState = 'BLOCKED';
  isAuthenticTestCloudBootstrapHub(undefined);
  return false;
}

export function registerTestCloudIdentityBootstrap() {
  if (arguments.length !== 0 || readTestCloudRuntimeLifecycle() !== 'BOOTSTRAPPING'
    || registrationState !== 'EMPTY') return blockIdentityBootstrap();
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(globalThis, BOOTSTRAP_HUB);
  if (descriptor === undefined || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.enumerable !== false || descriptor.configurable !== true
    || descriptor.writable !== false
    || !isAuthenticTestCloudBootstrapHub(descriptor.value)) return blockIdentityBootstrap();
  const hub = descriptor.value;
  if (typeof hub.registerIdentityAuthorityBridge !== 'function'
    || typeof hub.authenticateProviderQualification !== 'function'
    || typeof hub.prepareShareValuesTransition !== 'function'
    || typeof hub.abortShareValuesTransition !== 'function'
    || typeof hub.commitShareValuesTransition !== 'function'
    || typeof hub.finalizeShareValuesTransition !== 'function') return blockIdentityBootstrap();
  registrationState = 'REGISTERING';
  if (REFLECT_APPLY(hub.registerIdentityAuthorityBridge, hub.bridgeReceiver,
    [registrationObject]) !== true) return blockIdentityBootstrap();
  providerAuthenticator = hub.authenticateProviderQualification;
  prepareShareValuesTransition = hub.prepareShareValuesTransition;
  abortShareValuesTransition = hub.abortShareValuesTransition;
  commitShareValuesTransition = hub.commitShareValuesTransition;
  finalizeShareValuesTransition = hub.finalizeShareValuesTransition;
  registrationState = 'REGISTERED';
  return true;
}
