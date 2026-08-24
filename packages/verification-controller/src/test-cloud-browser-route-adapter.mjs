import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import {
  authenticateTestCloudRuntimeActive,
  consumeTestCloudBrowserFactoryAuthorization,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from '../../../scripts/verification/test-cloud-provider-contract.mjs';
import {
  readQualifiedTestCloudBrowserArtifactMember,
} from './test-cloud-browser-artifact-set.mjs';

const HUB_PROPERTY = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const BLOCKED = freezeClosed({
  status: 'BLOCKED',
  value: null,
  diagnostics: Object.freeze([]),
});
const adapterReceiver = Object.freeze(Object.create(null));
const artifactMemberReader = readQualifiedTestCloudBrowserArtifactMember;
const IS_PROXY = utilTypes.isProxy;
const REFLECT_APPLY = Reflect.apply;
const PROMISE = Promise;
const PROMISE_PROTOTYPE = Promise.prototype;
const PROMISE_THEN = Promise.prototype.then;
const REQUEST_TEMPLATE_KEYS = Object.freeze([
  'bindingNames', 'bodyKind', 'bodyTemplate', 'executionEnvelopeTemplate',
  'method', 'mutationOrdinal', 'pathBindings', 'pathTemplate', 'query',
  'routeId', 'schemaVersion',
]);
const SOURCE_OPERATION_BINDING_KEYS = Object.freeze([
  'ownerSlot', 'name', 'valueKind', 'value', 'valueDigest',
]);
const MEMBER_READBACK_CONTRACT_KEYS = Object.freeze([
  'applicationKeys', 'databaseBinding', 'logicalResource', 'ownerSlot',
  'projectionKeys', 'providerKind', 'tableBinding', 'transactionId',
  'transactionMode',
]);
const FIXED_SHARE_QUERY_CONTRACT_KEYS = Object.freeze([
  'bindingName', 'databaseBinding', 'databaseId', 'filterField', 'limit',
  'projectionKeys', 'tableId', 'tableIdSource', 'total', 'transactionId',
  'transactionMode',
]);
const TABLESDB_SYSTEM_KEYS = Object.freeze([
  '$id', '$sequence', '$tableId', '$databaseId', '$createdAt', '$updatedAt', '$permissions',
]);
const INITIAL_SOURCE_OPERATION_ROWS = Object.freeze([
  Object.freeze(['rootManifestInitial', 'sourceBytesDigest', 'source-bytes-digest']),
  Object.freeze(['rootArtifact', 'rootArtifactId', 'artifact-id']),
  Object.freeze(['rootVersionInitial', 'rootContentHash', 'content-hash']),
  Object.freeze(['projectFacade', 'projectId', 'project-id']),
  Object.freeze(['entrypointArtifact', 'entrypointArtifactId', 'artifact-id']),
  Object.freeze(['entrypointVersionInitial', 'initialEntrypointVersionId', 'artifact-version-id']),
  Object.freeze(['entrypointVersionInitial', 'workflowContentHash', 'content-hash']),
]);
const CLOCK_OPERATION_KEYS = Object.freeze([
  'receiver', 'installTestCloudFixtureClock', 'authenticateTestCloudFixtureClock',
  'advanceTestCloudFixtureClock', 'sealTestCloudFixtureClock',
]);

let factoryState = 'EMPTY';
let registrationState = 'EMPTY';
let finalizerState = 'UNUSED';
let scenarioState = 'UNBOUND';
let registration;
let page;
let browserFacade;
let browserScenarioQualification;
let httpHandler;
let webSocketHandler;
let teardownPromise;
let initScriptInstalled = false;
let ownerAccount;
let pendingRouteRecord;
let browserCapture;
let browserContextCapture;
let apiRequestCapture;
let pageCapture;
let retainedClock;
let cancellationGeneration = 0;
const observedRouteRecords = new Map();
const providerMemberReadbacks = new Map();
const shareBaselineReadbacks = new Map();
let primaryDatabaseId;
let primaryProjectId;

function freezeClosed(properties) {
  return Object.freeze(Object.assign(Object.create(null), properties));
}

function pass(properties) {
  return freezeClosed({
    status: 'PASS',
    value: freezeClosed(properties),
    diagnostics: Object.freeze([]),
  });
}

function digestParts(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return 'sha256:' + hash.digest('hex');
}

function isClosedRoot(value, keys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || IS_PROXY(value)
      || Object.getPrototypeOf(value) !== null
      || !Object.isFrozen(value)
    ) return false;
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length
      || ownKeys.some((key) => typeof key !== 'string')
      || keys.some((key) => !ownKeys.includes(key))
    ) return false;
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined
        && Object.hasOwn(descriptor, 'value')
        && descriptor.enumerable === true
        && descriptor.configurable === false
        && descriptor.writable === false;
    });
  } catch {
    return false;
  }
}

function isNominal(value) {
  return isClosedRoot(value, []);
}

function exactLocalPromise(value) {
  try {
    return value !== null
      && typeof value === 'object'
      && !IS_PROXY(value)
      && Object.getPrototypeOf(value) === PROMISE_PROTOTYPE
      && value.constructor === PROMISE;
  } catch {
    return false;
  }
}

function awaitLocalPromise(value) {
  if (!exactLocalPromise(value)) throw new TypeError('foreign Promise');
  return new PROMISE((resolve, reject) => {
    REFLECT_APPLY(PROMISE_THEN, value, [resolve, reject]);
  });
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new PROMISE((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function descriptorSnapshot(owner, descriptor) {
  return Object.freeze({
    owner,
    value: descriptor.value,
    enumerable: descriptor.enumerable,
    configurable: descriptor.configurable,
    writable: descriptor.writable,
  });
}

function firstDataMethod(chain, name) {
  for (const owner of chain) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (
        !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'function'
        || IS_PROXY(descriptor.value)
      ) throw new TypeError('method descriptor');
      return descriptorSnapshot(owner, descriptor);
    }
  }
  throw new TypeError('missing method');
}

function captureOwnedObjectProperty(capture, name) {
  for (const owner of capture.chain) {
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor === undefined) continue;
    if (Object.hasOwn(descriptor, 'value')) {
      if (descriptor.value === null || typeof descriptor.value !== 'object'
        || IS_PROXY(descriptor.value)) throw new TypeError('property descriptor');
      return Object.freeze({
        kind: 'data', owner, value: descriptor.value,
        enumerable: descriptor.enumerable, configurable: descriptor.configurable,
        writable: descriptor.writable,
      });
    }
    if (typeof descriptor.get !== 'function' || IS_PROXY(descriptor.get)
      || descriptor.set !== undefined) throw new TypeError('property accessor');
    return Object.freeze({
      kind: 'accessor', owner, get: descriptor.get,
      enumerable: descriptor.enumerable, configurable: descriptor.configurable,
    });
  }
  throw new TypeError('missing property');
}

function readCapturedObjectProperty(capture, property) {
  if (!capture.chain.every((entry, index) => {
    let cursor = capture.receiver;
    for (let step = 0; step < index; step += 1) cursor = Object.getPrototypeOf(cursor);
    return Object.is(cursor, entry);
  })) throw new TypeError('property receiver changed');
  const descriptor = Object.getOwnPropertyDescriptor(property.owner, 'request');
  const matches = descriptor !== undefined
    && descriptor.enumerable === property.enumerable
    && descriptor.configurable === property.configurable
    && (property.kind === 'data'
      ? Object.hasOwn(descriptor, 'value')
        && Object.is(descriptor.value, property.value)
        && descriptor.writable === property.writable
      : !Object.hasOwn(descriptor, 'value')
        && Object.is(descriptor.get, property.get)
        && descriptor.set === undefined);
  if (!matches) throw new TypeError('property changed');
  const value = property.kind === 'data'
    ? property.value : REFLECT_APPLY(property.get, capture.receiver, []);
  if (value === null || typeof value !== 'object' || IS_PROXY(value)) {
    throw new TypeError('property value');
  }
  return value;
}

function captureOwnedInstance(receiver, methodNames) {
  if (
    receiver === null
    || (typeof receiver !== 'object' && typeof receiver !== 'function')
    || IS_PROXY(receiver)
  ) throw new TypeError('receiver');
  const chain = [];
  const seen = new Set();
  let cursor = receiver;
  while (cursor !== null) {
    if (IS_PROXY(cursor) || seen.has(cursor)) throw new TypeError('prototype closure');
    seen.add(cursor);
    chain.push(cursor);
    cursor = Object.getPrototypeOf(cursor);
  }
  const methods = Object.create(null);
  for (const name of methodNames) methods[name] = firstDataMethod(chain, name);
  return Object.freeze({
    receiver,
    chain: Object.freeze(chain),
    methods: Object.freeze(methods),
    constructor: firstDataMethod(chain, 'constructor'),
  });
}

function sameDescriptor(expected, actual) {
  return actual !== undefined
    && Object.hasOwn(actual, 'value')
    && Object.is(actual.value, expected.value)
    && actual.enumerable === expected.enumerable
    && actual.configurable === expected.configurable
    && actual.writable === expected.writable;
}

function isGenuinePlaywrightTimeoutError(error) {
  void error;
  return false;
}

function reauthenticateOwnedInstance(capture, methodName) {
  try {
    if (IS_PROXY(capture.receiver)) return false;
    const actualChain = [];
    const seen = new Set();
    let cursor = capture.receiver;
    while (cursor !== null) {
      if (IS_PROXY(cursor) || seen.has(cursor)) return false;
      seen.add(cursor);
      actualChain.push(cursor);
      cursor = Object.getPrototypeOf(cursor);
    }
    if (
      actualChain.length !== capture.chain.length
      || actualChain.some((entry, index) => !Object.is(entry, capture.chain[index]))
    ) return false;
    const method = capture.methods[methodName];
    return method !== undefined
      && sameDescriptor(method, Object.getOwnPropertyDescriptor(method.owner, methodName))
      && sameDescriptor(
        capture.constructor,
        Object.getOwnPropertyDescriptor(capture.constructor.owner, 'constructor'),
      );
  } catch {
    return false;
  }
}

function invokeCaptured(capture, methodName, args = []) {
  if (!reauthenticateOwnedInstance(capture, methodName)) {
    throw new TypeError('captured method changed');
  }
  return REFLECT_APPLY(capture.methods[methodName].value, capture.receiver, args);
}

async function invokeCapturedAsync(capture, methodName, args = []) {
  return await awaitLocalPromise(invokeCaptured(capture, methodName, args));
}

function authenticateRuntime(runtimeQualification) {
  return authenticateTestCloudRuntimeActive(Object.freeze({
    runtimeQualification,
  })) === true;
}

function hubValue(hub, name, expectedType) {
  const descriptor = Object.getOwnPropertyDescriptor(hub, name);
  if (
    descriptor === undefined
    || !Object.hasOwn(descriptor, 'value')
    || descriptor.enumerable !== true
    || descriptor.configurable !== false
    || descriptor.writable !== false
    || (expectedType !== undefined && typeof descriptor.value !== expectedType)
  ) return undefined;
  return descriptor.value;
}

function currentHub() {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, HUB_PROPERTY);
  if (
    descriptor === undefined
    || !Object.hasOwn(descriptor, 'value')
    || descriptor.enumerable !== false
    || descriptor.configurable !== true
    || descriptor.writable !== false
  ) return undefined;
  return descriptor.value;
}

function blockFactory() {
  if (factoryState !== 'CLOSING' && factoryState !== 'CLOSED') factoryState = 'BLOCKED';
  scenarioState = 'BLOCKED';
  cancellationGeneration += 1;
  return BLOCKED;
}

async function closeCaptured(capture, methodName, args) {
  if (capture === undefined) return false;
  try {
    await invokeCapturedAsync(capture, methodName, args);
    return true;
  } catch {
    return false;
  }
}

async function closeOwnedGraph() {
  if (teardownPromise !== undefined) return teardownPromise;
  factoryState = 'CLOSING';
  scenarioState = 'CLOSING';
  cancellationGeneration += 1;
  const ownedPage = pageCapture;
  const ownedContext = browserContextCapture;
  const ownedBrowser = browserCapture;
  const ownedRoute = pendingRouteRecord;
  pendingRouteRecord = undefined;
  teardownPromise = (async () => {
    if (ownedRoute !== undefined && ownedRoute.terminal !== true) {
      await closeCaptured(ownedRoute.routeCapture, 'abort', ['blockedbyclient']);
    }
    await closeCaptured(ownedPage, 'close', [{
      runBeforeUnload: false,
      reason: 'verification-teardown',
    }]);
    await closeCaptured(ownedContext, 'unrouteAll', [{ behavior: 'ignoreErrors' }]);
    await closeCaptured(ownedContext, 'close', [{ reason: 'verification-teardown' }]);
    await closeCaptured(ownedBrowser, 'close', [{ reason: 'verification-teardown' }]);
    page = undefined;
    pageCapture = undefined;
    browserContextCapture = undefined;
    apiRequestCapture = undefined;
    browserCapture = undefined;
    retainedClock = undefined;
    ownerAccount = undefined;
    httpHandler = undefined;
    webSocketHandler = undefined;
    factoryState = 'CLOSED';
    scenarioState = 'CLOSED';
    return true;
  })();
  return teardownPromise;
}

function validFacadeCall(receiver, args, keys) {
  return Object.is(receiver, browserFacade)
    && factoryState === 'ACTIVE_BOUND'
    && isClosedRoot(args, keys);
}

async function installPausedBeforeNavigation(args) {
  if (
    arguments.length !== 1
    || !validFacadeCall(this, args, ['baseUtc'])
    || typeof args.baseUtc !== 'string'
    || initScriptInstalled
    || page === undefined
    || invokeCaptured(pageCapture, 'url') !== 'about:blank'
  ) return false;
  try {
    await invokeCapturedAsync(pageCapture, 'addInitScript', [{ baseUtc: args.baseUtc }]);
    initScriptInstalled = true;
    return true;
  } catch {
    scenarioState = 'BLOCKED';
    return false;
  }
}

async function proveOwnerUiReady(args) {
  if (
    arguments.length !== 1
    || !validFacadeCall(this, args, [])
    || ownerAccount === undefined
    || page === undefined
  ) return false;
  try {
    const marker = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', {
      name: 'Open user menu',
      exact: true,
    }]));
    return await exactLocator(marker, []);
  } catch {
    scenarioState = 'BLOCKED';
    return false;
  }
}

async function readOwnerAccount(args) {
  if (
    arguments.length !== 1
    || !validFacadeCall(this, args, [])
    || ownerAccount === undefined
  ) return BLOCKED;
  return freezeClosed({
    $id: ownerAccount.$id,
    email: ownerAccount.email,
    name: ownerAccount.name,
    status: ownerAccount.status,
  });
}

async function runForExactly800Milliseconds(args) {
  if (
    arguments.length !== 1
    || !validFacadeCall(this, args, [])
    || scenarioState === 'BLOCKED'
    || scenarioState === 'CLOSING'
    || scenarioState === 'CLOSED'
  ) return BLOCKED;
  try {
    await invokeCapturedAsync(pageCapture, 'waitForTimeout', [800]);
  } catch {
    scenarioState = 'BLOCKED';
    return BLOCKED;
  }
  return Object.freeze({
    advancedMilliseconds: 800,
    autosaveCount: 1,
  });
}

async function sealClock(args) {
  if (
    arguments.length !== 1
    || !validFacadeCall(this, args, [])
    || scenarioState !== 'VIEWER_SHARE_COMPLETE'
  ) return false;
  scenarioState = 'SEALING';
  return closeOwnedGraph();
}

function canonicalJson(value, stack = new Set()) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('number');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || IS_PROXY(value) || stack.has(value)) {
    throw new TypeError('canonical value');
  }
  stack.add(value);
  let result;
  if (Array.isArray(value)) {
    if (Reflect.ownKeys(value).length !== value.length + 1) throw new TypeError('array');
    result = '[' + value.map((item) => canonicalJson(item, stack)).join(',') + ']';
  } else {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) throw new TypeError('symbol');
    keys.sort();
    result = '{' + keys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('accessor');
      }
      return JSON.stringify(key) + ':' + canonicalJson(descriptor.value, stack);
    }).join(',') + '}';
  }
  stack.delete(value);
  return result;
}

function parseJsonNoDuplicateKeys(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 262144) {
    throw new TypeError('json bound');
  }
  let offset = 0;
  const whitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  };
  const string = () => {
    if (text[offset] !== '"') throw new TypeError('json string');
    const start = offset++;
    while (offset < text.length) {
      const char = text[offset++];
      if (char === '"') return JSON.parse(text.slice(start, offset));
      if (char === '\\') {
        if (offset >= text.length) throw new TypeError('json escape');
        const escaped = text[offset++];
        if (escaped === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(offset, offset + 4))) {
            throw new TypeError('json unicode');
          }
          offset += 4;
        } else if (!'"\\/bfnrt'.includes(escaped)) throw new TypeError('json escape');
      } else if (char.charCodeAt(0) < 0x20) throw new TypeError('json control');
    }
    throw new TypeError('json string');
  };
  const value = () => {
    whitespace();
    if (text[offset] === '{') {
      offset += 1;
      whitespace();
      const keys = new Set();
      if (text[offset] === '}') { offset += 1; return; }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new TypeError('duplicate json key');
        keys.add(key);
        whitespace();
        if (text[offset++] !== ':') throw new TypeError('json colon');
        value();
        whitespace();
        if (text[offset] === '}') { offset += 1; return; }
        if (text[offset++] !== ',') throw new TypeError('json comma');
      }
    }
    if (text[offset] === '[') {
      offset += 1;
      whitespace();
      if (text[offset] === ']') { offset += 1; return; }
      while (true) {
        value();
        whitespace();
        if (text[offset] === ']') { offset += 1; return; }
        if (text[offset++] !== ',') throw new TypeError('json comma');
      }
    }
    if (text[offset] === '"') { string(); return; }
    const match = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/u
      .exec(text.slice(offset));
    if (match === null) throw new TypeError('json value');
    offset += match[0].length;
  };
  value();
  whitespace();
  if (offset !== text.length) throw new TypeError('json tail');
  return JSON.parse(text);
}

function exactHeaderRow(row) {
  try {
    if (row === null || typeof row !== 'object' || Array.isArray(row) || IS_PROXY(row)) return false;
    const keys = Reflect.ownKeys(row);
    if (keys.length !== 2 || !keys.includes('name') || !keys.includes('value')) return false;
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(row, key);
      return descriptor !== undefined && Object.hasOwn(descriptor, 'value') && descriptor.enumerable;
    });
  } catch {
    return false;
  }
}

const FORBIDDEN_HEADERS = new Set([
  'authorization', 'x-appwrite-dev-key', 'x-appwrite-jwt', 'x-appwrite-key',
  'x-appwrite-session', 'x-fallback-cookies',
]);

function classifiedHeaders(rows, safeRows, opaqueRules, allowCookie, responseMimeEssence = null) {
  if (!Array.isArray(rows) || rows.length > 256 || Reflect.ownKeys(rows).length !== rows.length + 1) {
    throw new TypeError('headers');
  }
  const safe = new Map((safeRows ?? []).map((row) => [row.name, row.valueDigest]));
  const opaque = new Map((opaqueRules ?? []).map((row) => [row.name, row]));
  const observed = new Map();
  for (const row of rows) {
    if (!exactHeaderRow(row)) throw new TypeError('header row');
    const name = Object.getOwnPropertyDescriptor(row, 'name').value;
    if (typeof name !== 'string' || !/^[\x21-\x7e]{1,128}$/u.test(name)) {
      throw new TypeError('header name');
    }
    const folded = name.toLowerCase();
    if (FORBIDDEN_HEADERS.has(folded) || (folded === 'cookie' && !allowCookie)) {
      throw new TypeError('credential header');
    }
    if (
      !safe.has(folded)
      && !opaque.has(folded)
      && !(folded === 'content-type' && responseMimeEssence !== null)
    ) throw new TypeError('unknown header');
    observed.set(folded, (observed.get(folded) ?? 0) + 1);
    if (safe.has(folded)) {
      const value = Object.getOwnPropertyDescriptor(row, 'value').value;
      if (typeof value !== 'string' || digestParts(value) !== safe.get(folded)) {
        throw new TypeError('safe header');
      }
    }
  }
  for (const [name] of safe) if (observed.get(name) !== 1) throw new TypeError('safe count');
  for (const [name, rule] of opaque) {
    const count = observed.get(name) ?? 0;
    if (count < rule.minimumCount || count > rule.maximumCount) throw new TypeError('opaque count');
  }
  if (responseMimeEssence !== null && observed.get('content-type') !== 1) {
    throw new TypeError('mime count');
  }
  return true;
}

function mutationHeaderProjection(rows) {
  const allowed = new Set([
    'accept', 'accept-encoding', 'accept-language', 'content-length', 'content-type',
    'cookie', 'origin', 'referer', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'user-agent',
    'x-appwrite-project', 'x-appwrite-response-format', 'x-sdk-language',
    'x-sdk-name', 'x-sdk-platform', 'x-sdk-version',
  ]);
  if (!Array.isArray(rows) || rows.length > 256) throw new TypeError('headers');
  const safe = [];
  const names = new Set();
  for (const row of rows) {
    if (!exactHeaderRow(row)) throw new TypeError('header row');
    const name = Object.getOwnPropertyDescriptor(row, 'name').value;
    if (typeof name !== 'string') throw new TypeError('header name');
    const folded = name.toLowerCase();
    if (FORBIDDEN_HEADERS.has(folded) || !allowed.has(folded) || names.has(folded)) {
      throw new TypeError('mutation header');
    }
    names.add(folded);
    if (folded !== 'cookie') {
      const value = Object.getOwnPropertyDescriptor(row, 'value').value;
      if (typeof value !== 'string' || value.length > 8192) throw new TypeError('header value');
      safe.push(freezeClosed({ name: folded, valueDigest: digestParts(value) }));
    }
  }
  return Object.freeze(safe.sort((left, right) => left.name.localeCompare(right.name)));
}

function mutationContentType(rows) {
  const matches = rows.filter((row) => row.name.toLowerCase() === 'content-type');
  if (matches.length > 1) throw new TypeError('content type');
  const value = matches[0]?.value ?? null;
  if (value !== null && (typeof value !== 'string' || value.length > 8192)) {
    throw new TypeError('content type');
  }
  return value;
}

function currentPolicyRow(method, url, resourceType) {
  const rows = registration?.browserRequestPolicy?.rows;
  if (!Array.isArray(rows)) return undefined;
  const matches = rows.filter((row) => row.method === method
    && row.finalUrl === url && row.resourceType === resourceType);
  return matches.length === 1 ? matches[0] : undefined;
}

async function serveSyntheticRoute(record, row) {
  const occurrenceIndex = registration.policyCounts[row.ordinal] ?? 0;
  const member = artifactMemberReader(freezeClosed({
    runtimeQualification: registration.runtimeQualification,
    context: registration.context,
    providerContractQualification: registration.providerContractQualification,
    providerSetupReadbackQualification: registration.providerSetupReadbackQualification,
    browserScenarioQualification,
    policyOrdinal: row.ordinal,
    occurrenceIndex,
  }));
  if (member?.status !== 'PASS' || member.value === null) throw new TypeError('artifact');
  const body = Buffer.from(member.value.bodyBase64, 'base64');
  if (
    body.length !== row.responseByteLength
    || digestParts(body) !== row.responseBodyDigest
    || member.value.responseBodyDigest !== row.responseBodyDigest
    || member.value.responseByteLength !== row.responseByteLength
  ) throw new TypeError('artifact bytes');
  await invokeCapturedAsync(record.routeCapture, 'fulfill', [{
    status: row.expectedResponseStatus,
    body,
    contentType: row.responseMimeEssence,
  }]);
  registration.policyCounts[row.ordinal] = occurrenceIndex + 1;
  record.terminal = true;
}

async function readOwnerAccountResponse(responseCapture, row) {
  if (ownerAccount !== undefined) throw new TypeError('duplicate account');
  const bytes = Buffer.from(await invokeCapturedAsync(responseCapture, 'body'));
  const parsed = parseJsonNoDuplicateKeys(bytes.toString('utf8'));
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || IS_PROXY(parsed)) {
    throw new TypeError('account body');
  }
  const projection = Object.create(null);
  for (const key of ['$id', 'email', 'name', 'status']) {
    const descriptor = Object.getOwnPropertyDescriptor(parsed, key);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('account projection');
    }
    projection[key] = descriptor.value;
  }
  if (
    typeof projection.$id !== 'string' || projection.$id.length === 0
    || typeof projection.email !== 'string' || projection.email.length === 0
    || typeof projection.name !== 'string'
    || typeof projection.status !== 'boolean'
  ) throw new TypeError('account types');
  const expectedEmail = REFLECT_APPLY(
    registration.readAuthenticatedBrowserIdentityEmail,
    registration.bridgeReceiver,
    [Object.freeze({
      runtimeQualification: registration.runtimeQualification,
      context: registration.context,
      identityBindingsQualification: registration.identityBindingsQualification,
      role: 'owner',
    })],
  );
  if (projection.email !== expectedEmail) throw new TypeError('account identity');
  ownerAccount = freezeClosed(projection);
}

async function serveFetchedPolicyRoute(record, row) {
  const response = await invokeCapturedAsync(record.routeCapture, 'fetch', [{
    maxRedirects: 0,
    maxRetries: 0,
    timeout: 5000,
  }]);
  const responseCapture = captureOwnedInstance(response, [
    'url', 'status', 'headersArray', 'body', 'dispose',
  ]);
  try {
    if (
      invokeCaptured(responseCapture, 'url') !== row.finalUrl
      || invokeCaptured(responseCapture, 'status') !== row.expectedResponseStatus
    ) throw new TypeError('response');
    const responseHeaders = await invokeCapturedAsync(responseCapture, 'headersArray');
    classifiedHeaders(
      responseHeaders,
      row.responseHeaderBindings,
      row.responseOpaqueHeaderRules,
      true,
      row.responseMimeEssence,
    );
    if (row.responseMimeEssence !== null) {
      const contentType = responseHeaders.find((entry) => entry.name.toLowerCase() === 'content-type');
      if (contentType === undefined
        || contentType.value.split(';', 1)[0].trim().toLowerCase() !== row.responseMimeEssence) {
        throw new TypeError('mime');
      }
    }
    if (row.requestClass === 'appwrite-read'
      && new URL(row.finalUrl).pathname.endsWith('/account')) {
      await readOwnerAccountResponse(responseCapture, row);
    }
    await invokeCapturedAsync(record.routeCapture, 'fulfill', [{ response }]);
    record.terminal = true;
  } finally {
    await invokeCapturedAsync(responseCapture, 'dispose');
  }
  registration.policyCounts[row.ordinal] = (registration.policyCounts[row.ordinal] ?? 0) + 1;
}

async function ownedHttpHandler(route) {
  let record;
  try {
    if (factoryState !== 'ACTIVE_BOUND' || registration?.policyBound !== true
      || scenarioState === 'BLOCKED') throw new TypeError('route ineligible');
    const routeCapture = captureOwnedInstance(route, ['request', 'abort', 'fetch', 'fulfill']);
    const request = invokeCaptured(routeCapture, 'request');
    const requestCapture = captureOwnedInstance(request, [
      'url', 'method', 'postDataBuffer', 'headersArray', 'resourceType',
    ]);
    const method = invokeCaptured(requestCapture, 'method');
    const url = invokeCaptured(requestCapture, 'url');
    const resourceType = invokeCaptured(requestCapture, 'resourceType');
    const headers = await invokeCapturedAsync(requestCapture, 'headersArray');
    record = { routeCapture, requestCapture, method, url, resourceType, terminal: false };
    const row = currentPolicyRow(method, url, resourceType);
    if (row !== undefined && row.requestClass !== 'appwrite-json-mutation') {
      classifiedHeaders(
        headers,
        row.requestHeaderBindings,
        row.requestOpaqueHeaderRules,
        row.credentialCarrier === 'browser-cookie-jar-only',
      );
      if (row.requestClass === 'main-document' || row.requestClass === 'build-asset') {
        await serveSyntheticRoute(record, row);
      } else {
        await serveFetchedPolicyRoute(record, row);
      }
      return;
    }
    if (!['POST', 'PATCH'].includes(method) || pendingRouteRecord !== undefined) {
      throw new TypeError('classifier blocked');
    }
    const body = invokeCaptured(requestCapture, 'postDataBuffer');
    if (body === null || (!Buffer.isBuffer(body) && !(body instanceof Uint8Array))) {
      throw new TypeError('mutation body');
    }
    const releaseGate = createDeferred();
    const released = createDeferred();
    const delivery = createDeferred();
    record = {
      ...record,
      state: 'ROUTE_OBSERVED',
      headerProjection: mutationHeaderProjection(headers),
      contentType: mutationContentType(headers),
      bodyBytes: Buffer.from(body),
      observationQualification: Object.freeze(Object.create(null)),
      routeProjection: undefined,
      issueKind: undefined,
      issue: undefined,
      releaseDisposition: undefined,
      responseCapture: undefined,
      releaseGate,
      released,
      delivery,
      completionUsed: false,
      cancellationGeneration,
      terminal: false,
    };
    pendingRouteRecord = record;
    await awaitLocalPromise(releaseGate.promise);
    if (record.state === 'ABORTED') return;
    await settleOwnedRelease(record);
  } catch (error) {

    blockFactory();
    if (record?.routeCapture !== undefined && !record.terminal) {
      await closeCaptured(record.routeCapture, 'abort', ['blockedbyclient']);
    }
  }
}

async function denyWebSocket(webSocketRoute) {
  try {
    if (factoryState !== 'ACTIVE_BOUND' || scenarioState === 'BLOCKED') return;
    const capture = captureOwnedInstance(webSocketRoute, ['close']);
    await invokeCapturedAsync(capture, 'close', [{
      code: 1008,
      reason: 'verification-network-denied',
    }]);
  } catch {
    blockFactory();
  }
}

async function invokeClockOperation(clockOperations, name, args, resultKey) {
  if (!isClosedRoot(clockOperations, CLOCK_OPERATION_KEYS)) {
    throw new TypeError('clock operations');
  }
  const operation = clockOperations[name];
  if (typeof operation !== 'function' || IS_PROXY(operation)) {
    throw new TypeError('clock operation');
  }
  const result = await awaitLocalPromise(REFLECT_APPLY(
    operation,
    clockOperations.receiver,
    [Object.freeze({ ...args })],
  ));
  if (
    result?.status !== 'PASS' || result.value === null
    || typeof result.value !== 'object'
    || (resultKey !== undefined && !Object.is(result.value[resultKey], args.clock))
  ) throw new TypeError('clock result');
  return result.value;
}

function authenticateOperation(args, keys, expectedState) {
  if (
    factoryState !== 'ACTIVE_BOUND'
    || registrationState !== 'REGISTERED'
    || scenarioState !== expectedState
    || !isClosedRoot(args, keys)
    || !Object.is(
      args.browserScenarioQualification,
      browserScenarioQualification,
    )
    || !authenticateRuntime(args.runtimeQualification)
  ) return false;
  return REFLECT_APPLY(
    registration.authenticateBrowserScenarioQualification,
    registration.bridgeReceiver,
    [freezeClosed({
      runtimeQualification: args.runtimeQualification,
      browserScenarioQualification: args.browserScenarioQualification,
    })],
  ) === true;
}

function captureLocator(locator) {
  return captureOwnedInstance(locator, [
    'count', 'isVisible', 'isEnabled', 'isEditable', 'fill', 'click', 'selectOption', 'isChecked', 'dragTo',
  ]);
}

async function exactLocator(locatorCapture, needs) {
  if (await invokeCapturedAsync(locatorCapture, 'count') !== 1 || !await invokeCapturedAsync(locatorCapture, 'isVisible')) return false;
  if (needs.includes('enabled') && !await invokeCapturedAsync(locatorCapture, 'isEnabled')) return false;
  if (needs.includes('editable') && !await invokeCapturedAsync(locatorCapture, 'isEditable')) return false;
  return true;
}

async function performOwnerLogin(args) {

  const keys = [
    'runtimeQualification',
    'context',
    'browserScenarioQualification',
    'clock',
    'ownerLoginInput',
    'providerContractQualification',
    'identityBindingsQualification',
    'providerSetupReadbackQualification',
    'sessionIntentQualification',
    'clockOperations',
  ];
  if (
    arguments.length !== 1
    || !authenticateOperation(args, keys, 'READY')
    || !isClosedRoot(args.ownerLoginInput, ['password'])
    || typeof args.ownerLoginInput.password !== 'string'
    || args.ownerLoginInput.password.length < 1
    || args.ownerLoginInput.password.length > 4096
    || /[\u0000-\u001f\u007f]/u.test(args.ownerLoginInput.password)
  ) {

    return BLOCKED;
  }
  let email;
  let password;
  try {
    scenarioState = 'POLICY_BINDING';

    const policyEnvelope = REFLECT_APPLY(
      registration.readBrowserRequestPolicy,
      registration.bridgeReceiver,
      [freezeClosed({
        runtimeQualification: args.runtimeQualification,
        context: args.context,
        providerContractQualification: args.providerContractQualification,
        providerSetupReadbackQualification: args.providerSetupReadbackQualification,
      })],
    );
    if (
      !isClosedRoot(policyEnvelope, ['browserRequestPolicy'])
      || !isClosedRoot(policyEnvelope.browserRequestPolicy, [
        'schemaVersion', 'timeoutMilliseconds', 'rows', 'digest',
      ])
      || policyEnvelope.browserRequestPolicy.schemaVersion
        !== 'test-cloud.browser-request-policy.v1'
      || policyEnvelope.browserRequestPolicy.timeoutMilliseconds !== 5000
      || !Array.isArray(policyEnvelope.browserRequestPolicy.rows)
      || !Object.isFrozen(policyEnvelope.browserRequestPolicy.rows)
      || policyEnvelope.browserRequestPolicy.rows.length < 3
      || typeof policyEnvelope.browserRequestPolicy.digest !== 'string'
    ) throw new TypeError('browser policy');

    const mainRows = policyEnvelope.browserRequestPolicy.rows.filter((row) => (
      row?.requestClass === 'main-document'
      && row.method === 'GET'
      && row.resourceType === 'document'
      && typeof row.finalUrl === 'string'
    ));
    if (mainRows.length !== 1) throw new TypeError('main document policy');

    registration = freezeClosed({
      ...registration,
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      providerContractQualification: args.providerContractQualification,
      identityBindingsQualification: args.identityBindingsQualification,
      providerSetupReadbackQualification: args.providerSetupReadbackQualification,
      browserRequestPolicy: policyEnvelope.browserRequestPolicy,
      policyCounts: Object.create(null),
      policyBound: true,
    });
    scenarioState = 'POLICY_BOUND';

    const playwright = await import('playwright');

    const chromiumDescriptor = Object.getOwnPropertyDescriptor(playwright, 'chromium');
    if (
      chromiumDescriptor === undefined
      || !Object.hasOwn(chromiumDescriptor, 'value')
      || chromiumDescriptor.value === null
      || typeof chromiumDescriptor.value !== 'object'
      || IS_PROXY(chromiumDescriptor.value)
    ) throw new TypeError('playwright chromium');
    const chromiumCapture = captureOwnedInstance(chromiumDescriptor.value, ['launch']);

    const launchedBrowser = await invokeCapturedAsync(chromiumCapture, 'launch', [{ headless: true }]);

    browserCapture = captureOwnedInstance(launchedBrowser, ['contexts', 'newContext', 'close']);
    const initialContexts = invokeCaptured(browserCapture, 'contexts');
    if (!Array.isArray(initialContexts) || initialContexts.length !== 0) {
      throw new TypeError('initial contexts');
    }
    const browserContext = await invokeCapturedAsync(browserCapture, 'newContext', [{
      serviceWorkers: 'block',
      acceptDownloads: false,
    }]);
    browserContextCapture = captureOwnedInstance(browserContext, [
      'pages', 'serviceWorkers', 'route', 'routeWebSocket', 'newPage',
      'unrouteAll', 'close',
    ]);
    apiRequestCapture = captureOwnedInstance(
      readCapturedObjectProperty(
        browserContextCapture,
        captureOwnedObjectProperty(browserContextCapture, 'request'),
      ),
      ['get'],
    );
    const contexts = invokeCaptured(browserCapture, 'contexts');
    if (
      !Array.isArray(contexts)
      || contexts.length !== 1
      || !Object.is(contexts[0], browserContext)
      || invokeCaptured(browserContextCapture, 'pages').length !== 0
      || invokeCaptured(browserContextCapture, 'serviceWorkers').length !== 0
    ) throw new TypeError('fresh context');
    await invokeCapturedAsync(browserContextCapture, 'route', ['**/*', httpHandler]);
    await invokeCapturedAsync(
      browserContextCapture,
      'routeWebSocket',
      ['**/*', webSocketHandler],
    );
    page = await invokeCapturedAsync(browserContextCapture, 'newPage');
    pageCapture = captureOwnedInstance(page, [
      'context', 'url', 'workers', 'goto', 'locator', 'getByRole',
      'addInitScript', 'waitForTimeout', 'close',
    ]);
    const pages = invokeCaptured(browserContextCapture, 'pages');
    if (
      pages.length !== 1
      || !Object.is(pages[0], page)
      || !Object.is(invokeCaptured(pageCapture, 'context'), browserContext)
      || invokeCaptured(pageCapture, 'url') !== 'about:blank'
      || invokeCaptured(pageCapture, 'workers').length !== 0
    ) throw new TypeError('fresh page');

    retainedClock = args.clock;
    scenarioState = 'CLOCK_PREPARED';
    scenarioState = 'CLOCK_INSTALLING';
    await invokeClockOperation(
      args.clockOperations,
      'installTestCloudFixtureClock',
      { runtimeQualification: args.runtimeQualification, clock: args.clock },
      'clock',
    );
    scenarioState = 'CLOCK_INSTALLED';
    scenarioState = 'NAVIGATING';
    const navigation = await invokeCapturedAsync(pageCapture, 'goto', [
      mainRows[0].finalUrl,
      { waitUntil: 'load', timeout: 5000 },
    ]);
    const navigationCapture = captureOwnedInstance(navigation, ['url', 'status']);
    if (
      invokeCaptured(navigationCapture, 'url') !== mainRows[0].finalUrl
      || invokeCaptured(navigationCapture, 'status') !== mainRows[0].expectedResponseStatus
      || invokeCaptured(pageCapture, 'url') !== mainRows[0].finalUrl
    ) throw new TypeError('navigation');
    const emailInput = captureLocator(invokeCaptured(
      pageCapture,
      'locator',
      ['#appwritework-login-email'],
    ));
    const passwordInput = captureLocator(invokeCaptured(
      pageCapture,
      'locator',
      ['#appwritework-login-password'],
    ));
    const login = captureLocator(invokeCaptured(pageCapture, 'getByRole', [
      'button',
      { name: 'Login', exact: true },
    ]));
    if (
      !await exactLocator(emailInput, ['enabled', 'editable'])
      || !await exactLocator(passwordInput, ['enabled', 'editable'])
      || !await exactLocator(login, ['enabled'])
    ) throw new TypeError('signed out form');
    scenarioState = 'NAVIGATED_SIGNED_OUT';
    email = REFLECT_APPLY(
      registration.readAuthenticatedBrowserIdentityEmail,
      registration.bridgeReceiver,
      [Object.freeze({
        runtimeQualification: args.runtimeQualification,
        context: args.context,
        identityBindingsQualification: args.identityBindingsQualification,
        role: 'owner',
      })],
    );
    password = args.ownerLoginInput.password;
    if (typeof email !== 'string' || email.length === 0) {
      throw new TypeError('owner identity');
    }
    scenarioState = 'OWNER_LOGIN_RUNNING';
    await invokeCapturedAsync(emailInput, 'fill', [email]);
    await invokeCapturedAsync(passwordInput, 'fill', [password]);
    await invokeCapturedAsync(login, 'click');
    if (ownerAccount === undefined) throw new TypeError('owner session');
    scenarioState = 'OWNER_SESSION_COMMITTED';
    const ownerMenu = captureLocator(invokeCaptured(pageCapture, 'getByRole', [
      'button',
      { name: 'Open user menu', exact: true },
    ]));
    if (!await exactLocator(ownerMenu, [])) throw new TypeError('owner UI');
    scenarioState = 'OWNER_UI_READY';
    await invokeClockOperation(
      args.clockOperations,
      'authenticateTestCloudFixtureClock',
      {
        runtimeQualification: args.runtimeQualification,
        clock: args.clock,
        sessionIntentQualification: args.sessionIntentQualification,
      },
      'clock',
    );
    scenarioState = 'AUTHENTICATED';
    return pass({ ownerLoginComplete: true });
  } catch (error) {

    blockFactory();
    await closeOwnedGraph();
    return BLOCKED;
  } finally {
    email = undefined;
    password = undefined;
  }
}

async function performProjectCreateAndGraphEditPrefix(args) {
  const keys = [
    'runtimeQualification',
    'context',
    'browserScenarioQualification',
    'clock',
    'providerContractQualification',
    'sessionIntentQualification',
    'clockOperations',
  ];
  if (
    arguments.length !== 1
    || !authenticateOperation(args, keys, 'AUTHENTICATED')
  ) return BLOCKED;
  try {
    scenarioState = 'PREFIX_RUNNING';
    const action = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', {
      name: 'New Project',
      exact: true,
    }]));
    if (!await exactLocator(action, ['enabled'])) throw new Error('new project');
    await invokeCapturedAsync(action, 'click');
    const dialog = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['dialog', { name: 'New Project', exact: true }]));
    const name = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['textbox', { name: 'Project name', exact: true }]));
    const create = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', { name: 'Create', exact: true }]));
    if (!await exactLocator(dialog, [])
      || !await exactLocator(name, ['enabled', 'editable'])
      || !await exactLocator(create, ['enabled'])) throw new Error('project modal');
    await invokeCapturedAsync(name, 'fill', ['Verification Project']);
    await invokeCapturedAsync(create, 'click');
    const open = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', {
      name: 'Open project Verification Project', exact: true,
    }]));
    if (!await exactLocator(open, ['enabled'])) throw new Error('open project');
    await invokeCapturedAsync(open, 'click');
    const inputNode = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', { name: 'Add Input: Text', exact: true }]));
    const outputNode = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', { name: 'Add Output: Display', exact: true }]));
    if (!await exactLocator(inputNode, ['enabled'])
      || !await exactLocator(outputNode, ['enabled'])) throw new Error('catalog');
    await invokeCapturedAsync(inputNode, 'click');
    await invokeCapturedAsync(outputNode, 'click');
    const inputValue = captureLocator(invokeCaptured(pageCapture, 'locator', ['[data-id="n_11111111-1111-4111-8111-111111111111"] textarea']));
    const sourceHandle = captureLocator(invokeCaptured(pageCapture, 'locator', ['[data-nodeid="n_11111111-1111-4111-8111-111111111111"][data-handleid="value"]']));
    const targetHandle = captureLocator(invokeCaptured(pageCapture, 'locator', ['[data-nodeid="n_22222222-2222-4222-8222-222222222222"][data-handleid="in"]']));
    if (!await exactLocator(inputValue, ['enabled', 'editable'])
      || !await exactLocator(sourceHandle, [])
      || !await exactLocator(targetHandle, [])) throw new Error('graph anchors');
    await invokeCapturedAsync(inputValue, 'fill', ['Hello, World!']);
    await invokeCapturedAsync(sourceHandle, 'dragTo', [targetHandle.receiver]);
    scenarioState = 'PREFIX_READY';
    scenarioState = 'AUTOSAVE_RUNNING';
    await invokeClockOperation(
      args.clockOperations,
      'advanceTestCloudFixtureClock',
      { runtimeQualification: args.runtimeQualification, clock: args.clock },
      'clock',
    );
    if (scenarioState !== 'PREFIX_COMPLETE') throw new Error('autosave completion');
    return pass({ projectGraphPrefixReady: true });
  } catch (error) {
    blockFactory();
    await closeOwnedGraph();
    return BLOCKED;
  }
}

async function performShare(args, role, expectedState, completeState) {
  const keys = [
    'runtimeQualification',
    'context',
    'browserScenarioQualification',
    'providerContractQualification',
    'identityBindingsQualification',
    'sessionIntentQualification',
  ];
  if (!authenticateOperation(args, keys, expectedState)) return BLOCKED;
  let email;
  try {
    email = REFLECT_APPLY(
      registration.readAuthenticatedBrowserIdentityEmail,
      registration.bridgeReceiver,
      [Object.freeze({
        runtimeQualification: args.runtimeQualification,
        context: args.context,
        identityBindingsQualification: args.identityBindingsQualification,
        role,
      })],
    );
    if (typeof email !== 'string' || email.length === 0) {
      throw new Error('share identity blocked');
    }

    scenarioState = role === 'editor'
      ? 'EDITOR_SHARE_RUNNING'
      : 'VIEWER_SHARE_RUNNING';
    if (role === 'editor') {
      const settings = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', {
        name: 'Project settings',
        exact: true,
      }]));
      if (!await exactLocator(settings, ['enabled'])) {
        throw new Error('project settings blocked');
      }
      await invokeCapturedAsync(settings, 'click');
    }
    const emailInput = captureLocator(invokeCaptured(pageCapture, 'locator', ['[aria-label="Share user email"]']));
    const roleSelect = captureLocator(invokeCaptured(pageCapture, 'locator', ['[aria-label="Share role"]']));
    const submit = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['button', { name: 'Share', exact: true }]));
    if (
      !await exactLocator(emailInput, ['enabled', 'editable'])
      || !await exactLocator(roleSelect, ['enabled'])
      || !await exactLocator(submit, ['enabled'])
    ) throw new Error('share controls blocked');
    await invokeCapturedAsync(emailInput, 'fill', [email]);
    await invokeCapturedAsync(roleSelect, 'selectOption', [role]);
    if (role === 'viewer') {
      const canRun = captureLocator(invokeCaptured(pageCapture, 'locator', ['[aria-label="Share can run"]']));
      if (!await exactLocator(canRun, ['enabled']) || await invokeCapturedAsync(canRun, 'isChecked')) {
        throw new Error('viewer can-run blocked');
      }
    }
    await invokeCapturedAsync(submit, 'click');
    const shareRow = captureLocator(invokeCaptured(pageCapture, 'getByRole', ['group', {
      name: 'Shared user ' + email + ' as ' + role + ' '
        + (role === 'editor' ? 'can run' : 'cannot run'),
      exact: true,
    }]));
    if (!await exactLocator(shareRow, [])) {
      throw new Error('share row blocked');
    }
    scenarioState = completeState;
    return pass(role === 'editor'
      ? { editorShareComplete: true }
      : { viewerShareComplete: true });
  } catch {
    blockFactory();
    await closeOwnedGraph();
    return BLOCKED;
  } finally {
    email = undefined;
  }
}

async function performEditorShare(args) {
  if (arguments.length !== 1) return BLOCKED;
  return performShare(
    args,
    'editor',
    'PREFIX_COMPLETE',
    'EDITOR_SHARE_COMPLETE',
  );
}

async function performViewerShare(args) {
  if (arguments.length !== 1) return BLOCKED;
  return performShare(
    args,
    'viewer',
    'EDITOR_SHARE_COMPLETE',
    'VIEWER_SHARE_COMPLETE',
  );
}

const browserImplementation = freezeClosed({
  receiver: adapterReceiver,
  performOwnerLogin,
  performProjectCreateAndGraphEditPrefix,
  performEditorShare,
  performViewerShare,
});

function exactLogicalBindings(bindings, bindingNames) {
  if (!Array.isArray(bindings) || Reflect.ownKeys(bindings).length !== bindings.length + 1) {
    throw new TypeError('logical bindings');
  }
  const byName = new Map();
  for (const binding of bindings) {
    if (binding === null || typeof binding !== 'object' || IS_PROXY(binding)) {
      throw new TypeError('logical binding');
    }
    const name = Object.getOwnPropertyDescriptor(binding, 'name')?.value
      ?? Object.getOwnPropertyDescriptor(binding, 'bindingName')?.value;
    const value = Object.getOwnPropertyDescriptor(binding, 'value')?.value;
    const suppliedDigest = Object.getOwnPropertyDescriptor(binding, 'valueDigest')?.value;
    const valueDigest = digestParts(
      typeof value === 'string' ? value : canonicalJson(value),
    );
    if (
      typeof name !== 'string' || name.length === 0 || byName.has(name)
      || (suppliedDigest !== undefined && suppliedDigest !== valueDigest)
    ) throw new TypeError('logical binding value');
    byName.set(name, freezeClosed({ name, value, valueDigest }));
  }
  if (!Array.isArray(bindingNames)
    || (byName.size !== 0 && (bindingNames.length !== byName.size
      || bindingNames.some((name) => !byName.has(name))))) {
    throw new TypeError('binding names');
  }
  return byName;
}

function exactInitialSourceOperationBindings(bindings, mutationOrdinal) {
  if (!Array.isArray(bindings) || !Object.isFrozen(bindings)
    || Reflect.ownKeys(bindings).length !== bindings.length + 1
    || bindings.length !== 0) {
    throw new TypeError('source operation bindings');
  }
  if (!Number.isSafeInteger(mutationOrdinal) || mutationOrdinal < 0 || mutationOrdinal > 18) {
    throw new TypeError('source operation ordinal');
  }
  return new Map();
}

function parseMultipartFileCreate(record) {
  if (typeof record.contentType !== 'string') throw new TypeError('file content type');
  const match = /^multipart\/form-data\s*;\s*boundary=(?:"([!#$%&'*+.^_`|~0-9A-Za-z-]{1,70})"|([!#$%&'*+.^_`|~0-9A-Za-z-]{1,70}))$/u
    .exec(record.contentType);
  if (match === null) throw new TypeError('file content type');
  const boundary = match[1] ?? match[2];
  const bytes = record.bodyBytes;
  const delimiter = Buffer.from('--' + boundary, 'ascii');
  const headerSeparator = Buffer.from('\r\n\r\n', 'ascii');
  const nextDelimiter = Buffer.from('\r\n--' + boundary, 'ascii');
  if (!bytes.subarray(0, delimiter.length).equals(delimiter)) {
    throw new TypeError('multipart boundary');
  }
  const fields = new Map();
  const permissions = [];
  let file;
  let cursor = delimiter.length;
  while (true) {
    if (bytes.subarray(cursor, cursor + 2).toString('ascii') === '--') {
      cursor += 2;
      if (bytes.subarray(cursor).toString('ascii') !== '\r\n') {
        throw new TypeError('multipart epilogue');
      }
      break;
    }
    if (bytes.subarray(cursor, cursor + 2).toString('ascii') !== '\r\n') {
      throw new TypeError('multipart delimiter');
    }
    cursor += 2;
    const headerEnd = bytes.indexOf(headerSeparator, cursor);
    if (headerEnd < 0 || headerEnd - cursor > 8192) throw new TypeError('multipart headers');
    const headerLines = bytes.subarray(cursor, headerEnd).toString('latin1').split('\r\n');
    const headers = new Map();
    for (const line of headerLines) {
      const colon = line.indexOf(':');
      if (colon < 1) throw new TypeError('multipart header');
      const name = line.slice(0, colon).toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (headers.has(name) || !['content-disposition', 'content-type'].includes(name)) {
        throw new TypeError('multipart header');
      }
      headers.set(name, value);
    }
    const disposition = headers.get('content-disposition');
    const dispositionMatch = /^form-data;\s*name="([A-Za-z0-9.\[\]_-]{1,128})"(?:;\s*filename="([^"\r\n]{1,255})")?$/u
      .exec(disposition ?? '');
    if (dispositionMatch === null) throw new TypeError('multipart disposition');
    const payloadStart = headerEnd + headerSeparator.length;
    const payloadEnd = bytes.indexOf(nextDelimiter, payloadStart);
    if (payloadEnd < 0) throw new TypeError('multipart payload');
    const name = dispositionMatch[1];
    const filename = dispositionMatch[2];
    const payload = bytes.subarray(payloadStart, payloadEnd);
    if (name === 'file') {
      if (file !== undefined || filename === undefined
        || headers.size !== 2 || typeof headers.get('content-type') !== 'string') {
        throw new TypeError('multipart file');
      }
      file = freezeClosed({
        bytes: Buffer.from(payload),
        fileName: filename,
        mimeType: headers.get('content-type'),
      });
    } else {
      if (filename !== undefined || headers.size !== 1 || name === 'file') {
        throw new TypeError('multipart field');
      }
      const value = payload.toString('utf8');
      if (name === 'permissions[]') {
        permissions.push(value);
      } else if (name === 'permissions') {
        if (fields.has(name) || permissions.length !== 0) throw new TypeError('permissions');
        const parsed = parseJsonNoDuplicateKeys(value);
        if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== 'string')) {
          throw new TypeError('permissions');
        }
        permissions.push(...parsed);
        fields.set(name, true);
      } else {
        if (fields.has(name)) throw new TypeError('multipart duplicate');
        fields.set(name, value);
      }
    }
    cursor = payloadEnd + 2 + delimiter.length;
  }
  if (file === undefined || fields.size !== (fields.has('permissions') ? 2 : 1)
    || typeof fields.get('fileId') !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(fields.get('fileId'))
    || permissions.some((entry) => entry.length === 0 || entry.length > 4096)) {
    throw new TypeError('file form');
  }
  return freezeClosed({
    semanticBody: freezeClosed({
      fileId: fields.get('fileId'),
      fileName: file.fileName,
      mimeType: file.mimeType,
      permissionsDigest: digestParts(canonicalJson(permissions)),
      sizeBytes: file.bytes.byteLength,
      sourceBytesDigest: digestParts(file.bytes),
    }),
    sourceBytes: file.bytes,
  });
}

function initialSourceOperationReceipt(sourceBytes, mutationOrdinal) {
  if (mutationOrdinal !== 0) return new Map();
  const manifest = parseJsonNoDuplicateKeys(sourceBytes.toString('utf8'));
  const manifestKeys = [
    'schemaVersion', 'projectId', 'artifactId', 'containerProfile', 'name',
    'parentContainerId', 'children', 'lifecycleState',
  ];
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)
    || Object.keys(manifest).length !== manifestKeys.length
    || Object.keys(manifest).some((key, index) => key !== manifestKeys[index])
    || manifest.schemaVersion !== 1 || manifest.containerProfile !== 'project-root'
    || typeof manifest.name !== 'string' || manifest.name.length === 0
    || manifest.parentContainerId !== null || manifest.lifecycleState !== 'published'
    || typeof manifest.projectId !== 'string' || typeof manifest.artifactId !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(manifest.projectId)
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(manifest.artifactId)
    || !Array.isArray(manifest.children) || manifest.children.length !== 1) {
    throw new TypeError('root manifest');
  }
  const child = manifest.children[0];
  const ref = child?.ref;
  if (child === null || typeof child !== 'object' || Array.isArray(child)
    || Object.keys(child).join('|') !== 'relationship|ref' || child.relationship !== 'owned'
    || ref === null || typeof ref !== 'object' || Array.isArray(ref)
    || Object.keys(ref).join('|')
      !== 'projectId|artifactId|artifactType|artifactVersionId|contentHash'
    || ref.projectId !== manifest.projectId || ref.artifactType !== 'workflow.dag.v1'
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(ref.artifactId)
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(ref.artifactVersionId)
    || !/^sha256:[0-9a-f]{64}$/u.test(ref.contentHash)) {
    throw new TypeError('root manifest child');
  }
  const sourceDigest = digestParts(sourceBytes);
  const values = [
    sourceDigest, manifest.artifactId, sourceDigest, manifest.projectId,
    ref.artifactId, ref.artifactVersionId, ref.contentHash,
  ];
  return new Map(INITIAL_SOURCE_OPERATION_ROWS.map(([ownerSlot, name, valueKind], index) => {
    const value = values[index];
    const row = freezeClosed({
      ownerSlot, name, valueKind, value, valueDigest: digestParts(value),
    });
    if (!isClosedRoot(row, SOURCE_OPERATION_BINDING_KEYS)) {
      throw new TypeError('source operation receipt');
    }
    return [ownerSlot + '|' + name, row];
  }));
}

function exactMemberReadbackContract(contract, bodyKind) {
  if (bodyKind === 'share-create') {
    if (contract !== null) throw new TypeError('share member readback contract');
    return null;
  }
  const providerKind = bodyKind === 'file-create' ? 'storage-file' : 'tablesdb-row';
  if (!isClosedRoot(contract, MEMBER_READBACK_CONTRACT_KEYS)
    || contract.providerKind !== providerKind
    || typeof contract.logicalResource !== 'string' || contract.logicalResource.length === 0
    || typeof contract.ownerSlot !== 'string' || contract.ownerSlot.length === 0
    || typeof contract.tableBinding !== 'string' || contract.tableBinding.length === 0
    || !Array.isArray(contract.applicationKeys) || !Object.isFrozen(contract.applicationKeys)
    || !Array.isArray(contract.projectionKeys) || !Object.isFrozen(contract.projectionKeys)) {
    throw new TypeError('member readback contract');
  }
  if (providerKind === 'tablesdb-row'
    ? (typeof contract.databaseBinding !== 'string' || contract.databaseBinding.length === 0
      || contract.transactionId !== null || contract.transactionMode !== 'committed')
    : (contract.databaseBinding !== null || contract.transactionId !== null
      || contract.transactionMode !== null)) {
    throw new TypeError('member readback transaction');
  }
  if (contract.applicationKeys.some((key, index) => typeof key !== 'string'
      || key.length === 0 || contract.applicationKeys.indexOf(key) !== index)
    || contract.projectionKeys.length !== (providerKind === 'storage-file'
      ? contract.applicationKeys.length
      : TABLESDB_SYSTEM_KEYS.length + contract.applicationKeys.length)
    || (providerKind === 'storage-file'
      ? contract.projectionKeys.some((key, index) => key !== contract.applicationKeys[index])
      : TABLESDB_SYSTEM_KEYS.some((key, index) => contract.projectionKeys[index] !== key)
        || contract.projectionKeys.slice(TABLESDB_SYSTEM_KEYS.length).some((key) => (
          !contract.applicationKeys.includes(key)
        ))
        || contract.applicationKeys.some((key) => (
          !contract.projectionKeys.includes(key)
        )))) {
    throw new TypeError('member readback projection');
  }
  return contract;
}

function exactFixedShareQueryContract(contract, bodyKind) {
  if (bodyKind !== 'share-create') {
    if (contract !== null) throw new TypeError('unexpected share query contract');
    return null;
  }
  if (!isClosedRoot(contract, FIXED_SHARE_QUERY_CONTRACT_KEYS)
    || contract.bindingName !== 'project-shares'
    || contract.databaseBinding !== 'VERIFICATION_PRIMARY_DATABASE_ID'
    || contract.tableIdSource !== 'VERIFICATION_SHARES_TABLE_ID'
    || typeof contract.databaseId !== 'string' || contract.databaseId.length === 0
    || typeof contract.tableId !== 'string' || contract.tableId.length === 0
    || contract.filterField !== 'projectId' || contract.limit !== 3
    || contract.total !== true || contract.transactionId !== null
    || contract.transactionMode !== 'committed'
    || !Array.isArray(contract.projectionKeys) || !Object.isFrozen(contract.projectionKeys)
    || contract.projectionKeys.length !== 14
    || contract.projectionKeys.some((key, index) => key !== [
      ...TABLESDB_SYSTEM_KEYS,
      'projectId', 'userId', 'userEmail', 'userName', 'role', 'canRun', 'sharedBy',
    ][index])) {
    throw new TypeError('fixed share query contract');
  }
  return contract;
}

function observedPathBindings(template, pathname) {
  const names = template.bindingNames.filter((name) => name.startsWith('path.'));
  const templateSegments = template.pathTemplate.split('/');
  const pathSegments = pathname.split('/');
  if (templateSegments.length !== pathSegments.length) throw new TypeError('path binding');
  const output = new Map();
  for (let index = 0; index < templateSegments.length; index += 1) {
    const token = /^\{([^{}]+)\}$/u.exec(templateSegments[index]);
    if (token === null) {
      if (templateSegments[index] !== pathSegments[index]) throw new TypeError('path binding');
      continue;
    }
    const name = 'path.' + token[1];
    if (!names.includes(name)) throw new TypeError('path binding name');
    const value = decodeURIComponent(pathSegments[index]);
    if (value.length === 0 || output.has(name)) throw new TypeError('path binding value');
    output.set(name, freezeClosed({
      name,
      value,
      valueDigest: digestParts(value),
    }));
  }
  if (output.size !== names.length) throw new TypeError('path binding count');
  return output;
}

function replacePathBindings(template, bindings) {
  let path = template.pathTemplate;
  for (const name of template.bindingNames.filter((entry) => entry.startsWith('path.'))) {
    const token = name.slice(5);
    const binding = bindings.get(name);
    if (typeof binding.value !== 'string' || binding.value.length === 0) {
      throw new TypeError('path binding');
    }
    path = path.replace('{' + token + '}', encodeURIComponent(binding.value));
  }
  if (/\{[^}]+\}/u.test(path)) throw new TypeError('unbound path');
  return path;
}

function bodyValue(body, name) {
  const segments = name.split('.').slice(1);
  let value = body;
  if (segments.length === 1 && segments[0] === 'permissionsDigest'
    && value !== null && typeof value === 'object') {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'permissions');
    if (descriptor !== undefined && Object.hasOwn(descriptor, 'value')
      && Array.isArray(descriptor.value)) {
      return digestParts(canonicalJson(descriptor.value));
    }
  }
  if (segments.length === 1 && segments[0] !== 'data'
    && value !== null && typeof value === 'object'
    && Object.hasOwn(value, 'data') && value.data !== null
    && typeof value.data === 'object' && Object.hasOwn(value.data, segments[0])) {
    value = value.data;
  }
  for (const segment of segments) {
    if (value === null || typeof value !== 'object') return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, segment);
    if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) return undefined;
    value = descriptor.value;
  }
  return value;
}

function interpretRouteProjection(record, authority) {
  if (!isClosedRoot(authority, [
    'operationQualification', 'requestTemplate', 'requestTemplateDigest',
    'exactDeploymentOrigin', 'fixedShareQueryContract', 'initialSourceOperationBindings',
    'logicalValueBindings', 'memberReadbackContract',
  ]) || !isClosedRoot(authority.requestTemplate, REQUEST_TEMPLATE_KEYS)) {
    throw new TypeError('request authority');
  }
  const template = authority.requestTemplate;
  if (
    template.schemaVersion !== 'verification-provider-request-template.v1'
    || template.mutationOrdinal !== record.mutationOrdinal
    || template.method !== record.method
    || !['row-create', 'row-update', 'file-create', 'share-create'].includes(template.bodyKind)
    || authority.requestTemplateDigest !== digestParts(canonicalJson(template))
  ) throw new TypeError('request template');
  const url = new URL(record.url);
  const expectedOrigin = new URL(authority.exactDeploymentOrigin);
  if (
    expectedOrigin.protocol !== 'https:' || expectedOrigin.origin !== authority.exactDeploymentOrigin
    || url.origin !== expectedOrigin.origin || url.search !== ''
  ) throw new TypeError('origin');
  const providerPath = url.pathname.startsWith('/v1/')
    ? url.pathname.slice('/v1'.length)
    : url.pathname;
  exactInitialSourceOperationBindings(
    authority.initialSourceOperationBindings,
    record.mutationOrdinal,
  );
  let bindings = exactLogicalBindings(authority.logicalValueBindings, template.bindingNames);
  const fileCreate = template.bodyKind === 'file-create'
    ? parseMultipartFileCreate(record)
    : null;
  let wireBody = fileCreate === null
    ? parseJsonNoDuplicateKeys(record.bodyBytes.toString('utf8'))
    : fileCreate.semanticBody;
  let semanticBody = wireBody;
  let executionEnvelopeDigest = null;
  if (template.bodyKind === 'share-create') {
    if (wireBody === null || typeof wireBody !== 'object' || typeof wireBody.body !== 'string') {
      throw new TypeError('share envelope');
    }
    semanticBody = parseJsonNoDuplicateKeys(wireBody.body);
    const envelope = template.executionEnvelopeTemplate;
    if (
      envelope === null || wireBody.async !== envelope.async
      || wireBody.path !== envelope.path || wireBody.method !== envelope.method
    ) throw new TypeError('share execution');
    executionEnvelopeDigest = digestParts(canonicalJson({
      ...envelope,
      bodyBytesDigest: digestParts(Buffer.from(wireBody.body, 'utf8')),
    }));
  } else if (template.executionEnvelopeTemplate !== null) {
    throw new TypeError('unexpected envelope');
  }
  if (bindings.size === 0) {
    const observed = observedPathBindings(template, providerPath);
    if (template.bodyKind === 'share-create') {
      const bodyKeys = Reflect.ownKeys(semanticBody);
      if (
        semanticBody === null
        || typeof semanticBody !== 'object'
        || bodyKeys.length !== 3
        || !['email', 'role', 'canRun'].every((key) => bodyKeys.includes(key))
        || typeof semanticBody.email !== 'string'
        || semanticBody.email.length === 0
        || semanticBody.role !== template.bodyTemplate.role
        || semanticBody.canRun !== template.bodyTemplate.canRun
      ) throw new TypeError('share body');
      observed.set('canonicalTargetEmail', freezeClosed({
        name: 'canonicalTargetEmail',
        value: semanticBody.email,
        valueDigest: digestParts(semanticBody.email),
      }));
    }
    for (const name of template.bindingNames.filter((entry) => entry.startsWith('body.'))) {
      const value = bodyValue(semanticBody, name);
      if (value === undefined) throw new TypeError('body binding ' + name);
      observed.set(name, freezeClosed({
        name,
        value,
        valueDigest: digestParts(
          typeof value === 'string' ? value : canonicalJson(value),
        ),
      }));
    }
    if (template.bodyKind !== 'share-create'
      && observed.size !== template.bindingNames.length) {
      throw new TypeError('unobserved logical binding');
    }
    bindings = observed;
  }
  if (providerPath !== replacePathBindings(template, bindings)) throw new TypeError('path');
  for (const name of template.bindingNames.filter((entry) => entry.startsWith('body.'))) {
    const binding = bindings.get(name);
    const actual = bodyValue(semanticBody, name);
    if (actual === undefined
      || digestParts(typeof actual === 'string' ? actual : canonicalJson(actual)) !== binding.valueDigest) {
      throw new TypeError('body binding ' + name);
    }
  }
  const digestRows = Object.freeze(template.bindingNames
    .filter((name) => bindings.has(name))
    .map((name) => freezeClosed({
    name,
    valueDigest: bindings.get(name).valueDigest,
    })));
  const generatedIdBindings = Object.freeze(template.bindingNames
    .filter((name) => name === 'body.rowId' || name === 'body.fileId')
    .map((bindingName) => freezeClosed({
      bindingName,
      valueDigest: bindings.get(bindingName).valueDigest,
    })));
  record.requestTemplate = template;
  record.logicalBindings = bindings;
  record.initialSourceOperationBindings = initialSourceOperationReceipt(
    fileCreate?.sourceBytes,
    record.mutationOrdinal,
  );
  record.memberReadbackContract = exactMemberReadbackContract(
    authority.memberReadbackContract,
    template.bodyKind,
  );
  record.fixedShareQueryContract = exactFixedShareQueryContract(
    authority.fixedShareQueryContract,
    template.bodyKind,
  );
  record.semanticBody = semanticBody;
  const pathClass = template.bodyKind;
  const sourceBinding = bindings.get('body.sourceBytesDigest');
  return freezeClosed({
    method: record.method,
    originBinding: freezeClosed({
      originClass: 'appwrite-api',
      originDigest: digestParts(url.origin),
    }),
    pathBinding: freezeClosed({
      pathClass,
      pathDigest: digestParts(url.pathname),
    }),
    queryBinding: freezeClosed({
      queryClass: 'absent',
      queryDigest: digestParts(''),
    }),
    bodyBinding: freezeClosed({
      semanticBodyDigest: digestParts(canonicalJson(semanticBody)),
      boundValuesDigest: digestParts(canonicalJson(digestRows)),
      executionEnvelopeDigest,
    }),
    sourceBytesDigest: sourceBinding?.value ?? null,
    generatedIdBindings,
  });
}

function closedJson(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return Object.freeze(value.map(closedJson));
  const output = Object.create(null);
  for (const key of Object.keys(value)) {
    Object.defineProperty(output, key, {
      value: closedJson(value[key]), enumerable: true,
      configurable: false, writable: false,
    });
  }
  return Object.freeze(output);
}

async function backendReadJson(url) {
  if (apiRequestCapture === undefined) throw new TypeError('backend transport');
  const response = await invokeCapturedAsync(apiRequestCapture, 'get', [url, {
    failOnStatusCode: false,
    maxRetries: 0,
    timeout: 5000,
  }]);
  const capture = captureOwnedInstance(response, [
    'url', 'status', 'headersArray', 'body', 'dispose',
  ]);
  try {
    if (invokeCaptured(capture, 'url') !== url || invokeCaptured(capture, 'status') !== 200) {
      throw new TypeError('backend status');
    }
    const bytes = await invokeCapturedAsync(capture, 'body');
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
      throw new TypeError('backend body');
    }
    return closedJson(parseJsonNoDuplicateKeys(Buffer.from(bytes).toString('utf8')));
  } finally {
    await invokeCapturedAsync(capture, 'dispose');
  }
}

function pointReadUrl(record, providerId) {
  const url = new URL(record.url);
  const encoded = encodeURIComponent(providerId);
  if (record.requestTemplate.bodyKind === 'row-create'
    || record.requestTemplate.bodyKind === 'file-create') {
    url.pathname = url.pathname.replace(/\/$/u, '') + '/' + encoded;
  } else if (!url.pathname.endsWith('/' + encoded)) {
    throw new TypeError('provider identity path');
  }
  return url.href;
}

function normalizedProviderState(record, raw) {
  let observedResultState;
  let schemaVersion;
  let contentKey;
  if (record.requestTemplate.bodyKind === 'file-create') {
    observedResultState = freezeClosed({
      bucketBinding: raw.bucketId,
      fileName: raw.name,
      mimeType: raw.mimeType,
      sizeBytes: raw.sizeOriginal,
    });
    schemaVersion = 'storage-file-metadata-state.v1';
    contentKey = 'metadataDigest';
  } else {
    const contract = record.memberReadbackContract;
    const actualKeys = Object.keys(raw);
    if (contract === null || contract.providerKind !== 'tablesdb-row'
      || actualKeys.length !== contract.projectionKeys.length
      || actualKeys.some((key, index) => key !== contract.projectionKeys[index])
      || raw.$databaseId !== record.logicalBindings.get('path.databaseId')?.value
      || raw.$tableId !== record.logicalBindings.get('path.tableId')?.value
      || !Number.isSafeInteger(raw.$sequence) || raw.$sequence < 0
      || typeof raw.$createdAt !== 'string' || typeof raw.$updatedAt !== 'string'
      || !Array.isArray(raw.$permissions)
      || raw.$permissions.some((permission) => typeof permission !== 'string')) {
      throw new TypeError('row projection');
    }
    const values = Object.create(null);
    for (const key of contract.applicationKeys) {
      Object.defineProperty(values, key, {
        value: closedJson(raw[key]), enumerable: true,
        configurable: false, writable: false,
      });
    }
    observedResultState = Object.freeze(values);
    schemaVersion = 'tablesdb-row-state.v1';
    contentKey = 'dataDigest';
  }
  const permissions = Array.isArray(raw.$permissions) ? raw.$permissions : [];
  return freezeClosed({
    observedResultState,
    memberState: freezeClosed({
      [contentKey]: digestParts(canonicalJson(observedResultState)),
      permissionsDigest: digestParts(canonicalJson(permissions)),
      presence: 'present',
      schemaVersion,
    }),
  });
}

async function readProviderState(record, providerId) {
  const raw = await backendReadJson(pointReadUrl(record, providerId));
  if (raw.$id !== providerId) throw new TypeError('provider id readback');
  return normalizedProviderState(record, raw);
}

function providerValueForName(ownerSlot, name) {
  const initial = observedRouteRecords.get(0)?.initialSourceOperationBindings
    ?.get(ownerSlot + '|' + name);
  if (initial !== undefined) return initial.value;
  const bindingCandidates = Object.freeze({
    sourceBytesDigest: ['body.sourceBytesDigest'],
    rootArtifactId: ['body.artifactId'],
    rootContentHash: ['body.contentHash'],
    projectId: ['body.projectId', 'body.rowId'],
    entrypointArtifactId: ['body.artifactId'],
    initialEntrypointVersionId: ['body.versionId', 'body.rowId'],
    workflowContentHash: ['body.contentHash'],
    initialRootVersionId: ['body.versionId', 'body.rowId'],
    savedEntrypointVersionId: ['body.versionId', 'body.rowId'],
    savedRootVersionId: ['body.versionId', 'body.rowId'],
    visualArtifactId: ['body.artifactId'],
    visualContentHash: ['body.contentHash'],
    visualVersionId: ['body.versionId', 'body.rowId'],
  })[name] ?? [];
  for (const record of [...observedRouteRecords.values()].reverse()) {
    for (const candidate of bindingCandidates) {
      const binding = record.logicalBindings.get(candidate);
      if (binding !== undefined) return binding.value;
    }
  }
  return undefined;
}

async function readShareRows(record) {
  const contract = record.fixedShareQueryContract;
  if (contract === null || primaryDatabaseId === undefined || primaryProjectId === undefined
    || contract.databaseId !== primaryDatabaseId) {
    throw new TypeError('share query binding');
  }
  const origin = new URL(record.url).origin;
  const url = new URL(origin + '/tablesdb/' + encodeURIComponent(contract.databaseId)
    + '/tables/' + encodeURIComponent(contract.tableId) + '/rows');
  const clauses = [
    { method: 'select', values: contract.projectionKeys },
    { method: 'equal', attribute: contract.filterField, values: [primaryProjectId] },
    { method: 'limit', values: [contract.limit] },
  ];
  for (const clause of clauses) {
    url.searchParams.append('queries[]', JSON.stringify(clause));
  }
  url.searchParams.set('total', String(contract.total));
  const result = await backendReadJson(url.href);
  if (Object.keys(result).length !== 2 || !Object.hasOwn(result, 'total')
    || !Object.hasOwn(result, 'rows') || !Number.isSafeInteger(result.total)
    || result.total < 0
    || !Array.isArray(result.rows)
    || result.rows.length !== Math.min(result.total, contract.limit)) {
    throw new TypeError('share query result');
  }
  const ids = new Set();
  for (const row of result.rows) {
    const keys = Object.keys(row);
    if (keys.length !== contract.projectionKeys.length
      || keys.some((key, index) => key !== contract.projectionKeys[index])
      || typeof row.$id !== 'string' || row.$id.length === 0 || ids.has(row.$id)
      || !Number.isSafeInteger(row.$sequence) || row.$sequence < 0
      || row.$databaseId !== contract.databaseId || row.$tableId !== contract.tableId
      || typeof row.$createdAt !== 'string' || typeof row.$updatedAt !== 'string'
      || !Array.isArray(row.$permissions)
      || row.$permissions.some((permission) => typeof permission !== 'string')
      || row.projectId !== primaryProjectId) {
      throw new TypeError('share row projection');
    }
    ids.add(row.$id);
  }
  return result.rows;
}

function exactExpectedShareRow(value) {
  if (!isClosedRoot(value, [
    'projectId', 'userId', 'userEmail', 'userName', 'role', 'canRun',
    'sharedBy', 'permissions',
  ]) || !Array.isArray(value.permissions) || !Object.isFrozen(value.permissions)
    || value.permissions.some((permission) => typeof permission !== 'string')) return false;
  for (const key of ['projectId', 'userId', 'userEmail', 'userName', 'role', 'sharedBy']) {
    if (typeof value[key] !== 'string' || value[key].length === 0) return false;
  }
  return typeof value.canRun === 'boolean';
}

function exactShareRowIdentity(row, expected) {
  return row.projectId === expected.projectId
    && row.userId === expected.userId
    && row.userEmail === expected.userEmail
    && row.userName === expected.userName
    && row.role === expected.role
    && row.canRun === expected.canRun
    && row.sharedBy === expected.sharedBy
    && canonicalJson(row.$permissions) === canonicalJson(expected.permissions);
}

async function completeDelivery(record, reconciliationQualification) {
  if (record.completionUsed || record.state !== 'RELEASE_CONSUMED'
    || record.releaseDisposition !== 'returned' || record.responseCapture === undefined
    || reconciliationQualification === null || typeof reconciliationQualification !== 'object') {
    throw new TypeError('delivery ineligible');
  }
  record.completionUsed = true;
  try {
    await invokeCapturedAsync(record.routeCapture, 'fulfill', [{
      response: record.responseCapture.receiver,
    }]);
    record.terminal = true;
    await invokeCapturedAsync(record.responseCapture, 'dispose');
    record.responseCapture = undefined;
    if (!Object.is(pendingRouteRecord, record)) throw new TypeError('stale delivery');
    pendingRouteRecord = undefined;
    return freezeClosed({ delivered: true });
  } catch (error) {
    abortOwnedDelivery(record);
    throw error;
  }
}

function abortOwnedDelivery(record) {
  if (!Object.is(pendingRouteRecord, record) || record.state === 'ABORTED') {
    return BLOCKED;
  }
  pendingRouteRecord = undefined;
  record.state = 'ABORTED';
  record.releaseGate.resolve(false);
  record.released.resolve(false);
  blockFactory();
  void (async () => {
    try {
      const responseCapture = record.responseCapture;
      record.responseCapture = undefined;
      await closeCaptured(responseCapture, 'dispose', []);
      await closeCaptured(record.routeCapture, 'abort', ['blockedbyclient']);
      record.terminal = true;
      await closeOwnedGraph();
    } catch {
      blockFactory();
      await closeOwnedGraph();
    }
  })();
  return freezeClosed({ aborted: true });
}

async function settleOwnedRelease(record) {
  let disposition = 'unknown';
  let responseCapture;
  try {
    const response = await invokeCapturedAsync(record.routeCapture, 'fetch', [{
      maxRedirects: 0,
      maxRetries: 0,
      timeout: 5000,
    }]);
    responseCapture = captureOwnedInstance(response, [
      'url', 'status', 'headersArray', 'body', 'dispose',
    ]);
    disposition = 'returned';
  } catch (error) {
    disposition = cancellationGeneration !== record.cancellationGeneration
      || isGenuinePlaywrightTimeoutError(error) ? 'unknown'
      : 'threw';
  }
  if (
    Object.is(pendingRouteRecord, record)
    && pendingRouteRecord.state === 'ISSUE_BOUND'
  ) {
    record.state = 'RELEASE_RECORDED';
    record.releaseDisposition = disposition;
    record.responseCapture = responseCapture;
    record.released.resolve(true);
    return;
  }
  blockFactory();
}

function captureProviderMutationRoute(args) {
  const captureKeys = [
    'runtimeQualification',
    'context',
    'sessionIntentQualification',
    'mutationOrdinal',
    'requestAuthority',
  ];
  const bindProviderKeys = [
    'operation',
    'runtimeQualification',
    'observationQualification',
    'providerMutationIssue',
  ];
  const consumeProviderKeys = [
    'operation',
    'runtimeQualification',
    'providerMutationIssue',
  ];
  const bindShareKeys = [
    'operation',
    'runtimeQualification',
    'observationQualification',
    'shareIssue',
  ];
  const consumeShareKeys = [
    'operation',
    'runtimeQualification',
    'shareIssue',
  ];
  const abortKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'mutationOrdinal',
    'observationQualification',
  ];
  const readProviderBindingKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'mutationOrdinal',
    'observationQualification',
  ];
  const readProviderValuesKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'mutationOrdinal',
    'observationQualification', 'logicalResource', 'batchIndex',
  ];
  const readProviderResultKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'mutationOrdinal',
    'observationQualification', 'logicalResource', 'ownerSlot',
    'providerKind', 'providerId', 'providerCompositeIdentity',
  ];
  const readProviderMemberKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'logicalResource', 'ownerSlot',
    'mutationOrdinal', 'providerId',
  ];
  const readShareBaselineKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'providerQualification', 'ownerSlot',
    'mutationOrdinal', 'expectedShareRow',
  ];
  const readShareResultKeys = [
    'operation', 'runtimeQualification', 'context',
    'sessionIntentQualification', 'mutationOrdinal',
    'observationQualification',
  ];
  if (
    arguments.length !== 1
    || factoryState !== 'ACTIVE_BOUND'
    || registrationState !== 'REGISTERED'
    || !authenticateRuntime(args.runtimeQualification)
  ) return BLOCKED;

  if (isClosedRoot(args, readProviderMemberKeys)
    && args.operation === 'read-provider-member-state') {
    const descriptor = providerMemberReadbacks.get(
      args.logicalResource + '|' + args.ownerSlot + '|' + args.mutationOrdinal,
    );
    if (descriptor === undefined || descriptor.context !== args.context
      || descriptor.sessionIntentQualification !== args.sessionIntentQualification
      || descriptor.providerId !== args.providerId) return BLOCKED;
    return (async () => freezeClosed({
      memberState: (await readProviderState(
        descriptor.routeRecord,
        descriptor.providerId,
      )).memberState,
    }))();
  }

  if (pendingRouteRecord === undefined) return BLOCKED;

  if (
    isClosedRoot(args, abortKeys)
    && args.operation === 'abort-delivery'
    && Object.is(args.runtimeQualification, pendingRouteRecord.runtimeQualification)
    && Object.is(args.context, pendingRouteRecord.context)
    && Object.is(
      args.sessionIntentQualification,
      pendingRouteRecord.sessionIntentQualification,
    )
    && args.mutationOrdinal === pendingRouteRecord.mutationOrdinal
    && Object.is(
      args.observationQualification,
      pendingRouteRecord.observationQualification,
    )
  ) return abortOwnedDelivery(pendingRouteRecord);

  if (
    isClosedRoot(args, captureKeys)
    && pendingRouteRecord.state === 'ROUTE_OBSERVED'
    && Number.isSafeInteger(args.mutationOrdinal)
    && args.mutationOrdinal >= 0
    && args.mutationOrdinal <= 18
  ) {
    const record = pendingRouteRecord;
    record.runtimeQualification = args.runtimeQualification;
    record.context = args.context;
    record.sessionIntentQualification = args.sessionIntentQualification;
    record.mutationOrdinal = args.mutationOrdinal;
    try {
      record.routeProjection = interpretRouteProjection(record, args.requestAuthority);
    } catch (error) {
      abortOwnedDelivery(record);
      return BLOCKED;
    }
    observedRouteRecords.set(args.mutationOrdinal, record);
    const databaseBinding = record.logicalBindings.get('path.databaseId');
    if (databaseBinding !== undefined) primaryDatabaseId ??= databaseBinding.value;
    record.state = 'ROUTE_CAPTURED';
    return freezeClosed({
      observationQualification: record.observationQualification,
      routeProjection: record.routeProjection,
    });
  }

  if (
    isClosedRoot(args, readProviderBindingKeys)
    && args.operation === 'read-provider-binding'
    && pendingRouteRecord.state === 'ROUTE_CAPTURED'
    && Object.is(args.runtimeQualification, pendingRouteRecord.runtimeQualification)
    && Object.is(args.context, pendingRouteRecord.context)
    && Object.is(
      args.sessionIntentQualification,
      pendingRouteRecord.sessionIntentQualification,
    )
    && args.mutationOrdinal === pendingRouteRecord.mutationOrdinal
    && Object.is(
      args.observationQualification,
      pendingRouteRecord.observationQualification,
    )
  ) {
    const binding = pendingRouteRecord.logicalBindings.get('body.rowId')
      ?? pendingRouteRecord.logicalBindings.get('body.fileId');
    if (
      binding !== undefined
      && typeof binding.value === 'string'
      && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(binding.value)
    ) return freezeClosed({ providerId: binding.value });
  }

  if (
    isClosedRoot(args, readProviderValuesKeys)
    && args.operation === 'read-provider-values'
    && pendingRouteRecord.state === 'ROUTE_CAPTURED'
    && Object.is(args.runtimeQualification, pendingRouteRecord.runtimeQualification)
    && Object.is(args.context, pendingRouteRecord.context)
    && Object.is(args.sessionIntentQualification, pendingRouteRecord.sessionIntentQualification)
    && args.mutationOrdinal === pendingRouteRecord.mutationOrdinal
    && Object.is(args.observationQualification, pendingRouteRecord.observationQualification)
    && Number.isSafeInteger(args.batchIndex)
  ) {
    if (args.batchIndex === -1 && args.logicalResource === 'route-observation') {
      const bindings = pendingRouteRecord.requestTemplate.bindingNames
        .filter((bindingName) => pendingRouteRecord.logicalBindings.has(bindingName))
        .map((bindingName) => {
          const binding = pendingRouteRecord.logicalBindings.get(bindingName);
          if (binding === undefined) throw new TypeError('observed binding');
          const value = closedJson(binding.value);
          return freezeClosed({
            bindingName,
            valueType: value === null ? 'null'
              : Array.isArray(value) ? 'array' : typeof value,
            value,
          });
        });
      if (ownerAccount?.$id !== undefined) {
        bindings.push(freezeClosed({
          bindingName: 'ownerUserId',
          valueType: 'string',
          value: ownerAccount.$id,
        }));
      }
      return freezeClosed({ bindings: Object.freeze(bindings) });
    }
    const batchRows = Object.freeze([
      [['rootManifestInitial', 'sourceBytesDigest', 'source-bytes-digest'], ['rootArtifact', 'rootArtifactId', 'artifact-id'], ['rootVersionInitial', 'rootContentHash', 'content-hash'], ['projectFacade', 'projectId', 'project-id']],
      [['entrypointArtifact', 'entrypointArtifactId', 'artifact-id'], ['entrypointVersionInitial', 'initialEntrypointVersionId', 'artifact-version-id'], ['entrypointVersionInitial', 'workflowContentHash', 'content-hash']],
      [['entrypointSourceInitial', 'sourceBytesDigest', 'source-bytes-digest']],
      [['rootVersionInitial', 'initialRootVersionId', 'artifact-version-id']],
      [['entrypointSourceSaved', 'sourceBytesDigest', 'source-bytes-digest'], ['entrypointVersionSaved', 'workflowContentHash', 'content-hash']],
      [['entrypointVersionSaved', 'savedEntrypointVersionId', 'artifact-version-id']],
      [['rootManifestSaved', 'sourceBytesDigest', 'source-bytes-digest'], ['rootVersionSaved', 'rootContentHash', 'content-hash']],
      [['rootVersionSaved', 'savedRootVersionId', 'artifact-version-id']],
      [['visualModelSourceSaved', 'sourceBytesDigest', 'source-bytes-digest'], ['visualModelArtifact', 'visualArtifactId', 'artifact-id'], ['visualModelVersionSaved', 'visualContentHash', 'content-hash']],
      [['visualModelVersionSaved', 'visualVersionId', 'artifact-version-id']],
    ])[args.batchIndex];
    if (batchRows !== undefined) {
      const values = batchRows.map(([ownerSlot, name, valueKind]) => {
        const value = providerValueForName(ownerSlot, name);
        if (value === undefined) throw new TypeError('provider value unavailable');
        return freezeClosed({
          ownerSlot, name, valueKind, value,
          valueDigest: digestParts(typeof value === 'string' ? value : canonicalJson(value)),
        });
      });
      return freezeClosed({ bindings: Object.freeze(values) });
    }
  }

  if (
    isClosedRoot(args, readProviderResultKeys)
    && args.operation === 'read-provider-result'
    && pendingRouteRecord.state === 'RELEASE_CONSUMED'
    && Object.is(args.runtimeQualification, pendingRouteRecord.runtimeQualification)
    && Object.is(args.context, pendingRouteRecord.context)
    && Object.is(args.sessionIntentQualification, pendingRouteRecord.sessionIntentQualification)
    && args.mutationOrdinal === pendingRouteRecord.mutationOrdinal
    && Object.is(args.observationQualification, pendingRouteRecord.observationQualification)
    && typeof args.providerCompositeIdentity === 'string'
    && args.providerCompositeIdentity.endsWith('|' + args.providerId)
    && pendingRouteRecord.memberReadbackContract?.logicalResource === args.logicalResource
    && pendingRouteRecord.memberReadbackContract?.ownerSlot === args.ownerSlot
    && pendingRouteRecord.memberReadbackContract?.providerKind === args.providerKind
  ) {
    const record = pendingRouteRecord;
    return (async () => {
      const readback = await readProviderState(record, args.providerId);
      providerMemberReadbacks.set(
        args.logicalResource + '|' + args.ownerSlot + '|' + args.mutationOrdinal,
        Object.freeze({
          context: args.context,
          sessionIntentQualification: args.sessionIntentQualification,
          providerId: args.providerId,
          routeRecord: record,
        }),
      );
      if (args.mutationOrdinal === 6) primaryProjectId = args.providerId;
      return freezeClosed({
        logicalResource: args.logicalResource,
        ownerSlot: args.ownerSlot,
        providerKind: args.providerKind,
        providerId: args.providerId,
        providerCompositeIdentity: args.providerCompositeIdentity,
        memberState: readback.memberState,
        observedResultState: readback.observedResultState,
      });
    })();
  }

  if (isClosedRoot(args, readShareBaselineKeys)
    && args.operation === 'read-share-baseline'
    && pendingRouteRecord.mutationOrdinal === args.mutationOrdinal
    && exactExpectedShareRow(args.expectedShareRow)
    && args.expectedShareRow.projectId === primaryProjectId) {
    const record = pendingRouteRecord;
    return (async () => {
      const rows = await readShareRows(record);
      const baselineDigest = digestParts(canonicalJson(rows));
      shareBaselineReadbacks.set(args.ownerSlot, Object.freeze({
        baselineDigest,
        ids: Object.freeze(rows.map((row) => row.$id)),
        expectedShareRow: args.expectedShareRow,
      }));
      return freezeClosed({ baselineDigest });
    })();
  }

  if (isClosedRoot(args, readShareResultKeys)
    && args.operation === 'read-share-result'
    && pendingRouteRecord.state === 'RELEASE_CONSUMED'
    && pendingRouteRecord.mutationOrdinal === args.mutationOrdinal
    && Object.is(args.observationQualification, pendingRouteRecord.observationQualification)) {
    const record = pendingRouteRecord;
    return (async () => {
      const rows = await readShareRows(record);
      const baseline = shareBaselineReadbacks.get(args.mutationOrdinal === 17
        ? 'editorShare' : 'viewerShare');
      if (baseline === undefined) throw new TypeError('share baseline proof');
      const candidates = rows.filter((row) => !baseline.ids.includes(row.$id)
        && exactShareRowIdentity(row, baseline.expectedShareRow)
        && row.userEmail === record.semanticBody.email
        && row.role === record.semanticBody.role
        && row.canRun === record.semanticBody.canRun);
      if (candidates.length !== 1 || rows.length !== baseline.ids.length + 1) {
        throw new TypeError('share result');
      }
      const row = candidates[0];
      const memberState = freezeClosed({
        dataDigest: digestParts(canonicalJson(row)),
        permissionsDigest: digestParts(canonicalJson(row.$permissions ?? [])),
        presence: 'present',
        schemaVersion: 'tablesdb-row-state.v1',
      });
      return freezeClosed({
        discoveryProofDigest: digestParts(canonicalJson(rows)),
        memberState,
        providerId: row.$id,
        resultStateDigest: digestParts(canonicalJson(memberState)),
      });
    })();
  }

  const isProviderBind = isClosedRoot(args, bindProviderKeys)
    && args.operation === 'bind-provider-issue'
    && args.providerMutationIssue !== null
    && typeof args.providerMutationIssue === 'object';
  const isShareBind = isClosedRoot(args, bindShareKeys)
    && args.operation === 'bind-share-issue'
    && args.shareIssue !== null
    && typeof args.shareIssue === 'object';
  if (
    pendingRouteRecord.state === 'ROUTE_CAPTURED'
    && (isProviderBind || isShareBind)
    && Object.is(
      args.runtimeQualification,
      pendingRouteRecord.runtimeQualification,
    )
    && Object.is(
      args.observationQualification,
      pendingRouteRecord.observationQualification,
    )
  ) {
    pendingRouteRecord.state = 'ISSUE_BOUND';
    pendingRouteRecord.issueKind = isProviderBind ? 'provider' : 'share';
    pendingRouteRecord.issue = isProviderBind ? args.providerMutationIssue : args.shareIssue;
    pendingRouteRecord.releaseGate.resolve(true);
    return true;
  }

  const isProviderConsume = isClosedRoot(args, consumeProviderKeys)
    && args.operation === 'consume-release-disposition'
    && pendingRouteRecord.issueKind === 'provider'
    && Object.is(args.providerMutationIssue, pendingRouteRecord.issue);
  const isShareConsume = isClosedRoot(args, consumeShareKeys)
    && args.operation === 'consume-share-release-disposition'
    && pendingRouteRecord.issueKind === 'share'
    && Object.is(args.shareIssue, pendingRouteRecord.issue);
  if (
    ['ISSUE_BOUND', 'RELEASE_RECORDED'].includes(pendingRouteRecord.state)
    && (isProviderConsume || isShareConsume)
    && Object.is(
      args.runtimeQualification,
      pendingRouteRecord.runtimeQualification,
    )
  ) {
    const record = pendingRouteRecord;
    if (record.state === 'RELEASE_RECORDED') {
      const result = freezeClosed({
        observationQualification: record.observationQualification,
        releaseDisposition: record.releaseDisposition,
      });
      record.state = 'RELEASE_CONSUMED';
      return result;
    }
    return (async () => {
      try {
        await awaitLocalPromise(record.released.promise);
        if (
          !Object.is(pendingRouteRecord, record)
          || record.state !== 'RELEASE_RECORDED'
        ) throw new TypeError('release handoff');
        const result = freezeClosed({
          observationQualification: record.observationQualification,
          releaseDisposition: record.releaseDisposition,
        });
        record.state = 'RELEASE_CONSUMED';
        return result;
      } catch {
        blockFactory();
        return BLOCKED;
      }
    })();
  }

  if (isClosedRoot(args, [
    'operation', 'runtimeQualification', 'issueKind', 'issue',
    'reconciliationQualification',
  ]) && args.operation === 'complete-delivery'
    && (args.issueKind === 'provider' || args.issueKind === 'share')
    && pendingRouteRecord.state === 'RELEASE_CONSUMED'
    && pendingRouteRecord.issueKind === args.issueKind
    && Object.is(pendingRouteRecord.issue, args.issue)
    && Object.is(
      pendingRouteRecord.runtimeQualification,
      args.runtimeQualification,
    )) {
    return completeDelivery(
      pendingRouteRecord,
      args.reconciliationQualification,
    );
  }

  blockFactory();
  return BLOCKED;
}

function receiveAutosaveCompletion(args) {
  if (
    arguments.length !== 1
    || factoryState !== 'ACTIVE_BOUND'
    || registrationState !== 'REGISTERED'
    || scenarioState !== 'AUTOSAVE_RUNNING'
    || !isClosedRoot(args, ['runtimeQualification', 'clock'])
    || !Object.is(args.runtimeQualification, registration.runtimeQualification)
    || !Object.is(args.clock, retainedClock)
  ) return false;
  scenarioState = 'PREFIX_COMPLETE';
  return true;
}

function registrationEnvelope(implementation) {
  return freezeClosed({
    receiver: adapterReceiver,
    implementation,
    moduleUrl: import.meta.url,
  });
}

function routeProducerRegistrationEnvelope(implementation) {
  return freezeClosed({
    receiver: adapterReceiver,
    implementation,
    moduleUrl: import.meta.url,
    artifactMemberReader,
  });
}

function blockRegistration() {
  registrationState = 'BLOCKED';
  registration = undefined;
  try {
    isAuthenticTestCloudBootstrapHub(undefined);
  } catch {}
  return false;
}

async function finalizeBootstrap(args) {
  if (
    arguments.length !== 1
    || finalizerState !== 'UNUSED'
    || factoryState !== 'READY'
    || !isClosedRoot(args, ['outcome'])
    || (args.outcome !== 'commit' && args.outcome !== 'abort')
  ) {
    finalizerState = 'BLOCKED';
    blockFactory();
    await closeOwnedGraph();
    return false;
  }
  finalizerState = 'CONSUMED';
  if (args.outcome === 'abort') {
    blockFactory();
    await closeOwnedGraph();
    return false;
  }
  if (
    registrationState !== 'REGISTERED'
    || registration === undefined
    || !Object.is(registration.browserFacade, browserFacade)
    || !Object.is(
      registration.browserScenarioQualification,
      browserScenarioQualification,
    )
  ) {
    blockFactory();
    await closeOwnedGraph();
    return false;
  }
  factoryState = 'ACTIVE_BOUND';
  scenarioState = 'READY';
  return true;
}

export async function createTestCloudBrowserFacade() {
  if (
    arguments.length !== 0
    || factoryState !== 'EMPTY'
    || readTestCloudRuntimeLifecycle() !== 'BOOTSTRAPPING'
  ) return blockFactory();

  factoryState = 'BINDING';
  if (consumeTestCloudBrowserFactoryAuthorization() !== true) {
    return blockFactory();
  }

  try {
    httpHandler = ownedHttpHandler;
    webSocketHandler = denyWebSocket;
    browserScenarioQualification = Object.freeze(Object.create(null));
    browserFacade = freezeClosed({
      installPausedBeforeNavigation,
      proveOwnerUiReady,
      readOwnerAccount,
      runForExactly800Milliseconds,
      sealClock,
    });
    factoryState = 'READY';
    return freezeClosed({
      browserFacade,
      browserScenarioQualification,
      finalizeBootstrap,
    });
  } catch {
    blockFactory();
    await closeOwnedGraph();
    return BLOCKED;
  }
}

export function registerTestCloudBrowserRouteAdapterBootstrap() {
  const hub = currentHub();
  if (
    arguments.length !== 0
    || registrationState !== 'EMPTY'
    || factoryState !== 'READY'
    || readTestCloudRuntimeLifecycle() !== 'BOOTSTRAPPING'
    || hub === undefined
    || isAuthenticTestCloudBootstrapHub(hub) !== true
  ) return blockRegistration();

  registrationState = 'REGISTERING';
  try {
    const bridgeReceiver = hubValue(hub, 'bridgeReceiver');
    const registerRouteProducer = hubValue(
      hub,
      'registerProviderMutationRouteProducer',
      'function',
    );
    const registerImplementation = hubValue(
      hub,
      'registerBrowserRouteAdapterImplementation',
      'function',
    );
    const registerAutosaveReceiver = hubValue(
      hub,
      'registerBrowserScenarioAutosaveCompletionReceiver',
      'function',
    );
    const readBrowserRequestPolicy = hubValue(
      hub,
      'readBrowserRequestPolicy',
      'function',
    );
    const readAuthenticatedBrowserIdentityEmail = hubValue(
      hub,
      'readAuthenticatedBrowserIdentityEmail',
      'function',
    );
    const authenticateBrowserScenarioQualification = hubValue(
      hub,
      'authenticateBrowserScenarioQualification',
      'function',
    );
    const hubFacade = hubValue(hub, 'browserFacade');
    const hubQualification = hubValue(hub, 'browserScenarioQualification');
    if (
      bridgeReceiver === undefined
      || registerRouteProducer === undefined
      || registerImplementation === undefined
      || registerAutosaveReceiver === undefined
      || readBrowserRequestPolicy === undefined
      || readAuthenticatedBrowserIdentityEmail === undefined
      || authenticateBrowserScenarioQualification === undefined
      || !Object.is(hubFacade, browserFacade)
      || !Object.is(hubQualification, browserScenarioQualification)
    ) return blockRegistration();

    if (
      REFLECT_APPLY(registerRouteProducer, bridgeReceiver, [
        routeProducerRegistrationEnvelope(captureProviderMutationRoute),
      ]) !== true
      || REFLECT_APPLY(registerImplementation, bridgeReceiver, [
        browserImplementation,
      ]) !== true
      || REFLECT_APPLY(registerAutosaveReceiver, bridgeReceiver, [
        registrationEnvelope(receiveAutosaveCompletion),
      ]) !== true
      || registrationState !== 'REGISTERING'
    ) return blockRegistration();

    registration = freezeClosed({
      bridgeReceiver,
      authenticateBrowserScenarioQualification,
      browserFacade: hubFacade,
      browserScenarioQualification: hubQualification,
      readAuthenticatedBrowserIdentityEmail,
      readBrowserRequestPolicy,
      routeProducer: captureProviderMutationRoute,
      webSocketHandler,
    });
    registrationState = 'REGISTERED';
    return true;
  } catch {
    return blockRegistration();
  }
}
