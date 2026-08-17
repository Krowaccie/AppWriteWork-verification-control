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
let pageCapture;
let retainedClock;
let cancellationGeneration = 0;

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
  return authenticateTestCloudRuntimeActive(freezeClosed({
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
  return freezeClosed({
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

function classifiedHeaders(rows, safeRows, opaqueRules, allowCookie) {
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
    if (!safe.has(folded) && !opaque.has(folded)) throw new TypeError('unknown header');
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
    [freezeClosed({
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
    if (row !== undefined) {
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
    await settleOwnedRelease(record);
  } catch {
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
    [freezeClosed(args)],
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
  ) return BLOCKED;
  return BLOCKED;
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
  } catch {
    scenarioState = 'BLOCKED';
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
    email = Reflect.apply(
      registration.readAuthenticatedBrowserIdentityEmail,
      registration.bridgeReceiver,
      [freezeClosed({
        runtimeQualification: args.runtimeQualification,
        context: args.context,
        providerContractQualification: args.providerContractQualification,
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
    scenarioState = 'BLOCKED';
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
    const name = Object.getOwnPropertyDescriptor(binding, 'name')?.value;
    const value = Object.getOwnPropertyDescriptor(binding, 'value')?.value;
    const valueDigest = Object.getOwnPropertyDescriptor(binding, 'valueDigest')?.value;
    if (
      typeof name !== 'string' || name.length === 0 || byName.has(name)
      || typeof valueDigest !== 'string'
      || valueDigest !== digestParts(typeof value === 'string' ? value : canonicalJson(value))
    ) throw new TypeError('logical binding value');
    byName.set(name, freezeClosed({ name, value, valueDigest }));
  }
  if (!Array.isArray(bindingNames) || bindingNames.length !== byName.size
    || bindingNames.some((name) => !byName.has(name))) {
    throw new TypeError('binding names');
  }
  return byName;
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
    'exactDeploymentOrigin', 'logicalValueBindings',
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
  const bindings = exactLogicalBindings(authority.logicalValueBindings, template.bindingNames);
  if (url.pathname !== replacePathBindings(template, bindings)) throw new TypeError('path');
  let wireBody = parseJsonNoDuplicateKeys(record.bodyBytes.toString('utf8'));
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
  for (const name of template.bindingNames.filter((entry) => entry.startsWith('body.'))) {
    const binding = bindings.get(name);
    const actual = bodyValue(semanticBody, name);
    if (actual === undefined
      || digestParts(typeof actual === 'string' ? actual : canonicalJson(actual)) !== binding.valueDigest) {
      throw new TypeError('body binding');
    }
  }
  const digestRows = Object.freeze(template.bindingNames.map((name) => freezeClosed({
    name,
    valueDigest: bindings.get(name).valueDigest,
  })));
  const generatedIdBindings = Object.freeze(template.bindingNames
    .filter((name) => name === 'body.rowId' || name === 'body.fileId')
    .map((bindingName) => freezeClosed({
      bindingName,
      valueDigest: bindings.get(bindingName).valueDigest,
    })));
  const pathClass = template.bodyKind === 'share-create' ? 'row-create' : template.bodyKind;
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
    blockFactory();
    throw error;
  }
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
  if (
    arguments.length !== 1
    || factoryState !== 'ACTIVE_BOUND'
    || registrationState !== 'REGISTERED'
    || pendingRouteRecord === undefined
    || !authenticateRuntime(args.runtimeQualification)
  ) return BLOCKED;

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
    record.routeProjection = interpretRouteProjection(record, args.requestAuthority);
    record.state = 'ROUTE_CAPTURED';
    return freezeClosed({
      observationQualification: record.observationQualification,
      routeProjection: record.routeProjection,
    });
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
    pendingRouteRecord.state === 'RELEASE_RECORDED'
    && (isProviderConsume || isShareConsume)
    && Object.is(
      args.runtimeQualification,
      pendingRouteRecord.runtimeQualification,
    )
  ) {
    const record = pendingRouteRecord;
    const result = freezeClosed({
      observationQualification: record.observationQualification,
      releaseDisposition: record.releaseDisposition,
    });
    record.state = 'RELEASE_CONSUMED';
    return result;
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
      Reflect.apply(registerRouteProducer, bridgeReceiver, [
        routeProducerRegistrationEnvelope(captureProviderMutationRoute),
      ]) !== true
      || Reflect.apply(registerImplementation, bridgeReceiver, [
        browserImplementation,
      ]) !== true
      || Reflect.apply(registerAutosaveReceiver, bridgeReceiver, [
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
