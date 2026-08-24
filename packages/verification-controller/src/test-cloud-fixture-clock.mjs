import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import {
  authenticateTestCloudRuntimeActive,
  isAuthenticTestCloudBootstrapHub,
  readTestCloudRuntimeLifecycle,
} from '../../../scripts/verification/test-cloud-provider-contract.mjs';

const BOOTSTRAP_HUB = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';
const MODULE_URL = import.meta.url;

const ARRAY_IS_ARRAY = Array.isArray;
const DATE = Date;
const DATE_NOW = Date.now;
const DATE_TO_ISO_STRING = Date.prototype.toISOString;
const JSON_STRINGIFY = JSON.stringify;
const OBJECT_CREATE = Object.create;
const OBJECT_DEFINE_PROPERTIES = Object.defineProperties;
const OBJECT_FREEZE = Object.freeze;
const OBJECT_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const OBJECT_GET_PROTOTYPE_OF = Object.getPrototypeOf;
const OBJECT_HAS_OWN = Object.hasOwn;
const OBJECT_IS_FROZEN = Object.isFrozen;
const OBJECT_IS = Object.is;
const OBJECT_KEYS = Object.keys;
const PROMISE_PROTOTYPE = Promise.prototype;
const REFLECT_APPLY = Reflect.apply;
const REFLECT_OWN_KEYS = Reflect.ownKeys;
const WEAK_MAP_GET = WeakMap.prototype.get;
const WEAK_MAP_HAS = WeakMap.prototype.has;
const WEAK_MAP_SET = WeakMap.prototype.set;
const WEAK_SET_ADD = WeakSet.prototype.add;
const WEAK_SET_HAS = WeakSet.prototype.has;
const IS_PROMISE = utilTypes.isPromise;
const IS_PROXY = utilTypes.isProxy;

const CLOCK_ORDINALS = OBJECT_FREEZE([4, 5, 8, 11, 16]);
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

const FORBIDDEN = OBJECT_FREEZE({
  status: 'BLOCKED',
  value: null,
  diagnostics: OBJECT_FREEZE([
    OBJECT_FREEZE({
      code: 'TEST_FIXTURE_CLOCK_FORBIDDEN',
      retryable: false,
      safeMessage: 'Fixture clock operation is not authorized.',
    }),
  ]),
});

const INVALID = OBJECT_FREEZE({
  status: 'BLOCKED',
  value: null,
  diagnostics: OBJECT_FREEZE([
    OBJECT_FREEZE({
      code: 'TEST_FIXTURE_CLOCK_INVALID',
      retryable: false,
      safeMessage: 'Fixture clock qualification failed.',
    }),
  ]),
});

const EXPECTED_POLICY = OBJECT_FREEZE({
  schemaVersion: 'verification-dashboard-clock-policy.v1',
  authenticationBoundary: OBJECT_FREEZE({
    browserOwnership: 'adapter-single-launch-context-page',
    policyPhase: 'before-owner-session',
    navigation: 'sole-main-document-before-login-actions',
    ledgerCommit: 'account-session-set-after-login-actions',
  }),
  installBoundary: OBJECT_FREEZE({
    after: 'factory-ready-policy-bound',
    before: 'adapter-owned-sole-main-document-navigation',
  }),
  initialState: 'paused',
  autosaveDelayMilliseconds: 800,
  intermediateTimerPolicy: 'cancel',
  advanceMilliseconds: OBJECT_FREEZE([800]),
  allowedAutosaves: 1,
  finalState: 'paused',
  publishedAtOffsets: OBJECT_FREEZE([
    OBJECT_FREEZE({ mutationOrdinal: 4, offsetMilliseconds: 0 }),
    OBJECT_FREEZE({ mutationOrdinal: 5, offsetMilliseconds: 0 }),
    OBJECT_FREEZE({ mutationOrdinal: 8, offsetMilliseconds: 800 }),
    OBJECT_FREEZE({ mutationOrdinal: 11, offsetMilliseconds: 800 }),
    OBJECT_FREEZE({ mutationOrdinal: 16, offsetMilliseconds: 800 }),
  ]),
});

const CLOCK_RECORDS = new WeakMap();
const BLOCKED_CLOCKS = new WeakSet();
const CLOCK_RUN_BINDINGS = new WeakMap();
const AUTHENTIC_EXPECTED_RESULTS = new WeakMap();
const RECONCILIATION_AGGREGATES = new WeakMap();

class InvalidOperation extends Error {}
class ForbiddenOperation extends Error {}

function invalid() {
  throw new InvalidOperation();
}

function forbidden() {
  throw new ForbiddenOperation();
}

function mapGet(map, key) {
  return REFLECT_APPLY(WEAK_MAP_GET, map, [key]);
}

function mapHas(map, key) {
  return REFLECT_APPLY(WEAK_MAP_HAS, map, [key]);
}

function mapSet(map, key, value) {
  REFLECT_APPLY(WEAK_MAP_SET, map, [key, value]);
  if (!OBJECT_IS(mapGet(map, key), value)) forbidden();
}

function setHas(set, key) {
  return REFLECT_APPLY(WEAK_SET_HAS, set, [key]);
}

function setAdd(set, key) {
  REFLECT_APPLY(WEAK_SET_ADD, set, [key]);
  if (!setHas(set, key)) forbidden();
}

function frozenNullRecord(values) {
  return OBJECT_FREEZE(Object.assign(OBJECT_CREATE(null), values));
}

function pass(values) {
  return OBJECT_FREEZE({
    status: 'PASS',
    value: frozenNullRecord(values),
    diagnostics: OBJECT_FREEZE([]),
  });
}

function readExactRecord(value, expectedKeys, allowNullPrototype = false) {
  if (value === null || typeof value !== 'object' || IS_PROXY(value)) invalid();
  const prototype = OBJECT_GET_PROTOTYPE_OF(value);
  if (prototype !== Object.prototype && !(allowNullPrototype && prototype === null)) invalid();
  const keys = REFLECT_OWN_KEYS(value);
  if (
    keys.length !== expectedKeys.length
    || keys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
  ) invalid();
  const result = OBJECT_CREATE(null);
  for (const key of expectedKeys) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    if (
      descriptor === undefined
      || !OBJECT_HAS_OWN(descriptor, 'value')
      || descriptor.enumerable !== true
    ) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function readData(value, key) {
  if (value === null || typeof value !== 'object' || IS_PROXY(value)) invalid();
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
  if (
    descriptor === undefined
    || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.enumerable !== true
  ) invalid();
  return descriptor.value;
}

function isNominalToken(value) {
  return value !== null
    && typeof value === 'object'
    && !IS_PROXY(value)
    && OBJECT_GET_PROTOTYPE_OF(value) === null
    && OBJECT_IS_FROZEN(value)
    && REFLECT_OWN_KEYS(value).length === 0;
}

function makeToken() {
  return OBJECT_FREEZE(OBJECT_CREATE(null));
}

function assertActive(runtimeQualification) {
  if (
    !isNominalToken(runtimeQualification)
    || authenticateTestCloudRuntimeActive(Object.freeze({ runtimeQualification })) !== true
  ) invalid();
}

function startOperation(args, argumentLength, expectedKeys) {
  if (readTestCloudRuntimeLifecycle() !== 'ACTIVE') forbidden();
  if (argumentLength !== 1) invalid();
  const fields = readExactRecord(args, expectedKeys);
  assertActive(fields.runtimeQualification);
  if (bootstrapBindings === undefined || registrationState !== 'REGISTERED') forbidden();
  return fields;
}

function canonicalJson(value, ancestors = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON_STRINGIFY(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) invalid();
    return String(value);
  }
  if (typeof value !== 'object' || IS_PROXY(value) || ancestors.has(value)) invalid();
  ancestors.add(value);
  let encoded;
  if (ARRAY_IS_ARRAY(value)) {
    const keys = REFLECT_OWN_KEYS(value);
    if (keys.some((key) => key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key))) invalid();
    for (let index = 0; index < value.length; index += 1) {
      if (!OBJECT_HAS_OWN(value, String(index))) invalid();
    }
    encoded = `[${value.map((item) => canonicalJson(item, ancestors)).join(',')}]`;
  } else {
    const prototype = OBJECT_GET_PROTOTYPE_OF(value);
    if (prototype !== Object.prototype && prototype !== null) invalid();
    const keys = REFLECT_OWN_KEYS(value);
    if (keys.some((key) => typeof key !== 'string')) invalid();
    keys.sort();
    encoded = `{${keys.map((key) => {
      const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      if (
        descriptor === undefined
        || !OBJECT_HAS_OWN(descriptor, 'value')
        || descriptor.enumerable !== true
      ) invalid();
      return `${JSON_STRINGIFY(key)}:${canonicalJson(descriptor.value, ancestors)}`;
    }).join(',')}}`;
  }
  ancestors.delete(value);
  return encoded;
}

function digestJson(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function exactPolicy(value) {
  return canonicalJson(value) === canonicalJson(EXPECTED_POLICY);
}

function parseProviderTuple(providerContract) {

  const outer = readExactRecord(
    providerContract,
    ['status', 'value', 'diagnostics'],
    true,
  );

  if (
    outer.status !== 'PASS'
    || !ARRAY_IS_ARRAY(outer.diagnostics)
    || outer.diagnostics.length !== 0
    || !OBJECT_IS_FROZEN(outer.diagnostics)
  ) invalid();

  const value = readExactRecord(
    outer.value,
    ['qualification', 'providerContractDigest'],
    true,
  );

  if (!isNominalToken(value.qualification) || !DIGEST_PATTERN.test(value.providerContractDigest)) {
    invalid();
  }
  return value;
}

function parseContext(context) {
  const runId = readData(context, 'runId');
  const environmentDigest = readData(context, 'environmentDigest');
  if (
    typeof runId !== 'string'
    || !/^verify-[0-9a-f]{12}-[1-9][0-9]*-[1-9][0-9]*$/.test(runId)
    || typeof environmentDigest !== 'string'
    || !DIGEST_PATTERN.test(environmentDigest)
  ) invalid();
  return { runId, environmentDigest };
}

function formatUtc(milliseconds) {
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) invalid();
  const date = new DATE(milliseconds);
  const value = REFLECT_APPLY(DATE_TO_ISO_STRING, date, []);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) invalid();
  return value;
}

function makeSchedule(contextTuple, providerTuple, baseMilliseconds) {
  const baseUtc = formatUtc(baseMilliseconds);
  const plus800 = formatUtc(baseMilliseconds + 800);
  const schedule = OBJECT_FREEZE({
    schemaVersion: 'verification-dashboard-clock-schedule.v1',
    runId: contextTuple.runId,
    environmentDigest: contextTuple.environmentDigest,
    providerContractDigest: providerTuple.providerContractDigest,
    baseUtc,
    publishedAtByMutation: OBJECT_FREEZE([
      OBJECT_FREEZE({ mutationOrdinal: 4, value: baseUtc }),
      OBJECT_FREEZE({ mutationOrdinal: 5, value: baseUtc }),
      OBJECT_FREEZE({ mutationOrdinal: 8, value: plus800 }),
      OBJECT_FREEZE({ mutationOrdinal: 11, value: plus800 }),
      OBJECT_FREEZE({ mutationOrdinal: 16, value: plus800 }),
    ]),
  });
  return { baseUtc, schedule, scheduleDigest: digestJson(schedule) };
}

function makeClockRecord(values) {
  return frozenNullRecord(values);
}

function clockRecord(clock) {
  if (!isNominalToken(clock) || setHas(BLOCKED_CLOCKS, clock)) forbidden();
  const record = mapGet(CLOCK_RECORDS, clock);
  if (record === undefined) invalid();
  return record;
}

function replaceClockRecord(clock, expected, successorFields) {
  if (setHas(BLOCKED_CLOCKS, clock) || !OBJECT_IS(mapGet(CLOCK_RECORDS, clock), expected)) {
    forbidden();
  }
  const successor = makeClockRecord({
    ...expected,
    ...successorFields,
    version: expected.version + 1,
  });
  mapSet(CLOCK_RECORDS, clock, successor);
  return successor;
}

function blockClock(clock) {
  if (isNominalToken(clock)) {
    try {
      setAdd(BLOCKED_CLOCKS, clock);
    } catch {
      // The public result remains sanitized.
    }
  }
  return FORBIDDEN;
}

function invokeDispatcher(name, args) {
  const dispatcher = bootstrapBindings[name];
  if (typeof dispatcher !== 'function') forbidden();
  assertActive(args.runtimeQualification);
  return REFLECT_APPLY(
    dispatcher,
    bootstrapBindings.hubReceiver,
    [name === 'readFixtureClockPolicy'
      || name === 'authenticateSessionLineage'
      || name === 'deliverBrowserScenarioAutosaveCompletion'
      ? frozenNullRecord(args) : args],
  );
}

function readFacadeMethod(name) {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(bootstrapBindings.browserFacade, name);
  if (
    descriptor === undefined
    || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.value !== bootstrapBindings.browserFacadeMethods[name]
    || typeof descriptor.value !== 'function'
    || descriptor.enumerable !== true
    || descriptor.configurable !== false
    || descriptor.writable !== false
  ) forbidden();
  return descriptor.value;
}

function assertLocalPromise(value) {
  if (
    value === null
    || typeof value !== 'object'
    || IS_PROXY(value)
    || IS_PROMISE(value) !== true
    || OBJECT_GET_PROTOTYPE_OF(value) !== PROMISE_PROTOTYPE
    || REFLECT_OWN_KEYS(value).length !== 0
  ) forbidden();
  const constructorDescriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
    PROMISE_PROTOTYPE,
    'constructor',
  );
  if (
    constructorDescriptor === undefined
    || !OBJECT_HAS_OWN(constructorDescriptor, 'value')
    || constructorDescriptor.value !== Promise
    || constructorDescriptor.enumerable !== false
    || constructorDescriptor.configurable !== true
    || constructorDescriptor.writable !== true
  ) forbidden();
}

async function invokeFacade(record, methodName, args) {
  assertActive(record.runtimeQualification);
  const method = readFacadeMethod(methodName);
  let promise;
  try {
    promise = REFLECT_APPLY(method, bootstrapBindings.browserFacade, [args]);
  } catch {
    forbidden();
  }
  assertLocalPromise(promise);
  try {
    return await promise;
  } catch {
    forbidden();
  }
}

function validateOwnerProjection(value) {
  const fields = readExactRecord(value, ['$id', 'email', 'name', 'status'], true);
  if (
    typeof fields.$id !== 'string'
    || typeof fields.email !== 'string'
    || typeof fields.name !== 'string'
    || fields.status !== true
  ) invalid();
  return frozenNullRecord(fields);
}

function expectedTimestamp(record, ordinal) {
  const item = record.schedule.publishedAtByMutation.find(
    (entry) => entry.mutationOrdinal === ordinal,
  );
  if (item === undefined) invalid();
  return item.value;
}

function authenticateCompleteMutationReconciliationAggregate(record, clock) {
  const aggregate = mapGet(RECONCILIATION_AGGREGATES, clock);
  if (
    aggregate === undefined
    || aggregate.state !== 'RECONCILIATIONS_COMPLETE'
    || aggregate.cursor !== CLOCK_ORDINALS.length
    || aggregate.qualifications.length !== CLOCK_ORDINALS.length
  ) forbidden();
  for (let index = 0; index < CLOCK_ORDINALS.length; index += 1) {
    if (invokeDispatcher('authenticateMutationReconciliation', {
      runtimeQualification: record.runtimeQualification,
      clock,
      mutationOrdinal: CLOCK_ORDINALS[index],
      qualification: aggregate.qualifications[index],
    }) !== true) forbidden();
  }
  const authenticated = frozenNullRecord({
    state: 'RECONCILIATIONS_AUTHENTICATED',
    version: aggregate.version + 1,
    cursor: aggregate.cursor,
    qualifications: aggregate.qualifications,
  });
  mapSet(RECONCILIATION_AGGREGATES, clock, authenticated);
  return true;
}

const clockBridgeReceiver = OBJECT_FREEZE(OBJECT_CREATE(null));
let registrationState = 'EMPTY';
let bootstrapBindings;

function sanitizeOperationFailure(error, clock) {
  if (isNominalToken(clock)) blockClock(clock);
  return error instanceof InvalidOperation ? INVALID : FORBIDDEN;
}

function consumeExpectedStateResult(args) {
  let clock;
  try {
    const fields = startOperation(args, arguments.length, [
      'runtimeQualification',
      'expectedStateResult',
      'clock',
      'mutationOrdinal',
    ]);
    clock = fields.clock;
    const record = clockRecord(clock);
    const expectedOrdinal = CLOCK_ORDINALS[record.consumeCursor];
    const authentication = mapGet(
      AUTHENTIC_EXPECTED_RESULTS,
      fields.expectedStateResult,
    );
    if (
      record.lifecycle !== 'AUTHENTICATED'
      || fields.mutationOrdinal !== expectedOrdinal
      || authentication === undefined
      || authentication.clock !== clock
      || authentication.mutationOrdinal !== fields.mutationOrdinal
      || authentication.fixtureClockScheduleDigest !== record.scheduleDigest
      || authentication.consumed !== false
    ) forbidden();
    const consumed = frozenNullRecord({ ...authentication, consumed: true });
    mapSet(AUTHENTIC_EXPECTED_RESULTS, fields.expectedStateResult, consumed);
    replaceClockRecord(clock, record, { consumeCursor: record.consumeCursor + 1 });
    return authentication.publishedAt;
  } catch {
    if (isNominalToken(clock)) blockClock(clock);
    return false;
  }
}

function deliverMutationReconciliationQualification(args) {
  let clock;
  try {

    const fields = startOperation(args, arguments.length, [
      'runtimeQualification',
      'clock',
      'mutationOrdinal',
      'qualification',
    ]);

    clock = fields.clock;
    const record = clockRecord(clock);
    const aggregate = mapGet(RECONCILIATION_AGGREGATES, clock);

    if (
      aggregate === undefined
      || aggregate.state !== 'RECONCILIATIONS_ACCEPTING'
      || aggregate.cursor >= CLOCK_ORDINALS.length
      || fields.mutationOrdinal !== CLOCK_ORDINALS[aggregate.cursor]
      || !isNominalToken(fields.qualification)
      || aggregate.qualifications.includes(fields.qualification)
      || (aggregate.cursor < 2 && record.lifecycle !== 'AUTHENTICATED')
      || (aggregate.cursor >= 2 && record.lifecycle !== 'ADVANCING')
    ) forbidden();
    const authenticated = invokeDispatcher('authenticateMutationReconciliation', {
      runtimeQualification: fields.runtimeQualification,
      clock,
      mutationOrdinal: fields.mutationOrdinal,
      qualification: fields.qualification,
    });

    if (authenticated !== true) forbidden();
    const qualifications = OBJECT_FREEZE([
      ...aggregate.qualifications,
      fields.qualification,
    ]);
    const cursor = aggregate.cursor + 1;
    const successor = frozenNullRecord({
      state: cursor === CLOCK_ORDINALS.length
        ? 'RECONCILIATIONS_COMPLETE'
        : 'RECONCILIATIONS_ACCEPTING',
      version: aggregate.version + 1,
      cursor,
      qualifications,
    });
    mapSet(RECONCILIATION_AGGREGATES, clock, successor);
    replaceClockRecord(clock, record, {
      reconciliationOrdinals: OBJECT_FREEZE([
        ...record.reconciliationOrdinals,
        fields.mutationOrdinal,
      ]),
    });
    return true;
  } catch (error) {

    if (isNominalToken(clock)) blockClock(clock);
    return false;
  }
}

function readBootstrapHub() {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(globalThis, BOOTSTRAP_HUB);
  if (
    descriptor === undefined
    || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.enumerable !== false
    || descriptor.configurable !== true
    || descriptor.writable !== false
  ) {
    return undefined;
  }
  return descriptor.value;
}

function readHubDataFunction(hub, name) {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(hub, name);
  if (
    descriptor === undefined
    || !OBJECT_HAS_OWN(descriptor, 'value')
    || typeof descriptor.value !== 'function'
    || descriptor.enumerable !== true
    || descriptor.configurable !== false
    || descriptor.writable !== false
  ) {
    return undefined;
  }
  return descriptor.value;
}

function readHubReceiver(hub) {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(hub, 'bridgeReceiver');
  if (
    descriptor === undefined
    || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.enumerable !== true
    || descriptor.configurable !== false
    || descriptor.writable !== false
    || descriptor.value === null
    || typeof descriptor.value !== 'object'
    || OBJECT_GET_PROTOTYPE_OF(descriptor.value) !== null
    || OBJECT_IS_FROZEN(descriptor.value) !== true
  ) {
    return undefined;
  }
  return descriptor.value;
}

function readHubDataValue(hub, name) {
  const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(hub, name);
  if (
    descriptor === undefined
    || !OBJECT_HAS_OWN(descriptor, 'value')
    || descriptor.enumerable !== true
    || descriptor.configurable !== false
    || descriptor.writable !== false
  ) return undefined;
  return descriptor.value;
}

function createRegistration(implementation) {
  const registration = OBJECT_CREATE(null);
  OBJECT_DEFINE_PROPERTIES(registration, {
    receiver: {
      value: clockBridgeReceiver,
      enumerable: true,
      configurable: false,
      writable: false,
    },
    implementation: {
      value: implementation,
      enumerable: true,
      configurable: false,
      writable: false,
    },
    moduleUrl: {
      value: MODULE_URL,
      enumerable: true,
      configurable: false,
      writable: false,
    },
  });
  return OBJECT_FREEZE(registration);
}

function createBootstrapBindings(values) {
  const facadeNames = [
    'installPausedBeforeNavigation',
    'proveOwnerUiReady',
    'readOwnerAccount',
    'runForExactly800Milliseconds',
    'sealClock',
  ];
  const browserFacade = values.browserFacade;
  if (
    browserFacade === null
    || typeof browserFacade !== 'object'
    || IS_PROXY(browserFacade)
    || OBJECT_GET_PROTOTYPE_OF(browserFacade) !== null
    || OBJECT_IS_FROZEN(browserFacade) !== true
    || REFLECT_OWN_KEYS(browserFacade).length !== facadeNames.length
  ) forbidden();
  const browserFacadeMethods = OBJECT_CREATE(null);
  for (const name of facadeNames) {
    const descriptor = OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(browserFacade, name);
    if (
      descriptor === undefined
      || !OBJECT_HAS_OWN(descriptor, 'value')
      || typeof descriptor.value !== 'function'
      || descriptor.enumerable !== true
      || descriptor.configurable !== false
      || descriptor.writable !== false
    ) forbidden();
    browserFacadeMethods[name] = descriptor.value;
  }
  return frozenNullRecord({
    ...values,
    browserFacadeMethods: OBJECT_FREEZE(browserFacadeMethods),
  });
}

function terminallyBlockRegistration() {
  registrationState = 'BLOCKED';
  try {
    isAuthenticTestCloudBootstrapHub(undefined);
  } catch {
    // The public registrar remains a non-throwing primitive boundary.
  }
  return false;
}

export function prepareTestCloudFixtureClock(args) {
  let clock;
  let contextKey;
  try {

    const fields = startOperation(args, arguments.length, [
      'runtimeQualification',
      'context',
      'providerContract',
      'identityBindingsQualification',
    ]);

    if (!isNominalToken(fields.identityBindingsQualification)) invalid();

    const contextTuple = parseContext(fields.context);

    const providerTuple = parseProviderTuple(fields.providerContract);

    contextKey = fields.context;
    if (mapHas(CLOCK_RUN_BINDINGS, contextKey)) forbidden();

    const reservation = frozenNullRecord({
      version: 1,
      state: 'PREPARING',
      sessionIntentQualification: null,
      clock: null,
    });
    mapSet(CLOCK_RUN_BINDINGS, contextKey, reservation);

    if (invokeDispatcher('authenticateProviderQualification', {
      runtimeQualification: fields.runtimeQualification,
      context: fields.context,
      providerContractQualification: providerTuple.qualification,
      expectedEnvironmentDigest: contextTuple.environmentDigest,
      expectedProviderContractDigest: providerTuple.providerContractDigest,
    }) !== true) forbidden();

    const policyEnvelope = invokeDispatcher('readFixtureClockPolicy', {
      runtimeQualification: fields.runtimeQualification,
      context: fields.context,
      providerContractQualification: providerTuple.qualification,
    });
    const policyFields = readExactRecord(
      policyEnvelope,
      ['fixtureClockPolicy'],
      true,
    );

    if (!exactPolicy(policyFields.fixtureClockPolicy)) invalid();

    const sampledNow = REFLECT_APPLY(DATE_NOW, DATE, []);
    if (!Number.isSafeInteger(sampledNow) || sampledNow < 0) invalid();
    const scheduleTuple = makeSchedule(contextTuple, providerTuple, sampledNow);
    clock = makeToken();
    const record = makeClockRecord({
      version: 1,
      lifecycle: 'PREPARED',
      operationEpoch: 0,
      runtimeQualification: fields.runtimeQualification,
      context: fields.context,
      runId: contextTuple.runId,
      environmentDigest: contextTuple.environmentDigest,
      providerContractQualification: providerTuple.qualification,
      providerContractDigest: providerTuple.providerContractDigest,
      identityBindingsQualification: fields.identityBindingsQualification,
      sessionIntentQualification: null,
      fixtureClockPolicy: policyFields.fixtureClockPolicy,
      baseUtc: scheduleTuple.baseUtc,
      schedule: scheduleTuple.schedule,
      scheduleDigest: scheduleTuple.scheduleDigest,
      readCursor: 0,
      consumeCursor: 0,
      reconciliationOrdinals: OBJECT_FREEZE([]),
    });
    mapSet(CLOCK_RECORDS, clock, record);
    mapSet(RECONCILIATION_AGGREGATES, clock, frozenNullRecord({
      state: 'RECONCILIATIONS_ACCEPTING',
      version: 1,
      cursor: 0,
      qualifications: OBJECT_FREEZE([]),
    }));
    const qualifiedReservation = frozenNullRecord({
      version: 2,
      state: 'QUALIFIED',
      sessionIntentQualification: null,
      clock,
    });
    if (!OBJECT_IS(mapGet(CLOCK_RUN_BINDINGS, contextKey), reservation)) forbidden();
    mapSet(CLOCK_RUN_BINDINGS, contextKey, qualifiedReservation);
    return pass({
      clock,
      fixtureClockScheduleDigest: scheduleTuple.scheduleDigest,
    });
  } catch (error) {
    if (contextKey !== undefined && mapHas(CLOCK_RUN_BINDINGS, contextKey)) {
      try {
        mapSet(CLOCK_RUN_BINDINGS, contextKey, frozenNullRecord({
          version: 2,
          state: 'BLOCKED',
          sessionIntentQualification: null,
          clock: null,
        }));
      } catch {
        // Sanitized failure remains authoritative.
      }
    }
    return sanitizeOperationFailure(error, clock);
  }
}

export async function installTestCloudFixtureClock(args) {
  let clock;
  try {

    const fields = startOperation(args, arguments.length, [
      'runtimeQualification', 'clock',
    ]);
    clock = fields.clock;
    const record = clockRecord(clock);

    if (
      record.runtimeQualification !== fields.runtimeQualification
      || record.lifecycle !== 'PREPARED'
    ) forbidden();
    const pending = replaceClockRecord(clock, record, {
      lifecycle: 'INSTALLING',
      operationEpoch: record.operationEpoch + 1,
    });

    const result = await invokeFacade(
      pending,
      'installPausedBeforeNavigation',
      frozenNullRecord({ baseUtc: pending.baseUtc }),
    );

    assertActive(pending.runtimeQualification);
    if (!OBJECT_IS(clockRecord(clock), pending) || result !== true) forbidden();
    replaceClockRecord(clock, pending, { lifecycle: 'INSTALLED' });
    return pass({ clock });
  } catch (error) {

    return sanitizeOperationFailure(error, clock);
  }
}

export async function authenticateTestCloudFixtureClock(args) {
  let clock;
  try {

    const fields = startOperation(args, arguments.length, [
      'runtimeQualification', 'clock', 'sessionIntentQualification',
    ]);
    clock = fields.clock;
    if (!isNominalToken(fields.sessionIntentQualification)) invalid();
    const record = clockRecord(clock);

    if (
      record.runtimeQualification !== fields.runtimeQualification
      || record.lifecycle !== 'INSTALLED'
      || record.sessionIntentQualification !== null
    ) forbidden();
    const pending = replaceClockRecord(clock, record, {
      lifecycle: 'AUTHENTICATING',
      operationEpoch: record.operationEpoch + 1,
    });
    const ready = await invokeFacade(
      pending,
      'proveOwnerUiReady',
      frozenNullRecord(),
    );

    if (ready !== true || !OBJECT_IS(clockRecord(clock), pending)) forbidden();
    if (invokeDispatcher('authenticateSessionLineage', {
      runtimeQualification: pending.runtimeQualification,
      context: pending.context,
      identityBindingsQualification: pending.identityBindingsQualification,
      sessionIntentQualification: fields.sessionIntentQualification,
    }) !== true) forbidden();

    const account = await invokeFacade(
      pending,
      'readOwnerAccount',
      frozenNullRecord(),
    );
    const ownerProjection = validateOwnerProjection(account);

    if (!OBJECT_IS(clockRecord(clock), pending)) forbidden();
    if (invokeDispatcher('ownerAuthenticator', {
      runtimeQualification: pending.runtimeQualification,
      identityBindingsQualification: pending.identityBindingsQualification,
      observedOwnerProjection: ownerProjection,
      expectedEnvironmentDigest: pending.environmentDigest,
      expectedProviderContractDigest: pending.providerContractDigest,
    }) !== true) forbidden();

    if (!OBJECT_IS(clockRecord(clock), pending)) forbidden();
    replaceClockRecord(clock, pending, {
      lifecycle: 'AUTHENTICATED',
      sessionIntentQualification: fields.sessionIntentQualification,
    });
    return pass({ clock });
  } catch (error) {

    return sanitizeOperationFailure(error, clock);
  }
}

export function readTestCloudFixtureExpectedState(args) {
  let clock;
  try {

    const fields = startOperation(args, arguments.length, [
      'runtimeQualification', 'clock', 'mutationOrdinal',
    ]);
    clock = fields.clock;
    const record = clockRecord(clock);

    if (
      record.runtimeQualification !== fields.runtimeQualification
      || record.lifecycle !== 'AUTHENTICATED'
      || fields.mutationOrdinal !== CLOCK_ORDINALS[record.readCursor]
    ) forbidden();
    const publishedAt = expectedTimestamp(record, fields.mutationOrdinal);
    const result = pass({ mutationOrdinal: fields.mutationOrdinal, publishedAt });

    mapSet(AUTHENTIC_EXPECTED_RESULTS, result, frozenNullRecord({
      clock,
      runId: record.runId,
      mutationOrdinal: fields.mutationOrdinal,
      publishedAt,
      fixtureClockScheduleDigest: record.scheduleDigest,
      consumed: false,
    }));
    replaceClockRecord(clock, record, { readCursor: record.readCursor + 1 });

    if (invokeDispatcher('deliverTimestampBindingResult', {
      runtimeQualification: fields.runtimeQualification,
      expectedStateResult: result,
      clock,
      mutationOrdinal: fields.mutationOrdinal,
    }) !== true) forbidden();

    return result;
  } catch (error) {

    return sanitizeOperationFailure(error, clock);
  }
}

export async function advanceTestCloudFixtureClock(args) {
  let clock;
  try {
    const fields = startOperation(args, arguments.length, [
      'runtimeQualification', 'clock',
    ]);
    clock = fields.clock;
    const record = clockRecord(clock);
    const aggregate = mapGet(RECONCILIATION_AGGREGATES, clock);

    if (
      record.runtimeQualification !== fields.runtimeQualification
      || record.lifecycle !== 'AUTHENTICATED'
      || record.readCursor !== CLOCK_ORDINALS.length
      || record.consumeCursor !== CLOCK_ORDINALS.length
      || aggregate === undefined
      || aggregate.state !== 'RECONCILIATIONS_ACCEPTING'
      || aggregate.cursor !== 2
    ) forbidden();
    const authorizing = replaceClockRecord(clock, record, {
      lifecycle: 'AUTHORIZING_ADVANCE',
      operationEpoch: record.operationEpoch + 1,
    });
    if (invokeDispatcher('authenticateInitialProviderPrefix', {
      runtimeQualification: authorizing.runtimeQualification,
      context: authorizing.context,
      providerContractQualification: authorizing.providerContractQualification,
      identityBindingsQualification: authorizing.identityBindingsQualification,
      sessionIntentQualification: authorizing.sessionIntentQualification,
      clock,
    }) !== true) forbidden();
    if (!OBJECT_IS(clockRecord(clock), authorizing)) forbidden();
    const advancing = replaceClockRecord(clock, authorizing, {
      lifecycle: 'ADVANCING',
    });
    const payload = await invokeFacade(
      advancing,
      'runForExactly800Milliseconds',
      frozenNullRecord(),
    );

    const resultFields = readExactRecord(
      payload,
      ['advancedMilliseconds', 'autosaveCount'],
    );

    if (
      resultFields.advancedMilliseconds !== 800
      || resultFields.autosaveCount !== 1
    ) forbidden();
    assertActive(advancing.runtimeQualification);

    const current = clockRecord(clock);
    if (
      current.lifecycle !== 'ADVANCING'
      || current.operationEpoch !== advancing.operationEpoch
      || current.reconciliationOrdinals.length !== CLOCK_ORDINALS.length
    ) forbidden();

    authenticateCompleteMutationReconciliationAggregate(current, clock);

    const advanced = replaceClockRecord(clock, current, { lifecycle: 'ADVANCED' });
    if (invokeDispatcher('deliverBrowserScenarioAutosaveCompletion', {
      runtimeQualification: advanced.runtimeQualification,
      clock,
    }) !== true) forbidden();

    return pass({ clock });
  } catch (error) {

    return sanitizeOperationFailure(error, clock);
  }
}

export async function sealTestCloudFixtureClock(args) {
  let clock;
  try {
    const fields = startOperation(args, arguments.length, [
      'runtimeQualification', 'clock',
    ]);
    clock = fields.clock;
    const record = clockRecord(clock);
    const aggregate = mapGet(RECONCILIATION_AGGREGATES, clock);
    if (
      record.runtimeQualification !== fields.runtimeQualification
      || record.lifecycle !== 'ADVANCED'
      || record.readCursor !== CLOCK_ORDINALS.length
      || record.consumeCursor !== CLOCK_ORDINALS.length
      || aggregate === undefined
      || aggregate.state !== 'RECONCILIATIONS_AUTHENTICATED'
    ) forbidden();
    const pending = replaceClockRecord(clock, record, {
      lifecycle: 'SEALING',
      operationEpoch: record.operationEpoch + 1,
    });
    const result = await invokeFacade(pending, 'sealClock', frozenNullRecord());
    assertActive(pending.runtimeQualification);
    if (!OBJECT_IS(clockRecord(clock), pending) || result !== true) forbidden();
    replaceClockRecord(clock, pending, { lifecycle: 'SEALED' });
    return pass({ fixtureClockScheduleDigest: pending.scheduleDigest });
  } catch (error) {
    return sanitizeOperationFailure(error, clock);
  }
}

export function registerTestCloudFixtureClockBootstrap() {
  const exactArity = arguments.length === 0;
  const lifecycle = readTestCloudRuntimeLifecycle();
  const hub = readBootstrapHub();
  const authenticHub = isAuthenticTestCloudBootstrapHub(hub);

  if (
    exactArity !== true
    || lifecycle !== 'BOOTSTRAPPING'
    || authenticHub !== true
    || hub === undefined
    || registrationState !== 'EMPTY'
  ) {
    return terminallyBlockRegistration();
  }

  registrationState = 'REGISTERING';
  try {
    const hubReceiver = readHubReceiver(hub);
    const registerExpectedStateResultConsumer = readHubDataFunction(
      hub,
      'registerExpectedStateResultConsumer',
    );
    const registerClockReconciliationAggregateReceiver = readHubDataFunction(
      hub,
      'registerClockReconciliationAggregateReceiver',
    );
    const deliverTimestampBindingResult = readHubDataFunction(
      hub,
      'deliverTimestampBindingResult',
    );
    const deliverMutationReconciliationQualificationDispatcher = readHubDataFunction(
      hub,
      'deliverMutationReconciliationQualification',
    );
    const deliverBrowserScenarioAutosaveCompletion = readHubDataFunction(
      hub,
      'deliverBrowserScenarioAutosaveCompletion',
    );
    const authenticateProviderQualification = readHubDataFunction(
      hub,
      'authenticateProviderQualification',
    );
    const readFixtureClockPolicy = readHubDataFunction(
      hub,
      'readFixtureClockPolicy',
    );
    const authenticateInitialProviderPrefix = readHubDataFunction(
      hub,
      'authenticateInitialProviderPrefix',
    );
    const ownerAuthenticator = readHubDataFunction(hub, 'ownerAuthenticator');
    const authenticateSessionLineage = readHubDataFunction(
      hub,
      'authenticateSessionLineage',
    );
    const authenticateMutationReconciliation = readHubDataFunction(
      hub,
      'authenticateMutationReconciliation',
    );
    const constructExpectedStateForProviderMutation = readHubDataFunction(
      hub,
      'constructExpectedStateForProviderMutation',
    );
    const browserFacade = readHubDataValue(hub, 'browserFacade');

    if (
      hubReceiver === undefined
      || registerExpectedStateResultConsumer === undefined
      || registerClockReconciliationAggregateReceiver === undefined
      || deliverTimestampBindingResult === undefined
      || deliverMutationReconciliationQualificationDispatcher === undefined
      || deliverBrowserScenarioAutosaveCompletion === undefined
      || authenticateProviderQualification === undefined
      || readFixtureClockPolicy === undefined
      || authenticateInitialProviderPrefix === undefined
      || ownerAuthenticator === undefined
      || authenticateSessionLineage === undefined
      || authenticateMutationReconciliation === undefined
      || constructExpectedStateForProviderMutation === undefined
      || browserFacade === undefined
    ) {
      return terminallyBlockRegistration();
    }

    const resultConsumerRegistered = REFLECT_APPLY(
      registerExpectedStateResultConsumer,
      hubReceiver,
      [createRegistration(consumeExpectedStateResult)],
    );
    if (resultConsumerRegistered !== true) {
      return terminallyBlockRegistration();
    }

    const reconciliationReceiverRegistered = REFLECT_APPLY(
      registerClockReconciliationAggregateReceiver,
      hubReceiver,
      [createRegistration(deliverMutationReconciliationQualification)],
    );
    if (reconciliationReceiverRegistered !== true) {
      return terminallyBlockRegistration();
    }

    bootstrapBindings = createBootstrapBindings({
      hubReceiver,
      deliverTimestampBindingResult,
      deliverMutationReconciliationQualification:
        deliverMutationReconciliationQualificationDispatcher,
      deliverBrowserScenarioAutosaveCompletion,
      authenticateProviderQualification,
      readFixtureClockPolicy,
      authenticateInitialProviderPrefix,
      ownerAuthenticator,
      authenticateSessionLineage,
      authenticateMutationReconciliation,
      constructExpectedStateForProviderMutation,
      browserFacade,
    });
    registrationState = 'REGISTERED';
    return true;
  } catch {
    return terminallyBlockRegistration();
  }
}
