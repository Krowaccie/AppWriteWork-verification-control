import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

const SCENARIO_IDS = [
  'public-smoke',
  'auth',
  'project-lifecycle',
  'graph-editor',
  'runtime',
  'sharing-permissions',
];
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const FULL_SHA = /^[0-9a-f]{40}$/;
const MAX_TIMEOUT_MS = 300_000;
const STDERR_LIMIT_BYTES = 4_096;
const STDOUT_LIMIT_BYTES = 65_536;
const FACADE_ARGUMENT_KEYS = ['launcher', 'scenarioDrivers'];
const LAUNCHER_KEYS = ['runPlaywrightScenario'];
const RUN_ARGUMENT_KEYS = ['controllerBinding', 'scenarioId', 'timeoutMs'];
const CONTROLLER_BINDING_KEYS = [
  'controllerBundleDigest',
  'controllerRevision',
  'playwrightImageDigest',
  'scenarioInventoryDigest',
];
const TRANSCRIPT_KEYS = ['exitCode', 'stderr', 'stdout', 'timedOut'];
const RESULT_KEYS = ['scenarioId', 'schemaVersion', 'status'];
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER_GETTER =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'buffer').get;
const TYPED_ARRAY_BYTE_LENGTH_GETTER =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength').get;
const TYPED_ARRAY_BYTE_OFFSET_GETTER =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteOffset').get;
const ARRAY_BUFFER_BYTE_LENGTH_GETTER =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const ARRAY_BUFFER_MAX_BYTE_LENGTH_GETTER =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'maxByteLength').get;
const ARRAY_BUFFER_RESIZABLE_GETTER =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable').get;

export const testCloudScenarioInventory = Object.freeze([...SCENARIO_IDS]);
export const testCloudScenarioInventoryDigest = `sha256:${createHash('sha256')
  .update(JSON.stringify(testCloudScenarioInventory))
  .digest('hex')}`;

function failure(code, ErrorType = TypeError) {
  const error = new ErrorType('Test-cloud Playwright facade rejected unsafe input.');
  error.code = code;
  return error;
}

function exactDataObject(value, expectedKeys, { ordered = false } = {}) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || utilTypes.isProxy(value)
    || (Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null)
    || Object.getOwnPropertySymbols(value).length !== 0
  ) return false;
  const names = Object.getOwnPropertyNames(value);
  const compared = ordered ? names : [...names].sort();
  const expected = ordered ? expectedKeys : [...expectedKeys].sort();
  if (
    compared.length !== expected.length
    || compared.some((name, index) => name !== expected[index])
  ) return false;
  return names.every((name) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return descriptor !== undefined && Object.hasOwn(descriptor, 'value');
  });
}

function dataValue(value, key) {
  return Object.getOwnPropertyDescriptor(value, key).value;
}

function frozenRecord(entries) {
  return Object.freeze(Object.assign(Object.create(null), entries));
}

function snapshotFixedBytes(value, minimum, maximum) {
  if (
    !(value instanceof Uint8Array)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Uint8Array.prototype
  ) return null;
  try {
    const buffer = Reflect.apply(TYPED_ARRAY_BUFFER_GETTER, value, []);
    const byteLength = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH_GETTER, value, []);
    const byteOffset = Reflect.apply(TYPED_ARRAY_BYTE_OFFSET_GETTER, value, []);
    if (Object.getPrototypeOf(buffer) !== ArrayBuffer.prototype) return null;
    const backingByteLength = Reflect.apply(
      ARRAY_BUFFER_BYTE_LENGTH_GETTER,
      buffer,
      [],
    );
    const maxByteLength = Reflect.apply(
      ARRAY_BUFFER_MAX_BYTE_LENGTH_GETTER,
      buffer,
      [],
    );
    const resizable = Reflect.apply(ARRAY_BUFFER_RESIZABLE_GETTER, buffer, []);
    if (
      resizable !== false
      || maxByteLength !== backingByteLength
      || byteLength < minimum
      || byteLength > maximum
      || byteOffset + byteLength > backingByteLength
    ) return null;
    const source = new Uint8Array(buffer, byteOffset, byteLength);
    const snapshot = new Uint8Array(byteLength);
    for (let index = 0; index < byteLength; index += 1) {
      snapshot[index] = source[index];
    }
    return snapshot;
  } catch {
    return null;
  }
}

function validateScenarioDrivers(value) {
  if (
    !exactDataObject(value, SCENARIO_IDS, { ordered: true })
    || !Object.isFrozen(value)
  ) {
    throw failure('TEST_CLOUD_PLAYWRIGHT_FACADE_INVALID');
  }
  const drivers = Object.create(null);
  const identities = new Set();
  for (const scenarioId of SCENARIO_IDS) {
    const driver = dataValue(value, scenarioId);
    if (typeof driver !== 'function' || utilTypes.isProxy(driver) || identities.has(driver)) {
      throw failure('TEST_CLOUD_PLAYWRIGHT_FACADE_INVALID');
    }
    identities.add(driver);
    drivers[scenarioId] = driver;
  }
  return Object.freeze(drivers);
}

function validateLauncher(value) {
  if (!exactDataObject(value, LAUNCHER_KEYS) || !Object.isFrozen(value)) {
    throw failure('TEST_CLOUD_PLAYWRIGHT_FACADE_INVALID');
  }
  const runPlaywrightScenario = dataValue(value, 'runPlaywrightScenario');
  if (typeof runPlaywrightScenario !== 'function' || utilTypes.isProxy(runPlaywrightScenario)) {
    throw failure('TEST_CLOUD_PLAYWRIGHT_FACADE_INVALID');
  }
  return frozenRecord({ runPlaywrightScenario });
}

function snapshotControllerBinding(value) {
  if (!exactDataObject(value, CONTROLLER_BINDING_KEYS)) {
    throw failure('TEST_CLOUD_PLAYWRIGHT_REQUEST_INVALID');
  }
  const binding = frozenRecord({
    controllerBundleDigest: dataValue(value, 'controllerBundleDigest'),
    controllerRevision: dataValue(value, 'controllerRevision'),
    playwrightImageDigest: dataValue(value, 'playwrightImageDigest'),
    scenarioInventoryDigest: dataValue(value, 'scenarioInventoryDigest'),
  });
  if (
    typeof binding.controllerBundleDigest !== 'string'
    || !DIGEST.test(binding.controllerBundleDigest)
    || typeof binding.controllerRevision !== 'string'
    || !FULL_SHA.test(binding.controllerRevision)
    || typeof binding.playwrightImageDigest !== 'string'
    || !DIGEST.test(binding.playwrightImageDigest)
    || typeof binding.scenarioInventoryDigest !== 'string'
    || binding.scenarioInventoryDigest !== testCloudScenarioInventoryDigest
  ) throw failure('TEST_CLOUD_PLAYWRIGHT_REQUEST_INVALID');
  return binding;
}

function parseTranscript(value, scenarioId) {
  if (!exactDataObject(value, TRANSCRIPT_KEYS)) {
    throw failure('TEST_CLOUD_PLAYWRIGHT_TRANSCRIPT_INVALID', Error);
  }
  const exitCode = dataValue(value, 'exitCode');
  const stderr = dataValue(value, 'stderr');
  const stdout = dataValue(value, 'stdout');
  const timedOut = dataValue(value, 'timedOut');
  const stderrSnapshot = snapshotFixedBytes(stderr, 0, STDERR_LIMIT_BYTES);
  const stdoutSnapshot = snapshotFixedBytes(stdout, 1, STDOUT_LIMIT_BYTES);
  if (
    exitCode !== 0
    || timedOut !== false
    || stderrSnapshot === null
    || stderrSnapshot.byteLength !== 0
    || stdoutSnapshot === null
  ) throw failure('TEST_CLOUD_PLAYWRIGHT_TRANSCRIPT_INVALID', Error);

  let parsed;
  try {
    parsed = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(stdoutSnapshot),
    );
  } catch {
    throw failure('TEST_CLOUD_PLAYWRIGHT_TRANSCRIPT_INVALID', Error);
  }
  if (
    !exactDataObject(parsed, RESULT_KEYS)
    || dataValue(parsed, 'schemaVersion') !== 'test-cloud-playwright-scenario-result.v1'
    || dataValue(parsed, 'scenarioId') !== scenarioId
    || !['PASS', 'FAIL'].includes(dataValue(parsed, 'status'))
  ) throw failure('TEST_CLOUD_PLAYWRIGHT_TRANSCRIPT_INVALID', Error);

  const result = frozenRecord({
    schemaVersion: dataValue(parsed, 'schemaVersion'),
    scenarioId: dataValue(parsed, 'scenarioId'),
    status: dataValue(parsed, 'status'),
  });
  const canonicalBytes = new TextEncoder().encode(JSON.stringify(result));
  if (
    canonicalBytes.byteLength !== stdoutSnapshot.byteLength
    || canonicalBytes.some((byte, index) => byte !== stdoutSnapshot[index])
  ) throw failure('TEST_CLOUD_PLAYWRIGHT_TRANSCRIPT_INVALID', Error);
  return result;
}

export function createTestCloudPlaywrightFacade(args) {
  if (!exactDataObject(args, FACADE_ARGUMENT_KEYS)) {
    throw failure('TEST_CLOUD_PLAYWRIGHT_FACADE_INVALID');
  }
  const scenarioDrivers = validateScenarioDrivers(dataValue(args, 'scenarioDrivers'));
  const launcher = validateLauncher(dataValue(args, 'launcher'));

  async function runExactScenario(runArgs) {
    if (!exactDataObject(runArgs, RUN_ARGUMENT_KEYS)) {
      throw failure('TEST_CLOUD_PLAYWRIGHT_REQUEST_INVALID');
    }
    const scenarioId = dataValue(runArgs, 'scenarioId');
    const timeoutMs = dataValue(runArgs, 'timeoutMs');
    if (
      !SCENARIO_IDS.includes(scenarioId)
      || !Number.isSafeInteger(timeoutMs)
      || timeoutMs < 1
      || timeoutMs > MAX_TIMEOUT_MS
    ) throw failure('TEST_CLOUD_PLAYWRIGHT_REQUEST_INVALID');
    const controllerBinding = snapshotControllerBinding(
      dataValue(runArgs, 'controllerBinding'),
    );
    const request = frozenRecord({
      controllerBinding,
      scenarioDriver: scenarioDrivers[scenarioId],
      scenarioId,
      scenarioInventoryDigest: testCloudScenarioInventoryDigest,
      shell: false,
      stderrLimitBytes: STDERR_LIMIT_BYTES,
      stdoutLimitBytes: STDOUT_LIMIT_BYTES,
      timeoutMs,
    });
    const transcript = await Reflect.apply(
      launcher.runPlaywrightScenario,
      undefined,
      [request],
    );
    return parseTranscript(transcript, scenarioId);
  }

  return frozenRecord({ runExactScenario });
}
