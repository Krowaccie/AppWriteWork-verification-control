import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { isTrustedControllerContext } from '../../../scripts/verification/controller-bundle.mjs';

const PROTOCOL_VERSION = 'verification-runner.v1';
const RUNNER_FUNCTION_ID = 'verification-runner-py';
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MAX_EXECUTION_RESPONSE_BODY_BYTES = 1024 * 1024;
const RECORD_KEYS = [
  'artifactId', 'bundleDigest', 'cleanupProtocolDigest', 'controllerArchiveDigest',
  'controllerRepository', 'controllerRevision', 'evidenceValidatorDigest',
  'materializedManifestDigest', 'protocolVersion', 'providerContractDigest',
  'requestSchemaDigest', 'responseSchemaDigest', 'scenarioSchemaDigest',
  'sourceRevision', 'timeoutMs', 'transcriptCorpusDigest',
];
const BOOTSTRAP_RECORD_KEYS = [
  'bootstrapBundleDigest', 'bootstrapDigest', 'cleanupDebt', 'controllerArchiveDigest',
  'controllerRevision', 'materializedManifestDigest', 'schemaVersion',
  'sourceRevision', 'status',
];

class TranscriptFailure extends Error {}
class QualificationTimeout extends Error {}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  try {
    if (utilTypes.isProxy(value)
        || Object.getPrototypeOf(value) !== Object.prototype
        || Object.getOwnPropertySymbols(value).length !== 0) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Reflect.ownKeys(descriptors).length === Object.keys(value).length
      && Object.values(descriptors).every((descriptor) => (
        Object.hasOwn(descriptor, 'value') && descriptor.enumerable === true
      ));
  } catch {
    return false;
  }
}

function hasExactKeys(value, keys) {
  return isPlainObject(value)
    && Reflect.ownKeys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function hasPromotionCapability(value) {
  if (value === null || typeof value !== 'object' || utilTypes.isProxy(value)) return false;
  try {
    return Reflect.ownKeys(value).some((key) => (
      typeof key === 'string' && /(promot|successor|write|update|setactive)/i.test(key)
    ));
  } catch {
    return false;
  }
}

function readClosedOwnData(value, keys, label) {
  if (value === null || typeof value !== 'object') {
    throw new TypeError(`${label} must be a closed object`);
  }
  let descriptors;
  let ownKeys;
  try {
    if (utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError(`${label} must have the ordinary object prototype`);
    }
    ownKeys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`${label} must be inspectable as a closed object`);
  }
  if (ownKeys.some((key) => typeof key !== 'string')
      || ownKeys.sort().join('\0') !== [...keys].sort().join('\0')) {
    throw new TypeError(`${label} has an unexpected capability shape`);
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      throw new TypeError(`${label}.${key} must be an enumerable own data property`);
    }
    Object.defineProperty(snapshot, key, {
      enumerable: true,
      value: descriptor.value,
      writable: false,
    });
  }
  return Object.freeze(snapshot);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pass(value) {
  return deepFreeze({ diagnostics: [], status: 'PASS', value });
}

function blocked(code, safeMessage) {
  return deepFreeze({ diagnostics: [{ code, retryable: false, safeMessage }], status: 'BLOCKED', value: null });
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('value is not closed JSON');
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestJson(value) {
  return digestBytes(new TextEncoder().encode(canonicalJson(value)));
}

function readScenarioCleanupProtocolDigest(bytes) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = JSON.parse(text);
    const digest = isPlainObject(parsed) ? parsed['x-cleanupProtocolDigest'] : null;
    return DIGEST_PATTERN.test(digest) ? digest : null;
  } catch {
    return null;
  }
}

function validateOuterShape(args) {
  const outer = readClosedOwnData(
    args,
    ['bootstrap', 'clock', 'controller', 'executionClient', 'runner'],
    'qualification arguments',
  );
  if (hasPromotionCapability(outer.executionClient)) {
    return { forbidden: true, value: null };
  }
  const controller = outer.controller;
  const executionClient = readClosedOwnData(
    outer.executionClient,
    ['createFunctionExecution'],
    'executionClient',
  );
  const clock = readClosedOwnData(
    outer.clock,
    ['clearTimeout', 'now', 'setTimeout'],
    'clock',
  );
  const runner = readClosedOwnData(
    outer.runner,
    ['deploymentId', 'functionId', 'revision'],
    'runner',
  );
  const bootstrapOuter = readClosedOwnData(
    outer.bootstrap,
    [
      'bootstrapDigest', 'bootstrapRecord', 'evidenceValidatorJson',
      'extractedBundleRoot', 'providerContractJson', 'record', 'scenarioSchemaJson',
      'transcriptCorpusJson', 'verifiedBundleDigest',
    ],
    'bootstrap',
  );
  const record = readClosedOwnData(bootstrapOuter.record, RECORD_KEYS, 'bootstrap.record');
  const bootstrapRecord = readClosedOwnData(
    bootstrapOuter.bootstrapRecord,
    BOOTSTRAP_RECORD_KEYS,
    'bootstrap.bootstrapRecord',
  );

  if (!isTrustedControllerContext(controller)) throw new TypeError('controller is not authentic');
  if (typeof executionClient.createFunctionExecution !== 'function') {
    throw new TypeError('executionClient must expose only createFunctionExecution');
  }
  if (typeof clock.clearTimeout !== 'function'
      || typeof clock.now !== 'function'
      || typeof clock.setTimeout !== 'function') {
    throw new TypeError('clock must expose only now, setTimeout, and clearTimeout');
  }
  if (runner.functionId !== RUNNER_FUNCTION_ID
      || typeof runner.deploymentId !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(runner.deploymentId)
      || typeof runner.revision !== 'string'
      || !SHA_PATTERN.test(runner.revision)) {
    throw new TypeError('runner identity is invalid');
  }
  if (typeof bootstrapOuter.bootstrapDigest !== 'string'
      || !DIGEST_PATTERN.test(bootstrapOuter.bootstrapDigest)
      || typeof bootstrapOuter.extractedBundleRoot !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/.test(bootstrapOuter.extractedBundleRoot)
      || bootstrapOuter.extractedBundleRoot.split('/').some((part) => part === '' || part === '.' || part === '..')
      || typeof bootstrapOuter.evidenceValidatorJson !== 'string'
      || Buffer.byteLength(bootstrapOuter.evidenceValidatorJson, 'utf8') > 1024 * 1024
      || typeof bootstrapOuter.providerContractJson !== 'string'
      || Buffer.byteLength(bootstrapOuter.providerContractJson, 'utf8') > 1024 * 1024
      || typeof bootstrapOuter.scenarioSchemaJson !== 'string'
      || Buffer.byteLength(bootstrapOuter.scenarioSchemaJson, 'utf8') > 1024 * 1024
      || typeof bootstrapOuter.transcriptCorpusJson !== 'string'
      || Buffer.byteLength(bootstrapOuter.transcriptCorpusJson, 'utf8') > 1024 * 1024
      || typeof bootstrapOuter.verifiedBundleDigest !== 'string'
      || !DIGEST_PATTERN.test(bootstrapOuter.verifiedBundleDigest)) {
    throw new TypeError('bootstrap is invalid');
  }
  const bootstrap = Object.freeze({
    bootstrapDigest: bootstrapOuter.bootstrapDigest,
    bootstrapRecord,
    evidenceValidatorJson: bootstrapOuter.evidenceValidatorJson,
    extractedBundleRoot: bootstrapOuter.extractedBundleRoot,
    providerContractJson: bootstrapOuter.providerContractJson,
    record,
    scenarioSchemaJson: bootstrapOuter.scenarioSchemaJson,
    transcriptCorpusJson: bootstrapOuter.transcriptCorpusJson,
    verifiedBundleDigest: bootstrapOuter.verifiedBundleDigest,
  });
  return {
    forbidden: false,
    value: Object.freeze({ bootstrap, clock, controller, executionClient, runner }),
  };
}

function validRecord(record) {
  return hasExactKeys(record, RECORD_KEYS)
    && typeof record.artifactId === 'string' && /^[1-9][0-9]{0,19}$/.test(record.artifactId)
    && typeof record.bundleDigest === 'string' && DIGEST_PATTERN.test(record.bundleDigest)
    && typeof record.cleanupProtocolDigest === 'string' && DIGEST_PATTERN.test(record.cleanupProtocolDigest)
    && typeof record.controllerArchiveDigest === 'string'
    && DIGEST_PATTERN.test(record.controllerArchiveDigest)
    && typeof record.controllerRepository === 'string' && record.controllerRepository.length > 0
    && typeof record.controllerRevision === 'string' && SHA_PATTERN.test(record.controllerRevision)
    && typeof record.evidenceValidatorDigest === 'string' && DIGEST_PATTERN.test(record.evidenceValidatorDigest)
    && typeof record.materializedManifestDigest === 'string'
    && DIGEST_PATTERN.test(record.materializedManifestDigest)
    && typeof record.protocolVersion === 'string'
    && typeof record.providerContractDigest === 'string' && DIGEST_PATTERN.test(record.providerContractDigest)
    && typeof record.requestSchemaDigest === 'string' && DIGEST_PATTERN.test(record.requestSchemaDigest)
    && typeof record.responseSchemaDigest === 'string' && DIGEST_PATTERN.test(record.responseSchemaDigest)
    && typeof record.scenarioSchemaDigest === 'string' && DIGEST_PATTERN.test(record.scenarioSchemaDigest)
    && typeof record.sourceRevision === 'string' && SHA_PATTERN.test(record.sourceRevision)
    && Number.isInteger(record.timeoutMs) && record.timeoutMs > 0 && record.timeoutMs <= 300_000
    && typeof record.transcriptCorpusDigest === 'string'
    && DIGEST_PATTERN.test(record.transcriptCorpusDigest);
}

function validBootstrapRecord(record, pointer, controller, bootstrapDigest) {
  return hasExactKeys(record, BOOTSTRAP_RECORD_KEYS)
    && record.schemaVersion === 'active-bootstrap-record.v1'
    && record.controllerRevision === controller.controllerBundleSha
    && record.controllerRevision === pointer.controllerRevision
    && record.sourceRevision === pointer.sourceRevision
    && record.materializedManifestDigest === pointer.materializedManifestDigest
    && record.controllerArchiveDigest === controller.controllerBundleDigest
    && record.controllerArchiveDigest === pointer.controllerArchiveDigest
    && record.bootstrapDigest === bootstrapDigest
    && record.bootstrapBundleDigest === pointer.bundleDigest
    && record.bootstrapDigest !== record.bootstrapBundleDigest
    && record.status === 'PASS'
    && record.cleanupDebt === false;
}

function parseJsonBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) throw new TranscriptFailure();
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(value);
    const parsed = JSON.parse(text);
    if (text !== canonicalJson(parsed)) throw new TranscriptFailure();
    return parsed;
  } catch (error) {
    if (error instanceof TranscriptFailure) throw error;
    throw new TranscriptFailure();
  }
}

function validateValidator(value) {
  return hasExactKeys(value, ['executionStatus', 'protocolVersion', 'schemaVersion', 'transportStatus'])
    && value.schemaVersion === 'verification-runner-evidence-validator.v1'
    && value.protocolVersion === PROTOCOL_VERSION
    && value.executionStatus === 'completed'
    && value.transportStatus === 201;
}

function validateScenario(value) {
  if (!hasExactKeys(value, ['expected', 'id', 'polarity', 'request'])
      || typeof value.id !== 'string'
      || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value.id)
      || !['negative', 'positive'].includes(value.polarity)
      || !isPlainObject(value.request)
      || !hasExactKeys(value.request, [
        'environmentDigest', 'leaseToken', 'parameters', 'protocolVersion', 'runId', 'scenarioId',
      ])
      || value.request.protocolVersion !== PROTOCOL_VERSION
      || !DIGEST_PATTERN.test(value.request.environmentDigest)
      || typeof value.request.leaseToken !== 'string'
      || !/^[A-Za-z0-9_-]{43,256}$/.test(value.request.leaseToken)
      || typeof value.request.runId !== 'string' || value.request.runId.length === 0
      || !isPlainObject(value.request.parameters)
      || (value.polarity === 'positive' && value.request.scenarioId !== 'health')
      || (value.polarity === 'negative' && value.request.scenarioId !== 'future')
      || !hasExactKeys(value.expected, ['responseBody', 'responseStatusCode'])
      || !Number.isInteger(value.expected.responseStatusCode)
      || value.expected.responseStatusCode < 100 || value.expected.responseStatusCode > 599) {
    return false;
  }
  try {
    canonicalJson(value.request);
    canonicalJson(value.expected.responseBody);
    return true;
  } catch {
    return false;
  }
}

function validateCorpus(value) {
  if (!hasExactKeys(value, ['protocolVersion', 'scenarios', 'schemaVersion'])
      || value.schemaVersion !== 'verification-runner-transcripts.v1'
      || value.protocolVersion !== PROTOCOL_VERSION
      || !Array.isArray(value.scenarios)
      || value.scenarios.length === 0
      || !value.scenarios.every(validateScenario)) return false;
  const ids = value.scenarios.map((scenario) => scenario.id);
  return new Set(ids).size === ids.length
    && value.scenarios.some((scenario) => scenario.polarity === 'positive')
    && value.scenarios.some((scenario) => scenario.polarity === 'negative');
}

function validateMappedRunnerEnvelope(body, scenario, runner) {
  if (!isPlainObject(body)
      || body.protocolVersion !== PROTOCOL_VERSION
      || body.runId !== scenario.request.runId
      || !Number.isFinite(body.durationMs) || body.durationMs < 0) return false;
  if (scenario.polarity === 'positive') {
    return hasExactKeys(body, ['data', 'durationMs', 'protocolVersion', 'runId', 'scenarioId', 'status'])
      && body.scenarioId === 'health'
      && body.status === 'passed'
      && hasExactKeys(body.data, ['ready', 'runnerRevision'])
      && body.data.ready === true
      && body.data.runnerRevision === runner.revision;
  }
  return hasExactKeys(body, ['durationMs', 'error', 'protocolVersion', 'runId', 'scenarioId', 'status'])
    && body.scenarioId === 'invalid'
    && body.status === 'failed'
    && hasExactKeys(body.error, ['code', 'retryable', 'safeMessage'])
    && body.error.code === 'unknown_scenario'
    && body.error.retryable === false
    && typeof body.error.safeMessage === 'string' && body.error.safeMessage.length > 0;
}

function validateExecutionResult(result, scenario, validator, runner) {
  if (!hasExactKeys(result, ['diagnostics', 'status', 'value'])
      || result.status !== 'PASS'
      || !Array.isArray(result.diagnostics) || result.diagnostics.length !== 0
      || !hasExactKeys(result.value, ['execution', 'transportStatus'])
      || result.value.transportStatus !== validator.transportStatus
      || !hasExactKeys(result.value.execution, [
        'executionId', 'responseBody', 'responseStatusCode', 'status',
      ])) throw new TranscriptFailure();
  const execution = result.value.execution;
  if (typeof execution.executionId !== 'string' || execution.executionId.length === 0
      || execution.status !== validator.executionStatus
      || execution.responseStatusCode !== scenario.expected.responseStatusCode
      || typeof execution.responseBody !== 'string') throw new TranscriptFailure();
  if (execution.responseBody.length > MAX_EXECUTION_RESPONSE_BODY_BYTES
      || Buffer.byteLength(execution.responseBody, 'utf8') > MAX_EXECUTION_RESPONSE_BODY_BYTES) {
    throw new TranscriptFailure();
  }
  let responseBody;
  try {
    responseBody = JSON.parse(execution.responseBody);
  } catch {
    throw new TranscriptFailure();
  }
  if (!validateMappedRunnerEnvelope(responseBody, scenario, runner)
      || canonicalJson(responseBody) !== canonicalJson(scenario.expected.responseBody)) {
    throw new TranscriptFailure();
  }
  return {
    id: scenario.id,
    polarity: scenario.polarity,
    responseBodyDigest: digestJson(responseBody),
    responseStatusCode: execution.responseStatusCode,
    transportStatus: result.value.transportStatus,
  };
}

function ensureActive(session) {
  if (!session.active) throw new QualificationTimeout();
}

function readClock(clock) {
  let value;
  try {
    value = clock.now();
  } catch {
    throw new QualificationTimeout();
  }
  if (!Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000) {
    throw new QualificationTimeout();
  }
  return value;
}

function ensureBeforeDeadline(context, session, startedAt, deadline) {
  ensureActive(session);
  const now = readClock(context.clock);
  if (now < startedAt || now >= deadline) {
    session.active = false;
    throw new QualificationTimeout();
  }
}

async function executeCorpus(context, corpus, validator, session, startedAt, deadline) {
  const evidence = [];
  for (const scenario of [...corpus.scenarios]
    .sort((left, right) => ordinalCompare(left.id, right.id))) {
    ensureBeforeDeadline(context, session, startedAt, deadline);
    let result;
    try {
      result = await context.executionClient.createFunctionExecution({
        body: { async: false, body: canonicalJson(scenario.request) },
        deploymentId: context.runner.deploymentId,
        functionId: RUNNER_FUNCTION_ID,
      });
    } catch {
      throw new QualificationTimeout();
    }
    ensureBeforeDeadline(context, session, startedAt, deadline);
    evidence.push(validateExecutionResult(result, scenario, validator, context.runner));
  }
  return evidence;
}

function readTrustedInputs(context, session) {
  ensureActive(session);
  const transcriptBytes = new TextEncoder().encode(context.bootstrap.transcriptCorpusJson);
  const validatorBytes = new TextEncoder().encode(context.bootstrap.evidenceValidatorJson);
  const scenarioBytes = new TextEncoder().encode(context.bootstrap.scenarioSchemaJson);
  const providerContractBytes = new TextEncoder().encode(context.bootstrap.providerContractJson);
  if (digestBytes(transcriptBytes) !== context.bootstrap.record.transcriptCorpusDigest
      || digestBytes(validatorBytes) !== context.bootstrap.record.evidenceValidatorDigest
      || digestBytes(scenarioBytes) !== context.bootstrap.record.scenarioSchemaDigest
      || digestBytes(providerContractBytes) !== context.bootstrap.record.providerContractDigest
      || readScenarioCleanupProtocolDigest(scenarioBytes) !== context.bootstrap.record.cleanupProtocolDigest) {
    const error = new Error();
    error.code = 'BOOTSTRAP_DIGEST_MISMATCH';
    throw error;
  }
  const corpus = parseJsonBytes(transcriptBytes);
  const validator = parseJsonBytes(validatorBytes);
  if (!validateCorpus(corpus) || !validateValidator(validator)) throw new TranscriptFailure();
  return { corpus, validator };
}

export async function qualifyRunner(args) {
  const captured = validateOuterShape(args);
  if (captured.forbidden) {
    return blocked('BOOTSTRAP_PROMOTION_FORBIDDEN', 'Promotion capability is forbidden during qualification.');
  }
  const context = captured.value;
  const { record } = context.bootstrap;
  if (!validRecord(record)) return blocked('BOOTSTRAP_RECORD_INVALID', 'Bootstrap record is invalid.');
  if (record.controllerRepository !== context.controller.controllerRepository) {
    return blocked(
      'BOOTSTRAP_REPOSITORY_MISMATCH',
      'Bootstrap record is outside the trusted controller repository.',
    );
  }
  if (record.protocolVersion !== PROTOCOL_VERSION) {
    return blocked('BOOTSTRAP_PROTOCOL_MISMATCH', 'Bootstrap protocol is not supported.');
  }
  if (context.bootstrap.bootstrapDigest !== digestJson(record)
      || context.bootstrap.bootstrapDigest === record.bundleDigest
      || context.bootstrap.verifiedBundleDigest !== record.bundleDigest) {
    return blocked('BOOTSTRAP_DIGEST_MISMATCH', 'Bootstrap bundle digest does not match its record.');
  }
  if (!validBootstrapRecord(
    context.bootstrap.bootstrapRecord,
    record,
    context.controller,
    context.bootstrap.bootstrapDigest,
  )) {
    return blocked('BOOTSTRAP_RECORD_INVALID', 'Bootstrap identity projection is invalid.');
  }
  if (context.runner.revision === record.sourceRevision) {
    return blocked('BOOTSTRAP_SELF_REFERENCE', 'Candidate runner must use a different revision than its bootstrap.');
  }
  let startedAt;
  try {
    startedAt = readClock(context.clock);
  } catch {
    return blocked('BOOTSTRAP_TIMEOUT', 'Runner qualification did not finish within the trusted timeout.');
  }
  const deadline = startedAt + record.timeoutMs;
  if (!Number.isSafeInteger(deadline) || deadline > 8_640_000_000_000_000) {
    return blocked('BOOTSTRAP_TIMEOUT', 'Runner qualification did not finish within the trusted timeout.');
  }
  const session = { active: true };
  let timer;
  const timeout = new Promise((_, reject) => {
    try {
      timer = context.clock.setTimeout(() => {
        session.active = false;
        reject(new QualificationTimeout());
      }, record.timeoutMs);
    } catch {
      session.active = false;
      reject(new QualificationTimeout());
    }
  });
  try {
    const evidence = await Promise.race([
      (async () => {
        const { corpus, validator } = readTrustedInputs(context, session);
        const mappedEvidence = await executeCorpus(
          context,
          corpus,
          validator,
          session,
          startedAt,
          deadline,
        );
        ensureBeforeDeadline(context, session, startedAt, deadline);
        return { corpus, mappedEvidence };
      })(),
      timeout,
    ]);
    const positiveScenarioIds = evidence.corpus.scenarios
      .filter((scenario) => scenario.polarity === 'positive')
      .map((scenario) => scenario.id).sort(ordinalCompare);
    const negativeScenarioIds = evidence.corpus.scenarios
      .filter((scenario) => scenario.polarity === 'negative')
      .map((scenario) => scenario.id).sort(ordinalCompare);
    return pass({
      evidenceDigest: digestJson({
        bootstrapDigest: context.bootstrap.bootstrapDigest,
        bootstrapBundleDigest: record.bundleDigest,
        controllerRevision: context.controller.controllerBundleSha,
        deploymentId: context.runner.deploymentId,
        evidence: evidence.mappedEvidence,
        runnerRevision: context.runner.revision,
        sourceRevision: record.sourceRevision,
      }),
      bootstrapBundleDigest: record.bundleDigest,
      bootstrapDigest: context.bootstrap.bootstrapDigest,
      cleanupDebt: false,
      controllerRevision: context.controller.controllerBundleSha,
      deploymentId: context.runner.deploymentId,
      negativeScenarioIds,
      positiveScenarioIds,
      qualified: true,
      runnerRevision: context.runner.revision,
      schemaVersion: 'runner-qualification.v1',
      sourceRevision: record.sourceRevision,
      status: 'PASS',
    });
  } catch (error) {
    if (error instanceof QualificationTimeout) {
      return blocked('BOOTSTRAP_TIMEOUT', 'Runner qualification did not finish within the trusted timeout.');
    }
    if (error?.code === 'BOOTSTRAP_DIGEST_MISMATCH') {
      return blocked('BOOTSTRAP_DIGEST_MISMATCH', 'Trusted qualification input digest mismatch.');
    }
    return blocked('BOOTSTRAP_TRANSCRIPT_FAILED', 'Runner response did not match the trusted transcript corpus.');
  } finally {
    session.active = false;
    if (timer !== undefined) {
      try {
        context.clock.clearTimeout(timer);
      } catch {
        // Cleanup failures are never allowed to replace the safe qualification result.
      }
    }
  }
}
