import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from './canonical-json.mjs';
import { consumeRunnerRequest } from './test-cloud-control-store.mjs';
import { isAuthenticTestEnvironmentContext } from './test-cloud-environment.mjs';
import {
  CLEANUP_PROTOCOL_DIGEST,
  QUALIFIED_CLEANUP_PROTOCOL,
  parseCleanupStepResponse,
  validateCleanupFence,
} from './test-cloud-cleanup-protocol.mjs';

export const RUNNER_PROTOCOL_VERSION = 'verification-runner.v1';
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
const protocolRoot = fileURLToPath(new URL('../../src/functions/verification-runner-py/protocol/', import.meta.url));
const readSchema = (name) => JSON.parse(readFileSync(`${protocolRoot}/${name}`, 'utf8'));
const requestSchema = readSchema('request.v1.schema.json');
const responseSchema = readSchema('response.v1.schema.json');
const scenarioSchema = readSchema('scenarios.v1.schema.json');

export const RUNNER_CLEANUP_PROTOCOL_DIGEST = CLEANUP_PROTOCOL_DIGEST;
const CLEANUP_SCENARIO_IDS = new Set([
  'resource.cleanup_preflight_step',
  'resource.cleanup_step',
  'resource.cleanup_proof_step',
  'resource.cleanup',
]);
for (const schema of [requestSchema, responseSchema, scenarioSchema]) {
  if (schema['x-cleanupProtocolDigest'] !== CLEANUP_PROTOCOL_DIGEST) {
    throw new Error('Runner cleanup protocol digest mismatch.');
  }
}
for (const scenarioId of CLEANUP_SCENARIO_IDS) {
  const resources = scenarioSchema.$defs[scenarioId]?.properties?.logicalResource?.enum;
  if (canonicalJson(resources) !== canonicalJson(QUALIFIED_CLEANUP_PROTOCOL.resourceOrder)) {
    throw new Error('Runner cleanup scenario catalog mismatch.');
  }
}
const RUN_PATTERN = new RegExp(requestSchema.properties.runId.pattern, 'u');
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const RUNNER_SAFE_MESSAGES = Object.freeze({
  unknown_scenario: 'Scenario is outside the closed runner protocol.',
  invalid_request: 'Request did not match the closed runner protocol.',
  environment_mismatch: 'Runner environment attestation did not match.',
  lease_invalid: 'Runner lease capability was invalid.',
  ownership_mismatch: 'Ledger ownership could not be proven.',
  timeout: 'Runner scenario exceeded its fixed timeout.',
  provider_failure: 'Provider operation failed safely.',
  cleanup_incomplete: 'Owned resource absence could not be proven.',
});
const RUNNER_ERROR_STATUSES = Object.freeze({
  invalid_request: 'failed',
  unknown_scenario: 'failed',
  environment_mismatch: 'blocked',
  lease_invalid: 'blocked',
  ownership_mismatch: 'blocked',
  timeout: 'failed',
  provider_failure: 'failed',
  cleanup_incomplete: 'blocked',
});

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export const RUNNER_SCENARIO_DEFINITIONS = deepFreeze(Object.fromEntries(
  Object.entries(scenarioSchema.$defs).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([scenarioId, definition]) => [scenarioId, {
      scenarioId,
      timeoutSeconds: definition['x-timeoutSeconds'],
      parameters: definition,
    }]),
));

function exactObject(value, required) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === required.length && required.every((key) => keys.includes(key))
    && keys.every((key) => typeof key === 'string' && Object.getOwnPropertyDescriptor(value, key)?.value !== undefined);
}

function resolveRef(schema, root) {
  if (!schema.$ref) return { schema, root };
  const external = schema.$ref.startsWith('verification-runner-scenarios.v1#');
  const selectedRoot = external ? scenarioSchema : root;
  const fragment = external ? schema.$ref.split('#')[1] : schema.$ref.slice(1);
  const parts = fragment.slice(1).split('/');
  return { schema: parts.reduce((value, part) => value[part], selectedRoot), root: selectedRoot };
}

function validSchemaValue(value, inputSchema, inputRoot = inputSchema) {
  const resolved = resolveRef(inputSchema, inputRoot);
  const schema = resolved.schema;
  const root = resolved.root;
  if (schema.oneOf && schema.oneOf.filter((entry) => validSchemaValue(value, entry, root)).length !== 1) return false;
  if (schema.allOf && !schema.allOf.every((entry) => validSchemaValue(value, entry, root))) return false;
  if (schema.if) {
    const matched = validSchemaValue(value, schema.if, root);
    if (matched && schema.then && !validSchemaValue(value, schema.then, root)) return false;
    if (!matched && schema.else && !validSchemaValue(value, schema.else, root)) return false;
  }
  if (schema.not && validSchemaValue(value, schema.not, root)) return false;
  if (Object.hasOwn(schema, 'const') && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
    if (!types.includes(actual) && !(actual === 'integer' && types.includes('number'))) return false;
  }
  if (typeof value === 'string') {
    if (schema.pattern && !(new RegExp(schema.pattern, 'u')).test(value)) return false;
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) return false;
  }
  if (Number.isInteger(value)) {
    if (schema.minimum !== undefined && value < schema.minimum) return false;
    if (schema.maximum !== undefined && value > schema.maximum) return false;
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const required = schema.required ?? [];
    const allowed = Object.keys(schema.properties ?? {});
    if (schema.additionalProperties === false && (!exactObject(value, Object.keys(value)) || Object.keys(value).some((key) => !allowed.includes(key)))) return false;
    for (const key of required) if (!Object.hasOwn(value, key)) return false;
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key) && !validSchemaValue(value[key], child, root)) return false;
    }
  }
  return true;
}

class DuplicateJsonObjectKeyError extends Error {}

function assertNoDuplicateJsonObjectKeys(text) {
  let index = 0;
  const skipWhitespace = () => { while (/\s/u.test(text[index] ?? '')) index += 1; };
  const parseString = () => {
    if (text[index] !== '"') throw new SyntaxError();
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      index += 1;
      if (character === '"') return JSON.parse(text.slice(start, index));
      if (character === '\\') index += 1;
    }
    throw new SyntaxError();
  };
  const parseValue = () => {
    skipWhitespace();
    if (text[index] === '{') {
      index += 1;
      const keys = new Set();
      skipWhitespace();
      if (text[index] === '}') { index += 1; return; }
      while (index < text.length) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) throw new DuplicateJsonObjectKeyError();
        keys.add(key);
        skipWhitespace();
        if (text[index] !== ':') throw new SyntaxError();
        index += 1;
        parseValue();
        skipWhitespace();
        if (text[index] === '}') { index += 1; return; }
        if (text[index] !== ',') throw new SyntaxError();
        index += 1;
      }
      throw new SyntaxError();
    }
    if (text[index] === '[') {
      index += 1;
      skipWhitespace();
      if (text[index] === ']') { index += 1; return; }
      while (index < text.length) {
        parseValue();
        skipWhitespace();
        if (text[index] === ']') { index += 1; return; }
        if (text[index] !== ',') throw new SyntaxError();
        index += 1;
      }
      throw new SyntaxError();
    }
    if (text[index] === '"') { parseString(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, index)) { index += literal.length; return; }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0];
    if (number) { index += number.length; return; }
    throw new SyntaxError();
  };
  parseValue();
  skipWhitespace();
  if (index !== text.length) throw new SyntaxError();
}

function parseJson(value, maximum, label) {
  let text;
  if (value instanceof Uint8Array) {
    if (value.byteLength > maximum) throw new TypeError(`${label} exceeds ${maximum === MAX_REQUEST_BYTES ? '16' : '64'} KiB`);
    try { text = decoder.decode(value); } catch { throw new TypeError(`${label} is not valid UTF-8`); }
  } else if (typeof value === 'string') {
    if (encoder.encode(value).byteLength > maximum) throw new TypeError(`${label} exceeds ${maximum === MAX_REQUEST_BYTES ? '16' : '64'} KiB`);
    text = value;
  } else {
    text = canonicalJson(value);
    if (encoder.encode(text).byteLength > maximum) throw new TypeError(`${label} exceeds ${maximum === MAX_REQUEST_BYTES ? '16' : '64'} KiB`);
    return structuredClone(value);
  }
  try {
    assertNoDuplicateJsonObjectKeys(text);
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof DuplicateJsonObjectKeyError) throw new TypeError(`${label} contains duplicate JSON object keys`);
    throw new TypeError(`${label} is not valid JSON`);
  }
}

export function getRunnerScenarioDefinition(scenarioId) {
  return typeof scenarioId === 'string' && Object.hasOwn(RUNNER_SCENARIO_DEFINITIONS, scenarioId)
    ? RUNNER_SCENARIO_DEFINITIONS[scenarioId] : null;
}

export function parseRunnerRequest(value) {
  const parsed = parseJson(value, MAX_REQUEST_BYTES, 'Runner request');
  if (!validSchemaValue(parsed, requestSchema, requestSchema)) throw new TypeError('Runner request schema mismatch');
  if (CLEANUP_SCENARIO_IDS.has(parsed.scenarioId)
    && !validateCleanupFence({
      scenarioId: parsed.scenarioId,
      logicalResource: parsed.parameters?.logicalResource,
      cleanupFence: parsed.cleanupFence,
    })) {
    throw new TypeError('Runner cleanup fence mismatch');
  }
  return deepFreeze(parsed);
}

function validData(scenarioId, data) {
  const definition = responseSchema.$defs[scenarioId];
  if (!definition || !validSchemaValue(data, definition, responseSchema)) return false;
  if (scenarioId === 'resource.read') {
    return data.exists === true
      ? data.ownership === 'run-owned' && DIGEST_PATTERN.test(data.stateDigest ?? '')
      : data.exists === false && data.ownership === 'absent' && data.stateDigest === null;
  }
  return true;
}

export function parseRunnerResponse(value) {
  const parsed = parseJson(value, MAX_RESPONSE_BYTES, 'Runner response');
  if (parsed?.status === 'passed') {
  if (!validSchemaValue(parsed, responseSchema, responseSchema)) throw new TypeError('Runner response schema mismatch');
    const keys = ['protocolVersion', 'scenarioId', 'runId', 'status', 'durationMs', 'data'];
    if (!exactObject(parsed, keys) || parsed.protocolVersion !== RUNNER_PROTOCOL_VERSION
      || !Object.hasOwn(RUNNER_SCENARIO_DEFINITIONS, parsed.scenarioId) || !RUN_PATTERN.test(parsed.runId)
      || !Number.isSafeInteger(parsed.durationMs) || parsed.durationMs < 0 || parsed.durationMs > 25000
      || !validData(parsed.scenarioId, parsed.data)) throw new TypeError('Runner response schema mismatch');
  } else {
    const keys = ['protocolVersion', 'scenarioId', 'runId', 'status', 'durationMs', 'error'];
    if (!validSchemaValue(parsed, responseSchema, responseSchema)
      || !exactObject(parsed, keys) || parsed.protocolVersion !== RUNNER_PROTOCOL_VERSION
      || !['failed', 'blocked'].includes(parsed.status) || !Number.isSafeInteger(parsed.durationMs)
      || parsed.durationMs < 0 || parsed.durationMs > 25000
      || !validSchemaValue(parsed.error, responseSchema.$defs.error, responseSchema)
      || parsed.error.retryable !== false
      || parsed.status !== RUNNER_ERROR_STATUSES[parsed.error.code]
      || parsed.error.safeMessage !== RUNNER_SAFE_MESSAGES[parsed.error.code]) throw new TypeError('Runner response schema mismatch');
    if (parsed.scenarioId === 'invalid') {
      if (!((parsed.runId === null && parsed.error.code === 'invalid_request') || (typeof parsed.runId === 'string' && RUN_PATTERN.test(parsed.runId) && ['invalid_request', 'unknown_scenario'].includes(parsed.error.code)))) throw new TypeError('Runner response identity mismatch');
    } else if (!Object.hasOwn(RUNNER_SCENARIO_DEFINITIONS, parsed.scenarioId) || !RUN_PATTERN.test(parsed.runId)) {
      throw new TypeError('Runner response identity mismatch');
    }
  }
  return deepFreeze(parsed);
}

export function createRunnerExecutionWire({ context, runnerRequest }) {
  if (!isAuthenticTestEnvironmentContext(context)) throw new TypeError('Runner context invalid');
  const fields = consumeRunnerRequest({ context, runnerRequest });
  const body = parseRunnerRequest({ protocolVersion: RUNNER_PROTOCOL_VERSION, ...fields,
    environmentDigest: context.environmentDigest });
  return deepFreeze({ async: false, body: canonicalJson(body) });
}

const protocolMismatch = () => deepFreeze({ status: 'BLOCKED', code: 'RUNNER_PROTOCOL_MISMATCH', envelope: null });

export function mapRunnerExecution({ request, expectedRunnerRevision, transportStatus, execution }) {
  if ([401, 403, 404].includes(transportStatus)) return deepFreeze({ status: 'BLOCKED', code: 'RUNNER_TRANSPORT_AUTHORITY', envelope: null });
  if (transportStatus !== 201) return deepFreeze({ status: 'FAIL', code: 'RUNNER_TRANSPORT_FAILURE', envelope: null });
  if (!exactObject(execution, ['status', 'responseStatusCode', 'responseBody']) || execution.status !== 'completed') {
    return deepFreeze({ status: 'FAIL', code: 'RUNNER_EXECUTION_INCOMPLETE', envelope: null });
  }
  let envelope;
  try { envelope = parseRunnerResponse(execution.responseBody); } catch { return protocolMismatch(); }
  const requestKnown = Object.hasOwn(RUNNER_SCENARIO_DEFINITIONS, request.scenarioId);
  if (requestKnown) {
    if (envelope.scenarioId !== request.scenarioId || envelope.runId !== request.runId
      || ['invalid_request', 'unknown_scenario'].includes(envelope.error?.code)) return protocolMismatch();
  } else if (envelope.scenarioId !== 'invalid' || envelope.runId !== request.runId
    || envelope.error?.code !== 'unknown_scenario') {
    return protocolMismatch();
  }
  if (requestKnown && CLEANUP_SCENARIO_IDS.has(request.scenarioId) && envelope.status === 'passed') {
    try {
      parseCleanupStepResponse({
        scenarioId: request.scenarioId,
        logicalResource: request.parameters?.logicalResource,
        environmentDigest: request.environmentDigest,
        cleanupFence: request.cleanupFence,
        response: envelope.data,
      });
    } catch {
      return protocolMismatch();
    }
  }
  if (['health', 'environment.readback'].includes(envelope.scenarioId)
    && envelope.status === 'passed' && envelope.data.runnerRevision !== expectedRunnerRevision) return protocolMismatch();
  const key = `${execution.responseStatusCode}\0${envelope.status}\0${envelope.error?.code ?? ''}`;
  const status = key === '200\0passed\0' ? 'PASS'
    : ['400\0failed\0invalid_request', '400\0failed\0unknown_scenario', '502\0failed\0provider_failure', '504\0failed\0timeout'].includes(key) ? 'FAIL'
      : ['403\0blocked\0environment_mismatch', '403\0blocked\0lease_invalid', '403\0blocked\0ownership_mismatch', '409\0blocked\0cleanup_incomplete'].includes(key) ? 'BLOCKED' : null;
  return status === null ? protocolMismatch() : deepFreeze({ status, code: null, envelope });
}
