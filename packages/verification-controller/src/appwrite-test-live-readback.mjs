import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { computeTestCloudSetupProjectionDigests } from
  '../../../scripts/verification/test-cloud-preflight.mjs';
import closedInventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};

const INPUT_KEYS = Object.freeze([
  'clock',
  'configuredEmails',
  'fetchImpl',
  'fixtureCredential',
  'inventory',
  'operatorCredential',
]);
const EMAIL_KEYS = Object.freeze(['editor', 'owner', 'viewer']);
const CREDENTIAL_KEYS = Object.freeze(['readSecret']);
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const EMAIL = /^[\x21-\x7e]+@[\x21-\x7e]+$/u;
const MAX_RESPONSE_BYTES = 262_144;
const RESPONSE_ROUTE_CLASSES = Object.freeze([
  'FUNCTION', 'IDENTITY', 'LEASE', 'RUNNER_VARIABLE', 'SITE',
]);
const RESPONSE_FAILURE_CLASSES = Object.freeze([
  'BODY_INVALID',
  'CONTENT_LENGTH_INVALID',
  'CONTENT_TYPE_INVALID',
  'CONTRACT_INVALID',
  'FETCH_INVALID',
  'JSON_INVALID',
  'REDIRECT_INVALID',
  'SECRET_REFLECTION_INVALID',
  'STATUS_INVALID',
]);
const ENVIRONMENT_DIGEST =
  'sha256:e83dac9cc615ccf37fd027683690edb2ff7332ac523d57130c1e86fa8617f302';
const PROVIDER_CONTRACT_DIGEST =
  'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8';
const FIXTURE_PREFERENCES = Object.freeze({
  onboardingCompletedAt: '2026-08-01T00:00:00.000Z',
  onboardingHintsEnabled: false,
});
const RUNNER_VARIABLE_QUERY =
  '/functions/verification-runner-py/variables?queries%5B%5D=%7B%22method%22%3A%22limit%22%2C%22values%22%3A%5B17%5D%7D&total=true';
const EXPECTED_RUNNER = Object.freeze({
  functionId: 'verification-runner-py',
  runtime: 'python-3.12',
  entrypoint: 'main.py',
  commands: 'python -m pip install --require-hashes --only-binary=:all: -r requirements.txt',
  providerRootDirectory: 'src/functions/verification-runner-py',
  name: 'verification-runner',
  execute: Object.freeze([]),
  events: Object.freeze([]),
  schedule: '',
  timeout: 30,
  enabled: false,
  logging: false,
  scopes: Object.freeze([
    'execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write',
  ]),
});

class LiveReadbackError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function digestText(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestJson(value) {
  return digestText(canonicalJson(value));
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null)
    && Object.getOwnPropertySymbols(value).length === 0;
}

function exactObject(value, keys) {
  if (!isPlainObject(value)) return null;
  const names = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    return null;
  }
  return value;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function blocked(code) {
  return deepFreeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code,
      retryable: false,
      safeMessage: 'The protected Appwrite Test readback could not be completed safely.',
    }],
  });
}

function pass(value) {
  return deepFreeze({ status: 'PASS', value, diagnostics: [] });
}

function fail(code) {
  throw new LiveReadbackError(code);
}

function failResponse(routeClass, failureClass) {
  if (
    !RESPONSE_ROUTE_CLASSES.includes(routeClass)
    || !RESPONSE_FAILURE_CLASSES.includes(failureClass)
  ) fail('APPWRITE_TEST_RESPONSE_INVALID');
  fail(`APPWRITE_TEST_${routeClass}_RESPONSE_${failureClass}`);
}

function validateInput(args) {
  const input = exactObject(args, INPUT_KEYS);
  if (
    input === null
    || canonicalJson(input.inventory) !== canonicalJson(closedInventory)
    || input.inventory.environment.endpoint !== 'https://fra.cloud.appwrite.io/v1'
    || input.inventory.environment.projectId !== '69137c5d003952a36d4c'
    || input.inventory.environment.siteId !== '694579860016df0d2d3c'
    || input.inventory.environment.publicOrigin !== 'https://appwritework.appwrite.network'
    || exactObject(input.operatorCredential, CREDENTIAL_KEYS) === null
    || exactObject(input.fixtureCredential, CREDENTIAL_KEYS) === null
    || typeof input.operatorCredential.readSecret !== 'function'
    || typeof input.fixtureCredential.readSecret !== 'function'
    || typeof input.fetchImpl !== 'function'
    || typeof input.clock?.nowEpochSeconds !== 'function'
  ) fail('APPWRITE_TEST_LIVE_READBACK_INPUT_INVALID');
  const emails = exactObject(input.configuredEmails, EMAIL_KEYS);
  if (
    emails === null
    || EMAIL_KEYS.some((role) => (
      typeof emails[role] !== 'string'
      || emails[role].length > 320
      || emails[role] !== emails[role].trim().toLowerCase()
      || !EMAIL.test(emails[role])
    ))
    || new Set(EMAIL_KEYS.map((role) => emails[role])).size !== 3
  ) fail('APPWRITE_TEST_LIVE_READBACK_INPUT_INVALID');
  const now = Reflect.apply(input.clock.nowEpochSeconds, input.clock, []);
  if (!Number.isSafeInteger(now) || now < 0) fail('APPWRITE_TEST_LIVE_READBACK_INPUT_INVALID');
  return { input, emails, now };
}

function assertNoDuplicateJsonKeys(text) {
  let cursor = 0;
  const whitespace = () => {
    while (cursor < text.length && /[\x20\x09\x0a\x0d]/u.test(text[cursor])) cursor += 1;
  };
  const stringToken = () => {
    if (text[cursor] !== '"') fail('APPWRITE_TEST_RESPONSE_INVALID');
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      const code = text.charCodeAt(cursor);
      if (code === 0x22) {
        cursor += 1;
        try {
          return JSON.parse(text.slice(start, cursor));
        } catch {
          fail('APPWRITE_TEST_RESPONSE_INVALID');
        }
      }
      if (code < 0x20) fail('APPWRITE_TEST_RESPONSE_INVALID');
      if (code === 0x5c) {
        cursor += 1;
        if (cursor >= text.length || !/["\\/bfnrtu]/u.test(text[cursor])) {
          fail('APPWRITE_TEST_RESPONSE_INVALID');
        }
        if (text[cursor] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(cursor + 1, cursor + 5))) {
            fail('APPWRITE_TEST_RESPONSE_INVALID');
          }
          cursor += 4;
        }
      }
      cursor += 1;
    }
    fail('APPWRITE_TEST_RESPONSE_INVALID');
  };
  const numberToken = () => {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      text.slice(cursor),
    );
    if (match === null) fail('APPWRITE_TEST_RESPONSE_INVALID');
    cursor += match[0].length;
  };
  const valueToken = () => {
    whitespace();
    if (text[cursor] === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set();
      if (text[cursor] === '}') { cursor += 1; return; }
      while (true) {
        const key = stringToken();
        if (keys.has(key)) fail('APPWRITE_TEST_RESPONSE_INVALID');
        keys.add(key);
        whitespace();
        if (text[cursor] !== ':') fail('APPWRITE_TEST_RESPONSE_INVALID');
        cursor += 1;
        valueToken();
        whitespace();
        if (text[cursor] === '}') { cursor += 1; return; }
        if (text[cursor] !== ',') fail('APPWRITE_TEST_RESPONSE_INVALID');
        cursor += 1;
      }
    }
    if (text[cursor] === '[') {
      cursor += 1;
      whitespace();
      if (text[cursor] === ']') { cursor += 1; return; }
      while (true) {
        valueToken();
        whitespace();
        if (text[cursor] === ']') { cursor += 1; return; }
        if (text[cursor] !== ',') fail('APPWRITE_TEST_RESPONSE_INVALID');
        cursor += 1;
      }
    }
    if (text[cursor] === '"') { stringToken(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, cursor)) { cursor += literal.length; return; }
    }
    numberToken();
  };
  whitespace();
  valueToken();
  whitespace();
  if (cursor !== text.length) fail('APPWRITE_TEST_RESPONSE_INVALID');
}

function createReader(input) {
  const allowlists = {
    operator: new Map(),
    fixture: new Map(),
  };
  const credentials = {
    operator: input.operatorCredential,
    fixture: input.fixtureCredential,
  };
  const add = (credentialClass, path, routeClass) => {
    if (
      !['operator', 'fixture'].includes(credentialClass)
      || typeof path !== 'string'
      || !RESPONSE_ROUTE_CLASSES.includes(routeClass)
    ) {
      fail('APPWRITE_TEST_ROUTE_INVALID');
    }
    const target = new URL(input.inventory.environment.endpoint + path);
    if (
      target.origin !== new URL(input.inventory.environment.endpoint).origin
      || !target.pathname.startsWith('/v1/')
      || /(?:salmora|69eb4818000afa64a7fa|69eb4a020024c520642e)/iu.test(target.href)
    ) fail('APPWRITE_TEST_ROUTE_INVALID');
    allowlists[credentialClass].set(path, routeClass);
  };
  const get = async (credentialClass, path) => {
    const routeClass = allowlists[credentialClass]?.get(path);
    if (routeClass === undefined) fail('APPWRITE_TEST_ROUTE_INVALID');
    const credential = credentials[credentialClass];
    let secret;
    let headers;
    try {
      secret = Reflect.apply(credential.readSecret, credential, []);
      if (typeof secret !== 'string' || !/^[\x21-\x7e]{1,8192}$/u.test(secret)) {
        fail('APPWRITE_TEST_CREDENTIAL_INVALID');
      }
      headers = {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        'X-Appwrite-Project': input.inventory.environment.projectId,
        'X-Appwrite-Response-Format': '1.9.5',
        'X-Appwrite-Key': secret,
      };
      const finalUrl = input.inventory.environment.endpoint + path;
      let response;
      try {
        response = await input.fetchImpl(finalUrl, {
          method: 'GET', headers, redirect: 'error', signal: AbortSignal.timeout(10_000),
        });
      } catch {
        failResponse(routeClass, 'FETCH_INVALID');
      }
      if (
        response === null
        || typeof response !== 'object'
        || typeof response.headers?.get !== 'function'
        || typeof response.arrayBuffer !== 'function'
      ) failResponse(routeClass, 'CONTRACT_INVALID');
      if (response.status !== 200) failResponse(routeClass, 'STATUS_INVALID');
      if (response.redirected !== false || response.url !== finalUrl) {
        failResponse(routeClass, 'REDIRECT_INVALID');
      }
      const contentType = response.headers.get('content-type');
      if (
        typeof contentType !== 'string'
        || contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json'
      ) failResponse(routeClass, 'CONTENT_TYPE_INVALID');
      const contentLength = response.headers.get('content-length');
      if (
        contentLength !== null
        && (!/^[1-9][0-9]*$/u.test(contentLength)
          || Number(contentLength) > MAX_RESPONSE_BYTES)
      ) failResponse(routeClass, 'CONTENT_LENGTH_INVALID');
      const buffer = await response.arrayBuffer();
      if (!(buffer instanceof ArrayBuffer) || buffer.byteLength < 1 || buffer.byteLength > MAX_RESPONSE_BYTES) {
        failResponse(routeClass, 'BODY_INVALID');
      }
      if (contentLength !== null && Number(contentLength) !== buffer.byteLength) {
        failResponse(routeClass, 'CONTENT_LENGTH_INVALID');
      }
      let text;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
      } catch {
        failResponse(routeClass, 'JSON_INVALID');
      }
      if (text.includes(secret)) failResponse(routeClass, 'SECRET_REFLECTION_INVALID');
      try {
        assertNoDuplicateJsonKeys(text);
        return JSON.parse(text);
      } catch (error) {
        if (
          error instanceof LiveReadbackError
          && error.code !== 'APPWRITE_TEST_RESPONSE_INVALID'
        ) throw error;
        failResponse(routeClass, 'JSON_INVALID');
      }
    } finally {
      if (headers !== undefined) headers['X-Appwrite-Key'] = undefined;
      secret = undefined;
    }
  };
  return { add, get };
}

function stringArray(value) {
  return Array.isArray(value)
    && Object.keys(value).length === value.length
    && value.every((entry) => typeof entry === 'string');
}

function siteProjection(raw, inventory) {
  if (
    !isPlainObject(raw)
    || raw.$id !== inventory.environment.siteId
    || !SAFE_ID.test(raw.installationId ?? '')
    || !SAFE_ID.test(raw.providerRepositoryId ?? '')
    || !['providerRootDirectory', 'providerBranch', 'installCommand', 'buildCommand', 'outputDirectory']
      .every((key) => typeof raw[key] === 'string')
    || !(raw.deploymentId === null || SAFE_ID.test(raw.deploymentId ?? ''))
  ) fail('APPWRITE_TEST_SITE_READBACK_INVALID');
  return {
    activeDeploymentId: raw.deploymentId,
    buildCommand: raw.buildCommand,
    installCommand: raw.installCommand,
    installationId: raw.installationId,
    outputDirectory: raw.outputDirectory,
    providerBranch: raw.providerBranch,
    providerRepositoryId: raw.providerRepositoryId,
    providerRootDirectory: raw.providerRootDirectory,
    siteId: inventory.environment.siteId,
  };
}

function functionProjection(raw, record) {
  if (
    !isPlainObject(raw)
    || raw.$id !== record.functionId
    || raw.runtime !== record.runtime
    || raw.entrypoint !== record.entrypoint
    || !['commands', 'providerRootDirectory', 'name', 'schedule']
      .every((key) => typeof raw[key] === 'string')
    || raw.name.length === 0
    || !stringArray(raw.execute)
    || !stringArray(raw.events)
    || !stringArray(raw.scopes)
    || !Number.isSafeInteger(raw.timeout)
    || raw.timeout < 1
    || typeof raw.enabled !== 'boolean'
    || typeof raw.logging !== 'boolean'
    || !(raw.deploymentId === null || SAFE_ID.test(raw.deploymentId ?? ''))
  ) fail('APPWRITE_TEST_FUNCTION_READBACK_INVALID');
  const projection = {
    activeDeploymentId: raw.deploymentId,
    commands: raw.commands,
    entrypoint: raw.entrypoint,
    functionId: record.functionId,
    providerRootDirectory: raw.providerRootDirectory,
    runtime: raw.runtime,
    enabled: raw.enabled,
    events: [...raw.events],
    execute: [...raw.execute],
    logging: raw.logging,
    name: raw.name,
    schedule: raw.schedule,
    scopes: [...raw.scopes],
    timeout: raw.timeout,
  };
  if (record.functionId === EXPECTED_RUNNER.functionId) {
    for (const [key, expected] of Object.entries(EXPECTED_RUNNER)) {
      const actual = projection[key];
      if (Array.isArray(expected)) {
        if (!Array.isArray(actual) || canonicalJson(actual) !== canonicalJson(expected)) {
          fail('APPWRITE_TEST_RUNNER_CONFIGURATION_INVALID');
        }
      } else if (actual !== expected) {
        fail('APPWRITE_TEST_RUNNER_CONFIGURATION_INVALID');
      }
    }
  }
  return projection;
}

function identityRole(role, raw, expectedEmail) {
  if (
    !isPlainObject(raw)
    || !SAFE_ID.test(raw.$id ?? '')
    || raw.email !== expectedEmail
    || typeof raw.name !== 'string'
    || raw.name.length < 1
    || raw.name.length > 128
    || raw.status !== true
    || canonicalJson(raw.prefs) !== canonicalJson(FIXTURE_PREFERENCES)
  ) fail('APPWRITE_TEST_IDENTITY_READBACK_INVALID');
  const configuredEmailDigest = digestText(raw.email);
  const fixturePreferencesDigest = digestJson(FIXTURE_PREFERENCES);
  const identityCriticalProjectionDigest = digestJson({
    schemaVersion: 'test-cloud.identity-critical-projection.v1',
    role,
    userId: raw.$id,
    email: raw.email,
    name: raw.name,
    active: true,
  });
  const sessionSetDigest = digestJson({
    schemaVersion: 'test-cloud.identity-session-set.v1', role, total: 0,
  });
  const identityDigest = digestJson({
    schemaVersion: 'test-cloud.identity-role-binding.v1',
    role,
    configuredEmailDigest,
    fixturePreferencesDigest,
    identityCriticalProjectionDigest,
    sessionSetDigest,
  });
  return {
    role,
    userId: raw.$id,
    email: raw.email,
    name: raw.name,
    active: true,
    configuredEmailDigest,
    fixturePreferencesDigest,
    identityCriticalProjectionDigest,
    sessionSetDigest,
    identityDigest,
  };
}

async function readIdentities(reader, emails) {
  const roles = [];
  for (const role of EMAIL_KEYS) {
    const query = new URLSearchParams();
    query.append('queries[0]', JSON.stringify({
      method: 'equal', attribute: 'email', values: [emails[role]],
    }));
    query.append('queries[1]', '{"method":"limit","values":[2]}');
    query.append('total', 'true');
    const listPath = `/users?${query.toString()}`;
    reader.add('fixture', listPath, 'IDENTITY');
    const listed = await reader.get('fixture', listPath);
    if (
      exactObject(listed, ['total', 'users']) === null
      || listed.total !== 1
      || !Array.isArray(listed.users)
      || listed.users.length !== 1
    ) fail('APPWRITE_TEST_IDENTITY_READBACK_INVALID');
    const roleProjection = identityRole(role, listed.users[0], emails[role]);
    const userPath = `/users/${encodeURIComponent(roleProjection.userId)}`;
    const sessionsPath = `${userPath}/sessions?total=true`;
    reader.add('fixture', userPath, 'IDENTITY');
    reader.add('fixture', sessionsPath, 'IDENTITY');
    const fetched = await reader.get('fixture', userPath);
    if (canonicalJson(fetched) !== canonicalJson(listed.users[0])) {
      fail('APPWRITE_TEST_IDENTITY_READBACK_INVALID');
    }
    const sessions = await reader.get('fixture', sessionsPath);
    if (
      exactObject(sessions, ['sessions', 'total']) === null
      || sessions.total !== 0
      || !Array.isArray(sessions.sessions)
      || sessions.sessions.length !== 0
    ) fail('APPWRITE_TEST_IDENTITY_READBACK_INVALID');
    roles.push(roleProjection);
  }
  if (
    new Set(roles.map(({ userId }) => userId)).size !== 3
    || new Set(roles.map(({ email }) => email)).size !== 3
  ) fail('APPWRITE_TEST_IDENTITY_READBACK_INVALID');
  const withoutSelf = {
    schemaVersion: 'test-cloud.identity-bindings.v1',
    responseFormat: '1.9.5',
    environmentDigest: ENVIRONMENT_DIGEST,
    providerContractDigest: PROVIDER_CONTRACT_DIGEST,
    roles,
  };
  return {
    identityBindingsDigest: digestJson(withoutSelf),
    sessionCounts: EMAIL_KEYS.map((role) => ({ role, total: 0 })),
  };
}

function readRunnerVariables(raw, identityBindingsDigest) {
  if (
    exactObject(raw, ['total', 'variables']) === null
    || raw.total !== 16
    || !Array.isArray(raw.variables)
    || raw.variables.length !== 16
  ) fail('APPWRITE_TEST_RUNNER_VARIABLE_READBACK_INVALID');
  const values = new Map();
  for (const variable of raw.variables) {
    if (
      !isPlainObject(variable)
      || !SAFE_ID.test(variable.$id ?? '')
      || typeof variable.key !== 'string'
      || !closedInventory.testOnlyFunctions.length
      || values.has(variable.key)
      || typeof variable.value !== 'string'
      || variable.value.length < 1
      || Buffer.byteLength(variable.value, 'utf8') > 8192
      || variable.secret !== false
      || variable.resourceType !== 'function'
      || variable.resourceId !== closedInventory.control.runnerFunctionId
    ) fail('APPWRITE_TEST_RUNNER_VARIABLE_READBACK_INVALID');
    values.set(variable.key, variable.value);
  }
  const configuredKeys = [
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
  ];
  if (configuredKeys.some((key) => !values.has(key))) {
    fail('APPWRITE_TEST_RUNNER_VARIABLE_READBACK_INVALID');
  }
  const expectedLiterals = {
    VERIFICATION_AUDIT_TABLE_ID: closedInventory.control.auditTableId,
    VERIFICATION_CONTROL_DATABASE_ID: closedInventory.control.databaseId,
    VERIFICATION_ENDPOINT_ORIGIN: closedInventory.environment.endpoint,
    VERIFICATION_ENVIRONMENT_CLASS: closedInventory.environmentClass,
    VERIFICATION_ENVIRONMENT_DIGEST: ENVIRONMENT_DIGEST,
    VERIFICATION_IDENTITY_BINDINGS_DIGEST: identityBindingsDigest,
    VERIFICATION_INTENT_TABLE_ID: closedInventory.control.intentTableId,
    VERIFICATION_LEASE_ROW_ID: closedInventory.control.leaseRowId,
    VERIFICATION_LEASE_TABLE_ID: closedInventory.control.leaseTableId,
    VERIFICATION_PROJECT_ID: closedInventory.environment.projectId,
    VERIFICATION_PROVIDER_CONTRACT_DIGEST: PROVIDER_CONTRACT_DIGEST,
  };
  if (Object.entries(expectedLiterals).some(([key, value]) => values.get(key) !== value)) {
    fail('APPWRITE_TEST_RUNNER_VARIABLE_READBACK_INVALID');
  }
  const variables = configuredKeys.map((key) => ({ key, valueDigest: digestText(values.get(key)) }));
  const expectedRunnerVariables = {
    identityQualifiedKey: 'VERIFICATION_IDENTITY_BINDINGS_DIGEST',
    staticTotal: 15,
    total: 16,
    variables,
  };
  const runnerVariableReadbackDigest = digestJson({
    schemaVersion: 'test-cloud.runner-variable-readback.v1',
    environmentDigest: ENVIRONMENT_DIGEST,
    providerContractDigest: PROVIDER_CONTRACT_DIGEST,
    functionIdDigest: digestText(closedInventory.control.runnerFunctionId),
    variables,
  });
  return { expectedRunnerVariables, runnerVariableReadbackDigest };
}

function validateIdleLease(raw) {
  const data = Object.fromEntries(Object.entries(raw).filter(([key]) => !key.startsWith('$')));
  if (
    raw.$id !== closedInventory.control.leaseRowId
    || data.leaseRowId !== closedInventory.control.leaseRowId
    || data.state !== 'idle'
    || data.ownerRunId !== null
    || data.ownerWorkflowRunId !== null
    || data.environmentDigest !== null
    || data.acquiredAt !== null
    || data.renewedAt !== null
    || data.expiresAt !== null
    || data.leaseTokenDigest !== null
    || data.cleanupDebt !== false
    || !Number.isSafeInteger(data.leaseVersion)
    || data.leaseVersion < 0
    || !DIGEST.test(data.ledgerDigest ?? '')
  ) fail('APPWRITE_TEST_LEASE_READBACK_INVALID');
  return {
    leaseVersion: data.leaseVersion,
    ledgerDigest: data.ledgerDigest,
    state: data.state,
    cleanupDebt: data.cleanupDebt,
  };
}

export async function readAppwriteTestLiveProjection(args) {
  try {
    const { input, emails, now } = validateInput(args);
    const reader = createReader(input);
    const sitePath = `/sites/${encodeURIComponent(input.inventory.environment.siteId)}`;
    reader.add('operator', sitePath, 'SITE');
    const functionRecords = [...input.inventory.productFunctions, ...input.inventory.testOnlyFunctions]
      .sort((left, right) => left.functionId < right.functionId ? -1 : 1);
    for (const record of functionRecords) {
      reader.add('operator', `/functions/${encodeURIComponent(record.functionId)}`, 'FUNCTION');
    }
    reader.add('operator', RUNNER_VARIABLE_QUERY, 'RUNNER_VARIABLE');
    const leasePath = `/tablesdb/${encodeURIComponent(input.inventory.control.databaseId)}`
      + `/tables/${encodeURIComponent(input.inventory.control.leaseTableId)}`
      + `/rows/${encodeURIComponent(input.inventory.control.leaseRowId)}`;
    reader.add('fixture', leasePath, 'LEASE');

    const site = siteProjection(await reader.get('operator', sitePath), input.inventory);
    const functions = [];
    for (const record of functionRecords) {
      const path = `/functions/${encodeURIComponent(record.functionId)}`;
      functions.push(functionProjection(await reader.get('operator', path), record));
    }
    const identity = await readIdentities(reader, emails);
    const variables = readRunnerVariables(
      await reader.get('operator', RUNNER_VARIABLE_QUERY),
      identity.identityBindingsDigest,
    );
    const lease = validateIdleLease(await reader.get('fixture', leasePath));
    const configurationDigests = computeTestCloudSetupProjectionDigests({ site, functions });
    return pass({
      environmentDigest: ENVIRONMENT_DIGEST,
      providerContractDigest: PROVIDER_CONTRACT_DIGEST,
      identityBindingsDigest: identity.identityBindingsDigest,
      expectedRunnerVariables: variables.expectedRunnerVariables,
      runnerVariableReadbackDigest: variables.runnerVariableReadbackDigest,
      siteConfigurationDigest: configurationDigests.siteConfigurationDigest,
      functionConfigurationsDigest: configurationDigests.functionConfigurationsDigest,
      globalCleanupReadbackDigest: digestJson({
        schemaVersion: 'appwrite-test-global-cleanup-readback.v1',
        observedAtEpochSeconds: now,
        lease,
        sessionCounts: identity.sessionCounts,
      }),
      projectReadbackDigest: digestJson({
        schemaVersion: 'appwrite-test-project-readback.v1',
        environmentDigest: ENVIRONMENT_DIGEST,
        projectIdDigest: digestText(input.inventory.environment.projectId),
        siteIdDigest: digestText(input.inventory.environment.siteId),
      }),
    });
  } catch (error) {
    return blocked(error instanceof LiveReadbackError
      ? error.code : 'APPWRITE_TEST_LIVE_READBACK_INVALID');
  }
}
