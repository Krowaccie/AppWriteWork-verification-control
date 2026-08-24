import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { readAppwriteTestLiveProjection } from './appwrite-test-live-readback.mjs';

const OPERATOR_SECRET = 'operator-secret-for-test';
const FIXTURE_SECRET = 'fixture-secret-for-test';
const EMAILS = Object.freeze({
  editor: 'editor@appwrite-test.invalid',
  owner: 'owner@appwrite-test.invalid',
  viewer: 'viewer@appwrite-test.invalid',
});
const ENVIRONMENT_DIGEST =
  'sha256:02560e84745ed7b577b334a3412885f6a547b2a22f164f4978b255d3b35c0044';
const PROVIDER_CONTRACT_DIGEST =
  'sha256:47a1d778ca8b8cea333b10574ffbc2db488fd711c12a1c40faf9da5235e27184';

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function identityDigest() {
  const preferenceDigest = digest(canonicalJson({
    onboardingCompletedAt: '2026-08-01T00:00:00.000Z',
    onboardingHintsEnabled: false,
  }));
  const roles = ['editor', 'owner', 'viewer'].map((role) => {
    const userId = `${role}-user`;
    const email = EMAILS[role];
    const name = `${role} fixture`;
    const configuredEmailDigest = digest(email);
    const identityCriticalProjectionDigest = digest(canonicalJson({
      schemaVersion: 'test-cloud.identity-critical-projection.v1',
      role,
      userId,
      email,
      name,
      active: true,
    }));
    const sessionSetDigest = digest(canonicalJson({
      schemaVersion: 'test-cloud.identity-session-set.v1', role, total: 0,
    }));
    const roleDigest = digest(canonicalJson({
      schemaVersion: 'test-cloud.identity-role-binding.v1',
      role,
      configuredEmailDigest,
      fixturePreferencesDigest: preferenceDigest,
      identityCriticalProjectionDigest,
      sessionSetDigest,
    }));
    return {
      role,
      userId,
      email,
      name,
      active: true,
      configuredEmailDigest,
      fixturePreferencesDigest: preferenceDigest,
      identityCriticalProjectionDigest,
      sessionSetDigest,
      identityDigest: roleDigest,
    };
  });
  return digest(canonicalJson({
    schemaVersion: 'test-cloud.identity-bindings.v1',
    responseFormat: '1.9.5',
    environmentDigest: ENVIRONMENT_DIGEST,
    providerContractDigest: PROVIDER_CONTRACT_DIGEST,
    roles,
  }));
}

function variableValues() {
  return {
    VERIFICATION_AUDIT_TABLE_ID: inventory.control.auditTableId,
    VERIFICATION_CONTROL_DATABASE_ID: inventory.control.databaseId,
    VERIFICATION_ENDPOINT_ORIGIN: inventory.environment.endpoint,
    VERIFICATION_ENVIRONMENT_CLASS: inventory.environmentClass,
    VERIFICATION_ENVIRONMENT_DIGEST: ENVIRONMENT_DIGEST,
    VERIFICATION_IDENTITY_BINDINGS_DIGEST: identityDigest(),
    VERIFICATION_INTENT_TABLE_ID: inventory.control.intentTableId,
    VERIFICATION_LEASE_ROW_ID: inventory.control.leaseRowId,
    VERIFICATION_LEASE_TABLE_ID: inventory.control.leaseTableId,
    VERIFICATION_PRIMARY_DATABASE_ID: 'project',
    VERIFICATION_PROJECTS_TABLE_ID: 'projects',
    VERIFICATION_PROJECT_FILES_BUCKET_ID: 'project-files',
    VERIFICATION_PROJECT_ID: inventory.environment.projectId,
    VERIFICATION_PROVIDER_CONTRACT_DIGEST: PROVIDER_CONTRACT_DIGEST,
    VERIFICATION_SHARES_TABLE_ID: 'project_shares',
    VERIFICATION_WORKER_FUNCTION_ID: 'execute-node-py',
  };
}

function user(role) {
  const at = '2026-08-01T00:00:00.000Z';
  return {
    $id: `${role}-user`,
    $createdAt: at,
    $updatedAt: at,
    name: `${role} fixture`,
    registration: at,
    passwordUpdate: at,
    email: EMAILS[role],
    phone: '',
    accessedAt: at,
    status: true,
    emailVerification: true,
    phoneVerification: false,
    mfa: false,
    labels: [],
    targets: [],
    prefs: {
      onboardingCompletedAt: at,
      onboardingHintsEnabled: false,
    },
  };
}

function functionResponse(record) {
  const runner = record.functionId === inventory.control.runnerFunctionId;
  return {
    $id: record.functionId,
    runtime: record.runtime,
    entrypoint: record.entrypoint,
    commands: runner
      ? 'python -m pip install --require-hashes --only-binary=:all: -r requirements.txt'
      : '',
    providerRootDirectory: runner ? '' : record.sourcePath,
    name: runner ? 'verification-runner' : record.logicalId,
    execute: [],
    events: [],
    schedule: '',
    timeout: runner ? 30 : 15,
    enabled: runner ? false : true,
    logging: false,
    scopes: runner
      ? ['execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write']
      : [],
    deploymentId: null,
  };
}

function jsonResponse(url, value, { status = 200, redirected = false } = {}) {
  const bytes = Buffer.from(JSON.stringify(value), 'utf8');
  return {
    status,
    redirected,
    url,
    headers: {
      get(name) {
        if (name.toLowerCase() === 'content-type') return 'application/json; charset=utf-8';
        if (name.toLowerCase() === 'content-length') return String(bytes.byteLength);
        return null;
      },
    },
    async arrayBuffer() {
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
}

function createTransport(overrides = {}) {
  const allFunctions = [...inventory.productFunctions, ...inventory.testOnlyFunctions];
  const functionMap = new Map(allFunctions.map((record) => [record.functionId, record]));
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    if (typeof overrides.before === 'function') {
      const overridden = overrides.before(url, options);
      if (overridden !== undefined) return overridden;
    }
    const parsed = new URL(url);
    const path = `${parsed.pathname}${parsed.search}`;
    if (path === `/v1/sites/${inventory.environment.siteId}`) {
      return jsonResponse(url, {
        $id: inventory.environment.siteId,
        installationId: '154580138',
        providerRepositoryId: '1119118902',
        providerRootDirectory: 'src/web',
        providerBranch: 'main',
        installCommand: 'npm ci',
        buildCommand: 'npm run build',
        outputDirectory: 'dist',
        deploymentId: null,
      });
    }
    const functionMatch = /^\/v1\/functions\/([^/]+)$/u.exec(parsed.pathname);
    if (functionMatch !== null && functionMap.has(functionMatch[1])) {
      return jsonResponse(url, functionResponse(functionMap.get(functionMatch[1])));
    }
    if (parsed.pathname === '/v1/functions/verification-runner-py/variables') {
      const values = variableValues();
      return jsonResponse(url, {
        total: 16,
        variables: Object.entries(values).map(([key, value], index) => ({
          $id: `variable-${index}`,
          $createdAt: '2026-08-01T00:00:00.000Z',
          $updatedAt: '2026-08-01T00:00:00.000Z',
          key,
          value,
          secret: false,
          resourceType: 'function',
          resourceId: inventory.control.runnerFunctionId,
        })),
      });
    }
    if (parsed.pathname === '/v1/users') {
      const equal = JSON.parse(parsed.searchParams.get('queries[0]'));
      const role = Object.entries(EMAILS).find(([, email]) => email === equal.values[0])?.[0];
      return jsonResponse(url, role === undefined
        ? { total: 0, users: [] }
        : { total: 1, users: [user(role)] });
    }
    const userMatch = /^\/v1\/users\/([^/]+)$/u.exec(parsed.pathname);
    if (userMatch !== null) {
      const role = userMatch[1].replace(/-user$/u, '');
      return jsonResponse(url, user(role));
    }
    const sessionMatch = /^\/v1\/users\/([^/]+)\/sessions$/u.exec(parsed.pathname);
    if (sessionMatch !== null) return jsonResponse(url, { total: 0, sessions: [] });
    if (parsed.pathname === '/v1/tablesdb/verification_control/tables/verification_leases/rows/appwrite_test_verification') {
      return jsonResponse(url, {
        $id: inventory.control.leaseRowId,
        leaseRowId: inventory.control.leaseRowId,
        leaseVersion: 0,
        state: 'idle',
        ownerRunId: null,
        ownerWorkflowRunId: null,
        environmentDigest: null,
        acquiredAt: null,
        renewedAt: null,
        expiresAt: null,
        ledgerDigest: digest('genesis-ledger'),
        leaseTokenDigest: null,
        cleanupDebt: false,
      });
    }
    throw new Error(`Unexpected URL: ${url}`);
  };
  return { fetchImpl, requests };
}

function credentials(counters = { operator: 0, fixture: 0 }) {
  return {
    operatorCredential: Object.freeze({
      readSecret() {
        counters.operator += 1;
        return OPERATOR_SECRET;
      },
    }),
    fixtureCredential: Object.freeze({
      readSecret() {
        counters.fixture += 1;
        return FIXTURE_SECRET;
      },
    }),
  };
}

async function run(overrides = {}) {
  const transport = createTransport(overrides.transport);
  const counters = { operator: 0, fixture: 0 };
  return {
    result: await readAppwriteTestLiveProjection({
      inventory: overrides.inventory ?? inventory,
      configuredEmails: overrides.configuredEmails ?? EMAILS,
      ...credentials(counters),
      fetchImpl: transport.fetchImpl,
      clock: Object.freeze({ nowEpochSeconds: () => 1_800_000_000 }),
    }),
    counters,
    requests: transport.requests,
  };
}

test('reads and returns only the sanitized Appwrite Test projection', async () => {
  const { result, counters, requests } = await run();
  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
  assert.equal(result.value.environmentDigest, ENVIRONMENT_DIGEST);
  assert.equal(result.value.providerContractDigest, PROVIDER_CONTRACT_DIGEST);
  assert.equal(result.value.identityBindingsDigest, identityDigest());
  assert.equal(result.value.expectedRunnerVariables.variables.length, 16);
  assert.match(result.value.runnerVariableReadbackDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(result.value.siteConfigurationDigest, /^sha256:[0-9a-f]{64}$/);
  assert.match(result.value.functionConfigurationsDigest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(counters.operator > 0);
  assert.ok(counters.fixture > 0);
  assert.equal(requests.every(({ options }) => options.method === 'GET'), true);
  assert.equal(requests.every(({ options }) => options.redirect === 'error'), true);
  assert.equal(requests.every(
    ({ options }) => options.headers['Accept-Encoding'] === 'identity',
  ), true);
  const serialized = JSON.stringify(result);
  for (const forbidden of [OPERATOR_SECRET, FIXTURE_SECRET, ...Object.values(EMAILS)]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test('normalizes an empty Appwrite deployment ID to no active deployment', async () => {
  const firstFunction = inventory.productFunctions[0];
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.endsWith(`/${firstFunction.functionId}`)) {
          return jsonResponse(url, {
            ...functionResponse(firstFunction),
            deploymentId: '',
          });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
});

test('requires the test runner to remain disconnected from a VCS provider', async () => {
  const runner = inventory.testOnlyFunctions[0];
  const baseline = await run();
  assert.equal(baseline.result.status, 'PASS', baseline.result.diagnostics?.[0]?.code);
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.endsWith(`/${runner.functionId}`)) {
          return jsonResponse(url, {
            ...functionResponse(runner),
            providerRootDirectory: 'src/functions/verification-runner-py',
          });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(
    result.diagnostics[0].code,
    'APPWRITE_TEST_RUNNER_PROVIDER_ROOT_DIRECTORY_INVALID',
  );
});

test('does not read either credential before the fixed inventory is accepted', async () => {
  const changed = structuredClone(inventory);
  changed.environment.projectId = '69eb4818000afa64a7fa';
  const counters = { operator: 0, fixture: 0 };
  const result = await readAppwriteTestLiveProjection({
    inventory: changed,
    configuredEmails: EMAILS,
    ...credentials(counters),
    fetchImpl: async () => { throw new Error('must not fetch'); },
    clock: Object.freeze({ nowEpochSeconds: () => 1_800_000_000 }),
  });
  assert.equal(result.status, 'BLOCKED');
  assert.deepEqual(counters, { operator: 0, fixture: 0 });
});

test('rejects a nonzero identity session set', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.endsWith('/sessions')) {
          return jsonResponse(url, { total: 1, sessions: [{ $id: 'unexpected' }] });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
});

test('rejects a reflected credential without exposing it in diagnostics', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.includes('/sites/')) {
          return jsonResponse(url, { reflected: OPERATOR_SECRET });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(JSON.stringify(result).includes(OPERATOR_SECRET), false);
});

test('rejects a redirected Appwrite response', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.includes('/sites/')) {
          return jsonResponse(url, {}, { redirected: true });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_SITE_RESPONSE_REDIRECT_INVALID');
});

test('reports a non-success Site response without serializing its body or credential', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.includes('/sites/')) {
          return jsonResponse(url, { secretValue: OPERATOR_SECRET }, { status: 403 });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_SITE_RESPONSE_STATUS_INVALID');
  assert.equal(JSON.stringify(result).includes(OPERATOR_SECRET), false);
});

test('rejects a missing runner variable', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.endsWith('/variables')) {
          const variables = Object.entries(variableValues()).slice(0, 15).map(
            ([key, value], index) => ({
              $id: `variable-${index}`,
              $createdAt: '2026-08-01T00:00:00.000Z',
              $updatedAt: '2026-08-01T00:00:00.000Z',
              key,
              value,
              secret: false,
              resourceType: 'function',
              resourceId: inventory.control.runnerFunctionId,
            }),
          );
          return jsonResponse(url, { total: 15, variables });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
});

test('rejects a runner configuration mismatch', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.endsWith('/verification-runner-py')) {
          const record = inventory.testOnlyFunctions[0];
          return jsonResponse(url, { ...functionResponse(record), logging: true });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_RUNNER_LOGGING_INVALID');
});

test('rejects a non-idle fixed lease', async () => {
  const { result } = await run({
    transport: {
      before(url) {
        if (new URL(url).pathname.endsWith('/appwrite_test_verification')) {
          return jsonResponse(url, {
            $id: inventory.control.leaseRowId,
            leaseRowId: inventory.control.leaseRowId,
            leaseVersion: 1,
            state: 'active',
            ownerRunId: 'foreign-run',
            ownerWorkflowRunId: '1',
            environmentDigest: ENVIRONMENT_DIGEST,
            acquiredAt: '2026-08-01T00:00:00.000Z',
            renewedAt: '2026-08-01T00:00:00.000Z',
            expiresAt: '2026-08-01T01:00:00.000Z',
            ledgerDigest: digest('active-ledger'),
            leaseTokenDigest: digest('lease-token'),
            cleanupDebt: false,
          });
        }
        return undefined;
      },
    },
  });
  assert.equal(result.status, 'BLOCKED');
});
