import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import { assertRunReadback, observePortableProduct, resolveRestoredResource } from './product-observer.mjs';
import { canonical, connect, executionClient, hash, localApi, operation, validateExecution } from './product-client.mjs';

const endpoint = 'https://localhost:43210/v1', ca = Buffer.from('synthetic public CA');
const body = operation('observer_test', 'projects.create.v1', { name: 'Test', nested: { b: 1, a: 2 } });
const envelope = { contract: 'salmora.operation-result.v1', operationId: body.operationId, status: 'succeeded', result: {} };
const execution = response => ({ $id: 'exec_1', status: 'completed', responseStatusCode: 200, responseBody: JSON.stringify(response) });
const resultValue = { value: 'nonce-exact-output' };
test('restore resolves the unique currently published resource instead of reusing a retired artifact ID', () => {
  const bytes = Buffer.from('exact restored bytes'), options = { projectId: 'project', rootId: 'root', name: 'observer.txt', bytes };
  const artifact = { artifactId: 'new-restored-id', projectId: 'project', parentContainerId: 'root', artifactType: 'resource.file.v1',
    name: 'observer.txt', contentHash: hash(bytes), sizeBytes: bytes.length, stability: 'stable', lifecycleState: 'published' };
  const inventory = { projectId: 'project', nextCursor: null, artifacts: [artifact] };
  assert.deepEqual(resolveRestoredResource(inventory, options), { artifactId: 'new-restored-id', alias: 'stable' });
  for (const change of [value => { value.nextCursor = 'more'; }, value => { value.projectId = 'foreign'; },
    value => { value.artifacts = []; }, value => { value.artifacts.push({ ...artifact, artifactId: 'duplicate' }); },
    value => { value.artifacts.push({ ...artifact, artifactId: 'duplicate', contentHash: hash('wrong bytes') }); },
    value => { value.artifacts[0].projectId = 'foreign'; }, value => { value.artifacts[0].parentContainerId = 'foreign'; },
    value => { value.artifacts[0].name = 'different.txt'; },
    value => { value.artifacts[0].contentHash = hash('wrong bytes'); }, value => { value.artifacts[0].sizeBytes++; },
    value => { value.artifacts[0].stability = 'draft'; }, value => { value.artifacts[0].lifecycleState = 'pending'; },
    value => { value.artifacts[0].artifactId = '../escape'; }, value => { value.artifacts[0].artifactType = 'workflow.graph.v1'; }]) {
    const invalid = structuredClone(inventory); change(invalid); assert.throws(() => resolveRestoredResource(invalid, options));
  }
});
const options = { tenantId: 'tenant', ownerId: 'owner', projectId: 'project', runId: 'run', value: 'nonce-exact-output', resultValue };
const row = { tenant_id: 'tenant', caller_principal_id: 'owner', project_id: 'project', run_id: 'run', engine_id: 'temporal',
  engine_attempt_ref: 'attempt-1', workflow_id: 'workflow-1', state: 'succeeded', terminal_receipt: { succeeded: true },
  first_execution_ref: 'temporal-first-run', terminal_proof: { receipt: true },
  terminal_result: { output_ref: { artifact_ref: 'execution-artifact-' + 'c'.repeat(64), digest: 'sha256:' + 'd'.repeat(64), size_bytes: 100 }, plan_digest: 'sha256:' + 'a'.repeat(64) },
  step_output_ref: { artifact_ref: 'execution-artifact-' + 'b'.repeat(64), digest: hash(canonical(resultValue)), size_bytes: Buffer.byteLength(canonical(resultValue)) } };

function transportFixture({ value = {}, status = 200, raw, oversized = false } = {}) {
  const captured = {};
  const transport = (url, requestOptions, callback) => {
    Object.assign(captured, { url, options: requestOptions });
    const request = new EventEmitter();
    request.destroy = error => queueMicrotask(() => request.emit('error', error));
    request.end = bytes => {
      captured.body = bytes;
      queueMicrotask(() => {
        const response = new EventEmitter(); response.statusCode = status; response.headers = {};
        callback(response);
        response.emit('data', oversized ? Buffer.alloc(1024 * 1024 + 1) : Buffer.from(raw ?? JSON.stringify(value)));
        response.emit('end');
      });
    };
    return request;
  };
  return { transport, captured };
}

test('canonical payload and operation digest are stable across object key order', () => {
  const first = operation('same', 'projects.create.v1', { a: 1, b: [2, 3] });
  const second = operation('same', 'projects.create.v1', { b: [2, 3], a: 1 });
  assert.equal(canonical(first), canonical(second));
  assert.match(first.idempotency.payloadDigest, /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(first.idempotency.payloadDigest, operation('same', 'projects.create.v1', { a: 9, b: [2, 3] }).idempotency.payloadDigest);
});

test('transport pins local HTTPS and CA with bounded JSON', async () => {
  const { transport, captured } = transportFixture({ value: { $id: 'account' } });
  const request = localApi(endpoint, ca, { 'x-appwrite-key': 'synthetic-key' }, { transport });
  assert.equal((await request('POST', '/account', { name: 'test' })).value.$id, 'account');
  assert.equal(captured.options.rejectUnauthorized, true);
  assert.equal(captured.options.ca, ca);
  assert.equal(captured.options.timeout, 60_000);
  assert.deepEqual(JSON.parse(captured.body.toString()), { name: 'test' });
});

test('transport rejects remote endpoints, private keys and path escapes before requests', async () => {
  for (const url of ['http://localhost:43210/v1', 'https://127.0.0.1:43210/v1', 'https://example.test:43210/v1', 'https://localhost:99999/v1']) {
    assert.throws(() => localApi(url, ca), /OBSERVER_LOCAL_HTTPS_REQUIRED|Invalid URL/);
  }
  assert.throws(() => localApi(endpoint, Buffer.from('PRIVATE KEY')), /OBSERVER_PUBLIC_CA_REQUIRED/);
  const request = localApi(endpoint, ca, {}, { transport: () => assert.fail('transport must not run') });
  for (const route of ['//evil.test', '/../account', '/%2e%2e/account', '/%2Faccount', '/%5caccount']) {
    await assert.rejects(request('GET', route), /OBSERVER_ROUTE_INVALID/);
  }
});

test('transport rejects oversized response and request without revealing payloads', async () => {
  const request = localApi(endpoint, ca, {}, transportFixture({ oversized: true }));
  await assert.rejects(request('GET', '/account'), /OBSERVER_RESPONSE_LIMIT/);
  const noTransport = localApi(endpoint, ca, {}, { transport: () => assert.fail('oversized request transported') });
  await assert.rejects(noTransport('POST', '/account', { secret: 's'.repeat(1024 * 1024) }), /OBSERVER_REQUEST_LIMIT/);
});

test('transport refuses redirects, non-JSON and error bodies containing secrets', async () => {
  for (const status of [302, 401, 500]) {
    const request = localApi(endpoint, ca, {}, transportFixture({ status, value: { message: 'secret-jwt-value' } }));
    await assert.rejects(request('GET', '/account'), error => error.status === status && !error.message.includes('secret'));
  }
  const request = localApi(endpoint, ca, {}, transportFixture({ raw: 'private malformed body' }));
  await assert.rejects(request('GET', '/account'), /OBSERVER_RESPONSE_JSON_REQUIRED/);
});

test('session/user cleanup accepts Appwrite empty HTTP 204 response', async () => {
  const request = localApi(endpoint, ca, {}, transportFixture({ status: 204, raw: '' }));
  assert.deepEqual(await request('DELETE', '/account/sessions/current'), { value: null, status: 204, fallbackCookies: undefined });
});

test('execution response must match execution identity, operation, status and real denial code', () => {
  assert.equal(validateExecution(execution(envelope), 'exec_1', body).status, 'succeeded');
  assert.throws(() => validateExecution(execution({ ...envelope, operationId: 'forged' }), 'exec_1', body), /OBSERVER_OPERATION_BINDING_MISMATCH/);
  assert.throws(() => validateExecution({ ...execution(envelope), $id: 'forged' }, 'exec_1', body), /OBSERVER_EXECUTION_ID_DRIFT/);
  assert.throws(() => validateExecution({ ...execution(envelope), status: 'failed' }, 'exec_1', body), /OBSERVER_EXECUTION_NOT_COMPLETED/);
  assert.throws(() => validateExecution(execution(envelope), 'exec_1', body, { status: 403, code: 'AUTHORITY_DENIED' }), /OBSERVER_EXECUTION_HTTP_MISMATCH/);
  const denied = { ...execution({ error: { code: 'AUTHORITY_DENIED' } }), responseStatusCode: 403 };
  assert.equal(validateExecution(denied, 'exec_1', body, { status: 403, code: 'AUTHORITY_DENIED' }).error.code, 'AUTHORITY_DENIED');
  assert.throws(() => validateExecution({ ...denied, responseBody: '{"error":"other"}' }, 'exec_1', body,
    { status: 403, code: 'AUTHORITY_DENIED' }), /OBSERVER_DENIAL_CODE_MISMATCH/);
});

test('execution polling retries one 404 for the same ID and never trusts another execution', async () => {
  const checks = [], routes = [];
  let reads = 0;
  const invoke = executionClient({ functions: { fn: { functionId: 'native_fn' } }, checks, delay: async () => {},
    operator: async (method, route) => {
      routes.push(route);
      if (!reads++) { const error = new Error('not yet visible'); error.status = 404; throw error; }
      return { value: execution(envelope) };
    } });
  await invoke('invoke', 'fn', async () => ({ value: { $id: 'exec_1', status: 'processing' } }), body);
  assert.deepEqual(routes, ['/functions/native_fn/executions/exec_1', '/functions/native_fn/executions/exec_1']);
  assert.equal(checks[0].status, 'PASS');
  const drift = executionClient({ functions: { fn: { functionId: 'native_fn' } }, checks: [], delay: async () => {},
    operator: async () => ({ value: { ...execution(envelope), $id: 'wrong_id' } }) });
  await assert.rejects(drift('invoke', 'fn', async () => ({ value: { $id: 'exec_1', status: 'processing' } }), body), /OBSERVER_EXECUTION_ID_DRIFT/);
});

test('second missing execution read remains failure with zero PASS observations', async () => {
  const checks = [];
  const invoke = executionClient({ functions: { fn: { functionId: 'native_fn' } }, checks, delay: async () => {},
    operator: async () => { const error = new Error('not found'); error.status = 404; throw error; } });
  await assert.rejects(invoke('invoke', 'fn', async () => ({ value: { $id: 'exec_1', status: 'processing' } }), body), /not found/);
  assert.deepEqual(checks, []);
});

test('login checks the real session and account identity before issuing JWT', async () => {
  const calls = [];
  const make = wrong => connect({ state: { endpoint, product: { functions: {} } }, credentials: { projectId: 'project', apiKey: 'synthetic' },
    ca, checks: [], api: (url, certificate, headers) => async (method, route) => {
      calls.push(route);
      if (route === '/account/sessions/email') return { value: { userId: 'owner' }, fallbackCookies: 'synthetic-cookie' };
      if (route === '/account') return { value: { $id: wrong ? 'guest' : 'owner', email: 'owner@portable.invalid' } };
      if (route === '/account/jwt') return { value: { jwt: 'synthetic.only.jwt' } };
      return { value: {} };
    } });
  await assert.rejects(make(true).login('owner', { email: 'owner@portable.invalid', password: 'synthetic' }), /OBSERVER_AUTH_IDENTITY_BINDING/);
  assert.equal(calls.includes('/account/jwt'), false);
  await make(false).login('owner', { email: 'owner@portable.invalid', password: 'synthetic' });
  assert.equal(calls.includes('/account/jwt'), true);
});

test('SQL observer requires exact caller, tenant, project, run and Temporal identity', () => {
  const binding = assertRunReadback(row, options);
  assert.equal(binding.state, 'succeeded');
  assert.equal(binding.firstExecutionRef, 'temporal-first-run');
  assert.equal(binding.terminalResultDigest, hash(canonical(row.terminal_result)));
  assert.equal(assertRunReadback({ ...row, terminal_result: { ...row.terminal_result, plan_digest: 'sha256:' + 'e'.repeat(64) } }, options).terminalResultDigest === binding.terminalResultDigest, false);
  for (const key of ['tenant_id', 'caller_principal_id', 'project_id', 'run_id', 'engine_id']) {
    assert.throws(() => assertRunReadback({ ...row, [key]: 'forged' }, options), /OBSERVER_SQL_RUN_BINDING/);
  }
  assert.throws(() => assertRunReadback({ ...row, workflow_id: '' }, options), /OBSERVER_SQL_ENGINE_BINDING/);
});

test('SQL observer rejects fake successful stdout without durable terminal result and engine chain', () => {
  for (const key of ['terminal_receipt', 'first_execution_ref', 'terminal_proof', 'terminal_result']) {
    assert.throws(() => assertRunReadback({ ...row, [key]: null }, options), /OBSERVER_SQL_RESULT_NOT_DURABLE/);
  }
  assert.throws(() => assertRunReadback({ ...row, terminal_result: { output: 'fake receipt' } }, options), /OBSERVER_SQL_RESULT_NOT_DURABLE/);
  assert.throws(() => assertRunReadback({ ...row, step_output_ref: { ...row.step_output_ref, digest: 'sha256:' + '0'.repeat(64) } }, options), /OBSERVER_SQL_RESULT_NOT_DURABLE/);
  assert.throws(() => assertRunReadback({ ...row, state: 'running' }, options), /OBSERVER_SQL_RESULT_NOT_DURABLE/);
});

test('result nonce must be the exact input.text value, not unrelated fields or a substring', () => {
  for (const resultValue of [{ value: 'WRONG', debug: options.value }, { value: options.value + '_suffix' }, { value: 'prefix_' + options.value }, { output: options.value }]) {
    const forged = { ...row, step_output_ref: { ...row.step_output_ref, digest: hash(canonical(resultValue)), size_bytes: Buffer.byteLength(canonical(resultValue)) } };
    assert.throws(() => assertRunReadback(forged, { ...options, resultValue }), /OBSERVER_SQL_RESULT_NOT_DURABLE/);
  }
});

test('queued recovery assertion requires accepted durable run and no terminal receipt', () => {
  const queued = { ...row, state: 'accepted', terminal_receipt: null, first_execution_ref: null, terminal_proof: null, terminal_result: null };
  assert.equal(assertRunReadback(queued, { ...options, queued: true }).state, 'accepted');
  assert.throws(() => assertRunReadback(row, { ...options, queued: true }), /OBSERVER_SQL_QUEUE_NOT_DURABLE/);
  assert.throws(() => assertRunReadback({ ...queued, terminal_receipt: {} }, { ...options, queued: true }), /OBSERVER_SQL_QUEUE_NOT_DURABLE/);
  assert.throws(() => assertRunReadback({ ...queued, first_execution_ref: 'already-started' }, { ...options, queued: true }), /OBSERVER_SQL_QUEUE_NOT_DURABLE/);
});

test('observer refuses foreign scope and malformed bindings before HTTP/Docker side effects', async () => {
  await assert.rejects(observePortableProduct({ state: { project: 'foreign' }, credentials: {} }), /OBSERVER_FRESH_SCOPE_REQUIRED/);
  await assert.rejects(observePortableProduct({ state: { project: 'sm9-owned-observer' }, credentials: { projectId: "'; DROP TABLE x;--" },
    docker: () => assert.fail('must not call Docker') }), /OBSERVER_BINDING_ID_INVALID/);
});

test('trusted observer imports no candidate runtime, legacy lab, private file or shell process', async () => {
  const files = ['product-client.mjs', 'product-observer.mjs'];
  for (const file of files) {
    const source = await fs.readFile(new URL(file, import.meta.url), 'utf8');
    const imports = [...source.matchAll(/from ['"]([^'"]+)['"]/g)].map(match => match[1]);
    assert.ok(imports.every(value => value.startsWith('node:') || value === './product-client.mjs'));
    assert.equal(/node:child_process|import\(|readFile\(|appwrite\.private|dev\/labs/.test(source), false);
  }
});
