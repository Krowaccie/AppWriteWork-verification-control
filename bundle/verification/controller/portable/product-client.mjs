import https from 'node:https';
import { createHash } from 'node:crypto';

const MAX_BYTES = 1024 * 1024;
export const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export function requireThat(value, code) { if (!value) throw new Error(code); }
export const canonical = value => Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
  : value !== null && typeof value === 'object'
    ? '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
    : JSON.stringify(value);
export const hash = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export function operation(label, kind, payload, { revision, tenant, caller, scope = 'authoring', selector } = {}) {
  requireThat(/^[A-Za-z0-9_-]{1,100}$/.test(label), 'OBSERVER_OPERATION_ID_INVALID');
  return { contract: 'salmora.operation.v1', operationId: 'm1_' + label, operationKind: kind,
    idempotency: { scope, key: 'm1_' + label, payloadDigest: hash(canonical(payload)) }, payload,
    ...(revision === undefined ? {} : { expectedRevision: revision }),
    ...(tenant ? { tenantId: tenant, callerPrincipalId: caller } : {}),
    ...(selector ? { requestedTenantId: selector } : {}) };
}

// Only the driver's fresh local endpoint and public CA cross this boundary.
// Bodies/cookies/JWTs are never included in errors or public observations.
export function localApi(endpoint, ca, base = {}, { transport = https.request, timeout = 60_000 } = {}) {
  requireThat(/^https:\/\/localhost:[1-9][0-9]{0,4}\/v1$/.test(endpoint)
    && Number(new URL(endpoint).port) <= 65535, 'OBSERVER_LOCAL_HTTPS_REQUIRED');
  requireThat(Buffer.isBuffer(ca) && ca.length > 0 && !ca.toString().includes('PRIVATE KEY'), 'OBSERVER_PUBLIC_CA_REQUIRED');
  return async (method, route, body) => {
    requireThat(['GET', 'POST', 'DELETE', 'PATCH', 'PUT'].includes(method)
      && /^\/[A-Za-z0-9_/?=&%.$-]*$/.test(route) && !route.startsWith('//')
      && !/%2e|%2f|%5c/i.test(route) && !route.includes('..'), 'OBSERVER_ROUTE_INVALID');
    const bytes = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    requireThat(!bytes || bytes.length <= MAX_BYTES, 'OBSERVER_REQUEST_LIMIT');
    return new Promise((resolve, reject) => {
      const request = transport(endpoint + route, { method, ca, rejectUnauthorized: true, timeout,
        headers: { ...base, ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}) } }, response => {
        const chunks = []; let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > MAX_BYTES) { request.destroy(new Error('OBSERVER_RESPONSE_LIMIT')); return; }
          chunks.push(chunk);
        });
        response.on('error', () => reject(new Error('OBSERVER_RESPONSE_TRANSPORT_FAILED')));
        response.on('end', () => {
          if (length > MAX_BYTES) return reject(new Error('OBSERVER_RESPONSE_LIMIT'));
          let value;
          try { value = response.statusCode === 204 && length === 0 ? null : JSON.parse(Buffer.concat(chunks).toString('utf8')); }
          catch { return reject(new Error('OBSERVER_RESPONSE_JSON_REQUIRED')); }
          if (response.statusCode < 200 || response.statusCode >= 300) {
            const error = new Error('OBSERVER_HTTP_' + response.statusCode);
            error.status = response.statusCode; return reject(error);
          }
          resolve({ value, status: response.statusCode, fallbackCookies: response.headers['x-fallback-cookies'] });
        });
      });
      request.on('timeout', () => request.destroy(new Error('OBSERVER_HTTP_TIMEOUT')));
      request.on('error', error => reject(new Error(/^OBSERVER_[A-Z_]+$/.test(error.message) ? error.message : 'OBSERVER_HTTP_TRANSPORT_FAILED')));
      request.end(bytes);
    });
  };
}

export function validateExecution(execution, id, body, { status = 200, code, envelope = true } = {}) {
  requireThat(execution?.$id === id && typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id), 'OBSERVER_EXECUTION_ID_DRIFT');
  requireThat(execution.status === 'completed', 'OBSERVER_EXECUTION_NOT_COMPLETED');
  requireThat((Array.isArray(status) ? status : [status]).includes(execution.responseStatusCode), 'OBSERVER_EXECUTION_HTTP_MISMATCH');
  requireThat(typeof execution.responseBody === 'string' && Buffer.byteLength(execution.responseBody) <= MAX_BYTES, 'OBSERVER_EXECUTION_BODY_LIMIT');
  let response;
  try { response = JSON.parse(execution.responseBody); } catch { throw new Error('OBSERVER_EXECUTION_JSON_REQUIRED'); }
  if (code) requireThat((response.error?.code ?? response.errorCode ?? response.code ?? response.error) === code, 'OBSERVER_DENIAL_CODE_MISMATCH');
  else if (envelope) requireThat(response.contract === 'salmora.operation-result.v1'
    && response.operationId === body.operationId && response.status === 'succeeded', 'OBSERVER_OPERATION_BINDING_MISMATCH');
  return response;
}

export function executionClient({ operator, functions, checks, timeout = 120_000, delay = pause }) {
  return async (label, component, client, body, options = {}) => {
    const functionId = functions?.[component]?.functionId;
    requireThat(typeof functionId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(functionId), 'OBSERVER_FUNCTION_ID_INVALID');
    const route = '/functions/' + functionId + '/executions';
    const primary = await client('POST', route, { body: JSON.stringify(body), async: false, path: '/', method: 'POST',
      headers: { 'content-type': 'application/json' } });
    const id = primary.value?.$id;
    requireThat(typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id), 'OBSERVER_EXECUTION_ID_REQUIRED');
    let execution = primary.value, visibilityRetry = false;
    const deadline = Date.now() + timeout;
    while (!['completed', 'failed'].includes(execution.status)) {
      requireThat(Date.now() < deadline, 'OBSERVER_EXECUTION_TIMEOUT');
      await delay(500);
      try { execution = (await operator('GET', route + '/' + id)).value; }
      catch (error) { if (error.status === 404 && !visibilityRetry) { visibilityRetry = true; continue; } throw error; }
      requireThat(execution?.$id === id, 'OBSERVER_EXECUTION_ID_DRIFT');
    }
    const result = validateExecution(execution, id, body, options);
    checks.push({ label, component, executionId: id, status: 'PASS', responseStatus: options.status ?? 200 });
    return result;
  };
}

export function connect({ state, credentials, ca, checks, api = localApi }) {
  const base = { 'x-appwrite-project': credentials.projectId };
  const anonymous = api(state.endpoint, ca, base);
  const operator = api(state.endpoint, ca, { ...base, 'x-appwrite-key': credentials.apiKey });
  const sessions = [];
  return { anonymous, operator, invoke: executionClient({ operator, functions: state.product.functions, checks }),
    login: async (id, user) => {
      const session = await anonymous('POST', '/account/sessions/email', user);
      requireThat(session.value?.userId === id && typeof session.fallbackCookies === 'string' && session.fallbackCookies.length > 0, 'OBSERVER_AUTH_SESSION_BINDING');
      const account = api(state.endpoint, ca, { ...base, 'x-fallback-cookies': session.fallbackCookies }); sessions.push(account);
      const identity = (await account('GET', '/account')).value;
      requireThat(identity.$id === id && identity.email === user.email, 'OBSERVER_AUTH_IDENTITY_BINDING');
      const jwt = (await account('POST', '/account/jwt', {})).value?.jwt;
      requireThat(typeof jwt === 'string' && jwt.split('.').length === 3, 'OBSERVER_AUTH_JWT_REQUIRED');
      checks.push({ label: 'real-auth-' + id, status: 'PASS' });
      return api(state.endpoint, ca, { ...base, 'x-appwrite-jwt': jwt });
    }, close: async () => { for (const session of sessions) await session('DELETE', '/account/sessions/current'); } };
}
