import { createHash } from 'node:crypto';

import closedInventory from '../../../dev/verification/environments/production.inventory.v1.json' with {
  type: 'json',
};

const EXACT_ENVIRONMENT = Object.freeze({
  endpoint: 'https://api.salmora.net/v1',
  projectId: '69eb4818000afa64a7fa',
  siteId: '69eb4a020024c520642e',
  origin: 'https://salmora.net',
});
const READONLY_VARIABLE = 'APPWRITE_PRODUCTION_READONLY_API_KEY';
const FORBIDDEN_VARIABLES = Object.freeze([
  'APPWRITE_API_KEY',
  'APPWRITE_PRODUCTION_RELEASE_API_KEY',
]);
const EXACT_SCOPES = Object.freeze(['functions.read', 'sites.read']);
const ALLOWED_PUBLIC_PATHS = new Set([
  '/',
  '/build-identity.json',
  '/salmora-mark.svg',
  '/theme-init.js',
]);
const DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const APPWRITE_BINDINGS = new WeakMap();
const PUBLIC_BINDINGS = new WeakMap();

function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || seen.has(value)
  ) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) deepFreeze(descriptor.value, seen);
  }
  return Object.freeze(value);
}

deepFreeze(closedInventory);
export const productionInventory = closedInventory;

function blocked(code) {
  return Object.freeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: Object.freeze([
      Object.freeze({
        code,
        safeMessage: 'Production read-only prerequisites are not satisfied.',
        retryable: false,
      }),
    ]),
  });
}

function pass(value) {
  return Object.freeze({ status: 'PASS', value, diagnostics: Object.freeze([]) });
}

function exactJson(left, right) {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('unsupported value');
}

const ENVIRONMENT_DIGEST = `sha256:${createHash('sha256')
  .update(canonicalJson(productionInventory), 'utf8')
  .digest('hex')}`;
export const productionEnvironmentDigest = ENVIRONMENT_DIGEST;

function safeUrl(value, expected) {
  if (typeof value !== 'string' || value !== expected) return false;
  try {
    const parsed = new URL(value);
    return parsed.username === '' && parsed.password === '' && parsed.href === new URL(expected).href;
  } catch {
    return false;
  }
}

function validEnvironment(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  if (!exactJson(keys, ['endpoint', 'origin', 'projectId', 'siteId'])) return false;
  return (
    safeUrl(value.endpoint, EXACT_ENVIRONMENT.endpoint)
    && safeUrl(value.origin, EXACT_ENVIRONMENT.origin)
    && value.projectId === EXACT_ENVIRONMENT.projectId
    && value.siteId === EXACT_ENVIRONMENT.siteId
  );
}

function validCredentialSource(value) {
  if (value === null || typeof value !== 'object' || !Object.isFrozen(value)) return false;
  if (!Array.isArray(value.names) || !Object.isFrozen(value.names) || typeof value.read !== 'function') return false;
  if (
    value.names.length !== 1
    || value.names[0] !== READONLY_VARIABLE
    || value.names.some((name) => FORBIDDEN_VARIABLES.includes(name) || /^APPWRITE_TEST_/.test(name))
  ) {
    return false;
  }
  return true;
}

function validScopes(value) {
  return Array.isArray(value) && exactJson([...value].sort(), EXACT_SCOPES);
}

function safeSegment(value) {
  return (
    typeof value === 'string'
    && /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value)
    && !/%2f|%5c/i.test(value)
  );
}

function makeOpaqueTarget(fields, registry, binding) {
  const target = function productionReadonlyOpaqueTarget() {};
  for (const [key, value] of Object.entries(fields)) {
    Object.defineProperty(target, key, {
      configurable: false,
      enumerable: true,
      value,
      writable: false,
    });
  }
  registry.set(target, binding);
  return Object.freeze(target);
}

export async function executeClosedAppwriteRead(target, operation, deploymentId) {
  const binding = APPWRITE_BINDINGS.get(target);
  if (!binding || !safeSegment(binding.providerId)) throw safeError('PRODUCTION_READONLY_REQUEST_BLOCKED');

  let path;
  if (operation === 'site-metadata' && binding.kind === 'site' && deploymentId === undefined) {
    path = `/v1/sites/${binding.providerId}`;
  } else if (
    operation === 'site-deployment'
    && binding.kind === 'site'
    && DEPLOYMENT_ID.test(deploymentId)
  ) {
    path = `/v1/sites/${binding.providerId}/deployments/${deploymentId}`;
  } else if (
    operation === 'function-metadata'
    && binding.kind === 'function'
    && deploymentId === undefined
  ) {
    path = `/v1/functions/${binding.providerId}`;
  } else if (
    operation === 'function-deployment'
    && binding.kind === 'function'
    && DEPLOYMENT_ID.test(deploymentId)
  ) {
    path = `/v1/functions/${binding.providerId}/deployments/${deploymentId}`;
  } else {
    throw safeError('PRODUCTION_READONLY_REQUEST_BLOCKED');
  }

  const url = new URL(path, EXACT_ENVIRONMENT.endpoint);
  if (
    url.origin !== new URL(EXACT_ENVIRONMENT.endpoint).origin
    || url.search !== ''
    || url.hash !== ''
    || url.username !== ''
    || url.password !== ''
  ) throw safeError('PRODUCTION_READONLY_REQUEST_BLOCKED');

  return binding.fetchImpl(url.href, {
    method: 'GET',
    redirect: 'error',
    headers: {
      'X-Appwrite-Project': EXACT_ENVIRONMENT.projectId,
      'X-Appwrite-Key': binding.secret,
    },
  });
}

export async function executeClosedPublicRead(target, method) {
  const binding = PUBLIC_BINDINGS.get(target);
  if (!binding || !['GET', 'HEAD'].includes(method) || !ALLOWED_PUBLIC_PATHS.has(binding.path)) {
    throw safeError('PRODUCTION_READONLY_HTTP_BLOCKED');
  }
  const url = new URL(binding.path, EXACT_ENVIRONMENT.origin);
  if (
    url.protocol !== 'https:'
    || url.origin !== EXACT_ENVIRONMENT.origin
    || url.username !== ''
    || url.password !== ''
    || url.search !== ''
    || url.hash !== ''
    || !ALLOWED_PUBLIC_PATHS.has(url.pathname)
  ) throw safeError('PRODUCTION_READONLY_HTTP_BLOCKED');

  return binding.fetchImpl(url.href, {
    method,
    redirect: 'error',
    credentials: 'omit',
    headers: {},
  });
}

export function createProductionReadonlyEnvironment({
  credentialSource,
  environment,
  fetchImpl,
  inventory = productionInventory,
  scopes,
} = {}) {
  try {
    if (!exactJson(inventory, productionInventory)) return blocked('PRODUCTION_INVENTORY_INVALID');
    if (!validEnvironment(environment)) return blocked('PRODUCTION_IDENTITY_MISMATCH');
    if (!validScopes(scopes)) return blocked('PRODUCTION_SCOPE_ATTESTATION_MISMATCH');
    if (!validCredentialSource(credentialSource)) return blocked('PRODUCTION_CREDENTIAL_ISOLATION');
    if (typeof fetchImpl !== 'function') return blocked('PRODUCTION_TRANSPORT_INVALID');

    const secret = credentialSource.read(READONLY_VARIABLE);
    if (typeof secret !== 'string' || secret.length === 0) return blocked('PRODUCTION_CREDENTIAL_UNAVAILABLE');

    const siteTarget = makeOpaqueTarget({
      kind: 'site',
      logicalId: productionInventory.site.logicalId,
      providerId: EXACT_ENVIRONMENT.siteId,
    }, APPWRITE_BINDINGS, {
      fetchImpl,
      kind: 'site',
      providerId: EXACT_ENVIRONMENT.siteId,
      secret,
    });
    const functionTargets = Object.freeze(productionInventory.productFunctions.map((record) => makeOpaqueTarget({
      kind: 'function',
      logicalId: record.logicalId,
      providerId: record.functionId,
    }, APPWRITE_BINDINGS, {
      fetchImpl,
      kind: 'function',
      providerId: record.functionId,
      secret,
    })));
    const publicTargets = deepFreeze({
      root: makeOpaqueTarget({ path: '/' }, PUBLIC_BINDINGS, { fetchImpl, path: '/' }),
      buildIdentity: makeOpaqueTarget(
        { path: '/build-identity.json' },
        PUBLIC_BINDINGS,
        { fetchImpl, path: '/build-identity.json' },
      ),
      icon: makeOpaqueTarget(
        { path: '/salmora-mark.svg' },
        PUBLIC_BINDINGS,
        { fetchImpl, path: '/salmora-mark.svg' },
      ),
      themeInit: makeOpaqueTarget(
        { path: '/theme-init.js' },
        PUBLIC_BINDINGS,
        { fetchImpl, path: '/theme-init.js' },
      ),
    });

    return pass(deepFreeze({
      environmentClass: 'production-readonly',
      environmentDigest: ENVIRONMENT_DIGEST,
      environmentDigestSource: productionInventory,
      functionTargets,
      publicTargets,
      siteTarget,
    }));
  } catch {
    return blocked('PRODUCTION_READONLY_ENVIRONMENT_INVALID');
  }
}

function safeError(code) {
  const error = new Error('Production read-only request blocked.');
  error.code = code;
  return error;
}
