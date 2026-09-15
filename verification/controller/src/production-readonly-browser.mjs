import { createHash } from 'node:crypto';

const BLOCKED_TYPES = new Set([
  'beacon',
  'eventsource',
  'serviceworker',
  'websocket',
]);
const ASSET_PATH_PATTERN = '^/assets/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{6,}\\.(?:css|js|mjs|woff2?|ttf|otf|png|jpe?g|gif|svg|webp|ico)$';
const POLICY_KEYS = Object.freeze([
  'assetPathPattern',
  'origin',
  'paths',
  'queryKeys',
  'schemaVersion',
]);

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function hasExactPolicyKeys(policy) {
  return (
    policy !== null
    && typeof policy === 'object'
    && !Array.isArray(policy)
    && JSON.stringify(Object.keys(policy).sort()) === JSON.stringify(POLICY_KEYS)
  );
}

function validPolicy(policy) {
  return (
    hasExactPolicyKeys(policy)
    && policy.schemaVersion === 'production-browser-policy.v1'
    && policy.origin === 'https://salmora.net'
    && Array.isArray(policy.paths)
    && JSON.stringify(policy.paths) === JSON.stringify(['/', '/build-identity.json', '/salmora-mark.svg', '/theme-init.js'])
    && policy.assetPathPattern === ASSET_PATH_PATTERN
    && Array.isArray(policy.queryKeys)
    && policy.queryKeys.length === 0
  );
}

export const productionBrowserPolicy = deepFreeze({
  schemaVersion: 'production-browser-policy.v1',
  origin: 'https://salmora.net',
  paths: ['/', '/build-identity.json', '/salmora-mark.svg', '/theme-init.js'],
  assetPathPattern: ASSET_PATH_PATTERN,
  queryKeys: [],
});

export function validateProductionBrowserPolicy(policy) {
  return validPolicy(policy);
}

function allowedPath(policy, pathname) {
  return policy.paths.includes(pathname) || new RegExp(policy.assetPathPattern, 'u').test(pathname);
}

export function evaluateProductionRequest(policy, request) {
  let allowed = false;
  try {
    if (!validPolicy(policy)) return deepFreeze({ allowed: false });
    const method = request?.method;
    if (!['GET', 'HEAD'].includes(method)) return deepFreeze({ allowed: false });
    if (request.body !== undefined && request.body !== null && request.body !== '') return deepFreeze({ allowed: false });
    if (request.postData !== undefined && request.postData !== null && request.postData !== '') return deepFreeze({ allowed: false });
    if (BLOCKED_TYPES.has(String(request.resourceType ?? '').toLowerCase())) return deepFreeze({ allowed: false });
    const headers = request.headers ?? {};
    if (Object.keys(headers).some((name) => ['authorization', 'cookie'].includes(name.toLowerCase()))) {
      return deepFreeze({ allowed: false });
    }
    const url = new URL(request.url);
    if (
      url.protocol !== 'https:'
      || url.origin !== policy.origin
      || url.username !== ''
      || url.password !== ''
      || url.hash !== ''
      || /%2f|%5c/i.test(url.pathname)
      || !allowedPath(policy, url.pathname)
    ) return deepFreeze({ allowed: false });
    if ([...url.searchParams.keys()].some((key) => !policy.queryKeys.includes(key))) {
      return deepFreeze({ allowed: false });
    }
    allowed = true;
  } catch {
    allowed = false;
  }
  return deepFreeze({ allowed });
}

function requestShape(request) {
  return {
    method: request.method(),
    url: request.url(),
    postData: request.postData?.(),
    resourceType: request.resourceType?.(),
    headers: request.headers?.(),
  };
}

async function inspectResponse(policy, response, failures, probes, phaseProbes = null) {
  try {
    const status = response?.status?.();
    if (status !== 200) failures.add('RESPONSE_STATUS_BLOCKED');
    const request = response?.request?.();
    if (request?.redirectedFrom?.()) failures.add('REDIRECT_BLOCKED');
    const url = response?.url?.();
    const method = request?.method?.() ?? 'GET';
    if (!evaluateProductionRequest(policy, { method, url }).allowed) {
      failures.add('RESPONSE_URL_BLOCKED');
    }
    const headers = await response?.headers?.();
    if (
      headers === null
      || typeof headers !== 'object'
      || Object.keys(headers).some((name) => name.toLowerCase() === 'set-cookie')
    ) failures.add('SET_COOKIE_BLOCKED');

    let body;
    try {
      body = await response?.body?.();
    } catch {
      failures.add('RESPONSE_BODY_INVALID');
      return;
    }
    if (!(body instanceof Uint8Array)) {
      failures.add('RESPONSE_BODY_INVALID');
      return;
    }
    const parsed = new URL(url);
    const key = `${method}:${parsed.pathname}`;
    const probe = Object.freeze({
      digest: `sha256:${createHash('sha256').update(body).digest('hex')}`,
      method,
      path: parsed.pathname,
      status,
    });
    probes.set(key, probe);
    phaseProbes?.set(key, probe);
  } catch {
    failures.add('RESPONSE_INVALID');
  }
}

export function createProductionReadonlyBrowser({ browserFactory, policy } = {}) {
  const run = async () => {
    if (!validPolicy(policy) || typeof browserFactory?.newContext !== 'function') {
      return deepFreeze({ status: 'BLOCKED', diagnostics: [{ code: 'PRODUCTION_BROWSER_POLICY_INVALID' }] });
    }
    const failures = new Set();
    const probes = new Map();
    const rootLoadProbes = new Map();
    const responseChecks = [];
    let rootLoadInProgress = true;
    let context;
    try {
      context = await browserFactory.newContext({
        acceptDownloads: false,
        serviceWorkers: 'block',
        storageState: undefined,
      });
      await context.route('**/*', async (route) => {
        const decision = evaluateProductionRequest(policy, requestShape(route.request()));
        if (decision.allowed) await route.continue();
        else {
          failures.add('REQUEST_BLOCKED');
          await route.abort('blockedbyclient');
        }
      });
      await context.routeWebSocket(/.*/, async (webSocketRoute) => {
        failures.add('WEBSOCKET_BLOCKED');
        await webSocketRoute.close();
      });
      const page = await context.newPage();
      page.on('console', (message) => {
        if (message.type?.() === 'error') failures.add('CONSOLE_ERROR');
      });
      page.on('pageerror', () => failures.add('PAGE_ERROR'));
      page.on('requestfailed', () => failures.add('REQUEST_FAILED'));
      page.on('popup', (popup) => {
        failures.add('POPUP_BLOCKED');
        void popup.close?.();
      });
      page.on('download', (download) => {
        failures.add('DOWNLOAD_BLOCKED');
        void download.cancel?.();
      });
      page.on('response', (response) => {
        responseChecks.push(inspectResponse(
          policy,
          response,
          failures,
          probes,
          rootLoadInProgress ? rootLoadProbes : null,
        ));
      });

      const response = await page.goto(`${policy.origin}/`, { waitUntil: 'load' });
      rootLoadInProgress = false;
      await inspectResponse(policy, response, failures, probes, rootLoadProbes);
      await page.evaluate(async (paths) => {
        await Promise.all(paths.map(async (pathname) => {
          const probe = await fetch(pathname, {
            method: 'GET',
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-store',
          });
          await probe.arrayBuffer();
        }));
      }, policy.paths.filter((pathname) => pathname !== '/'));
      await Promise.all(responseChecks);

      const contentProbes = [...probes.values()].sort((left, right) => (
        left.path.localeCompare(right.path) || left.method.localeCompare(right.method)
      ));
      const observedPaths = new Set(contentProbes.map(({ path: pathname }) => pathname));
      if (policy.paths.some((pathname) => !observedPaths.has(pathname))) {
        failures.add('REQUIRED_PATH_MISSING');
      }
      const assetPattern = new RegExp(policy.assetPathPattern, 'u');
      if (![...rootLoadProbes.values()].some(({ path: pathname }) => assetPattern.test(pathname))) {
        failures.add('REQUIRED_ASSET_MISSING');
      }

      const cookies = await context.cookies();
      if (!Array.isArray(cookies) || cookies.length !== 0) failures.add('COOKIE_STATE_BLOCKED');
      return deepFreeze({
        status: failures.size === 0 ? 'PASS' : 'BLOCKED',
        contentProbes,
        diagnostics: [...failures].map((code) => ({ code })),
      });
    } catch {
      return deepFreeze({ status: 'BLOCKED', diagnostics: [{ code: 'PRODUCTION_BROWSER_FAILED' }] });
    } finally {
      await context?.close?.();
    }
  };
  return Object.freeze({ run });
}
