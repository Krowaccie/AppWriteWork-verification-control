import { executeClosedPublicRead } from './production-readonly-environment.mjs';

const ALLOWED_PATHS = new Set([
  '/',
  '/build-identity.json',
  '/salmora-mark.svg',
  '/theme-init.js',
]);
const EXACT_ORIGIN = 'https://salmora.net';

function blocked() {
  const error = new Error('Production public read blocked.');
  error.code = 'PRODUCTION_READONLY_HTTP_BLOCKED';
  return error;
}

function authenticTarget(target) {
  try {
    return (
      typeof target === 'function'
      && Object.isFrozen(target)
      && typeof target.path === 'string'
      && ALLOWED_PATHS.has(target.path)
      && Object.getOwnPropertySymbols(target).length === 0
    );
  } catch {
    return false;
  }
}

async function request(method, target) {
  if (!authenticTarget(target)) throw blocked();
  let expected;
  try {
    expected = new URL(target.path, EXACT_ORIGIN);
  } catch {
    throw blocked();
  }
  if (
    expected.protocol !== 'https:'
    || expected.origin !== EXACT_ORIGIN
    || expected.username !== ''
    || expected.password !== ''
    || expected.search !== ''
    || expected.hash !== ''
    || !ALLOWED_PATHS.has(expected.pathname)
    || /%2f|%5c/i.test(expected.pathname)
  ) {
    throw blocked();
  }

  let response;
  try {
    response = await executeClosedPublicRead(target, method);
  } catch {
    throw blocked();
  }
  if (
    response === null
    || typeof response !== 'object'
    || response.ok !== true
    || response.status !== 200
    || response.redirected === true
    || response.url !== expected.href
    || response.headers?.has?.('set-cookie') === true
  ) {
    throw blocked();
  }

  let body = null;
  if (method === 'GET') {
    try {
      body = expected.pathname === '/build-identity.json'
        ? await response.json()
        : await response.text();
    } catch {
      throw blocked();
    }
  }
  return Object.freeze({ body, status: response.status, url: expected.href });
}

export function get(target) {
  return request('GET', target);
}

export function head(target) {
  return request('HEAD', target);
}
