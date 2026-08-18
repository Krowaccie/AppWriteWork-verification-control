import { types as utilTypes } from 'node:util';

import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };

const SCENARIO_IDS = Object.freeze([
  'public-smoke',
  'auth',
  'project-lifecycle',
  'graph-editor',
  'runtime',
  'sharing-permissions',
]);
const REQUEST_KEYS = Object.freeze([
  'controllerRevision',
  'identities',
  'origin',
  'scenarioId',
]);
const IDENTITY_KEYS = Object.freeze([
  'ownerEmail',
  'ownerPassword',
  'editorEmail',
  'viewerEmail',
]);
const FULL_SHA = /^[0-9a-f]{40}$/u;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;
const CONTROL = /[\u0000-\u001f\u007f]/u;

function exactDataObject(value, keys) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || utilTypes.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Object.getOwnPropertySymbols(value).length !== 0
  ) return false;
  const names = Object.getOwnPropertyNames(value).sort();
  const expected = [...keys].sort();
  return names.length === expected.length
    && names.every((name, index) => name === expected[index])
    && names.every((name) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      return descriptor !== undefined
        && Object.hasOwn(descriptor, 'value')
        && descriptor.enumerable === true;
    });
}

function validOptionalEmail(value) {
  return value === null || (
    typeof value === 'string'
    && value.length <= 320
    && EMAIL.test(value)
    && !CONTROL.test(value)
  );
}

function validRequest(value) {
  if (!exactDataObject(value, REQUEST_KEYS)) return false;
  const identities = value.identities;
  if (
    !exactDataObject(identities, IDENTITY_KEYS)
    || !SCENARIO_IDS.includes(value.scenarioId)
    || !FULL_SHA.test(value.controllerRevision)
    || value.origin !== inventory.environment.publicOrigin
    || !validOptionalEmail(identities.ownerEmail)
    || !validOptionalEmail(identities.editorEmail)
    || !validOptionalEmail(identities.viewerEmail)
    || !(identities.ownerPassword === null || (
      typeof identities.ownerPassword === 'string'
      && identities.ownerPassword.length >= 1
      && identities.ownerPassword.length <= 4096
      && !CONTROL.test(identities.ownerPassword)
    ))
  ) return false;
  if (value.scenarioId === 'public-smoke') {
    return Object.values(identities).every((entry) => entry === null);
  }
  if (value.scenarioId === 'auth') {
    return identities.ownerEmail !== null
      && identities.ownerPassword !== null
      && identities.editorEmail === null
      && identities.viewerEmail === null;
  }
  return Object.values(identities).every((entry) => entry === null);
}

function transcript(scenarioId, status) {
  return Object.freeze({
    schemaVersion: 'test-cloud-playwright-scenario-result.v1',
    scenarioId,
    status,
  });
}

async function exactLocator(locator, needs = []) {
  if (
    locator === null
    || typeof locator !== 'object'
    || await locator.count() !== 1
    || await locator.isVisible() !== true
  ) return false;
  if (needs.includes('enabled') && await locator.isEnabled() !== true) return false;
  if (needs.includes('editable') && await locator.isEditable() !== true) return false;
  return true;
}

async function proveLoginSurface(page) {
  const email = page.locator('#appwritework-login-email');
  const password = page.locator('#appwritework-login-password');
  const submit = page.getByRole('button', { name: 'Login', exact: true });
  return await exactLocator(email, ['enabled', 'editable'])
    && await exactLocator(password, ['enabled', 'editable'])
    && await exactLocator(submit, ['enabled']);
}

async function loginOwner(page, identities) {
  if (!await proveLoginSurface(page)) return false;
  const email = page.locator('#appwritework-login-email');
  const password = page.locator('#appwritework-login-password');
  const submit = page.getByRole('button', { name: 'Login', exact: true });
  await email.fill(identities.ownerEmail);
  await password.fill(identities.ownerPassword);
  await submit.click();
  return exactLocator(
    page.getByRole('button', { name: 'Open user menu', exact: true }),
    ['enabled'],
  );
}

async function logoutOwner(page) {
  const menu = page.getByRole('button', { name: 'Open user menu', exact: true });
  if (!await exactLocator(menu, ['enabled'])) return false;
  await menu.click();
  const logout = page.getByRole('button', { name: 'Logout', exact: true });
  if (!await exactLocator(logout, ['enabled'])) return false;
  await logout.click();
  return proveLoginSurface(page);
}

async function runAuthScenario(page, identities) {
  if (!await loginOwner(page, identities)) return false;
  if (!await logoutOwner(page)) return false;
  if (!await loginOwner(page, identities)) return false;
  return logoutOwner(page);
}

async function runScenario(page, request) {
  const response = await page.goto(request.origin, {
    waitUntil: 'load',
    timeout: 5_000,
  });
  if (
    response === null
    || typeof response !== 'object'
    || response.status() !== 200
    || new URL(response.url()).origin !== request.origin
  ) return false;
  if (request.scenarioId === 'public-smoke') return proveLoginSurface(page);
  if (request.scenarioId === 'auth') {
    return runAuthScenario(page, request.identities);
  }
  return false;
}

function allowedNetworkOrigin(rawUrl, requestOrigin) {
  try {
    const origin = new URL(rawUrl).origin;
    return origin === requestOrigin || origin === new URL(inventory.environment.endpoint).origin;
  } catch {
    return false;
  }
}

async function installNetworkPolicy(context, requestOrigin) {
  await context.route('**/*', async (route) => {
    const request = route.request();
    if (allowedNetworkOrigin(request.url(), requestOrigin)) {
      await route.continue();
    } else {
      await route.abort('blockedbyclient');
    }
  });
  await context.routeWebSocket('**/*', (socket) => socket.close());
}

export async function runTrustedContainedBrowserScenario(request) {
  const scenarioId = exactDataObject(request, REQUEST_KEYS)
    && SCENARIO_IDS.includes(request.scenarioId)
    ? request.scenarioId
    : 'public-smoke';
  if (!validRequest(request)) return transcript(scenarioId, 'FAIL');

  let browser;
  let context;
  let passed = false;
  try {
    const playwright = await import('playwright');
    if (
      playwright === null
      || typeof playwright !== 'object'
      || playwright.chromium === null
      || typeof playwright.chromium !== 'object'
      || typeof playwright.chromium.launch !== 'function'
    ) return transcript(request.scenarioId, 'FAIL');
    browser = await playwright.chromium.launch({ headless: true });
    context = await browser.newContext({
      acceptDownloads: false,
      serviceWorkers: 'block',
    });
    await installNetworkPolicy(context, request.origin);
    const page = await context.newPage();
    passed = await runScenario(page, request);
  } catch {
    passed = false;
  } finally {
    try {
      if (context !== undefined) await context.close();
    } catch {
      passed = false;
    }
    try {
      if (browser !== undefined) await browser.close();
    } catch {
      passed = false;
    }
  }
  return transcript(request.scenarioId, passed ? 'PASS' : 'FAIL');
}
