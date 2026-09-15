import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const STATE_KEY = Symbol.for('appwritework.test-cloud.contained-browser-adapter-test.v1');
const ADAPTER_SUFFIX = '/test-cloud-contained-browser-scenario-adapter.mjs';
const playwrightModule = `
export const chromium = Object.freeze({
  launch(options) {
    return globalThis[
      Symbol.for('appwritework.test-cloud.contained-browser-adapter-test.v1')
    ].launch(options);
  },
});
`;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'playwright' && context.parentURL?.endsWith(ADAPTER_SUFFIX)) {
      return {
        url: `data:text/javascript,${encodeURIComponent(playwrightModule)}`,
        shortCircuit: true,
      };
    }
    return nextResolve(specifier, context);
  },
});

function createPlaywrightState({ responseStatus = 200 } = {}) {
  const calls = [];
  const locator = (name) => ({
    async count() { calls.push(['locator.count', name]); return 1; },
    async isVisible() { calls.push(['locator.isVisible', name]); return true; },
    async isEnabled() { calls.push(['locator.isEnabled', name]); return true; },
    async isEditable() { calls.push(['locator.isEditable', name]); return true; },
    async fill(value) { calls.push(['locator.fill', name, value]); },
    async click() { calls.push(['locator.click', name]); },
  });
  const page = {
    async goto(url, options) {
      calls.push(['goto', url, options]);
      return Object.freeze({
        status: () => responseStatus,
        url: () => `${url}/`,
      });
    },
    locator(selector) { calls.push(['locator', selector]); return locator(`locator:${selector}`); },
    getByRole(role, options) {
      calls.push(['getByRole', role, options]);
      return locator(`role:${role}:${options.name}`);
    },
  };
  const context = {
    async route(pattern, handler) { calls.push(['route', pattern, typeof handler]); },
    async routeWebSocket(pattern, handler) {
      calls.push(['routeWebSocket', pattern, typeof handler]);
    },
    async newPage() { calls.push('newPage'); return page; },
    async close() { calls.push('context.close'); },
  };
  const browser = {
    async newContext(options) { calls.push(['newContext', options]); return context; },
    async close() { calls.push('browser.close'); },
  };
  return {
    calls,
    async launch(options) { calls.push(['launch', options]); return browser; },
  };
}

function request(scenarioId = 'public-smoke') {
  const credentialed = scenarioId === 'auth';
  return Object.freeze({
    controllerRevision: '0123456789abcdef0123456789abcdef01234567',
    identities: Object.freeze(Object.assign(Object.create(null), {
      ownerEmail: credentialed ? 'owner@example.test' : null,
      ownerPassword: credentialed ? 'owner-password-for-test' : null,
      editorEmail: null,
      viewerEmail: null,
    })),
    origin: 'https://appwritework.appwrite.network',
    scenarioId,
  });
}

test('trusted contained browser adapter requires real Playwright calls before PASS', async () => {
  const state = createPlaywrightState();
  globalThis[STATE_KEY] = state;
  const { runTrustedContainedBrowserScenario } = await import(
    './test-cloud-contained-browser-scenario-adapter.mjs'
  );

  const transcript = await runTrustedContainedBrowserScenario(request());

  assert.deepEqual(transcript, {
    schemaVersion: 'test-cloud-playwright-scenario-result.v1',
    scenarioId: 'public-smoke',
    status: 'PASS',
  });
  assert.deepEqual(state.calls[0], ['launch', { headless: true }]);
  assert.ok(state.calls.some((call) => Array.isArray(call) && call[0] === 'goto'));
  assert.ok(state.calls.some((call) => call[0] === 'locator.count'));
  assert.deepEqual(state.calls.slice(-2), ['context.close', 'browser.close']);
});

test('trusted contained browser adapter completes the exact owner login logout fresh-login cycle', async () => {
  const state = createPlaywrightState();
  globalThis[STATE_KEY] = state;
  const { runTrustedContainedBrowserScenario } = await import(
    './test-cloud-contained-browser-scenario-adapter.mjs'
  );

  const transcript = await runTrustedContainedBrowserScenario(request('auth'));

  assert.deepEqual(transcript, {
    schemaVersion: 'test-cloud-playwright-scenario-result.v1',
    scenarioId: 'auth',
    status: 'PASS',
  });
  assert.equal(
    state.calls.filter((call) => call[0] === 'locator.click' && call[1] === 'role:button:Login').length,
    2,
  );
  assert.equal(
    state.calls.filter((call) => call[0] === 'locator.click' && call[1] === 'role:button:Logout').length,
    2,
  );
  assert.equal(
    state.calls.filter((call) => call[0] === 'locator.fill' && call[1] === 'locator:#appwritework-login-email').length,
    2,
  );
});

test('trusted contained browser adapter fails closed for mutation scenarios without provider registry authority', async () => {
  for (const scenarioId of [
    'project-lifecycle',
    'graph-editor',
    'runtime',
    'sharing-permissions',
  ]) {
    const state = createPlaywrightState();
    globalThis[STATE_KEY] = state;
    const { runTrustedContainedBrowserScenario } = await import(
      './test-cloud-contained-browser-scenario-adapter.mjs'
    );

    const transcript = await runTrustedContainedBrowserScenario(request(scenarioId));

    assert.deepEqual(transcript, {
      schemaVersion: 'test-cloud-playwright-scenario-result.v1',
      scenarioId,
      status: 'FAIL',
    });
    assert.equal(
      state.calls.some(
        (call) => call[0] === 'getByRole' && call[2]?.name === 'New Project',
      ),
      false,
    );
    assert.equal(
      state.calls.filter((call) => Array.isArray(call) && call[0] === 'launch').length,
      1,
    );
  }
});

test('trusted contained browser adapter emits FAIL when the browser scenario fails', async () => {
  const state = createPlaywrightState({ responseStatus: 503 });
  globalThis[STATE_KEY] = state;
  const { runTrustedContainedBrowserScenario } = await import(
    './test-cloud-contained-browser-scenario-adapter.mjs'
  );

  const transcript = await runTrustedContainedBrowserScenario(request());

  assert.deepEqual(transcript, {
    schemaVersion: 'test-cloud-playwright-scenario-result.v1',
    scenarioId: 'public-smoke',
    status: 'FAIL',
  });
  assert.equal(state.calls.filter((call) => Array.isArray(call) && call[0] === 'launch').length, 1);
  assert.deepEqual(state.calls.slice(-2), ['context.close', 'browser.close']);
});

test.after(() => {
  Reflect.deleteProperty(globalThis, STATE_KEY);
});
