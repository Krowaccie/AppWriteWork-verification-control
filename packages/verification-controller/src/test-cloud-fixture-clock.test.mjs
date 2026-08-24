import assert from 'node:assert/strict';
import test from 'node:test';
import { Worker } from 'node:worker_threads';

import {
  readTestCloudRuntimeLifecycle,
} from '../../../scripts/verification/test-cloud-provider-contract.mjs';

import * as fixtureClock from './test-cloud-fixture-clock.mjs';

const BOOTSTRAP_HUB = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';

const EXPECTED_EXPORTS = Object.freeze([
  'advanceTestCloudFixtureClock',
  'authenticateTestCloudFixtureClock',
  'installTestCloudFixtureClock',
  'prepareTestCloudFixtureClock',
  'readTestCloudFixtureExpectedState',
  'registerTestCloudFixtureClockBootstrap',
  'sealTestCloudFixtureClock',
]);

const EXPECTED_FORBIDDEN = Object.freeze({
  status: 'BLOCKED',
  value: null,
  diagnostics: Object.freeze([
    Object.freeze({
      code: 'TEST_FIXTURE_CLOCK_FORBIDDEN',
      retryable: false,
      safeMessage: 'Fixture clock operation is not authorized.',
    }),
  ]),
});

function assertForbidden(value) {
  assert.deepEqual(value, EXPECTED_FORBIDDEN);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.diagnostics), true);
  assert.equal(Object.isFrozen(value.diagnostics[0]), true);
}

test('4C-pre: fixture clock exposes only the exact inert seven-export namespace', () => {
  assert.deepEqual(Object.keys(fixtureClock).sort(), EXPECTED_EXPORTS);
  assert.equal(readTestCloudRuntimeLifecycle(), 'EMPTY');
  assert.equal(Object.getOwnPropertyDescriptor(globalThis, BOOTSTRAP_HUB), undefined);

  assert.equal(fixtureClock.prepareTestCloudFixtureClock.length, 1);
  assert.equal(fixtureClock.installTestCloudFixtureClock.length, 1);
  assert.equal(fixtureClock.authenticateTestCloudFixtureClock.length, 1);
  assert.equal(fixtureClock.readTestCloudFixtureExpectedState.length, 1);
  assert.equal(fixtureClock.advanceTestCloudFixtureClock.length, 1);
  assert.equal(fixtureClock.sealTestCloudFixtureClock.length, 1);
  assert.equal(fixtureClock.registerTestCloudFixtureClockBootstrap.length, 0);
});

test('4C-pre: fixture clock operations remain non-activatable and do not inspect arguments', async () => {
  const forbiddenArgs = new Proxy({}, {
    get() {
      assert.fail('4C-pre fixture clock inspected caller data');
    },
    ownKeys() {
      assert.fail('4C-pre fixture clock enumerated caller data');
    },
    getOwnPropertyDescriptor() {
      assert.fail('4C-pre fixture clock inspected caller descriptors');
    },
  });

  assertForbidden(fixtureClock.prepareTestCloudFixtureClock(forbiddenArgs));
  assertForbidden(await fixtureClock.installTestCloudFixtureClock(forbiddenArgs));
  assertForbidden(await fixtureClock.authenticateTestCloudFixtureClock(forbiddenArgs));
  assertForbidden(fixtureClock.readTestCloudFixtureExpectedState(forbiddenArgs));
  assertForbidden(await fixtureClock.advanceTestCloudFixtureClock(forbiddenArgs));
  assertForbidden(await fixtureClock.sealTestCloudFixtureClock(forbiddenArgs));

  assert.equal(readTestCloudRuntimeLifecycle(), 'EMPTY');
  assert.equal(Object.getOwnPropertyDescriptor(globalThis, BOOTSTRAP_HUB), undefined);
});

test('4C-pre: fixture clock registrar outside BOOTSTRAPPING terminally blocks runtime', () => {
  assert.equal(readTestCloudRuntimeLifecycle(), 'EMPTY');
  assert.equal(fixtureClock.registerTestCloudFixtureClockBootstrap(), false);
  assert.equal(readTestCloudRuntimeLifecycle(), 'BLOCKED');
  assert.equal(fixtureClock.registerTestCloudFixtureClockBootstrap(), false);
  assert.equal(readTestCloudRuntimeLifecycle(), 'BLOCKED');
  assert.equal(Object.getOwnPropertyDescriptor(globalThis, BOOTSTRAP_HUB), undefined);
});

function runActiveWorker(scenario = 'happy') {
  const moduleUrl = new URL('./test-cloud-fixture-clock.mjs?active-worker', import.meta.url).href;
  const source = `
    import { registerHooks } from 'node:module';
    import { parentPort, workerData } from 'node:worker_threads';

    const providerSource = encodeURIComponent(String.raw\`
      export function readTestCloudRuntimeLifecycle() {
        return globalThis.__fixtureClockHarness.lifecycle;
      }
      export function isAuthenticTestCloudBootstrapHub(hub) {
        if (hub === undefined) {
          globalThis.__fixtureClockHarness.lifecycle = 'BLOCKED';
          return false;
        }
        return globalThis.__fixtureClockHarness.lifecycle === 'BOOTSTRAPPING'
          && hub === globalThis.__fixtureClockHarness.hub;
      }
      export function authenticateTestCloudRuntimeActive(args) {
        return globalThis.__fixtureClockHarness.lifecycle === 'ACTIVE'
          && args !== null
          && typeof args === 'object'
          && Object.getPrototypeOf(args) === Object.prototype
          && Reflect.ownKeys(args).length === 1
          && args.runtimeQualification === globalThis.__fixtureClockHarness.runtimeQualification;
      }
    \`);
    const providerUrl = \`data:text/javascript,\${providerSource}\`;
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (specifier.endsWith('/scripts/verification/test-cloud-provider-contract.mjs')) {
          return { shortCircuit: true, url: providerUrl };
        }
        return nextResolve(specifier, context);
      },
    });

    const freezeNull = (value = {}) => Object.freeze(Object.assign(Object.create(null), value));
    const runtimeQualification = freezeNull();
    const identityBindingsQualification = freezeNull();
    const sessionIntentQualification = freezeNull();
    const providerContractQualification = freezeNull();
    const identityBindingVersions = new WeakMap();
    identityBindingVersions.set(identityBindingsQualification, 1);
    let currentIdentityBinding = freezeNull({
      qualification: identityBindingsQualification,
      version: 1,
    });
    function identityBindingIsCurrent(args) {
      return args.identityBindingsQualification === currentIdentityBinding.qualification
        && identityBindingVersions.get(args.identityBindingsQualification)
          === currentIdentityBinding.version;
    }
    const context = Object.freeze({
      runId: 'verify-0123456789ab-1-1',
      environmentDigest: 'sha256:' + '1'.repeat(64),
    });
    const providerContract = Object.freeze({
      status: 'PASS',
      value: freezeNull({
        qualification: providerContractQualification,
        providerContractDigest: 'sha256:' + '2'.repeat(64),
      }),
      diagnostics: Object.freeze([]),
    });
    const fixtureClockPolicy = Object.freeze({
      schemaVersion: 'verification-dashboard-clock-policy.v1',
      authenticationBoundary: Object.freeze({
        browserOwnership: 'adapter-single-launch-context-page',
        policyPhase: 'before-owner-session',
        navigation: 'sole-main-document-before-login-actions',
        ledgerCommit: 'account-session-set-after-login-actions',
      }),
      installBoundary: Object.freeze({
        after: 'factory-ready-policy-bound',
        before: 'adapter-owned-sole-main-document-navigation',
      }),
      initialState: 'paused',
      autosaveDelayMilliseconds: 800,
      intermediateTimerPolicy: 'cancel',
      advanceMilliseconds: Object.freeze([800]),
      allowedAutosaves: 1,
      finalState: 'paused',
      publishedAtOffsets: Object.freeze([
        Object.freeze({ mutationOrdinal: 4, offsetMilliseconds: 0 }),
        Object.freeze({ mutationOrdinal: 5, offsetMilliseconds: 0 }),
        Object.freeze({ mutationOrdinal: 8, offsetMilliseconds: 800 }),
        Object.freeze({ mutationOrdinal: 11, offsetMilliseconds: 800 }),
        Object.freeze({ mutationOrdinal: 16, offsetMilliseconds: 800 }),
      ]),
    });

    const calls = [];
    const authTrace = [];
    let releaseInstall;
    let releaseAuthentication;
    let releaseSeal;
    const scenario = workerData.scenario;
    let expectedStateConsumer;
    let reconciliationReceiver;
    let clock;
    const bridgeReceiver = freezeNull();
    function record(name) {
      calls.push(name);
      return true;
    }
    const browserFacade = freezeNull({
      async installPausedBeforeNavigation(args) {
        calls.push(['install', args.baseUtc]);
        if (
          scenario === 'duplicate-install-await'
          || scenario === 'runtime-blocked-install-await'
        ) {
          await new Promise((resolve) => { releaseInstall = resolve; });
        }
        return true;
      },
      async proveOwnerUiReady(args) {
        calls.push(['ready', Reflect.ownKeys(args).length]);
        if (scenario === 'duplicate-auth-await') {
          await new Promise((resolve) => { releaseAuthentication = resolve; });
        }
        return true;
      },
      async readOwnerAccount(args) {
        calls.push(['account', Reflect.ownKeys(args).length]);
        return { $id: 'owner-id', email: 'owner@example.test', name: 'Owner', status: true };
      },
      async runForExactly800Milliseconds(args) {
        calls.push(['advance', Reflect.ownKeys(args).length]);
        for (const mutationOrdinal of [8, 11, 16]) {
          const qualification = freezeNull();
          if (reconciliationReceiver.implementation.call(reconciliationReceiver.receiver, {
            runtimeQualification,
            clock,
            mutationOrdinal,
            qualification,
          }) !== true) throw new Error('reconciliation delivery failed');
        }
        return { advancedMilliseconds: 800, autosaveCount: 1 };
      },
      async sealClock(args) {
        calls.push(['seal', Reflect.ownKeys(args).length]);
        if (scenario === 'runtime-blocked-seal-await') {
          await new Promise((resolve) => { releaseSeal = resolve; });
        }
        return true;
      },
    });
    function registrar(slot) {
      return function register(registration) {
        if (this !== bridgeReceiver || registration.receiver === undefined) return false;
        if (slot === 'consumer') expectedStateConsumer = registration;
        else reconciliationReceiver = registration;
        return true;
      };
    }
    const hubValues = {
      bridgeReceiver,
      registerExpectedStateResultConsumer: registrar('consumer'),
      registerClockReconciliationAggregateReceiver: registrar('reconciliation'),
      deliverTimestampBindingResult(args) {
        calls.push(['timestamp', args.mutationOrdinal]);
        const publishedAt = expectedStateConsumer.implementation.call(
          expectedStateConsumer.receiver,
          args,
        );
        return typeof publishedAt === 'string';
      },
      deliverMutationReconciliationQualification() { return false; },
      deliverBrowserScenarioAutosaveCompletion(args) {
        calls.push(['autosave-complete', args.clock === clock]);
        return true;
      },
      authenticateProviderQualification(args) {
        authTrace.push({
          name: 'provider',
          keys: Reflect.ownKeys(args),
          mutationOrdinal: null,
        });
        return args.runtimeQualification === runtimeQualification
          && args.context === context
          && args.providerContractQualification === providerContractQualification
          && args.expectedEnvironmentDigest === context.environmentDigest
          && args.expectedProviderContractDigest === providerContract.value.providerContractDigest;
      },
      readFixtureClockPolicy(args) {
        authTrace.push({
          name: 'policy',
          keys: Reflect.ownKeys(args),
          mutationOrdinal: null,
        });
        return args.runtimeQualification === runtimeQualification
          && args.context === context
          && args.providerContractQualification === providerContractQualification
          ? freezeNull({ fixtureClockPolicy })
          : false;
      },
      authenticateInitialProviderPrefix(args) {
        authTrace.push({
          name: 'prefix',
          keys: Reflect.ownKeys(args),
          mutationOrdinal: null,
        });
        return args.clock === clock
          && identityBindingIsCurrent(args)
          && record('prefix');
      },
      ownerAuthenticator(args) {
        authTrace.push({
          name: 'owner',
          keys: Reflect.ownKeys(args),
          mutationOrdinal: null,
        });
        return args.observedOwnerProjection.$id === 'owner-id'
          && identityBindingIsCurrent(args)
          && args.expectedEnvironmentDigest === context.environmentDigest
          && args.expectedProviderContractDigest === providerContract.value.providerContractDigest;
      },
      authenticateSessionLineage(args) {
        authTrace.push({
          name: 'session',
          keys: Reflect.ownKeys(args),
          mutationOrdinal: null,
        });
        return args.clock === undefined
          && args.runtimeQualification === runtimeQualification
          && args.context === context
          && args.identityBindingsQualification === identityBindingsQualification
          && args.sessionIntentQualification === sessionIntentQualification;
      },
      authenticateMutationReconciliation(args) {
        authTrace.push({
          name: 'reconciliation',
          keys: Reflect.ownKeys(args),
          mutationOrdinal: args.mutationOrdinal,
        });
        return args.clock === clock && [4, 5, 8, 11, 16].includes(args.mutationOrdinal);
      },
      constructExpectedStateForProviderMutation() { return false; },
      browserFacade,
    };
    const hub = Object.create(null);
    const descriptors = Object.create(null);
    for (const [key, value] of Object.entries(hubValues)) {
      descriptors[key] = { value, enumerable: true, configurable: false, writable: false };
    }
    Object.defineProperties(hub, descriptors);
    Object.freeze(hub);
    globalThis.__fixtureClockHarness = { lifecycle: 'BOOTSTRAPPING', hub, runtimeQualification };
    Object.defineProperty(globalThis, '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__', {
      value: hub,
      enumerable: false,
      configurable: true,
      writable: false,
    });

    function sameKeys(actual, expected) {
      return actual.length === expected.length
        && actual.every((key, index) => key === expected[index]);
    }
    function assertExactPassShape(result, valueKeys) {
      if (
        result === null
        || typeof result !== 'object'
        || Object.getPrototypeOf(result) !== Object.prototype
        || Object.isFrozen(result) !== true
        || !sameKeys(Reflect.ownKeys(result), ['status', 'value', 'diagnostics'])
        || result.status !== 'PASS'
        || result.value === null
        || typeof result.value !== 'object'
        || Object.getPrototypeOf(result.value) !== null
        || Object.isFrozen(result.value) !== true
        || !sameKeys(Reflect.ownKeys(result.value), valueKeys)
        || !Array.isArray(result.diagnostics)
        || Object.isFrozen(result.diagnostics) !== true
        || result.diagnostics.length !== 0
      ) throw new Error('PASS result shape mismatch');
      for (const key of ['status', 'value', 'diagnostics']) {
        const descriptor = Object.getOwnPropertyDescriptor(result, key);
        if (
          descriptor === undefined
          || !Object.hasOwn(descriptor, 'value')
          || descriptor.enumerable !== true
          || descriptor.configurable !== false
          || descriptor.writable !== false
        ) throw new Error('PASS outer descriptor mismatch');
      }
      for (const key of valueKeys) {
        const descriptor = Object.getOwnPropertyDescriptor(result.value, key);
        if (
          descriptor === undefined
          || !Object.hasOwn(descriptor, 'value')
          || descriptor.enumerable !== true
          || descriptor.configurable !== false
          || descriptor.writable !== false
        ) throw new Error('PASS value descriptor mismatch');
      }
    }
    function assertClockPassShape(result, originalClock, valueKeys = ['clock']) {
      assertExactPassShape(result, valueKeys);
      if (result.value.clock !== originalClock) {
        throw new Error('clock PASS identity mismatch');
      }
    }
    function postBlockedScenario(results) {
      parentPort.postMessage({
        scenario,
        statuses: results.map((result) => result.status),
        diagnosticCodes: results.map((result) => (
          result.status === 'BLOCKED' ? result.diagnostics[0].code : null
        )),
        lifecycle: globalThis.__fixtureClockHarness.lifecycle,
      });
    }

    try {
      const fixtureClock = await import(workerData.moduleUrl);
      scenarioExecution: {
      if (fixtureClock.registerTestCloudFixtureClockBootstrap() !== true) {
        throw new Error('registration failed');
      }
      if (scenario === 'duplicate-registrar') {
        const duplicateResult = fixtureClock.registerTestCloudFixtureClockBootstrap();
        parentPort.postMessage({
          scenario,
          duplicateResult,
          lifecycle: globalThis.__fixtureClockHarness.lifecycle,
        });
        break scenarioExecution;
      }
      globalThis.__fixtureClockHarness.lifecycle = 'ACTIVE';
      const prepared = fixtureClock.prepareTestCloudFixtureClock({
        runtimeQualification,
        context,
        providerContract,
        identityBindingsQualification: scenario === 'substitute-identity-binding'
          ? freezeNull()
          : identityBindingsQualification,
      });
      if (prepared.status !== 'PASS') {
        throw new Error(\`expected active prepare PASS, received \${prepared.status}\`);
      }
      clock = prepared.value.clock;
      assertClockPassShape(prepared, clock, ['clock', 'fixtureClockScheduleDigest']);
      const installArgs = { runtimeQualification, clock };
      if (scenario === 'duplicate-install-await') {
        const original = fixtureClock.installTestCloudFixtureClock(installArgs);
        const duplicate = fixtureClock.installTestCloudFixtureClock(installArgs);
        if (typeof releaseInstall !== 'function') throw new Error('install gate missing');
        releaseInstall();
        postBlockedScenario(await Promise.all([original, duplicate]));
        break scenarioExecution;
      }
      if (scenario === 'runtime-blocked-install-await') {
        const pending = fixtureClock.installTestCloudFixtureClock(installArgs);
        if (typeof releaseInstall !== 'function') throw new Error('install gate missing');
        globalThis.__fixtureClockHarness.lifecycle = 'BLOCKED';
        releaseInstall();
        postBlockedScenario([await pending]);
        break scenarioExecution;
      }
      const installed = await fixtureClock.installTestCloudFixtureClock({ runtimeQualification, clock });
      assertClockPassShape(installed, clock);
      if (scenario === 'stale-identity-binding') {
        const successor = freezeNull();
        identityBindingVersions.set(successor, 2);
        currentIdentityBinding = freezeNull({ qualification: successor, version: 2 });
      }
      const authenticationArgs = {
        runtimeQualification,
        clock,
        sessionIntentQualification,
      };
      if (scenario === 'duplicate-auth-await') {
        const original = fixtureClock.authenticateTestCloudFixtureClock(authenticationArgs);
        const duplicate = fixtureClock.authenticateTestCloudFixtureClock(authenticationArgs);
        if (typeof releaseAuthentication !== 'function') {
          throw new Error('authentication gate missing');
        }
        releaseAuthentication();
        postBlockedScenario(await Promise.all([original, duplicate]));
        break scenarioExecution;
      }
      if (
        scenario === 'stale-identity-binding'
        || scenario === 'substitute-identity-binding'
      ) {
        postBlockedScenario([
          await fixtureClock.authenticateTestCloudFixtureClock(authenticationArgs),
        ]);
        break scenarioExecution;
      }
      const authenticated = await fixtureClock.authenticateTestCloudFixtureClock(
        authenticationArgs,
      );
      assertClockPassShape(authenticated, clock);
      if (scenario === 'early-advance') {
        postBlockedScenario([
          await fixtureClock.advanceTestCloudFixtureClock({ runtimeQualification, clock }),
        ]);
        break scenarioExecution;
      }
      if (scenario === 'early-seal') {
        postBlockedScenario([
          await fixtureClock.sealTestCloudFixtureClock({ runtimeQualification, clock }),
        ]);
        break scenarioExecution;
      }
      if (scenario === 'wrong-ordinal') {
        postBlockedScenario([
          fixtureClock.readTestCloudFixtureExpectedState({
            runtimeQualification, clock, mutationOrdinal: 5,
          }),
        ]);
        break scenarioExecution;
      }
      if (scenario === 'duplicate-read') {
        const first = fixtureClock.readTestCloudFixtureExpectedState({
          runtimeQualification, clock, mutationOrdinal: 4,
        });
        assertExactPassShape(first, ['mutationOrdinal', 'publishedAt']);
        const duplicate = fixtureClock.readTestCloudFixtureExpectedState({
          runtimeQualification, clock, mutationOrdinal: 4,
        });
        postBlockedScenario([first, duplicate]);
        break scenarioExecution;
      }
      if (scenario === 'replayed-ordinal') {
        const first = fixtureClock.readTestCloudFixtureExpectedState({
          runtimeQualification, clock, mutationOrdinal: 4,
        });
        const second = fixtureClock.readTestCloudFixtureExpectedState({
          runtimeQualification, clock, mutationOrdinal: 5,
        });
        assertExactPassShape(first, ['mutationOrdinal', 'publishedAt']);
        assertExactPassShape(second, ['mutationOrdinal', 'publishedAt']);
        const replay = fixtureClock.readTestCloudFixtureExpectedState({
          runtimeQualification, clock, mutationOrdinal: 4,
        });
        postBlockedScenario([first, second, replay]);
        break scenarioExecution;
      }
      const reads = [4, 5, 8, 11, 16].map((mutationOrdinal) =>
        fixtureClock.readTestCloudFixtureExpectedState({
          runtimeQualification, clock, mutationOrdinal,
        }));
      for (const read of reads) {
        assertExactPassShape(read, ['mutationOrdinal', 'publishedAt']);
      }
      for (const mutationOrdinal of [4, 5]) {
        const qualification = freezeNull();
        if (reconciliationReceiver.implementation.call(reconciliationReceiver.receiver, {
          runtimeQualification,
          clock,
          mutationOrdinal,
          qualification,
        }) !== true) throw new Error('prefix reconciliation failed');
      }
      const advanced = await fixtureClock.advanceTestCloudFixtureClock({ runtimeQualification, clock });
      assertClockPassShape(advanced, clock);
      if (scenario === 'runtime-blocked-seal-await') {
        const pending = fixtureClock.sealTestCloudFixtureClock({ runtimeQualification, clock });
        if (typeof releaseSeal !== 'function') throw new Error('seal gate missing');
        globalThis.__fixtureClockHarness.lifecycle = 'BLOCKED';
        releaseSeal();
        postBlockedScenario([await pending]);
        break scenarioExecution;
      }
      const sealed = await fixtureClock.sealTestCloudFixtureClock({ runtimeQualification, clock });
      assertExactPassShape(sealed, ['fixtureClockScheduleDigest']);
      const replay = await fixtureClock.sealTestCloudFixtureClock({ runtimeQualification, clock });
      parentPort.postMessage({
        exports: Object.keys(fixtureClock).sort(),
        statuses: [prepared, installed, authenticated, ...reads, advanced, sealed, replay]
          .map((value) => value.status),
        scheduleDigest: prepared.value.fixtureClockScheduleDigest,
        sealedDigest: sealed.value.fixtureClockScheduleDigest,
        timestamps: reads.map((value) => value.value.publishedAt),
        calls,
        authTrace,
        passShapesVerified: true,
        clockPassIdentitiesVerified: true,
        clockOwnKeys: Reflect.ownKeys(clock).length,
      });
      }
    } catch (error) {
      parentPort.postMessage({ error: error && error.stack ? error.stack : String(error) });
    }
  `;
  const workerUrl = new URL(`data:text/javascript,${encodeURIComponent(source)}`);
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerUrl, {
      type: 'module',
      workerData: { moduleUrl, scenario },
    });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', (code) => {
      if (code !== 0) reject(new Error(`fixture-clock worker exited ${code}`));
    });
  });
}

test('4C-final: fixture clock completes the single authenticated paused lifecycle', async () => {
  const result = await runActiveWorker();
  assert.equal(result.error, undefined, result.error);
  assert.deepEqual(result.exports, EXPECTED_EXPORTS);
  assert.deepEqual(result.statuses, [
    'PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'PASS', 'BLOCKED',
  ]);
  assert.equal(result.passShapesVerified, true);
  assert.equal(result.clockPassIdentitiesVerified, true);
  assert.match(result.scheduleDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.sealedDigest, result.scheduleDigest);
  assert.equal(result.clockOwnKeys, 0);
  assert.deepEqual(result.timestamps, [
    result.timestamps[0],
    result.timestamps[0],
    new Date(Date.parse(result.timestamps[0]) + 800).toISOString(),
    new Date(Date.parse(result.timestamps[0]) + 800).toISOString(),
    new Date(Date.parse(result.timestamps[0]) + 800).toISOString(),
  ]);
  assert.deepEqual(result.calls.filter((entry) => Array.isArray(entry) && entry[0] === 'advance'), [
    ['advance', 0],
  ]);
  assert.deepEqual(result.calls.filter((entry) => Array.isArray(entry) && entry[0] === 'seal'), [
    ['seal', 0],
  ]);
});

test('4C-final: fixture clock authenticates exact edges and blocks grouped replay vectors', async () => {
  const expectedAuthenticationKeys = Object.freeze({
    provider: Object.freeze([
      'runtimeQualification',
      'context',
      'providerContractQualification',
      'expectedEnvironmentDigest',
      'expectedProviderContractDigest',
    ]),
    policy: Object.freeze([
      'runtimeQualification', 'context', 'providerContractQualification',
    ]),
    session: Object.freeze([
      'runtimeQualification',
      'context',
      'identityBindingsQualification',
      'sessionIntentQualification',
    ]),
    owner: Object.freeze([
      'runtimeQualification',
      'identityBindingsQualification',
      'observedOwnerProjection',
      'expectedEnvironmentDigest',
      'expectedProviderContractDigest',
    ]),
    prefix: Object.freeze([
      'runtimeQualification',
      'context',
      'providerContractQualification',
      'identityBindingsQualification',
      'sessionIntentQualification',
      'clock',
    ]),
    reconciliation: Object.freeze([
      'runtimeQualification', 'clock', 'mutationOrdinal', 'qualification',
    ]),
  });
  const happy = await runActiveWorker();
  assert.equal(happy.error, undefined, happy.error);
  assert.deepEqual(
    happy.authTrace.map(({ name, mutationOrdinal }) => [name, mutationOrdinal]),
    [
      ['provider', null],
      ['policy', null],
      ['session', null],
      ['owner', null],
      ['reconciliation', 4],
      ['reconciliation', 5],
      ['prefix', null],
      ['reconciliation', 8],
      ['reconciliation', 11],
      ['reconciliation', 16],
      ['reconciliation', 4],
      ['reconciliation', 5],
      ['reconciliation', 8],
      ['reconciliation', 11],
      ['reconciliation', 16],
    ],
  );
  for (const entry of happy.authTrace) {
    assert.deepEqual(entry.keys, expectedAuthenticationKeys[entry.name]);
  }

  const vectors = Object.freeze([
    Object.freeze({ scenario: 'duplicate-install-await', statuses: ['BLOCKED', 'BLOCKED'] }),
    Object.freeze({
      scenario: 'runtime-blocked-install-await',
      statuses: ['BLOCKED'],
      lifecycle: 'BLOCKED',
      diagnosticCode: 'TEST_FIXTURE_CLOCK_INVALID',
    }),
    Object.freeze({ scenario: 'duplicate-auth-await', statuses: ['BLOCKED', 'BLOCKED'] }),
    Object.freeze({ scenario: 'stale-identity-binding', statuses: ['BLOCKED'] }),
    Object.freeze({ scenario: 'substitute-identity-binding', statuses: ['BLOCKED'] }),
    Object.freeze({ scenario: 'duplicate-read', statuses: ['PASS', 'BLOCKED'] }),
    Object.freeze({ scenario: 'wrong-ordinal', statuses: ['BLOCKED'] }),
    Object.freeze({ scenario: 'replayed-ordinal', statuses: ['PASS', 'PASS', 'BLOCKED'] }),
    Object.freeze({ scenario: 'early-advance', statuses: ['BLOCKED'] }),
    Object.freeze({ scenario: 'early-seal', statuses: ['BLOCKED'] }),
    Object.freeze({
      scenario: 'runtime-blocked-seal-await',
      statuses: ['BLOCKED'],
      lifecycle: 'BLOCKED',
      diagnosticCode: 'TEST_FIXTURE_CLOCK_INVALID',
    }),
  ]);
  const results = await Promise.all(vectors.map(({ scenario }) => runActiveWorker(scenario)));
  for (let index = 0; index < vectors.length; index += 1) {
    const vector = vectors[index];
    const result = results[index];
    assert.equal(result.error, undefined, result.error);
    assert.equal(result.scenario, vector.scenario);
    assert.deepEqual(result.statuses, vector.statuses);
    assert.deepEqual(
      result.diagnosticCodes,
      vector.statuses.map((status) => (
        status === 'BLOCKED'
          ? (vector.diagnosticCode ?? 'TEST_FIXTURE_CLOCK_FORBIDDEN')
          : null
      )),
    );
    assert.equal(result.lifecycle, vector.lifecycle ?? 'ACTIVE');
  }

  const duplicateRegistrar = await runActiveWorker('duplicate-registrar');
  assert.equal(duplicateRegistrar.error, undefined, duplicateRegistrar.error);
  assert.equal(duplicateRegistrar.duplicateResult, false);
  assert.equal(duplicateRegistrar.lifecycle, 'BLOCKED');
});
