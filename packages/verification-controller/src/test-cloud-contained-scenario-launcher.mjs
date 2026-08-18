import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createTestCloudPlaywrightFacade,
} from './test-cloud-playwright-facade.mjs';
import {
  createTestCloudScenarioDrivers,
} from './test-cloud-scenario-driver.mjs';
import {
  runTrustedContainedBrowserScenario,
} from './test-cloud-contained-browser-scenario-adapter.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };

const FULL_SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SCENARIO_IDS = Object.freeze([
  'public-smoke',
  'auth',
  'project-lifecycle',
  'graph-editor',
  'runtime',
  'sharing-permissions',
]);

function parseArguments(argv) {
  if (!(Array.isArray(argv)
    && argv.length === 10
    && argv[0] === '--scenario-id'
    && SCENARIO_IDS.includes(argv[1])
    && argv[2] === '--controller-revision'
    && FULL_SHA.test(argv[3] ?? '')
    && argv[4] === '--controller-bundle-digest'
    && DIGEST.test(argv[5] ?? '')
    && argv[6] === '--playwright-image-digest'
    && DIGEST.test(argv[7] ?? '')
    && argv[8] === '--scenario-inventory-digest'
    && DIGEST.test(argv[9] ?? ''))) return null;
  return Object.freeze({
    scenarioId: argv[1],
    controllerRevision: argv[3],
    controllerBundleDigest: argv[5],
    playwrightImageDigest: argv[7],
    scenarioInventoryDigest: argv[9],
  });
}

function write(stream, value) {
  if (stream && typeof stream.write === 'function') stream.write(value);
}

function readEnvironmentValue(environment, name) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(environment, name);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'string'
      || descriptor.value.length === 0
    ) return null;
    return descriptor.value;
  } catch {
    return null;
  }
}

function scenarioIdentities(environment, scenarioId) {
  const identities = Object.assign(Object.create(null), {
    ownerEmail: null,
    ownerPassword: null,
    editorEmail: null,
    viewerEmail: null,
  });
  if (scenarioId === 'auth') {
    identities.ownerEmail = readEnvironmentValue(environment, 'E2E_OWNER_EMAIL');
    identities.ownerPassword = readEnvironmentValue(environment, 'E2E_OWNER_PASSWORD');
  }
  return Object.freeze(identities);
}

export async function main(argv = process.argv.slice(2), streams = {}) {
  const stdout = streams.stdout ?? process.stdout;
  const stderr = streams.stderr ?? process.stderr;
  const environment = streams.environment ?? process.env;
  const request = parseArguments(argv);
  if (request === null) {
    write(stderr, 'BLOCKED TRUSTED_SCENARIO_LAUNCHER_INVALID\n');
    return 2;
  }
  try {
    const launcher = Object.freeze({
      async runPlaywrightScenario(runRequest) {
        const binding = runRequest.scenarioDriver({
          controllerBinding: runRequest.controllerBinding,
        });
        if (
          binding.controllerRevision !== request.controllerRevision
          || binding.scenarioId !== request.scenarioId
        ) throw new TypeError('Trusted scenario binding mismatch.');
        const transcript = await runTrustedContainedBrowserScenario({
          controllerRevision: binding.controllerRevision,
          identities: scenarioIdentities(environment, binding.scenarioId),
          origin: inventory.environment.publicOrigin,
          scenarioId: binding.scenarioId,
        });
        return Object.freeze({
          exitCode: 0,
          stderr: new Uint8Array(),
          stdout: new TextEncoder().encode(JSON.stringify(transcript)),
          timedOut: false,
        });
      },
    });
    const facade = createTestCloudPlaywrightFacade({
      launcher,
      scenarioDrivers: createTestCloudScenarioDrivers(),
    });
    const outcome = await facade.runExactScenario({
      controllerBinding: Object.freeze({
        controllerBundleDigest: request.controllerBundleDigest,
        controllerRevision: request.controllerRevision,
        playwrightImageDigest: request.playwrightImageDigest,
        scenarioInventoryDigest: request.scenarioInventoryDigest,
      }),
      scenarioId: request.scenarioId,
      timeoutMs: 300_000,
    });
    write(stdout, JSON.stringify(outcome));
    return 0;
  } catch {
    write(stderr, 'BLOCKED TRUSTED_SCENARIO_EXECUTION_FAILED\n');
    return 2;
  }
}

if (
  process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = await main();
}
