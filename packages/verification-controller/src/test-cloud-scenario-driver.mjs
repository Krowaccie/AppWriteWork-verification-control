import { types as utilTypes } from 'node:util';

import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { canonicalJson, sha256Bytes } from '../../../scripts/verification/canonical-json.mjs';
import {
  createRunnerRequest,
} from '../../../scripts/verification/test-cloud-control-store.mjs';
import {
  isAuthenticTestCloudOperatorClient,
} from '../../../scripts/verification/test-cloud-appwrite.mjs';
import {
  isAuthenticTestEnvironmentContext,
} from '../../../scripts/verification/test-cloud-environment.mjs';
import {
  markPrimaryExecutionObserved,
  planCreate,
} from '../../../scripts/verification/test-cloud-fixtures.mjs';
import {
  createRunnerExecutionWire,
  mapRunnerExecution,
} from '../../../scripts/verification/runner-protocol.mjs';

const ARGUMENT_KEYS = Object.freeze([
  'scenarioId',
  'parameters',
  'context',
  'client',
  'store',
  'lease',
  'capability',
  'clock',
]);
const SCENARIO_ID = 'worker.invoke_no_cost';
const PARAMETER_KEYS = Object.freeze(['logicalWorkflow', 'inputProfile']);
const PARAMETERS = Object.freeze({
  logicalWorkflow: 'hello-world-no-cost',
  inputProfile: 'verification-minimal',
});
const PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const PLAYWRIGHT_SCENARIO_IDS = Object.freeze([
  'public-smoke',
  'auth',
  'project-lifecycle',
  'graph-editor',
  'runtime',
  'sharing-permissions',
]);
const encoder = new TextEncoder();

function exactDataObject(value, keys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || utilTypes.isProxy(value)
      || Reflect.ownKeys(value).length !== keys.length
    ) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function result(status, value, code) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null
      ? []
      : [{
        code,
        safeMessage: status === 'FAIL'
          ? 'The trusted test-cloud scenario failed.'
          : 'The trusted test-cloud scenario was blocked.',
        retryable: false,
      }],
  });
}

function blocked(value = null) {
  return result('BLOCKED', value, 'TRUSTED_SCENARIO_DRIVER_BLOCKED');
}

function failed(value) {
  return result('FAIL', value, 'TRUSTED_SCENARIO_EXECUTION_FAILED');
}

function passed(lease, capability) {
  return result('PASS', { passed: true, lease, capability }, null);
}

function validScenario(fields) {
  const parameters = exactDataObject(fields.parameters, PARAMETER_KEYS);
  return fields.scenarioId === SCENARIO_ID
    && parameters !== null
    && parameters.logicalWorkflow === PARAMETERS.logicalWorkflow
    && parameters.inputProfile === PARAMETERS.inputProfile;
}

function digestText(value) {
  return sha256Bytes(encoder.encode(value));
}

function primaryExecutionDescriptor(context) {
  const operationKey = digestText(
    `${context.runId}|${SCENARIO_ID}|${canonicalJson(PARAMETERS)}`,
  );
  const resourceId = 'vr-' + digestText(
    `${context.environmentDigest}|${context.runId}|primary-execution`,
  ).slice(7, 39);
  const ownerMarker = `verification-owner.v1:${digestText(canonicalJson({
    environmentDigest: context.environmentDigest,
    operationKey,
    resourceId,
    resourceType: 'primary-execution',
    runId: context.runId,
    schemaVersion: 'verification-owner-marker.v1',
  }))}`;
  return {
    resourceType: 'primary-execution',
    resourceId,
    providerResourceIds: [],
    ownerMarker,
    dependencyOrder: 50,
    lifecycleClass: 'provider-retained-observation',
    retentionExpiresAt: null,
  };
}

function safeExecutionObservation(invocation) {
  const value = invocation?.status === 'PASS' ? invocation.value : null;
  const execution = value?.execution;
  const responseBody = typeof execution?.responseBody === 'string'
    ? execution.responseBody
    : null;
  let outputDigest = null;
  if (responseBody !== null) {
    try {
      const parsed = JSON.parse(responseBody);
      const candidate = parsed?.data?.outputDigest;
      if (typeof candidate === 'string' && DIGEST.test(candidate)) outputDigest = candidate;
    } catch {
      outputDigest = null;
    }
  }
  return {
    executionId: typeof execution?.executionId === 'string'
      && PROVIDER_ID.test(execution.executionId)
      ? execution.executionId
      : null,
    transportStatus: Number.isSafeInteger(value?.transportStatus)
      && value.transportStatus >= 100
      && value.transportStatus <= 599
      ? value.transportStatus
      : null,
    status: typeof execution?.status === 'string' ? execution.status : null,
    responseStatusCode: Number.isInteger(execution?.responseStatusCode)
      ? execution.responseStatusCode
      : null,
    outputDigest,
  };
}

function mappedExecution(invocation, request, candidateRevision) {
  if (invocation?.status !== 'PASS') {
    return { status: 'BLOCKED', code: 'RUNNER_TRANSPORT_AUTHORITY', envelope: null };
  }
  if (invocation.value.transportStatus === null) {
    return { status: 'BLOCKED', code: 'RUNNER_TRANSPORT_AUTHORITY', envelope: null };
  }
  const execution = invocation.value.execution;
  return mapRunnerExecution({
    request,
    expectedRunnerRevision: candidateRevision,
    transportStatus: invocation.value.transportStatus,
    execution: execution === null
      ? null
      : {
        status: execution.status,
        responseStatusCode: execution.responseStatusCode,
        responseBody: execution.responseBody,
      },
  });
}

function cleanupState(value) {
  if (
    value === null
    || typeof value !== 'object'
    || value.lease === null
    || value.lease === undefined
    || value.capability === null
    || value.capability === undefined
  ) return null;
  return { lease: value.lease, capability: value.capability };
}

export function createTestCloudScenarioDrivers() {
  const drivers = Object.create(null);
  for (const scenarioId of PLAYWRIGHT_SCENARIO_IDS) {
    drivers[scenarioId] = Object.freeze((args) => {
      const fields = exactDataObject(args, ['controllerBinding']);
      const controllerRevision = fields?.controllerBinding?.controllerRevision;
      if (typeof controllerRevision !== 'string' || !FULL_SHA.test(controllerRevision)) {
        throw new TypeError('Trusted Playwright scenario binding is invalid.');
      }
      return Object.freeze(Object.assign(Object.create(null), {
        controllerRevision,
        scenarioId,
      }));
    });
  }
  return Object.freeze(drivers);
}

export async function runTrustedTestCloudScenario(args) {
  const fields = exactDataObject(args, ARGUMENT_KEYS);
  if (
    fields === null
    || !validScenario(fields)
    || !isAuthenticTestEnvironmentContext(fields.context)
    || !isAuthenticTestCloudOperatorClient(fields.client, fields.context)
    || fields.clock === null
    || typeof fields.clock !== 'object'
    || typeof fields.clock.nowEpochSeconds !== 'function'
  ) return blocked();

  let planned;
  try {
    planned = await planCreate({
      context: fields.context,
      store: fields.store,
      lease: fields.lease,
      capability: fields.capability,
      descriptor: primaryExecutionDescriptor(fields.context),
      clock: fields.clock,
    });
  } catch {
    return blocked();
  }
  if (planned?.status !== 'PASS') return blocked(cleanupState(planned?.value));

  const stateAfterPlan = cleanupState(planned.value);
  let runnerRequest;
  let wire;
  let request;
  try {
    const created = createRunnerRequest({
      capability: planned.value.capability,
      lease: planned.value.lease,
      context: fields.context,
      clock: fields.clock,
      scenario: { scenarioId: SCENARIO_ID, parameters: PARAMETERS },
    });
    if (created.status !== 'PASS') return blocked(stateAfterPlan);
    runnerRequest = created.value;
    wire = createRunnerExecutionWire({ context: fields.context, runnerRequest });
    request = JSON.parse(wire.body);
  } catch {
    return blocked(stateAfterPlan);
  }

  let invocation;
  try {
    invocation = await fields.client.createFunctionExecution({
      functionId: inventory.control.runnerFunctionId,
      body: wire,
    });
  } catch {
    invocation = null;
  }

  const observation = safeExecutionObservation(invocation);
  let observed;
  try {
    observed = await markPrimaryExecutionObserved({
      context: fields.context,
      store: fields.store,
      lease: planned.value.lease,
      capability: planned.value.capability,
      intent: planned.value.intent,
      observation,
      clock: fields.clock,
    });
  } catch {
    return blocked();
  }
  const observedState = cleanupState(observed?.value);
  if (observedState === null) return blocked();

  let mapped;
  try {
    mapped = mappedExecution(invocation, request, fields.context.candidateRevision);
  } catch {
    mapped = { status: 'BLOCKED' };
  }
  if (mapped.status === 'FAIL') return failed(observedState);
  if (mapped.status !== 'PASS' || observed.status !== 'PASS') return blocked(observedState);
  return passed(observed.value.lease, observed.value.capability);
}
