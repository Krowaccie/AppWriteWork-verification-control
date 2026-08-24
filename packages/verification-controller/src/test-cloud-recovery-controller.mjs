import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isProxy } from 'node:util/types';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { RECOVERY_COUNTS } from '../../../scripts/verification/test-cloud-cleanup-protocol.mjs';
import {
  createTestCloudRecoveryClients,
  isAuthenticTestCloudRecoveryControlClient,
  isAuthenticTestCloudRecoveryProductClient,
} from '../../../scripts/verification/test-cloud-appwrite.mjs';
import { createTestRecoveryEnvironmentContext } from '../../../scripts/verification/test-cloud-environment.mjs';
import { createProviderRecoveryControlStore } from '../../../scripts/verification/test-cloud-provider-control-store.mjs';
import {
  closeRecoveryLease,
  openRecoveryAccountSessionStage,
  openRecoveryCheckpoint,
} from '../../../scripts/verification/test-cloud-control-store.mjs';
import {
  createRecoveryResourceExecutor,
  recoverTestCloud,
} from '../../../scripts/verification/test-cloud-recovery.mjs';
import { qualifyExecutionObservationReadback } from '../../../scripts/verification/test-cloud-setup-check.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { readExactBindingDirectory } from './test-cloud-controller.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const POSITIVE_ID = /^[1-9][0-9]*$/u;
const RECOVERY_RESULT_KEYS = Object.freeze(['diagnostics', 'status', 'value']);
const RECOVERY_AUTHORITY_KEYS = Object.freeze([
  'failedWorkflowRunId',
  'sourceRunAttempt',
  'sourceRunId',
  'sourceRevision',
]);
const LEASE_KEYS = Object.freeze([
  'acquiredAt',
  'cleanupDebt',
  'environmentDigest',
  'expiresAt',
  'leaseRowId',
  'leaseTokenDigest',
  'leaseVersion',
  'ledgerDigest',
  'ownerRunId',
  'ownerWorkflowRunId',
  'renewedAt',
  'state',
]);
const CLI_RUNTIME_KEYS = Object.freeze([
  'bindingDirectoryIo',
  'clock',
  'environment',
  'fetchImpl',
  'stderr',
  'stdout',
]);
const RECOVERY_ENVIRONMENT_KEYS = Object.freeze([
  'APPWRITE_TEST_RECOVERY_API_KEY',
  'GITHUB_REPOSITORY',
  'GITHUB_SHA',
  'TRUSTED_CONTROLLER_SHA',
]);
const BINDING_IO_KEYS = Object.freeze(['lstat', 'readFile', 'readdir', 'realpath']);

function blocked(code) {
  return Object.freeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: Object.freeze([Object.freeze({
      code,
      safeMessage: 'Appwrite Test recovery was blocked.',
      retryable: false,
    })]),
  });
}

function exactObject(value, keys) {
  try {
    if (value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || isProxy(value)) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Reflect.ownKeys(descriptors).length === keys.length
      && keys.every((key) => {
        const descriptor = descriptors[key];
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
      });
  } catch {
    return false;
  }
}

function dataValue(value, key) {
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

function exactPlainDataObject(value, keys, { allowSubset = false } = {}) {
  try {
    if (value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || isProxy(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
      || (!allowSubset && ownKeys.length !== keys.length)) return false;
    return ownKeys.every((key) => (
      descriptors[key]?.enumerable === true
      && Object.hasOwn(descriptors[key], 'value')
    ));
  } catch {
    return false;
  }
}

function safeFunction(value) {
  try {
    return typeof value === 'function' && !isProxy(value);
  } catch {
    return false;
  }
}

function exactFunctionPort(value, keys) {
  return exactPlainDataObject(value, keys)
    && keys.every((key) => safeFunction(dataValue(value, key)));
}

function denseArray(value, length) {
  try {
    if (!Array.isArray(value) || isProxy(value)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const expected = [...Array(length).keys()].map(String);
    if (Reflect.ownKeys(descriptors).length !== length + 1
      || descriptors.length?.value !== length
      || expected.some((key) => descriptors[key]?.enumerable !== true
        || !Object.hasOwn(descriptors[key], 'value'))) return null;
    return expected.map((key) => descriptors[key].value);
  } catch {
    return null;
  }
}

function countSet(value, keys) {
  if (!exactObject(value, keys)) return null;
  const counts = Object.fromEntries(keys.map((key) => [key, dataValue(value, key)]));
  if (keys.some((key) => !Number.isSafeInteger(counts[key]) || counts[key] < 0)
    || (Object.hasOwn(counts, 'known')
      && Object.hasOwn(counts, 'maximum')
      && counts.known > counts.maximum)
    || (Object.hasOwn(counts, 'observed')
      && counts.observed > counts.maximum)) return null;
  return counts;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function resultValue(outcome) {
  const diagnostics = exactObject(outcome, RECOVERY_RESULT_KEYS)
    ? dataValue(outcome, 'diagnostics')
    : null;
  return exactObject(outcome, RECOVERY_RESULT_KEYS)
    && dataValue(outcome, 'status') === 'PASS'
    && denseArray(diagnostics, 0) !== null
    ? dataValue(outcome, 'value')
    : null;
}

function snapshotRecoveryAuthority(value) {
  if (!exactObject(value, RECOVERY_AUTHORITY_KEYS)) return null;
  const snapshot = Object.freeze(Object.fromEntries(RECOVERY_AUTHORITY_KEYS.map((key) => (
    [key, dataValue(value, key)]
  ))));
  return POSITIVE_ID.test(snapshot.failedWorkflowRunId)
    && POSITIVE_ID.test(snapshot.sourceRunAttempt)
    && POSITIVE_ID.test(snapshot.sourceRunId)
    && snapshot.failedWorkflowRunId !== snapshot.sourceRunId
    && FULL_SHA.test(snapshot.sourceRevision)
    ? snapshot
    : null;
}

function exactSourceLease(value, authority) {
  const expectedRunId = `verify-${authority.sourceRevision.slice(0, 12)}`
    + `-${authority.sourceRunId}-${authority.sourceRunAttempt}`;
  return exactObject(value, LEASE_KEYS)
    && value.leaseRowId === inventory.control.leaseRowId
    && Number.isSafeInteger(value.leaseVersion)
    && value.leaseVersion >= 0
    && value.ownerRunId === expectedRunId
    && value.ownerWorkflowRunId === authority.sourceRunId
    && value.cleanupDebt === true
    && ['cleanup-debt', 'recovering'].includes(value.state)
    && DIGEST.test(value.environmentDigest ?? '')
    && DIGEST.test(value.ledgerDigest ?? '')
    && DIGEST.test(value.leaseTokenDigest ?? '');
}

function exactEmptyAccountStage(outcome) {
  const value = resultValue(outcome);
  if (!exactObject(value, ['measurements', 'nextAuthority', 'sessionAbsenceDigest'])
    || !DIGEST.test(dataValue(value, 'sessionAbsenceDigest') ?? '')) return null;
  const measurements = dataValue(value, 'measurements');
  return exactObject(measurements, [
    'knownProductCalls',
    'maximumProductCalls',
    'knownStoreCalls',
    'maximumStoreCalls',
  ])
    && dataValue(measurements, 'knownProductCalls') === 0
    && dataValue(measurements, 'maximumProductCalls') === 0
    && dataValue(measurements, 'knownStoreCalls') === 1
    && dataValue(measurements, 'maximumStoreCalls') === 1
    ? value
    : null;
}

function exactTerminalRecovery(outcome) {
  try {
    const value = resultValue(outcome);
    if (exactObject(value, ['completion', 'recoveryCloseDigest', 'measurements'])
      && dataValue(value, 'completion') === 'recovery-closed'
      && DIGEST.test(dataValue(value, 'recoveryCloseDigest') ?? '')) {
      const emptyCloseStore = countSet(dataValue(value, 'measurements'), [
        'knownStoreCalls',
        'maximumStoreCalls',
      ]);
      return emptyCloseStore?.knownStoreCalls === 2
        && emptyCloseStore.maximumStoreCalls === 2;
    }
    if (!exactObject(value, [
      'completion',
      'session',
      'resources',
      'close',
      'measurements',
      'proofDigest',
    ])) return false;
    const completion = dataValue(value, 'completion');
    const session = dataValue(value, 'session');
    const resources = dataValue(value, 'resources');
    const close = dataValue(value, 'close');
    const measurements = dataValue(value, 'measurements');
    const proofDigest = dataValue(value, 'proofDigest');
    if (completion !== 'recovery-complete'
      || !DIGEST.test(proofDigest ?? '')
      || !exactObject(session, ['status', 'proofDigest', 'productCalls'])
      || dataValue(session, 'status') !== 'absent'
      || !DIGEST.test(dataValue(session, 'proofDigest') ?? '')) return false;
    const sessionProductCalls = countSet(dataValue(session, 'productCalls'), [
      'known',
      'maximum',
    ]);
    if (sessionProductCalls === null || sessionProductCalls.maximum !== 10) return false;
    if (!exactObject(resources, [
      'completion',
      'recoveryCheckpointDigest',
      'resources',
      'measurements',
    ])
      || dataValue(resources, 'completion') !== 'resources-complete'
      || !DIGEST.test(dataValue(resources, 'recoveryCheckpointDigest') ?? '')) return false;
    const resourceItems = denseArray(dataValue(resources, 'resources'), 3);
    const logicalResources = ['primary-share', 'primary-graph', 'primary-project'];
    if (resourceItems === null || resourceItems.some((resource, index) => (
      !exactObject(resource, ['logicalResource', 'status', 'cleanupProofDigest'])
      || dataValue(resource, 'logicalResource') !== logicalResources[index]
      || dataValue(resource, 'status') !== 'absent'
      || !DIGEST.test(dataValue(resource, 'cleanupProofDigest') ?? '')
    ))) return false;
    const resourceMeasurements = dataValue(resources, 'measurements');
    if (!exactObject(resourceMeasurements, ['productHttp', 'store', 'functionExecutions'])
      || dataValue(resourceMeasurements, 'functionExecutions') !== 0) return false;
    const resourceProduct = countSet(dataValue(resourceMeasurements, 'productHttp'), [
      'observed',
      'known',
      'maximum',
    ]);
    const resourceStore = countSet(dataValue(resourceMeasurements, 'store'), [
      'observed',
      'known',
      'maximum',
    ]);
    if (resourceProduct === null
      || resourceStore === null
      || resourceProduct.known !== RECOVERY_COUNTS.knownProductHttpCalls
      || resourceProduct.maximum !== RECOVERY_COUNTS.maximumProductHttpCalls
      || resourceStore.known !== RECOVERY_COUNTS.knownStoreCalls
      || resourceStore.maximum !== RECOVERY_COUNTS.maximumStoreCalls) return false;
    if (!exactObject(close, ['completion', 'recoveryCloseDigest', 'measurements'])
      || dataValue(close, 'completion') !== 'recovery-closed'
      || !DIGEST.test(dataValue(close, 'recoveryCloseDigest') ?? '')) return false;
    const closeStore = countSet(dataValue(close, 'measurements'), [
      'knownStoreCalls',
      'maximumStoreCalls',
    ]);
    if (closeStore === null
      || closeStore.knownStoreCalls !== 2
      || closeStore.maximumStoreCalls !== 2) return false;
    if (!exactObject(measurements, [
      'sessionProductCalls',
      'resourceProductHttp',
      'storeCalls',
      'functionExecutions',
    ]) || dataValue(measurements, 'functionExecutions') !== 0) return false;
    const totalSessionProduct = countSet(dataValue(measurements, 'sessionProductCalls'), [
      'known',
      'maximum',
    ]);
    const totalResourceProduct = countSet(dataValue(measurements, 'resourceProductHttp'), [
      'observed',
      'known',
      'maximum',
    ]);
    const totalStore = countSet(dataValue(measurements, 'storeCalls'), [
      'known',
      'maximum',
    ]);
    const sessionStoreKnown = sessionProductCalls.known === 0 ? 1 : 2;
    if (totalSessionProduct === null
      || totalResourceProduct === null
      || totalStore === null
      || canonicalJson(totalSessionProduct) !== canonicalJson(sessionProductCalls)
      || canonicalJson(totalResourceProduct) !== canonicalJson(resourceProduct)
      || totalStore.known !== resourceStore.known
        + closeStore.knownStoreCalls + sessionStoreKnown
      || totalStore.maximum !== resourceStore.maximum
        + closeStore.maximumStoreCalls + 2) return false;
    return proofDigest === digest({
      completion,
      session,
      resources,
      close,
      measurements,
    });
  } catch {
    return false;
  }
}

function createClosedApprovalGateway(authority) {
  const expectedRunId = authority.sourceRunId;
  return Object.freeze({
    async getRun(workflowRunId) {
      if (workflowRunId !== expectedRunId) throw new TypeError('recovery run mismatch');
      return Object.freeze({ status: 'completed' });
    },
    async hasActiveTestCloudRun() {
      return false;
    },
    async getRecoveryApproval(workflowRunId) {
      if (workflowRunId !== expectedRunId) throw new TypeError('recovery run mismatch');
      return Object.freeze({
        bundlePromoted: true,
        controllerBundleSha: authority.controllerBundleSha,
        environmentClass: 'appwrite-cloud-test-recovery',
        environmentDeploymentStatus: 'approved',
      });
    },
  });
}

export function createRecoveryTargetEnvironment() {
  return Object.freeze({
    endpoint: inventory.environment.endpoint,
    origin: inventory.environment.publicOrigin,
    projectId: inventory.environment.projectId,
    siteId: inventory.environment.siteId,
  });
}

function recoveryHandle(secret) {
  const configured = inventory.credentialVariables.recovery;
  return Object.freeze({
    ...configured,
    scopes: Object.freeze([...configured.scopes]),
    readSecret() { return secret; },
  });
}

function readHostedObservationQualification(bindings) {
  try {
    const text = bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_JSON;
    const expectedDigest = bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST;
    if (typeof text !== 'string' || !DIGEST.test(expectedDigest ?? '')) return null;
    const readback = JSON.parse(text);
    if (canonicalJson(readback) !== text || digest(readback) !== expectedDigest) return null;
    const executionObservation = readback.executionObservation;
    const qualified = qualifyExecutionObservationReadback({
      expectedReadbackDigest: digest(executionObservation),
      inventory,
      readback: executionObservation,
    });
    return resultValue(qualified);
  } catch {
    return null;
  }
}

function defaultRecoveryCliRuntime() {
  return Object.freeze({
    bindingDirectoryIo: undefined,
    clock: Object.freeze({ nowEpochSeconds: () => Math.floor(Date.now() / 1000) }),
    environment: Object.freeze(Object.fromEntries(RECOVERY_ENVIRONMENT_KEYS.map((key) => (
      [key, process.env[key]]
    )))),
    fetchImpl: globalThis.fetch,
    stderr: Object.freeze({ write: (value) => process.stderr.write(value) }),
    stdout: Object.freeze({ write: (value) => process.stdout.write(value) }),
  });
}

function readRecoveryCliRuntime(runtime) {
  try {
    if (runtime === undefined) return defaultRecoveryCliRuntime();
    if (!exactPlainDataObject(runtime, CLI_RUNTIME_KEYS, { allowSubset: true })) return null;
    const defaults = defaultRecoveryCliRuntime();
    const has = (key) => Object.hasOwn(Object.getOwnPropertyDescriptors(runtime), key);
    const environment = has('environment') ? dataValue(runtime, 'environment') : defaults.environment;
    const bindingDirectoryIo = has('bindingDirectoryIo')
      ? dataValue(runtime, 'bindingDirectoryIo')
      : defaults.bindingDirectoryIo;
    const fetchImpl = has('fetchImpl') ? dataValue(runtime, 'fetchImpl') : defaults.fetchImpl;
    const clock = has('clock') ? dataValue(runtime, 'clock') : defaults.clock;
    const stderr = has('stderr') ? dataValue(runtime, 'stderr') : defaults.stderr;
    const stdout = has('stdout') ? dataValue(runtime, 'stdout') : defaults.stdout;
    if (!exactPlainDataObject(environment, RECOVERY_ENVIRONMENT_KEYS)
      || (bindingDirectoryIo !== undefined
        && !exactFunctionPort(bindingDirectoryIo, BINDING_IO_KEYS))
      || !safeFunction(fetchImpl)
      || !exactFunctionPort(clock, ['nowEpochSeconds'])
      || !exactFunctionPort(stderr, ['write'])
      || !exactFunctionPort(stdout, ['write'])) return null;
    return Object.freeze({
      bindingDirectoryIo,
      clock,
      environment: Object.freeze(Object.fromEntries(RECOVERY_ENVIRONMENT_KEYS.map((key) => (
        [key, dataValue(environment, key)]
      )))),
      fetchImpl,
      stderr,
      stdout,
    });
  } catch {
    return null;
  }
}

export async function runTestCloudRecoveryStateMachine(args) {
  try {
    if (arguments.length !== 1
      || !exactObject(args, ['clients', 'clock', 'context', 'recoveryAuthority'])) {
      return blocked('RECOVERY_SCOPE_INVALID');
    }
    const clientsInput = dataValue(args, 'clients');
    const clockInput = dataValue(args, 'clock');
    const context = dataValue(args, 'context');
    const recoveryAuthority = snapshotRecoveryAuthority(dataValue(args, 'recoveryAuthority'));
    if (!exactObject(clientsInput, ['control', 'product'])
      || !exactObject(clockInput, ['nowEpochSeconds'])
      || recoveryAuthority === null) {
      return blocked('RECOVERY_SCOPE_INVALID');
    }
    const controlClient = dataValue(clientsInput, 'control');
    const productClient = dataValue(clientsInput, 'product');
    const nowFunction = dataValue(clockInput, 'nowEpochSeconds');
    if (!safeFunction(nowFunction)
      || !isAuthenticTestCloudRecoveryControlClient(controlClient, context)
      || !isAuthenticTestCloudRecoveryProductClient(productClient, context)
      || context.originalWorkflowRunId !== recoveryAuthority.sourceRunId
      || context.approvalRef !== 'https://github.com/'
        + 'Krowaccie/AppWriteWork-verification-control/actions/runs/'
        + recoveryAuthority.sourceRunId) {
      return blocked('RECOVERY_SCOPE_INVALID');
    }
    const nowEpochSeconds = Reflect.apply(nowFunction, clockInput, []);
    if (!Number.isSafeInteger(nowEpochSeconds) || nowEpochSeconds < 0) {
      return blocked('RECOVERY_SCOPE_INVALID');
    }
    const clock = Object.freeze({ nowEpochSeconds: () => nowEpochSeconds });
    const read = await controlClient.getRow({
      rowId: inventory.control.leaseRowId,
      tableId: inventory.control.leaseTableId,
    });
    const readValue = resultValue(read);
    const lease = exactObject(readValue, ['data', 'rowId'])
      && readValue.rowId === inventory.control.leaseRowId
      ? readValue.data
      : null;
    if (!exactSourceLease(lease, recoveryAuthority)) {
      return blocked('RECOVERY_SOURCE_BINDING_INVALID');
    }
    const createStore = () => createProviderRecoveryControlStore(Object.freeze({
      context,
      recoveryControlClient: controlClient,
    }));
    const createdValue = resultValue(createStore());
    if (!exactObject(createdValue, ['request', 'store'])) {
      return blocked('RECOVERY_CONTROL_STORE_INVALID');
    }
    const accountStage = exactEmptyAccountStage(await openRecoveryAccountSessionStage({
      clock,
      context,
      request: createdValue.request,
      store: createdValue.store,
    }));
    if (accountStage !== null) {
      const openedValue = resultValue(await openRecoveryCheckpoint({
        clock,
        context,
        request: accountStage.nextAuthority,
        store: createdValue.store,
      }));
      if (!exactObject(openedValue, ['emptyResourceSet', 'session', 'snapshot'])
        || dataValue(openedValue, 'emptyResourceSet') !== true) {
        return blocked('RECOVERY_TERMINAL_PROOF_INVALID');
      }
      const close = await closeRecoveryLease({
        clock,
        context,
        session: dataValue(openedValue, 'session'),
        store: createdValue.store,
      });
      return exactTerminalRecovery(close)
        ? close
        : blocked('RECOVERY_TERMINAL_PROOF_INVALID');
    }
    const executionStore = resultValue(createStore());
    if (!exactObject(executionStore, ['request', 'store'])) {
      return blocked('RECOVERY_CONTROL_STORE_INVALID');
    }
    const gatewayAuthority = Object.freeze({
      controllerBundleSha: context.controllerBundleSha,
      failedWorkflowRunId: recoveryAuthority.failedWorkflowRunId,
      sourceRunId: recoveryAuthority.sourceRunId,
    });
    const github = createClosedApprovalGateway(gatewayAuthority);
    const request = Object.freeze({
      runId: lease.ownerRunId,
      originalWorkflowRunId: recoveryAuthority.sourceRunId,
      approvalRef: context.approvalRef,
      expectedLeaseVersion: lease.leaseVersion,
      expectedLedgerDigest: lease.ledgerDigest,
      confirmedRunId: lease.ownerRunId,
    });
    const createdExecutor = createRecoveryResourceExecutor({
      clock,
      context,
      controlStore: executionStore,
      github,
      productClient,
      request,
    });
    const executor = resultValue(createdExecutor);
    if (executor === null) return blocked('RECOVERY_EXECUTOR_INVALID');
    const outcome = await recoverTestCloud({ executor });
    return exactTerminalRecovery(outcome)
      ? outcome
      : blocked('RECOVERY_TERMINAL_PROOF_INVALID');
  } catch {
    return blocked('RECOVERY_SCOPE_INVALID');
  }
}

function parseHostedArgs(argv) {
  const values = denseArray(argv, 12);
  if (values === null
    || values[0] !== '--hosted'
    || values[1] !== '--revision'
    || !FULL_SHA.test(values[2] ?? '')
    || values[3] !== '--source-workflow-run-id'
    || !POSITIVE_ID.test(values[4] ?? '')
    || values[5] !== '--source-run-attempt'
    || !POSITIVE_ID.test(values[6] ?? '')
    || values[7] !== '--original-workflow-run-id'
    || !POSITIVE_ID.test(values[8] ?? '')
    || values[9] !== '--binding-directory'
    || typeof values[10] !== 'string'
    || values[10].length < 1
    || values[10].includes('\0')
    || values[11] !== '--execute') return null;
  return Object.freeze({
    bindingDirectory: values[10],
    failedWorkflowRunId: values[8],
    sourceRevision: values[2],
    sourceRunAttempt: values[6],
    sourceRunId: values[4],
  });
}

function write(stream, value) {
  if (stream && typeof stream.write === 'function') stream.write(value);
}

export async function main(argv = process.argv.slice(2), runtimeInput) {
  const parsed = parseHostedArgs(argv);
  if (parsed === null) return 2;
  const runtime = readRecoveryCliRuntime(runtimeInput);
  if (runtime === null) return 2;
  const { environment, stderr, stdout } = runtime;
  try {
    const controllerBundleSha = environment.TRUSTED_CONTROLLER_SHA;
    const runtimeSha = environment.GITHUB_SHA;
    const secret = environment.APPWRITE_TEST_RECOVERY_API_KEY;
    if (!FULL_SHA.test(controllerBundleSha ?? '')
      || runtimeSha !== controllerBundleSha
      || typeof secret !== 'string'
      || secret.length < 1
      || environment.GITHUB_REPOSITORY
        !== 'Krowaccie/AppWriteWork-verification-control') {
      throw new TypeError('invalid recovery environment');
    }
    const bindingDirectory = path.resolve(parsed.bindingDirectory);
    if (!path.isAbsolute(parsed.bindingDirectory)
      || bindingDirectory !== parsed.bindingDirectory) {
      throw new TypeError('invalid binding directory');
    }
    const bindings = await readExactBindingDirectory(
      bindingDirectory,
      runtime.bindingDirectoryIo,
    );
    const executionObservationQualification = readHostedObservationQualification(bindings);
    if (executionObservationQualification === null) {
      throw new TypeError('invalid observation');
    }
    const handle = recoveryHandle(secret);
    const approvalRef = 'https://github.com/'
      + 'Krowaccie/AppWriteWork-verification-control/actions/runs/'
      + parsed.sourceRunId;
    const contextOutcome = createTestRecoveryEnvironmentContext({
      approvalRef,
      controllerBundleSha,
      environment: createRecoveryTargetEnvironment(),
      executionObservationQualification,
      originalWorkflowRunId: parsed.sourceRunId,
      recoveryHandle: handle,
    });
    const context = resultValue(contextOutcome);
    if (context === null) throw new TypeError('invalid recovery context');
    const clientsOutcome = createTestCloudRecoveryClients({
      context,
      fetch: runtime.fetchImpl,
      recoveryHandle: handle,
    });
    const clients = resultValue(clientsOutcome);
    if (clients === null) throw new TypeError('invalid recovery clients');
    const outcome = await runTestCloudRecoveryStateMachine({
      clients,
      clock: runtime.clock,
      context,
      recoveryAuthority: Object.freeze({
        failedWorkflowRunId: parsed.failedWorkflowRunId,
        sourceRunAttempt: parsed.sourceRunAttempt,
        sourceRunId: parsed.sourceRunId,
        sourceRevision: parsed.sourceRevision,
      }),
    });
    if (!exactTerminalRecovery(outcome)) {
      const code = exactObject(outcome, RECOVERY_RESULT_KEYS)
        ? outcome.diagnostics?.[0]?.code
        : 'RECOVERY_SCOPE_INVALID';
      write(stderr, `BLOCKED ${code ?? 'RECOVERY_SCOPE_INVALID'}\n`);
      return 2;
    }
    write(stdout, 'PASS\n');
    return 0;
  } catch {
    write(stderr, 'BLOCKED RECOVERY_SCOPE_INVALID\n');
    return 2;
  }
}

if (process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
