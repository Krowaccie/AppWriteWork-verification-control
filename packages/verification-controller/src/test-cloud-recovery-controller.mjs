import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  createTestCloudRecoveryClients,
  isAuthenticTestCloudRecoveryControlClient,
  isAuthenticTestCloudRecoveryProductClient,
  readRecoveryOwnerOnlyProjectionDigest,
} from '../../../scripts/verification/test-cloud-appwrite.mjs';
import {
  advanceRecoveryAccountSessionDelete,
  advanceRecoveryAccountSessionList,
  closeRecoveryLease,
  commitRecoveryMutationIssue,
  commitRecoveryResourcesComplete,
  commitRecoveryStepObservation,
  openRecoveryAccountSessionStage,
  openRecoveryCheckpoint,
  readRecoveryCheckpointStage,
} from '../../../scripts/verification/test-cloud-control-store.mjs';
import { createTestRecoveryEnvironmentContext } from '../../../scripts/verification/test-cloud-environment.mjs';
import { createProviderRecoveryControlStore } from '../../../scripts/verification/test-cloud-provider-control-store.mjs';
import {
  qualifyExecutionObservationReadback,
} from '../../../scripts/verification/test-cloud-setup-check.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import { readExactBindingDirectory } from './test-cloud-controller.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const POSITIVE_ID = /^[1-9][0-9]*$/u;
const RESULT_KEYS = Object.freeze(['diagnostics', 'status', 'value']);
const RECOVERY_CLIENT_KEYS = Object.freeze(['control', 'product']);
const RECOVERY_HANDLE_SCOPES = Object.freeze([
  'rows.read',
  'rows.write',
  'users.read',
  'users.write',
  'files.read',
  'files.write',
]);
const encoder = new TextEncoder();

function pass(value) {
  return Object.freeze({ status: 'PASS', value, diagnostics: Object.freeze([]) });
}

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
    return value !== null
      && typeof value === 'object'
      && !Array.isArray(value)
      && Reflect.ownKeys(value).length === keys.length
      && keys.every((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
      });
  } catch {
    return false;
  }
}

function resultValue(outcome) {
  return exactObject(outcome, RESULT_KEYS)
    && outcome.status === 'PASS'
    && Array.isArray(outcome.diagnostics)
    && outcome.diagnostics.length === 0
    && outcome.value !== null
    && typeof outcome.value === 'object'
    && !Array.isArray(outcome.value)
    ? outcome.value
    : null;
}

function digest(value) {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function validProjection(outcome) {
  const value = resultValue(outcome);
  return value !== null
    && typeof value.projection === 'string'
    && ['absent', 'desired', 'invalid', 'old'].includes(value.projection)
    && DIGEST.test(value.projectionDigest ?? '')
    ? value
    : null;
}

function absentProjectionDigest(readMethod) {
  if (readMethod === 'getBoundRow') {
    return digest({
      schemaVersion: 'tablesdb-row-state.v1',
      presence: 'absent',
      dataDigest: null,
      permissionsDigest: null,
    });
  }
  if (readMethod === 'getBoundFile') {
    return digest({
      schemaVersion: 'storage-file-metadata-state.v1',
      presence: 'absent',
      metadataDigest: null,
      permissionsDigest: null,
    });
  }
  return null;
}

function recoveryObservationDigest(primary, extras) {
  return digest({
    schemaVersion: 'verification-recovery-product-observation.v1',
    primaryProjectionDigest: primary.projectionDigest,
    extraProjectionDigests: Object.freeze(Object.entries(extras)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([method, projection]) => Object.freeze({
        method,
        projectionDigest: projection.projectionDigest,
      }))),
  });
}

async function invokeProduct(product, method, authorization) {
  try {
    if (typeof method !== 'string' || typeof product[method] !== 'function') {
      return blocked('RECOVERY_SCOPE_INVALID');
    }
    const outcome = await product[method](authorization);
    return exactObject(outcome, RESULT_KEYS) ? outcome : blocked('CLEANUP_AMBIGUOUS');
  } catch {
    return blocked('CLEANUP_AMBIGUOUS');
  }
}

async function recoverAccountSessions({ clock, context, product, request, store }) {
  let opened = await openRecoveryAccountSessionStage({ clock, context, request, store });
  let value = resultValue(opened);
  if (value === null) return opened;
  if (Object.hasOwn(value, 'nextAuthority')) return pass(value.nextAuthority);
  const session = value.session;
  let action = Object.hasOwn(value, 'listHandle')
    ? { kind: 'list', authorization: value.listHandle }
    : null;
  for (let ordinal = 0; ordinal < 16 && action !== null; ordinal += 1) {
    if (action.kind === 'list') {
      const listed = await invokeProduct(
        product,
        'listBoundAccountSessions',
        action.authorization,
      );
      const listedValue = resultValue(listed);
      if (listedValue === null || !Object.hasOwn(listedValue, 'observation')) return listed;
      opened = await advanceRecoveryAccountSessionList({
        clock,
        context,
        observation: listedValue.observation,
        session,
        store,
      });
    } else {
      await invokeProduct(
        product,
        'deleteBoundAccountSession',
        action.authorization,
      );
      opened = await advanceRecoveryAccountSessionDelete({
        clock,
        context,
        permit: action.authorization,
        session,
        store,
      });
    }
    value = resultValue(opened);
    if (value === null) return opened;
    if (Object.hasOwn(value, 'nextAuthority')) return pass(value.nextAuthority);
    if (Object.hasOwn(value, 'listHandle')) {
      action = { kind: 'list', authorization: value.listHandle };
    } else if (Object.hasOwn(value, 'deletePermit')) {
      action = { kind: 'delete', authorization: value.deletePermit };
    } else {
      return blocked('AUDIT_CHAIN_MISMATCH');
    }
  }
  return blocked('CLEANUP_AMBIGUOUS');
}

async function readStepProjection(product, stage) {
  if (!Object.hasOwn(stage, 'stepHandle')) return blocked('AUDIT_CHAIN_MISMATCH');
  return invokeProduct(product, stage.readMethod, stage.stepHandle);
}

async function commitObservedStep({ clock, context, product, session, stage, store }) {
  const primaryOutcome = await readStepProjection(product, stage);
  const primary = validProjection(primaryOutcome);
  if (primary === null) return primaryOutcome;
  const extras = {};
  for (const method of stage.extraQueryMethods) {
    const authorization = stage.queryStepHandles?.[method];
    if (authorization === undefined) return blocked('AUDIT_CHAIN_MISMATCH');
    const extraOutcome = await invokeProduct(product, method, authorization);
    const extra = validProjection(extraOutcome);
    if (extra === null) return extraOutcome;
    extras[method] = extra;
  }
  if (primary.projection !== 'desired'
    || Object.values(extras).some(({ projection }) => projection !== 'desired')) {
    return blocked('CLEANUP_AMBIGUOUS');
  }
  return commitRecoveryStepObservation({
    clock,
    context,
    providerObservationDigest: recoveryObservationDigest(primary, extras),
    session,
    store,
  });
}

async function issueRecoveryMutation({ context, product, session, stage, store }) {
  const beforeOutcome = await readStepProjection(product, stage);
  const before = validProjection(beforeOutcome);
  if (before === null) return beforeOutcome;
  const desiredProjectionDigest = stage.checkpoint.action === 'delete-and-prove-absent'
    ? absentProjectionDigest(stage.readMethod)
    : stage.checkpoint.action === 'converge-owner-only'
      ? readRecoveryOwnerOnlyProjectionDigest(before)
      : null;
  if (!DIGEST.test(desiredProjectionDigest ?? '')) return blocked('CLEANUP_AMBIGUOUS');
  return commitRecoveryMutationIssue({
    context,
    desiredProjectionDigest,
    preWriteProjectionDigest: before.projectionDigest,
    session,
    store,
  });
}

async function observeIssuedMutation({ clock, context, product, session, stage, store }) {
  const observedOutcome = await readStepProjection(product, stage);
  const observed = validProjection(observedOutcome);
  if (observed === null) return observedOutcome;
  return commitRecoveryStepObservation({
    clock,
    context,
    providerObservationDigest: observed.projectionDigest,
    session,
    store,
  });
}

export async function runTestCloudRecoveryStateMachine(args) {
  try {
    if (!exactObject(args, ['clients', 'clock', 'context'])
      || !exactObject(args.clients, RECOVERY_CLIENT_KEYS)
      || typeof args.clock?.nowEpochSeconds !== 'function'
      || !isAuthenticTestCloudRecoveryControlClient(args.clients.control, args.context)
      || !isAuthenticTestCloudRecoveryProductClient(args.clients.product, args.context)) {
      return blocked('RECOVERY_SCOPE_INVALID');
    }
    const created = createProviderRecoveryControlStore({
      context: args.context,
      recoveryControlClient: args.clients.control,
    });
    const createdValue = resultValue(created);
    if (createdValue === null) return created;
    const store = createdValue.store;
    const sessions = await recoverAccountSessions({
      clock: args.clock,
      context: args.context,
      product: args.clients.product,
      request: createdValue.request,
      store,
    });
    const sessionsValue = resultValue(sessions);
    if (sessionsValue === null) return sessions;
    const opened = await openRecoveryCheckpoint({
      clock: args.clock,
      context: args.context,
      request: sessionsValue,
      store,
    });
    const openedValue = resultValue(opened);
    if (openedValue === null) return opened;
    const session = openedValue.session;

    for (let ordinal = 0; ordinal < 256; ordinal += 1) {
      const staged = await readRecoveryCheckpointStage({
        context: args.context,
        session,
        store,
      });
      const stage = resultValue(staged);
      if (stage === null) return staged;
      const checkpoint = stage.checkpoint;
      if (checkpoint.checkpointState === 'resources-complete') {
        return closeRecoveryLease({
          clock: args.clock,
          context: args.context,
          session,
          store,
        });
      }
      if (checkpoint.checkpointState === 'ready' && checkpoint.prefixLength === 42) {
        const completed = await commitRecoveryResourcesComplete({
          context: args.context,
          session,
          store,
        });
        if (resultValue(completed) === null) return completed;
        continue;
      }
      if (checkpoint.checkpointState === 'ready') {
        if (stage.mutationMethod === null) {
          const committed = await commitObservedStep({
            clock: args.clock,
            context: args.context,
            product: args.clients.product,
            session,
            stage,
            store,
          });
          if (resultValue(committed) === null) return committed;
          continue;
        }
        const issued = await issueRecoveryMutation({
          context: args.context,
          product: args.clients.product,
          session,
          stage,
          store,
        });
        const issuedValue = resultValue(issued);
        if (issuedValue === null || !Object.hasOwn(issuedValue, 'mutationPermit')) return issued;
        await invokeProduct(args.clients.product, stage.mutationMethod, issuedValue.mutationPermit);
        continue;
      }
      if (checkpoint.checkpointState === 'write-issued') {
        const observed = await observeIssuedMutation({
          clock: args.clock,
          context: args.context,
          product: args.clients.product,
          session,
          stage,
          store,
        });
        if (resultValue(observed) === null) return observed;
        continue;
      }
      if (checkpoint.checkpointState === 'blocked'
        && checkpoint.attemptOrdinal === 1
        && checkpoint.providerObservationDigest === checkpoint.preWriteProjectionDigest) {
        const retried = await commitRecoveryMutationIssue({
          context: args.context,
          desiredProjectionDigest: checkpoint.desiredProjectionDigest,
          preWriteProjectionDigest: checkpoint.preWriteProjectionDigest,
          session,
          store,
        });
        const retriedValue = resultValue(retried);
        if (retriedValue === null || !Object.hasOwn(retriedValue, 'mutationPermit')) return retried;
        await invokeProduct(args.clients.product, stage.mutationMethod, retriedValue.mutationPermit);
        continue;
      }
      return blocked('CLEANUP_AMBIGUOUS');
    }
    return blocked('CLEANUP_AMBIGUOUS');
  } catch {
    return blocked('RECOVERY_SCOPE_INVALID');
  }
}

function recoveryHandle(secret) {
  const handle = {
    credentialClass: 'test-recovery',
    variableName: 'APPWRITE_TEST_RECOVERY_API_KEY',
    scopes: RECOVERY_HANDLE_SCOPES,
    readSecret() {
      return secret;
    },
  };
  return Object.freeze(handle);
}

function readHostedObservationQualification(bindings) {
  try {
    const text = bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_JSON;
    const expectedDigest = bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST;
    if (typeof text !== 'string' || !DIGEST.test(expectedDigest ?? '')) return null;
    const readback = JSON.parse(text);
    if (canonicalJson(readback) !== text || digest(readback) !== expectedDigest) return null;
    const observationDigest = digest(readback.executionObservation);
    const qualified = qualifyExecutionObservationReadback({
      inventory,
      readback: readback.executionObservation,
      expectedReadbackDigest: observationDigest,
    });
    return resultValue(qualified);
  } catch {
    return null;
  }
}

function parseHostedArgs(argv) {
  if (!Array.isArray(argv)
    || argv.length !== 6
    || argv[0] !== '--hosted'
    || argv[1] !== '--original-workflow-run-id'
    || !POSITIVE_ID.test(argv[2] ?? '')
    || argv[3] !== '--binding-directory'
    || typeof argv[4] !== 'string'
    || argv[4].length < 1
    || argv[4].includes('\0')
    || argv[5] !== '--execute') return null;
  return Object.freeze({
    originalWorkflowRunId: argv[2],
    bindingDirectory: argv[4],
  });
}

function write(stream, value) {
  if (stream && typeof stream.write === 'function') stream.write(value);
}

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  const parsed = parseHostedArgs(argv);
  const environment = dependencies.environment ?? process.env;
  const stderr = dependencies.stderr ?? process.stderr;
  const stdout = dependencies.stdout ?? process.stdout;
  if (parsed === null) {
    write(stderr, 'BLOCKED RECOVERY_CLI_INVALID\n');
    return 2;
  }
  try {
    const controllerBundleSha = environment.TRUSTED_CONTROLLER_SHA;
    const runtimeSha = environment.GITHUB_SHA;
    const secret = environment.APPWRITE_TEST_RECOVERY_API_KEY;
    if (!FULL_SHA.test(controllerBundleSha ?? '')
      || runtimeSha !== controllerBundleSha
      || typeof secret !== 'string'
      || secret.length < 1
      || environment.GITHUB_REPOSITORY !== 'Krowaccie/AppWriteWork-verification-control') {
      throw new TypeError('invalid recovery environment');
    }
    const bindingDirectory = path.resolve(parsed.bindingDirectory);
    if (!path.isAbsolute(parsed.bindingDirectory) || bindingDirectory !== parsed.bindingDirectory) {
      throw new TypeError('invalid binding directory');
    }
    const bindings = await readExactBindingDirectory(
      bindingDirectory,
      dependencies.bindingDirectoryIo,
    );
    const executionObservationQualification = readHostedObservationQualification(bindings);
    if (executionObservationQualification === null) throw new TypeError('invalid observation');
    const handle = recoveryHandle(secret);
    const approvalRef = `https://github.com/Krowaccie/AppWriteWork-verification-control/actions/runs/${parsed.originalWorkflowRunId}`;
    const contextOutcome = createTestRecoveryEnvironmentContext({
      approvalRef,
      controllerBundleSha,
      environment: inventory.environment,
      executionObservationQualification,
      originalWorkflowRunId: parsed.originalWorkflowRunId,
      recoveryHandle: handle,
    });
    const context = resultValue(contextOutcome);
    if (context === null) throw new TypeError('invalid recovery context');
    const clientsOutcome = createTestCloudRecoveryClients({
      context,
      fetch: dependencies.fetchImpl ?? globalThis.fetch,
      recoveryHandle: handle,
    });
    const clients = resultValue(clientsOutcome);
    if (clients === null) throw new TypeError('invalid recovery clients');
    const outcome = await (dependencies.runRecovery ?? runTestCloudRecoveryStateMachine)({
      clients,
      clock: Object.freeze({ nowEpochSeconds: () => Math.floor(Date.now() / 1000) }),
      context,
    });
    if (resultValue(outcome) === null) {
      const code = exactObject(outcome, RESULT_KEYS)
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
