import { canonicalJson, sha256Bytes } from '../../../scripts/verification/canonical-json.mjs';
import { commitIntentSnapshot } from '../../../scripts/verification/test-cloud-control-runtime.mjs';
import {
  captureTestCloudProviderMutationRoute,
  createShareBaselineProof,
  installProviderControlStore,
  issueProviderMutation,
  issueShareCreate,
  reconcileProviderMutation,
  reconcileShareCreate,
} from '../../../scripts/verification/test-cloud-provider-contract.mjs';
import providerContract from '../../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json' with { type: 'json' };

const RESOURCES = Object.freeze([
  Object.freeze({ resourceType: 'primary-project', dependencyOrder: 10 }),
  Object.freeze({ resourceType: 'primary-graph', dependencyOrder: 20 }),
  Object.freeze({ resourceType: 'primary-share', dependencyOrder: 30 }),
]);
const INITIALIZER_KEYS = Object.freeze([
  'runtimeQualification', 'context', 'providerContractQualification', 'store',
  'lease', 'capability', 'clock', 'providerContractDigest',
]);
const PRODUCER_KEYS = Object.freeze([
  'context', 'store', 'lease', 'capability', 'clock', 'providerContractDigest',
  'sessionIntentQualification', 'fixtureMutationPort',
]);
const MUTATION_PORT_KEYS = Object.freeze([
  'performOwnerLogin',
  'performProjectCreateAndGraphEditPrefix',
  'performEditorShare',
  'performViewerShare',
]);
const MARKERS = Object.freeze([
  'ownerLoginComplete',
  'projectGraphPrefixReady',
  'editorShareComplete',
  'viewerShareComplete',
]);
const INTENT_KEYS = Object.freeze([
  'schemaVersion', 'intentId', 'runId', 'environmentDigest', 'resourceType',
  'resourceId', 'providerAggregateJson', 'providerAggregateDigest', 'ownerMarker',
  'dependencyOrder', 'lifecycleClass', 'state', 'intentVersion',
  'observationDigest', 'retentionExpiresAt', 'cleanupCursor',
  'cleanupProgressDigest', 'cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest', 'cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson', 'cleanupRunnerExecutionRecordDigest',
  'cleanupRunnerExecutionRetentionExpiresAt', 'createdAt', 'updatedAt',
]);
const NULL_CLEANUP_KEYS = Object.freeze([
  'observationDigest', 'retentionExpiresAt', 'cleanupCursor',
  'cleanupProgressDigest', 'cleanupProofDigest',
  'cleanupRunnerExecutionPlanDigest', 'cleanupRunnerExecutionCursor',
  'cleanupRunnerExecutionSlotsJson', 'cleanupRunnerExecutionRecordDigest',
  'cleanupRunnerExecutionRetentionExpiresAt',
]);
const LEASE_KEYS = Object.freeze([
  'acquiredAt', 'cleanupDebt', 'environmentDigest', 'expiresAt', 'leaseRowId',
  'leaseTokenDigest', 'leaseVersion', 'ledgerDigest', 'ownerRunId',
  'ownerWorkflowRunId', 'renewedAt', 'state',
]);
const AUDIT_EVENT_KEYS = Object.freeze([
  'schemaVersion', 'previousLedgerDigest', 'runId', 'leaseVersionBefore',
  'leaseVersionAfter', 'transition', 'intentId', 'intentProjectionDigest',
]);
const STABLE_SUCCESSOR_LEASE_KEYS = Object.freeze([
  'acquiredAt', 'environmentDigest', 'leaseRowId', 'leaseTokenDigest',
  'ownerRunId', 'ownerWorkflowRunId',
]);
const encoder = new TextEncoder();
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SESSION_LINEAGES = new WeakMap();

function digest(value) {
  return sha256Bytes(encoder.encode(canonicalJson(value)));
}

function textDigest(value) {
  return sha256Bytes(encoder.encode(value));
}

function exactDataRecord(value, keys) {
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

function frozen(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) frozen(child);
    Object.freeze(value);
  }
  return value;
}

function blocked() {
  return frozen({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code: 'TEST_CLOUD_SETUP_INCOMPLETE',
      safeMessage: 'Fixture intent initialization was blocked.',
      retryable: false,
    }],
  });
}

function blockedAtHead(head) {
  const state = Object.assign(Object.create(null), {
    lease: head.lease,
    capability: head.capability,
  });
  Object.freeze(state);
  return frozen({
    status: 'BLOCKED',
    value: state,
    diagnostics: [{
      code: 'TEST_CLOUD_SETUP_INCOMPLETE',
      safeMessage: 'Fixture intent initialization was blocked.',
      retryable: false,
    }],
  });
}

function exactCleanupDebtSuccessor(candidate, prior, context) {
  try {
    return exactDataRecord(candidate, LEASE_KEYS)
      && exactDataRecord(prior, LEASE_KEYS)
      && Object.isFrozen(candidate)
      && Object.isFrozen(prior)
      && prior.state === 'active'
      && prior.cleanupDebt === false
      && candidate.state === 'cleanup-debt'
      && candidate.cleanupDebt === true
      && Number.isSafeInteger(prior.leaseVersion)
      && prior.leaseVersion >= 0
      && Number.isSafeInteger(candidate.leaseVersion)
      && candidate.leaseVersion > prior.leaseVersion
      && candidate.leaseVersion - prior.leaseVersion <= 256
      && DIGEST.test(prior.ledgerDigest)
      && DIGEST.test(candidate.ledgerDigest)
      && candidate.ledgerDigest !== prior.ledgerDigest
      && candidate.ownerRunId === context.runId
      && candidate.environmentDigest === context.environmentDigest
      && Number.isFinite(Date.parse(prior.renewedAt))
      && Number.isFinite(Date.parse(prior.expiresAt))
      && Number.isFinite(Date.parse(candidate.renewedAt))
      && Number.isFinite(Date.parse(candidate.expiresAt))
      && Date.parse(candidate.renewedAt) >= Date.parse(prior.renewedAt)
      && Date.parse(candidate.expiresAt) >= Date.parse(prior.expiresAt)
      && Date.parse(candidate.expiresAt) > Date.parse(candidate.renewedAt)
      && STABLE_SUCCESSOR_LEASE_KEYS.every((key) => candidate[key] === prior[key]);
  } catch {
    return false;
  }
}

function exactAuditEventAt(event, head, leaseVersionAfter, context) {
  return exactDataRecord(event, AUDIT_EVENT_KEYS)
    && Object.isFrozen(event)
    && event.schemaVersion === 'verification-audit-event.v1'
    && DIGEST.test(event.previousLedgerDigest)
    && event.runId === context.runId
    && event.leaseVersionBefore === leaseVersionAfter - 1
    && event.leaseVersionAfter === leaseVersionAfter
    && typeof event.transition === 'string'
    && /^[a-z][a-z0-9._]{1,127}$/u.test(event.transition)
    && (
      (event.intentId === null && event.intentProjectionDigest === null)
      || (typeof event.intentId === 'string' && DIGEST.test(event.intentProjectionDigest))
    )
    && digest(event) === head;
}

async function exactCleanupDebtAuditLineage(store, debt, prior, context) {
  let head = debt.ledgerDigest;
  let leaseVersionAfter = debt.leaseVersion;
  let terminal = true;
  const seen = new Set();
  while (head !== prior.ledgerDigest) {
    if (leaseVersionAfter <= prior.leaseVersion || seen.has(head)) return false;
    seen.add(head);
    const event = await store.getAuditEventByDigest(head);
    if (!exactAuditEventAt(event, head, leaseVersionAfter, context)) return false;
    if (terminal) {
      if (event.transition !== 'lease.cleanup_debt'
        || event.intentId !== null
        || event.intentProjectionDigest !== null) return false;
    } else if (event.transition === 'lease.cleanup_debt') return false;
    head = event.previousLedgerDigest;
    leaseVersionAfter = event.leaseVersionBefore;
    terminal = false;
  }
  return terminal === false && leaseVersionAfter === prior.leaseVersion;
}

const approvedProviderContractDigest = sha256Bytes(encoder.encode(
  `${canonicalJson(providerContract)}\n`,
));

function identityFor(context, resourceType) {
  const parameters = {};
  const operationScenario = 'sharing-permissions';
  const operationKey = textDigest(`${context.runId}|${operationScenario}|${canonicalJson(parameters)}`);
  const resourceId = `vr-${textDigest(
    `${context.environmentDigest}|${context.runId}|${resourceType}`,
  ).slice(7, 39)}`;
  const intentId = textDigest(
    `${context.environmentDigest}|${context.runId}|${resourceType}|${resourceId}`,
  ).slice(7);
  const ownerMarker = `verification-owner.v1:${digest({
    schemaVersion: 'verification-owner-marker.v1',
    environmentDigest: context.environmentDigest,
    operationKey,
    runId: context.runId,
    resourceType,
    resourceId,
  })}`;
  return { intentId, operationKey, operationScenario, ownerMarker, parameters, resourceId, resourceType };
}

function aggregateBinding(context, identity, providerContractDigest) {
  return {
    schemaVersion: 'verification-provider-aggregate-binding.v1',
    environmentDigest: context.environmentDigest,
    providerContractDigest,
    runId: context.runId,
    resourceType: identity.resourceType,
    resourceId: identity.resourceId,
    operationScenario: identity.operationScenario,
    parameters: identity.parameters,
    operationKey: identity.operationKey,
    ownerMarker: identity.ownerMarker,
    intentId: identity.intentId,
  };
}

function plannedMember(template, identity, bindingDigest) {
  const memberBinding = {
    schemaVersion: 'verification-provider-member-binding.v1',
    aggregateBindingDigest: bindingDigest,
    ownerResourceType: identity.resourceType,
    ownerResourceId: identity.resourceId,
    slot: template.slot,
    ownerOrdinal: template.ownerOrdinal,
    memberTemplateDigest: template.memberTemplateDigest,
  };
  const isFile = template.providerKind === 'storage-file';
  return {
    schemaVersion: 'verification-provider-member.v1',
    memberBinding,
    memberBindingDigest: digest(memberBinding),
    providerId: null,
    providerIdentity: null,
    bindingState: identity.resourceType === 'primary-share' ? 'unissued' : 'unbound',
    logicalValueBindings: template.logicalValueBindingContracts.map((contract) => ({
      name: contract.name,
      valueKind: contract.valueKind,
      sourceMutationOrdinal: contract.sourceMutationOrdinal,
      state: 'unbound',
      value: null,
      valueDigest: null,
    })),
    operationStates: template.operations.map((operation) => ({
      mutationOrdinal: operation.mutationOrdinal,
      state: 'pending',
      requestInstanceDigest: null,
      expectedResultState: null,
      resultStateDigest: null,
      baselineDigest: null,
      discoveryProofDigest: null,
    })),
    memberState: identity.resourceType === 'primary-share'
      ? {
        schemaVersion: 'tablesdb-row-state.v1', dataDigest: null,
        permissionsDigest: null, presence: 'absent',
      }
      : isFile
        ? {
          schemaVersion: 'storage-file-metadata-state.v1', metadataDigest: null,
          permissionsDigest: null, presence: 'unknown',
        }
        : {
          schemaVersion: 'tablesdb-row-state.v1', dataDigest: null,
          permissionsDigest: null, presence: 'unknown',
        },
  };
}

function plannedReference(context, reference, providerContractDigest) {
  const owner = identityFor(context, reference.ownerResourceType);
  const ownerBinding = aggregateBinding(context, owner, providerContractDigest);
  const ownerResource = providerContract.aggregateContracts.resources.find((resource) => (
    resource.resourceType === reference.ownerResourceType
  ));
  const template = ownerResource.memberTemplates[reference.ownerOrdinal];
  const memberBinding = {
    schemaVersion: 'verification-provider-member-binding.v1',
    aggregateBindingDigest: digest(ownerBinding),
    ownerResourceType: reference.ownerResourceType,
    ownerResourceId: owner.resourceId,
    slot: reference.ownerSlot,
    ownerOrdinal: reference.ownerOrdinal,
    memberTemplateDigest: template.memberTemplateDigest,
  };
  return {
    schemaVersion: 'verification-provider-member-reference.v1',
    memberBinding,
    memberBindingDigest: digest(memberBinding),
  };
}

function plannedSnapshot(context, clock, { resourceType, dependencyOrder }, providerContractDigest) {
  const identity = identityFor(context, resourceType);
  const resource = providerContract.aggregateContracts.resources.find((candidate) => (
    candidate.resourceType === resourceType
  ));
  const binding = aggregateBinding(context, identity, providerContractDigest);
  const bindingDigest = digest(binding);
  const aggregate = {
    schemaVersion: 'verification-provider-aggregate.v1',
    phase: 'owner-baseline',
    aggregateBinding: binding,
    aggregateBindingDigest: bindingDigest,
    ownedMembers: resource.memberTemplates.map((template) => plannedMember(template, identity, bindingDigest)),
    referencedMembers: resource.referencedSlots.map((reference) => plannedReference(
      context, reference, providerContractDigest,
    )),
  };
  const at = new Date(clock.nowEpochSeconds() * 1000).toISOString();
  return frozen({
    schemaVersion: 'verification-intent-snapshot.v2',
    intentId: identity.intentId,
    runId: context.runId,
    environmentDigest: context.environmentDigest,
    resourceType,
    resourceId: identity.resourceId,
    providerAggregateJson: canonicalJson(aggregate),
    providerAggregateDigest: digest(aggregate),
    ownerMarker: identity.ownerMarker,
    dependencyOrder,
    lifecycleClass: 'fixture',
    state: 'planned',
    intentVersion: 1,
    observationDigest: null,
    retentionExpiresAt: null,
    cleanupCursor: null,
    cleanupProgressDigest: null,
    cleanupProofDigest: null,
    cleanupRunnerExecutionPlanDigest: null,
    cleanupRunnerExecutionCursor: null,
    cleanupRunnerExecutionSlotsJson: null,
    cleanupRunnerExecutionRecordDigest: null,
    cleanupRunnerExecutionRetentionExpiresAt: null,
    createdAt: at,
    updatedAt: at,
  });
}

function exactInstallPass(value) {
  return exactDataRecord(value, ['status', 'value', 'diagnostics'])
    && value.status === 'PASS'
    && Array.isArray(value.diagnostics)
    && value.diagnostics.length === 0
    && exactDataRecord(value.value, ['installed', 'sessionIntentQualification'])
    && value.value.installed === true
    && exactOpaqueToken(value.value.sessionIntentQualification);
}

function exactOpaqueToken(value) {
  try {
    return value !== null
      && typeof value === 'object'
      && Object.getPrototypeOf(value) === null
      && Object.isFrozen(value)
      && Reflect.ownKeys(value).length === 0;
  } catch {
    return false;
  }
}

function exactMutationPort(value) {
  try {
    const keys = Reflect.ownKeys(value);
    return value !== null
      && typeof value === 'object'
      && Object.getPrototypeOf(value) === null
      && Object.isFrozen(value)
      && keys.length === MUTATION_PORT_KEYS.length
      && MUTATION_PORT_KEYS.every((key, index) => (
        keys[index] === key
        && Object.getOwnPropertyDescriptor(value, key)?.enumerable === true
        && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value')
        && typeof Object.getOwnPropertyDescriptor(value, key).value === 'function'
        && Object.getOwnPropertyDescriptor(value, key).value.length === 0
        && Object.isFrozen(Object.getOwnPropertyDescriptor(value, key).value)
      ));
  } catch {
    return false;
  }
}

function exactMarkerPass(value, marker) {
  return exactDataRecord(value, ['status', 'value', 'diagnostics'])
    && value.status === 'PASS'
    && Array.isArray(value.diagnostics)
    && Object.isFrozen(value.diagnostics)
    && value.diagnostics.length === 0
    && exactDataRecord(value.value, [marker])
    && Object.isFrozen(value.value)
    && value.value[marker] === true;
}

function publicRecord(values) {
  return Object.freeze({ ...values });
}

function exactPublicPass(value, key, predicate) {
  return exactDataRecord(value, ['status', 'value', 'diagnostics'])
    && value.status === 'PASS'
    && Array.isArray(value.diagnostics)
    && Object.isFrozen(value.diagnostics)
    && value.diagnostics.length === 0
    && exactDataRecord(value.value, [key])
    && predicate(value.value[key]);
}

function opaque(value) {
  return exactOpaqueToken(value);
}

async function nextOwnedRouteTurn() {
  await new Promise((resolve) => setImmediate(resolve));
}

async function driveProviderMutation(lineage, mutationOrdinal) {
  await nextOwnedRouteTurn();
  const common = publicRecord({
    runtimeQualification: lineage.runtimeQualification,
    context: lineage.context,
    sessionIntentQualification: lineage.sessionIntentQualification,
    mutationOrdinal,
  });
  const captured = await captureTestCloudProviderMutationRoute(common);
  if (!exactPublicPass(captured, 'captured', (value) => value === true)) return false;
  const issued = await issueProviderMutation(common);
  if (!exactPublicPass(issued, 'providerMutationIssue', opaque)) return false;
  const reconciled = await reconcileProviderMutation(publicRecord({
    runtimeQualification: lineage.runtimeQualification,
    providerMutationIssue: issued.value.providerMutationIssue,
  }));
  return exactPublicPass(reconciled, 'reconciliationQualification', opaque);
}

async function driveShareMutation(lineage, mutationOrdinal, ownerSlot) {
  await nextOwnedRouteTurn();
  const captured = await captureTestCloudProviderMutationRoute(publicRecord({
    runtimeQualification: lineage.runtimeQualification,
    context: lineage.context,
    sessionIntentQualification: lineage.sessionIntentQualification,
    mutationOrdinal,
  }));
  if (!exactPublicPass(captured, 'captured', (value) => value === true)) return false;
  const baseline = await createShareBaselineProof(publicRecord({
    runtimeQualification: lineage.runtimeQualification,
    context: lineage.context,
    sessionIntentQualification: lineage.sessionIntentQualification,
    providerQualification: lineage.providerContractQualification,
    ownerSlot,
  }));
  if (!exactPublicPass(baseline, 'baselineProof', opaque)) return false;
  const issued = await issueShareCreate(publicRecord({
    runtimeQualification: lineage.runtimeQualification,
    context: lineage.context,
    sessionIntentQualification: lineage.sessionIntentQualification,
    providerQualification: lineage.providerContractQualification,
    baselineProof: baseline.value.baselineProof,
    requestTuple: Object.freeze(Object.create(null)),
  }));
  if (!exactPublicPass(issued, 'shareIssue', opaque)) return false;
  const reconciled = await reconcileShareCreate(publicRecord({
    runtimeQualification: lineage.runtimeQualification,
    shareIssue: issued.value.shareIssue,
  }));
  return exactPublicPass(reconciled, 'reconciled', (value) => value === true);
}

function exactLease(value, expected) {
  try {
    return value !== null
      && typeof value === 'object'
      && canonicalJson(value) === canonicalJson(expected);
  } catch {
    return false;
  }
}

function exactCreatedIntent(intent, context, resource, providerContractDigest) {
  try {
    if (
      !exactDataRecord(intent, INTENT_KEYS)
      || intent.schemaVersion !== 'verification-intent-snapshot.v2'
      || intent.runId !== context.runId
      || intent.environmentDigest !== context.environmentDigest
      || intent.resourceType !== resource.resourceType
      || intent.dependencyOrder !== resource.dependencyOrder
      || intent.lifecycleClass !== 'fixture'
      || intent.state !== 'created'
      || !Number.isSafeInteger(intent.intentVersion)
      || intent.intentVersion < 2
      || NULL_CLEANUP_KEYS.some((key) => intent[key] !== null)
      || Date.parse(intent.updatedAt) < Date.parse(intent.createdAt)
    ) return false;
    const identity = identityFor(context, resource.resourceType);
    if (
      intent.intentId !== identity.intentId
      || intent.resourceId !== identity.resourceId
      || intent.ownerMarker !== identity.ownerMarker
    ) return false;
    const aggregate = JSON.parse(intent.providerAggregateJson);
    const expectedPhase = resource.resourceType === 'primary-share'
      ? 'shared' : 'normal-owner';
    return canonicalJson(aggregate) === intent.providerAggregateJson
      && digest(aggregate) === intent.providerAggregateDigest
      && exactDataRecord(aggregate, [
        'schemaVersion', 'phase', 'aggregateBinding', 'aggregateBindingDigest',
        'ownedMembers', 'referencedMembers',
      ])
      && aggregate.schemaVersion === 'verification-provider-aggregate.v1'
      && aggregate.phase === expectedPhase
      && canonicalJson(aggregate.aggregateBinding)
        === canonicalJson(aggregateBinding(context, identity, providerContractDigest))
      && aggregate.aggregateBindingDigest === digest(aggregate.aggregateBinding)
      && Array.isArray(aggregate.ownedMembers)
      && Array.isArray(aggregate.referencedMembers);
  } catch {
    return false;
  }
}

function exactNineteenReconciledOperations(intents) {
  try {
    const ordinals = [];
    for (const intent of intents) {
      const aggregate = JSON.parse(intent.providerAggregateJson);
      for (const member of aggregate.ownedMembers) {
        for (const operation of member.operationStates) {
          if (operation.state !== 'reconciled') return false;
          ordinals.push(operation.mutationOrdinal);
        }
      }
    }
    return ordinals.length === 19
      && [...ordinals].sort((left, right) => left - right)
        .every((ordinal, index) => ordinal === index);
  } catch {
    return false;
  }
}

async function recoverCurrentHead(lineage) {
  try {
    const durableLease = await lineage.store.getLease();
    if (exactLease(durableLease, lineage.lease)) {
      return Object.freeze({ lease: lineage.lease, capability: lineage.capability });
    }
    for (const resource of RESOURCES) {
      const identity = identityFor(lineage.context, resource.resourceType);
      const snapshot = await lineage.store.getIntentProjection(identity.intentId);
      if (snapshot === null || typeof snapshot !== 'object') continue;
      const replayed = await commitIntentSnapshot({
        context: lineage.context,
        store: lineage.store,
        lease: lineage.lease,
        capability: lineage.capability,
        clock: lineage.clock,
        snapshot,
      });
      if (
        replayed?.status === 'PASS'
        && exactLease(replayed.value?.lease, durableLease)
        && opaque(replayed.value?.capability)
        && canonicalJson(replayed.value?.snapshot) === canonicalJson(snapshot)
      ) {
        return Object.freeze({
          lease: replayed.value.lease,
          capability: replayed.value.capability,
        });
      }
      return null;
    }
    return null;
  } catch {
    return null;
  }
}

async function recoverCurrentCleanupDebtHead(lineage) {
  try {
    if (typeof lineage.store.getAuditEventByDigest !== 'function') return null;
    const durableLease = await lineage.store.getLease();
    if (!exactCleanupDebtSuccessor(durableLease, lineage.lease, lineage.context)) return null;
    if (!await exactCleanupDebtAuditLineage(
      lineage.store,
      durableLease,
      lineage.lease,
      lineage.context,
    )) return null;
    const currentLease = await lineage.store.getLease();
    if (!exactLease(currentLease, durableLease)
      || !exactCleanupDebtSuccessor(currentLease, lineage.lease, lineage.context)) return null;
    return Object.freeze({ lease: currentLease, capability: null });
  } catch {
    return null;
  }
}

async function settlePortAndBlock(lineage, startedPort) {
  if (startedPort !== undefined) {
    try {
      await startedPort;
    } catch {
      // The private broker owns abort; only settlement is observed here.
    }
  }
  const head = await recoverCurrentHead(lineage);
  if (head !== null) return blockedAtHead(head);
  const debtHead = await recoverCurrentCleanupDebtHead(lineage);
  return debtHead === null ? blocked() : blockedAtHead(debtHead);
}

export async function initializeProviderFixtureIntentSet(args) {
  try {
    if (!exactDataRecord(args, INITIALIZER_KEYS)
      || typeof args.context?.runId !== 'string'
      || typeof args.context?.environmentDigest !== 'string'
      || typeof args.clock?.nowEpochSeconds !== 'function'
      || args.providerContractDigest !== approvedProviderContractDigest) return blocked();
    let lease = args.lease;
    let capability = args.capability;
    const intents = [];
    for (const resource of RESOURCES) {
      const snapshot = plannedSnapshot(args.context, args.clock, resource, args.providerContractDigest);
      const committed = await commitIntentSnapshot({
        context: args.context,
        store: args.store,
        lease,
        capability,
        clock: args.clock,
        snapshot,
      });
      if (
        committed?.status !== 'PASS'
        || !exactDataRecord(committed.value, ['lease', 'capability', 'event', 'snapshot'])
        || committed.value.lease === null
        || typeof committed.value.lease !== 'object'
        || !exactOpaqueToken(committed.value.capability)
        || canonicalJson(committed.value.snapshot) !== canonicalJson(snapshot)
      ) {
        return blocked();
      }
      lease = committed.value.lease;
      capability = committed.value.capability;
      intents.push(committed.value.snapshot);
    }
    const installed = await installProviderControlStore(publicRecord({
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      providerContractQualification: args.providerContractQualification,
      providerControlStore: args.store,
    }));
    if (!exactInstallPass(installed)) return blocked();
    const lineage = Object.freeze({
      runtimeQualification: args.runtimeQualification,
      context: args.context,
      providerContractQualification: args.providerContractQualification,
      store: args.store,
      lease,
      capability,
      clock: args.clock,
      providerContractDigest: args.providerContractDigest,
      sessionIntentQualification: installed.value.sessionIntentQualification,
      intents: Object.freeze([...intents]),
    });
    SESSION_LINEAGES.set(installed.value.sessionIntentQualification, lineage);
    return frozen({
      status: 'PASS',
      value: { lease, capability, sessionIntentQualification: installed.value.sessionIntentQualification, intents },
      diagnostics: [],
    });
  } catch {
    return blocked();
  }
}

export async function runTrustedTestCloudFixtureIntentProducer(args) {
  let startedPort;
  let lineage;
  try {
    lineage = SESSION_LINEAGES.get(args?.sessionIntentQualification);
    if (
      !exactDataRecord(args, PRODUCER_KEYS)
      || typeof args.context?.runId !== 'string'
      || typeof args.context?.environmentDigest !== 'string'
      || typeof args.clock?.nowEpochSeconds !== 'function'
      || args.providerContractDigest !== approvedProviderContractDigest
      || !exactOpaqueToken(args.sessionIntentQualification)
      || !exactMutationPort(args.fixtureMutationPort)
      || typeof args.store?.getLease !== 'function'
      || typeof args.store?.getIntentProjection !== 'function'
      || lineage === undefined
      || lineage.context !== args.context
      || lineage.store !== args.store
      || lineage.clock !== args.clock
      || lineage.providerContractDigest !== args.providerContractDigest
      || lineage.lease !== args.lease
      || lineage.capability !== args.capability
    ) return blocked();

    const installedLease = await args.store.getLease();
    if (!exactLease(installedLease, args.lease)) return blocked();
    for (const expected of lineage.intents) {
      const observed = await args.store.getIntentProjection(expected.intentId);
      if (canonicalJson(observed) !== canonicalJson(expected)) return blocked();
    }

    const portMethods = MUTATION_PORT_KEYS.map((key) => (
      Object.getOwnPropertyDescriptor(args.fixtureMutationPort, key).value
    ));
    const owner = await portMethods[0]();
    if (!exactMarkerPass(owner, MARKERS[0])) return settlePortAndBlock(lineage);
    startedPort = portMethods[1]();
    for (let mutationOrdinal = 0; mutationOrdinal <= 16; mutationOrdinal += 1) {
      if (!await driveProviderMutation(lineage, mutationOrdinal)) {
        return settlePortAndBlock(lineage, startedPort);
      }
    }
    if (!exactMarkerPass(await startedPort, MARKERS[1])) {
      return settlePortAndBlock(lineage, startedPort);
    }
    startedPort = undefined;

    startedPort = portMethods[2]();
    if (!await driveShareMutation(lineage, 17, 'editorShare')) {
      return settlePortAndBlock(lineage, startedPort);
    }
    if (!exactMarkerPass(await startedPort, MARKERS[2])) {
      return settlePortAndBlock(lineage, startedPort);
    }
    startedPort = undefined;

    startedPort = portMethods[3]();
    if (!await driveShareMutation(lineage, 18, 'viewerShare')) {
      return settlePortAndBlock(lineage, startedPort);
    }
    if (!exactMarkerPass(await startedPort, MARKERS[3])) {
      return settlePortAndBlock(lineage, startedPort);
    }
    startedPort = undefined;

    const durableLease = await args.store.getLease();
    if (durableLease === null || typeof durableLease !== 'object') return blocked();
    let lease = args.lease;
    let capability = args.capability;
    const intents = [];
    for (const resource of RESOURCES) {
      const identity = identityFor(args.context, resource.resourceType);
      const intent = await args.store.getIntentProjection(identity.intentId);
      if (!exactCreatedIntent(
        intent,
        args.context,
        resource,
        args.providerContractDigest,
      )) return blocked();
      const replayed = await commitIntentSnapshot({
        context: args.context,
        store: args.store,
        lease,
        capability,
        clock: args.clock,
        snapshot: intent,
      });
      if (
        replayed?.status !== 'PASS'
        || !exactLease(replayed.value?.lease, durableLease)
        || !opaque(replayed.value?.capability)
        || canonicalJson(replayed.value?.snapshot) !== canonicalJson(intent)
      ) return blocked();
      lease = replayed.value.lease;
      capability = replayed.value.capability;
      intents.push(intent);
    }
    if (!exactNineteenReconciledOperations(intents)) return blocked();
    return frozen({
      status: 'PASS',
      value: { lease, capability, intents },
      diagnostics: [],
    });
  } catch {
    return lineage === undefined
      ? blocked()
      : settlePortAndBlock(lineage, startedPort);
  }
}
