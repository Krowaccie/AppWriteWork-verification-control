import { types as utilTypes } from 'node:util';

import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import { canonicalJson, sha256Bytes } from './canonical-json.mjs';
import { validateArtifactManifest } from './artifact-manifest.mjs';
import { readExecutionObservationQualification } from './test-cloud-setup-check.mjs';
import { validateTestCloudSetupAttestationDocument } from './test-cloud-setup-attestation.mjs';
import { isAuthenticTestEnvironmentContext } from './test-cloud-environment.mjs';
import {
  authenticateTestCloudRuntimeActive,
  isQualifiedTestCloudProviderContract,
  isQualifiedTestCloudSetupReadback,
} from './test-cloud-provider-contract.mjs';
import { isQualifiedTestCloudIdentityBindings } from './test-cloud-identity-bindings.mjs';
import { isAuthenticTestCloudRunnerVariableReadbackResult } from './test-cloud-appwrite.mjs';

const IS_PROXY = utilTypes.isProxy;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ATTESTATION_INPUT_KEYS = Object.freeze([
  'runtimeQualification',
  'context',
  'document',
  'expectedDocumentDigest',
  'clock',
  'executionObservationQualification',
  'providerContract',
  'identityBindings',
  'providerSetupReadback',
  'runnerVariableReadbackResult',
]);
const PREFLIGHT_INPUT_KEYS = Object.freeze([
  'runtimeQualification', 'context', 'clients', 'manifest', 'setupAttestation', 'clock',
]);
const ATTESTATION_BINDINGS = new WeakMap();
const PREFLIGHT_BINDINGS = new WeakMap();
const AUTHENTIC_PREFLIGHT_RESULTS = new WeakSet();
const PREFLIGHT_CONTEXTS = new WeakMap();

const FIXED_LEASE_IDENTITY = Object.freeze({
  databaseId: 'verification_control',
  tableId: 'verification_leases',
  rowId: 'appwrite_test_verification',
});

const RUNNER = Object.freeze({
  logicalId: 'verification-runner-py',
  functionId: 'verification-runner-py',
  sourcePath: 'src/functions/verification-runner-py',
});
const EXPECTED_RUNNER_CONFIGURATION = Object.freeze({
  functionId: 'verification-runner-py',
  runtime: 'python-3.12',
  entrypoint: 'main.py',
  commands: 'python -m pip install --require-hashes --only-binary=:all: -r requirements.txt',
  providerRootDirectory: 'src/functions/verification-runner-py',
  name: 'verification-runner',
  execute: Object.freeze([]),
  events: Object.freeze([]),
  schedule: '',
  timeout: 30,
  enabled: false,
  logging: false,
  scopes: Object.freeze([
    'execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write',
  ]),
});


const EXPECTED_FUNCTIONS = Object.freeze([...inventory.productFunctions, RUNNER]);
const EXPECTED_FUNCTION_IDS = Object.freeze(EXPECTED_FUNCTIONS
  .map(({ functionId }) => functionId)
  .sort((left, right) => left < right ? -1 : left > right ? 1 : 0));

function ordinalCompare(left, right) { return left < right ? -1 : left > right ? 1 : 0; }

const MESSAGES = Object.freeze({
  ARTIFACT_HANDOFF_INVALID: 'Artifact manifest does not match the exact deployable inventory.',
  TEST_CLOUD_PREFLIGHT_MISMATCH: 'Test-cloud recurring readback differs from protected setup attestation.',
  TEST_IDENTITY_BLOCKED: 'Test context or client identity is invalid.',
  TEST_SETUP_ATTESTATION_INVALID: 'Test-cloud setup attestation is invalid or untrusted.',
  TEST_SETUP_ATTESTATION_STALE: 'Test-cloud setup attestation is outside its validity window.',
});

function result(status, value, code = null) {
  return Object.freeze({
    status,
    value,
    diagnostics: code === null ? Object.freeze([]) : Object.freeze([Object.freeze({
      code,
      safeMessage: MESSAGES[code],
      retryable: false,
    })]),
  });
}

function blocked(code) { return result('BLOCKED', null, code); }

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function digest(value) {
  return sha256Bytes(new TextEncoder().encode(canonicalJson(value)));
}

function exactObject(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || IS_PROXY(value)) return false;
    const actual = Reflect.ownKeys(value).sort(ordinalCompare);
    const expected = [...keys].sort(ordinalCompare);
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      return false;
    }
    return actual.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
  } catch {
    return false;
  }
}

function exactPass(value, valueKeys) {
  if (!exactObject(value, ['status', 'value', 'diagnostics']) || value.status !== 'PASS') return null;
  if (!Array.isArray(value.diagnostics) || value.diagnostics.length !== 0) return null;
  return exactObject(value.value, valueKeys) ? value.value : null;
}

function evidenceIsCurrent(binding) {
  const provider = binding.providerValue;
  const identity = binding.identityValue;
  const setup = binding.setupValue;
  if (!authenticateTestCloudRuntimeActive(Object.freeze({
    runtimeQualification: binding.runtimeQualification,
  }))) return false;
  if (!isQualifiedTestCloudProviderContract(provider.qualification, Object.freeze({
    runtimeQualification: binding.runtimeQualification,
    expectedDigest: binding.digests.providerContractDigest,
    expectedEnvironmentDigest: binding.digests.environmentDigest,
  }))) return false;
  if (!isQualifiedTestCloudIdentityBindings(Object.freeze({
    runtimeQualification: binding.runtimeQualification,
    qualification: identity.qualification,
    context: binding.context,
    providerContractQualification: provider.qualification,
    expectedEnvironmentDigest: binding.digests.environmentDigest,
    expectedProviderContractDigest: binding.digests.providerContractDigest,
    expectedIdentityBindingsDigest: binding.digests.identityBindingsDigest,
  }))) return false;
  if (!isQualifiedTestCloudSetupReadback(setup.qualification, Object.freeze({
    runtimeQualification: binding.runtimeQualification,
    expectedContractDigest: binding.digests.providerContractDigest,
    expectedDigest: binding.digests.providerSetupReadbackDigest,
    expectedEnvironmentDigest: binding.digests.environmentDigest,
    expectedIdentityBindingsDigest: binding.digests.identityBindingsDigest,
    expectedRunnerVariableExpectationDigest: setup.runnerVariableExpectationDigest,
  }))) return false;
  return isAuthenticTestCloudRunnerVariableReadbackResult(
    binding.runnerVariableReadbackResult,
    Object.freeze({
      runtimeQualification: binding.runtimeQualification,
      context: binding.context,
      providerContractQualification: provider.qualification,
      identityBindingsQualification: identity.qualification,
      providerSetupReadbackQualification: setup.qualification,
    }),
  );
}

function stringArray(value) {
  return Array.isArray(value)
    && Object.keys(value).length === value.length
    && value.every((entry) => typeof entry === 'string');
}

function siteConfiguration(site) {
  const keys = [
    'activeDeploymentId', 'buildCommand', 'installCommand', 'installationId',
    'outputDirectory', 'providerBranch', 'providerRepositoryId',
    'providerRootDirectory', 'siteId',
  ];
  if (!exactObject(site, keys)) throw new TypeError('site');
  for (const key of keys.filter((key) => key !== 'activeDeploymentId')) {
    if (typeof site[key] !== 'string') throw new TypeError('site');
  }
  if (!(site.activeDeploymentId === null || typeof site.activeDeploymentId === 'string')) {
    throw new TypeError('site');
  }
  return {
    siteId: site.siteId,
    installationId: site.installationId,
    providerRepositoryId: site.providerRepositoryId,
    providerRootDirectory: site.providerRootDirectory,
    providerBranch: site.providerBranch,
    installCommand: site.installCommand,
    buildCommand: site.buildCommand,
    outputDirectory: site.outputDirectory,
  };
}

function functionConfiguration(entry) {
  const keys = [
    'activeDeploymentId', 'commands', 'enabled', 'entrypoint', 'events', 'execute',
    'functionId', 'logging', 'name', 'providerRootDirectory', 'runtime', 'schedule',
    'scopes', 'timeout',
  ];
  if (!exactObject(entry, keys)) throw new TypeError('function');
  for (const key of [
    'commands', 'entrypoint', 'functionId', 'name', 'providerRootDirectory',
    'runtime', 'schedule',
  ]) if (typeof entry[key] !== 'string') throw new TypeError('function');
  if (
    !(entry.activeDeploymentId === null || typeof entry.activeDeploymentId === 'string')
    || !stringArray(entry.execute)
    || !stringArray(entry.events)
    || !stringArray(entry.scopes)
    || !Number.isSafeInteger(entry.timeout)
    || entry.timeout < 1
    || typeof entry.enabled !== 'boolean'
    || typeof entry.logging !== 'boolean'
  ) throw new TypeError('function');
  return {
    functionId: entry.functionId,
    runtime: entry.runtime,
    entrypoint: entry.entrypoint,
    commands: entry.commands,
    providerRootDirectory: entry.providerRootDirectory,
    name: entry.name,
    execute: [...entry.execute],
    events: [...entry.events],
    schedule: entry.schedule,
    timeout: entry.timeout,
    enabled: entry.enabled,
    logging: entry.logging,
    scopes: [...entry.scopes],
  };
}

function exactRunnerConfiguration(entry) {
  try {
    const actual = functionConfiguration(entry);
    return Object.entries(EXPECTED_RUNNER_CONFIGURATION).every(([key, expected]) => (
      Array.isArray(expected)
        ? actual[key].length === expected.length
          && actual[key].every((value, index) => value === expected[index])
        : actual[key] === expected
    ));
  } catch {
    return false;
  }
}

const CREDENTIAL_SCOPE_PROJECTION = Object.freeze(
  Object.entries(inventory.credentialVariables)
    .sort(([left], [right]) => ordinalCompare(left, right))
    .map(([role, entry]) => Object.freeze({
      role,
      credentialClass: entry.credentialClass,
      variableName: entry.variableName,
      scopes: Object.freeze([...entry.scopes]),
    })),
);
const CREDENTIAL_SCOPE_DIGEST = digest(CREDENTIAL_SCOPE_PROJECTION);
const FIXED_LEASE_DIGEST = digest(FIXED_LEASE_IDENTITY);

export function computeTestCloudSetupProjectionDigests({ site, functions }) {
  const siteProjection = siteConfiguration(site);
  const functionProjections = functions.map(functionConfiguration)
    .sort((left, right) => ordinalCompare(left.functionId, right.functionId));
  if (
    functionProjections.length !== EXPECTED_FUNCTION_IDS.length
    || functionProjections.some(({ functionId }, index) => functionId !== EXPECTED_FUNCTION_IDS[index])
  ) throw new TypeError('functions');
  return deepFreeze({
    credentialScopeReadbackDigest: CREDENTIAL_SCOPE_DIGEST,
    siteConfigurationDigest: digest(siteProjection),
    functionConfigurationsDigest: digest(functionProjections),
    fixedLeaseIdentityDigest: FIXED_LEASE_DIGEST,
  });
}

export function createTestCloudSetupAttestation(args) {
  try {
    if (arguments.length !== 1 || !exactObject(args, ATTESTATION_INPUT_KEYS)) {
      return blocked('TEST_SETUP_ATTESTATION_INVALID');
    }
    const {
      runtimeQualification,
      context,
      document,
      expectedDocumentDigest,
      clock,
      executionObservationQualification,
      providerContract,
      identityBindings,
      providerSetupReadback,
      runnerVariableReadbackResult,
    } = args;
    if (!authenticateTestCloudRuntimeActive(Object.freeze({ runtimeQualification }))) {
      return blocked('TEST_SETUP_ATTESTATION_INVALID');
    }
    const providerValue = exactPass(providerContract, ['qualification', 'providerContractDigest']);
    const identityValue = exactPass(identityBindings, ['qualification', 'identityBindingsDigest']);
    const setupValue = exactPass(providerSetupReadback, [
      'qualification', 'identityBindingsDigest', 'providerSetupReadbackDigest',
      'runnerVariableExpectationDigest',
    ]);
    const runnerValue = exactPass(runnerVariableReadbackResult, [
      'total', 'variables', 'runnerVariableReadbackDigest',
    ]);
    const observation = readExecutionObservationQualification(executionObservationQualification);
    if (
      !isAuthenticTestEnvironmentContext(context)
      || providerValue === null
      || identityValue === null
      || setupValue === null
      || runnerValue === null
      || observation === null
    ) return blocked('TEST_SETUP_ATTESTATION_INVALID');
    const digests = deepFreeze({
      environmentDigest: context.environmentDigest,
      providerContractDigest: providerValue.providerContractDigest,
      identityBindingsDigest: identityValue.identityBindingsDigest,
      providerSetupReadbackDigest: setupValue.providerSetupReadbackDigest,
      runnerVariableReadbackDigest: runnerValue.runnerVariableReadbackDigest,
    });
    const binding = Object.freeze({
      runtimeQualification,
      context,
      providerContract,
      providerValue,
      identityBindings,
      identityValue,
      providerSetupReadback,
      setupValue,
      runnerVariableReadbackResult,
      digests,
    });
    if (!evidenceIsCurrent(binding)) return blocked('TEST_SETUP_ATTESTATION_INVALID');
    if (
      document.runnerVariableReadbackDigest !== digests.runnerVariableReadbackDigest
      || document.credentialScopeReadbackDigest !== CREDENTIAL_SCOPE_DIGEST
      || document.fixedLeaseIdentityDigest !== FIXED_LEASE_DIGEST
      || document.executionObservationPolicyDigest !== observation.readbackDigest
    ) return blocked('TEST_SETUP_ATTESTATION_INVALID');
    const validation = validateTestCloudSetupAttestationDocument({
      attestation: document,
      attestationDigest: expectedDocumentDigest,
      clock,
      expectedEnvironmentDigest: digests.environmentDigest,
      expectedProviderContractDigest: digests.providerContractDigest,
      expectedIdentityBindingsDigest: digests.identityBindingsDigest,
      expectedProviderSetupReadbackDigest: digests.providerSetupReadbackDigest,
      expectedPrimaryExecutionRetentionMaxSeconds: observation.maximumRetentionSeconds,
      maximumRetentionSeconds: inventory.control.primaryExecutionRetentionMaxSeconds,
    });
    if (validation.status !== 'PASS') return blocked(validation.diagnostics[0].code);
    const attestation = deepFreeze({ ...validation.value });
    ATTESTATION_BINDINGS.set(attestation, binding);
    return result('PASS', attestation);
  } catch {
    return blocked('TEST_SETUP_ATTESTATION_INVALID');
  }
}
function validateExactManifest(manifest, context) {
  const validation = validateArtifactManifest(manifest);
  if (!validation.ok || manifest.sourceRevision !== context.candidateRevision) return false;
  const sites = manifest.artifacts.filter(({ kind }) => kind === 'site');
  const functions = manifest.artifacts.filter(({ kind }) => kind === 'function');
  const expectedLogicalIds = EXPECTED_FUNCTIONS.map(({ logicalId }) => logicalId).sort();
  return sites.length === 1
    && sites[0].logicalTarget === 'web'
    && sites[0].relativePath === 'site/site.tar.gz'
    && functions.length === expectedLogicalIds.length
    && functions.map(({ logicalTarget }) => logicalTarget).sort()
      .every((logicalId, index) => logicalId === expectedLogicalIds[index]);
}

function idleLease(value) {
  if (!exactObject(value, [
    'acquiredAt', 'cleanupDebt', 'environmentDigest', 'expiresAt', 'leaseRowId', 'leaseTokenDigest',
    'leaseVersion', 'ledgerDigest', 'ownerRunId', 'ownerWorkflowRunId', 'renewedAt', 'state',
  ])) return false;
  return value.state === 'idle'
    && value.leaseRowId === FIXED_LEASE_IDENTITY.rowId
    && value.environmentDigest === null
    && value.acquiredAt === null
    && value.renewedAt === null
    && value.expiresAt === null
    && value.leaseTokenDigest === null
    && value.ownerRunId === null
    && value.ownerWorkflowRunId === null
    && value.cleanupDebt === false
    && Number.isSafeInteger(value.leaseVersion)
    && value.leaseVersion >= 0
    && DIGEST.test(value.ledgerDigest);
}

export function isAuthenticTestCloudPreflightResult(value, context) {
  try {
    return AUTHENTIC_PREFLIGHT_RESULTS.has(value) && PREFLIGHT_CONTEXTS.get(value) === context;
  } catch {
    return false;
  }
}

export async function preflightTestCloud(args) {
  try {
    if (arguments.length !== 1 || !exactObject(args, PREFLIGHT_INPUT_KEYS)) {
      return blocked('TEST_SETUP_ATTESTATION_INVALID');
    }
    const { runtimeQualification, context, clients, manifest, setupAttestation, clock } = args;
    if (!authenticateTestCloudRuntimeActive(Object.freeze({ runtimeQualification }))) {
      return blocked('TEST_SETUP_ATTESTATION_INVALID');
    }
    const binding = ATTESTATION_BINDINGS.get(setupAttestation);
    if (
      !isAuthenticTestEnvironmentContext(context)
      || binding === undefined
      || binding.context !== context
      || binding.runtimeQualification !== runtimeQualification
      || !evidenceIsCurrent(binding)
      || typeof clock?.nowEpochSeconds !== 'function'
    ) return blocked('TEST_SETUP_ATTESTATION_INVALID');
    const now = clock.nowEpochSeconds();
    if (
      !Number.isSafeInteger(now)
      || setupAttestation.issuedAtEpochSeconds > now
      || now < 0
      || now >= setupAttestation.expiresAtEpochSeconds
    ) return blocked('TEST_SETUP_ATTESTATION_STALE');
    if (!validateExactManifest(manifest, context)) return blocked('ARTIFACT_HANDOFF_INVALID');
    if (
      typeof clients?.operator?.getSite !== 'function'
      || typeof clients?.operator?.getFunction !== 'function'
      || typeof clients?.fixture?.getRow !== 'function'
    ) return blocked('TEST_IDENTITY_BLOCKED');
    const siteResult = await clients.operator.getSite({});
    if (siteResult?.status !== 'PASS') return blocked('TEST_CLOUD_PREFLIGHT_MISMATCH');
    const functionRecords = [...EXPECTED_FUNCTIONS]
      .sort((left, right) => ordinalCompare(left.functionId, right.functionId));
    const functions = [];
    for (const record of functionRecords) {
      const read = await clients.operator.getFunction({ functionId: record.functionId });
      if (read?.status !== 'PASS') return blocked('TEST_CLOUD_PREFLIGHT_MISMATCH');
      if (record.functionId === RUNNER.functionId && !exactRunnerConfiguration(read.value)) {
        return blocked('TEST_CLOUD_PREFLIGHT_MISMATCH');
      }
      functions.push(read.value);
    }
    const observed = computeTestCloudSetupProjectionDigests({ site: siteResult.value, functions });
    if (
      observed.siteConfigurationDigest !== setupAttestation.siteConfigurationDigest
      || observed.functionConfigurationsDigest !== setupAttestation.functionConfigurationsDigest
      || observed.credentialScopeReadbackDigest !== setupAttestation.credentialScopeReadbackDigest
      || observed.fixedLeaseIdentityDigest !== setupAttestation.fixedLeaseIdentityDigest
    ) return blocked('TEST_CLOUD_PREFLIGHT_MISMATCH');
    const leaseResult = await clients.fixture.getRow({
      tableId: FIXED_LEASE_IDENTITY.tableId,
      rowId: FIXED_LEASE_IDENTITY.rowId,
    });
    if (
      leaseResult?.status !== 'PASS'
      || leaseResult.value?.rowId !== FIXED_LEASE_IDENTITY.rowId
      || !idleLease(leaseResult.value.data)
    ) return blocked('TEST_CLOUD_PREFLIGHT_MISMATCH');
    const preflight = result('PASS', deepFreeze({
      site: siteResult.value,
      functions,
      lease: leaseResult.value.data,
      primaryExecutionRetentionMaxSeconds: setupAttestation.primaryExecutionRetentionMaxSeconds,
      environmentDigest: binding.digests.environmentDigest,
      providerContractDigest: binding.digests.providerContractDigest,
      identityBindingsDigest: binding.digests.identityBindingsDigest,
      providerSetupReadbackDigest: binding.digests.providerSetupReadbackDigest,
      runnerVariableReadbackDigest: binding.digests.runnerVariableReadbackDigest,
    }));
    PREFLIGHT_BINDINGS.set(preflight, Object.freeze({
      context,
      runtimeQualification,
      setupAttestation,
      digests: binding.digests,
    }));
    AUTHENTIC_PREFLIGHT_RESULTS.add(preflight);
    PREFLIGHT_CONTEXTS.set(preflight, context);
    return preflight;
  } catch {
    return blocked('TEST_CLOUD_PREFLIGHT_MISMATCH');
  }
}
