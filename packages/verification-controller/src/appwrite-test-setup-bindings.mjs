import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { validateTestCloudHostedSetupAttestationDocument } from
  '../../../scripts/verification/test-cloud-hosted-setup-attestation.mjs';
import { validateTestCloudSetupAttestationDocument } from
  '../../../scripts/verification/test-cloud-setup-attestation.mjs';
import {
  checkInitialTestCloudSetup,
  checkTestCloudSetup,
  qualifyExecutionObservationReadback,
} from '../../../scripts/verification/test-cloud-setup-check.mjs';
import { validateTestCloudSetupReadbackBytes } from
  '../../../scripts/verification/test-cloud-provider-contract.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import providerContract from
  '../../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json' with {
    type: 'json',
  };

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const EXPECTED_ENVIRONMENT_DIGEST =
  'sha256:02560e84745ed7b577b334a3412885f6a547b2a22f164f4978b255d3b35c0044';
const EXPECTED_PROVIDER_CONTRACT_DIGEST =
  'sha256:47a1d778ca8b8cea333b10574ffbc2db488fd711c12a1c40faf9da5235e27184';
const RETENTION_SECONDS = 86_400;
const ATTESTATION_LIFETIME_SECONDS = 21_600;
const INPUT_KEYS = Object.freeze([
  'browserRequestPolicy',
  'controllerArtifact',
  'controllerRevision',
  'initialSeed',
  'liveProjection',
  'nowEpochSeconds',
  'runnerRevision',
  'sourceRepositoryRevision',
]);
const LIVE_KEYS = Object.freeze([
  'environmentDigest',
  'expectedRunnerVariables',
  'functionConfigurationsDigest',
  'globalCleanupReadbackDigest',
  'identityBindingsDigest',
  'projectReadbackDigest',
  'providerContractDigest',
  'runnerVariableReadbackDigest',
  'siteConfigurationDigest',
]);
const BINDING_NAMES = Object.freeze([
  'TEST_CLOUD_SETUP_READBACK_JSON',
  'TEST_CLOUD_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
]);
const RUNNER_VARIABLE_KEYS = Object.freeze([...providerContract.runnerVariables.configuredKeys]);

function digestText(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestJson(value) {
  return digestText(canonicalJson(value));
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.getOwnPropertySymbols(value).length === 0;
}

function exactObject(value, keys) {
  if (!isPlainObject(value)) return null;
  const names = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    return null;
  }
  return value;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function blocked(code) {
  return deepFreeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code,
      retryable: false,
      safeMessage: 'Appwrite Test setup bindings could not be produced safely.',
    }],
  });
}

function pass(value) {
  return deepFreeze({ status: 'PASS', value, diagnostics: [] });
}

function variableDigestMap(expectedRunnerVariables, identityBindingsDigest) {
  const record = exactObject(expectedRunnerVariables, [
    'identityQualifiedKey', 'staticTotal', 'total', 'variables',
  ]);
  if (
    record === null
    || record.identityQualifiedKey !== providerContract.runnerVariables.identityQualifiedKey
    || record.staticTotal !== 15
    || record.total !== 16
    || !Array.isArray(record.variables)
    || record.variables.length !== 16
  ) throw new TypeError('runner variables');
  const map = new Map();
  for (const variable of record.variables) {
    if (
      exactObject(variable, ['key', 'valueDigest']) === null
      || !RUNNER_VARIABLE_KEYS.includes(variable.key)
      || !DIGEST.test(variable.valueDigest)
      || map.has(variable.key)
    ) throw new TypeError('runner variables');
    map.set(variable.key, variable.valueDigest);
  }
  if (
    RUNNER_VARIABLE_KEYS.some((key) => !map.has(key))
    || map.get('VERIFICATION_IDENTITY_BINDINGS_DIGEST') !== digestText(identityBindingsDigest)
  ) throw new TypeError('runner variables');

  const fixedValues = {
    VERIFICATION_AUDIT_TABLE_ID: inventory.control.auditTableId,
    VERIFICATION_CONTROL_DATABASE_ID: inventory.control.databaseId,
    VERIFICATION_ENDPOINT_ORIGIN: inventory.environment.endpoint,
    VERIFICATION_ENVIRONMENT_CLASS: inventory.environmentClass,
    VERIFICATION_ENVIRONMENT_DIGEST: EXPECTED_ENVIRONMENT_DIGEST,
    VERIFICATION_INTENT_TABLE_ID: inventory.control.intentTableId,
    VERIFICATION_LEASE_ROW_ID: inventory.control.leaseRowId,
    VERIFICATION_LEASE_TABLE_ID: inventory.control.leaseTableId,
    VERIFICATION_PROJECT_ID: inventory.environment.projectId,
    VERIFICATION_PROVIDER_CONTRACT_DIGEST: EXPECTED_PROVIDER_CONTRACT_DIGEST,
  };
  for (const [key, value] of Object.entries(fixedValues)) {
    if (map.get(key) !== digestText(value)) throw new TypeError('runner variables');
  }
  return map;
}

function validateBrowserPolicy(policy) {
  const record = exactObject(policy, [
    'digest', 'rows', 'schemaVersion', 'timeoutMilliseconds',
  ]);
  if (
    record === null
    || record.schemaVersion !== 'test-cloud.browser-request-policy.v1'
    || record.timeoutMilliseconds !== 5000
    || !DIGEST.test(record.digest)
    || !Array.isArray(record.rows)
    || record.rows.length !== 56
  ) throw new TypeError('browser policy');
  const withoutDigest = {
    schemaVersion: record.schemaVersion,
    timeoutMilliseconds: record.timeoutMilliseconds,
    rows: record.rows,
  };
  if (digestJson(withoutDigest) !== record.digest) throw new TypeError('browser policy');
  for (const [ordinal, row] of record.rows.entries()) {
    if (!isPlainObject(row) || row.ordinal !== ordinal || typeof row.finalUrl !== 'string') {
      throw new TypeError('browser policy');
    }
    const url = new URL(row.finalUrl);
    const expectedOrigin = ordinal < 25
      ? inventory.environment.publicOrigin
      : new URL(inventory.environment.endpoint).origin;
    if (
      url.protocol !== 'https:'
      || url.origin !== expectedOrigin
      || /(?:test-only\.invalid|\.example|salmora\.net|69eb4818000afa64a7fa|69eb4a020024c520642e)/iu
        .test(row.finalUrl)
    ) throw new TypeError('browser policy');
  }
  return record;
}

function controlDatabase() {
  return {
    ...providerContract.controlProvider.database,
    tables: providerContract.controlProvider.tables.map(({ bindingName: _bindingName, ...table }) => (
      structuredClone(table)
    )),
  };
}

function coreBindings(variableDigests) {
  const idDigest = (source) => variableDigests.get(source) ?? digestText(source);
  return {
    primaryDatabaseIdDigest: idDigest(providerContract.coreProvider.databaseBindingSource),
    projectFilesBucket: {
      allowedFileExtensions: [],
      antivirus: true,
      compression: 'none',
      enabled: true,
      encryption: true,
      fileSecurity: true,
      idDigest: idDigest(providerContract.coreProvider.bucketBinding.idSource),
      maximumFileSize: 52_428_800,
      name: providerContract.coreProvider.bucketBinding.bindingName,
      permissionsDigest: digestJson([]),
      transformations: true,
    },
    tables: providerContract.coreProvider.tableBindings.map((table) => ({
      enabled: table.enabled,
      idDigest: idDigest(table.idSource),
      role: table.bindingName,
      tableBinding: table.bindingName.replaceAll('-', '_'),
    })),
  };
}

function genesis() {
  const binding = providerContract.controlProvider.genesis.tableBinding;
  const table = providerContract.controlProvider.tables.find(
    (candidate) => candidate.bindingName === binding,
  );
  if (table === undefined) throw new TypeError('genesis');
  return {
    dataDigest: providerContract.controlProvider.genesis.dataDigest,
    permissions: [...providerContract.controlProvider.genesis.permissions],
    rowId: providerContract.controlProvider.genesis.rowId,
    tableId: table.id,
  };
}

function credentialProjection() {
  return Object.entries(inventory.credentialVariables)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([role, entry]) => ({
      role,
      credentialClass: entry.credentialClass,
      variableName: entry.variableName,
      scopes: [...entry.scopes],
    }));
}

function hostedReadback({ initialSeed, controllerRevision, sourceRepositoryRevision, artifact }) {
  const common = {
    resources: {
      endpoint: inventory.environment.endpoint,
      projectId: inventory.environment.projectId,
      siteId: inventory.environment.siteId,
      databaseId: inventory.control.databaseId,
      leaseTableId: inventory.control.leaseTableId,
      intentTableId: inventory.control.intentTableId,
      auditTableId: inventory.control.auditTableId,
      leaseRowId: inventory.control.leaseRowId,
    },
    providerSchema: {
      schemaVersion: 'appwrite-test-provider-schema-readback.v1',
      descriptorDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
      databaseId: inventory.control.databaseId,
      tableIds: [
        inventory.control.auditTableId,
        inventory.control.intentTableId,
        inventory.control.leaseTableId,
      ].sort(),
    },
    executionObservation: {
      schemaVersion: 'appwrite-execution-observation-readback.v1',
      observationAccess: 'read-only',
      providerManagedRetention: true,
      retentionMaxSeconds: RETENTION_SECONDS,
    },
    productFunctions: inventory.productFunctions.map(({ logicalId, functionId }) => ({
      logicalId, functionId,
    })),
    credentialScopes: Object.fromEntries(
      Object.entries(inventory.credentialVariables).map(([role, entry]) => [role, {
        variableName: entry.variableName,
        scopes: [...entry.scopes],
      }]),
    ),
    runner: {
      functionId: inventory.control.runnerFunctionId,
      runtime: 'python-3.12',
      privateExecute: true,
      publicExecute: false,
      scopes: ['execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write'],
    },
    githubApp: {
      sourceRepository: 'Krowaccie/AppWriteWork',
      installationScoped: true,
      userAuthorization: false,
      webhooks: false,
      permissions: { actions: 'read', metadata: 'read' },
    },
    identities: ['editor', 'owner', 'viewer'].map((role) => ({ role, sessions: [] })),
  };
  if (initialSeed) {
    return {
      schemaVersion: 'test-cloud.hosted-prepublication-readback.v1',
      ...common,
      controller: {
        repository: 'Krowaccie/AppWriteWork-verification-control',
        rulesetProtected: true,
        codeownersProtected: true,
        environments: ['appwrite-test', 'controller-promotion'],
      },
      initialSeed: {
        sourceRepositoryRevision,
        controllerRevision,
        approvalMode: 'single-maintainer',
      },
    };
  }
  return {
    schemaVersion: 'test-cloud.hosted-setup-readback.v1',
    ...common,
    controller: {
      repository: 'Krowaccie/AppWriteWork-verification-control',
      rulesetProtected: true,
      codeownersProtected: true,
      environments: ['appwrite-test', 'controller-promotion'],
      bundle: {
        sourceRepositoryRevision,
        controllerRevision,
        artifactId: artifact.artifactId,
        digest: artifact.digest,
      },
    },
    bootstrap: {
      seeded: true,
      sourceRevision: sourceRepositoryRevision,
      bundleDigest: artifact.digest,
    },
  };
}

export function createAppwriteTestSetupBindings(args) {
  let stage = 'INPUT';
  try {
    const input = exactObject(args, INPUT_KEYS);
    const live = input === null ? null : exactObject(input.liveProjection, LIVE_KEYS);
    if (
      input === null
      || live === null
      || !SHA.test(input.controllerRevision)
      || !SHA.test(input.sourceRepositoryRevision)
      || !SHA.test(input.runnerRevision)
      || new Set([
        input.controllerRevision, input.sourceRepositoryRevision, input.runnerRevision,
      ]).size !== 3
      || typeof input.initialSeed !== 'boolean'
      || !Number.isSafeInteger(input.nowEpochSeconds)
      || input.nowEpochSeconds < 0
      || live.environmentDigest !== EXPECTED_ENVIRONMENT_DIGEST
      || live.providerContractDigest !== EXPECTED_PROVIDER_CONTRACT_DIGEST
      || ![
        live.identityBindingsDigest,
        live.runnerVariableReadbackDigest,
        live.siteConfigurationDigest,
        live.functionConfigurationsDigest,
        live.globalCleanupReadbackDigest,
        live.projectReadbackDigest,
      ].every((value) => DIGEST.test(value ?? ''))
    ) return blocked('APPWRITE_TEST_BINDING_INPUT_INVALID');
    const artifact = input.controllerArtifact;
    if (
      (input.initialSeed && artifact !== null)
      || (!input.initialSeed && (
        exactObject(artifact, ['artifactId', 'digest']) === null
        || !SAFE_ID.test(artifact.artifactId)
        || !DIGEST.test(artifact.digest)
      ))
    ) return blocked('APPWRITE_TEST_CONTROLLER_ARTIFACT_INVALID');

    stage = 'BROWSER_POLICY';
    const policy = validateBrowserPolicy(input.browserRequestPolicy);
    stage = 'RUNNER_VARIABLES';
    const variableDigests = variableDigestMap(
      live.expectedRunnerVariables,
      live.identityBindingsDigest,
    );
    stage = 'SETUP_DOCUMENT';
    const setupReadback = {
      browserRequestPolicy: structuredClone(policy),
      controlDatabase: controlDatabase(),
      coreBindings: coreBindings(variableDigests),
      environmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
      expectedRunnerVariables: structuredClone(live.expectedRunnerVariables),
      genesis: genesis(),
      identityBindings: {
        identityBindingsDigest: live.identityBindingsDigest,
        sessionCounts: ['editor', 'owner', 'viewer'].map((role) => ({ role, total: 0 })),
      },
      nodeResponseFormat: providerContract.responseFormats.nodeSetupReadback,
      providerContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
      pythonRuntimeResponseFormat: providerContract.responseFormats.pythonRuntime,
      schemaVersion: 'test-cloud.setup-readback.v1',
    };
    const setupReadbackJson = canonicalJson(setupReadback);
    const setupReadbackDigest = digestText(setupReadbackJson);
    stage = 'SETUP_READBACK';
    const setupValidation = validateTestCloudSetupReadbackBytes({
      bytes: new TextEncoder().encode(setupReadbackJson),
      expectedDigest: setupReadbackDigest,
      expectedEnvironmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
      expectedProviderContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
    });
    if (setupValidation.status !== 'PASS') {
      return blocked('APPWRITE_TEST_SETUP_READBACK_INVALID');
    }

    stage = 'SETUP_ATTESTATION';
    const observation = {
      schemaVersion: 'appwrite-execution-observation-readback.v1',
      observationAccess: 'read-only',
      providerManagedRetention: true,
      retentionMaxSeconds: RETENTION_SECONDS,
    };
    const executionObservationPolicyDigest = digestJson(observation);
    const setupAttestation = {
      credentialScopeReadbackDigest: digestJson(credentialProjection()),
      environmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
      executionObservationPolicyDigest,
      expiresAtEpochSeconds: input.nowEpochSeconds + ATTESTATION_LIFETIME_SECONDS,
      fixedLeaseIdentityDigest: digestJson({
        databaseId: inventory.control.databaseId,
        tableId: inventory.control.leaseTableId,
        rowId: inventory.control.leaseRowId,
      }),
      functionConfigurationsDigest: live.functionConfigurationsDigest,
      globalCleanupReadbackDigest: live.globalCleanupReadbackDigest,
      identityBindingsDigest: live.identityBindingsDigest,
      issuedAtEpochSeconds: input.nowEpochSeconds,
      primaryExecutionRetentionMaxSeconds: RETENTION_SECONDS,
      projectReadbackDigest: live.projectReadbackDigest,
      providerContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
      providerSetupReadbackDigest: setupReadbackDigest,
      runnerVariableReadbackDigest: live.runnerVariableReadbackDigest,
      schemaVersion: 'test-cloud-setup-attestation.v1',
      siteConfigurationDigest: live.siteConfigurationDigest,
    };
    const setupAttestationJson = canonicalJson(setupAttestation);
    const setupAttestationDigest = digestText(setupAttestationJson);
    const clock = Object.freeze({ nowEpochSeconds: () => input.nowEpochSeconds });
    if (validateTestCloudSetupAttestationDocument({
      attestation: setupAttestation,
      attestationDigest: setupAttestationDigest,
      clock,
      expectedEnvironmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
      expectedProviderContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
      expectedIdentityBindingsDigest: live.identityBindingsDigest,
      expectedProviderSetupReadbackDigest: setupReadbackDigest,
      expectedPrimaryExecutionRetentionMaxSeconds: RETENTION_SECONDS,
      maximumRetentionSeconds: RETENTION_SECONDS,
    }).status !== 'PASS') return blocked('APPWRITE_TEST_SETUP_ATTESTATION_INVALID');

    stage = 'HOSTED_READBACK';
    const hosted = hostedReadback({
      initialSeed: input.initialSeed,
      controllerRevision: input.controllerRevision,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      artifact,
    });
    const hostedJson = canonicalJson(hosted);
    const hostedDigest = digestText(hostedJson);
    const observationQualification = qualifyExecutionObservationReadback({
      inventory,
      readback: hosted.executionObservation,
      expectedReadbackDigest: executionObservationPolicyDigest,
    });
    const hostedCheck = observationQualification.status === 'PASS'
      ? (input.initialSeed ? checkInitialTestCloudSetup : checkTestCloudSetup)({
        inventory,
        readback: hosted,
        expectedProviderSchemaDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
        executionObservationQualification: observationQualification.value,
      })
      : observationQualification;
    if (hostedCheck.status !== 'PASS') return blocked('APPWRITE_TEST_HOSTED_READBACK_INVALID');

    stage = 'HOSTED_ATTESTATION';
    const hostedAttestation = {
      executionObservationPolicyDigest,
      expiresAtEpochSeconds: input.nowEpochSeconds + ATTESTATION_LIFETIME_SECONDS,
      hostedSetupReadbackDigest: hostedDigest,
      issuedAtEpochSeconds: input.nowEpochSeconds,
      primaryExecutionRetentionMaxSeconds: RETENTION_SECONDS,
      providerSetupReadbackDigest: setupReadbackDigest,
      schemaVersion: 'test-cloud.hosted-setup-attestation.v1',
    };
    const hostedAttestationJson = canonicalJson(hostedAttestation);
    const hostedAttestationDigest = digestText(hostedAttestationJson);
    if (validateTestCloudHostedSetupAttestationDocument({
      attestation: hostedAttestation,
      attestationDigest: hostedAttestationDigest,
      clock,
      expectedExecutionObservationPolicyDigest: executionObservationPolicyDigest,
      expectedHostedSetupReadbackDigest: hostedDigest,
      expectedPrimaryExecutionRetentionMaxSeconds: RETENTION_SECONDS,
      expectedProviderSetupReadbackDigest: setupReadbackDigest,
    }).status !== 'PASS') return blocked('APPWRITE_TEST_HOSTED_ATTESTATION_INVALID');

    stage = 'OUTPUT';
    const bindings = Object.fromEntries([
      ['TEST_CLOUD_SETUP_READBACK_JSON', setupReadbackJson],
      ['TEST_CLOUD_SETUP_READBACK_DIGEST', setupReadbackDigest],
      ['TEST_CLOUD_SETUP_ATTESTATION_JSON', setupAttestationJson],
      ['TEST_CLOUD_SETUP_ATTESTATION_DIGEST', setupAttestationDigest],
      ['TEST_CLOUD_HOSTED_SETUP_READBACK_JSON', hostedJson],
      ['TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST', hostedDigest],
      ['TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON', hostedAttestationJson],
      ['TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST', hostedAttestationDigest],
    ]);
    if (Object.keys(bindings).some((name, index) => name !== BINDING_NAMES[index])) {
      return blocked('APPWRITE_TEST_BINDING_OUTPUT_INVALID');
    }
    return pass({
      bindings,
      evidence: {
        schemaVersion: 'appwrite-test-setup-binding-evidence.v1',
        controllerRevision: input.controllerRevision,
        sourceRepositoryRevision: input.sourceRepositoryRevision,
        runnerRevision: input.runnerRevision,
        initialSeed: input.initialSeed,
        environmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
        providerContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
        identityBindingsDigest: live.identityBindingsDigest,
        runnerVariableReadbackDigest: live.runnerVariableReadbackDigest,
        providerSetupReadbackDigest: setupReadbackDigest,
        hostedSetupReadbackDigest: hostedDigest,
        issuedAtEpochSeconds: input.nowEpochSeconds,
        expiresAtEpochSeconds: input.nowEpochSeconds + ATTESTATION_LIFETIME_SECONDS,
      },
    });
  } catch {
    return blocked(`APPWRITE_TEST_BINDING_${stage}_INVALID`);
  }
}
