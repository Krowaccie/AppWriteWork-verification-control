#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { readFile as readFileDefault } from 'node:fs/promises';

import { canonicalJson, sha256Bytes } from './canonical-json.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const FULL_SHA = /^[0-9a-f]{40}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_REPOSITORY_JSON_SEGMENT = /^[A-Za-z0-9._-]+$/;
const TEST_CLOUD_INVENTORY_PATH = 'dev/verification/environments/test-cloud.inventory.v1.json';
const CLOSED_INVENTORY_DIGEST =
  'sha256:e83dac9cc615ccf37fd027683690edb2ff7332ac523d57130c1e86fa8617f302';

const INVENTORY_KEYS = Object.freeze([
  'schemaVersion',
  'environmentClass',
  'providerContractDigest',
  'sourceBranch',
  'environment',
  'deploymentModes',
  'productionDenylist',
  'control',
  'credentialVariables',
  'identityVariables',
  'productFunctions',
  'testOnlyFunctions',
].sort());
const EXECUTION_OBSERVATION_QUALIFICATIONS = new WeakMap();
const READBACK_KEYS = Object.freeze([
  'schemaVersion',
  'resources',
  'providerSchema',
  'executionObservation',
  'productFunctions',
  'credentialScopes',
  'runner',
  'controller',
  'githubApp',
  'identities',
  'bootstrap',
].sort());
const INITIAL_READBACK_KEYS = Object.freeze([
  'schemaVersion',
  'resources',
  'providerSchema',
  'executionObservation',
  'productFunctions',
  'credentialScopes',
  'runner',
  'controller',
  'githubApp',
  'identities',
  'initialSeed',
].sort());

function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || seen.has(value)
  ) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

function safeMessage(code) {
  const messages = {
    TEST_SETUP_INVENTORY_INVALID: 'The closed test-cloud inventory is invalid.',
    TEST_SETUP_PROVIDER_SCHEMA_READBACK_REQUIRED:
      'A versioned provider columns/indexes readback descriptor and trusted digest are required.',
    TEST_SETUP_PROVIDER_SCHEMA_MISMATCH:
      'The provider columns/indexes readback does not match the trusted descriptor digest.',
    TEST_SETUP_EXECUTION_OBSERVATION_READBACK_REQUIRED:
      'An independently selected execution retention and read-only observation digest is required.',
    TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH:
      'The execution retention and read-only observation readback does not match its trusted digest.',
    TEST_SETUP_READBACK_MISMATCH:
      'One or more exact test-cloud setup prerequisites have not been read back.',
    TEST_SETUP_CLI_INVALID: 'The setup checker accepts only the offline inventory command.',
  };
  return messages[code] ?? 'The test-cloud setup remains blocked.';
}

function result(status, value, code = null) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null
      ? []
      : [{
        code,
        safeMessage: safeMessage(code),
        retryable: false,
      }],
  });
}

function exactDataObject(value, expectedKeys) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Object.getOwnPropertySymbols(value).length !== 0
  ) return false;
  const keys = Object.getOwnPropertyNames(value).sort();
  if (
    keys.length !== expectedKeys.length
    || keys.some((key, index) => key !== expectedKeys[index])
  ) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && Object.hasOwn(descriptor, 'value');
  });
}

function exactArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function validFunctionRecord(value) {
  return exactDataObject(value, ['entrypoint', 'functionId', 'logicalId', 'runtime', 'sourcePath'])
    && value.entrypoint === 'main.py'
    && typeof value.functionId === 'string'
    && SAFE_ID.test(value.functionId)
    && typeof value.logicalId === 'string'
    && /^[a-z0-9][a-z0-9-]*-py$/.test(value.logicalId)
    && value.runtime === 'python-3.12'
    && value.sourcePath === `src/functions/${value.logicalId}`;
}

function validScopeRecord(record, expectedName, expectedScopes) {
  return exactDataObject(record, ['credentialClass', 'scopes', 'variableName'])
    && record.variableName === expectedName
    && exactArray(record.scopes, expectedScopes);
}

function validInventory(inventory) {
  try {
    const digest = sha256Bytes(new TextEncoder().encode(canonicalJson(inventory)));
    if (digest !== CLOSED_INVENTORY_DIGEST) return false;
  } catch {
    return false;
  }
  if (
    !exactDataObject(inventory, INVENTORY_KEYS)
    || inventory.schemaVersion !== 'test-cloud-inventory.v1'
    || inventory.environmentClass !== 'appwrite-cloud-test'
    || inventory.providerContractDigest !== 'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8'
    || inventory.sourceBranch !== 'main'
    || !exactDataObject(inventory.environment, ['endpoint', 'projectId', 'publicOrigin', 'siteId'])
    || inventory.environment.endpoint !== 'https://fra.cloud.appwrite.io/v1'
    || inventory.environment.projectId !== '69137c5d003952a36d4c'
    || inventory.environment.siteId !== '694579860016df0d2d3c'
    || inventory.environment.publicOrigin !== 'https://appwritework.appwrite.network'
    || !exactDataObject(inventory.deploymentModes, ['function', 'site'])
    || inventory.deploymentModes.site !== 'artifact-upload'
    || inventory.deploymentModes.function !== 'artifact-upload'
    || !exactDataObject(inventory.control, [
      'auditTableId',
      'databaseId',
      'intentTableId',
      'leaseRowId',
      'leaseTableId',
      'primaryExecutionRetentionMaxSeconds',
      'runnerFunctionId',
    ])
    || inventory.control.databaseId !== 'verification_control'
    || inventory.control.leaseTableId !== 'verification_leases'
    || inventory.control.intentTableId !== 'verification_intents'
    || inventory.control.auditTableId !== 'verification_audit_events'
    || inventory.control.leaseRowId !== 'appwrite_test_verification'
    || inventory.control.runnerFunctionId !== 'verification-runner-py'
    || inventory.control.primaryExecutionRetentionMaxSeconds !== 86400
    || !exactDataObject(inventory.credentialVariables, ['fixture', 'operator', 'recovery'])
  ) return false;

  if (
    !validScopeRecord(
      inventory.credentialVariables.operator,
      'APPWRITE_TEST_OPERATOR_API_KEY',
      ['execution.write', 'functions.read', 'functions.write', 'sites.read', 'sites.write'],
    )
    || inventory.credentialVariables.operator.credentialClass !== 'test-operator'
    || !validScopeRecord(
      inventory.credentialVariables.fixture,
      'APPWRITE_TEST_FIXTURE_API_KEY',
      ['rows.read', 'rows.write', 'users.read', 'users.write'],
    )
    || inventory.credentialVariables.fixture.credentialClass !== 'test-fixture'
    || !validScopeRecord(
      inventory.credentialVariables.recovery,
      'APPWRITE_TEST_RECOVERY_API_KEY',
      ['rows.read', 'rows.write', 'users.read', 'users.write', 'files.read', 'files.write'],
    )
    || inventory.credentialVariables.recovery.credentialClass !== 'test-recovery'
    || !Array.isArray(inventory.productFunctions)
    || inventory.productFunctions.length !== 35
    || !inventory.productFunctions.every(validFunctionRecord)
    || new Set(inventory.productFunctions.map((record) => record.logicalId)).size !== 35
    || !Array.isArray(inventory.testOnlyFunctions)
    || inventory.testOnlyFunctions.length !== 1
    || !validFunctionRecord(inventory.testOnlyFunctions[0])
    || inventory.testOnlyFunctions[0].logicalId !== 'verification-runner-py'
  ) return false;

  return true;
}

function validResources(resources, inventory) {
  return exactDataObject(resources, [
    'auditTableId',
    'databaseId',
    'endpoint',
    'intentTableId',
    'leaseRowId',
    'leaseTableId',
    'projectId',
    'siteId',
  ])
    && resources.endpoint === inventory.environment.endpoint
    && resources.projectId === inventory.environment.projectId
    && resources.siteId === inventory.environment.siteId
    && resources.databaseId === inventory.control.databaseId
    && resources.leaseTableId === inventory.control.leaseTableId
    && resources.intentTableId === inventory.control.intentTableId
    && resources.auditTableId === inventory.control.auditTableId
    && resources.leaseRowId === inventory.control.leaseRowId;
}

function validProductFunctions(value, inventory) {
  if (!Array.isArray(value) || value.length !== inventory.productFunctions.length) return false;
  return value.every((record, index) => {
    const expected = inventory.productFunctions[index];
    return exactDataObject(record, ['functionId', 'logicalId'])
      && record.logicalId === expected.logicalId
      && record.functionId === expected.functionId;
  });
}

function validProviderSchema(providerSchema, inventory, expectedDigest) {
  return exactDataObject(providerSchema, [
    'databaseId',
    'descriptorDigest',
    'schemaVersion',
    'tableIds',
  ])
    && providerSchema.schemaVersion === 'appwrite-test-provider-schema-readback.v1'
    && providerSchema.descriptorDigest === expectedDigest
    && providerSchema.databaseId === inventory.control.databaseId
    && exactArray(providerSchema.tableIds, [
      inventory.control.auditTableId,
      inventory.control.intentTableId,
      inventory.control.leaseTableId,
    ].sort());
}


function validExecutionObservation(value, inventory) {
  return exactDataObject(value, [
    'observationAccess',
    'providerManagedRetention',
    'retentionMaxSeconds',
    'schemaVersion',
  ])
    && value.schemaVersion === 'appwrite-execution-observation-readback.v1'
    && value.observationAccess === 'read-only'
    && value.providerManagedRetention === true
    && Number.isSafeInteger(value.retentionMaxSeconds)
    && value.retentionMaxSeconds > 0
    && value.retentionMaxSeconds <= inventory.control.primaryExecutionRetentionMaxSeconds;
}


export function qualifyExecutionObservationReadback({
  inventory,
  readback,
  expectedReadbackDigest,
} = {}) {
  try {
    if (
      !validInventory(inventory)
      || !validExecutionObservation(readback, inventory)
      || typeof expectedReadbackDigest !== 'string'
      || !DIGEST.test(expectedReadbackDigest)
    ) return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_READBACK_REQUIRED');
    const observedDigest = sha256Bytes(new TextEncoder().encode(canonicalJson(readback)));
    if (observedDigest !== expectedReadbackDigest) {
      return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH');
    }
    const qualification = deepFreeze({
      schemaVersion: 'qualified-execution-observation-readback.v1',
      readbackDigest: observedDigest,
      maximumRetentionSeconds: readback.retentionMaxSeconds,
    });
    EXECUTION_OBSERVATION_QUALIFICATIONS.set(qualification, {
      inventory,
      readbackDigest: observedDigest,
      maximumRetentionSeconds: readback.retentionMaxSeconds,
    });
    return result('PASS', qualification);
  } catch {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH');
  }
}


export function readExecutionObservationQualification(value) {
  const binding = EXECUTION_OBSERVATION_QUALIFICATIONS.get(value);
  return binding === undefined ? null : deepFreeze({
    readbackDigest: binding.readbackDigest,
    maximumRetentionSeconds: binding.maximumRetentionSeconds,
  });
}

function validReadbackScope(record, inventoryRecord) {
  return exactDataObject(record, ['scopes', 'variableName'])
    && record.variableName === inventoryRecord.variableName
    && exactArray(record.scopes, inventoryRecord.scopes);
}

function validCredentialScopes(value, inventory) {
  return exactDataObject(value, ['fixture', 'operator', 'recovery'])
    && validReadbackScope(value.operator, inventory.credentialVariables.operator)
    && validReadbackScope(value.fixture, inventory.credentialVariables.fixture)
    && validReadbackScope(value.recovery, inventory.credentialVariables.recovery);
}

function validRunner(value, inventory) {
  return exactDataObject(value, [
    'functionId',
    'privateExecute',
    'publicExecute',
    'runtime',
    'scopes',
  ])
    && value.functionId === inventory.control.runnerFunctionId
    && value.runtime === 'python-3.12'
    && value.privateExecute === true
    && value.publicExecute === false
    && exactArray(value.scopes, [
      'execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write',
    ]);
}

function validController(value) {
  return exactDataObject(value, [
    'bundle',
    'codeownersProtected',
    'environments',
    'repository',
    'rulesetProtected',
  ])
    && value.repository === 'Krowaccie/AppWriteWork-verification-control'
    && value.rulesetProtected === true
    && value.codeownersProtected === true
    && exactArray(value.environments, ['appwrite-test', 'controller-promotion'])
    && exactDataObject(value.bundle, ['artifactId', 'controllerRevision', 'digest', 'sourceRepositoryRevision'])
    && FULL_SHA.test(value.bundle.sourceRepositoryRevision)
    && FULL_SHA.test(value.bundle.controllerRevision)
    && value.bundle.sourceRepositoryRevision !== value.bundle.controllerRevision
    && SAFE_ID.test(value.bundle.artifactId)
    && DIGEST.test(value.bundle.digest);
}

function validInitialController(value) {
  return exactDataObject(value, [
    'codeownersProtected',
    'environments',
    'repository',
    'rulesetProtected',
  ])
    && value.repository === 'Krowaccie/AppWriteWork-verification-control'
    && value.rulesetProtected === true
    && value.codeownersProtected === true
    && exactArray(value.environments, ['appwrite-test', 'controller-promotion']);
}

function validGitHubApp(value) {
  return exactDataObject(value, [
    'installationScoped',
    'permissions',
    'sourceRepository',
    'userAuthorization',
    'webhooks',
  ])
    && value.sourceRepository === 'Krowaccie/AppWriteWork'
    && value.installationScoped === true
    && value.userAuthorization === false
    && value.webhooks === false
    && exactDataObject(value.permissions, ['actions', 'metadata'])
    && value.permissions.actions === 'read'
    && value.permissions.metadata === 'read';
}

function validIdentities(value) {
  if (!Array.isArray(value) || value.length !== 3) return false;
  const roles = ['editor', 'owner', 'viewer'];
  return value.every((identity, index) => exactDataObject(identity, ['role', 'sessions'])
    && identity.role === roles[index]
    && Array.isArray(identity.sessions)
    && identity.sessions.length === 0);
}

function validBootstrap(value, controller) {
  return exactDataObject(value, ['bundleDigest', 'seeded', 'sourceRevision'])
    && value.seeded === true
    && value.sourceRevision === controller.bundle.sourceRepositoryRevision
    && value.bundleDigest === controller.bundle.digest;
}

function validInitialSeed(value) {
  return exactDataObject(value, [
    'approvalMode',
    'controllerRevision',
    'sourceRepositoryRevision',
  ])
    && value.approvalMode === 'single-maintainer'
    && FULL_SHA.test(value.sourceRepositoryRevision)
    && FULL_SHA.test(value.controllerRevision)
    && value.sourceRepositoryRevision !== value.controllerRevision;
}

export function checkInitialTestCloudSetup({
  inventory,
  readback,
  expectedProviderSchemaDigest,
  executionObservationQualification,
} = {}, _dependencies = {}) {
  if (!validInventory(inventory)) {
    return result('BLOCKED', null, 'TEST_SETUP_INVENTORY_INVALID');
  }
  if (typeof expectedProviderSchemaDigest !== 'string' || !DIGEST.test(expectedProviderSchemaDigest)) {
    return result('BLOCKED', null, 'TEST_SETUP_PROVIDER_SCHEMA_READBACK_REQUIRED');
  }
  if (
    readback === null
    || typeof readback !== 'object'
    || !exactDataObject(readback, INITIAL_READBACK_KEYS)
    || !validProviderSchema(readback.providerSchema, inventory, expectedProviderSchemaDigest)
  ) {
    return result('BLOCKED', null, 'TEST_SETUP_PROVIDER_SCHEMA_MISMATCH');
  }
  const observationBinding = EXECUTION_OBSERVATION_QUALIFICATIONS.get(
    executionObservationQualification,
  );
  if (observationBinding === undefined) {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_READBACK_REQUIRED');
  }
  let observedExecutionObservationPolicyDigest;
  try {
    observedExecutionObservationPolicyDigest = sha256Bytes(
      new TextEncoder().encode(canonicalJson(readback.executionObservation)),
    );
  } catch {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH');
  }
  if (
    !validExecutionObservation(readback.executionObservation, inventory)
    || observedExecutionObservationPolicyDigest !== observationBinding.readbackDigest
    || readback.executionObservation.retentionMaxSeconds
      !== observationBinding.maximumRetentionSeconds
  ) {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH');
  }
  if (
    readback.schemaVersion !== 'test-cloud.hosted-prepublication-readback.v1'
    || !validResources(readback.resources, inventory)
    || !validProductFunctions(readback.productFunctions, inventory)
    || !validCredentialScopes(readback.credentialScopes, inventory)
    || !validRunner(readback.runner, inventory)
    || !validInitialController(readback.controller)
    || !validGitHubApp(readback.githubApp)
    || !validIdentities(readback.identities)
    || !validInitialSeed(readback.initialSeed)
  ) return result('BLOCKED', null, 'TEST_SETUP_READBACK_MISMATCH');

  return result('PASS', {
    ready: true,
    controllerBundleSha: readback.initialSeed.controllerRevision,
    sourceRepositoryRevision: readback.initialSeed.sourceRepositoryRevision,
    providerSchemaDigest: expectedProviderSchemaDigest,
    executionObservationPolicyDigest: observedExecutionObservationPolicyDigest,
    primaryExecutionRetentionMaxSeconds: observationBinding.maximumRetentionSeconds,
  });
}

export function checkTestCloudSetup({
  inventory,
  readback,
  expectedProviderSchemaDigest,
  executionObservationQualification,
} = {}, _dependencies = {}) {
  if (!validInventory(inventory)) {
    return result('BLOCKED', null, 'TEST_SETUP_INVENTORY_INVALID');
  }
  if (typeof expectedProviderSchemaDigest !== 'string' || !DIGEST.test(expectedProviderSchemaDigest)) {
    return result('BLOCKED', null, 'TEST_SETUP_PROVIDER_SCHEMA_READBACK_REQUIRED');
  }
  if (
    readback === null
    || typeof readback !== 'object'
    || !exactDataObject(readback, READBACK_KEYS)
    || !validProviderSchema(readback.providerSchema, inventory, expectedProviderSchemaDigest)
  ) {
    return result('BLOCKED', null, 'TEST_SETUP_PROVIDER_SCHEMA_MISMATCH');
  }
  const observationBinding = EXECUTION_OBSERVATION_QUALIFICATIONS.get(
    executionObservationQualification,
  );
  if (observationBinding === undefined) {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_READBACK_REQUIRED');
  }
  let observedExecutionObservationPolicyDigest;
  try {
    observedExecutionObservationPolicyDigest = sha256Bytes(
      new TextEncoder().encode(canonicalJson(readback.executionObservation)),
    );
  } catch {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH');
  }
  if (
    !validExecutionObservation(readback.executionObservation, inventory)
    || observedExecutionObservationPolicyDigest !== observationBinding.readbackDigest
    || readback.executionObservation.retentionMaxSeconds
      !== observationBinding.maximumRetentionSeconds
  ) {
    return result('BLOCKED', null, 'TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH');
  }
  if (
    readback.schemaVersion !== 'test-cloud.hosted-setup-readback.v1'
    || !validResources(readback.resources, inventory)
    || !validExecutionObservation(readback.executionObservation, inventory)
    || !validProductFunctions(readback.productFunctions, inventory)
    || !validCredentialScopes(readback.credentialScopes, inventory)
    || !validRunner(readback.runner, inventory)
    || !validController(readback.controller)
    || !validGitHubApp(readback.githubApp)
    || !validIdentities(readback.identities)
    || !validBootstrap(readback.bootstrap, readback.controller)
  ) return result('BLOCKED', null, 'TEST_SETUP_READBACK_MISMATCH');

  return result('PASS', {
    ready: true,
    controllerBundleSha: readback.controller.bundle.controllerRevision,
    sourceRepositoryRevision: readback.controller.bundle.sourceRepositoryRevision,
    controllerBundleDigest: readback.controller.bundle.digest,
    providerSchemaDigest: expectedProviderSchemaDigest,
    executionObservationPolicyDigest: observedExecutionObservationPolicyDigest,
    primaryExecutionRetentionMaxSeconds: observationBinding.maximumRetentionSeconds,
  });
}

function safeRepositoryJsonPath(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || path.isAbsolute(value)
    || value.includes('\\')
    || !value.endsWith('.json')
  ) return false;
  const segments = value.split('/');
  return segments.length > 0
    && segments.every((segment) => segment !== ''
      && segment !== '.'
      && segment !== '..'
      && SAFE_REPOSITORY_JSON_SEGMENT.test(segment));
}

function parsePositiveInteger(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/.test(value)) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : null;
}

function parseArgs(argv) {
  if (
    Array.isArray(argv)
    && argv.length === 3
    && argv[0] === '--offline'
    && argv[1] === '--inventory'
    && argv[2] === TEST_CLOUD_INVENTORY_PATH
  ) {
    return {
      command: 'inventory-only',
      inventoryPath: TEST_CLOUD_INVENTORY_PATH,
    };
  }

  if (
    !Array.isArray(argv)
    || argv.length !== 13
    || argv[0] !== '--offline'
    || argv[1] !== '--inventory'
    || argv[2] !== TEST_CLOUD_INVENTORY_PATH
    || argv[3] !== '--setup-readback'
    || argv[5] !== '--provider-schema-digest'
    || argv[7] !== '--execution-observation-readback'
    || argv[9] !== '--execution-observation-digest'
    || argv[11] !== '--execution-retention-max-seconds'
    || !safeRepositoryJsonPath(argv[4])
    || !DIGEST.test(argv[6])
    || !safeRepositoryJsonPath(argv[8])
    || !DIGEST.test(argv[10])
  ) return null;

  const executionRetentionMaxSeconds = parsePositiveInteger(argv[12]);
  if (executionRetentionMaxSeconds === null) return null;
  return {
    command: 'setup-readback',
    inventoryPath: TEST_CLOUD_INVENTORY_PATH,
    setupReadbackPath: argv[4],
    expectedProviderSchemaDigest: argv[6],
    executionObservationReadbackPath: argv[8],
    expectedExecutionObservationDigest: argv[10],
    executionRetentionMaxSeconds,
  };
}

function write(stream, value) {
  if (stream && typeof stream.write === 'function') stream.write(value);
}

async function readJsonFromRepositoryRoot({ readFile, root, relativePath }) {
  return JSON.parse(await readFile(path.resolve(root, relativePath), 'utf8'));
}

export async function main(argv = [], dependencies = {}) {
  const parsed = parseArgs(argv);
  if (parsed === null) {
    write(dependencies.stderr ?? process.stderr, 'BLOCKED TEST_SETUP_CLI_INVALID\n');
    return 2;
  }

  const root = dependencies.root ?? process.cwd();
  const readFile = dependencies.readFile ?? readFileDefault;
  let inventory;
  try {
    inventory = await readJsonFromRepositoryRoot({
      readFile,
      root,
      relativePath: parsed.inventoryPath,
    });
  } catch {
    write(dependencies.stderr ?? process.stderr, 'BLOCKED TEST_SETUP_INVENTORY_INVALID\n');
    return 2;
  }

  if (parsed.command === 'inventory-only') {
    const checked = checkTestCloudSetup({
      inventory,
      readback: null,
      expectedProviderSchemaDigest: null,
    });
    if (checked.status === 'PASS') {
      write(dependencies.stdout ?? process.stdout, 'PASS TEST_CLOUD_SETUP_READY\n');
      return 0;
    }
    write(
      dependencies.stderr ?? process.stderr,
      `BLOCKED ${checked.diagnostics[0].code}\n`,
    );
    return 2;
  }

  let setupReadback;
  try {
    setupReadback = await readJsonFromRepositoryRoot({
      readFile,
      root,
      relativePath: parsed.setupReadbackPath,
    });
  } catch {
    write(dependencies.stderr ?? process.stderr, 'BLOCKED TEST_SETUP_READBACK_MISMATCH\n');
    return 2;
  }

  let executionObservationReadback;
  try {
    executionObservationReadback = await readJsonFromRepositoryRoot({
      readFile,
      root,
      relativePath: parsed.executionObservationReadbackPath,
    });
  } catch {
    write(
      dependencies.stderr ?? process.stderr,
      'BLOCKED TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH\n',
    );
    return 2;
  }

  if (
    executionObservationReadback === null
    || typeof executionObservationReadback !== 'object'
    || executionObservationReadback.retentionMaxSeconds
      !== parsed.executionRetentionMaxSeconds
  ) {
    write(
      dependencies.stderr ?? process.stderr,
      'BLOCKED TEST_SETUP_EXECUTION_OBSERVATION_MISMATCH\n',
    );
    return 2;
  }

  const qualifiedObservation = qualifyExecutionObservationReadback({
    inventory,
    readback: executionObservationReadback,
    expectedReadbackDigest: parsed.expectedExecutionObservationDigest,
  });
  if (qualifiedObservation.status !== 'PASS') {
    write(
      dependencies.stderr ?? process.stderr,
      `BLOCKED ${qualifiedObservation.diagnostics[0].code}\n`,
    );
    return 2;
  }

  const checked = checkTestCloudSetup({
    inventory,
    readback: setupReadback,
    expectedProviderSchemaDigest: parsed.expectedProviderSchemaDigest,
    executionObservationQualification: qualifiedObservation.value,
  });
  if (checked.status === 'PASS') {
    write(dependencies.stdout ?? process.stdout, 'PASS TEST_CLOUD_SETUP_READY\n');
    return 0;
  }
  write(
    dependencies.stderr ?? process.stderr,
    `BLOCKED ${checked.diagnostics[0].code}\n`,
  );
  return 2;
}

const isEntrypoint = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  process.exitCode = await main(process.argv.slice(2), {
    root: process.cwd(),
    stdout: process.stdout,
    stderr: process.stderr,
  });
}
