import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';

const rootUrl = process.env.APPWRITEWORK_ROOT === undefined
  ? new URL('../../', import.meta.url)
  : new URL(`${pathToFileURL(process.env.APPWRITEWORK_ROOT).href.replace(/\/$/u, '')}/`);
const scriptUrl = (name) => new URL(`scripts/verification/${name}`, rootUrl);

const inventory = (await import(
  new URL('dev/verification/environments/test-cloud.inventory.v1.json', rootUrl),
  { with: { type: 'json' } }
)).default;
const { canonicalJson, sha256Bytes } = await import(scriptUrl('canonical-json.mjs'));
const { createArtifactManifest } = await import(scriptUrl('artifact-manifest.mjs'));
const { createTestEnvironmentContext } = await import(scriptUrl('test-cloud-environment.mjs'));
const { qualifyExecutionObservationReadback } = await import(scriptUrl('test-cloud-setup-check.mjs'));

const PREFLIGHT_SOURCE_DIGEST =
  'sha256:e24797ba2bed855620d739a15f2df069e1878b905356674df9d1cab2db731c40';
const AUTHORITY_KEY = Symbol.for('appwritework.a2.5c.control-helper-authorities.v1');
const authority = {
  active: new WeakSet(),
  provider: new WeakMap(),
  identity: new WeakMap(),
  setup: new WeakMap(),
  runner: new WeakMap(),
  contexts: new WeakSet(),
  recoveryContexts: new WeakSet(),
  recoveryStores: new WeakMap(),
  controlPreflights: new WeakMap(),
};
globalThis[AUTHORITY_KEY] = authority;

function dataModule(source) {
  return `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
}

let syntheticControlModulePromise;
export function loadSyntheticControlModule() {
  if (syntheticControlModulePromise === undefined) {
    syntheticControlModulePromise = (async () => {
      const environmentAuthority = dataModule(`
        const state=globalThis[Symbol.for('appwritework.a2.5c.control-helper-authorities.v1')];
        export const isAuthenticTestEnvironmentContext=(value)=>state.contexts.has(value);
        export const isAuthenticTestRecoveryEnvironmentContext=(value)=>state.recoveryContexts.has(value);
      `);
      const preflightAuthority = dataModule(`
        const state=globalThis[Symbol.for('appwritework.a2.5c.control-helper-authorities.v1')];
        export const isAuthenticTestCloudPreflightResult=(value,context)=>state.controlPreflights.get(value)===context;
      `);
      const recoveryStoreAuthority = dataModule(`
        const state=globalThis[Symbol.for('appwritework.a2.5c.control-helper-authorities.v1')];
        export const isAuthenticProviderRecoveryControlStore=(value,context)=>state.recoveryStores.get(value)===context;
      `);
      let source = await readFile(scriptUrl('test-cloud-control-store.mjs'), 'utf8');
      for (const [from,to] of [
        ["'./canonical-json.mjs'", JSON.stringify(scriptUrl('canonical-json.mjs').href)],
        ["'./test-cloud-environment.mjs'", JSON.stringify(environmentAuthority)],
        ["'./test-cloud-preflight.mjs'", JSON.stringify(preflightAuthority)],
        ["'./test-cloud-provider-control-store.mjs'", JSON.stringify(recoveryStoreAuthority)],
        ["'./test-cloud-cleanup-protocol.mjs'", JSON.stringify(scriptUrl('test-cloud-cleanup-protocol.mjs').href)],
        ["import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };",'const inventory=Object.freeze({control:Object.freeze({primaryExecutionRetentionMaxSeconds:86400})});'],
      ]) {
        if (!source.includes(from)) throw new TypeError(`control helper import seam ${from}`);
        source = source.replace(from,to);
      }
      return import(dataModule(source));
    })();
  }
  return syntheticControlModulePromise;
}
const providerAuthority = dataModule(`
const state = globalThis[Symbol.for('appwritework.a2.5c.control-helper-authorities.v1')];
function exactArgs(value, keys) {
  if (value === null || typeof value !== 'object' || !Object.isFrozen(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
export function authenticateTestCloudRuntimeActive(args) {
  return arguments.length === 1
    && exactArgs(args, ['runtimeQualification'])
    && state.active.has(args.runtimeQualification);
}
export function isQualifiedTestCloudProviderContract(qualification, args) {
  if (arguments.length !== 2 || !exactArgs(args, [
    'runtimeQualification', 'expectedDigest', 'expectedEnvironmentDigest',
  ])) return false;
  const meta = state.provider.get(qualification);
  return meta !== undefined
    && args.runtimeQualification === meta.runtimeQualification
    && args.expectedDigest === meta.providerContractDigest
    && args.expectedEnvironmentDigest === meta.environmentDigest;
}
export function isQualifiedTestCloudSetupReadback(qualification, args) {
  if (arguments.length !== 2 || !exactArgs(args, [
    'runtimeQualification', 'expectedContractDigest', 'expectedDigest',
    'expectedEnvironmentDigest', 'expectedIdentityBindingsDigest',
    'expectedRunnerVariableExpectationDigest',
  ])) return false;
  const meta = state.setup.get(qualification);
  return meta !== undefined
    && args.runtimeQualification === meta.runtimeQualification
    && args.expectedContractDigest === meta.providerContractDigest
    && args.expectedDigest === meta.providerSetupReadbackDigest
    && args.expectedEnvironmentDigest === meta.environmentDigest
    && args.expectedIdentityBindingsDigest === meta.identityBindingsDigest
    && args.expectedRunnerVariableExpectationDigest === meta.runnerVariableExpectationDigest;
}
`);

const identityAuthority = dataModule(`
const state = globalThis[Symbol.for('appwritework.a2.5c.control-helper-authorities.v1')];
function exactArgs(value, keys) {
  if (value === null || typeof value !== 'object' || !Object.isFrozen(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
export function isQualifiedTestCloudIdentityBindings(args) {
  if (arguments.length !== 1 || !exactArgs(args, [
    'runtimeQualification', 'qualification', 'context', 'providerContractQualification',
    'expectedEnvironmentDigest', 'expectedProviderContractDigest',
    'expectedIdentityBindingsDigest',
  ])) return false;
  const meta = state.identity.get(args.qualification);
  return meta !== undefined
    && args.runtimeQualification === meta.runtimeQualification
    && args.context === meta.context
    && args.providerContractQualification === meta.providerContractQualification
    && args.expectedEnvironmentDigest === meta.environmentDigest
    && args.expectedProviderContractDigest === meta.providerContractDigest
    && args.expectedIdentityBindingsDigest === meta.identityBindingsDigest;
}
`);

const appwriteAuthority = dataModule(`
const state = globalThis[Symbol.for('appwritework.a2.5c.control-helper-authorities.v1')];
function exactArgs(value, keys) {
  if (value === null || typeof value !== 'object' || !Object.isFrozen(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
export function isAuthenticTestCloudRunnerVariableReadbackResult(value, args) {
  if (arguments.length !== 2 || !exactArgs(args, [
    'runtimeQualification', 'context', 'providerContractQualification',
    'identityBindingsQualification', 'providerSetupReadbackQualification',
  ])) return false;
  const meta = state.runner.get(value);
  return meta !== undefined
    && args.runtimeQualification === meta.runtimeQualification
    && args.context === meta.context
    && args.providerContractQualification === meta.providerContractQualification
    && args.identityBindingsQualification === meta.identityBindingsQualification
    && args.providerSetupReadbackQualification === meta.providerSetupReadbackQualification;
}
`);

async function importInstrumentedPreflight() {
  let source = await readFile(scriptUrl('test-cloud-preflight.mjs'), 'utf8');
  source = source.replaceAll('\r\n', '\n');
  if (source.includes('\r')) throw new TypeError('test-cloud preflight source is not canonical text');
  const sourceDigest = sha256Bytes(new TextEncoder().encode(source));
  if (sourceDigest !== PREFLIGHT_SOURCE_DIGEST) {
    throw new TypeError('test-cloud preflight source changed');
  }
  const replacements = new Map([
    ['../../dev/verification/environments/test-cloud.inventory.v1.json',
      new URL('dev/verification/environments/test-cloud.inventory.v1.json', rootUrl).href],
    ['./canonical-json.mjs', scriptUrl('canonical-json.mjs').href],
    ['./artifact-manifest.mjs', scriptUrl('artifact-manifest.mjs').href],
    ['./test-cloud-setup-check.mjs', scriptUrl('test-cloud-setup-check.mjs').href],
    ['./test-cloud-setup-attestation.mjs', scriptUrl('test-cloud-setup-attestation.mjs').href],
    ['./test-cloud-environment.mjs', scriptUrl('test-cloud-environment.mjs').href],
    ['./test-cloud-provider-contract.mjs', providerAuthority],
    ['./test-cloud-identity-bindings.mjs', identityAuthority],
    ['./test-cloud-appwrite.mjs', appwriteAuthority],
  ]);
  for (const [from, to] of replacements) {
    const needle = `'${from}'`;
    if (!source.includes(needle)) throw new TypeError(`missing preflight import seam ${from}`);
    source = source.replace(needle, JSON.stringify(to));
  }
  return import(dataModule(source));
}

const preflightModule = await importInstrumentedPreflight();
export const computeTestCloudSetupProjectionDigests =
  preflightModule.computeTestCloudSetupProjectionDigests;
export const createTestCloudSetupAttestation = preflightModule.createTestCloudSetupAttestation;
export const isAuthenticTestCloudPreflightResult =
  preflightModule.isAuthenticTestCloudPreflightResult;
export const preflightTestCloud = preflightModule.preflightTestCloud;

const DIGEST = `sha256:${'d'.repeat(64)}`;
const PROVIDER_DIGEST = `sha256:${'3'.repeat(64)}`;
const IDENTITY_DIGEST = `sha256:${'4'.repeat(64)}`;
const SETUP_DIGEST = `sha256:${'5'.repeat(64)}`;
const RUNNER_DIGEST = `sha256:${'6'.repeat(64)}`;
const EXPECTATION_DIGEST = `sha256:${'7'.repeat(64)}`;
const REVISION = 'c8af52c092df9065897b6b75e9e83df43b1ac3f7';
const RUN_ID = 'verify-c8af52c092df-123456789-2';
const RUNNER = Object.freeze({
  logicalId: 'verification-runner-py',
  functionId: 'verification-runner-py',
  sourcePath: 'src/functions/verification-runner-py',
});
const CONTEXT_HANDLES = new WeakMap();
const PROVENANCE = new WeakMap();

function pass(value) {
  return Object.freeze({
    status: 'PASS',
    value: Object.freeze(value),
    diagnostics: Object.freeze([]),
  });
}

function sha(value) {
  return sha256Bytes(new TextEncoder().encode(canonicalJson(value)));
}

function handle(role) {
  const definition = inventory.credentialVariables[role];
  return Object.freeze({
    credentialClass: definition.credentialClass,
    variableName: definition.variableName,
    scopes: Object.freeze([...definition.scopes]),
    readSecret() { return `${role}-synthetic-secret`; },
  });
}

const SYNTHETIC_HANDLES = Object.freeze({
  operator: handle('operator'),
  fixture: handle('fixture'),
});
let syntheticContext;

export function createSyntheticTestCloudContext() {
  if (syntheticContext === undefined) {
    const created = createTestEnvironmentContext({
      inventory,
      environment: {
        endpoint: inventory.environment.endpoint,
        projectId: inventory.environment.projectId,
        siteId: inventory.environment.siteId,
        origin: inventory.environment.publicOrigin,
      },
      candidateRevision: REVISION,
      runId: RUN_ID,
      credentialHandles: SYNTHETIC_HANDLES,
    });
    if (created.status !== 'PASS') throw new TypeError('synthetic context');
    syntheticContext = created.value;
    CONTEXT_HANDLES.set(syntheticContext, SYNTHETIC_HANDLES);
  }
  return Object.freeze({ context: syntheticContext, credentialHandles: SYNTHETIC_HANDLES });
}

function siteProjection() {
  return {
    siteId: inventory.environment.siteId,
    activeDeploymentId: 'site-deployment',
    installationId: 'installation-1',
    providerRepositoryId: 'repository-1',
    providerRootDirectory: 'src/web',
    providerBranch: 'main',
    installCommand: 'npm ci',
    buildCommand: 'npm run build',
    outputDirectory: 'dist',
  };
}

function functionProjection(record) {
  if (record.functionId === RUNNER.functionId) {
    return {
      functionId: RUNNER.functionId,
      activeDeploymentId: `deployment-${RUNNER.logicalId}`,
      runtime: 'python-3.12',
      entrypoint: 'main.py',
      commands: 'python -m pip install --require-hashes --only-binary=:all: -r requirements.txt',
      providerRootDirectory: '',
      name: 'verification-runner',
      execute: [],
      events: [],
      schedule: '',
      timeout: 30,
      enabled: false,
      logging: false,
      scopes: ['execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write'],
    };
  }
  return {
    functionId: record.functionId,
    activeDeploymentId: `deployment-${record.logicalId}`,
    runtime: 'python-3.12',
    entrypoint: 'main.py',
    commands: '',
    providerRootDirectory: record.sourcePath,
    name: record.logicalId,
    execute: ['any'],
    events: [],
    schedule: '',
    timeout: 15,
    enabled: true,
    logging: true,
    scopes: [],
  };
}

function manifest(context) {
  const entries = [
    ...[...inventory.productFunctions, RUNNER].map((record) => ({
      kind: 'function',
      logicalTarget: record.logicalId,
      sourcePath: record.sourcePath,
      relativePath: `functions/${record.logicalId}.tar.gz`,
      canonicalContentDigest: DIGEST,
      transportDigest: DIGEST,
      sizeBytes: 1,
    })),
    {
      kind: 'site',
      logicalTarget: 'web',
      sourcePath: 'src/web',
      relativePath: 'site/site.tar.gz',
      canonicalContentDigest: DIGEST,
      transportDigest: DIGEST,
      sizeBytes: 1,
    },
  ].sort((left, right) => {
    const leftKey = `${left.kind}\0${left.logicalTarget}`;
    const rightKey = `${right.kind}\0${right.logicalTarget}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  return createArtifactManifest({
    candidateIdentity: {
      kind: 'git-revision',
      candidateRevision: context.candidateRevision,
      candidateSourceTreeDigest: DIGEST,
    },
    entries,
    verificationManifestDigest: DIGEST,
  });
}

function createEvidenceChain(context, credentialHandles) {
  const runtimeQualification = Object.freeze({ kind: 'runtime-loader-token' });
  const providerContractQualification = Object.freeze({ kind: 'provider-loader-token' });
  const identityBindingsQualification = Object.freeze({ kind: 'identity-loader-token' });
  const providerSetupReadbackQualification = Object.freeze({ kind: 'setup-loader-token' });
  const providerContract = pass({
    qualification: providerContractQualification,
    providerContractDigest: PROVIDER_DIGEST,
  });
  const identityBindings = pass({
    qualification: identityBindingsQualification,
    identityBindingsDigest: IDENTITY_DIGEST,
  });
  const providerSetupReadback = pass({
    qualification: providerSetupReadbackQualification,
    identityBindingsDigest: IDENTITY_DIGEST,
    providerSetupReadbackDigest: SETUP_DIGEST,
    runnerVariableExpectationDigest: EXPECTATION_DIGEST,
  });
  const runnerVariableReadbackResult = pass({
    total: 16,
    variables: Object.freeze([]),
    runnerVariableReadbackDigest: RUNNER_DIGEST,
  });
  const provenance = Object.freeze({
    preflightModule,
    runtimeQualification,
    context,
    credentialHandles,
    providerContract,
    identityBindings,
    providerSetupReadback,
    runnerVariableReadbackResult,
    safeDigests: Object.freeze({
      environmentDigest: context.environmentDigest,
      providerContractDigest: PROVIDER_DIGEST,
      identityBindingsDigest: IDENTITY_DIGEST,
      providerSetupReadbackDigest: SETUP_DIGEST,
      runnerVariableReadbackDigest: RUNNER_DIGEST,
    }),
  });
  authority.active.add(runtimeQualification);
  authority.provider.set(providerContractQualification, {
    runtimeQualification,
    environmentDigest: context.environmentDigest,
    providerContractDigest: PROVIDER_DIGEST,
  });
  authority.identity.set(identityBindingsQualification, {
    runtimeQualification,
    context,
    providerContractQualification,
    environmentDigest: context.environmentDigest,
    providerContractDigest: PROVIDER_DIGEST,
    identityBindingsDigest: IDENTITY_DIGEST,
  });
  authority.setup.set(providerSetupReadbackQualification, {
    runtimeQualification,
    environmentDigest: context.environmentDigest,
    providerContractDigest: PROVIDER_DIGEST,
    identityBindingsDigest: IDENTITY_DIGEST,
    providerSetupReadbackDigest: SETUP_DIGEST,
    runnerVariableExpectationDigest: EXPECTATION_DIGEST,
  });
  authority.runner.set(runnerVariableReadbackResult, {
    runtimeQualification,
    context,
    providerContractQualification,
    identityBindingsQualification,
    providerSetupReadbackQualification,
  });
  PROVENANCE.set(context, provenance);
  return provenance;
}

export async function createSyntheticTestCloudProvenance(context, credentialHandles) {
  authority.contexts.add(context);
  const boundHandles = CONTEXT_HANDLES.get(context);
  if (boundHandles !== undefined && boundHandles !== credentialHandles) {
    throw new TypeError('synthetic context binding');
  }
  return PROVENANCE.get(context) ?? createEvidenceChain(context, credentialHandles);
}

async function readObservedLease(store) {
  if (store === null || typeof store !== 'object' || Array.isArray(store)) {
    throw new TypeError('control store');
  }
  for (const methodName of ['peekLease', 'getLease']) {
    const descriptor = Object.getOwnPropertyDescriptor(store, methodName);
    if (descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value')
        && typeof descriptor.value === 'function') {
      return Reflect.apply(descriptor.value, store, []);
    }
  }
  throw new TypeError('control store lease reader');
}
export async function authenticPreflight(
  context,
  store,
  now = 1000,
  primaryExecutionRetentionMaxSeconds = inventory.control.primaryExecutionRetentionMaxSeconds,
  credentialHandles = CONTEXT_HANDLES.get(context),
) {
  const provenance = await createSyntheticTestCloudProvenance(context, credentialHandles);
  const observedLease = await readObservedLease(store);
  const site = siteProjection();
  const functions = [...inventory.productFunctions, RUNNER].map(functionProjection);
  const projections = computeTestCloudSetupProjectionDigests({ site, functions });
  const observationReadback = {
    schemaVersion: 'appwrite-execution-observation-readback.v1',
    observationAccess: 'read-only',
    providerManagedRetention: true,
    retentionMaxSeconds: primaryExecutionRetentionMaxSeconds,
  };
  const observationQualification = qualifyExecutionObservationReadback({
    inventory,
    readback: observationReadback,
    expectedReadbackDigest: sha(observationReadback),
  });
  const document = {
    schemaVersion: 'test-cloud-setup-attestation.v1',
    environmentDigest: provenance.safeDigests.environmentDigest,
    providerContractDigest: provenance.safeDigests.providerContractDigest,
    identityBindingsDigest: provenance.safeDigests.identityBindingsDigest,
    providerSetupReadbackDigest: provenance.safeDigests.providerSetupReadbackDigest,
    runnerVariableReadbackDigest: provenance.safeDigests.runnerVariableReadbackDigest,
    issuedAtEpochSeconds: now - 10,
    expiresAtEpochSeconds: now + 100,
    projectReadbackDigest: `sha256:${'1'.repeat(64)}`,
    globalCleanupReadbackDigest: `sha256:${'2'.repeat(64)}`,
    credentialScopeReadbackDigest: projections.credentialScopeReadbackDigest,
    siteConfigurationDigest: projections.siteConfigurationDigest,
    functionConfigurationsDigest: projections.functionConfigurationsDigest,
    fixedLeaseIdentityDigest: projections.fixedLeaseIdentityDigest,
    executionObservationPolicyDigest: sha(observationReadback),
    primaryExecutionRetentionMaxSeconds,
  };
  const attestationArgs = Object.freeze({
    runtimeQualification: provenance.runtimeQualification,
    context,
    document,
    expectedDocumentDigest: sha(document),
    clock: Object.freeze({ nowEpochSeconds: () => now }),
    executionObservationQualification: observationQualification.value,
    providerContract: provenance.providerContract,
    identityBindings: provenance.identityBindings,
    providerSetupReadback: provenance.providerSetupReadback,
    runnerVariableReadbackResult: provenance.runnerVariableReadbackResult,
  });
  const setup = createTestCloudSetupAttestation(attestationArgs);
  if (setup.status !== 'PASS') {
    return Object.freeze({ preflight: setup, setupAttestationDigest: null });
  }
  const byId = new Map(functions.map((value) => [value.functionId, value]));
  const preflight = await preflightTestCloud(Object.freeze({
    runtimeQualification: provenance.runtimeQualification,
    context,
    manifest: manifest(context),
    setupAttestation: setup.value,
    clock: Object.freeze({ nowEpochSeconds: () => now }),
    clients: Object.freeze({
      operator: Object.freeze({
        getSite: async () => pass(site),
        getFunction: async ({ functionId }) => pass(byId.get(functionId)),
      }),
      fixture: Object.freeze({
        getRow: async () => pass({ rowId: 'appwrite_test_verification', data: observedLease }),
      }),
    }),
  }));
  authority.controlPreflights.set(preflight, context);
  return Object.freeze({
    preflight,
    setupAttestationDigest: sha(document),
    setupAttestation: setup.value,
    attestationArgs,
    provenance,
  });
}
