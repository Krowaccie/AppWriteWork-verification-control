import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';
import path from 'node:path';
import nodeTest from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isMainThread, parentPort, Worker, workerData } from 'node:worker_threads';

import {
  issueTrustedControllerContextForArtifactVerifier,
  validateControllerBundleManifest,
} from '../../../scripts/verification/controller-bundle.mjs';
import { createArtifactManifest } from '../../../scripts/verification/artifact-manifest.mjs';
import { canonicalJson, sha256Bytes } from '../../../scripts/verification/canonical-json.mjs';
import { createHostedArtifactHandoff } from '../../../scripts/verification/hosted-artifact-handoff.mjs';
import { createHostedSiteBuildIdentity } from '../../../scripts/verification/hosted-site-build-identity.mjs';
import {
  contentDigestToRowId,
  intentIdToRowId,
} from '../../../scripts/verification/test-cloud-row-id.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import task8ProviderContract from '../../../src/functions/verification-runner-py/provider-contract/test-cloud.provider-contract.v1.json' with { type: 'json' };
import { runTestCloudLane } from '../../../scripts/verification/test-cloud-lane.mjs';
import {
  QUALIFIED_CLEANUP_PROTOCOL,
  advanceCleanupPhaseDigest,
  advanceCleanupProgressDigest,
  advanceCleanupProofDigest,
  createCleanupPhaseGenesisDigest,
  getCleanupResourceCatalog,
} from '../../../scripts/verification/test-cloud-cleanup-protocol.mjs';
import {
  canonicalReadback,
  canonicalReadbackDigest,
  digestJson,
  setupAttestation,
} from '../../../scripts/verification/controller-trust-materials-test-helper.mjs';
import {
  testCloudScenarioInventory,
  testCloudScenarioInventoryDigest,
} from './test-cloud-playwright-facade.mjs';
import { createReleaseEligibleSourceArtifactSet } from '../../../scripts/verification/test-cloud-real-composition-fixture.mjs';
import { projectTestCloudBrowserArtifactPolicyRows } from './test-cloud-browser-artifact-set.mjs';
import { createAppwriteTestBrowserPolicy } from './appwrite-test-browser-policy.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SOURCE_WORKFLOW = '.github/workflows/verify-main.yml';
const CONTROLLER_WORKFLOW = 'packages/verification-controller/workflows/verify-test-cloud.yml';
const CONTROLLER_MANIFEST = 'packages/verification-controller/controller-bundle.proposal.json';
const CONTROLLER_SETUP = 'docs/verification/CONTROLLER-SETUP.md';
const APPWRITE_SETUP = 'docs/verification/APPWRITE-TEST-SETUP.md';
const CONTROLLER_BOOTSTRAP_HARNESS_KEY =
  Symbol.for('appwritework.test-cloud.controller-bootstrap-harness.v1');
const CONTROLLER_LANE_HARNESS_KEY =
  Symbol.for('appwritework.test-cloud.controller-lane-harness.v1');
const CONTROLLER_BOOTSTRAP_HARNESS_QUERY =
  '?appwritework-controller-bootstrap-harness=4c-final';
const PRODUCTION_COMPOSITION_WORKER_PROTOCOL =
  'appwritework.test-cloud.production-composition.v1';
const ORDINARY_LANE_WORKER_PROTOCOL =
  'appwritework.test-cloud.ordinary-lane-terminality.v1';
const productionCompositionWorker = !isMainThread
  && workerData?.protocol === PRODUCTION_COMPOSITION_WORKER_PROTOCOL;
const ordinaryLaneWorker = !isMainThread
  && workerData?.protocol === ORDINARY_LANE_WORKER_PROTOCOL;
const test = productionCompositionWorker || ordinaryLaneWorker
  ? Object.assign(() => {}, { after() {} })
  : nodeTest;
let controllerBootstrapHarnessCalls = 0;
let controllerBootstrapHarnessOutcome;
let controllerHarnessModulePromise;
let controllerHarnessRunLane = runTestCloudLane;
let controllerLaneHarnessArgs;

const controllerLaneModuleUrl = pathToFileURL(path.join(
  root,
  'scripts',
  'verification',
  'test-cloud-lane.mjs',
)).href;
const controllerLaneStubUrl = `data:text/javascript,${encodeURIComponent(`
import { validateTestCloudArtifactSet } from '${controllerLaneModuleUrl}';
export { validateTestCloudArtifactSet };
export function runTestCloudLane(args) {
  return globalThis[
    Symbol.for('appwritework.test-cloud.controller-lane-harness.v1')
  ](args);
}
`)}`;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (
      context.parentURL?.endsWith(
        `test-cloud-controller.mjs${CONTROLLER_BOOTSTRAP_HARNESS_QUERY}`,
      )
      && specifier === '../../../scripts/verification/test-cloud-lane.mjs'
    ) {
      return {
        url: controllerLaneStubUrl,
        shortCircuit: true,
      };
    }
    return nextResolve(specifier, context);
  },
});

Object.defineProperty(globalThis, CONTROLLER_BOOTSTRAP_HARNESS_KEY, {
  value() {
    controllerBootstrapHarnessCalls += 1;
    return typeof controllerBootstrapHarnessOutcome === 'function'
      ? controllerBootstrapHarnessOutcome()
      : controllerBootstrapHarnessOutcome;
  },
  enumerable: false,
  configurable: true,
  writable: false,
});

Object.defineProperty(globalThis, CONTROLLER_LANE_HARNESS_KEY, {
  value(args) {
    controllerLaneHarnessArgs = args;
    return runTestCloudLane(args);
  },
  enumerable: false,
  configurable: true,
  writable: false,
});

test.after(() => {
  Reflect.deleteProperty(globalThis, CONTROLLER_BOOTSTRAP_HARNESS_KEY);
  Reflect.deleteProperty(globalThis, CONTROLLER_LANE_HARNESS_KEY);
});

function loadControllerHarnessModule() {
  if (controllerHarnessModulePromise === undefined) {
    const controllerUrl = pathToFileURL(path.join(
      root,
      'packages',
      'verification-controller',
      'src',
      'test-cloud-controller.mjs',
    )).href;
    controllerHarnessModulePromise = Promise.all([
      import(`${controllerUrl}${CONTROLLER_BOOTSTRAP_HARNESS_QUERY}`),
      import(controllerLaneStubUrl),
    ]).then(([controller, lane]) => {
      controllerHarnessRunLane = lane.runTestCloudLane;
      return controller;
    });
  }
  return controllerHarnessModulePromise;
}

function configureControllerBootstrapHarness(outcome) {
  controllerBootstrapHarnessCalls = 0;
  controllerBootstrapHarnessOutcome = outcome;
  controllerLaneHarnessArgs = undefined;
}

function frozenNullRecord(entries) {
  const value = Object.create(null);
  for (const [key, entry] of entries) {
    Object.defineProperty(value, key, {
      value: entry,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(value);
}

function controllerBootstrapPass({
  runtimeQualification = Object.freeze(Object.create(null)),
  browserScenarioQualification = Object.freeze(Object.create(null)),
} = {}) {
  return frozenNullRecord([
    ['status', 'PASS'],
    ['value', frozenNullRecord([
      ['runtimeQualification', runtimeQualification],
      ['browserScenarioQualification', browserScenarioQualification],
    ])],
    ['diagnostics', Object.freeze([])],
  ]);
}

const pins = Object.freeze({
  checkout: 'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0',
  node: 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
  python: 'actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1',
  trustedA1: 'Krowaccie/AppWriteWork-verification-control/.github/actions/a1-source-artifact-launcher@eeaaaf7619bdac124101cfb1d8c628e8447d83be',
});
const PLAYWRIGHT_IMAGE =
  'mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48';

async function text(relativePath) {
  return readFile(path.join(root, relativePath), 'utf8');
}

function actionReferences(workflow) {
  return [...workflow.matchAll(/^\s*uses:\s*([^\s#]+)\s*$/gmu)]
    .map((match) => match[1])
    .filter((reference) => reference.startsWith('actions/'));
}

const SHA = '0123456789abcdef0123456789abcdef01234567';
const DIGEST = `sha256:${'a'.repeat(64)}`;
const EVIDENCE_DIGEST = `sha256:${'e'.repeat(64)}`;
const CONTROLLER_SOURCE_SHA = 'b'.repeat(40);
const HOSTED_CLI_ARGS = Object.freeze([
  '--hosted',
  '--revision', SHA,
  '--source-run-id', '1234',
  '--source-run-attempt', '2',
]);

function pass(value) {
  return Object.freeze({
    status: 'PASS',
    value,
    diagnostics: Object.freeze([]),
  });
}

function task8ActiveLease(overrides = {}) {
  return Object.freeze({
    acquiredAt: '2026-07-20T09:59:00.000Z',
    cleanupDebt: false,
    environmentDigest: `sha256:${'7'.repeat(64)}`,
    expiresAt: '2026-07-20T10:29:00.000Z',
    leaseRowId: 'test-cloud-singleton',
    leaseTokenDigest: `sha256:${'8'.repeat(64)}`,
    leaseVersion: 20,
    ledgerDigest: `sha256:${'9'.repeat(64)}`,
    ownerRunId: 'verify-0123456789ab-1234-1',
    ownerWorkflowRunId: '1234',
    renewedAt: '2026-07-20T09:59:00.000Z',
    state: 'active',
    ...overrides,
  });
}

function task8CleanupDebtLease(prior, overrides = {}) {
  return Object.freeze({
    ...prior,
    cleanupDebt: true,
    leaseVersion: prior.leaseVersion + 1,
    ledgerDigest: `sha256:${'d'.repeat(64)}`,
    state: 'cleanup-debt',
    ...overrides,
  });
}

function trustedController() {
  const manifest = {
    schemaVersion: 'controller-bundle.v2',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: CONTROLLER_SOURCE_SHA,
    controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
    controllerRevision: SHA,
    entrypoints: [
      { path: 'packages/verification-controller/src/test-cloud-controller.mjs', sha256: DIGEST },
    ],
    files: [
      { path: 'packages/verification-controller/src/test-cloud-controller.mjs', sha256: DIGEST },
    ],
    schemaDigests: [
      { path: 'dev/verification/schemas/controller-bundle.v2.schema.json', sha256: DIGEST },
    ],
    trustMaterials: [
      { kind: 'evaluator', path: 'trust/evaluator.v1.json', sha256: DIGEST },
      { kind: 'evidenceValidator', path: 'trust/evidence-validator.v1.json', sha256: DIGEST },
      { kind: 'networkPolicy', path: 'trust/network-policy.v1.json', sha256: DIGEST },
      { kind: 'transcriptCorpus', path: 'trust/transcript-corpus.v2.json', sha256: DIGEST },
    ],
    provenance: { path: 'trust/provenance.v1.json', sha256: DIGEST },
  };
  const result = issueTrustedControllerContextForArtifactVerifier({
    manifest,
    controllerArtifactId: '1',
    controllerBundleDigest: DIGEST,
  });
  assert.equal(result.status, 'PASS');
  return result.value;
}

function sourceSelection() {
  return Object.freeze({
    repository: 'Krowaccie/AppWriteWork',
    workflow: 'Verify Main',
    workflowRunId: '1234',
    workflowRunAttempt: 1,
    sourceRef: 'refs/heads/main',
    sourceRevision: SHA,
    artifactId: '5678',
    artifactName: `verification-artifacts-${SHA}`,
    archiveDigest: DIGEST,
  });
}

function artifactSetOutput({ sourceTreeDigest = DIGEST, authenticBrowserSite = false } = {}) {
  const makeArtifact = (kind, logicalTarget, relativePath, marker) => {
    const bytes = new TextEncoder().encode(`${marker}:${logicalTarget}`);
    return Object.freeze({
      kind,
      logicalTarget,
      relativePath,
      canonicalContentDigest: sha256Bytes(bytes),
      transportDigest: sha256Bytes(bytes),
      sizeBytes: bytes.byteLength,
      bytes,
    });
  };
  const site = authenticBrowserSite
    ? createReleaseEligibleSourceArtifactSet().releaseEligibleArtifacts[0]
    : makeArtifact('site', 'web', 'site/site.tar.gz', 'site');
  const functions = [...inventory.productFunctions, ...inventory.testOnlyFunctions]
    .map(({ logicalId }) => makeArtifact(
      'function',
      logicalId,
      `functions/${logicalId}.tar.gz`,
      'function',
    ));
  const releaseFunctions = functions.filter(({ logicalTarget }) => logicalTarget !== 'verification-runner-py');
  const runner = functions.find(({ logicalTarget }) => logicalTarget === 'verification-runner-py');
  const sourcePaths = new Map([
    ...inventory.productFunctions,
    ...inventory.testOnlyFunctions,
  ].map(({ logicalId, sourcePath }) => [logicalId, sourcePath]));
  const manifest = createArtifactManifest({
    candidateIdentity: {
      kind: 'git-revision',
      candidateRevision: SHA,
      candidateSourceTreeDigest: sourceTreeDigest,
    },
    verificationManifestDigest: DIGEST,
    entries: [...functions, site].map((artifact) => ({
      kind: artifact.kind,
      logicalTarget: artifact.logicalTarget,
      sourcePath: artifact.kind === 'site' ? 'src/web' : sourcePaths.get(artifact.logicalTarget),
      relativePath: artifact.relativePath,
      canonicalContentDigest: artifact.canonicalContentDigest,
      transportDigest: artifact.transportDigest,
      sizeBytes: artifact.sizeBytes,
    })).sort((left, right) => {
      const a = `${left.kind}\0${left.logicalTarget}`;
      const b = `${right.kind}\0${right.logicalTarget}`;
      return a < b ? -1 : a > b ? 1 : 0;
    }),
  });
  const handoff = createHostedArtifactHandoff({
    revision: SHA,
    manifest,
    github: {
      repository: 'Krowaccie/AppWriteWork',
      workflow: 'Verify Main',
      runId: '1234',
      runAttempt: 1,
      ref: 'refs/heads/main',
    },
  });
  assert.equal(handoff.status, 'PASS');
  return Object.freeze({
    buildIdentity: createHostedSiteBuildIdentity({
      schemaVersion: 'hosted-site-build-identity.v1',
      sourceRevision: SHA,
      sitePayloadDigest: site.canonicalContentDigest,
      verifierManifestDigest: DIGEST,
    }),
    releaseEligibleArtifacts: Object.freeze([site, ...releaseFunctions]),
    testOnlyArtifacts: Object.freeze([runner]),
    artifactManifest: manifest,
    artifactManifestDigest: manifest.artifactManifestDigest,
    handoff: handoff.value,
  });
}

function sourceTransportArtifact({ sourceTreeDigest = DIGEST, authenticBrowserSite = false } = {}) {
  const artifactSet = artifactSetOutput({ sourceTreeDigest, authenticBrowserSite });
  const artifacts = [
    ...artifactSet.releaseEligibleArtifacts,
    ...artifactSet.testOnlyArtifacts,
  ];
  const files = new Map([
    [
      'artifact-manifest.v1.json',
      new TextEncoder().encode(canonicalJson(artifactSet.artifactManifest)),
    ],
    [
      'artifact-handoff.v1.json',
      new TextEncoder().encode(canonicalJson(artifactSet.handoff)),
    ],
    ...artifacts.map((artifact) => [artifact.relativePath, artifact.bytes]),
  ]);
  return Object.freeze({
    artifactManifestDigest: artifactSet.artifactManifestDigest,
    files,
    releaseEligibleArtifacts: Object.freeze(
      artifactSet.artifactManifest.artifacts.filter(
        ({ logicalTarget }) => logicalTarget !== 'verification-runner-py',
      ),
    ),
    sourceArchiveDigest: DIGEST,
    sourceArtifactId: 5678,
    sourceArtifactName: `verification-artifacts-${SHA}`,
    sourceRevision: SHA,
    sourceRunAttempt: 1,
    sourceRunId: 1234,
    testOnlyArtifacts: Object.freeze(
      artifactSet.artifactManifest.artifacts.filter(
        ({ logicalTarget }) => logicalTarget === 'verification-runner-py',
      ),
    ),
    verifierManifestDigest: artifactSet.artifactManifest.verifierManifestDigest,
  });
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function storedZip(entries) {
  const locals = [];
  const centrals = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.path, 'utf8');
    const bytes = Buffer.from(entry.bytes);
    const checksum = crc32(bytes);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(bytes.length, 18);
    local.writeUInt32LE(bytes.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, bytes);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(bytes.length, 20);
    central.writeUInt32LE(bytes.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset += local.length + name.length + bytes.length;
  }
  const localBytes = Buffer.concat(locals);
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  return Buffer.concat([localBytes, centralBytes, end]);
}

function controllerArtifactIoFixture() {
  const controllerPath = CONTROLLER_WORKFLOW;
  const schemaPath = 'dev/verification/schemas/controller-bundle.v2.schema.json';
  const manifestPath = 'packages/verification-controller/controller-bundle.manifest.json';
  const controllerBytes = new TextEncoder().encode('inert controller fixture');
  const schemaBytes = new TextEncoder().encode('inert controller schema fixture');
  const manifest = {
    schemaVersion: 'controller-bundle.v2',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: CONTROLLER_SOURCE_SHA,
    controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
    controllerRevision: SHA,
    entrypoints: [{ path: controllerPath, sha256: sha256Bytes(controllerBytes) }],
    files: [{ path: controllerPath, sha256: sha256Bytes(controllerBytes) }],
    schemaDigests: [{ path: schemaPath, sha256: sha256Bytes(schemaBytes) }],
    trustMaterials: [
      { kind: 'evaluator', path: 'trust/evaluator.v1.json', sha256: DIGEST },
      { kind: 'evidenceValidator', path: 'trust/evidence-validator.v1.json', sha256: DIGEST },
      { kind: 'networkPolicy', path: 'trust/network-policy.v1.json', sha256: DIGEST },
      { kind: 'transcriptCorpus', path: 'trust/transcript-corpus.v2.json', sha256: DIGEST },
    ],
    provenance: { path: 'trust/provenance.v1.json', sha256: DIGEST },
  };
  assert.equal(validateControllerBundleManifest(manifest).status, 'PASS');
  const virtualRoot = path.resolve(root, '.inert-controller-artifact');
  const files = new Map([
    [path.join(virtualRoot, manifestPath), new TextEncoder().encode(canonicalJson(manifest))],
    [path.join(virtualRoot, controllerPath), controllerBytes],
    [path.join(virtualRoot, schemaPath), schemaBytes],
  ]);
  return Object.freeze({
    environment: Object.freeze({
      PROOF_ARTIFACT_ID: '1',
      PROOF_BUNDLE_DIGEST: DIGEST,
      PROOF_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
      PROOF_SHA: SHA,
      PROOF_STATUS: 'PASS',
      GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
      GITHUB_SHA: SHA,
      TRUSTED_CONTROLLER_ARTIFACT_ID: '1',
      TRUSTED_CONTROLLER_BUNDLE_DIGEST: DIGEST,
      TRUSTED_CONTROLLER_SHA: SHA,
    }),
    io: Object.freeze({
      root: virtualRoot,
      async lstat(absolutePath) {
        if (!files.has(absolutePath)) throw new Error('inert artifact path unavailable');
        return Object.freeze({
          isFile: () => true,
          isSymbolicLink: () => false,
        });
      },
      async readFile(absolutePath) {
        const bytes = files.get(absolutePath);
        if (bytes === undefined) throw new Error('inert artifact path unavailable');
        return bytes;
      },
      async realpath(absolutePath) {
        if (absolutePath !== virtualRoot && !files.has(absolutePath)) {
          throw new Error('inert artifact path unavailable');
        }
        return absolutePath;
      },
    }),
  });
}

function identityUser(role) {
  return {
    $id: `${role}-user`,
    $createdAt: '2026-08-01T00:00:00.000Z',
    $updatedAt: '2026-08-01T00:00:00.000Z',
    name: role[0].toUpperCase() + role.slice(1),
    registration: '2026-08-01T00:00:00.000Z',
    passwordUpdate: '2026-08-01T00:00:00.000Z',
    email: `${role}@example.test`,
    phone: '',
    accessedAt: '2026-08-01T00:00:00.000Z',
    status: true,
    emailVerification: true,
    phoneVerification: false,
    mfa: false,
    labels: [],
    targets: [],
    prefs: {
      onboardingCompletedAt: '2026-08-01T00:00:00.000Z',
      onboardingHintsEnabled: false,
    },
  };
}

function derivedIdentityBindingsDigest() {
  const preferences = {
    onboardingCompletedAt: '2026-08-01T00:00:00.000Z',
    onboardingHintsEnabled: false,
  };
  const roles = ['editor', 'owner', 'viewer'].map((role) => {
    const user = identityUser(role);
    const configuredEmailDigest = sha256Bytes(new TextEncoder().encode(user.email));
    const fixturePreferencesDigest = digestJson(preferences);
    const identityCriticalProjectionDigest = digestJson({
      schemaVersion: 'test-cloud.identity-critical-projection.v1',
      role,
      userId: user.$id,
      email: user.email,
      name: user.name,
      active: true,
    });
    const sessionSetDigest = digestJson({
      schemaVersion: 'test-cloud.identity-session-set.v1',
      role,
      total: 0,
    });
    return {
      role,
      userId: user.$id,
      email: user.email,
      name: user.name,
      active: true,
      configuredEmailDigest,
      fixturePreferencesDigest,
      identityCriticalProjectionDigest,
      sessionSetDigest,
      identityDigest: digestJson({
        schemaVersion: 'test-cloud.identity-role-binding.v1',
        role,
        configuredEmailDigest,
        fixturePreferencesDigest,
        identityCriticalProjectionDigest,
        sessionSetDigest,
      }),
    };
  });
  return digestJson({
    schemaVersion: 'test-cloud.identity-bindings.v1',
    responseFormat: '1.9.5',
    environmentDigest: canonicalReadback.environmentDigest,
    providerContractDigest: canonicalReadback.providerContractDigest,
    roles,
  });
}

function runnerVariableValue(key, identityBindingsDigest) {
  const values = {
    VERIFICATION_AUDIT_TABLE_ID: inventory.control.auditTableId,
    VERIFICATION_CONTROL_DATABASE_ID: inventory.control.databaseId,
    VERIFICATION_ENDPOINT_ORIGIN: new URL(inventory.environment.endpoint).origin,
    VERIFICATION_ENVIRONMENT_CLASS: 'appwrite-cloud-test',
    VERIFICATION_ENVIRONMENT_DIGEST: canonicalReadback.environmentDigest,
    VERIFICATION_IDENTITY_BINDINGS_DIGEST: identityBindingsDigest,
    VERIFICATION_INTENT_TABLE_ID: inventory.control.intentTableId,
    VERIFICATION_LEASE_ROW_ID: inventory.control.leaseRowId,
    VERIFICATION_LEASE_TABLE_ID: inventory.control.leaseTableId,
    VERIFICATION_PRIMARY_DATABASE_ID: 'project',
    VERIFICATION_PROJECTS_TABLE_ID: 'projects',
    VERIFICATION_PROJECT_FILES_BUCKET_ID: 'project-files',
    VERIFICATION_PROJECT_ID: inventory.environment.projectId,
    VERIFICATION_PROVIDER_CONTRACT_DIGEST: canonicalReadback.providerContractDigest,
    VERIFICATION_SHARES_TABLE_ID: 'project_shares',
    VERIFICATION_WORKER_FUNCTION_ID: 'verification-runner-py',
  };
  return values[key];
}

function productionSiteProjection(activeDeploymentId = 'existing-site-deployment') {
  return {
    activeDeploymentId,
    buildCommand: 'npm run build',
    installCommand: 'npm ci',
    installationId: 'installation-1',
    outputDirectory: 'dist',
    providerBranch: 'main',
    providerRepositoryId: 'repository-1',
    providerRootDirectory: 'src/web',
    siteId: inventory.environment.siteId,
  };
}

function productionFunctionProjections() {
  const records = [
    ...inventory.productFunctions,
    {
      entrypoint: 'main.py',
      functionId: inventory.control.runnerFunctionId,
      logicalId: inventory.control.runnerFunctionId,
      runtime: 'python-3.12',
      sourcePath: 'src/functions/verification-runner-py',
    },
  ];
  return records.map((record) => {
    const runner = record.functionId === inventory.control.runnerFunctionId;
    return {
      activeDeploymentId: `existing-${record.logicalId}`,
      commands: runner
        ? 'python -m pip install --require-hashes --only-binary=:all: -r requirements.txt'
        : '',
      enabled: !runner,
      entrypoint: record.entrypoint,
      events: [],
      execute: runner ? [] : ['any'],
      functionId: record.functionId,
      logging: !runner,
      name: runner ? 'verification-runner' : record.logicalId,
      providerRootDirectory: runner ? '' : record.sourcePath,
      runtime: record.runtime,
      schedule: '',
      scopes: runner
        ? ['execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write']
        : [],
      timeout: runner ? 30 : 15,
    };
  });
}

function providerSiteResponse(site) {
  return {
    $id: site.siteId,
    buildCommand: site.buildCommand,
    deploymentId: site.activeDeploymentId,
    installCommand: site.installCommand,
    installationId: site.installationId,
    outputDirectory: site.outputDirectory,
    providerBranch: site.providerBranch,
    providerRepositoryId: site.providerRepositoryId,
    providerRootDirectory: site.providerRootDirectory,
  };
}

function providerFunctionResponse(entry) {
  return {
    $id: entry.functionId,
    commands: entry.commands,
    deploymentId: entry.activeDeploymentId,
    enabled: entry.enabled,
    entrypoint: entry.entrypoint,
    events: [...entry.events],
    execute: [...entry.execute],
    logging: entry.logging,
    name: entry.name,
    providerRootDirectory: entry.providerRootDirectory,
    runtime: entry.runtime,
    schedule: entry.schedule,
    scopes: [...entry.scopes],
    timeout: entry.timeout,
  };
}

function productionSetupProjectionDigests(site, functions) {
  const siteProjection = {
    siteId: site.siteId,
    installationId: site.installationId,
    providerRepositoryId: site.providerRepositoryId,
    providerRootDirectory: site.providerRootDirectory,
    providerBranch: site.providerBranch,
    installCommand: site.installCommand,
    buildCommand: site.buildCommand,
    outputDirectory: site.outputDirectory,
  };
  const functionProjections = functions.map((entry) => ({
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
  })).sort((left, right) => (
    left.functionId < right.functionId ? -1 : left.functionId > right.functionId ? 1 : 0
  ));
  return {
    functionConfigurationsDigest: digestJson(functionProjections),
    siteConfigurationDigest: digestJson(siteProjection),
  };
}

function idleProductionLease(genesisLedgerDigest) {
  return {
    acquiredAt: null,
    cleanupDebt: false,
    environmentDigest: null,
    expiresAt: null,
    leaseRowId: inventory.control.leaseRowId,
    leaseTokenDigest: null,
    leaseVersion: 0,
    ledgerDigest: genesisLedgerDigest,
    ownerRunId: null,
    ownerWorkflowRunId: null,
    renewedAt: null,
    state: 'idle',
  };
}

function productionWorkerOutputDigest(request) {
  const parameters = {
    inputProfile: 'verification-minimal',
    logicalWorkflow: 'hello-world-no-cost',
  };
  const operationKey = sha256Bytes(new TextEncoder().encode(
    `${request.runId}|worker.invoke_no_cost|${canonicalJson(parameters)}`,
  ));
  const resourceId = `vr-${sha256Bytes(new TextEncoder().encode(
    `${request.environmentDigest}|${request.runId}|primary-execution`,
  )).slice(7, 39)}`;
  const ownerMarker = `verification-owner.v1:${digestJson({
    environmentDigest: request.environmentDigest,
    operationKey,
    resourceId,
    resourceType: 'primary-execution',
    runId: request.runId,
    schemaVersion: 'verification-owner-marker.v1',
  })}`;
  return digestJson({
    environmentDigest: request.environmentDigest,
    inputProfile: parameters.inputProfile,
    logicalWorkflow: parameters.logicalWorkflow,
    outcome: 'completed-no-cost',
    ownerMarker,
    runId: request.runId,
    schemaVersion: 'verification-worker-output.v1',
  });
}

function productionCleanupGenesis(request, logicalResource, phase, phaseStepCount) {
  const fence = request.cleanupFence;
  return {
    schemaVersion: QUALIFIED_CLEANUP_PROTOCOL.schemaVersion,
    environmentDigest: request.environmentDigest,
    providerContractDigest: fence.providerContractDigest,
    providerAggregateDigest: fence.providerAggregateDigest,
    intentId: fence.intentId,
    intentVersion: fence.intentVersion,
    intentProjectionDigest: fence.intentProjectionDigest,
    logicalResource,
    phase,
    phaseStepCount,
    cleanupRunnerExecutionPlanDigest: fence.cleanupRunnerExecutionPlanDigest,
  };
}

function productionCleanupRunnerData(request) {
  const { cleanupFence: fence, scenarioId } = request;
  const logicalResource = request.parameters.logicalResource;
  const catalog = getCleanupResourceCatalog(logicalResource);
  if (scenarioId === 'resource.cleanup_preflight_step') {
    const prior = fence.phaseCursor === 0
      ? createCleanupPhaseGenesisDigest(productionCleanupGenesis(
        request,
        logicalResource,
        'preflight',
        catalog.preflight.length,
      ))
      : fence.priorPhaseDigest;
    return {
      logicalResource,
      nextPhaseCursor: fence.phaseCursor + 1,
      phaseProgressDigest: advanceCleanupPhaseDigest({
        priorPhaseDigest: prior,
        logicalResource,
        phase: 'preflight',
        phaseCursor: fence.phaseCursor,
        stepId: catalog.preflight[fence.phaseCursor].stepId,
        result: QUALIFIED_CLEANUP_PROTOCOL.result,
      }),
    };
  }
  if (scenarioId === 'resource.cleanup_step') {
    return {
      logicalResource,
      nextCleanupCursor: fence.cleanupCursor + 1,
      cleanupProgressDigest: advanceCleanupProgressDigest({
        priorCleanupProgressDigest: fence.cleanupProgressDigest,
        logicalResource,
        cleanupCursor: fence.cleanupCursor,
        stepId: catalog.mutation[fence.cleanupCursor].stepId,
        result: QUALIFIED_CLEANUP_PROTOCOL.result,
      }),
    };
  }
  if (scenarioId === 'resource.cleanup_proof_step') {
    const phaseProgressDigest = advanceCleanupProofDigest({
      priorCleanupProofDigest: fence.priorPhaseDigest,
      logicalResource,
      proofCursor: fence.phaseCursor,
      stepId: catalog.proof[fence.phaseCursor].stepId,
      result: QUALIFIED_CLEANUP_PROTOCOL.result,
    });
    return {
      logicalResource,
      nextPhaseCursor: fence.phaseCursor + 1,
      phaseProgressDigest,
      cleanupProofDigest: fence.phaseCursor + 1 === catalog.proof.length
        ? phaseProgressDigest
        : null,
    };
  }
  return {
    logicalResource,
    deleted: true,
    absenceProven: true,
    cleanupProofDigest: fence.cleanupProofDigest,
  };
}

function simulateProductionRunnerControlWrites({ request, rows, rowKey }) {
  const intentEntry = [...rows.entries()].find(([, value]) => (
    value?.resourceType === 'primary-execution'
    && value.runId === request.runId
    && value.environmentDigest === request.environmentDigest
    && value.state === 'planned'
    && value.intentVersion === 1
  ));
  assert.ok(intentEntry, 'runner must observe the planned primary execution');
  const intent = structuredClone(intentEntry[1]);
  let lease = structuredClone(rows.get(rowKey(
    inventory.control.leaseTableId,
    inventory.control.leaseRowId,
  )));

  const commit = (snapshot, transition) => {
    const snapshotDigest = digestJson(snapshot);
    const event = {
      schemaVersion: 'verification-audit-event.v1',
      previousLedgerDigest: lease.ledgerDigest,
      runId: request.runId,
      leaseVersionBefore: lease.leaseVersion,
      leaseVersionAfter: lease.leaseVersion + 1,
      transition,
      intentId: snapshot.intentId,
      intentProjectionDigest: snapshotDigest,
    };
    lease = {
      ...lease,
      leaseVersion: lease.leaseVersion + 1,
      ledgerDigest: digestJson(event),
    };
    rows.set(rowKey(
      inventory.control.intentTableId,
      contentDigestToRowId(snapshotDigest),
    ), structuredClone(snapshot));
    rows.set(rowKey(
      inventory.control.intentTableId,
      intentIdToRowId(snapshot.intentId),
    ), structuredClone(snapshot));
    rows.set(rowKey(
      inventory.control.auditTableId,
      contentDigestToRowId(lease.ledgerDigest),
    ), structuredClone(event));
    rows.set(rowKey(
      inventory.control.leaseTableId,
      inventory.control.leaseRowId,
    ), structuredClone(lease));
  };

  const createdAt = Date.parse(intent.createdAt);
  const runnerPlanned = {
    ...intent,
    intentVersion: 2,
    updatedAt: intent.createdAt,
  };
  commit(runnerPlanned, 'observation.planned');
  commit({
    ...runnerPlanned,
    providerResourceIds: ['inner-worker-execution-1'],
    state: 'created',
    intentVersion: 3,
    observationDigest: digestJson({
      schemaVersion: 'verification-inner-execution-observation.v1',
      executionStatus: 'completed',
      responseStatusCode: 200,
      responseBodyDigest: `sha256:${'a'.repeat(64)}`,
      protocolOutcome: 'verified',
    }),
    retentionExpiresAt: new Date(
      createdAt + request.primaryExecutionRetentionMaxSeconds * 1000,
    ).toISOString(),
    updatedAt: intent.createdAt,
  }, 'observation.observed');
}

function installProviderResponseHarness() {
  const previousHeaders = globalThis.Headers;
  const previousResponse = globalThis.Response;
  const headerRecords = new WeakMap();
  const responseRecords = new WeakMap();
  class ProviderHeaders {
    constructor(values) {
      headerRecords.set(this, new Map(
        Object.entries(values).map(([name, value]) => [name.toLowerCase(), String(value)]),
      ));
    }

    get(name) {
      return headerRecords.get(this).get(String(name).toLowerCase()) ?? null;
    }
  }
  class ProviderResponse {
    constructor(value, { status = 200, url = '' } = {}) {
      const textValue = canonicalJson(value);
      const bytes = new TextEncoder().encode(textValue);
      responseRecords.set(this, {
        bytes,
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(bytes);
            controller.close();
          },
        }),
        headers: new ProviderHeaders({
          'content-length': String(bytes.byteLength),
          'content-type': 'application/json; charset=utf-8',
        }),
        status,
        url,
      });
    }

    get body() { return responseRecords.get(this).body; }

    get headers() { return responseRecords.get(this).headers; }

    get ok() { return this.status >= 200 && this.status < 300; }

    get redirected() { return false; }

    get status() { return responseRecords.get(this).status; }

    get url() { return responseRecords.get(this).url; }

    async arrayBuffer() {
      const bytes = responseRecords.get(this).bytes;
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    }

    async json() {
      return JSON.parse(new TextDecoder().decode(responseRecords.get(this).bytes));
    }

    async text() {
      return new TextDecoder().decode(responseRecords.get(this).bytes);
    }
  }
  globalThis.Headers = ProviderHeaders;
  globalThis.Response = ProviderResponse;
  return {
    ProviderResponse,
    restore() {
      globalThis.Headers = previousHeaders;
      globalThis.Response = previousResponse;
    },
  };
}

function controllerHarness() {
  const calls = [];
  const downstreamArgs = { createClients: null };
  const artifactSet = artifactSetOutput();
  const functionArtifacts = [
    ...artifactSet.releaseEligibleArtifacts.filter(({ kind }) => kind === 'function'),
    ...artifactSet.testOnlyArtifacts,
  ];
  const functionDeployments = Object.freeze(functionArtifacts.map((artifact, index) =>
    Object.freeze({
      kind: 'function',
      logicalTarget: artifact.logicalTarget,
      deploymentId: `function-deployment-${index + 1}`,
      activeDeploymentId: `function-deployment-${index + 1}`,
      status: 'ready',
      artifactTransportDigest: artifact.transportDigest,
    })));
  const siteDeployment = Object.freeze({
    kind: 'site',
    logicalTarget: 'web',
    deploymentId: 'site-deployment-1',
    activeDeploymentId: 'site-deployment-1',
    status: 'ready',
    artifactTransportDigest: artifactSet.releaseEligibleArtifacts[0].transportDigest,
  });
  const stage = (name, value) => async () => {
    calls.push(name);
    return pass(value);
  };
  const acquiredLease = Object.freeze({
    acquiredAt: '2026-07-20T09:59:00.000Z',
    cleanupDebt: false,
    environmentDigest: `sha256:${'a'.repeat(64)}`,
    expiresAt: '2026-07-20T10:29:00.000Z',
    leaseRowId: inventory.control.leaseRowId,
    leaseTokenDigest: `sha256:${'b'.repeat(64)}`,
    leaseVersion: 7,
    ledgerDigest: `sha256:${'c'.repeat(64)}`,
    ownerRunId: 'verify-0123456789ab-1234-1',
    ownerWorkflowRunId: '1234',
    renewedAt: '2026-07-20T09:59:00.000Z',
    state: 'active',
  });
  const e2eLease = Object.freeze({
    ...acquiredLease,
    leaseVersion: 8,
    ledgerDigest: `sha256:${'d'.repeat(64)}`,
  });
  const cleanup = async (request) => {
    calls.push('cleanup');
    const predecessorLease = Object.freeze({
      ...request.lease,
      leaseVersion: request.lease.leaseVersion
        + QUALIFIED_CLEANUP_PROTOCOL.counts.knownRunnerCalls,
      ledgerDigest: `sha256:${'f'.repeat(64)}`,
    });
    const event = {
      schemaVersion: 'verification-audit-event.v1',
      previousLedgerDigest: predecessorLease.ledgerDigest,
      runId: predecessorLease.ownerRunId,
      leaseVersionBefore: predecessorLease.leaseVersion,
      leaseVersionAfter: predecessorLease.leaseVersion + 1,
      transition: 'lease.close',
      intentId: null,
      intentProjectionDigest: null,
    };
    const outcome = pass(Object.freeze({
      closed: true,
      lease: Object.freeze({
        ...predecessorLease,
        leaseVersion: predecessorLease.leaseVersion + 1,
        state: 'idle',
        ownerRunId: null,
        ownerWorkflowRunId: null,
        environmentDigest: null,
        acquiredAt: null,
        renewedAt: null,
        expiresAt: null,
        ledgerDigest: digestJson(event),
        leaseTokenDigest: null,
        cleanupDebt: false,
      }),
      closeProof: Object.freeze({
        predecessorLease,
        event: Object.freeze(event),
      }),
    }));
    return outcome;
  };
  const clients = Object.freeze({
    preflight: stage('preflight', Object.freeze({ attested: true })),
    acquireLease: stage('acquireLease', Object.freeze({
      lease: acquiredLease,
      capability: 'capability-1',
    })),
    deployFunctionArtifacts: stage('deployFunctionArtifacts', functionDeployments),
    deploySiteArtifact: stage('deploySiteArtifact', siteDeployment),
    qualifyRunner: stage('qualifyRunner', Object.freeze({ qualified: true })),
    runE2E: stage('runE2E', Object.freeze({
      passed: true,
      lease: e2eLease,
      capability: 'capability-2',
    })),
    cleanup,
  });
  const clock = Object.freeze({
    now: () => '2026-07-20T10:00:00.000Z',
  });
  const evidenceWriter = Object.freeze({
    write: async () => {
      calls.push('evidence');
      return pass(Object.freeze({
        path: '.verification/results/test-cloud-result.json',
        evidenceDigest: EVIDENCE_DIGEST,
      }));
    },
  });
  const dependencies = Object.freeze({
    bootstrapRuntime: async () => globalThis[CONTROLLER_BOOTSTRAP_HARNESS_KEY](),
    resolveSourceSelection: async ({ requestedRevision }) => {
      calls.push('selection');
      assert.equal(requestedRevision, SHA);
      return pass(sourceSelection());
    },
    consumeHostedArtifact: async ({ selection }) => {
      calls.push('artifact');
      assert.equal(selection.sourceRevision, SHA);
      return pass(artifactSet);
    },
    createClients: async (args) => {
      downstreamArgs.createClients = args;
      const { controller, selection, artifactSet: received } = args;
      calls.push('clients');
      assert.equal(controller.controllerBundleSha, SHA);
      assert.equal(selection.sourceRevision, SHA);
      assert.equal(received, artifactSet);
      return pass(clients);
    },
    runLane: controllerHarnessRunLane,
    clock,
    evidenceWriter,
  });
  return {
    calls,
    dependencies,
    downstreamArgs,
    artifactSet,
    clients,
    functionDeployments,
    siteDeployment,
  };
}

async function installTask8SyntheticBrowserTransport(
  providerReadback,
  { interruptAfterPhysicalCreateOrdinal = null } = {},
) {
  const adapterTestSource = await readFile(new URL(
    './test-cloud-browser-route-adapter.test.mjs',
    import.meta.url,
  ), 'utf8');
  const sourceMatch = /const workerPlaywrightSource = String\.raw`([\s\S]*?)`;\r?\n\r?\nfunction runFinalLifecycleWorker/u
    .exec(adapterTestSource);
  assert.notEqual(sourceMatch, null, 'Task 7 in-memory transport source anchor');
  const transportSource = sourceMatch[1].replace(
    "else if (label.startsWith('mutation-')) state.calls.push(['fulfillResponse', Number(label.slice(9))]);",
    "else if (label.startsWith('mutation-')) { const ordinal = Number(label.slice(9)); state.calls.push(['fulfillResponse', ordinal]); state.routeDeliveries.get(ordinal)?.resolve(); }",
  ).replace(
    "  const handler = state.routeHandler(route);\n  await new Promise((resolve) => setImmediate(resolve));",
    "  const delivery = {};\n  delivery.promise = new Promise((resolve) => { delivery.resolve = resolve; });\n  state.routeDeliveries.set(ordinal, delivery);\n  const handler = state.routeHandler(route);\n  await new Promise((resolve) => setImmediate(resolve));",
  ).replace(
    "async addInitScript() { state.calls.push(['initScript']); },",
    "async addInitScript(options) { state.calls.push(['initScript']); state.baseUtc = options.baseUtc; },",
  ).replace(
    "state.calls.push(['launch', options]);",
    "state.calls.push(['injectedTransportLaunch']); state.calls.push(['launch', options]);",
  ).replace(
    "        if (row !== null) state.backendRows.set(row.$id, closed(row));",
    "        if (row !== null) state.backendRows.set(row.$id, closed(row));\n        if (ordinal === state.interruptAfterPhysicalCreateOrdinal) { state.physicalCreateInterruptions += 1; throw new Error('physical create response interrupted'); }",
  );
  assert.notEqual(transportSource, sourceMatch[1], 'Task 8 transport handoff anchors');
  const users = Object.freeze(Object.fromEntries(
    ['editor', 'owner', 'viewer'].map((role) => [role, identityUser(role)]),
  ));
  const runnerValues = Object.freeze(Object.fromEntries(
    providerReadback.expectedRunnerVariables.variables.map(({ key }) => [
      key,
      runnerVariableValue(key, providerReadback.identityBindings.identityBindingsDigest),
    ]),
  ));
  const state = globalThis.__routeAdapterTestState = {
    calls: [],
    lifecycle: 'ACTIVE',
    factoryAuthorization: false,
    playwrightModuleLoads: 0,
    realLaunches: 0,
    pageUrl: 'about:blank',
    nextOrdinal: 0,
    clockOperationsCreated: 0,
    shareEmail: undefined,
    shareRole: 'viewer',
    releaseMode: 'private-readback-real-composition',
    runtimeQualification: undefined,
    safeReflectApply: Reflect.apply,
    backendRows: new Map(),
    shareBackendRows: [],
    providerQualification: Object.freeze(Object.create(null)),
    reflectApplyPoisonCalls: [],
    primaryDatabaseId: runnerValues.VERIFICATION_PRIMARY_DATABASE_ID,
    sharesTableId: runnerValues.VERIFICATION_SHARES_TABLE_ID,
    ownerAccount: users.owner,
    routeDeliveries: new Map(),
    interruptAfterPhysicalCreateOrdinal,
    physicalCreateInterruptions: 0,
    producerObservations: [],
  };
  const transportModuleUrl =
    `data:text/javascript;base64,${Buffer.from(transportSource).toString('base64')}`;
  const realProducerUrl = new URL(
    './test-cloud-fixture-intent-producer.mjs',
    import.meta.url,
  ).href;
  const producerObserverSource = `
    import * as real from ${JSON.stringify(realProducerUrl)};
    export * from ${JSON.stringify(realProducerUrl)};
    export async function runTrustedTestCloudFixtureIntentProducer(args) {
      const result = await real.runTrustedTestCloudFixtureIntentProducer(args);
      globalThis.__routeAdapterTestState.producerObservations.push(Object.freeze({
        status: result?.status,
        capabilityIsNull: result?.value?.capability === null,
        cleanupDebt: result?.value?.lease?.cleanupDebt,
        leaseVersion: result?.value?.lease?.leaseVersion,
        ledgerDigest: result?.value?.lease?.ledgerDigest,
        state: result?.value?.lease?.state,
      }));
      return result;
    }
  `;
  const producerObserverUrl =
    `data:text/javascript;base64,${Buffer.from(producerObserverSource).toString('base64')}`;
  const transport = await import(transportModuleUrl);
  await transport.chromium.launch({ probe: true });
  state.calls.length = 0;
  const playwright = await import('playwright');
  const actualLauncherNames = Object.freeze([
    'launch', 'launchPersistentContext', 'launchServer',
  ]);
  const launcherDescriptors = new Map(actualLauncherNames.map((name) => [
    name,
    Object.getOwnPropertyDescriptor(playwright.chromium, name),
  ]));
  for (const name of actualLauncherNames) {
    assert.equal(typeof playwright.chromium[name], 'function');
    Object.defineProperty(playwright.chromium, name, {
      configurable: true,
      enumerable: false,
      writable: true,
      value: async function poisonActualTask8ChromiumLauncher() {
        state.realLaunches += 1;
        throw new Error(`actual Playwright chromium.${name} is poisoned in Task 8`);
      },
    });
  }
  const syntheticPlaywrightHook = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === 'playwright') {
        return { url: transportModuleUrl, shortCircuit: true };
      }
      if (specifier === './test-cloud-fixture-intent-producer.mjs') {
        return { url: producerObserverUrl, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
  });

  const operations = [];
  for (const resource of task8ProviderContract.aggregateContracts.resources) {
    for (const member of resource.memberTemplates) {
      for (const operation of member.operations) {
        operations[operation.mutationOrdinal] = { resource, member, operation };
      }
    }
  }
  const ids = Object.freeze({
    rootManifestInitial: 'file-0', entrypointSourceInitial: 'file-1',
    rootArtifact: 'row-2', entrypointArtifact: 'row-3', rootVersionInitial: 'row-4',
    entrypointVersionInitial: 'row-5', projectFacade: 'row-6',
    entrypointSourceSaved: 'file-7', entrypointVersionSaved: 'row-8',
    rootManifestSaved: 'file-10', rootVersionSaved: 'row-11',
    visualModelSourceSaved: 'file-14', visualModelArtifact: 'row-15',
    visualModelVersionSaved: 'row-16', editorShare: 'share-row-17',
    viewerShare: 'share-row-18',
  });
  const sha = (value) => sha256Bytes(value instanceof Uint8Array ? value : Buffer.from(value));
  const valueDigest = (value) => sha(Buffer.from(
    typeof value === 'string' ? value : canonicalJson(value),
  ));
  const logical = new Map([
    ['rootArtifact.rootArtifactId', 'root-artifact-id'],
    ['projectFacade.projectId', 'project-id'],
    ['entrypointArtifact.entrypointArtifactId', 'entrypoint-artifact-id'],
    ['entrypointVersionInitial.initialEntrypointVersionId', 'entrypoint-version-id'],
    ['entrypointVersionInitial.workflowContentHash', sha(Buffer.from('workflow-content'))],
    ['rootVersionInitial.initialRootVersionId', ids.rootVersionInitial],
    ['entrypointVersionSaved.savedEntrypointVersionId', ids.entrypointVersionSaved],
    ['rootVersionSaved.savedRootVersionId', ids.rootVersionSaved],
    ['visualModelArtifact.visualArtifactId', ids.visualModelArtifact],
    ['visualModelVersionSaved.visualVersionId', ids.visualModelVersionSaved],
  ]);
  const sourceBytes = new Map();
  const priorStates = new Map();
  const tableId = (binding) => binding.replaceAll('-', '_');
  const publishedAt = (mutationOrdinal) => {
    const row = task8ProviderContract.fixtureClockPolicy.publishedAtOffsets.find(
      (candidate) => candidate.mutationOrdinal === mutationOrdinal,
    );
    if (row === undefined || typeof state.baseUtc !== 'string') {
      throw new Error(`fixture clock ${mutationOrdinal}`);
    }
    return new Date(Date.parse(state.baseUtc) + row.offsetMilliseconds).toISOString();
  };
  const derive = (kind, inputs) => {
    if (kind === 'stable-default-entrypoint-ref') return JSON.stringify({
      kind: 'artifact-version',
      ref: {
        projectId: inputs[0], artifactId: inputs[1], artifactType: 'workflow.dag.v1',
        versionId: inputs[2], stability: 'stable',
      },
      contentHash: inputs[3],
    });
    if (kind === 'workflow-save-file-name') return `${inputs[0]}.workflow.dag.json`;
    if (kind === 'container-manifest-file-name') {
      return `${String(inputs[0]).split(':').at(-1).replace(/[^A-Za-z0-9._-]/gu, '-')}.container.json`;
    }
    if (kind === 'visual-model-artifact-name') return `${inputs[0]} layout`;
    if (kind === 'visual-model-file-name') {
      return `${String(inputs[0]).replace(/[^A-Za-z0-9._-]/gu, '-')}.json`;
    }
    throw new Error(`derive ${kind}`);
  };
  const resolveSource = (source) => {
    if (source.kind === 'literal') return structuredClone(source.value);
    if (source.kind === 'contract-literal') {
      return structuredClone(task8ProviderContract.fixtureSemanticLiterals[source.name]);
    }
    if (source.kind === 'owner-user-id') return users.owner.$id;
    if (source.kind === 'logical-value') return logical.get(`${source.ownerSlot}.${source.name}`);
    if (source.kind === 'provider-id') return ids[source.ownerSlot];
    if (source.kind === 'environment-id') {
      return runnerValues.VERIFICATION_PROJECT_FILES_BUCKET_ID;
    }
    if (source.kind === 'expected-state-field') {
      return priorStates.get(source.sourceMutationOrdinal)[source.key];
    }
    if (source.kind === 'source-bytes-size') {
      return sourceBytes.get(source.sourceMutationOrdinal).byteLength;
    }
    if (source.kind === 'runtime-utc-timestamp') return publishedAt(source.mutationOrdinal);
    if (source.kind === 'derived-string') {
      return derive(source.derivation, source.inputSources.map(resolveSource));
    }
    throw new Error(`source ${JSON.stringify(source)}`);
  };
  const expectedFor = (ordinal) => {
    const expected = operations[ordinal].operation.expectedStateContract;
    if (expected === null) return null;
    const output = expected.baseSourceMutationOrdinal === null
      || expected.baseSourceMutationOrdinal === undefined
      ? {}
      : { ...priorStates.get(expected.baseSourceMutationOrdinal) };
    for (const row of expected.valueSources) output[row.key] = resolveSource(row.source);
    const ordered = {};
    for (const key of expected.applicationKeys ?? expected.metadataKeys) ordered[key] = output[key];
    return ordered;
  };
  const multipart = (ordinal, fileId, fileName, mimeType, bytes) => {
    const boundary = `----task8-composition-${ordinal}`;
    return {
      bytes: Buffer.concat([
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="fileId"\r\n\r\n${fileId}\r\n--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: ${mimeType}\r\n\r\n`),
        bytes,
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]),
      contentType: `multipart/form-data; boundary=${boundary}`,
    };
  };
  state.realRequestAuthority = (ordinal, role) => {
    const { resource, member, operation } = operations[ordinal];
    if (ordinal === 0) {
      const manifest = {
        schemaVersion: 1, projectId: 'project-id', artifactId: 'root-artifact-id',
        containerProfile: 'project-root', name: 'Hello World', parentContainerId: null,
        children: [{
          relationship: 'owned',
          ref: {
            projectId: 'project-id', artifactId: 'entrypoint-artifact-id',
            artifactType: 'workflow.dag.v1', artifactVersionId: 'entrypoint-version-id',
            contentHash: sha(Buffer.from('workflow-content')),
          },
        }],
        lifecycleState: 'published',
      };
      sourceBytes.set(0, Buffer.from(JSON.stringify(manifest)));
      logical.set('rootVersionInitial.rootContentHash', sha(sourceBytes.get(0)));
    }
    if ([1, 7, 10, 14].includes(ordinal)) {
      sourceBytes.set(ordinal, Buffer.from(canonicalJson({ ordinal, content: `source-${ordinal}` })));
      if (ordinal === 1) {
        logical.set('entrypointSourceInitial.sourceBytesDigest', sha(sourceBytes.get(ordinal)));
      }
      if (ordinal === 7) {
        logical.set('entrypointSourceSaved.sourceBytesDigest', sha(sourceBytes.get(ordinal)));
        logical.set('entrypointVersionSaved.workflowContentHash', sha(sourceBytes.get(ordinal)));
      }
      if (ordinal === 10) {
        logical.set('rootManifestSaved.sourceBytesDigest', sha(sourceBytes.get(ordinal)));
        logical.set('rootVersionSaved.rootContentHash', sha(sourceBytes.get(ordinal)));
      }
      if (ordinal === 14) {
        logical.set('visualModelSourceSaved.sourceBytesDigest', sha(sourceBytes.get(ordinal)));
        logical.set('visualModelVersionSaved.visualContentHash', sha(sourceBytes.get(ordinal)));
      }
    }
    let body;
    let bytes;
    let headers = Object.freeze([]);
    const pathValues = {};
    const bodyValues = {};
    if (ordinal >= 17) {
      body = { email: `${role}@example.test`, role, canRun: role === 'editor' };
      bytes = Buffer.from(JSON.stringify({
        body: JSON.stringify(body), async: false, path: '/', method: 'POST',
      }));
      Object.assign(bodyValues, {
        canonicalTargetEmail: body.email,
        sharePermissionsDigest: valueDigest([]),
        sharedByUserId: users.owner.$id,
        targetIdentityDigest: valueDigest(`${role}-user`),
        targetUserId: `${role}-user`,
        tupleDigest: valueDigest(`${role}|${body.canRun}`),
      });
    } else if (member.providerKind === 'storage-file') {
      const expected = expectedFor(ordinal);
      const fileBytes = sourceBytes.get(ordinal);
      const upload = multipart(
        ordinal, ids[member.slot], expected.fileName, expected.mimeType, fileBytes,
      );
      bytes = upload.bytes;
      headers = Object.freeze([Object.freeze({ name: 'content-type', value: upload.contentType })]);
      Object.assign(pathValues, {
        'path.bucketId': runnerValues.VERIFICATION_PROJECT_FILES_BUCKET_ID,
      });
      Object.assign(bodyValues, {
        'body.fileId': ids[member.slot],
        'body.fileName': expected.fileName,
        'body.mimeType': expected.mimeType,
        'body.permissionsDigest': valueDigest([]),
        'body.sizeBytes': fileBytes.byteLength,
        'body.sourceBytesDigest': sha(fileBytes),
      });
      priorStates.set(ordinal, expected);
    } else {
      const expected = expectedFor(ordinal);
      const template = operation.requestTemplate;
      const data = Object.fromEntries(
        template.bodyTemplate.dataKeys.map((key) => [key, expected[key]]),
      );
      const update = template.bodyKind === 'row-update';
      body = update ? { data } : { rowId: ids[member.slot], data, permissions: [] };
      bytes = Buffer.from(JSON.stringify(body));
      Object.assign(pathValues, {
        'path.databaseId': runnerValues.VERIFICATION_PRIMARY_DATABASE_ID,
        'path.tableId': tableId(member.bindingName),
        ...(update ? { 'path.rowId': ids[member.slot] } : {}),
      });
      for (const [key, value] of Object.entries(data)) bodyValues[`body.${key}`] = value;
      if (!update) {
        bodyValues['body.rowId'] = ids[member.slot];
        bodyValues['body.permissionsDigest'] = valueDigest([]);
      }
      priorStates.set(ordinal, expected);
    }
    const values = { ...pathValues, ...bodyValues };
    const requestTemplate = structuredClone(operation.requestTemplate);
    const freezeTree = (value) => {
      if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        for (const item of Object.values(value)) freezeTree(item);
        Object.freeze(value);
      }
      return value;
    };
    freezeTree(requestTemplate);
    const logicalValueBindings = Object.freeze(requestTemplate.bindingNames.map((name) =>
      Object.freeze(Object.assign(Object.create(null), {
        name,
        value: values[name],
        valueDigest: valueDigest(values[name]),
      }))));
    const fixedShareQueryContract = ordinal >= 17
      ? Object.freeze(Object.assign(Object.create(null), {
        bindingName: 'project-shares',
        databaseBinding: 'VERIFICATION_PRIMARY_DATABASE_ID',
        databaseId: runnerValues.VERIFICATION_PRIMARY_DATABASE_ID,
        filterField: 'projectId',
        limit: 3,
        projectionKeys: Object.freeze([
          '$id', '$sequence', '$tableId', '$databaseId', '$createdAt', '$updatedAt',
          '$permissions', 'projectId', 'userId', 'userEmail', 'userName', 'role',
          'canRun', 'sharedBy',
        ]),
        tableId: runnerValues.VERIFICATION_SHARES_TABLE_ID,
        tableIdSource: 'VERIFICATION_SHARES_TABLE_ID',
        total: true,
        transactionId: null,
        transactionMode: 'committed',
      }))
      : null;
    const expectedContract = operation.expectedStateContract;
    const applicationKeys = expectedContract === null
      ? null
      : Object.freeze([...(expectedContract.applicationKeys ?? expectedContract.metadataKeys)]);
    const systemKeys = Object.freeze([
      '$id', '$sequence', '$tableId', '$databaseId', '$createdAt', '$updatedAt', '$permissions',
    ]);
    const memberReadbackContract = ordinal >= 17
      ? null
      : Object.freeze(Object.assign(Object.create(null), {
        applicationKeys,
        databaseBinding: member.providerKind === 'tablesdb-row'
          ? 'VERIFICATION_PRIMARY_DATABASE_ID'
          : null,
        logicalResource: resource.resourceType,
        ownerSlot: member.slot,
        projectionKeys: member.providerKind === 'tablesdb-row'
          ? Object.freeze([...systemKeys, ...applicationKeys])
          : applicationKeys,
        providerKind: member.providerKind,
        tableBinding: member.bindingName,
        transactionId: null,
        transactionMode: member.providerKind === 'tablesdb-row' ? 'committed' : null,
      }));
    const url = ordinal >= 17
      ? `${inventory.environment.endpoint}/functions/sharing-py/executions`
      : member.providerKind === 'storage-file'
        ? `${inventory.environment.endpoint}/storage/buckets/${runnerValues.VERIFICATION_PROJECT_FILES_BUCKET_ID}/files`
        : `${inventory.environment.endpoint}/tablesdb/${runnerValues.VERIFICATION_PRIMARY_DATABASE_ID}/tables/${tableId(member.bindingName)}/rows${operation.requestTemplate.bodyKind === 'row-update' ? `/${ids[member.slot]}` : ''}`;
    return {
      authority: Object.freeze(Object.assign(Object.create(null), {
        operationQualification: Object.freeze(Object.create(null)),
        requestTemplate,
        requestTemplateDigest: sha(Buffer.from(canonicalJson(requestTemplate))),
        exactDeploymentOrigin: new URL(inventory.environment.endpoint).origin,
        fixedShareQueryContract,
        initialSourceOperationBindings: Object.freeze([]),
        logicalValueBindings,
        memberReadbackContract,
      })),
      bytes,
      headers,
      url,
    };
  };
  state.realBackendRowForOrdinal = (ordinal) => {
    if (ordinal >= 17) return null;
    const { member } = operations[ordinal];
    const expected = priorStates.get(ordinal);
    if (member.providerKind === 'storage-file') return {
      $id: ids[member.slot], bucketId: runnerValues.VERIFICATION_PROJECT_FILES_BUCKET_ID,
      name: expected.fileName, mimeType: expected.mimeType, sizeOriginal: expected.sizeBytes,
      $permissions: [],
    };
    const row = {
      $id: ids[member.slot], $sequence: ordinal, $tableId: tableId(member.bindingName),
      $databaseId: runnerValues.VERIFICATION_PRIMARY_DATABASE_ID,
      $createdAt: `2026-07-28T00:00:${String(ordinal).padStart(2, '0')}.000Z`,
      $updatedAt: `2026-07-28T00:00:${String(ordinal).padStart(2, '0')}.000Z`,
      $permissions: [], ...expected,
    };
    return Object.fromEntries(member.readProjectionKeys.map((key) => [key, row[key]]));
  };
  state.publicProviderMutation = async ({ handler, mutationOrdinal }) => {
    const delivery = state.routeDeliveries.get(mutationOrdinal);
    if (delivery === undefined) throw new Error(`missing route delivery ${mutationOrdinal}`);
    try {
      if (mutationOrdinal === state.interruptAfterPhysicalCreateOrdinal) {
        await handler;
        return Object.freeze({
          status: 'BLOCKED', value: null, diagnostics: Object.freeze([]),
        });
      }
      await handler;
      await delivery.promise;
      return pass({ reconciled: true });
    } finally {
      state.routeDeliveries.delete(mutationOrdinal);
    }
  };
  const policyRows = providerReadback.browserRequestPolicy.rows;
  state.endpointUrl = policyRows.find(
    ({ requestClass }) => requestClass === 'owner-session-create',
  ).finalUrl;
  state.accountUrl = policyRows.find(
    ({ requestClass }) => requestClass === 'appwrite-read',
  ).finalUrl;
  const header = (name, value) => Object.freeze({ name, value });
  const sdkHeaders = Object.freeze([
    header('x-appwrite-project', inventory.environment.projectId),
    header('x-appwrite-response-format', '1.8.0'),
    header('x-sdk-language', 'web'), header('x-sdk-name', 'Web'),
    header('x-sdk-platform', 'client'), header('x-sdk-version', '21.5.0'),
  ]);
  const corsHeaders = Object.freeze([
    header('access-control-allow-credentials', 'true'),
    header('access-control-allow-headers', 'Accept, Origin, Cookie, Set-Cookie, Content-Type, Content-Range, X-Appwrite-Project, X-Appwrite-Key, X-Appwrite-Dev-Key, X-Appwrite-Locale, X-Appwrite-Mode, X-Appwrite-JWT, X-Appwrite-Organization, X-Appwrite-Response-Format, X-Appwrite-Timeout, X-Appwrite-ID, X-Appwrite-Timestamp, X-Appwrite-Session, X-Appwrite-Platform, X-Appwrite-Impersonate-User-Id, X-Appwrite-Impersonate-User-Email, X-Appwrite-Impersonate-User-Phone, X-SDK-Version, X-SDK-Name, X-SDK-Language, X-SDK-Platform, X-SDK-GraphQL, X-SDK-Profile, Range, Cache-Control, Expires, Pragma, X-Fallback-Cookies, X-Requested-With, X-Forwarded-For, X-Forwarded-User-Agent'),
    header('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE'),
    header('access-control-allow-origin', inventory.environment.publicOrigin),
    header('access-control-expose-headers', 'X-Appwrite-Session, X-Fallback-Cookies'),
    header('access-control-max-age', '86400'),
  ]);
  state.ownerSessionRequestHeaders = Object.freeze([
    header('content-type', 'application/json'), ...sdkHeaders,
  ]);
  state.ownerSessionResponseHeaders = Object.freeze([
    ...corsHeaders, header('content-type', 'application/json; charset=utf-8'),
    header('set-cookie', 'opaque-session-a'), header('set-cookie', 'opaque-session-b'),
    header('x-debug-fallback', 'opaque-a'), header('x-debug-fallback', 'opaque-b'),
    header('x-debug-speed', 'opaque'), header('x-ratelimit-limit', 'opaque'),
    header('x-ratelimit-remaining', 'opaque'), header('x-ratelimit-reset', 'opaque'),
  ]);
  state.ownerAccountRequestHeaders = Object.freeze([
    ...sdkHeaders, header('cookie', 'opaque-cookie'),
  ]);
  state.ownerAccountResponseHeaders = Object.freeze([
    ...corsHeaders, header('content-type', 'application/json; charset=utf-8'),
    header('x-debug-fallback', 'opaque'), header('x-debug-speed', 'opaque'),
  ]);
  return Object.freeze({
    state,
    restore() {
      syntheticPlaywrightHook.deregister();
      for (const name of actualLauncherNames) {
        const descriptor = launcherDescriptors.get(name);
        if (descriptor === undefined) delete playwright.chromium[name];
        else Object.defineProperty(playwright.chromium, name, descriptor);
      }
      delete globalThis.__routeAdapterTestState;
    },
  });
}

async function productionCompositionOutcome(mode) {
  const responseHarness = installProviderResponseHarness();
  const previousFetch = globalThis.fetch;
  const processCalls = [];
  const providerCalls = [];
  const sourceCalls = [];
  const artifactTransportCalls = [];
  const site = productionSiteProjection();
  const functions = productionFunctionProjections();
  const sourceTreeDigest = mode === 'vcs-site-identity'
    ? `sha256:${'7'.repeat(64)}`
    : DIGEST;
  const artifactSet = artifactSetOutput({ sourceTreeDigest, authenticBrowserSite: true });
  const sourceArtifact = sourceTransportArtifact({ sourceTreeDigest, authenticBrowserSite: true });
  const browserArtifactProjection = await projectTestCloudBrowserArtifactPolicyRows({
    sourceArtifactSet: artifactSet,
  });
  assert.equal(browserArtifactProjection.status, 'PASS');
  const browserPolicy = createAppwriteTestBrowserPolicy({
    browserArtifactProjection: browserArtifactProjection.value,
    environmentDigest: canonicalReadback.environmentDigest,
    providerContractDigest: canonicalReadback.providerContractDigest,
  });
  assert.equal(browserPolicy.status, 'PASS');
  const sourceArchiveBytes = storedZip([...sourceArtifact.files].map(([entryPath, bytes]) => ({
    path: entryPath,
    bytes,
  })));
  const sourceArchiveDigest = sha256Bytes(sourceArchiveBytes);
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const sourcePrivateKey = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const controllerArtifact = controllerArtifactIoFixture();
  const setupProjectionDigests = productionSetupProjectionDigests(site, functions);
  const genesisLedgerDigest = digestJson({
    leaseRowId: inventory.control.leaseRowId,
    schemaVersion: 'verification-audit-genesis.v1',
  });
  const environment = {
    ...splitSetupEnvironment({
      site,
      functions,
      setupProjectionDigests,
      browserRequestPolicy: browserPolicy.value.browserRequestPolicy,
    }),
    ...controllerArtifact.environment,
    SOURCE_ARTIFACT_READER_PRIVATE_KEY: sourcePrivateKey,
    APPWRITE_TEST_OPERATOR_API_KEY: 'operator-secret',
    APPWRITE_TEST_FIXTURE_API_KEY: 'fixture-secret',
    E2E_OWNER_EMAIL: 'owner@example.test',
    E2E_OWNER_PASSWORD: 'owner-password',
    E2E_EDITOR_EMAIL: 'editor@example.test',
    E2E_EDITOR_PASSWORD: 'editor-password',
    E2E_VIEWER_EMAIL: 'viewer@example.test',
    E2E_VIEWER_PASSWORD: 'viewer-password',
  };
  const identityResponses = [];
  for (const role of ['editor', 'owner', 'viewer']) {
    const user = identityUser(role);
    identityResponses.push({ total: 1, users: [user] }, user, { total: 0, sessions: [] });
  }
  const providerReadback = JSON.parse(environment.TEST_CLOUD_SETUP_READBACK_JSON);
  const runnerResponse = {
    total: providerReadback.expectedRunnerVariables.total,
    variables: providerReadback.expectedRunnerVariables.variables.map(({ key }, index) => ({
      $id: `variable-${index + 1}`,
      $createdAt: '2026-08-01T00:00:00.000Z',
      $updatedAt: '2026-08-01T00:00:00.000Z',
      key,
      value: runnerVariableValue(key, providerReadback.identityBindings.identityBindingsDigest),
      secret: false,
      resourceType: 'function',
      resourceId: 'verification-runner-py',
    })),
  };
  const functionState = new Map(functions.map((entry) => [
    entry.functionId,
    structuredClone(entry),
  ]));
  let siteState = structuredClone(site);
  const rows = new Map([[
    `${inventory.control.leaseTableId}\0${inventory.control.leaseRowId}`,
    idleProductionLease(genesisLedgerDigest),
  ]]);
  const transactions = new Map();
  let identityResponseIndex = 0;
  let transactionOrdinal = 0;
  let deploymentOrdinal = 0;
  let debtCommittedAt = null;
  let debtHeadAuditReads = 0;
  let debtHeadAuditReadsAfterPortSettle = 0;
  let auditReadsAfterDebtCommit = 0;
  let postDebtProviderMutationCalls = 0;
  const cleanupRunnerCalls = [];
  const sourceHeadSha = mode === 'wrong-source' ? 'f'.repeat(40) : SHA;
  const sourceArchiveUrl =
    'https://productionresultssa2.blob.core.windows.net/actions-results/run/artifact.zip?sig=test';

  const respond = (value, url, status = 200) => new responseHarness.ProviderResponse(value, {
    status,
    url: String(url),
  });
  const respondArchive = (url) => ({
    status: 200,
    headers: new Headers({ 'content-length': String(sourceArchiveBytes.byteLength) }),
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(sourceArchiveBytes);
        controller.close();
      },
    }),
    async arrayBuffer() {
      throw new Error('source archive must use the bounded streaming transport');
    },
    url: String(url),
  });
  const rowKey = (tableId, rowId) => `${tableId}\0${rowId}`;
  const applyOperations = (operations) => {
    for (const operation of operations) {
      const key = rowKey(operation.tableId, operation.rowId);
      const prior = rows.get(key);
      if (operation.action === 'create' && prior === undefined) {
        rows.set(key, structuredClone(operation.data));
      } else if (operation.action === 'upsert') {
        rows.set(key, { ...(prior ?? {}), ...structuredClone(operation.data) });
      } else if (operation.action === 'update' && prior !== undefined) {
        rows.set(key, { ...prior, ...structuredClone(operation.data) });
      } else if (operation.action === 'increment' && prior !== undefined) {
        rows.set(key, {
          ...prior,
          [operation.data.column]: prior[operation.data.column] + operation.data.value,
        });
      } else {
        throw new Error(`unsupported provider operation ${operation.action}`);
      }
    }
  };
  const fetchImpl = async (url, options) => {
    const requestUrl = new URL(String(url));
    const requestPath = requestUrl.pathname.replace(/^\/v1/u, '');
    const method = options?.method ?? 'GET';
    if (String(url) === sourceArchiveUrl) {
      artifactTransportCalls.push({ url: String(url), options });
      if (mode === 'second-source-redirect') {
        return Promise.resolve(new Response(null, {
          status: 302,
          headers: {
            location: 'https://account.blob.core.windows.net/second/artifact.zip?sig=test',
          },
        }));
      }
      return Promise.resolve(respondArchive(url));
    }
    if (requestUrl.origin === 'https://api.github.com') {
      sourceCalls.push({ method, path: requestPath });
      if (method === 'POST' && requestPath === '/app/installations/2/access_tokens') {
        return Promise.resolve(respond({
          token: 'installation-secret',
          permissions: { actions: 'read', metadata: 'read' },
          repositories: [{ id: 3, full_name: 'Krowaccie/AppWriteWork' }],
        }, url, 201));
      }
      if (method === 'GET' && requestPath === '/repos/Krowaccie/AppWriteWork') {
        return Promise.resolve(respond({
          id: 3,
          full_name: 'Krowaccie/AppWriteWork',
        }, url));
      }
      if (
        method === 'GET'
        && requestPath === '/repos/Krowaccie/AppWriteWork/actions/workflows/verify-main.yml'
      ) {
        return Promise.resolve(respond({
          id: 4,
          name: 'Verify Main',
          path: '.github/workflows/verify-main.yml',
        }, url));
      }
      if (
        method === 'GET'
        && requestPath === '/repos/Krowaccie/AppWriteWork/actions/runs/1234'
      ) {
        return Promise.resolve(respond({
          id: 1234,
          workflow_id: 4,
          run_attempt: 1,
          status: 'completed',
          conclusion: 'success',
          event: 'push',
          head_branch: 'main',
          head_sha: sourceHeadSha,
          head_repository: { full_name: 'Krowaccie/AppWriteWork' },
        }, url));
      }
      if (
        method === 'GET'
        && requestPath === '/repos/Krowaccie/AppWriteWork/actions/runs/1234/artifacts'
      ) {
        return Promise.resolve(respond({
          artifacts: [{
            id: 5678,
            name: `verification-artifacts-${SHA}`,
            expired: false,
            digest: sourceArchiveDigest,
            size_in_bytes: sourceArchiveBytes.byteLength,
          }],
        }, url));
      }
      if (
        method === 'GET'
        && requestPath === '/repos/Krowaccie/AppWriteWork/actions/artifacts/5678/zip'
      ) {
        artifactTransportCalls.push({ url: String(url), options });
        if (mode === 'hostile-source-error') {
          const hostile = {};
          Object.defineProperty(hostile, 'code', {
            get() { throw new Error('hostile error code accessor'); },
          });
          return Promise.reject(hostile);
        }
        return Promise.resolve({
          status: 302,
          headers: new Headers({
            location: mode === 'unsafe-source-redirect'
              ? 'https://example.invalid/artifact.zip?sig=test'
              : mode === 'default-port-source-redirect'
                ? 'https://productionresultssa2.blob.core.windows.net:443/actions-results/run/artifact.zip?sig=test'
              : sourceArchiveUrl,
          }),
        });
      }
      if (method === 'DELETE' && requestPath === '/installation/token') {
        return Promise.resolve(respond(null, url, 204));
      }
      return Promise.reject(new Error(`unexpected source request ${method} ${requestPath}`));
    }
    providerCalls.push({ url: String(url), options });
    if (debtCommittedAt !== null && method !== 'GET') postDebtProviderMutationCalls += 1;

    if (method === 'GET' && requestPath.startsWith('/users/')) {
      const value = identityResponses[identityResponseIndex];
      identityResponseIndex += 1;
      return Promise.resolve(respond(value, url));
    }
    if (method === 'GET' && requestPath === '/users') {
      const value = identityResponses[identityResponseIndex];
      identityResponseIndex += 1;
      return Promise.resolve(respond(value, url));
    }
    if (method === 'GET' && requestPath === '/functions/verification-runner-py/variables') {
      return Promise.resolve(respond(runnerResponse, url));
    }
    if (method === 'GET' && String(url) === `${inventory.environment.publicOrigin}/build-identity.json`) {
      const publicIdentity = mode === 'vcs-site-identity'
        ? Object.freeze({
          schemaVersion: 1,
          identityKind: 'git-revision',
          candidateRevision: artifactSet.artifactManifest.sourceRevision,
          candidateSourceTreeDigest: artifactSet.artifactManifest.sourceTreeDigest,
          verificationManifestDigest: artifactSet.artifactManifest.verifierManifestDigest,
          contentDigest: `sha256:${'8'.repeat(64)}`,
        })
        : artifactSet.buildIdentity;
      return Promise.resolve(respond(publicIdentity, url));
    }
    if (requestPath === `/sites/${inventory.environment.siteId}` && method === 'GET') {
      return Promise.resolve(respond(providerSiteResponse(siteState), url));
    }
    if (requestPath === `/sites/${inventory.environment.siteId}/deployments` && method === 'POST') {
      deploymentOrdinal += 1;
      const deploymentId = `site-deployment-${deploymentOrdinal}`;
      return Promise.resolve(respond({ $id: deploymentId, status: 'ready' }, url, 202));
    }
    const siteDeployment = new RegExp(
      `^/sites/${inventory.environment.siteId}/deployments/([^/]+)$`,
      'u',
    ).exec(requestPath);
    if (siteDeployment !== null && method === 'GET') {
      return Promise.resolve(respond({ $id: siteDeployment[1], status: 'ready' }, url));
    }
    if (requestPath === `/sites/${inventory.environment.siteId}/deployment` && method === 'PATCH') {
      const { deploymentId } = JSON.parse(options.body);
      siteState = { ...siteState, activeDeploymentId: deploymentId };
      return Promise.resolve(respond({
        $id: inventory.environment.siteId,
        deploymentId,
      }, url));
    }

    const functionDeployment = /^\/functions\/([^/]+)\/deployments\/([^/]+)$/u.exec(requestPath);
    if (functionDeployment !== null && method === 'GET') {
      return Promise.resolve(respond({ $id: functionDeployment[2], status: 'ready' }, url));
    }
    const functionDeployments = /^\/functions\/([^/]+)\/deployments$/u.exec(requestPath);
    if (functionDeployments !== null && method === 'POST') {
      deploymentOrdinal += 1;
      const deploymentId = `function-deployment-${deploymentOrdinal}`;
      return Promise.resolve(respond({ $id: deploymentId, status: 'ready' }, url, 202));
    }
    const functionActivation = /^\/functions\/([^/]+)\/deployment$/u.exec(requestPath);
    if (functionActivation !== null && method === 'PATCH') {
      const entry = functionState.get(functionActivation[1]);
      const { deploymentId } = JSON.parse(options.body);
      entry.activeDeploymentId = deploymentId;
      return Promise.resolve(respond(providerFunctionResponse(entry), url));
    }
    const functionRead = /^\/functions\/([^/]+)$/u.exec(requestPath);
    if (functionRead !== null && method === 'GET') {
      return Promise.resolve(respond(providerFunctionResponse(functionState.get(functionRead[1])), url));
    }
    if (requestPath === '/functions/verification-runner-py/executions' && method === 'POST') {
      const wire = JSON.parse(options.body);
      const request = JSON.parse(wire.body);
      const cleanupRequest = request.scenarioId.startsWith('resource.cleanup');
      if (!cleanupRequest) {
        simulateProductionRunnerControlWrites({ request, rows, rowKey });
      }
      const responseData = cleanupRequest ? productionCleanupRunnerData(request) : {
        logicalWorkflow: 'hello-world-no-cost',
        inputProfile: 'verification-minimal',
        outcome: 'completed-no-cost',
        outputDigest: productionWorkerOutputDigest(request),
      };
      const responseBody = canonicalJson({
        protocolVersion: 'verification-runner.v1',
        scenarioId: request.scenarioId,
        runId: request.runId,
        status: 'passed',
        durationMs: 1,
        data: responseData,
      });
      if (cleanupRequest) {
        cleanupRunnerCalls.push({
          logicalResource: request.parameters.logicalResource,
          logicalPosition: request.cleanupFence.cleanupRunnerExecutionCursor,
          scenarioId: request.scenarioId,
          leaseVersion: request.cleanupFence.leaseVersion,
          ledgerDigest: request.cleanupFence.ledgerDigest,
        });
      }
      return Promise.resolve(respond({
        $id: cleanupRequest ? `cleanup-execution-${cleanupRunnerCalls.length}` : 'execution-1',
        status: 'completed',
        responseStatusCode: 200,
        responseBody,
      }, url, 201));
    }

    const rowMatch = /^\/tablesdb\/([^/]+)\/tables\/([^/]+)\/rows\/([^/]+)$/u.exec(requestPath);
    if (rowMatch !== null && method === 'GET') {
      const rowId = decodeURIComponent(rowMatch[3]);
      const value = rows.get(rowKey(rowMatch[2], rowId));
      const currentLease = rows.get(rowKey(
        inventory.control.leaseTableId,
        inventory.control.leaseRowId,
      ));
      if (
        rowMatch[2] === inventory.control.auditTableId
        && currentLease?.state === 'cleanup-debt'
      ) auditReadsAfterDebtCommit += 1;
      if (
        rowMatch[2] === inventory.control.auditTableId
        && currentLease?.state === 'cleanup-debt'
        && value?.transition === 'lease.cleanup_debt'
        && value?.runId === currentLease.ownerRunId
      ) {
        debtHeadAuditReads += 1;
        if (browserTransport?.state.calls.some(([name]) => name === 'browserClose')) {
          debtHeadAuditReadsAfterPortSettle += 1;
        }
      }
      return Promise.resolve(value === undefined
        ? respond({}, url, 404)
        : respond({ $id: rowId, ...structuredClone(value) }, url));
    }
    if (requestPath === '/tablesdb/transactions' && method === 'POST') {
      transactionOrdinal += 1;
      const transactionId = `transaction-${transactionOrdinal}`;
      transactions.set(transactionId, { operations: [], status: 'pending' });
      return Promise.resolve(respond({ $id: transactionId, status: 'pending' }, url, 201));
    }
    const transactionOperations = /^\/tablesdb\/transactions\/([^/]+)\/operations$/u.exec(requestPath);
    if (transactionOperations !== null && method === 'POST') {
      const transaction = transactions.get(transactionOperations[1]);
      transaction.operations = JSON.parse(options.body).operations;
      return Promise.resolve(respond({
        $id: transactionOperations[1],
        status: 'pending',
      }, url, 201));
    }
    const transaction = /^\/tablesdb\/transactions\/([^/]+)$/u.exec(requestPath);
    if (transaction !== null && method === 'PATCH') {
      const record = transactions.get(transaction[1]);
      applyOperations(record.operations);
      record.status = 'committed';
      const currentLease = rows.get(rowKey(
        inventory.control.leaseTableId,
        inventory.control.leaseRowId,
      ));
      if (debtCommittedAt === null && currentLease?.state === 'cleanup-debt') {
        debtCommittedAt = transactionOrdinal;
      }
      return Promise.resolve(respond({ $id: transaction[1], status: 'committed' }, url));
    }
    if (transaction !== null && method === 'GET') {
      const record = transactions.get(transaction[1]);
      return Promise.resolve(respond({
        $id: transaction[1],
        status: record?.status ?? 'unknown',
      }, url));
    }
    return Promise.reject(new Error(`unexpected provider request ${method} ${requestPath}`));
  };
  globalThis.fetch = fetchImpl;
  const browserTransport = mode === 'success' || mode === 'physical-create-failure'
    ? await installTask8SyntheticBrowserTransport(providerReadback, {
      interruptAfterPhysicalCreateOrdinal: mode === 'physical-create-failure' ? 0 : null,
    })
    : null;
  const { main } = await import('./test-cloud-controller.mjs');
  const runMain = async (candidateEnvironment) => {
    let stdout = '';
    let stderr = '';
    const exitCode = await main([
      '--hosted',
      '--revision', SHA,
      '--source-run-id', '1234',
      '--source-run-attempt', '1',
    ], {
      environment: candidateEnvironment,
      fetchImpl,
      controllerArtifactIo: controllerArtifact.io,
      async runContainedProcessImpl(options) {
        processCalls.push(options);
        if (options.args[0] === '--eval') {
          return Object.freeze({
            status: 'exited',
            exitCode: 0,
            signal: null,
            stdout: 'APPWRITEWORK_WINDOWS_JOB_OBJECT_QUALIFIED',
            stderr: '',
          });
        }
        const scenarioIndex = options.args.indexOf('--scenario-id');
        const scenarioId = options.args[scenarioIndex + 1];
        return Object.freeze({
          status: 'exited',
          exitCode: 0,
          signal: null,
          stdout: JSON.stringify({
            schemaVersion: 'test-cloud-playwright-scenario-result.v1',
            scenarioId,
            status: mode === 'success' ? 'PASS' : 'FAIL',
          }),
          stderr: '',
        });
      },
      stdout: { write(value) { stdout += value; } },
      stderr: { write(value) { stderr += value; } },
    });
    return { exitCode, stdout, stderr };
  };
  try {
    const candidateEnvironment = mode === 'wrong-reattestation'
      ? Object.freeze({ ...environment, PROOF_SHA: 'f'.repeat(40) })
      : environment;
    const outcome = await runMain(candidateEnvironment);
    return {
      ...outcome,
      processCalls: processCalls.map(({ args }) => ({ args })),
      providerCalls: providerCalls.map(({ url, options }) => ({
        method: options?.method,
        url,
      })),
      sourceCalls,
      artifactTransportCalls: artifactTransportCalls.map(({ url, options }) => ({
        url,
        method: options?.method,
        redirect: options?.redirect,
        authorization: options?.headers?.Authorization,
        accept: options?.headers?.Accept,
      })),
      browserTransport: browserTransport === null ? null : {
        injectedLaunches: browserTransport.state.calls.filter(
          ([name]) => name === 'injectedTransportLaunch',
        ).length,
        syntheticLaunches: browserTransport.state.calls.filter(
          ([name]) => name === 'launch',
        ).length,
        fulfilledMutations: browserTransport.state.calls.filter(
          ([name]) => name === 'fulfillResponse',
        ).length,
        realLaunches: browserTransport.state.realLaunches,
        activeRoutes: browserTransport.state.routeDeliveries.size,
        pageCloses: browserTransport.state.calls.filter(([name]) => name === 'pageClose').length,
        contextCloses: browserTransport.state.calls.filter(
          ([name]) => name === 'contextClose',
        ).length,
        browserCloses: browserTransport.state.calls.filter(
          ([name]) => name === 'browserClose',
        ).length,
        ...(mode === 'physical-create-failure' ? {
          physicalCreateInterruptions: browserTransport.state.physicalCreateInterruptions,
          producerObservations: structuredClone(browserTransport.state.producerObservations),
        } : {}),
      },
      control: {
        currentLease: structuredClone(rows.get(rowKey(
          inventory.control.leaseTableId,
          inventory.control.leaseRowId,
        ))),
        currentDebtEvent: structuredClone([...rows.values()].find(
          (row) => row?.transition === 'lease.cleanup_debt',
        )),
        currentCloseEvent: structuredClone([...rows.values()].find(
          (row) => row?.transition === 'lease.close',
        )),
        cleanupRunnerCalls: structuredClone(cleanupRunnerCalls),
        debtCommittedAt,
        debtHeadAuditReads,
        debtHeadAuditReadsAfterPortSettle,
        auditReadsAfterDebtCommit,
        postDebtProviderMutationCalls,
        transactionsAfterDebt: debtCommittedAt === null
          ? null
          : transactionOrdinal - debtCommittedAt,
      },
    };
  } finally {
    browserTransport?.restore();
    globalThis.fetch = previousFetch;
    responseHarness.restore();
  }
}

function runProductionCompositionWorker(mode) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), {
      execArgv: [],
      workerData: { protocol: PRODUCTION_COMPOSITION_WORKER_PROTOCOL, mode },
    });
    worker.once('message', (message) => {
      if (message?.status === 'PASS') resolve(message.value);
      else reject(new Error(message?.error ?? 'Production composition worker failed.'));
    });
    worker.once('error', reject);
    worker.once('exit', (code) => {
      if (code !== 0) reject(new Error(`Production composition worker exited ${code}.`));
    });
  });
}

async function ordinaryLaneTerminalOutcome() {
  const {
    composeProductionTestCloudLane,
    createProductionHostedDependencies,
  } = await import('./test-cloud-controller.mjs');
  const harness = controllerHarness();
  const processCalls = [];
  let networkCalls = 0;
  const dependencies = createProductionHostedDependencies({
    environment: Object.freeze({}),
    async fetchImpl() {
      networkCalls += 1;
      throw new Error('network must remain inert');
    },
    async runContainedProcessImpl(options) {
      processCalls.push(options);
      if (options.args[0] === '--eval') {
        return Object.freeze({
          status: 'exited',
          exitCode: 0,
          signal: null,
          stdout: 'APPWRITEWORK_WINDOWS_JOB_OBJECT_QUALIFIED',
          stderr: '',
        });
      }
      const scenarioIndex = options.args.indexOf('--scenario-id');
      const scenarioId = options.args[scenarioIndex + 1];
      return Object.freeze({
        status: 'exited',
        exitCode: 0,
        signal: null,
        stdout: JSON.stringify(Object.freeze(Object.assign(Object.create(null), {
          schemaVersion: 'test-cloud-playwright-scenario-result.v1',
          scenarioId,
          status: 'FAIL',
        }))),
        stderr: '',
      });
    },
  });
  const containment = await dependencies.qualifyContainment();
  const createdFacade = await dependencies.createPlaywrightFacade();
  const realLane = containment.status === 'PASS' && createdFacade.status === 'PASS'
    ? await dependencies.createOrdinaryLane({
      artifactSet: validatedHostedSnapshot(),
      controller: trustedController(),
      credentials: Object.freeze(Object.fromEntries(
        HOSTED_SECRET_NAMES
          .filter((name) => name !== 'SOURCE_ARTIFACT_READER_PRIVATE_KEY')
          .map((name) => [name, `value:${name}`]),
      )),
      facade: createdFacade.value,
      runtime: Object.freeze({ runtimeQualification: Object.freeze(Object.create(null)) }),
      setup: Object.freeze({}),
    })
    : Object.freeze({ status: 'BLOCKED' });
  const providerTransport = (value) => async () => pass(value);
  const composed = composeProductionTestCloudLane({
    artifactSet: harness.artifactSet,
    clock: Object.freeze({ now: () => '2026-07-20T10:00:00.000Z' }),
    controller: trustedController(),
    evidenceWriter: Object.freeze({
      write: async () => pass(Object.freeze({
        path: '.verification/results/test-cloud-result.json',
        evidenceDigest: EVIDENCE_DIGEST,
      })),
    }),
    facade: Object.freeze({
      facade: createdFacade.value.facade,
      scenarioIds: testCloudScenarioInventory,
      scenarioInventoryDigest: testCloudScenarioInventoryDigest,
    }),
    operations: Object.freeze({
      preflight: providerTransport(Object.freeze({ attested: true })),
      acquireLease: providerTransport(Object.freeze({
        lease: 'lease-1', capability: 'capability-1',
      })),
      deployFunctionArtifacts: providerTransport(harness.functionDeployments),
      deploySiteArtifact: providerTransport(harness.siteDeployment),
      qualifyRunner: providerTransport(Object.freeze({ qualified: true })),
      runTrustedScenario: providerTransport(Object.freeze({
        lease: 'lease-2', capability: 'capability-2',
      })),
      runTrustedFixtureIntentProducer: providerTransport(Object.freeze({
        lease: 'lease-2',
        capability: 'capability-2',
        intents: Object.freeze([
          Object.freeze({
            schemaVersion: 'verification-intent-snapshot.v2',
            resourceType: 'primary-project',
            state: 'created',
          }),
          Object.freeze({
            schemaVersion: 'verification-intent-snapshot.v2',
            resourceType: 'primary-graph',
            state: 'created',
          }),
          Object.freeze({
            schemaVersion: 'verification-intent-snapshot.v2',
            resourceType: 'primary-share',
            state: 'created',
          }),
        ]),
      })),
      cleanup: providerTransport(Object.freeze({
        lease: 'lease-2', capability: 'capability-2', intents: Object.freeze([]),
      })),
    }),
    selection: sourceSelection(),
  });
  const run = composed.status === 'PASS'
    ? await dependencies.runLane({ lane: composed.value })
    : composed;
  return Object.freeze({
    containmentStatus: containment.status,
    facadeStatus: createdFacade.status,
    laneStatus: realLane.status,
    compositionStatus: composed.status,
    runStatus: run.status,
    runCode: run.diagnostics?.[0]?.code,
    networkCalls,
    processCalls: processCalls.map((call) => Object.freeze({
      args: [...call.args],
      cwd: call.cwd,
      envKeys: Object.keys(call.env),
      executable: call.executable,
      maxOutputBytes: call.maxOutputBytes,
      timeoutMs: call.timeoutMs,
    })),
  });
}

function runOrdinaryLaneTerminalWorker() {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), {
      execArgv: [],
      workerData: { protocol: ORDINARY_LANE_WORKER_PROTOCOL },
    });
    worker.once('message', (message) => {
      if (message?.status === 'PASS') resolve(message.value);
      else reject(new Error(message?.error ?? 'Ordinary lane worker failed.'));
    });
    worker.once('error', reject);
    worker.once('exit', (code) => {
      if (code !== 0) reject(new Error(`Ordinary lane worker exited ${code}.`));
    });
  });
}

test('Task 9 vertical: real hosted composition atomically cleans the exact Task 8 fixture state before PASS', async () => {
  const wrongReattestation = await runProductionCompositionWorker('wrong-reattestation');
  assert.deepEqual({
    exitCode: wrongReattestation.exitCode,
    stdout: wrongReattestation.stdout,
    stderr: wrongReattestation.stderr,
  }, {
    exitCode: 2,
    stdout: '',
    stderr: 'BLOCKED TRUSTED_CONTROLLER_REQUIRED\n',
  });
  assert.equal(wrongReattestation.processCalls.length, 0);
  assert.equal(wrongReattestation.sourceCalls.length, 0);
  assert.equal(wrongReattestation.providerCalls.length, 0);

  const wrongSource = await runProductionCompositionWorker('wrong-source');
  assert.deepEqual({
    exitCode: wrongSource.exitCode,
    stdout: wrongSource.stdout,
    stderr: wrongSource.stderr,
  }, {
    exitCode: 2,
    stdout: '',
    stderr: 'BLOCKED SOURCE_RUN_IDENTITY_MISMATCH\n',
  }, JSON.stringify(wrongSource));
  assert.equal(wrongSource.processCalls.length, 1);
  assert.equal(wrongSource.providerCalls.length, 0);

  for (const mode of [
    'unsafe-source-redirect',
    'default-port-source-redirect',
    'hostile-source-error',
    'second-source-redirect',
  ]) {
    const rejectedRedirect = await runProductionCompositionWorker(mode);
    assert.deepEqual({
      exitCode: rejectedRedirect.exitCode,
      stdout: rejectedRedirect.stdout,
      stderr: rejectedRedirect.stderr,
    }, {
      exitCode: 2,
      stdout: '',
      stderr: 'BLOCKED SOURCE_ARTIFACT_DOWNLOAD_FAILED\n',
    }, JSON.stringify(rejectedRedirect));
    assert.equal(rejectedRedirect.providerCalls.length, 0);
  }

  const outcome = await runProductionCompositionWorker('success');
  assert.equal(outcome.exitCode, 0, JSON.stringify({
    exitCode: outcome.exitCode,
    stderr: outcome.stderr,
    cleanupEntry: outcome.control.cleanupRunnerCalls[0],
    cleanupFinal: outcome.control.cleanupRunnerCalls.at(-1),
    idleLeaseVersion: outcome.control.currentLease.leaseVersion,
    idleLedgerDigest: outcome.control.currentLease.ledgerDigest,
    closeEvent: outcome.control.currentCloseEvent,
  }));
  assert.equal(outcome.stdout, 'PASS\n');
  assert.equal(outcome.stderr, '');
  assert.equal(outcome.providerCalls.length > 0, true);
  assert.equal(outcome.processCalls.length, 4, JSON.stringify(outcome));
  assert.deepEqual(outcome.browserTransport, {
    injectedLaunches: 1,
    syntheticLaunches: 1,
    fulfilledMutations: 19,
    realLaunches: 0,
    activeRoutes: 0,
    pageCloses: 0,
    contextCloses: 0,
    browserCloses: 0,
  });
  assert.equal(outcome.control.cleanupRunnerCalls.length, 131);
  assert.deepEqual(
    [...new Set(outcome.control.cleanupRunnerCalls.map(({ logicalResource }) => logicalResource))],
    ['primary-share', 'primary-graph', 'primary-project'],
  );
  assert.deepEqual(Object.keys(outcome.control.currentLease).sort(), [
    'acquiredAt', 'cleanupDebt', 'environmentDigest', 'expiresAt', 'leaseRowId',
    'leaseTokenDigest', 'leaseVersion', 'ledgerDigest', 'ownerRunId',
    'ownerWorkflowRunId', 'renewedAt', 'state',
  ]);
  assert.deepEqual({
    leaseRowId: outcome.control.currentLease.leaseRowId,
    state: outcome.control.currentLease.state,
    ownerRunId: outcome.control.currentLease.ownerRunId,
    ownerWorkflowRunId: outcome.control.currentLease.ownerWorkflowRunId,
    environmentDigest: outcome.control.currentLease.environmentDigest,
    acquiredAt: outcome.control.currentLease.acquiredAt,
    renewedAt: outcome.control.currentLease.renewedAt,
    expiresAt: outcome.control.currentLease.expiresAt,
    leaseTokenDigest: outcome.control.currentLease.leaseTokenDigest,
    cleanupDebt: outcome.control.currentLease.cleanupDebt,
  }, {
    leaseRowId: inventory.control.leaseRowId,
    state: 'idle',
    ownerRunId: null,
    ownerWorkflowRunId: null,
    environmentDigest: null,
    acquiredAt: null,
    renewedAt: null,
    expiresAt: null,
    leaseTokenDigest: null,
    cleanupDebt: false,
  });
  assert.deepEqual(outcome.control.currentCloseEvent, {
    schemaVersion: 'verification-audit-event.v1',
    previousLedgerDigest: outcome.control.currentCloseEvent.previousLedgerDigest,
    runId: `verify-${SHA.slice(0, 12)}-1234-1`,
    leaseVersionBefore: outcome.control.currentLease.leaseVersion - 1,
    leaseVersionAfter: outcome.control.currentLease.leaseVersion,
    transition: 'lease.close',
    intentId: null,
    intentProjectionDigest: null,
  });
  assert.equal(
    outcome.control.currentLease.ledgerDigest,
    digestJson(outcome.control.currentCloseEvent),
  );
  assert.equal(
    outcome.processCalls[1].args[0],
    'packages/verification-controller/src/test-cloud-contained-scenario-launcher.mjs',
  );
  assert.deepEqual(
    outcome.sourceCalls.map(({ method, path: requestPath }) => `${method} ${requestPath}`),
    [
      'POST /app/installations/2/access_tokens',
      'GET /repos/Krowaccie/AppWriteWork',
      'GET /repos/Krowaccie/AppWriteWork/actions/workflows/verify-main.yml',
      'GET /repos/Krowaccie/AppWriteWork/actions/runs/1234',
      'GET /repos/Krowaccie/AppWriteWork/actions/runs/1234/artifacts',
      'GET /repos/Krowaccie/AppWriteWork/actions/artifacts/5678/zip',
      'DELETE /installation/token',
    ],
  );
  assert.deepEqual(outcome.artifactTransportCalls, [
    {
      url: 'https://api.github.com/repos/Krowaccie/AppWriteWork/actions/artifacts/5678/zip',
      method: 'GET',
      redirect: 'manual',
      authorization: 'Bearer installation-secret',
      accept: 'application/vnd.github+json',
    },
    {
      url: 'https://productionresultssa2.blob.core.windows.net/actions-results/run/artifact.zip?sig=test',
      method: 'GET',
      redirect: 'error',
      authorization: undefined,
      accept: 'application/octet-stream',
    },
  ]);

  const vcsIdentityOutcome = await runProductionCompositionWorker('vcs-site-identity');
  assert.deepEqual({
    exitCode: vcsIdentityOutcome.exitCode,
    stdout: vcsIdentityOutcome.stdout,
    stderr: vcsIdentityOutcome.stderr,
  }, {
    exitCode: 2,
    stdout: '',
    stderr: 'BLOCKED CLEANUP_DEBT\n',
  }, JSON.stringify(vcsIdentityOutcome));
  assert.equal(vcsIdentityOutcome.processCalls.length, 1, JSON.stringify(vcsIdentityOutcome));
  assert.equal(vcsIdentityOutcome.browserTransport, null);
});

test('Task 8 authentic physical-create failure retains only the durable cleanup-debt head and settles every port', async () => {
  const outcome = await runProductionCompositionWorker('physical-create-failure');

  assert.deepEqual({
    exitCode: outcome.exitCode,
    stdout: outcome.stdout,
    stderr: outcome.stderr,
  }, {
    exitCode: 2,
    stdout: '',
    stderr: 'BLOCKED CLEANUP_DEBT\n',
  }, JSON.stringify(outcome));
  assert.equal(outcome.control.currentLease.state, 'cleanup-debt');
  assert.equal(outcome.control.currentLease.cleanupDebt, true);
  assert.equal(outcome.control.debtCommittedAt > 0, true);
  assert.equal(outcome.control.debtHeadAuditReads >= 2, true, JSON.stringify(outcome));
  assert.equal(outcome.control.debtHeadAuditReadsAfterPortSettle >= 2, true, JSON.stringify(outcome));
  assert.equal(
    outcome.control.auditReadsAfterDebtCommit >= outcome.control.currentLease.leaseVersion,
    true,
    JSON.stringify(outcome),
  );
  assert.equal(outcome.control.transactionsAfterDebt, 0);
  assert.equal(outcome.control.postDebtProviderMutationCalls, 0);
  assert.deepEqual(outcome.browserTransport, {
    injectedLaunches: 1,
    syntheticLaunches: 1,
    fulfilledMutations: 0,
    realLaunches: 0,
    activeRoutes: 0,
    pageCloses: 1,
    contextCloses: 1,
    browserCloses: 1,
    physicalCreateInterruptions: 1,
    producerObservations: [{
      status: 'BLOCKED',
      capabilityIsNull: true,
      cleanupDebt: true,
      leaseVersion: outcome.control.currentLease.leaseVersion,
      ledgerDigest: outcome.control.currentLease.ledgerDigest,
      state: 'cleanup-debt',
    }],
  });
});

test('test-cloud controller module exposes only the closed orchestration and binding entrypoints', async () => {
  const modulePath = pathToFileURL(path.join(
    root,
    'packages',
    'verification-controller',
    'src',
    'test-cloud-controller.mjs',
  )).href;
  const controller = await import(modulePath);
  assert.deepEqual(Object.keys(controller).sort(), [
    'composeProductionTestCloudLane',
    'createProductionHostedDependencies',
    'main',
    'readExactBindingDirectory',
    'runHostedTestCloudController',
    'runTestCloudController',
    'validateArtifactSetOutput',
  ]);
});

test('production composition reaches the static child only through the contained-process transport', async () => {
  const isolated = await runOrdinaryLaneTerminalWorker();
  assert.deepEqual({
    containmentStatus: isolated.containmentStatus,
    facadeStatus: isolated.facadeStatus,
    laneStatus: isolated.laneStatus,
    compositionStatus: isolated.compositionStatus,
    runStatus: isolated.runStatus,
    runCode: isolated.runCode,
    networkCalls: isolated.networkCalls,
  }, {
    containmentStatus: 'PASS',
    facadeStatus: 'PASS',
    laneStatus: 'BLOCKED',
    compositionStatus: 'PASS',
    runStatus: 'BLOCKED',
    runCode: 'CLEANUP_DEBT',
    networkCalls: 0,
  });
  assert.equal(isolated.processCalls.length, 2);
  const childCall = isolated.processCalls[1];
  assert.equal(childCall.executable, process.execPath);
  assert.equal(path.resolve(childCall.cwd), root);
  assert.equal(childCall.timeoutMs, 300_000);
  assert.equal(childCall.maxOutputBytes, 69_632);
  assert.equal(
    childCall.args[0],
    'packages/verification-controller/src/test-cloud-contained-scenario-launcher.mjs',
  );
  assert.deepEqual(childCall.args.slice(1), [
    '--scenario-id', 'public-smoke',
    '--controller-revision', SHA,
    '--controller-bundle-digest', DIGEST,
    '--playwright-image-digest',
    'sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48',
    '--scenario-inventory-digest', testCloudScenarioInventoryDigest,
  ]);
  assert.deepEqual(childCall.envKeys, []);
});

test('Task 8 vertical RED: production composition requires authentic fixtures and keeps mutation scenarios out of the generic facade', async () => {
  const { composeProductionTestCloudLane } = await import('./test-cloud-controller.mjs');
  const harness = controllerHarness();
  const genericScenarioCalls = [];
  const producerCalls = [];
  const createdIntents = Object.freeze([
    Object.freeze({
      schemaVersion: 'verification-intent-snapshot.v2',
      resourceType: 'primary-project',
      state: 'created',
    }),
    Object.freeze({
      schemaVersion: 'verification-intent-snapshot.v2',
      resourceType: 'primary-graph',
      state: 'created',
    }),
    Object.freeze({
      schemaVersion: 'verification-intent-snapshot.v2',
      resourceType: 'primary-share',
      state: 'created',
    }),
  ]);
  const composed = composeProductionTestCloudLane({
    artifactSet: harness.artifactSet,
    clock: Object.freeze({ now: () => '2026-07-20T10:00:00.000Z' }),
    controller: trustedController(),
    evidenceWriter: Object.freeze({ write: async () => pass({}) }),
    facade: Object.freeze({
      facade: Object.freeze({
        async runExactScenario(request) {
          genericScenarioCalls.push(request.scenarioId);
          return pass({ passed: true });
        },
      }),
      scenarioIds: testCloudScenarioInventory,
      scenarioInventoryDigest: testCloudScenarioInventoryDigest,
    }),
    operations: Object.freeze({
      preflight: async () => pass({}),
      acquireLease: async () => pass({}),
      deployFunctionArtifacts: async () => pass({}),
      deploySiteArtifact: async () => pass({}),
      qualifyRunner: async () => pass({}),
      runTrustedScenario: async () => pass(Object.freeze({
        lease: 'trusted-lease',
        capability: 'trusted-capability',
      })),
      async runTrustedFixtureIntentProducer(request) {
        producerCalls.push(request);
        return pass(Object.freeze({
          lease: 'fixture-lease',
          capability: 'fixture-capability',
          intents: createdIntents,
        }));
      },
      cleanup: async () => pass({}),
    }),
    selection: sourceSelection(),
  });

  assert.equal(composed.status, 'PASS', JSON.stringify(composed));
  const outcome = await composed.value.clients.runE2E(Object.freeze({
    lease: 'lane-lease',
    capability: 'lane-capability',
  }));
  assert.deepEqual(outcome, pass(Object.freeze({
    lease: 'fixture-lease',
    capability: 'fixture-capability',
    passed: true,
  })));
  assert.equal(producerCalls.length, 1);
  assert.deepEqual(producerCalls[0], Object.freeze({
    lease: 'trusted-lease',
    capability: 'trusted-capability',
  }));
  assert.deepEqual(genericScenarioCalls, ['public-smoke', 'auth', 'runtime']);
});

test('Task 8 cleanup-debt failure handoff accepts only the frozen exact successor with null capability', async (t) => {
  const { composeProductionTestCloudLane } = await import('./test-cloud-controller.mjs');
  const acquired = task8ActiveLease();
  const debt = task8CleanupDebtLease(acquired);
  const malformed = { ...debt };
  delete malformed.leaseTokenDigest;
  const vectors = [
    ['exact debt', frozenNullRecord([['lease', debt], ['capability', null]]), debt],
    ['active', frozenNullRecord([['lease', acquired], ['capability', null]]), null],
    ['foreign run', frozenNullRecord([[
      'lease', task8CleanupDebtLease(acquired, { ownerRunId: 'verify-ffffffffffff-1234-1' }),
    ], ['capability', null]]), null],
    ['foreign environment', frozenNullRecord([[
      'lease', task8CleanupDebtLease(acquired, { environmentDigest: `sha256:${'f'.repeat(64)}` }),
    ], ['capability', null]]), null],
    ['stale debt', frozenNullRecord([[
      'lease', task8CleanupDebtLease(acquired, { leaseVersion: acquired.leaseVersion }),
    ], ['capability', null]]), null],
    ['copied unfrozen debt', frozenNullRecord([
      ['lease', structuredClone(debt)], ['capability', null],
    ]), null],
    ['malformed debt', frozenNullRecord([
      ['lease', Object.freeze(malformed)], ['capability', null],
    ]), null],
    ['open failure value', Object.freeze({ lease: debt, capability: null, extra: true }), null],
  ];

  for (const [name, failureValue, expectedLease] of vectors) {
    await t.test(name, async () => {
      const harness = controllerHarness();
      const operation = async () => pass(Object.freeze({}));
      const composed = composeProductionTestCloudLane({
        artifactSet: harness.artifactSet,
        clock: Object.freeze({ now: () => '2026-07-20T10:00:00.000Z' }),
        controller: trustedController(),
        evidenceWriter: Object.freeze({ write: operation }),
        facade: Object.freeze({
          facade: Object.freeze({ runExactScenario: operation }),
          scenarioIds: testCloudScenarioInventory,
          scenarioInventoryDigest: testCloudScenarioInventoryDigest,
        }),
        operations: Object.freeze({
          preflight: operation,
          acquireLease: operation,
          deployFunctionArtifacts: operation,
          deploySiteArtifact: operation,
          qualifyRunner: operation,
          runTrustedScenario: async () => pass(Object.freeze({
            lease: acquired,
            capability: Object.freeze(Object.create(null)),
          })),
          runTrustedFixtureIntentProducer: async () => Object.freeze({
            status: 'BLOCKED',
            value: failureValue,
            diagnostics: Object.freeze([]),
          }),
          cleanup: operation,
        }),
        selection: sourceSelection(),
      });
      assert.equal(composed.status, 'PASS');

      const outcome = await composed.value.clients.runE2E(Object.freeze({
        lease: acquired,
        capability: Object.freeze(Object.create(null)),
      }));
      assert.equal(outcome.status, 'BLOCKED');
      if (expectedLease === null) {
        assert.equal(outcome.value, null, name);
      } else {
        assert.equal(outcome.value.lease, expectedLease);
        assert.equal(outcome.value.capability, null);
        assert.equal(Object.isFrozen(outcome.value), true);
      }
    });
  }
});

test('Task 8 outer hosted boundary remains non-PASS for a missing producer and an empty created-intent set', async () => {
  const {
    composeProductionTestCloudLane,
    runHostedTestCloudController,
  } = await import('./test-cloud-controller.mjs');
  const harness = controllerHarness();
  const operation = async () => pass(Object.freeze({}));
  const baseOperations = {
    preflight: operation,
    acquireLease: operation,
    deployFunctionArtifacts: operation,
    deploySiteArtifact: operation,
    qualifyRunner: operation,
    runTrustedScenario: async () => pass(Object.freeze({
      lease: 'trusted-lease', capability: 'trusted-capability',
    })),
    runTrustedFixtureIntentProducer: async () => pass(Object.freeze({
      lease: 'fixture-lease', capability: 'fixture-capability', intents: Object.freeze([]),
    })),
    cleanup: operation,
  };
  const compose = (operations) => composeProductionTestCloudLane({
    artifactSet: harness.artifactSet,
    clock: Object.freeze({ now: () => '2026-07-20T10:00:00.000Z' }),
    controller: trustedController(),
    evidenceWriter: Object.freeze({ write: operation }),
    facade: Object.freeze({
      facade: Object.freeze({ runExactScenario: operation }),
      scenarioIds: testCloudScenarioInventory,
      scenarioInventoryDigest: testCloudScenarioInventoryDigest,
    }),
    operations: Object.freeze(operations),
    selection: sourceSelection(),
  });

  const missingOperations = { ...baseOperations };
  delete missingOperations.runTrustedFixtureIntentProducer;
  const missing = compose(missingOperations);
  assert.equal(missing.status, 'BLOCKED');

  const empty = compose(baseOperations);
  assert.equal(empty.status, 'PASS');
  const emptyRun = await empty.value.clients.runE2E(Object.freeze({
    lease: 'lane-lease', capability: 'lane-capability',
  }));
  assert.equal(emptyRun.status, 'BLOCKED');

  for (const [name, laneCreation, laneRun] of [
    ['missing', missing, pass(Object.freeze({ complete: true }))],
    ['empty', pass(Object.freeze({ lane: true })), emptyRun],
  ]) {
    const dependencies = Object.freeze({
      ...hostedDependencies([]),
      async createOrdinaryLane() { return laneCreation; },
      async runLane() { return laneRun; },
    });
    const outcome = await runHostedTestCloudController({
      dependencies,
      environment: hostedCredentialEnvironment([]),
      request: hostedControllerRequest(),
    });
    assert.notEqual(outcome.status, 'PASS', name);
  }
});

test('production lane composition fails closed before execution when an operation is absent', async () => {
  const { composeProductionTestCloudLane } = await import('./test-cloud-controller.mjs');
  const harness = controllerHarness();
  const result = composeProductionTestCloudLane({
    artifactSet: harness.artifactSet,
    clock: Object.freeze({ now: () => '2026-07-20T10:00:00.000Z' }),
    controller: trustedController(),
    evidenceWriter: Object.freeze({ write: async () => pass({}) }),
    facade: Object.freeze({
      facade: Object.freeze({ runExactScenario: async () => ({ status: 'PASS' }) }),
      scenarioIds: testCloudScenarioInventory,
      scenarioInventoryDigest: testCloudScenarioInventoryDigest,
    }),
    operations: Object.freeze({}),
    selection: sourceSelection(),
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.diagnostics[0].code, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
});

test('hosted production CLI uses the production dependency factory and fails closed without authority', async () => {
  const {
    createProductionHostedDependencies,
    main,
  } = await import('./test-cloud-controller.mjs');
  const processCalls = [];
  const environment = Object.freeze({});
  let stdout = '';
  let stderr = '';
  const exitCode = await main([
    '--hosted',
    '--revision', SHA,
    '--source-run-id', '1234',
    '--source-run-attempt', '1',
  ], {
    environment,
    inventory,
    createHostedDependencies: ({ environment: receivedEnvironment, fetchImpl }) =>
      createProductionHostedDependencies({
        environment: receivedEnvironment,
        fetchImpl,
        async runContainedProcessImpl(options) {
          processCalls.push(options);
          throw new Error('untrusted controller must block before process creation');
        },
      }),
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
  });
  assert.equal(exitCode, 2);
  assert.equal(stdout, '');
  assert.equal(stderr, 'BLOCKED TRUSTED_CONTROLLER_REQUIRED\n');
  assert.deepEqual(processCalls, []);
});

test('hosted controller production composition binds every approved Task 5 runtime contract', async () => {
  const source = await text('packages/verification-controller/src/test-cloud-controller.mjs');
  for (const required of [
    'reattestLocalControllerArtifact',
    'bootstrapRuntime',
    'runContainedProcess',
    'readTestCloudSourceArtifact',
    'extractSourceArtifactZip',
    'createHostedSiteBuildIdentity',
    'createTestEnvironmentContext',
    'createTestCloudClients',
    'createProviderControlStore',
    'loadQualifiedTestCloudProviderContract',
    'loadQualifiedTestCloudSetupReadback',
    'loadQualifiedTestCloudIdentityBindings',
    'preflightTestCloud',
    'createTestCloudPreflightHandoff',
    'acquireLease',
    'runTrustedTestCloudScenario',
    'createTestCloudPlaywrightFacade',
    'runTestCloudLane',
    'writeVerificationResult',
    'deployTestFunctionArtifacts',
    'deployTestSiteArtifact',
    'composeProductionTestCloudLane',
  ]) {
    assert.ok(source.includes(required), `missing production composition binding: ${required}`);
  }
  const module = await import('./test-cloud-controller.mjs');
  assert.equal(typeof module.createProductionHostedDependencies, 'function');
  const ordinaryStart = source.indexOf('async createOrdinaryLane(stage)');
  const ordinaryEnd = source.indexOf('\n    async runLane(stage)', ordinaryStart);
  const ordinary = source.slice(ordinaryStart, ordinaryEnd);
  assert.match(ordinary, /const lane = composeProductionTestCloudLane\(/u);
  assert.match(ordinary, /return lane\.status === 'PASS'/u);
  assert.match(
    ordinary,
    /expectedSourceTreeDigest:\s*source\.artifactSet\.artifactManifest\.sourceTreeDigest/u,
  );
  assert.doesNotMatch(ordinary, /closedComposition|void closedComposition/u);
  assert.doesNotMatch(
    ordinary,
    /return result\('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED'\);/u,
  );
});

test('hosted parent passes only the closed browser identity set into the contained child', async () => {
  const source = await text('packages/verification-controller/src/test-cloud-controller.mjs');
  const launcherStart = source.indexOf('async createPlaywrightFacade()');
  const launcherEnd = source.indexOf('\n    async qualifyContainment()', launcherStart);
  assert.notEqual(launcherStart, -1);
  assert.notEqual(launcherEnd, -1);
  const launcher = source.slice(launcherStart, launcherEnd);

  for (const name of [
    'E2E_OWNER_EMAIL',
    'E2E_OWNER_PASSWORD',
  ]) {
    assert.match(launcher, new RegExp(`['"]${name}['"]`, 'u'));
  }
  for (const name of [
    'APPWRITE_TEST_RECOVERY_API_KEY',
    'APPWRITE_TEST_OPERATOR_API_KEY',
    'APPWRITE_TEST_FIXTURE_API_KEY',
    'E2E_EDITOR_EMAIL',
    'E2E_EDITOR_PASSWORD',
    'E2E_VIEWER_EMAIL',
    'E2E_VIEWER_PASSWORD',
  ]) {
    assert.doesNotMatch(launcher, new RegExp(`['"]${name}['"]`, 'u'));
  }
});

test('production hosted dependency construction is closed and reads no credential', async () => {
  const { createProductionHostedDependencies } = await import('./test-cloud-controller.mjs');
  assert.throws(
    () => createProductionHostedDependencies(undefined),
    { code: 'CONTROLLER_DEPENDENCIES_INVALID' },
  );
  assert.throws(
    () => createProductionHostedDependencies({
      environment: Object.freeze({}),
      fetchImpl: async () => {},
      controllerArtifactIo: {
        root,
        lstat: async () => {},
        readFile: async () => {},
        realpath: async () => {},
        stageResult: pass(trustedController()),
      },
    }),
    { code: 'CONTROLLER_DEPENDENCIES_INVALID' },
  );
  let credentialReads = 0;
  const environment = new Proxy({}, {
    get(target, property, receiver) {
      const name = String(property);
      if (name === 'SOURCE_ARTIFACT_READER_PRIVATE_KEY'
        || name.startsWith('APPWRITE_TEST_')
        || name.startsWith('E2E_')) credentialReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  const dependencies = createProductionHostedDependencies({
    environment,
    fetchImpl: async () => { throw new Error('network must remain inert'); },
  });
  assert.deepEqual(Object.keys(dependencies).sort(), [
    'bootstrapRuntime',
    'consumeSourceArtifact',
    'createOrdinaryLane',
    'createPlaywrightFacade',
    'qualifyContainment',
    'reattestController',
    'runLane',
    'validateSetupBindings',
    'validateSourceArtifact',
  ]);
  assert.equal(Object.isFrozen(dependencies), true);
  assert.equal(credentialReads, 0);
});

test('production dependencies route containment qualification through the contained-process contract', async () => {
  const { createProductionHostedDependencies } = await import('./test-cloud-controller.mjs');
  const calls = [];
  const runContainedProcessImpl = async (options) => {
    calls.push(options);
    return Object.freeze({
      status: 'exited',
      exitCode: 0,
      signal: null,
      stdout: 'APPWRITEWORK_WINDOWS_JOB_OBJECT_QUALIFIED',
      stderr: '',
    });
  };
  const dependencies = createProductionHostedDependencies({
    environment: Object.freeze({}),
    fetchImpl: async () => { throw new Error('network must remain inert'); },
    runContainedProcessImpl,
  });

  const outcome = await dependencies.qualifyContainment();

  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].executable, process.execPath);
  assert.deepEqual(calls[0].args, [
    '--eval',
    'process.stdout.write("APPWRITEWORK_WINDOWS_JOB_OBJECT_QUALIFIED")',
  ]);
  assert.deepEqual(Object.keys(calls[0].env), []);
});

test('4C-final: controller owns one inert bootstrap call and keeps authority lexical', async () => {
  const source = await text('packages/verification-controller/src/test-cloud-controller.mjs');
  const legacyStart = source.indexOf('export async function runTestCloudController');
  const legacyEnd = source.indexOf('\nfunction hostedArgs', legacyStart);
  const legacySource = source.slice(legacyStart, legacyEnd);
  const bootstrapCall = 'args.dependencies.bootstrapRuntime()';

  assert.equal((legacySource.match(
    /args\.dependencies\.bootstrapRuntime\(\)/gu,
  ) ?? []).length, 1);
  assert.equal(legacySource.includes('test-cloud-provider-contract.mjs'), false);
  assert.equal(legacySource.includes('TEST_CLOUD_4C_PRE_REGISTRAR_ORDER'), false);
  assert.equal(legacySource.includes('TEST_CLOUD_4C_PRE_TOPOLOGY'), false);
  assert.doesNotMatch(legacySource, /test-cloud-browser-artifact-set\.mjs/u);
  assert.doesNotMatch(legacySource, /browserFacade|finalizeBootstrap|bootstrapHub/u);

  const trustedControllerCheck = legacySource.indexOf(
    'if (!isTrustedControllerContext(args.controller))',
  );
  const revisionCheck = legacySource.indexOf('args.requestedRevision !== null');
  const bootstrap = legacySource.indexOf(bootstrapCall);
  const dependencyValidation = legacySource.indexOf('validateDependencies(args.dependencies);');
  const firstExternalAction = legacySource.indexOf(
    'args.dependencies.resolveSourceSelection',
  );
  assert.ok(trustedControllerCheck !== -1);
  assert.ok(revisionCheck > trustedControllerCheck);
  assert.ok(dependencyValidation > revisionCheck);
  assert.ok(bootstrap > dependencyValidation);
  assert.ok(firstExternalAction > bootstrap);
  const controllerEnd = legacySource.length;
  assert.ok(controllerEnd > firstExternalAction);
  const bootstrapAuthorityRegion = legacySource.slice(bootstrap, controllerEnd);
  assert.doesNotMatch(
    bootstrapAuthorityRegion,
    /\b(?:const|let|var)\s+\w+\s*=\s*bootstrapResult\.value\s*;/u,
  );
  const deferredA4TransferRegion = legacySource.slice(firstExternalAction, controllerEnd);
  assert.doesNotMatch(
    deferredA4TransferRegion,
    /runtimeQualification|browserScenarioQualification/u,
    'deferred A4 transfer must not receive runtime authority',
  );

  assert.match(
    source,
    /const runtimeQualification = bootstrapResult\.value\.runtimeQualification;/u,
  );
  assert.match(
    source,
    /const browserScenarioQualification =\s*bootstrapResult\.value\.browserScenarioQualification;/u,
  );
  assert.doesNotMatch(
    source,
    /\{\s*runtimeQualification\s*,\s*browserScenarioQualification\s*\}/u,
  );

  const createClientsCall = source.match(
    /args\.dependencies\.createClients,[\s\S]*?'TEST_CLOUD_PREFLIGHT_BLOCKED',/u,
  );
  assert.notEqual(createClientsCall, null);
  assert.doesNotMatch(
    createClientsCall[0],
    /runtimeQualification|browserScenarioQualification/u,
  );
  const laneCall = source.match(
    /return args\.dependencies\.runLane\(\{([\s\S]*?)\}\);/u,
  );
  assert.notEqual(laneCall, null);
  assert.doesNotMatch(
    laneCall[1],
    /runtimeQualification|browserScenarioQualification/u,
  );

  const provider = await import(
    '../../../scripts/verification/test-cloud-provider-contract.mjs'
  );
  assert.ok(
    ['EMPTY', 'BLOCKED'].includes(provider.readTestCloudRuntimeLifecycle()),
  );
  assert.equal(
    Object.getOwnPropertyDescriptor(
      globalThis,
      '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__',
    ),
    undefined,
  );
});

test('4C-final: exact bootstrap result mutations and failures block before source dependencies', async (t) => {
  const validPass = controllerBootstrapPass();
  const unfrozenPass = Object.create(null);
  for (const key of Reflect.ownKeys(validPass)) {
    Object.defineProperty(
      unfrozenPass,
      key,
      Object.getOwnPropertyDescriptor(validPass, key),
    );
  }

  const accessorPass = Object.create(null);
  Object.defineProperties(accessorPass, {
    status: {
      value: 'PASS',
      enumerable: true,
      configurable: false,
      writable: false,
    },
    value: {
      get: () => validPass.value,
      enumerable: true,
      configurable: false,
    },
    diagnostics: {
      value: Object.freeze([]),
      enumerable: true,
      configurable: false,
      writable: false,
    },
  });
  Object.freeze(accessorPass);

  const aliasedToken = Object.freeze(Object.create(null));
  const nonemptyToken = Object.create(null);
  Object.defineProperty(nonemptyToken, 'authority', {
    value: true,
    enumerable: true,
    configurable: false,
    writable: false,
  });
  Object.freeze(nonemptyToken);

  let throwCalls = 0;
  let rejectCalls = 0;
  const mutations = [
    ['proxied result', new Proxy(validPass, {})],
    ['unfrozen result', unfrozenPass],
    ['accessor result', accessorPass],
    ['ordinary value prototype', frozenNullRecord([
      ['status', 'PASS'],
      ['value', Object.freeze({
        runtimeQualification: validPass.value.runtimeQualification,
        browserScenarioQualification: validPass.value.browserScenarioQualification,
      })],
      ['diagnostics', Object.freeze([])],
    ])],
    ['extra result key', frozenNullRecord([
      ['status', 'PASS'],
      ['value', validPass.value],
      ['diagnostics', Object.freeze([])],
      ['extra', true],
    ])],
    ['missing result key', frozenNullRecord([
      ['status', 'PASS'],
      ['value', validPass.value],
    ])],
    ['bad diagnostics', frozenNullRecord([
      ['status', 'PASS'],
      ['value', validPass.value],
      ['diagnostics', Object.freeze(['unexpected'])],
    ])],
    ['aliased tokens', controllerBootstrapPass({
      runtimeQualification: aliasedToken,
      browserScenarioQualification: aliasedToken,
    })],
    ['nonempty token', controllerBootstrapPass({
      runtimeQualification: Object.freeze(nonemptyToken),
    })],
    ['bootstrap throws', () => {
      throwCalls += 1;
      throw new Error('injected bootstrap throw');
    }],
    ['bootstrap rejects', () => {
      rejectCalls += 1;
      return Promise.reject(new Error('injected bootstrap rejection'));
    }],
  ];
  const { runTestCloudController } = await loadControllerHarnessModule();

  for (const [name, bootstrapOutcome] of mutations) {
    await t.test(name, async () => {
      configureControllerBootstrapHarness(bootstrapOutcome);
      const harness = controllerHarness();

      const outcome = await runTestCloudController({
        controller: trustedController(),
        requestedRevision: SHA,
        dependencies: harness.dependencies,
      });

      assert.equal(outcome.status, 'BLOCKED');
      assert.equal(outcome.value, null);
      assert.equal(outcome.diagnostics[0].code, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
      assert.equal(controllerBootstrapHarnessCalls, 1);
      assert.deepEqual(harness.calls, []);
    });
  }
  assert.equal(throwCalls, 1);
  assert.equal(rejectCalls, 1);
});

test('hosted module has one exact trusted lifecycle import allowlist and no candidate import', async () => {
  const source = await text('packages/verification-controller/src/test-cloud-controller.mjs');
  const imported = [...source.matchAll(/import\(\s*'([^']+)'\s*\)/gu)]
    .map((match) => match[1]);
  assert.deepEqual(imported, [
    './github-controller-artifact-verifier.mjs',
    '../../../scripts/verification/test-cloud-provider-contract.mjs',
    './test-cloud-playwright-facade.mjs',
    './test-cloud-scenario-driver.mjs',
    '../../../scripts/verification/process-containment.mjs',
    './test-cloud-source-artifact-reader.mjs',
    '../../../scripts/verification/hosted-site-build-identity.mjs',
    '../../../scripts/verification/test-cloud-environment.mjs',
    '../../../scripts/verification/test-cloud-appwrite-runtime.mjs',
    '../../../scripts/verification/test-cloud-provider-control-runtime.mjs',
    '../../../scripts/verification/test-cloud-identity-bindings.mjs',
    '../../../scripts/verification/test-cloud-setup-check.mjs',
    '../../../scripts/verification/test-cloud-setup-attestation.mjs',
    '../../../scripts/verification/test-cloud-hosted-setup-attestation.mjs',
    '../../../scripts/verification/test-cloud-preflight.mjs',
    '../../../scripts/verification/test-cloud-control-runtime.mjs',
    './test-cloud-fixture-clock.mjs',
    './test-cloud-fixture-intent-producer.mjs',
    './test-cloud-browser-artifact-set.mjs',
    '../../../scripts/verification/test-cloud-deploy.mjs',
    '../../../scripts/verification/evidence.mjs',
    '../../../scripts/verification/evidence-writer.mjs',
  ]);
  assert.match(
    source,
    /import \{ runTrustedTestCloudCleanup \} from '\.\/test-cloud-cleanup-driver\.mjs';/u,
  );
  assert.match(
    source,
    /validAtomicCleanupPass\(outcome, context, request\.lease\)/u,
  );
  assert.match(source, /TASK9_CLEANUP_VALUE_KEYS/u);
  assert.match(source, /TASK9_CLOSE_PROOF_KEYS/u);
  assert.match(source, /test-cloud-contained-scenario-launcher\.mjs/u);
  assert.doesNotMatch(source, /test-cloud-e2e\.mjs/u);
  assert.doesNotMatch(source, /import\(\s*(?!['"])/u);
  assert.doesNotMatch(source, /sourceArtifact\.(?:path|relativePath)/u);
  assert.doesNotMatch(source, /\beval\s*\(|new\s+Function\b|child_process/u);
});

test('artifact set output is a closed six-key byte and identity bound tuple', async () => {
  const { validateArtifactSetOutput } = await import('./test-cloud-controller.mjs');
  const selection = sourceSelection();
  const artifactSet = artifactSetOutput();
  assert.equal(validateArtifactSetOutput(artifactSet, selection), true);
  assert.equal(validateArtifactSetOutput({ ...artifactSet, extra: true }, selection), false);
  assert.equal(validateArtifactSetOutput({
    ...artifactSet,
    artifactManifestDigest: `sha256:${'0'.repeat(64)}`,
  }, selection), false);
  const changed = Uint8Array.from(artifactSet.releaseEligibleArtifacts[0].bytes);
  changed[0] ^= 1;
  assert.equal(validateArtifactSetOutput({
    ...artifactSet,
    releaseEligibleArtifacts: [
      { ...artifactSet.releaseEligibleArtifacts[0], bytes: changed },
      ...artifactSet.releaseEligibleArtifacts.slice(1),
    ],
  }, selection), false);
});

test('hosted CLI reports setup blocked before reading an Appwrite secret', async () => {
  const { main } = await import('./test-cloud-controller.mjs');
  let secretReads = 0;
  const environment = new Proxy({
    GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
    GITHUB_SHA: SHA,
    TRUSTED_CONTROLLER_SHA: SHA,
    TRUSTED_CONTROLLER_ARTIFACT_ID: '1',
    TRUSTED_CONTROLLER_BUNDLE_DIGEST: DIGEST,
  }, {
    get(target, property, receiver) {
      if (String(property).startsWith('APPWRITE_TEST_')) secretReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  let output = '';
  const incompleteInventory = { ...inventory, control: { ...inventory.control } };
  delete incompleteInventory.control.primaryExecutionRetentionMaxSeconds;
  const exitCode = await main(HOSTED_CLI_ARGS, {
    environment,
    inventory: incompleteInventory,
    stderr: { write(value) { output += value; } },
  });
  assert.equal(exitCode, 2);
  assert.equal(output, 'BLOCKED TEST_CLOUD_SETUP_INCOMPLETE\n');
  assert.equal(secretReads, 0);
});

test('hosted CLI forwards one exact request to the production controller', async () => {
  const { main } = await import('./test-cloud-controller.mjs');
  const environment = Object.freeze({ marker: true });
  const fetchImpl = async () => { throw new Error('network must remain inert'); };
  const productionDependencies = Object.freeze({ marker: 'dependencies' });
  const calls = [];
  let stdout = '';
  let stderr = '';
  const exitCode = await main(HOSTED_CLI_ARGS, {
    environment,
    inventory,
    fetchImpl,
    createHostedDependencies(args) {
      calls.push(['factory', args]);
      return productionDependencies;
    },
    async runHostedController(args) {
      calls.push(['controller', args]);
      return pass(Object.freeze({ completed: true }));
    },
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
  });
  assert.equal(exitCode, 0);
  assert.equal(stdout, 'PASS\n');
  assert.equal(stderr, '');
  assert.deepEqual(calls, [
    ['factory', { environment, fetchImpl }],
    ['controller', {
      dependencies: productionDependencies,
      environment,
      request: {
        requestedRevision: SHA,
        sourceRunId: '1234',
        sourceRunAttempt: 2,
      },
    }],
  ]);
});

test('hosted CLI admits only an absolute data-property controller artifact directory', async () => {
  const { main } = await import('./test-cloud-controller.mjs');
  const artifactDirectory = path.resolve(root, 'controller-artifact-input');
  const calls = [];
  const createHostedDependencies = (args) => {
    calls.push(args);
    return Object.freeze({ marker: 'dependencies' });
  };
  const runHostedController = async () => pass(Object.freeze({ completed: true }));
  let stdout = '';
  let stderr = '';
  const exitCode = await main(HOSTED_CLI_ARGS, {
    environment: Object.freeze({ CONTROLLER_ARTIFACT_DIRECTORY: artifactDirectory }),
    inventory,
    fetchImpl: async () => { throw new Error('network must remain inert'); },
    createHostedDependencies,
    runHostedController,
    stdout: { write(value) { stdout += value; } },
    stderr: { write(value) { stderr += value; } },
  });
  assert.equal(exitCode, 0);
  assert.equal(stdout, 'PASS\n');
  assert.equal(stderr, '');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].controllerArtifactIo.root, artifactDirectory);
  for (const name of ['lstat', 'readFile', 'realpath']) {
    assert.equal(typeof calls[0].controllerArtifactIo[name], 'function');
  }

  for (const hostile of ['relative-artifact', `C:${String.fromCharCode(0)}artifact`]) {
    let factoryCalls = 0;
    stderr = '';
    const blocked = await main(HOSTED_CLI_ARGS, {
      environment: Object.freeze({ CONTROLLER_ARTIFACT_DIRECTORY: hostile }),
      inventory,
      createHostedDependencies() {
        factoryCalls += 1;
        throw new Error('hostile path must block before dependency construction');
      },
      stderr: { write(value) { stderr += value; } },
    });
    assert.equal(blocked, 2);
    assert.equal(stderr, 'BLOCKED TEST_CLOUD_SETUP_INCOMPLETE\n');
    assert.equal(factoryCalls, 0);
  }

  let getterCalls = 0;
  const accessorEnvironment = {};
  Object.defineProperty(accessorEnvironment, 'CONTROLLER_ARTIFACT_DIRECTORY', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return artifactDirectory;
    },
  });
  Object.freeze(accessorEnvironment);
  calls.length = 0;
  const accessorExit = await main(HOSTED_CLI_ARGS, {
    environment: accessorEnvironment,
    inventory,
    createHostedDependencies,
    runHostedController,
    stdout: { write() {} },
    stderr: { write() {} },
  });
  assert.equal(accessorExit, 0);
  assert.equal(getterCalls, 0);
  assert.equal(Object.hasOwn(calls[0], 'controllerArtifactIo'), false);
});

test('hosted CLI grammar is exact and the real process fails closed before network access', async () => {
  const { main } = await import('./test-cloud-controller.mjs');
  for (const argv of [
    HOSTED_CLI_ARGS.slice(0, -2),
    [...HOSTED_CLI_ARGS, '--extra'],
    [...HOSTED_CLI_ARGS.slice(0, -1), '0'],
    [...HOSTED_CLI_ARGS.slice(0, -1), '01'],
    ['--hosted', '--revision', SHA.toUpperCase(), ...HOSTED_CLI_ARGS.slice(3)],
    ['--hosted', '--revision', SHA, '--source-run-id', 'unsafe/id', '--source-run-attempt', '2'],
  ]) {
    let output = '';
    let factoryCalls = 0;
    const exitCode = await main(argv, {
      createHostedDependencies() {
        factoryCalls += 1;
        throw new Error('invalid CLI must not construct production dependencies');
      },
      stderr: { write(value) { output += value; } },
    });
    assert.equal(exitCode, 2);
    assert.equal(output, 'BLOCKED TRUSTED_CONTROLLER_CLI_INVALID\n');
    assert.equal(factoryCalls, 0);
  }

  const executed = spawnSync(process.execPath, [
    path.join(root, 'packages/verification-controller/src/test-cloud-controller.mjs'),
    ...HOSTED_CLI_ARGS,
  ], {
    cwd: root,
    encoding: 'utf8',
    env: Object.create(null),
    windowsHide: true,
  });
  assert.equal(executed.status, 2);
  assert.equal(executed.stdout, '');
  assert.equal(executed.stderr, 'BLOCKED TRUSTED_CONTROLLER_REQUIRED\n');
});

test('missing accepted containment prerequisites block before source or Appwrite secret access', async () => {
  const { main } = await import('./test-cloud-controller.mjs');
  let secretReads = 0;
  const environment = new Proxy({
    GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
    GITHUB_SHA: SHA,
    TRUSTED_CONTROLLER_SHA: SHA,
    TRUSTED_CONTROLLER_ARTIFACT_ID: '1',
    TRUSTED_CONTROLLER_BUNDLE_DIGEST: DIGEST,
  }, {
    get(target, property, receiver) {
      if (
        String(property) === 'SOURCE_ARTIFACT_READER_PRIVATE_KEY'
        || String(property).startsWith('APPWRITE_TEST_')
      ) secretReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  let output = '';
  const exitCode = await main(HOSTED_CLI_ARGS, {
    environment,
    inventory,
    stderr: { write(value) { output += value; } },
  });
  assert.equal(exitCode, 2);
  assert.equal(output, 'BLOCKED TRUSTED_CONTROLLER_REQUIRED\n');
  assert.equal(secretReads, 0);
});

const HOSTED_SECRET_NAMES = Object.freeze([
  'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
  'APPWRITE_TEST_OPERATOR_API_KEY',
  'APPWRITE_TEST_FIXTURE_API_KEY',
  'E2E_OWNER_EMAIL',
  'E2E_OWNER_PASSWORD',
  'E2E_EDITOR_EMAIL',
  'E2E_EDITOR_PASSWORD',
  'E2E_VIEWER_EMAIL',
  'E2E_VIEWER_PASSWORD',
  'APPWRITE_TEST_RECOVERY_API_KEY',
]);

function hostedCredentialEnvironment(reads) {
  const values = Object.fromEntries(HOSTED_SECRET_NAMES.map((name) => [name, `value:${name}`]));
  return new Proxy(values, {
    get(target, property, receiver) {
      const name = String(property);
      if (HOSTED_SECRET_NAMES.includes(name)) reads.push(name);
      return Reflect.get(target, property, receiver);
    },
  });
}

function validatedHostedSnapshot() {
  return Object.freeze({
    artifactSet: artifactSetOutput(),
    selection: sourceSelection(),
  });
}

function hostedControllerRequest() {
  return Object.freeze({
    requestedRevision: SHA,
    sourceRunAttempt: 1,
    sourceRunId: '1234',
  });
}

function hostedSetupReadback({ retentionMaxSeconds = 3600 } = {}) {
  return {
    schemaVersion: 'test-cloud.hosted-setup-readback.v1',
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
      descriptorDigest: inventory.providerContractDigest,
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
      retentionMaxSeconds,
    },
    productFunctions: inventory.productFunctions.map(({ logicalId, functionId }) => ({
      logicalId,
      functionId,
    })),
    credentialScopes: Object.fromEntries(['operator', 'fixture', 'recovery'].map((name) => [
      name,
      {
        variableName: inventory.credentialVariables[name].variableName,
        scopes: [...inventory.credentialVariables[name].scopes],
      },
    ])),
    runner: {
      functionId: inventory.control.runnerFunctionId,
      runtime: 'python-3.12',
      privateExecute: true,
      publicExecute: false,
      scopes: ['execution.write', 'rows.read', 'rows.write', 'files.read', 'files.write'],
    },
    controller: {
      repository: 'Krowaccie/AppWriteWork-verification-control',
      rulesetProtected: true,
      codeownersProtected: true,
      environments: ['appwrite-test', 'controller-promotion'],
      bundle: {
        sourceRepositoryRevision: CONTROLLER_SOURCE_SHA,
        controllerRevision: SHA,
        artifactId: '1',
        digest: DIGEST,
      },
    },
    githubApp: {
      sourceRepository: 'Krowaccie/AppWriteWork',
      installationScoped: true,
      userAuthorization: false,
      webhooks: false,
      permissions: { actions: 'read', metadata: 'read' },
    },
    identities: [
      { role: 'editor', sessions: [] },
      { role: 'owner', sessions: [] },
      { role: 'viewer', sessions: [] },
    ],
    bootstrap: {
      seeded: true,
      sourceRevision: CONTROLLER_SOURCE_SHA,
      bundleDigest: DIGEST,
    },
  };
}

function splitSetupEnvironment({
  site = productionSiteProjection(),
  functions = productionFunctionProjections(),
  setupProjectionDigests = null,
  browserRequestPolicy = null,
} = {}) {
  const nowEpochSeconds = Math.floor(Date.now() / 1000);
  const providerReadback = structuredClone(canonicalReadback);
  if (browserRequestPolicy !== null) {
    providerReadback.browserRequestPolicy = structuredClone(browserRequestPolicy);
  }
  providerReadback.identityBindings.identityBindingsDigest = derivedIdentityBindingsDigest();
  for (const variable of providerReadback.expectedRunnerVariables.variables) {
    variable.valueDigest = sha256Bytes(new TextEncoder().encode(runnerVariableValue(
      variable.key,
      providerReadback.identityBindings.identityBindingsDigest,
    )));
  }
  const providerReadbackDigest = digestJson(providerReadback);
  const runnerVariableReadbackDigest = digestJson({
    schemaVersion: 'test-cloud.runner-variable-readback.v1',
    environmentDigest: providerReadback.environmentDigest,
    providerContractDigest: providerReadback.providerContractDigest,
    functionIdDigest: sha256Bytes(new TextEncoder().encode('verification-runner-py')),
    variables: providerReadback.expectedRunnerVariables.variables,
  });
  const hostedReadback = hostedSetupReadback();
  const hostedReadbackDigest = digestJson(hostedReadback);
  const executionObservationPolicyDigest = digestJson(hostedReadback.executionObservation);
  const credentialScopeReadbackDigest = digestJson(Object.entries(inventory.credentialVariables)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([role, entry]) => ({
      role,
      credentialClass: entry.credentialClass,
      variableName: entry.variableName,
      scopes: [...entry.scopes],
    })));
  const fixedLeaseIdentityDigest = digestJson({
    databaseId: inventory.control.databaseId,
    tableId: inventory.control.leaseTableId,
    rowId: inventory.control.leaseRowId,
  });
  const projectionDigests = setupProjectionDigests ?? {
    functionConfigurationsDigest: `sha256:${'8'.repeat(64)}`,
    siteConfigurationDigest: `sha256:${'c'.repeat(64)}`,
  };
  const providerAttestation = setupAttestation({
    readback: providerReadback,
    nowEpochSeconds,
    retentionMaxSeconds: hostedReadback.executionObservation.retentionMaxSeconds,
    overrides: {
      credentialScopeReadbackDigest,
      executionObservationPolicyDigest,
      fixedLeaseIdentityDigest,
      functionConfigurationsDigest: projectionDigests.functionConfigurationsDigest,
      providerSetupReadbackDigest: providerReadbackDigest,
      runnerVariableReadbackDigest,
      siteConfigurationDigest: projectionDigests.siteConfigurationDigest,
    },
  });
  const hostedAttestation = {
    schemaVersion: 'test-cloud.hosted-setup-attestation.v1',
    providerSetupReadbackDigest: providerReadbackDigest,
    hostedSetupReadbackDigest: hostedReadbackDigest,
    executionObservationPolicyDigest,
    primaryExecutionRetentionMaxSeconds:
      hostedReadback.executionObservation.retentionMaxSeconds,
    issuedAtEpochSeconds: nowEpochSeconds - 10,
    expiresAtEpochSeconds: nowEpochSeconds + 100,
  };
  return {
    SOURCE_ARTIFACT_READER_APP_ID: '1',
    SOURCE_ARTIFACT_READER_INSTALLATION_ID: '2',
    SOURCE_REPOSITORY_ID: '3',
    SOURCE_VERIFY_MAIN_WORKFLOW_ID: '4',
    TEST_CLOUD_SETUP_READBACK_JSON: canonicalJson(providerReadback),
    TEST_CLOUD_SETUP_READBACK_DIGEST: providerReadbackDigest,
    TEST_CLOUD_SETUP_ATTESTATION_JSON: canonicalJson(providerAttestation),
    TEST_CLOUD_SETUP_ATTESTATION_DIGEST: digestJson(providerAttestation),
    TEST_CLOUD_HOSTED_SETUP_READBACK_JSON: canonicalJson(hostedReadback),
    TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST: hostedReadbackDigest,
    TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON: canonicalJson(hostedAttestation),
    TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST: digestJson(hostedAttestation),
  };
}

function hostedDependencies(calls, failAt = null) {
  const stage = (name, value) => async () => {
    calls.push(name);
    return failAt === name
      ? Object.freeze({ status: 'BLOCKED', value: null, diagnostics: Object.freeze([]) })
      : Object.freeze({ status: 'PASS', value, diagnostics: Object.freeze([]) });
  };
  return Object.freeze({
    reattestController: stage('controller', Object.freeze({ trusted: true })),
    validateSetupBindings: stage('setup', Object.freeze({ setup: true })),
    bootstrapRuntime: stage('runtime', Object.freeze({ runtime: true })),
    createPlaywrightFacade: stage('facade', Object.freeze({ facade: true })),
    qualifyContainment: stage('containment', Object.freeze({ contained: true })),
    consumeSourceArtifact: stage('source-readback', Object.freeze({ files: new Map() })),
    validateSourceArtifact: stage('source-validation', validatedHostedSnapshot()),
    createOrdinaryLane: stage('lane-create', Object.freeze({ lane: true })),
    runLane: stage('lane', Object.freeze({ complete: true })),
  });
}

test('hosted controller forwards only fixed Task 5 identity and setup diagnostics', async (t) => {
  const { runHostedTestCloudController } = await import('./test-cloud-controller.mjs');
  const safeCodes = [
    'TEST_IDENTITY_HTTP_RESPONSE_INVALID',
    'TEST_IDENTITY_LIST_CARDINALITY_INVALID',
    'TEST_IDENTITY_SESSION_SET_INVALID',
    'TEST_IDENTITY_USER_CORE_INVALID',
    'TEST_IDENTITY_USER_KEYS_INVALID',
    'TEST_IDENTITY_USER_LABELS_INVALID',
    'TEST_IDENTITY_USER_OPTIONALS_INVALID',
    'TEST_IDENTITY_USER_PASSWORD_INVALID',
    'TEST_IDENTITY_USER_PREFS_INVALID',
    'TEST_IDENTITY_USER_READBACK_MISMATCH',
    'TEST_IDENTITY_USER_TARGETS_INVALID',
    'TEST_IDENTITY_USER_TIMESTAMPS_INVALID',
    'TEST_IDENTITY_USER_UNIQUENESS_INVALID',
    'TEST_CLOUD_SETUP_ENVIRONMENT_BINDING_INVALID',
    'TEST_CLOUD_SETUP_FINALIZATION_INVALID',
    'TEST_CLOUD_SETUP_IDENTITY_DIGEST_MISMATCH',
    'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID',
    'TEST_CLOUD_SETUP_PAYLOAD_INVALID',
    'TEST_CLOUD_SETUP_PROVIDER_BINDING_INVALID',
    'TEST_CLOUD_SETUP_REQUEST_INVALID',
    'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID',
  ];
  for (const code of safeCodes) {
    await t.test(code, async () => {
      const calls = [];
      const dependencies = Object.freeze({
        ...hostedDependencies(calls),
        async createOrdinaryLane() {
          calls.push('lane-create');
          return Object.freeze({
            status: 'BLOCKED',
            value: null,
            diagnostics: Object.freeze([Object.freeze({
              code,
              retryable: false,
              safeMessage: 'SECRET_STAGE_SENTINEL',
            })]),
          });
        },
      });
      const outcome = await runHostedTestCloudController({
        dependencies,
        environment: hostedCredentialEnvironment([]),
        request: hostedControllerRequest(),
      });
      assert.equal(outcome.status, 'BLOCKED');
      assert.equal(outcome.diagnostics[0].code, code);
      assert.equal(
        outcome.diagnostics[0].safeMessage,
        'The protected test-cloud client boundary could not be constructed.',
      );
      assert.equal(JSON.stringify(outcome).includes('SECRET_STAGE_SENTINEL'), false);
    });
  }

  await t.test('unknown and hostile diagnostics collapse without accessor reads', async () => {
    let getterCalls = 0;
    const diagnostic = { retryable: false, safeMessage: 'SECRET_STAGE_SENTINEL' };
    Object.defineProperty(diagnostic, 'code', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'TEST_IDENTITY_USER_TARGETS_INVALID';
      },
    });
    const dependencies = Object.freeze({
      ...hostedDependencies([]),
      async createOrdinaryLane() {
        return { status: 'BLOCKED', value: null, diagnostics: [diagnostic] };
      },
    });
    const outcome = await runHostedTestCloudController({
      dependencies,
      environment: hostedCredentialEnvironment([]),
      request: hostedControllerRequest(),
    });
    assert.equal(outcome.diagnostics[0].code, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
    assert.equal(getterCalls, 0);
    assert.equal(JSON.stringify(outcome).includes('SECRET_STAGE_SENTINEL'), false);
  });
});

test('hosted controller rejects an arbitrary source PASS value before ordinary credential reads', async () => {
  const { runHostedTestCloudController } = await import('./test-cloud-controller.mjs');
  const calls = [];
  const reads = [];
  const dependencies = {
    ...hostedDependencies(calls),
    validateSourceArtifact: async () => pass(Object.freeze({ artifactSet: true })),
  };
  const outcome = await runHostedTestCloudController({
    dependencies: Object.freeze(dependencies),
    environment: hostedCredentialEnvironment(reads),
    request: hostedControllerRequest(),
  });
  assert.equal(outcome.status, 'BLOCKED');
  assert.equal(outcome.diagnostics[0].code, 'SOURCE_ARTIFACT_INVALID');
  assert.deepEqual(reads, ['SOURCE_ARTIFACT_READER_PRIVATE_KEY']);
  assert.equal(calls.includes('lane-create'), false);
});

test('hosted controller binds the validated source snapshot to the exact requested run tuple', async () => {
  const { runHostedTestCloudController } = await import('./test-cloud-controller.mjs');
  for (const request of [
    { ...hostedControllerRequest(), sourceRunId: '9999' },
    { ...hostedControllerRequest(), sourceRunAttempt: 2 },
    { ...hostedControllerRequest(), requestedRevision: 'f'.repeat(40) },
  ]) {
    const calls = [];
    const reads = [];
    const outcome = await runHostedTestCloudController({
      dependencies: hostedDependencies(calls),
      environment: hostedCredentialEnvironment(reads),
      request,
    });
    assert.equal(outcome.status, 'BLOCKED');
    assert.equal(outcome.diagnostics[0].code, 'SOURCE_ARTIFACT_INVALID');
    assert.deepEqual(reads, ['SOURCE_ARTIFACT_READER_PRIVATE_KEY']);
    assert.equal(calls.includes('lane-create'), false);
  }
});

test('production hosted gates fail closed for repository identity and each setup binding', async () => {
  const { createProductionHostedDependencies } = await import('./test-cloud-controller.mjs');
  const setupBindings = [
    'TEST_CLOUD_SETUP_READBACK_JSON',
    'TEST_CLOUD_SETUP_READBACK_DIGEST',
    'TEST_CLOUD_SETUP_ATTESTATION_JSON',
    'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
    'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
    'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
  ];
  const base = {
    GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
    GITHUB_SHA: SHA,
    PROOF_ARTIFACT_ID: '1',
    PROOF_BUNDLE_DIGEST: DIGEST,
    PROOF_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
    PROOF_SHA: SHA,
    PROOF_STATUS: 'PASS',
    TRUSTED_CONTROLLER_ARTIFACT_ID: '1',
    TRUSTED_CONTROLLER_BUNDLE_DIGEST: DIGEST,
    TRUSTED_CONTROLLER_SHA: SHA,
    SOURCE_ARTIFACT_READER_APP_ID: '1',
    SOURCE_ARTIFACT_READER_INSTALLATION_ID: '2',
    SOURCE_REPOSITORY_ID: '3',
    SOURCE_VERIFY_MAIN_WORKFLOW_ID: '4',
    TEST_CLOUD_SETUP_READBACK_JSON: '{}',
    TEST_CLOUD_SETUP_READBACK_DIGEST: sha256Bytes(new TextEncoder().encode('{}')),
    TEST_CLOUD_SETUP_ATTESTATION_JSON: '{}',
    TEST_CLOUD_SETUP_ATTESTATION_DIGEST: sha256Bytes(new TextEncoder().encode('{}')),
    TEST_CLOUD_HOSTED_SETUP_READBACK_JSON: '{}',
    TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST: sha256Bytes(new TextEncoder().encode('{}')),
    TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON: '{}',
    TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST: sha256Bytes(new TextEncoder().encode('{}')),
  };

  const wrongRepository = createProductionHostedDependencies({
    environment: Object.freeze({
      ...base,
      GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork',
    }),
    fetchImpl: async () => { throw new Error('network must remain inert'); },
  });
  assert.equal((await wrongRepository.reattestController()).status, 'BLOCKED');

  for (const missing of setupBindings) {
    const environment = { ...base };
    delete environment[missing];
    const dependencies = createProductionHostedDependencies({
      environment: Object.freeze(environment),
      fetchImpl: async () => { throw new Error('network must remain inert'); },
    });
    const outcome = await dependencies.validateSetupBindings({
      controller: Object.freeze({
        controllerBundleSha: SHA,
        controllerBundleDigest: DIGEST,
      }),
    });
    assert.equal(outcome.status, 'BLOCKED', missing);
    assert.equal(outcome.diagnostics[0].code, 'TEST_CLOUD_SETUP_INCOMPLETE', missing);
  }
});

test('production hosted setup derives policy only from hosted bytes and confirms all eight bindings', async () => {
  const { createProductionHostedDependencies } = await import('./test-cloud-controller.mjs');
  const environment = Object.freeze(splitSetupEnvironment());
  const dependencies = createProductionHostedDependencies({
    environment,
    fetchImpl: async () => { throw new Error('network must remain inert'); },
  });
  const outcome = await dependencies.validateSetupBindings({
    controller: Object.freeze({
      controllerBundleSha: SHA,
      controllerBundleDigest: DIGEST,
    }),
  });
  assert.equal(outcome.status, 'PASS', JSON.stringify(outcome));
  assert.equal(outcome.value.readback.schemaVersion, 'test-cloud.setup-readback.v1');
  assert.equal(
    outcome.value.hostedReadback.schemaVersion,
    'test-cloud.hosted-setup-readback.v1',
  );
  assert.equal(
    outcome.value.attestation.providerSetupReadbackDigest,
    environment.TEST_CLOUD_SETUP_READBACK_DIGEST,
  );
  assert.equal(outcome.value.attestation.primaryExecutionRetentionMaxSeconds, 3600);
});

test('hosted controller admits credential classes only after their exact prerequisite gates', async (t) => {
  const { runHostedTestCloudController } = await import('./test-cloud-controller.mjs');

  for (const failingGate of ['controller', 'setup', 'runtime', 'facade', 'containment']) {
    await t.test(`${failingGate} failure reads no credential`, async () => {
      const reads = [];
      const calls = [];
      const outcome = await runHostedTestCloudController({
        request: hostedControllerRequest(),
        environment: hostedCredentialEnvironment(reads),
        dependencies: hostedDependencies(calls, failingGate),
      });
      assert.equal(outcome.status, 'BLOCKED');
      assert.deepEqual(reads, []);
      assert.deepEqual(calls, [
        'controller', 'setup', 'runtime', 'facade', 'containment',
      ].slice(0, ['controller', 'setup', 'runtime', 'facade', 'containment'].indexOf(failingGate) + 1));
    });
  }

  for (const failingGate of ['source-readback', 'source-validation']) {
    await t.test(`${failingGate} failure reads only the source-reader credential`, async () => {
      const reads = [];
      const calls = [];
      const outcome = await runHostedTestCloudController({
        request: hostedControllerRequest(),
        environment: hostedCredentialEnvironment(reads),
        dependencies: hostedDependencies(calls, failingGate),
      });
      assert.equal(outcome.status, 'BLOCKED');
      assert.deepEqual(reads, ['SOURCE_ARTIFACT_READER_PRIVATE_KEY']);
      assert.equal(calls.includes('lane-create'), false);
      assert.equal(calls.includes('lane'), false);
    });
  }
});

test('hosted controller happy path has deterministic admission order and never reads recovery', async () => {
  const { runHostedTestCloudController } = await import('./test-cloud-controller.mjs');
  const reads = [];
  const calls = [];
  const result = await runHostedTestCloudController({
    request: hostedControllerRequest(),
    environment: hostedCredentialEnvironment(reads),
    dependencies: hostedDependencies(calls),
  });
  assert.equal(result.status, 'PASS', JSON.stringify({ result, calls, reads }));
  assert.deepEqual(calls, [
    'controller',
    'setup',
    'runtime',
    'facade',
    'containment',
    'source-readback',
    'source-validation',
    'lane-create',
    'lane',
  ]);
  assert.deepEqual(reads, [
    'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
    'APPWRITE_TEST_OPERATOR_API_KEY',
    'APPWRITE_TEST_FIXTURE_API_KEY',
    'E2E_OWNER_EMAIL',
    'E2E_OWNER_PASSWORD',
    'E2E_EDITOR_EMAIL',
    'E2E_EDITOR_PASSWORD',
    'E2E_VIEWER_EMAIL',
    'E2E_VIEWER_PASSWORD',
  ]);
  assert.equal(reads.includes('APPWRITE_TEST_RECOVERY_API_KEY'), false);
});


test('forged controller and malformed revision stop before dependency access', async () => {
  const { runTestCloudController } = await import('./test-cloud-controller.mjs');
  for (const [controller, requestedRevision, expectedCode] of [
    [{ environment: 'appwrite-test' }, SHA, 'TRUSTED_CONTROLLER_REQUIRED'],
    [trustedController(), 'abc', 'SOURCE_RUN_NOT_GREEN'],
  ]) {
    let dependencyReads = 0;
    const dependencies = new Proxy({}, {
      ownKeys() {
        dependencyReads += 1;
        return [];
      },
      get() {
        dependencyReads += 1;
        return undefined;
      },
    });
    const result = await runTestCloudController({
      controller,
      requestedRevision,
      dependencies,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.value, null);
    assert.equal(result.diagnostics[0].code, expectedCode);
    assert.equal(dependencyReads, 0);
  }
});

test('controller resolves trusted source data before constructing clients and delegates to trusted lane', async () => {
  const bootstrapPass = controllerBootstrapPass();
  configureControllerBootstrapHarness(bootstrapPass);
  const { runTestCloudController } = await loadControllerHarnessModule();
  const harness = controllerHarness();
  const result = await runTestCloudController({
    controller: trustedController(),
    requestedRevision: SHA,
    dependencies: harness.dependencies,
  });

  assert.equal(result.status, 'PASS', JSON.stringify({ result, calls: harness.calls }));
  assert.equal(result.value.sourceRevision, SHA);
  assert.equal(result.value.evidenceDigest, EVIDENCE_DIGEST);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(controllerBootstrapHarnessCalls, 1);
  assert.deepEqual(Reflect.ownKeys(harness.downstreamArgs.createClients), [
    'controller',
    'selection',
    'artifactSet',
  ]);
  assert.notEqual(
    controllerLaneHarnessArgs,
    undefined,
    'runLane spy did not observe arguments',
  );
  assert.deepEqual(Reflect.ownKeys(controllerLaneHarnessArgs), [
    'controller',
    'selection',
    'artifactSet',
    'clients',
    'clock',
    'evidenceWriter',
  ]);
  const authorityTokens = [
    bootstrapPass.value.runtimeQualification,
    bootstrapPass.value.browserScenarioQualification,
  ];
  for (const downstream of [harness.downstreamArgs.createClients, controllerLaneHarnessArgs]) {
    assert.equal(
      Reflect.ownKeys(downstream).some((key) => (
        key === 'runtimeQualification' || key === 'browserScenarioQualification'
      )),
      false,
    );
    assert.equal(
      Object.values(downstream).some((value) => authorityTokens.includes(value)),
      false,
    );
  }
  assert.deepEqual(harness.calls, [
    'selection',
    'artifact',
    'clients',
    'preflight',
    'acquireLease',
    'deployFunctionArtifacts',
    'deploySiteArtifact',
    'qualifyRunner',
    'runE2E',
    'cleanup',
    'evidence',
  ]);
});

test('source selection and artifact failures leave client construction at zero', async (t) => {
  const { runTestCloudController } = await loadControllerHarnessModule();
  const blocked = (code) => Object.freeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: Object.freeze([Object.freeze({
      code,
      safeMessage: 'Injected trusted-boundary failure.',
      retryable: false,
    })]),
  });

  await t.test('selection failure', async () => {
    configureControllerBootstrapHarness(controllerBootstrapPass());
    const harness = controllerHarness();
    const dependencies = {
      ...harness.dependencies,
      resolveSourceSelection: async () => {
        harness.calls.push('selection');
        return blocked('SOURCE_RUN_NOT_GREEN');
      },
    };
    const result = await runTestCloudController({
      controller: trustedController(),
      requestedRevision: SHA,
      dependencies,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.diagnostics[0].code, 'SOURCE_RUN_NOT_GREEN');
    assert.deepEqual(harness.calls, ['selection']);
  });

  await t.test('open selection result', async () => {
    configureControllerBootstrapHarness(controllerBootstrapPass());
    const harness = controllerHarness();
    const dependencies = {
      ...harness.dependencies,
      resolveSourceSelection: async () => {
        harness.calls.push('selection');
        return { ...pass(sourceSelection()), extra: true };
      },
    };
    const result = await runTestCloudController({
      controller: trustedController(),
      requestedRevision: SHA,
      dependencies,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.diagnostics[0].code, 'SOURCE_RUN_NOT_GREEN');
    assert.deepEqual(harness.calls, ['selection']);
  });

  await t.test('artifact failure', async () => {
    configureControllerBootstrapHarness(controllerBootstrapPass());
    const harness = controllerHarness();
    const dependencies = {
      ...harness.dependencies,
      consumeHostedArtifact: async () => {
        harness.calls.push('artifact');
        return blocked('SOURCE_ARTIFACT_INVALID');
      },
    };
    const result = await runTestCloudController({
      controller: trustedController(),
      requestedRevision: SHA,
      dependencies,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.diagnostics[0].code, 'SOURCE_ARTIFACT_INVALID');
    assert.deepEqual(harness.calls, ['selection', 'artifact']);
  });
});

test('controller accepts only closed dependencies and the promoted lane entrypoint', async (t) => {
  const { runTestCloudController } = await loadControllerHarnessModule();
  for (const [name, patch] of [
    ['candidate-selected lane', { runLane: async () => pass(null) }],
    ['open clock', { clock: { now: () => '2026-07-20T10:00:00.000Z', extra: true } }],
    ['inherited clock capability', {
      clock: Object.assign(
        Object.create({ inherited: true }),
        { now: () => '2026-07-20T10:00:00.000Z' },
      ),
    }],
    ['open evidence writer', { evidenceWriter: { write: async () => pass(null), extra: true } }],
    ['missing bootstrap runtime', { bootstrapRuntime: null }],
    ['missing client factory', { createClients: null }],
  ]) {
    await t.test(name, async () => {
      configureControllerBootstrapHarness(controllerBootstrapPass());
      const harness = controllerHarness();
      const dependencies = {
        ...harness.dependencies,
        ...patch,
      };
      await assert.rejects(
        () => runTestCloudController({
          controller: trustedController(),
          requestedRevision: SHA,
          dependencies,
        }),
        (error) => error instanceof TypeError && error.code === 'CONTROLLER_DEPENDENCIES_INVALID',
      );
      assert.deepEqual(harness.calls, []);
    });
  }
});

test('source Verify Main remains credential-free and delegates publication only to trusted A1', async () => {
  const workflow = await text(SOURCE_WORKFLOW);
  assert.match(workflow, /^name:\s*Verify Main\s*$/mu);
  assert.doesNotMatch(workflow, /BLOCKED ARTIFACT_NETWORK_POLICY_UNAVAILABLE/u);
  assert.match(workflow, /node scripts\/verification\/hosted-source-artifact-request\.mjs/u);
  assert.equal(workflow.split(pins.trustedA1).length - 1, 1);
  assert.match(workflow, /request:\s*\$\{\{\s*steps\.source-artifact-request\.outputs\.request\s*\}\}/u);
  assert.deepEqual(actionReferences(workflow), [pins.checkout, pins.node, pins.python]);

  for (const forbidden of [
    /\$\{\{\s*secrets\./iu,
    /^\s*environment\s*:/imu,
    /^\s*id-token\s*:/imu,
    /\bAPPWRITE_[A-Z0-9_]+\b/u,
    /bootstrap/iu,
    /playwright/iu,
    /--lane\s+(?:test-cloud|production-readonly)/iu,
    /actions\/download-artifact@/iu,
    /\bGITHUB_TOKEN\b/u,
  ]) {
    assert.doesNotMatch(workflow, forbidden);
  }
});

test('controller test-cloud workflow is the bounded Windows hosted composition', async () => {
  const workflow = await text(CONTROLLER_WORKFLOW);
  for (const required of [
    'name: Verify Test Cloud',
    'workflow_dispatch:',
    'revision:',
    'source_run_id:',
    'source_run_attempt:',
    'contents: read',
    'actions: read',
    'group: appwrite-test-verification',
    'cancel-in-progress: false',
    'timeout-minutes: 45',
    'environment: appwrite-test',
    'runs-on: windows-2025',
    "github.repository == 'Krowaccie/AppWriteWork-verification-control'",
    'test "$GITHUB_SHA" = "$TRUSTED_CONTROLLER_SHA"',
    'prepare-controller-artifact.mjs',
    'CONTROLLER_ARTIFACT_DIRECTORY',
    'TRUSTED_CONTROLLER_ARTIFACT_ID',
    'TRUSTED_CONTROLLER_BUNDLE_DIGEST',
    'TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_ID',
    'TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_DIGEST',
    'test-cloud-binding-artifact-verifier.mjs',
    'BINDING_DIRECTORY',
    'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
    'APPWRITE_TEST_OPERATOR_API_KEY',
    'APPWRITE_TEST_FIXTURE_API_KEY',
    'E2E_OWNER_EMAIL',
    'E2E_OWNER_PASSWORD',
    'E2E_EDITOR_EMAIL',
    'E2E_EDITOR_PASSWORD',
    'E2E_VIEWER_EMAIL',
    'E2E_VIEWER_PASSWORD',
    'test-cloud-controller.mjs --hosted --revision',
    '--binding-directory "$BINDING_DIRECTORY"',
    pins.checkout,
    pins.node,
    'persist-credentials: false',
  ]) {
    assert.ok(workflow.includes(required), `missing controller workflow contract: ${required}`);
  }
  assert.doesNotMatch(workflow, /^\s*schedule\s*:/mu);
  assert.doesNotMatch(workflow, /^\s*container\s*:/mu);
  assert.doesNotMatch(workflow, /ubuntu-(?:latest|[0-9.]+)/u);
  assert.doesNotMatch(workflow, /APPWRITE_TEST_RECOVERY_API_KEY/u);
  assert.doesNotMatch(workflow, /repository:\s*Krowaccie\/AppWriteWork\s*$/imu);
  assert.doesNotMatch(workflow, /ref:\s*\$\{\{\s*inputs\.revision\s*\}\}/u);
  assert.doesNotMatch(workflow, /cancel-in-progress:\s*true/u);
  assert.doesNotMatch(workflow, /^\s*pattern:/mu);
  assert.equal((workflow.match(/test-cloud-controller\.mjs --hosted/gu) ?? []).length, 1);
  assert.doesNotMatch(workflow, /scripts\/verify\.mjs\s+--lane\s+test-cloud/iu);
});

test('inert test-cloud entrypoints cannot mint a vars-only trusted controller context', async () => {
  const controllerSource = await text(
    'packages/verification-controller/src/test-cloud-controller.mjs',
  );
  const preparationSource = await text(
    'packages/verification-controller/src/prepare-controller-artifact.mjs',
  );
  const workflow = await text(CONTROLLER_WORKFLOW);
  for (const value of [controllerSource, preparationSource, workflow]) {
    assert.doesNotMatch(value, /issueTrustedControllerContextForArtifactVerifier/u);
  }
  assert.match(preparationSource, /verifyGithubControllerArtifact/u);
  assert.match(workflow, /prepare-controller-artifact\.mjs/u);
  assert.match(
    workflow,
    /REQUIRED_CONTROLLER_ENTRYPOINT:\s*packages\/verification-controller\/workflows\/verify-test-cloud\.yml/u,
  );
  assert.match(controllerSource, /reattestLocalControllerArtifact/u);
});

test('Verify Test Cloud constructs and passes the production exact-SHA Git adapter', async () => {
  const preparationSource = await text(
    'packages/verification-controller/src/prepare-controller-artifact.mjs',
  );
  assert.match(
    preparationSource,
    /import \{ createProductionExactShaGitAdapter \} from '\.\/production-exact-sha-git-adapter\.mjs';/u,
  );
  assert.match(
    preparationSource,
    /createGit:\s*createProductionExactShaGitAdapter/u,
  );
  assert.match(
    preparationSource,
    /const git = runtime\.createGit\(\{\s*repositoryRoot: root,?\s*\}\);/u,
  );
  assert.match(
    preparationSource,
    /verifyGithubControllerArtifact\(Object\.freeze\(\{[\s\S]*?\}\), \{[\s\S]*?\bgit,?[\s\S]*?\}\);/u,
  );
  assert.doesNotMatch(preparationSource, /verifyGithubControllerArtifact\([^,]+\);/u);
});

test('controller bundle inventory is additive but ineligible until an exact committed tuple exists', async () => {
  const manifest = JSON.parse(await text(CONTROLLER_MANIFEST));
  assert.deepEqual(Object.keys(manifest).sort(), [
    'controllerRepository',
    'controllerRevision',
    'entrypoints',
    'files',
    'proposalStatus',
    'provenance',
    'schemaDigests',
    'schemaVersion',
    'seedSourceSets',
    'sourceRepository',
    'sourceRepositoryRevision',
    'trustMaterials',
  ]);
  assert.equal(manifest.schemaVersion, 'controller-bundle.proposal.v2');
  assert.equal(manifest.sourceRepository, 'Krowaccie/AppWriteWork');
  assert.equal(manifest.proposalStatus, 'BLOCKED_UNMATERIALIZED');
  assert.equal(manifest.sourceRepositoryRevision, 'UNMATERIALIZED');
  assert.equal(manifest.controllerRevision, 'UNMATERIALIZED');
  const paths = manifest.files.map((entry) => entry.path);
  assert.deepEqual(paths, [...paths].sort());
  assert.equal(new Set(paths).size, paths.length);
  for (const required of [
    'packages/verification-controller/src/appwrite-test-browser-policy.mjs',
    'packages/verification-controller/src/appwrite-test-live-readback.mjs',
    'packages/verification-controller/src/appwrite-test-setup-bindings.mjs',
    'packages/verification-controller/src/collect-appwrite-test-readback.mjs',
    'packages/verification-controller/src/test-cloud-binding-artifact-verifier.mjs',
    'packages/verification-controller/src/test-cloud-controller.mjs',
    'packages/verification-controller/src/release-production.mjs',
    'packages/verification-controller/src/run-production-readonly-playwright.mjs',
    'packages/verification-controller/workflows/collect-appwrite-test-readback.yml',
    'packages/verification-controller/workflows/verify-test-cloud.yml',
    'packages/verification-controller/workflows/release-production.yml',
    'packages/verification-controller/workflows/production-readonly.yml',
  ]) {
    assert.ok(paths.includes(required), `missing controller bundle file: ${required}`);
  }
  for (const entries of [manifest.entrypoints, manifest.files, manifest.schemaDigests]) {
    const entryPaths = entries.map((entry) => entry.path);
    assert.deepEqual(entryPaths, [...entryPaths].sort());
    assert.equal(new Set(entryPaths).size, entryPaths.length);
    for (const entry of entries) {
      assert.deepEqual(Object.keys(entry).sort(), ['path', 'sha256']);
      assert.equal(entry.sha256, 'UNMATERIALIZED');
    }
  }
  assert.deepEqual(manifest.trustMaterials.map(({ kind }) => kind), [
    'evaluator', 'evidenceValidator', 'networkPolicy', 'transcriptCorpus',
  ]);
  for (const record of [...manifest.trustMaterials, manifest.provenance]) {
    assert.equal(record.sha256, 'UNMATERIALIZED');
  }
  const validation = validateControllerBundleManifest(manifest);
  assert.equal(validation.status, 'BLOCKED');
  assert.equal(validation.value, null);
  assert.equal(validation.diagnostics[0].code, 'CONTROLLER_BUNDLE_INVALID');
});

test('controller setup is non-executing and preserves all protected lanes', async () => {
  const document = await text(CONTROLLER_SETUP);
  for (const required of [
    'Krowaccie/AppWriteWork-verification-control',
    'Krowaccie/AppWriteWork',
    'appwritework-verification-artifact-reader',
    'Actions: Read-only',
    'Metadata: Read-only',
    'SOURCE_ARTIFACT_READER_APP_ID',
    'SOURCE_ARTIFACT_READER_INSTALLATION_ID',
    'SOURCE_REPOSITORY_ID',
    'SOURCE_VERIFY_MAIN_WORKFLOW_ID',
    'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
    'appwrite-test',
    'controller-promotion',
    'production-readonly',
    'production-release',
    'APPWRITE_TEST_OPERATOR_API_KEY',
    'APPWRITE_TEST_FIXTURE_API_KEY',
    'APPWRITE_TEST_RECOVERY_API_KEY',
    'APPWRITE_PRODUCTION_READONLY_API_KEY',
    'APPWRITE_PRODUCTION_RELEASE_API_KEY',
    'TRUSTED_CONTROLLER_SHA',
    'TRUSTED_CONTROLLER_ARTIFACT_ID',
    'TRUSTED_CONTROLLER_BUNDLE_DIGEST',
    'required reviewers',
    'prevent self-review',
    'separate authority',
    'does not authorize',
    'BLOCKED_UNCOMMITTED_SOURCE',
    'UNMATERIALIZED',
    'CONTROLLER_BUNDLE_INVALID',
    'trusted hosted artifact launcher',
    'rollback',
    'readback',
  ]) {
    assert.ok(document.includes(required), `missing controller setup contract: ${required}`);
  }
});

test('Appwrite test setup is fail-closed until separately authorized exact schema readback', async () => {
  const document = await text(APPWRITE_SETUP);
  for (const required of [
    'verification_control',
    'verification_leases',
    'verification_intents',
    'verification_audit_events',
    'verification-runner-py',
    'execution.write',
    'rows.read',
    'rows.write',
    'users.read',
    'users.write',
    'three preprovisioned identities',
    'empty session sets',
    'provider schema contract',
    'schema readback digest',
    'must not be inferred',
    'BLOCKED',
    'separate authority',
    'node scripts/verification/test-cloud-setup-check.mjs --offline --inventory dev/verification/environments/test-cloud.inventory.v1.json',
  ]) {
    assert.ok(document.includes(required), `missing Appwrite setup contract: ${required}`);
  }
});

if (ordinaryLaneWorker) {
  try {
    parentPort.postMessage({
      status: 'PASS',
      value: await ordinaryLaneTerminalOutcome(),
    });
  } catch (error) {
    parentPort.postMessage({
      status: 'FAIL',
      error: error instanceof Error ? error.stack : String(error),
    });
  }
} else if (productionCompositionWorker) {
  try {
    parentPort.postMessage({
      status: 'PASS',
      value: await productionCompositionOutcome(workerData.mode),
    });
  } catch (error) {
    parentPort.postMessage({
      status: 'FAIL',
      error: error instanceof Error ? error.stack : String(error),
    });
  }
}
