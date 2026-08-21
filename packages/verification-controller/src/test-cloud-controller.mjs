import { createHash, randomBytes } from 'node:crypto';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isProxy } from 'node:util/types';

import { validateArtifactManifest } from '../../../scripts/verification/artifact-manifest.mjs';
import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { isTrustedControllerContext } from '../../../scripts/verification/controller-bundle.mjs';
import { validateHostedSiteBuildIdentity } from '../../../scripts/verification/hosted-site-build-identity.mjs';
import configuredInventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import {
  runTestCloudLane,
  validateTestCloudArtifactSet,
} from '../../../scripts/verification/test-cloud-lane.mjs';

const FULL_SHA = /^[0-9a-f]{40}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REPOSITORY_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const CONTROLLER_ENTRYPOINT =
  'packages/verification-controller/workflows/verify-test-cloud.yml';
const PLAYWRIGHT_IMAGE_DIGEST =
  'sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48';
const MAX_GITHUB_JSON_BYTES = 1024 * 1024;
const TEST_CLOUD_BINDING_NAMES = Object.freeze([
  'TEST_CLOUD_SETUP_READBACK_JSON',
  'TEST_CLOUD_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
]);
const SAFE_SOURCE_READER_DIAGNOSTIC_CODES = new Set([
  'SOURCE_ARTIFACT_DIGEST_MISMATCH',
  'SOURCE_ARTIFACT_DOWNLOAD_FAILED',
  'SOURCE_ARTIFACT_IDENTITY_MISMATCH',
  'SOURCE_ARTIFACT_LIST_FAILED',
  'SOURCE_ARTIFACT_MANIFEST_INVALID',
  'SOURCE_ARTIFACT_READER_INPUT_INVALID',
  'SOURCE_ARTIFACT_ZIP_UNSAFE',
  'SOURCE_APP_JWT_INPUT_INVALID',
  'SOURCE_APP_JWT_SIGN_FAILED',
  'SOURCE_INSTALLATION_TOKEN_CREATE_FAILED',
  'SOURCE_INSTALLATION_TOKEN_REVOCATION_FAILED',
  'SOURCE_INSTALLATION_TOKEN_SCOPE_MISMATCH',
  'SOURCE_REPOSITORY_IDENTITY_MISMATCH',
  'SOURCE_REPOSITORY_READ_FAILED',
  'SOURCE_RUN_IDENTITY_MISMATCH',
  'SOURCE_RUN_READ_FAILED',
  'SOURCE_WORKFLOW_IDENTITY_MISMATCH',
  'SOURCE_WORKFLOW_READ_FAILED',
  'PRODUCTION_HANDOFF_EXTRA_ARTIFACT',
  'PRODUCTION_RELEASE_SET_MISMATCH',
  'PRODUCTION_TEST_ONLY_SET_MISMATCH',
]);
const SAFE_PREFLIGHT_DIAGNOSTIC_CODES = new Set([
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
  'TEST_CLOUD_CLIENTS_INVALID',
  'TEST_CLOUD_CONTEXT_INVALID',
  'TEST_CLOUD_IDENTITY_BINDINGS_INVALID',
  'TEST_CLOUD_LANE_COMPOSITION_INVALID',
  'TEST_CLOUD_PROVIDER_CONTRACT_INVALID',
  'TEST_CLOUD_PROVIDER_STORE_INVALID',
  'TEST_CLOUD_RUNNER_VARIABLE_OPERATOR_INVALID',
  'TEST_CLOUD_RUNNER_VARIABLE_READBACK_INVALID',
  'TEST_CLOUD_RUNNER_VARIABLE_REQUEST_INVALID',
  'TEST_CLOUD_SETUP_ATTESTATION_INVALID',
  'TEST_CLOUD_SETUP_ENVIRONMENT_BINDING_INVALID',
  'TEST_CLOUD_SETUP_FINALIZATION_INVALID',
  'TEST_CLOUD_SETUP_IDENTITY_DIGEST_MISMATCH',
  'TEST_CLOUD_SETUP_IDENTITY_QUALIFICATION_INVALID',
  'TEST_CLOUD_SETUP_PAYLOAD_INVALID',
  'TEST_CLOUD_SETUP_PROVIDER_BINDING_INVALID',
  'TEST_CLOUD_SETUP_READBACK_INVALID',
  'TEST_CLOUD_SETUP_REQUEST_INVALID',
  'TEST_CLOUD_SETUP_RUNTIME_STATE_INVALID',
  'TEST_CLOUD_SITE_IDENTITY_READER_INVALID',
]);

const loadControllerReattestation = () =>
  import('./github-controller-artifact-verifier.mjs');
const loadProviderRuntime = () =>
  import('../../../scripts/verification/test-cloud-provider-contract.mjs');
const loadPlaywrightFacade = () =>
  import('./test-cloud-playwright-facade.mjs');
const loadScenarioDriver = () =>
  import('./test-cloud-scenario-driver.mjs');
const loadProcessContainment = () =>
  import('../../../scripts/verification/process-containment.mjs');
const loadSourceArtifactReader = () =>
  import('./source-artifact-reader.mjs');
const loadHostedSiteIdentity = () =>
  import('../../../scripts/verification/hosted-site-build-identity.mjs');
const loadTestEnvironment = () =>
  import('../../../scripts/verification/test-cloud-environment.mjs');
const loadTestCloudAppwrite = () =>
  import('../../../scripts/verification/test-cloud-appwrite-runtime.mjs');
const loadProviderControlStore = () =>
  import('../../../scripts/verification/test-cloud-provider-control-runtime.mjs');
const loadIdentityBindings = () =>
  import('../../../scripts/verification/test-cloud-identity-bindings.mjs');
const loadSetupCheck = () =>
  import('../../../scripts/verification/test-cloud-setup-check.mjs');
const loadSetupAttestation = () =>
  import('../../../scripts/verification/test-cloud-setup-attestation.mjs');
const loadHostedSetupAttestation = () =>
  import('../../../scripts/verification/test-cloud-hosted-setup-attestation.mjs');
const loadTestCloudPreflight = () =>
  import('../../../scripts/verification/test-cloud-preflight.mjs');
const loadTestCloudControlStore = () =>
  import('../../../scripts/verification/test-cloud-control-runtime.mjs');
const loadTestCloudFixtures = () =>
  import('../../../scripts/verification/test-cloud-fixtures.mjs');
const loadTestCloudDeploy = () =>
  import('../../../scripts/verification/test-cloud-deploy.mjs');
const loadEvidence = () => import('../../../scripts/verification/evidence.mjs');
const loadEvidenceWriter = () =>
  import('../../../scripts/verification/evidence-writer.mjs');
const RUNTIME_BOOTSTRAP_RESULT_KEYS = Object.freeze([
  'status',
  'value',
  'diagnostics',
]);
const RUNTIME_BOOTSTRAP_VALUE_KEYS = Object.freeze([
  'runtimeQualification',
  'browserScenarioQualification',
]);
const TEST_SETUP_ATTESTATION_KEYS = Object.freeze([
  'credentialScopeReadbackDigest',
  'environmentDigest',
  'executionObservationPolicyDigest',
  'expiresAtEpochSeconds',
  'fixedLeaseIdentityDigest',
  'functionConfigurationsDigest',
  'globalCleanupReadbackDigest',
  'identityBindingsDigest',
  'issuedAtEpochSeconds',
  'primaryExecutionRetentionMaxSeconds',
  'projectReadbackDigest',
  'providerContractDigest',
  'providerSetupReadbackDigest',
  'runnerVariableReadbackDigest',
  'schemaVersion',
  'siteConfigurationDigest',
].sort());
const ARTIFACT_SET_KEYS = Object.freeze([
  'artifactManifest',
  'artifactManifestDigest',
  'buildIdentity',
  'handoff',
  'releaseEligibleArtifacts',
  'testOnlyArtifacts',
].sort());
const ARTIFACT_KEYS = Object.freeze([
  'bytes',
  'canonicalContentDigest',
  'kind',
  'logicalTarget',
  'relativePath',
  'sizeBytes',
  'transportDigest',
].sort());

const ARGUMENT_KEYS = Object.freeze([
  'controller',
  'requestedRevision',
  'dependencies',
].sort());
const DEPENDENCY_KEYS = Object.freeze([
  'bootstrapRuntime',
  'createClients',
  'clock',
  'consumeHostedArtifact',
  'evidenceWriter',
  'resolveSourceSelection',
  'runLane',
].sort());
const CLOCK_KEYS = Object.freeze(['now']);
const EVIDENCE_WRITER_KEYS = Object.freeze(['write']);
const CONTROLLER_RESULT_KEYS = Object.freeze(['diagnostics', 'status', 'value']);
const HOSTED_ARGUMENT_KEYS = Object.freeze(['dependencies', 'environment', 'request'].sort());
const HOSTED_REQUEST_KEYS = Object.freeze([
  'requestedRevision',
  'sourceRunAttempt',
  'sourceRunId',
].sort());
const HOSTED_SOURCE_SNAPSHOT_KEYS = Object.freeze(['artifactSet', 'selection'].sort());
const HOSTED_DEPENDENCY_KEYS = Object.freeze([
  'bootstrapRuntime',
  'createOrdinaryLane',
  'createPlaywrightFacade',
  'qualifyContainment',
  'consumeSourceArtifact',
  'reattestController',
  'runLane',
  'validateSetupBindings',
  'validateSourceArtifact',
].sort());
const ORDINARY_CREDENTIAL_NAMES = Object.freeze([
  'APPWRITE_TEST_OPERATOR_API_KEY',
  'APPWRITE_TEST_FIXTURE_API_KEY',
  'E2E_OWNER_EMAIL',
  'E2E_OWNER_PASSWORD',
  'E2E_EDITOR_EMAIL',
  'E2E_EDITOR_PASSWORD',
  'E2E_VIEWER_EMAIL',
  'E2E_VIEWER_PASSWORD',
]);
const ORDINARY_CREDENTIAL_SCOPES = Object.freeze({
  APPWRITE_TEST_OPERATOR_API_KEY: Object.freeze([
    'execution.write',
    'functions.read',
    'functions.write',
    'sites.read',
    'sites.write',
  ]),
  APPWRITE_TEST_FIXTURE_API_KEY: Object.freeze([
    'rows.read',
    'rows.write',
    'users.read',
    'users.write',
  ]),
});
const SELECTION_KEYS = Object.freeze([
  'repository',
  'workflow',
  'workflowRunId',
  'workflowRunAttempt',
  'sourceRef',
  'sourceRevision',
  'artifactId',
  'artifactName',
  'archiveDigest',
].sort());
const PRODUCTION_LANE_ARGUMENT_KEYS = Object.freeze([
  'artifactSet',
  'clock',
  'controller',
  'evidenceWriter',
  'facade',
  'operations',
  'selection',
].sort());
const PRODUCTION_LANE_OPERATION_KEYS = Object.freeze([
  'acquireLease',
  'cleanup',
  'closeLease',
  'deployFunctionArtifacts',
  'deploySiteArtifact',
  'preflight',
  'proveAbsence',
  'qualifyRunner',
  'runTrustedScenario',
].sort());
const PRODUCTION_FACADE_KEYS = Object.freeze([
  'facade',
  'scenarioIds',
  'scenarioInventoryDigest',
].sort());

function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || seen.has(value)
  ) return value;
  if (ArrayBuffer.isView(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function validArtifact(value) {
  return exactDataObject(value, ARTIFACT_KEYS)
    && ['site', 'function'].includes(value.kind)
    && typeof value.logicalTarget === 'string'
    && SAFE_ID.test(value.logicalTarget)
    && typeof value.relativePath === 'string'
    && !value.relativePath.includes('..')
    && !value.relativePath.includes('\\')
    && value.bytes instanceof Uint8Array
    && value.bytes.byteLength > 0
    && value.sizeBytes === value.bytes.byteLength
    && DIGEST.test(value.canonicalContentDigest)
    && DIGEST.test(value.transportDigest)
    && digestBytes(value.bytes) === value.transportDigest;
}

export function validateArtifactSetOutput(value, selection) {
  try {
    if (
      !exactDataObject(value, ARTIFACT_SET_KEYS)
      || !validSelection(selection, selection?.sourceRevision)
      || !Array.isArray(value.releaseEligibleArtifacts)
      || value.releaseEligibleArtifacts.length !== 36
      || !Array.isArray(value.testOnlyArtifacts)
      || value.testOnlyArtifacts.length !== 1
      || !value.releaseEligibleArtifacts.every(validArtifact)
      || !value.testOnlyArtifacts.every(validArtifact)
      || value.testOnlyArtifacts[0].kind !== 'function'
      || value.testOnlyArtifacts[0].logicalTarget !== 'verification-runner-py'
      || value.testOnlyArtifacts[0].relativePath !== 'functions/verification-runner-py.tar.gz'
      || !validateArtifactManifest(value.artifactManifest).ok
      || value.artifactManifest.sourceRevision !== selection.sourceRevision
      || value.artifactManifest.artifactManifestDigest !== value.artifactManifestDigest
      || !validateHostedSiteBuildIdentity(value.buildIdentity).ok
      || value.buildIdentity.sourceRevision !== selection.sourceRevision
      || value.buildIdentity.verifierManifestDigest !== value.artifactManifest.verifierManifestDigest
    ) return false;
    const handoff = value.handoff;
    if (
      handoff?.schemaVersion !== 'artifact-handoff.v1'
      || handoff.sourceRepository !== selection.repository
      || handoff.sourceWorkflow !== selection.workflow
      || handoff.sourceWorkflowRunId !== selection.workflowRunId
      || handoff.sourceWorkflowRunAttempt !== selection.workflowRunAttempt
      || handoff.sourceRef !== selection.sourceRef
      || handoff.sourceRevision !== selection.sourceRevision
      || handoff.artifactName !== selection.artifactName
      || handoff.artifactManifestDigest !== value.artifactManifestDigest
      || handoff.verifierManifestDigest !== value.artifactManifest.verifierManifestDigest
    ) return false;
    const artifacts = [...value.releaseEligibleArtifacts, ...value.testOnlyArtifacts];
    const byIdentity = new Map(artifacts.map((artifact) => [
      `${artifact.kind}\0${artifact.logicalTarget}`,
      artifact,
    ]));
    if (byIdentity.size !== artifacts.length || value.artifactManifest.artifacts.length !== artifacts.length) {
      return false;
    }
    for (const entry of value.artifactManifest.artifacts) {
      const artifact = byIdentity.get(`${entry.kind}\0${entry.logicalTarget}`);
      if (
        artifact === undefined
        || artifact.relativePath !== entry.relativePath
        || artifact.canonicalContentDigest !== entry.canonicalContentDigest
        || artifact.transportDigest !== entry.transportDigest
        || artifact.sizeBytes !== entry.sizeBytes
      ) return false;
    }
    const sites = value.releaseEligibleArtifacts.filter(({ kind }) => kind === 'site');
    if (!(sites.length === 1
      && sites[0].logicalTarget === 'web'
      && sites[0].relativePath === 'site/site.tar.gz'
      && sites[0].canonicalContentDigest === value.buildIdentity.sitePayloadDigest)) return false;
    return validateTestCloudArtifactSet(value, selection).status === 'PASS';
  } catch {
    return false;
  }
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

function exactFrozenNullDataRecord(value, expectedKeys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || isProxy(value)
      || Object.getPrototypeOf(value) !== null
      || Object.isFrozen(value) !== true
    ) return false;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== expectedKeys.length
      || keys.some((key, index) => key !== expectedKeys[index])
    ) return false;
    return expectedKeys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined
        && Object.hasOwn(descriptor, 'value')
        && descriptor.enumerable === true
        && descriptor.configurable === false
        && descriptor.writable === false;
    });
  } catch {
    return false;
  }
}

function exactFrozenEmptyArray(value) {
  try {
    if (
      isProxy(value)
      || !Array.isArray(value)
      || Object.getPrototypeOf(value) !== Array.prototype
      || Object.isFrozen(value) !== true
    ) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 1 || keys[0] !== 'length') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, 'length');
    return descriptor !== undefined
      && descriptor.value === 0
      && descriptor.enumerable === false
      && descriptor.configurable === false
      && descriptor.writable === false;
  } catch {
    return false;
  }
}

function validRuntimeBootstrapPass(value) {
  try {
    if (!exactFrozenNullDataRecord(value, RUNTIME_BOOTSTRAP_RESULT_KEYS)) {
      return false;
    }
    const status = Object.getOwnPropertyDescriptor(value, 'status').value;
    const runtimeValue = Object.getOwnPropertyDescriptor(value, 'value').value;
    const diagnostics = Object.getOwnPropertyDescriptor(value, 'diagnostics').value;
    if (
      status !== 'PASS'
      || !exactFrozenEmptyArray(diagnostics)
      || !exactFrozenNullDataRecord(runtimeValue, RUNTIME_BOOTSTRAP_VALUE_KEYS)
    ) return false;
    const runtimeQualification = Object.getOwnPropertyDescriptor(
      runtimeValue,
      'runtimeQualification',
    ).value;
    const browserScenarioQualification = Object.getOwnPropertyDescriptor(
      runtimeValue,
      'browserScenarioQualification',
    ).value;
    return exactFrozenNullDataRecord(runtimeQualification, [])
      && exactFrozenNullDataRecord(browserScenarioQualification, [])
      && runtimeQualification !== browserScenarioQualification;
  } catch {
    return false;
  }
}

function result(status, value, code = null, retryable = false) {
  const messages = {
    TRUSTED_CONTROLLER_REQUIRED: 'A protected immutable controller is required.',
    SOURCE_RUN_NOT_GREEN: 'No exact successful Verify Main run was selected.',
    SOURCE_ARTIFACT_INVALID: 'The selected source artifact failed the trusted handoff checks.',
    TEST_CLOUD_PREFLIGHT_BLOCKED: 'The protected test-cloud client boundary could not be constructed.',
    TEST_CLOUD_SETUP_INCOMPLETE: 'The protected test-cloud containment and provider setup is incomplete.',
  };
  const safeMessage = SAFE_SOURCE_READER_DIAGNOSTIC_CODES.has(code)
    ? messages.SOURCE_ARTIFACT_INVALID
    : SAFE_PREFLIGHT_DIAGNOSTIC_CODES.has(code)
      ? messages.TEST_CLOUD_PREFLIGHT_BLOCKED
      : messages[code];
  return deepFreeze({
    status,
    value,
    diagnostics: code === null
      ? []
      : [{
        code,
        safeMessage,
        retryable,
      }],
  });
}

function dependencyError() {
  const error = new TypeError('Test-cloud controller dependencies are invalid');
  error.code = 'CONTROLLER_DEPENDENCIES_INVALID';
  return error;
}

function validControllerResult(value) {
  if (
    !exactDataObject(value, CONTROLLER_RESULT_KEYS)
    || !['PASS', 'FAIL', 'BLOCKED'].includes(value.status)
    || !Array.isArray(value.diagnostics)
  ) return false;
  if (value.status === 'PASS') {
    return value.value !== undefined && value.diagnostics.length === 0;
  }
  return value.value === null && value.diagnostics.length > 0;
}

function retryable(outcome) {
  return outcome?.diagnostics?.some((diagnostic) => diagnostic?.retryable === true) === true;
}

function validHostedRequest(value) {
  return exactDataObject(value, HOSTED_REQUEST_KEYS)
    && typeof value.requestedRevision === 'string'
    && FULL_SHA.test(value.requestedRevision)
    && typeof value.sourceRunId === 'string'
    && SAFE_ID.test(value.sourceRunId)
    && Number.isSafeInteger(value.sourceRunAttempt)
    && value.sourceRunAttempt > 0;
}

function validHostedDependencies(value) {
  return exactDataObject(value, HOSTED_DEPENDENCY_KEYS)
    && HOSTED_DEPENDENCY_KEYS.every((name) => typeof value[name] === 'function');
}

function validHostedSourceSnapshot(value, request) {
  return exactDataObject(value, HOSTED_SOURCE_SNAPSHOT_KEYS)
    && validSelection(value.selection, request.requestedRevision)
    && value.selection.workflowRunId === request.sourceRunId
    && value.selection.workflowRunAttempt === request.sourceRunAttempt
    && validateArtifactSetOutput(value.artifactSet, value.selection);
}

export function selectSafeDiagnosticCode(outcome, fallback, safeDiagnosticCodes) {
  const outcomeCode = outcome?.diagnostics?.[0]?.code;
  return safeDiagnosticCodes instanceof Set && safeDiagnosticCodes.has(outcomeCode)
    ? outcomeCode
    : fallback;
}

export function selectSafePreflightDiagnosticCode(
  outcome,
  fallback = 'TEST_CLOUD_PREFLIGHT_BLOCKED',
) {
  return selectSafeDiagnosticCode(outcome, fallback, SAFE_PREFLIGHT_DIAGNOSTIC_CODES);
}

async function hostedStage(method, request, code, safeDiagnosticCodes = null) {
  try {
    const outcome = await method(deepFreeze(request));
    if (!validControllerResult(outcome) || outcome.status !== 'PASS') {
      const selectedCode = selectSafeDiagnosticCode(
        outcome,
        code,
        safeDiagnosticCodes,
      );
      return result('BLOCKED', null, selectedCode, retryable(outcome));
    }
    return outcome;
  } catch {
    return result('BLOCKED', null, code);
  }
}

function readCredential(environment, name) {
  const value = environment?.[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function readEnvironmentValue(environment, name) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(environment, name);
    return descriptor !== undefined
      && Object.hasOwn(descriptor, 'value')
      && typeof descriptor.value === 'string'
      ? descriptor.value
      : null;
  } catch {
    return null;
  }
}

function positiveInteger(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function sourceReaderConfiguration(environment) {
  const appId = readEnvironmentValue(environment, 'SOURCE_ARTIFACT_READER_APP_ID');
  const installationId = readEnvironmentValue(
    environment,
    'SOURCE_ARTIFACT_READER_INSTALLATION_ID',
  );
  const sourceRepositoryId = positiveInteger(
    readEnvironmentValue(environment, 'SOURCE_REPOSITORY_ID'),
  );
  const sourceWorkflowId = positiveInteger(
    readEnvironmentValue(environment, 'SOURCE_VERIFY_MAIN_WORKFLOW_ID'),
  );
  if (
    positiveInteger(appId) === null
    || positiveInteger(installationId) === null
    || sourceRepositoryId === null
    || sourceWorkflowId === null
  ) return null;
  return Object.freeze({ appId, installationId, sourceRepositoryId, sourceWorkflowId });
}

function sourceArtifactDownloadFailure() {
  const error = new Error('The source artifact download failed its closed transport contract.');
  error.code = 'SOURCE_ARTIFACT_DOWNLOAD_FAILED';
  return error;
}

function trustedArtifactRedirect(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 8192) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:'
      || url.username !== ''
      || url.password !== ''
      || url.port !== ''
      || url.hash !== ''
      || url.search.length < 2
      || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.blob\.core\.windows\.net$/u
        .test(url.hostname)
    ) return null;
    return url.href;
  } catch {
    return null;
  }
}

export async function githubSourceRequest(fetchImpl, requestPath, options = {}) {
  if (typeof fetchImpl !== 'function' || typeof requestPath !== 'string') {
    throw new TypeError('GitHub source request is invalid.');
  }
  if (Number.isSafeInteger(options.expectedBytes)) {
    try {
      let response = await fetchImpl(`https://api.github.com${requestPath}`, {
        method: options.method,
        headers: options.headers,
        body: options.body,
        redirect: 'manual',
      });
      if (response?.status === 302) {
        const location = typeof response.headers?.get === 'function'
          ? response.headers.get('location')
          : null;
        const redirectUrl = trustedArtifactRedirect(location);
        if (redirectUrl === null) throw sourceArtifactDownloadFailure();
        response = await fetchImpl(redirectUrl, {
          method: 'GET',
          headers: { Accept: 'application/octet-stream' },
          redirect: 'error',
        });
      }
      const { readBoundedSourceArtifactArchive } = await loadSourceArtifactReader();
      return Object.freeze({
        status: response.status,
        bytes: await readBoundedSourceArtifactArchive(response, options.expectedBytes),
      });
    } catch (error) {
      if (error?.code === 'SOURCE_ARTIFACT_DOWNLOAD_FAILED') throw error;
      throw sourceArtifactDownloadFailure();
    }
  }
  const response = await fetchImpl(`https://api.github.com${requestPath}`, {
    method: options.method,
    headers: options.headers,
    body: options.body,
    redirect: options.redirect ?? 'error',
  });
  if (response.status === 204) return Object.freeze({ status: 204, body: null });
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength < 2 || bytes.byteLength > MAX_GITHUB_JSON_BYTES) {
    throw new TypeError('GitHub source response is outside the bounded JSON contract.');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return Object.freeze({ status: response.status, body: JSON.parse(text) });
}

function parseSourceJson(files, relativePath) {
  const bytes = files.get(relativePath);
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Source artifact JSON is absent.');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function artifactFromSource(entry, files) {
  const bytes = files.get(entry.relativePath);
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Source artifact member is absent.');
  return {
    bytes: new Uint8Array(bytes),
    canonicalContentDigest: entry.canonicalContentDigest,
    kind: entry.kind,
    logicalTarget: entry.logicalTarget,
    relativePath: entry.relativePath,
    sizeBytes: entry.sizeBytes,
    transportDigest: entry.transportDigest,
  };
}

async function validatedSourceArtifact(source) {
  const { createHostedSiteBuildIdentity } = await loadHostedSiteIdentity();
  const artifactManifest = parseSourceJson(source.files, 'artifact-manifest.v1.json');
  const handoff = parseSourceJson(source.files, 'artifact-handoff.v1.json');
  const releaseEligibleArtifacts = source.releaseEligibleArtifacts
    .map((entry) => artifactFromSource(entry, source.files))
    .sort((left, right) => {
      if (left.kind === 'site') return -1;
      if (right.kind === 'site') return 1;
      return left.logicalTarget < right.logicalTarget ? -1
        : left.logicalTarget > right.logicalTarget ? 1 : 0;
    });
  const testOnlyArtifacts = source.testOnlyArtifacts
    .map((entry) => artifactFromSource(entry, source.files));
  const site = releaseEligibleArtifacts[0];
  const artifactSet = {
    artifactManifest,
    artifactManifestDigest: source.artifactManifestDigest,
    buildIdentity: createHostedSiteBuildIdentity({
      schemaVersion: 'hosted-site-build-identity.v1',
      sourceRevision: source.sourceRevision,
      sitePayloadDigest: site.canonicalContentDigest,
      verifierManifestDigest: source.verifierManifestDigest,
    }),
    handoff,
    releaseEligibleArtifacts,
    testOnlyArtifacts,
  };
  const selection = {
    repository: 'Krowaccie/AppWriteWork',
    workflow: 'Verify Main',
    workflowRunId: String(source.sourceRunId),
    workflowRunAttempt: source.sourceRunAttempt,
    sourceRef: 'refs/heads/main',
    sourceRevision: source.sourceRevision,
    artifactId: String(source.sourceArtifactId),
    artifactName: source.sourceArtifactName,
    archiveDigest: source.sourceArchiveDigest,
  };
  if (!validateArtifactSetOutput(artifactSet, selection)) {
    throw new TypeError('Source artifact failed the exact lane contract.');
  }
  return deepFreeze({ artifactSet, selection });
}

function parseCanonicalJsonBinding(environment, jsonName, digestName) {
  try {
    const json = readEnvironmentValue(environment, jsonName);
    const expectedDigest = readEnvironmentValue(environment, digestName);
    if (
      typeof json !== 'string'
      || json.length < 2
      || Buffer.byteLength(json, 'utf8') > MAX_GITHUB_JSON_BYTES
      || typeof expectedDigest !== 'string'
      || !DIGEST.test(expectedDigest)
    ) return null;
    const value = JSON.parse(json);
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || digestBytes(new TextEncoder().encode(canonicalJson(value))) !== expectedDigest
    ) return null;
    return deepFreeze({ digest: expectedDigest, value });
  } catch {
    return null;
  }
}

function ordinaryCredentialHandle(configured, secret) {
  let handle;
  handle = Object.freeze({
    credentialClass: configured.credentialClass,
    variableName: configured.variableName,
    scopes: Object.freeze([...configured.scopes]),
    readSecret() {
      if (this !== handle) throw new TypeError('Credential handle receiver is invalid.');
      return secret;
    },
  });
  return handle;
}

function productionClock() {
  return Object.freeze({
    now: () => new Date().toISOString(),
    nowEpochSeconds: () => Math.floor(Date.now() / 1000),
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  });
}

function blockedFrom(outcome, code = 'TEST_CLOUD_PREFLIGHT_BLOCKED') {
  return outcome?.status === 'PASS'
    ? outcome
    : result('BLOCKED', null, code, retryable(outcome));
}

function scenarioFailure(status, state) {
  return deepFreeze({
    status,
    value: state,
    diagnostics: [{
      code: 'TRUSTED_SCENARIO_EXECUTION_FAILED',
      safeMessage: 'A trusted test-cloud scenario did not pass.',
      retryable: false,
    }],
  });
}

export function composeProductionTestCloudLane(args) {
  if (
    !exactDataObject(args, PRODUCTION_LANE_ARGUMENT_KEYS)
    || !exactDataObject(args.operations, PRODUCTION_LANE_OPERATION_KEYS)
    || PRODUCTION_LANE_OPERATION_KEYS.some(
      (name) => typeof args.operations[name] !== 'function',
    )
    || !exactDataObject(args.facade, PRODUCTION_FACADE_KEYS)
    || typeof args.facade.facade?.runExactScenario !== 'function'
    || !Array.isArray(args.facade.scenarioIds)
    || args.facade.scenarioIds.length !== 6
    || new Set(args.facade.scenarioIds).size !== 6
    || typeof args.facade.scenarioInventoryDigest !== 'string'
    || !DIGEST.test(args.facade.scenarioInventoryDigest)
    || !exactDataObject(args.clock, CLOCK_KEYS)
    || typeof args.clock.now !== 'function'
    || !exactDataObject(args.evidenceWriter, EVIDENCE_WRITER_KEYS)
    || typeof args.evidenceWriter.write !== 'function'
  ) return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');

  const runE2E = async (request) => {
    let trusted;
    try {
      trusted = await args.operations.runTrustedScenario(request);
    } catch {
      return scenarioFailure('BLOCKED', null);
    }
    if (
      trusted?.status !== 'PASS'
      || trusted.value?.lease === undefined
      || trusted.value?.capability === undefined
    ) return trusted;
    const state = Object.freeze({
      lease: trusted.value.lease,
      capability: trusted.value.capability,
    });
    const controllerBinding = Object.freeze({
      controllerBundleDigest: args.controller.controllerBundleDigest,
      controllerRevision: args.controller.controllerBundleSha,
      playwrightImageDigest: PLAYWRIGHT_IMAGE_DIGEST,
      scenarioInventoryDigest: args.facade.scenarioInventoryDigest,
    });
    try {
      for (const scenarioId of args.facade.scenarioIds) {
        const outcome = await args.facade.facade.runExactScenario({
          controllerBinding,
          scenarioId,
          timeoutMs: 300_000,
        });
        if (outcome.status !== 'PASS') return scenarioFailure('FAIL', state);
      }
    } catch {
      return scenarioFailure('BLOCKED', state);
    }
    return result('PASS', { ...state, passed: true });
  };

  return result('PASS', Object.freeze({
    controller: args.controller,
    selection: args.selection,
    artifactSet: args.artifactSet,
    clients: Object.freeze({
      preflight: args.operations.preflight,
      acquireLease: args.operations.acquireLease,
      deployFunctionArtifacts: args.operations.deployFunctionArtifacts,
      deploySiteArtifact: args.operations.deploySiteArtifact,
      qualifyRunner: args.operations.qualifyRunner,
      runE2E,
      cleanup: args.operations.cleanup,
      proveAbsence: args.operations.proveAbsence,
      closeLease: args.operations.closeLease,
    }),
    clock: args.clock,
    evidenceWriter: args.evidenceWriter,
  }));
}

export function createProductionHostedDependencies(args) {
  if (args === null || typeof args !== 'object') throw dependencyError();
  const hasControllerArtifactIo = Object.hasOwn(args, 'controllerArtifactIo');
  const hasContainedProcessTransport = Object.hasOwn(args, 'runContainedProcessImpl');
  const expectedKeys = ['environment', 'fetchImpl'];
  if (hasControllerArtifactIo) expectedKeys.push('controllerArtifactIo');
  if (hasContainedProcessTransport) expectedKeys.push('runContainedProcessImpl');
  expectedKeys.sort();
  if (!exactDataObject(args, expectedKeys)) throw dependencyError();
  if (
    args.environment === null
    || typeof args.environment !== 'object'
    || typeof args.fetchImpl !== 'function'
    || (hasControllerArtifactIo && (
      !exactDataObject(args.controllerArtifactIo, ['lstat', 'readFile', 'realpath', 'root'])
      || typeof args.controllerArtifactIo.root !== 'string'
      || typeof args.controllerArtifactIo.lstat !== 'function'
      || typeof args.controllerArtifactIo.readFile !== 'function'
      || typeof args.controllerArtifactIo.realpath !== 'function'
    ))
    || (hasContainedProcessTransport
      && typeof args.runContainedProcessImpl !== 'function')
  ) throw dependencyError();

  const { environment, fetchImpl } = args;
  const controllerArtifactIo = hasControllerArtifactIo
    ? Object.freeze({ ...args.controllerArtifactIo })
    : undefined;
  const runContainedProcessImpl = hasContainedProcessTransport
    ? args.runContainedProcessImpl
    : async (options) => {
      const { runContainedProcess } = await loadProcessContainment();
      return runContainedProcess(options);
    };
  const clock = productionClock();
  let admittedCredentials = null;

  const dependencies = {
    async reattestController() {
      const { reattestLocalControllerArtifact } = await loadControllerReattestation();
      return reattestLocalControllerArtifact({
        artifactId: readEnvironmentValue(environment, 'PROOF_ARTIFACT_ID'),
        bundleDigest: readEnvironmentValue(environment, 'PROOF_BUNDLE_DIGEST'),
        proofRepository: readEnvironmentValue(environment, 'PROOF_REPOSITORY'),
        proofSha: readEnvironmentValue(environment, 'PROOF_SHA'),
        proofStatus: readEnvironmentValue(environment, 'PROOF_STATUS'),
        repository: readEnvironmentValue(environment, 'GITHUB_REPOSITORY'),
        requiredEntrypoint: CONTROLLER_ENTRYPOINT,
        runtimeSha: readEnvironmentValue(environment, 'GITHUB_SHA'),
        trustedArtifactId: readEnvironmentValue(
          environment,
          'TRUSTED_CONTROLLER_ARTIFACT_ID',
        ),
        trustedBundleDigest: readEnvironmentValue(
          environment,
          'TRUSTED_CONTROLLER_BUNDLE_DIGEST',
        ),
        trustedSha: readEnvironmentValue(environment, 'TRUSTED_CONTROLLER_SHA'),
      }, controllerArtifactIo);
    },

    async validateSetupBindings(stage) {
      const providerReadback = parseCanonicalJsonBinding(
        environment,
        'TEST_CLOUD_SETUP_READBACK_JSON',
        'TEST_CLOUD_SETUP_READBACK_DIGEST',
      );
      const providerAttestation = parseCanonicalJsonBinding(
        environment,
        'TEST_CLOUD_SETUP_ATTESTATION_JSON',
        'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
      );
      const hostedReadback = parseCanonicalJsonBinding(
        environment,
        'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
        'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
      );
      const hostedAttestation = parseCanonicalJsonBinding(
        environment,
        'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
        'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
      );
      const sourceConfiguration = sourceReaderConfiguration(environment);
      if (
        providerReadback === null
        || providerAttestation === null
        || hostedReadback === null
        || hostedAttestation === null
        || sourceConfiguration === null
        || !exactDataObject(providerAttestation.value, TEST_SETUP_ATTESTATION_KEYS)
      ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');

      const [setupCheck, setupAttestation, hostedSetupAttestation, provider] = await Promise.all([
        loadSetupCheck(),
        loadSetupAttestation(),
        loadHostedSetupAttestation(),
        loadProviderRuntime(),
      ]);
      const providerValidated = provider.validateTestCloudSetupReadbackBytes({
        bytes: new TextEncoder().encode(canonicalJson(providerReadback.value)),
        expectedDigest: providerReadback.digest,
        expectedEnvironmentDigest: providerReadback.value.environmentDigest,
        expectedProviderContractDigest: configuredInventory.providerContractDigest,
      });
      if (providerValidated.status !== 'PASS') {
        return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
      }
      const observation = setupCheck.qualifyExecutionObservationReadback({
        inventory: configuredInventory,
        readback: hostedReadback.value.executionObservation,
        expectedReadbackDigest: digestBytes(new TextEncoder().encode(
          canonicalJson(hostedReadback.value.executionObservation),
        )),
      });
      if (observation.status !== 'PASS') {
        return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
      }
      const checked = setupCheck.checkTestCloudSetup({
        inventory: configuredInventory,
        readback: hostedReadback.value,
        expectedProviderSchemaDigest: configuredInventory.providerContractDigest,
        executionObservationQualification: observation.value,
      });
      if (
        checked.status !== 'PASS'
        || checked.value.controllerBundleSha !== stage.controller.controllerBundleSha
        || checked.value.controllerBundleDigest !== stage.controller.controllerBundleDigest
      ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
      const providerAttested = setupAttestation.validateTestCloudSetupAttestationDocument({
        attestation: providerAttestation.value,
        attestationDigest: providerAttestation.digest,
        clock,
        expectedEnvironmentDigest: providerReadback.value.environmentDigest,
        expectedIdentityBindingsDigest:
          providerReadback.value.identityBindings.identityBindingsDigest,
        expectedPrimaryExecutionRetentionMaxSeconds:
          checked.value.primaryExecutionRetentionMaxSeconds,
        expectedProviderContractDigest: configuredInventory.providerContractDigest,
        expectedProviderSetupReadbackDigest: providerReadback.digest,
        maximumRetentionSeconds: configuredInventory.control.primaryExecutionRetentionMaxSeconds,
      });
      const hostedAttested = hostedSetupAttestation
        .validateTestCloudHostedSetupAttestationDocument({
          attestation: hostedAttestation.value,
          attestationDigest: hostedAttestation.digest,
          clock,
          expectedExecutionObservationPolicyDigest:
            checked.value.executionObservationPolicyDigest,
          expectedHostedSetupReadbackDigest: hostedReadback.digest,
          expectedPrimaryExecutionRetentionMaxSeconds:
            checked.value.primaryExecutionRetentionMaxSeconds,
          expectedProviderSetupReadbackDigest: providerReadback.digest,
        });
      if (providerAttested.status !== 'PASS' || hostedAttested.status !== 'PASS') {
        return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
      }
      return result('PASS', deepFreeze({
        attestation: providerAttested.value,
        attestationDigest: providerAttestation.digest,
        executionObservationQualification: observation.value,
        hostedAttestation: hostedAttested.value,
        hostedAttestationDigest: hostedAttestation.digest,
        hostedReadback: hostedReadback.value,
        hostedReadbackDigest: hostedReadback.digest,
        readback: providerReadback.value,
        readbackDigest: providerReadback.digest,
        sourceConfiguration,
      }));
    },

    async bootstrapRuntime() {
      const provider = await loadProviderRuntime();
      const outcome = await provider.bootstrapRuntime();
      return validRuntimeBootstrapPass(outcome)
        ? outcome
        : result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
    },

    async createPlaywrightFacade() {
      const [playwright, scenario] = await Promise.all([
        loadPlaywrightFacade(),
        loadScenarioDriver(),
      ]);
      const launcher = Object.freeze({
        async runPlaywrightScenario(request) {
          if (admittedCredentials === null) {
            throw new Error('Ordinary credentials have not been admitted.');
          }
          const childEnvironment = Object.create(null);
          const childCredentialNames = request.scenarioId === 'auth'
            ? ['E2E_OWNER_EMAIL', 'E2E_OWNER_PASSWORD']
            : [];
          for (const name of childCredentialNames) {
            childEnvironment[name] = admittedCredentials[name];
          }
          const contained = await runContainedProcessImpl({
            executable: process.execPath,
            args: [
              'packages/verification-controller/src/test-cloud-contained-scenario-launcher.mjs',
              '--scenario-id',
              request.scenarioId,
              '--controller-revision',
              request.controllerBinding.controllerRevision,
              '--controller-bundle-digest',
              request.controllerBinding.controllerBundleDigest,
              '--playwright-image-digest',
              request.controllerBinding.playwrightImageDigest,
              '--scenario-inventory-digest',
              request.scenarioInventoryDigest,
            ],
            cwd: REPOSITORY_ROOT,
            env: childEnvironment,
            timeoutMs: request.timeoutMs,
            maxOutputBytes: request.stdoutLimitBytes + request.stderrLimitBytes,
          });
          return Object.freeze({
            exitCode: contained.exitCode,
            stderr: new TextEncoder().encode(contained.stderr),
            stdout: new TextEncoder().encode(contained.stdout),
            timedOut: contained.status === 'timed-out',
          });
        },
      });
      return result('PASS', deepFreeze({
        facade: playwright.createTestCloudPlaywrightFacade({
          launcher,
          scenarioDrivers: scenario.createTestCloudScenarioDrivers(),
        }),
        testCloudScenarioInventory: playwright.testCloudScenarioInventory,
        testCloudScenarioInventoryDigest: playwright.testCloudScenarioInventoryDigest,
      }));
    },

    async qualifyContainment() {
      const marker = 'APPWRITEWORK_WINDOWS_JOB_OBJECT_QUALIFIED';
      const contained = await runContainedProcessImpl({
        executable: process.execPath,
        args: ['--eval', `process.stdout.write(${JSON.stringify(marker)})`],
        cwd: REPOSITORY_ROOT,
        env: Object.create(null),
        timeoutMs: 30_000,
        maxOutputBytes: 4_096,
      });
      if (
        contained.status !== 'exited'
        || contained.exitCode !== 0
        || contained.stdout !== marker
        || contained.stderr !== ''
      ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');
      return result('PASS', Object.freeze({ qualified: true }));
    },

    async consumeSourceArtifact(stage) {
      const { extractSourceArtifactZip, readSourceArtifact } = await loadSourceArtifactReader();
      const configuration = sourceReaderConfiguration(environment);
      if (configuration === null) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
      try {
        return result('PASS', await readSourceArtifact({
          config: configuration,
          revision: stage.request.requestedRevision,
          qualifyingRunId: stage.request.sourceRunId,
          runAttempt: stage.request.sourceRunAttempt,
          privateKey: stage.privateKey,
          request: (requestPath, options) => githubSourceRequest(
            fetchImpl,
            requestPath,
            options,
          ),
          readZip: extractSourceArtifactZip,
        }));
      } catch (error) {
        const code = typeof error?.code === 'string'
          && SAFE_SOURCE_READER_DIAGNOSTIC_CODES.has(error.code)
          ? error.code
          : 'SOURCE_ARTIFACT_INVALID';
        return result('BLOCKED', null, code);
      }
    },

    async validateSourceArtifact(stage) {
      try {
        return result('PASS', await validatedSourceArtifact(stage.sourceArtifact));
      } catch {
        return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
      }
    },

    async createOrdinaryLane(stage) {
      admittedCredentials = stage.credentials;
      const credentialHandles = Object.freeze({
        fixture: ordinaryCredentialHandle(
          configuredInventory.credentialVariables.fixture,
          stage.credentials.APPWRITE_TEST_FIXTURE_API_KEY,
        ),
        operator: ordinaryCredentialHandle(
          configuredInventory.credentialVariables.operator,
          stage.credentials.APPWRITE_TEST_OPERATOR_API_KEY,
        ),
      });
      const [testEnvironment, appwrite, provider, identities, providerStore,
        preflight, control, fixtures, evidence, evidenceWriter,
        scenario, deployment] = await Promise.all([
        loadTestEnvironment(),
        loadTestCloudAppwrite(),
        loadProviderRuntime(),
        loadIdentityBindings(),
        loadProviderControlStore(),
        loadTestCloudPreflight(),
        loadTestCloudControlStore(),
        loadTestCloudFixtures(),
        loadEvidence(),
        loadEvidenceWriter(),
        loadScenarioDriver(),
        loadTestCloudDeploy(),
      ]);
      const source = stage.artifactSet;
      const contextResult = testEnvironment.createTestEnvironmentContext({
        inventory: configuredInventory,
        environment: {
          endpoint: configuredInventory.environment.endpoint,
          projectId: configuredInventory.environment.projectId,
          siteId: configuredInventory.environment.siteId,
          origin: configuredInventory.environment.publicOrigin,
        },
        candidateRevision: source.selection.sourceRevision,
        runId: `verify-${source.selection.sourceRevision.slice(0, 12)}-${source.selection.workflowRunId}-${source.selection.workflowRunAttempt}`,
        credentialHandles,
      });
      if (contextResult.status !== 'PASS') {
        return blockedFrom(contextResult, 'TEST_CLOUD_CONTEXT_INVALID');
      }
      const context = contextResult.value;
      const clients = appwrite.createTestCloudClients({
        context,
        credentialHandles,
        fetch: fetchImpl,
      });
      if (clients.status !== 'PASS') {
        return blockedFrom(clients, 'TEST_CLOUD_CLIENTS_INVALID');
      }
      const providerContract = await provider.loadQualifiedTestCloudProviderContract(Object.freeze({
        runtimeQualification: stage.runtime.runtimeQualification,
        context,
      }));
      if (providerContract.status !== 'PASS') {
        return blockedFrom(providerContract, 'TEST_CLOUD_PROVIDER_CONTRACT_INVALID');
      }
      const identityBindings = await identities.loadQualifiedTestCloudIdentityBindings({
        runtimeQualification: stage.runtime.runtimeQualification,
        context,
        credentialHandles,
        providerContractQualification: providerContract.value.qualification,
        configuredEmails: {
          owner: stage.credentials.E2E_OWNER_EMAIL,
          editor: stage.credentials.E2E_EDITOR_EMAIL,
          viewer: stage.credentials.E2E_VIEWER_EMAIL,
        },
      });
      if (identityBindings.status !== 'PASS') {
        return result(
          'BLOCKED',
          null,
          selectSafePreflightDiagnosticCode(
            identityBindings,
            'TEST_CLOUD_IDENTITY_BINDINGS_INVALID',
          ),
          retryable(identityBindings),
        );
      }
      const setupReadback = provider.loadQualifiedTestCloudSetupReadback(Object.freeze({
        runtimeQualification: stage.runtime.runtimeQualification,
        context,
        providerContract,
        identityBindings,
        setupReadbackJson: readEnvironmentValue(
          environment,
          'TEST_CLOUD_SETUP_READBACK_JSON',
        ),
        setupReadbackDigest: readEnvironmentValue(
          environment,
          'TEST_CLOUD_SETUP_READBACK_DIGEST',
        ),
      }));
      if (setupReadback.status !== 'PASS') {
        return result(
          'BLOCKED',
          null,
          selectSafePreflightDiagnosticCode(
            setupReadback,
            'TEST_CLOUD_SETUP_READBACK_INVALID',
          ),
          retryable(setupReadback),
        );
      }
      const runnerRequest = appwrite.qualifyTestCloudRunnerVariableReadbackRequest({
        runtimeQualification: stage.runtime.runtimeQualification,
        context,
        credentialHandles,
        providerContract,
        identityBindings,
        providerSetupReadback: setupReadback,
      });
      if (runnerRequest.status !== 'PASS') {
        return blockedFrom(runnerRequest, 'TEST_CLOUD_RUNNER_VARIABLE_REQUEST_INVALID');
      }
      const runnerOperator = appwrite.createTestCloudRunnerVariableReadbackOperator({
        runtimeQualification: stage.runtime.runtimeQualification,
        requestQualification: runnerRequest.value.requestQualification,
      });
      if (runnerOperator.status !== 'PASS') {
        return blockedFrom(runnerOperator, 'TEST_CLOUD_RUNNER_VARIABLE_OPERATOR_INVALID');
      }
      const runnerReadback = await runnerOperator.value.getRunnerVariableDigests({
        runtimeQualification: stage.runtime.runtimeQualification,
      });
      if (runnerReadback.status !== 'PASS') {
        return blockedFrom(runnerReadback, 'TEST_CLOUD_RUNNER_VARIABLE_READBACK_INVALID');
      }
      const setupAttestation = preflight.createTestCloudSetupAttestation({
        runtimeQualification: stage.runtime.runtimeQualification,
        context,
        document: stage.setup.attestation,
        expectedDocumentDigest: stage.setup.attestationDigest,
        clock,
        executionObservationQualification: stage.setup.executionObservationQualification,
        providerContract,
        identityBindings,
        providerSetupReadback: setupReadback,
        runnerVariableReadbackResult: runnerReadback,
      });
      if (setupAttestation.status !== 'PASS') {
        return blockedFrom(setupAttestation, 'TEST_CLOUD_SETUP_ATTESTATION_INVALID');
      }
      const store = providerStore.createProviderControlStore({
        context,
        client: clients.value.fixture,
      });
      if (store.status !== 'PASS') {
        return blockedFrom(store, 'TEST_CLOUD_PROVIDER_STORE_INVALID');
      }
      const siteIdentityReader = deployment.createTestSiteIdentityReader({
        context,
        fetchTrusted: fetchImpl,
      });
      if (siteIdentityReader.status !== 'PASS') {
        return blockedFrom(siteIdentityReader, 'TEST_CLOUD_SITE_IDENTITY_READER_INVALID');
      }
      const providerFacade = Object.freeze({
        async readExact() { return Object.freeze({ status: 500 }); },
        async deleteExact() { return Object.freeze({ status: 500 }); },
      });
      const preflightStage = async () => {
        const checked = await preflight.preflightTestCloud({
          runtimeQualification: stage.runtime.runtimeQualification,
          context,
          clients: clients.value,
          manifest: source.artifactSet.artifactManifest,
          setupAttestation: setupAttestation.value,
          clock,
        });
        if (checked.status !== 'PASS') return checked;
        const handoff = control.createTestCloudPreflightHandoff({
          context,
          preflight: checked,
          clock,
        });
        if (handoff.status !== 'PASS') return handoff;
        return result('PASS', { handoff: handoff.value });
      };
      const acquireLease = async ({ preflight: qualified }) => control.acquireLease({
        context,
        store: store.value,
        handoff: qualified.handoff,
        clock,
        randomBytes,
      });
      const deployFunctionArtifacts = async () => deployment.deployTestFunctionArtifacts({
        context,
        artifactSet: source.artifactSet,
        clients: clients.value,
        clock,
      });
      const siteArtifact = source.artifactSet.releaseEligibleArtifacts.find(
        ({ kind }) => kind === 'site',
      );
      const deploySiteArtifact = async () => deployment.deployTestSiteArtifact({
        context,
        artifact: siteArtifact,
        clients: clients.value,
        clock,
        siteIdentityReader: siteIdentityReader.value,
        expectedIdentity: source.artifactSet.buildIdentity,
        expectedSourceTreeDigest: source.artifactSet.artifactManifest.sourceTreeDigest,
      });
      const qualifyRunner = async ({ functionDeployments }) => {
        const runner = functionDeployments.find(
          ({ logicalTarget }) => logicalTarget === 'verification-runner-py',
        );
        return runner?.status === 'ready' && runner.activeDeploymentId === runner.deploymentId
          ? result('PASS', { qualified: true })
          : result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
      };
      const runTrustedScenario = async (request) => scenario.runTrustedTestCloudScenario({
        scenarioId: 'worker.invoke_no_cost',
        parameters: Object.freeze({
          logicalWorkflow: 'hello-world-no-cost',
          inputProfile: 'verification-minimal',
        }),
        context,
        client: clients.value.operator,
        store: store.value,
        lease: request.lease,
        capability: request.capability,
        clock,
      });
      const cleanup = async (request) => {
        const intents = await control.reconstructAuthoritativeIntents({
          store: store.value,
          lease: request.lease,
          primaryExecutionRetentionMaxSeconds:
            setupAttestation.value.primaryExecutionRetentionMaxSeconds,
        });
        if (intents.status !== 'PASS') return intents;
        return fixtures.cleanupRun({
          context,
          store: store.value,
          provider: providerFacade,
          lease: request.lease,
          capability: request.capability,
          intents: intents.value,
          clock,
        });
      };
      const proveAbsence = async (request) => fixtures.verifyRunAbsent({
        context,
        provider: providerFacade,
        intents: request.intents,
      });
      const closeLease = async (request) => control.closeLease({
        context,
        store: store.value,
        lease: request.lease,
        capability: request.capability,
        clock,
      });
      const laneEvidenceWriter = Object.freeze({
        async write(laneEvidence) {
          const started = Date.parse(laneEvidence.startedAt);
          const completed = Date.parse(laneEvidence.completedAt);
          const verificationResult = evidence.createVerificationResult({
            bootstrapQualification: {
              bundleDigest: stage.controller.controllerBundleDigest,
              status: 'PASS',
              verifierRevision: stage.controller.controllerBundleSha,
            },
            candidateArtifactDigest: source.selection.archiveDigest,
            candidateRevision: source.selection.sourceRevision,
            candidateSourceTreeDigest: source.artifactSet.artifactManifest.sourceTreeDigest,
            checks: [{
              attempts: 1,
              checkId: 'hosted-test-cloud',
              completedAt: laneEvidence.completedAt,
              diagnostics: [],
              durationMs: Math.max(0, completed - started),
              startedAt: laneEvidence.startedAt,
              status: 'PASS',
            }],
            cleanup: {
              absenceProven: true,
              diagnostics: [],
              ownedResourceCount: 0,
              removedResourceCount: 0,
              status: 'PASS',
            },
            completedAt: laneEvidence.completedAt,
            deploymentReadback: { diagnostics: [], status: 'PASS' },
            environmentClass: 'test',
            environmentIdentityDigest: context.environmentDigest,
            lane: 'test-cloud',
            manifestDigest: source.artifactSet.artifactManifestDigest,
            observedDeployment: {
              artifactDigest: laneEvidence.siteDeployment.artifactTransportDigest,
              readbackSource: 'public-build-identity',
              releaseRecordDigest: null,
              releaseRecordId: null,
              revision: source.selection.sourceRevision,
            },
            selectedChecks: ['hosted-test-cloud'],
            startedAt: laneEvidence.startedAt,
            verifierRevision: stage.controller.controllerBundleSha,
          });
          const written = await evidenceWriter.writeVerificationResult({
            root: REPOSITORY_ROOT,
            result: verificationResult,
          });
          return result('PASS', {
            path: path.relative(REPOSITORY_ROOT, written.path).replaceAll('\\', '/'),
            evidenceDigest: written.evidenceDigest,
          });
        },
      });
      const lane = composeProductionTestCloudLane({
        artifactSet: source.artifactSet,
        clock: Object.freeze({ now: clock.now }),
        controller: stage.controller,
        evidenceWriter: laneEvidenceWriter,
        facade: Object.freeze({
          facade: stage.facade.facade,
          scenarioIds: stage.facade.testCloudScenarioInventory,
          scenarioInventoryDigest: stage.facade.testCloudScenarioInventoryDigest,
        }),
        operations: Object.freeze({
          preflight: preflightStage,
          acquireLease,
          deployFunctionArtifacts,
          deploySiteArtifact,
          qualifyRunner,
          runTrustedScenario,
          cleanup,
          proveAbsence,
          closeLease,
        }),
        selection: source.selection,
      });
      return lane.status === 'PASS'
        ? lane
        : blockedFrom(lane, 'TEST_CLOUD_LANE_COMPOSITION_INVALID');
    },

    async runLane(stage) {
      return runTestCloudLane(stage.lane);
    },
  };
  return Object.freeze(dependencies);
}

export async function runHostedTestCloudController(args) {
  if (
    !exactDataObject(args, HOSTED_ARGUMENT_KEYS)
    || !validHostedRequest(args.request)
    || args.environment === null
    || typeof args.environment !== 'object'
    || !validHostedDependencies(args.dependencies)
  ) return result('BLOCKED', null, 'TEST_CLOUD_SETUP_INCOMPLETE');

  const shared = { request: args.request };
  const controller = await hostedStage(
    args.dependencies.reattestController,
    shared,
    'TRUSTED_CONTROLLER_REQUIRED',
  );
  if (controller.status !== 'PASS') return controller;

  const setup = await hostedStage(
    args.dependencies.validateSetupBindings,
    { ...shared, controller: controller.value },
    'TEST_CLOUD_SETUP_INCOMPLETE',
  );
  if (setup.status !== 'PASS') return setup;

  const runtime = await hostedStage(
    args.dependencies.bootstrapRuntime,
    { ...shared, controller: controller.value, setup: setup.value },
    'TEST_CLOUD_PREFLIGHT_BLOCKED',
  );
  if (runtime.status !== 'PASS') return runtime;

  const facade = await hostedStage(
    args.dependencies.createPlaywrightFacade,
    {
      ...shared,
      controller: controller.value,
      runtime: runtime.value,
      setup: setup.value,
    },
    'TEST_CLOUD_PREFLIGHT_BLOCKED',
  );
  if (facade.status !== 'PASS') return facade;

  const containment = await hostedStage(
    args.dependencies.qualifyContainment,
    {
      ...shared,
      controller: controller.value,
      facade: facade.value,
      runtime: runtime.value,
      setup: setup.value,
    },
    'TEST_CLOUD_SETUP_INCOMPLETE',
  );
  if (containment.status !== 'PASS') return containment;

  const sourcePrivateKey = readCredential(
    args.environment,
    'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
  );
  if (sourcePrivateKey === null) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');
  const source = await hostedStage(
    args.dependencies.consumeSourceArtifact,
    {
      ...shared,
      containment: containment.value,
      controller: controller.value,
      privateKey: sourcePrivateKey,
    },
    'SOURCE_ARTIFACT_INVALID',
    SAFE_SOURCE_READER_DIAGNOSTIC_CODES,
  );
  if (source.status !== 'PASS') return source;

  const artifact = await hostedStage(
    args.dependencies.validateSourceArtifact,
    {
      ...shared,
      controller: controller.value,
      sourceArtifact: source.value,
    },
    'SOURCE_ARTIFACT_INVALID',
  );
  if (
    artifact.status !== 'PASS'
    || !validHostedSourceSnapshot(artifact.value, args.request)
  ) return result('BLOCKED', null, 'SOURCE_ARTIFACT_INVALID');

  const credentials = Object.create(null);
  for (const name of ORDINARY_CREDENTIAL_NAMES) {
    const value = readCredential(args.environment, name);
    if (value === null) return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
    credentials[name] = value;
  }
  const lane = await hostedStage(
    args.dependencies.createOrdinaryLane,
    {
      ...shared,
      artifactSet: artifact.value,
      controller: controller.value,
      credentials: Object.freeze(credentials),
      facade: facade.value,
      runtime: runtime.value,
      setup: setup.value,
    },
    'TEST_CLOUD_PREFLIGHT_BLOCKED',
    SAFE_PREFLIGHT_DIAGNOSTIC_CODES,
  );
  if (lane.status !== 'PASS') return lane;
  try {
    const outcome = await args.dependencies.runLane(deepFreeze({
      ...shared,
      lane: lane.value,
    }));
    return validControllerResult(outcome)
      ? outcome
      : result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
  } catch {
    return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
  }
}

function validSelection(selection, requestedRevision) {
  return exactDataObject(selection, SELECTION_KEYS)
    && selection.repository === 'Krowaccie/AppWriteWork'
    && selection.workflow === 'Verify Main'
    && typeof selection.workflowRunId === 'string'
    && SAFE_ID.test(selection.workflowRunId)
    && Number.isSafeInteger(selection.workflowRunAttempt)
    && selection.workflowRunAttempt > 0
    && selection.sourceRef === 'refs/heads/main'
    && typeof selection.sourceRevision === 'string'
    && FULL_SHA.test(selection.sourceRevision)
    && (requestedRevision === null || selection.sourceRevision === requestedRevision)
    && typeof selection.artifactId === 'string'
    && SAFE_ID.test(selection.artifactId)
    && selection.artifactName === `verification-artifacts-${selection.sourceRevision}`
    && typeof selection.archiveDigest === 'string'
    && DIGEST.test(selection.archiveDigest);
}

function validateDependencies(dependencies) {
  if (
    !exactDataObject(dependencies, DEPENDENCY_KEYS)
    || typeof dependencies.bootstrapRuntime !== 'function'
    || typeof dependencies.resolveSourceSelection !== 'function'
    || typeof dependencies.consumeHostedArtifact !== 'function'
    || typeof dependencies.createClients !== 'function'
    || dependencies.runLane !== runTestCloudLane
    || !exactDataObject(dependencies.clock, CLOCK_KEYS)
    || typeof dependencies.clock.now !== 'function'
    || !exactDataObject(dependencies.evidenceWriter, EVIDENCE_WRITER_KEYS)
    || typeof dependencies.evidenceWriter.write !== 'function'
  ) throw dependencyError();
}

async function invokeBoundary(method, request, code) {
  try {
    const outcome = await method(deepFreeze(request));
    if (!validControllerResult(outcome)) {
      return result('BLOCKED', null, code);
    }
    if (outcome.status !== 'PASS') {
      return result(
        outcome.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
        null,
        code,
        retryable(outcome),
      );
    }
    return outcome;
  } catch {
    return result('BLOCKED', null, code);
  }
}

export async function runTestCloudController(args) {
  if (!exactDataObject(args, ARGUMENT_KEYS)) throw dependencyError();

  if (!isTrustedControllerContext(args.controller)) {
    return result('BLOCKED', null, 'TRUSTED_CONTROLLER_REQUIRED');
  }
  if (
    args.requestedRevision !== null
    && (
      typeof args.requestedRevision !== 'string'
      || !FULL_SHA.test(args.requestedRevision)
    )
  ) {
    return result('BLOCKED', null, 'SOURCE_RUN_NOT_GREEN');
  }

  validateDependencies(args.dependencies);

  let bootstrapResult;
  try {
    bootstrapResult = await args.dependencies.bootstrapRuntime();
  } catch {
    return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
  }
  if (!validRuntimeBootstrapPass(bootstrapResult)) {
    return result('BLOCKED', null, 'TEST_CLOUD_PREFLIGHT_BLOCKED');
  }
  const runtimeQualification = bootstrapResult.value.runtimeQualification;
  const browserScenarioQualification =
    bootstrapResult.value.browserScenarioQualification;
  void runtimeQualification;
  void browserScenarioQualification;

  const selected = await invokeBoundary(
    args.dependencies.resolveSourceSelection,
    {
      controller: args.controller,
      requestedRevision: args.requestedRevision,
    },
    'SOURCE_RUN_NOT_GREEN',
  );
  if (
    selected.status !== 'PASS'
    || !validSelection(selected.value, args.requestedRevision)
  ) {
    return result(
      'BLOCKED',
      null,
      'SOURCE_RUN_NOT_GREEN',
      retryable(selected),
    );
  }
  const selection = deepFreeze({ ...selected.value });

  const consumed = await invokeBoundary(
    args.dependencies.consumeHostedArtifact,
    {
      controller: args.controller,
      selection,
    },
    'SOURCE_ARTIFACT_INVALID',
  );
  if (
    consumed.status !== 'PASS'
    || !validateArtifactSetOutput(consumed.value, selection)
  ) {
    return result(
      'BLOCKED',
      null,
      'SOURCE_ARTIFACT_INVALID',
      retryable(consumed),
    );
  }
  const artifactSet = deepFreeze(consumed.value);

  const created = await invokeBoundary(
    args.dependencies.createClients,
    {
      controller: args.controller,
      selection,
      artifactSet,
    },
    'TEST_CLOUD_PREFLIGHT_BLOCKED',
  );
  if (
    created.status !== 'PASS'
    || created.value === null
    || typeof created.value !== 'object'
    || Array.isArray(created.value)
  ) {
    return result(
      'BLOCKED',
      null,
      'TEST_CLOUD_PREFLIGHT_BLOCKED',
      retryable(created),
    );
  }

  return args.dependencies.runLane({
    controller: args.controller,
    selection,
    artifactSet,
    clients: created.value,
    clock: args.dependencies.clock,
    evidenceWriter: args.dependencies.evidenceWriter,
  });
}

function hostedArgs(argv) {
  if (
    !Array.isArray(argv)
    || ![7, 9].includes(argv.length)
    || argv[0] !== '--hosted'
    || argv[1] !== '--revision'
    || !FULL_SHA.test(argv[2] ?? '')
    || argv[3] !== '--source-run-id'
    || !SAFE_ID.test(argv[4] ?? '')
    || argv[5] !== '--source-run-attempt'
    || (argv.length === 9 && (
      argv[7] !== '--binding-directory'
      || typeof argv[8] !== 'string'
      || argv[8].length < 1
      || argv[8].includes('\0')
    ))
  ) return null;
  const sourceRunAttempt = positiveInteger(argv[6]);
  if (sourceRunAttempt === null) return null;
  return Object.freeze({
    requestedRevision: argv[2],
    sourceRunId: argv[4],
    sourceRunAttempt,
    bindingDirectory: argv.length === 9 ? argv[8] : null,
  });
}

async function readExactBindingDirectory(directory, io = { lstat, readFile, readdir, realpath }) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory.includes('\0')) {
    throw new TypeError('invalid binding directory');
  }
  const root = await io.realpath(path.resolve(directory));
  const rootInfo = await io.lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new TypeError('invalid binding directory');
  const expectedFiles = TEST_CLOUD_BINDING_NAMES.map((name) => `${name}.txt`).sort();
  const actualFiles = (await io.readdir(root)).sort();
  if (
    actualFiles.length !== expectedFiles.length
    || actualFiles.some((name, index) => name !== expectedFiles[index])
  ) throw new TypeError('invalid binding directory');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const values = {};
  let totalBytes = 0;
  for (const name of TEST_CLOUD_BINDING_NAMES) {
    const filePath = path.join(root, `${name}.txt`);
    const info = await io.lstat(filePath);
    const resolved = await io.realpath(filePath);
    const relative = path.relative(root, resolved);
    if (
      !info.isFile()
      || info.isSymbolicLink()
      || relative.startsWith(`..${path.sep}`)
      || relative === '..'
      || path.isAbsolute(relative)
    ) throw new TypeError('invalid binding file');
    const bytes = Buffer.from(await io.readFile(resolved));
    totalBytes += bytes.length;
    if (bytes.length < 1 || bytes.length > 1024 * 1024 || totalBytes > 2 * 1024 * 1024) {
      throw new TypeError('invalid binding file');
    }
    values[name] = decoder.decode(bytes);
  }
  const overlay = Object.freeze(values);
  for (let index = 0; index < TEST_CLOUD_BINDING_NAMES.length; index += 2) {
    if (parseCanonicalJsonBinding(
      overlay,
      TEST_CLOUD_BINDING_NAMES[index],
      TEST_CLOUD_BINDING_NAMES[index + 1],
    ) === null) throw new TypeError('invalid binding pair');
  }
  return overlay;
}

function write(stream, value) {
  if (stream && typeof stream.write === 'function') stream.write(value);
}

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  const parsed = hostedArgs(argv);
  const stderr = dependencies.stderr ?? process.stderr;
  const stdout = dependencies.stdout ?? process.stdout;
  if (parsed === null) {
    write(stderr, 'BLOCKED TRUSTED_CONTROLLER_CLI_INVALID\n');
    return 2;
  }
  let environment = dependencies.environment ?? process.env;
  const inventory = dependencies.inventory ?? configuredInventory;
  if (
    !Number.isSafeInteger(inventory?.control?.primaryExecutionRetentionMaxSeconds)
    || inventory.control.primaryExecutionRetentionMaxSeconds < 1
    || inventory.control.primaryExecutionRetentionMaxSeconds > 86_400
  ) {
    write(stderr, 'BLOCKED TEST_CLOUD_SETUP_INCOMPLETE\n');
    return 2;
  }
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  const createHostedDependencies = dependencies.createHostedDependencies
    ?? createProductionHostedDependencies;
  const runHostedController = dependencies.runHostedController
    ?? runHostedTestCloudController;
  let outcome;
  try {
    if (parsed.bindingDirectory !== null) {
      const bindingValues = await readExactBindingDirectory(
        parsed.bindingDirectory,
        dependencies.bindingDirectoryIo,
      );
      environment = Object.freeze({ ...environment, ...bindingValues });
    }
    const request = Object.freeze({
      requestedRevision: parsed.requestedRevision,
      sourceRunId: parsed.sourceRunId,
      sourceRunAttempt: parsed.sourceRunAttempt,
    });
    const dependencyArgs = { environment, fetchImpl };
    if (Object.hasOwn(dependencies, 'controllerArtifactIo')) {
      dependencyArgs.controllerArtifactIo = dependencies.controllerArtifactIo;
    } else {
      const controllerArtifactDirectory = readEnvironmentValue(
        environment,
        'CONTROLLER_ARTIFACT_DIRECTORY',
      );
      if (controllerArtifactDirectory !== null) {
        if (
          !path.isAbsolute(controllerArtifactDirectory)
          || controllerArtifactDirectory.includes('\0')
        ) throw new TypeError('invalid controller artifact directory');
        dependencyArgs.controllerArtifactIo = Object.freeze({
          lstat,
          readFile,
          realpath,
          root: controllerArtifactDirectory,
        });
      }
    }
    if (Object.hasOwn(dependencies, 'runContainedProcessImpl')) {
      dependencyArgs.runContainedProcessImpl = dependencies.runContainedProcessImpl;
    }
    const hostedDependencies = createHostedDependencies(dependencyArgs);
    outcome = await runHostedController({
      dependencies: hostedDependencies,
      environment,
      request,
    });
  } catch {
    write(stderr, 'BLOCKED TEST_CLOUD_SETUP_INCOMPLETE\n');
    return 2;
  }
  if (!validControllerResult(outcome) || outcome.status !== 'PASS') {
    const code = validControllerResult(outcome)
      ? outcome.diagnostics[0]?.code
      : 'TEST_CLOUD_SETUP_INCOMPLETE';
    write(stderr, `BLOCKED ${code ?? 'TEST_CLOUD_SETUP_INCOMPLETE'}\n`);
    return 2;
  }
  write(stdout, 'PASS\n');
  return 0;
}

if (
  process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = await main();
}
