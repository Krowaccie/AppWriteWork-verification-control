import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { createAppwriteTestSetupBindings } from './appwrite-test-setup-bindings.mjs';

const SHA_A = '1'.repeat(40);
const SHA_B = '2'.repeat(40);
const SHA_C = '3'.repeat(40);
const ENVIRONMENT_DIGEST =
  'sha256:02560e84745ed7b577b334a3412885f6a547b2a22f164f4978b255d3b35c0044';
const PROVIDER_CONTRACT_DIGEST =
  'sha256:47a1d778ca8b8cea333b10574ffbc2db488fd711c12a1c40faf9da5235e27184';

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function browserProfile(index) {
  if (index < 25) {
    return {
      profileId: 'synthetic-immutable-asset',
      requestClass: index === 0 ? 'main-document' : 'build-asset',
      credentialCarrier: 'none',
      method: 'GET',
      lifecyclePhase: index <= 12
        ? 'APPLICATION_NAVIGATION'
        : index <= 21 ? 'OWNER_LOGIN' : 'APPLICATION_READ',
      resourceType: index === 0 ? 'document' : index >= 22 ? 'fetch' : 'script',
    };
  }
  const profileIds = [
    'cors-preflight-owner-session-post',
    'owner-session-create',
    'cors-preflight-appwrite-prefs-get',
    'authenticated-appwrite-read',
    'cors-preflight-appwrite-multipart-post',
    'cors-preflight-appwrite-json-post',
    'cors-preflight-appwrite-json-post',
    'cors-preflight-appwrite-json-post',
    'cors-preflight-appwrite-json-patch',
    'cors-preflight-appwrite-json-patch',
    'cors-preflight-appwrite-json-patch',
    'cors-preflight-appwrite-function-json-post',
    'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-multipart-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-json-mutation',
    'authenticated-appwrite-function-json-mutation',
    'authenticated-appwrite-function-json-mutation',
  ];
  const preflight = [25, 27, 29, 30, 31, 32, 33, 34, 35, 36].includes(index);
  if (preflight) {
    return {
      profileId: profileIds[index - 25],
      requestClass: 'cors-preflight',
      credentialCarrier: 'none',
      method: 'OPTIONS',
      lifecyclePhase: index <= 27 ? 'OWNER_LOGIN' : 'APPLICATION_MUTATION',
      resourceType: 'other',
    };
  }
  if (index === 26) {
    return {
      profileId: profileIds[index - 25],
      requestClass: 'owner-session-create',
      credentialCarrier: 'raw-playwright-request-body-only',
      method: 'POST',
      lifecyclePhase: 'OWNER_LOGIN',
      resourceType: 'fetch',
    };
  }
  if (index === 28) {
    return {
      profileId: profileIds[index - 25],
      requestClass: 'appwrite-read',
      credentialCarrier: 'browser-cookie-jar-only',
      method: 'GET',
      lifecyclePhase: 'OWNER_LOGIN',
      resourceType: 'fetch',
    };
  }
  const multipart = [37, 38, 44, 47, 51].includes(index);
  const patch = [46, 49, 50].includes(index);
  return {
    profileId: profileIds[index - 25],
    requestClass: multipart ? 'appwrite-multipart-mutation' : 'appwrite-json-mutation',
    credentialCarrier: 'browser-cookie-jar-only',
    method: patch ? 'PATCH' : 'POST',
    lifecyclePhase: 'APPLICATION_MUTATION',
    resourceType: 'fetch',
  };
}

function buildBrowserRequestPolicy() {
  const rows = Array.from({ length: 56 }, (_, ordinal) => ({
    ...browserProfile(ordinal),
    exactCount: 1,
    expectedResponseStatus: 200,
    finalUrl: ordinal < 25
      ? `${inventory.environment.publicOrigin}/asset-${ordinal}`
      : `${inventory.environment.endpoint}/closed-route-${ordinal}`,
    ordinal,
    requestHeaderBindings: [],
    requestOpaqueHeaderRules: [],
    responseBodyDigest: ordinal < 25 ? digest(`asset-${ordinal}`) : null,
    responseByteLength: ordinal < 25 ? 1 : null,
    responseHeaderBindings: [],
    responseMimeEssence: ordinal < 25 ? 'application/octet-stream' : null,
    responseOpaqueHeaderRules: [],
  }));
  const withoutDigest = {
    schemaVersion: 'test-cloud.browser-request-policy.v1',
    timeoutMilliseconds: 5000,
    rows,
  };
  return { ...withoutDigest, digest: digest(canonicalJson(withoutDigest)) };
}

function buildVariables(identityBindingsDigest) {
  const literals = {
    VERIFICATION_AUDIT_TABLE_ID: inventory.control.auditTableId,
    VERIFICATION_CONTROL_DATABASE_ID: inventory.control.databaseId,
    VERIFICATION_ENDPOINT_ORIGIN: inventory.environment.endpoint,
    VERIFICATION_ENVIRONMENT_CLASS: inventory.environmentClass,
    VERIFICATION_ENVIRONMENT_DIGEST: ENVIRONMENT_DIGEST,
    VERIFICATION_IDENTITY_BINDINGS_DIGEST: identityBindingsDigest,
    VERIFICATION_INTENT_TABLE_ID: inventory.control.intentTableId,
    VERIFICATION_LEASE_ROW_ID: inventory.control.leaseRowId,
    VERIFICATION_LEASE_TABLE_ID: inventory.control.leaseTableId,
    VERIFICATION_PRIMARY_DATABASE_ID: 'project',
    VERIFICATION_PROJECTS_TABLE_ID: 'projects',
    VERIFICATION_PROJECT_FILES_BUCKET_ID: 'project-files',
    VERIFICATION_PROJECT_ID: inventory.environment.projectId,
    VERIFICATION_PROVIDER_CONTRACT_DIGEST: PROVIDER_CONTRACT_DIGEST,
    VERIFICATION_SHARES_TABLE_ID: 'project_shares',
    VERIFICATION_WORKER_FUNCTION_ID: 'execute-node-py',
  };
  return Object.entries(literals)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, value]) => ({ key, valueDigest: digest(value) }));
}

function buildLiveProjection() {
  const identityBindingsDigest = digest('identity-bindings');
  const variables = buildVariables(identityBindingsDigest);
  const expectedRunnerVariables = {
    identityQualifiedKey: 'VERIFICATION_IDENTITY_BINDINGS_DIGEST',
    staticTotal: 15,
    total: 16,
    variables,
  };
  return {
    environmentDigest: ENVIRONMENT_DIGEST,
    providerContractDigest: PROVIDER_CONTRACT_DIGEST,
    identityBindingsDigest,
    expectedRunnerVariables,
    runnerVariableReadbackDigest: digest('runner-readback'),
    siteConfigurationDigest: digest('site-configuration'),
    functionConfigurationsDigest: digest('function-configurations'),
    globalCleanupReadbackDigest: digest('global-cleanup'),
    projectReadbackDigest: digest('project-readback'),
  };
}

test('creates the eight canonical initial-seed Appwrite Test bindings', () => {
  const result = createAppwriteTestSetupBindings({
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
    runnerRevision: SHA_C,
    initialSeed: true,
    liveProjection: buildLiveProjection(),
    browserRequestPolicy: buildBrowserRequestPolicy(),
    nowEpochSeconds: 1_800_000_000,
    controllerArtifact: null,
  });

  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
  assert.deepEqual(Object.keys(result.value.bindings).sort(), [
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
    'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
    'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
    'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
    'TEST_CLOUD_SETUP_ATTESTATION_JSON',
    'TEST_CLOUD_SETUP_READBACK_DIGEST',
    'TEST_CLOUD_SETUP_READBACK_JSON',
  ]);
  for (const [name, value] of Object.entries(result.value.bindings)) {
    if (name.endsWith('_DIGEST')) assert.match(value, /^sha256:[0-9a-f]{64}$/);
    else assert.equal(canonicalJson(JSON.parse(value)), value);
  }
  const hosted = JSON.parse(result.value.bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_JSON);
  assert.equal(hosted.schemaVersion, 'test-cloud.hosted-prepublication-readback.v1');
  assert.deepEqual(hosted.initialSeed, {
    approvalMode: 'single-maintainer',
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
  });
  assert.equal(result.value.evidence.controllerRevision, SHA_A);
  assert.equal(result.value.evidence.runnerRevision, SHA_C);
  assert.equal(result.value.evidence.sourceRepositoryRevision, SHA_B);
});

test('accepts a Salmora brand asset only on the fixed public test origin', () => {
  const browserRequestPolicy = buildBrowserRequestPolicy();
  browserRequestPolicy.rows[1].finalUrl =
    `${inventory.environment.publicOrigin}/salmora-mark.svg`;
  browserRequestPolicy.digest = digest(canonicalJson({
    schemaVersion: browserRequestPolicy.schemaVersion,
    timeoutMilliseconds: browserRequestPolicy.timeoutMilliseconds,
    rows: browserRequestPolicy.rows,
  }));
  const result = createAppwriteTestSetupBindings({
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
    runnerRevision: SHA_C,
    initialSeed: true,
    liveProjection: buildLiveProjection(),
    browserRequestPolicy,
    nowEpochSeconds: 1_800_000_000,
    controllerArtifact: null,
  });
  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
});

test('rejects production, fixture, and placeholder browser targets', () => {
  for (const finalUrl of [
    'https://salmora.net/index.html',
    'https://test-only.invalid/index.html',
    'https://v22-gate.example/index.html',
  ]) {
    const policy = buildBrowserRequestPolicy();
    policy.rows[0].finalUrl = finalUrl;
    policy.digest = digest(canonicalJson({
      schemaVersion: policy.schemaVersion,
      timeoutMilliseconds: policy.timeoutMilliseconds,
      rows: policy.rows,
    }));
    const result = createAppwriteTestSetupBindings({
      controllerRevision: SHA_A,
      sourceRepositoryRevision: SHA_B,
      runnerRevision: SHA_C,
      initialSeed: true,
      liveProjection: buildLiveProjection(),
      browserRequestPolicy: policy,
      nowEpochSeconds: 1_800_000_000,
      controllerArtifact: null,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.diagnostics[0].code, 'APPWRITE_TEST_BINDING_BROWSER_POLICY_INVALID');
  }
});

test('requires an exact controller artifact tuple in ordinary mode', () => {
  const result = createAppwriteTestSetupBindings({
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
    runnerRevision: SHA_C,
    initialSeed: false,
    liveProjection: buildLiveProjection(),
    browserRequestPolicy: buildBrowserRequestPolicy(),
    nowEpochSeconds: 1_800_000_000,
    controllerArtifact: null,
  });
  assert.equal(result.status, 'BLOCKED');
});

test('creates an ordinary hosted binding tied to one controller artifact', () => {
  const artifact = { artifactId: '123456789', digest: digest('controller-zip') };
  const result = createAppwriteTestSetupBindings({
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
    runnerRevision: SHA_C,
    initialSeed: false,
    liveProjection: buildLiveProjection(),
    browserRequestPolicy: buildBrowserRequestPolicy(),
    nowEpochSeconds: 1_800_000_000,
    controllerArtifact: artifact,
  });
  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
  const hosted = JSON.parse(result.value.bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_JSON);
  assert.equal(hosted.schemaVersion, 'test-cloud.hosted-setup-readback.v1');
  assert.deepEqual(hosted.controller.bundle, {
    artifactId: artifact.artifactId,
    controllerRevision: SHA_A,
    digest: artifact.digest,
    sourceRepositoryRevision: SHA_B,
  });
  assert.deepEqual(hosted.bootstrap, {
    bundleDigest: artifact.digest,
    seeded: true,
    sourceRevision: SHA_B,
  });
});

test('rejects a runner-variable projection that is not identity-bound', () => {
  const liveProjection = buildLiveProjection();
  const identityVariable = liveProjection.expectedRunnerVariables.variables.find(
    ({ key }) => key === 'VERIFICATION_IDENTITY_BINDINGS_DIGEST',
  );
  identityVariable.valueDigest = digest('wrong-identity');
  const result = createAppwriteTestSetupBindings({
    controllerRevision: SHA_A,
    sourceRepositoryRevision: SHA_B,
    runnerRevision: SHA_C,
    initialSeed: true,
    liveProjection,
    browserRequestPolicy: buildBrowserRequestPolicy(),
    nowEpochSeconds: 1_800_000_000,
    controllerArtifact: null,
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(
    result.diagnostics[0].code,
    'APPWRITE_TEST_BINDING_RUNNER_VARIABLES_INVALID',
  );
});
