import assert from 'node:assert/strict';
import test from 'node:test';

import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import { createArtifactManifest } from './artifact-manifest.mjs';
import { sha256Bytes } from './canonical-json.mjs';
import { createHostedSiteBuildIdentity } from './hosted-site-build-identity.mjs';
import {
  createTestSiteIdentityReader,
  deployTestFunctionArtifacts,
  deployTestSiteArtifact,
} from './test-cloud-deploy.mjs';
import { createTestEnvironmentContext } from './test-cloud-environment.mjs';

const REVISION = '0d7c599b9f512c50b141556e76fbf4a48c59603e';
const DIGEST = `sha256:${'1'.repeat(64)}`;

function credentialHandle(record) {
  return Object.freeze({
    credentialClass: record.credentialClass,
    variableName: record.variableName,
    scopes: Object.freeze([...record.scopes]),
    readSecret() {
      return `${record.credentialClass}-secret-sentinel`;
    },
  });
}

function buildArtifact(kind, logicalTarget, relativePath, index) {
  const bytes = new Uint8Array([index + 1]);
  const transportDigest = sha256Bytes(bytes);
  return Object.freeze({
    bytes,
    canonicalContentDigest: transportDigest,
    kind,
    logicalTarget,
    relativePath,
    sizeBytes: bytes.byteLength,
    transportDigest,
  });
}

function createFixture() {
  const credentialHandles = Object.freeze({
    operator: credentialHandle(inventory.credentialVariables.operator),
    fixture: credentialHandle(inventory.credentialVariables.fixture),
  });
  const context = createTestEnvironmentContext({
    inventory,
    environment: {
      endpoint: 'https://fra.cloud.appwrite.io/v1',
      projectId: '69137c5d003952a36d4c',
      siteId: '694579860016df0d2d3c',
      origin: 'https://appwritework.appwrite.network',
    },
    candidateRevision: REVISION,
    runId: 'verify-0d7c599b9f51-32435795813-1',
    credentialHandles,
  });
  assert.equal(context.status, 'PASS');

  const products = [...inventory.productFunctions]
    .sort((left, right) => left.logicalId < right.logicalId ? -1 : 1)
    .map((record, index) => buildArtifact(
      'function',
      record.logicalId,
      `functions/${record.logicalId}.tar.gz`,
      index,
    ));
  const runner = buildArtifact(
    'function',
    'verification-runner-py',
    'functions/verification-runner-py.tar.gz',
    products.length,
  );
  const site = buildArtifact('site', 'web', 'site/site.tar.gz', products.length + 1);
  const artifacts = [...products, runner, site];
  const entries = artifacts.map((artifact) => ({
    kind: artifact.kind,
    logicalTarget: artifact.logicalTarget,
    sourcePath: artifact.kind === 'site'
      ? 'src/web'
      : artifact.logicalTarget === 'verification-runner-py'
        ? 'src/functions/verification-runner-py'
        : inventory.productFunctions.find(
          (record) => record.logicalId === artifact.logicalTarget,
        ).sourcePath,
    relativePath: artifact.relativePath,
    canonicalContentDigest: artifact.canonicalContentDigest,
    transportDigest: artifact.transportDigest,
    sizeBytes: artifact.sizeBytes,
  })).sort((left, right) => {
    const a = `${left.kind}\0${left.logicalTarget}`;
    const b = `${right.kind}\0${right.logicalTarget}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  const manifest = createArtifactManifest({
    candidateIdentity: {
      candidateRevision: REVISION,
      candidateSourceTreeDigest: DIGEST,
      kind: 'git-revision',
    },
    entries,
    verificationManifestDigest: DIGEST,
  });
  const buildIdentity = createHostedSiteBuildIdentity({
    schemaVersion: 'hosted-site-build-identity.v1',
    sourceRevision: REVISION,
    sitePayloadDigest: site.canonicalContentDigest,
    verifierManifestDigest: DIGEST,
  });
  return {
    context: context.value,
    artifactSet: Object.freeze({
      artifactManifest: manifest,
      artifactManifestDigest: manifest.artifactManifestDigest,
      buildIdentity,
      handoff: Object.freeze({
        artifactManifestDigest: manifest.artifactManifestDigest,
        artifactName: `verification-artifacts-${REVISION}`,
        schemaVersion: 'artifact-handoff.v1',
        sourceRef: 'refs/heads/main',
        sourceRepository: 'Krowaccie/AppWriteWork',
        sourceRevision: REVISION,
        sourceWorkflow: 'Verify Main',
        sourceWorkflowRunAttempt: 1,
        sourceWorkflowRunId: '32404161044',
        verifierManifestDigest: DIGEST,
      }),
      releaseEligibleArtifacts: Object.freeze([site, ...products]),
      testOnlyArtifacts: Object.freeze([runner]),
    }),
  };
}

test('function deployment tolerates bounded unavailable, transient terminal, and stale parent readback', async () => {
  const fixture = createFixture();
  const desired = new Map();
  let firstFunctionId = null;
  let unavailableDeploymentReadReturned = false;
  let transientTerminalReadReturned = false;
  let staleReadReturned = false;
  let sleeps = 0;
  const clients = {
    operator: {
      async createFunctionDeployment({ functionId }) {
        firstFunctionId ??= functionId;
        const deploymentId = `deployment-${functionId}`;
        desired.set(functionId, deploymentId);
        return { status: 'PASS', value: { deploymentId } };
      },
      async getFunctionDeployment({ deploymentId }) {
        if (
          deploymentId === desired.get(firstFunctionId)
          && !unavailableDeploymentReadReturned
        ) {
          unavailableDeploymentReadReturned = true;
          return { status: 'BLOCKED', value: null };
        }
        if (
          deploymentId === desired.get(firstFunctionId)
          && !transientTerminalReadReturned
        ) {
          transientTerminalReadReturned = true;
          return { status: 'PASS', value: { deploymentId, status: 'failed' } };
        }
        return { status: 'PASS', value: { deploymentId, status: 'ready' } };
      },
      async activateFunctionDeployment({ deploymentId }) {
        return { status: 'PASS', value: { activeDeploymentId: deploymentId } };
      },
      async getFunction({ functionId }) {
        if (functionId === firstFunctionId && !staleReadReturned) {
          staleReadReturned = true;
          return { status: 'PASS', value: { activeDeploymentId: 'prior-deployment' } };
        }
        return { status: 'PASS', value: { activeDeploymentId: desired.get(functionId) } };
      },
    },
  };
  const clock = {
    now: () => '2026-08-21T01:20:00.000Z',
    async sleep() {
      sleeps += 1;
    },
  };

  const result = await deployTestFunctionArtifacts({
    context: fixture.context,
    artifactSet: fixture.artifactSet,
    clients,
    clock,
  });

  assert.equal(result.status, 'PASS');
  assert.equal(result.value.length, inventory.productFunctions.length + 1);
  assert.equal(unavailableDeploymentReadReturned, true);
  assert.equal(transientTerminalReadReturned, true);
  assert.equal(staleReadReturned, true);
  assert.equal(sleeps, 3);
});

test('function deployment reports a terminal state only after the bounded readback window', async () => {
  const fixture = createFixture();
  let creates = 0;
  let activations = 0;
  let sleeps = 0;
  const clients = {
    operator: {
      async createFunctionDeployment({ functionId }) {
        creates += 1;
        return { status: 'PASS', value: { deploymentId: `deployment-${functionId}` } };
      },
      async getFunctionDeployment({ deploymentId }) {
        return { status: 'PASS', value: { deploymentId, status: 'failed' } };
      },
      async activateFunctionDeployment() {
        activations += 1;
        return { status: 'PASS', value: { activeDeploymentId: 'unexpected' } };
      },
      async getFunction() {
        throw new Error('parent readback must not run');
      },
    },
  };
  const clock = {
    now: () => '2026-08-21T01:20:00.000Z',
    async sleep() {
      sleeps += 1;
    },
  };

  const result = await deployTestFunctionArtifacts({
    context: fixture.context,
    artifactSet: fixture.artifactSet,
    clients,
    clock,
  });

  assert.equal(result.status, 'FAIL');
  assert.equal(result.diagnostics[0].code, 'DEPLOYMENT_TERMINAL_FAILURE');
  assert.equal(creates, 1);
  assert.equal(activations, 0);
  assert.equal(sleeps, 59);
});

test('site verification reuses the active VCS deployment without mutating Appwrite Sites', async () => {
  const fixture = createFixture();
  const artifact = fixture.artifactSet.releaseEligibleArtifacts[0];
  const expectedIdentity = fixture.artifactSet.buildIdentity;
  const identityUrl = `${fixture.context.publicOrigin}/build-identity.json`;
  const readerResult = createTestSiteIdentityReader({
    context: fixture.context,
    async fetchTrusted(url) {
      assert.equal(url, identityUrl);
      const response = new Response(JSON.stringify(expectedIdentity), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
      return {
        status: response.status,
        redirected: false,
        url: identityUrl,
        headers: response.headers,
        body: response.body,
      };
    },
  });
  assert.equal(readerResult.status, 'PASS');
  const clients = {
    operator: {
      async createSiteDeployment() {
        throw new Error('site deployment creation must remain provider-owned');
      },
      async getSiteDeployment() {
        throw new Error('site deployment polling must remain provider-owned');
      },
      async activateSiteDeployment() {
        throw new Error('site deployment activation must remain provider-owned');
      },
      async getSite() {
        throw new Error('site identity proof must not depend on provider deployment metadata');
      },
    },
  };
  const clock = {
    now: () => '2026-08-21T01:20:00.000Z',
    async sleep() {
      throw new Error('site VCS readback must not poll or sleep');
    },
  };

  const result = await deployTestSiteArtifact({
    context: fixture.context,
    artifact,
    clients,
    clock,
    siteIdentityReader: readerResult.value,
    expectedIdentity,
    expectedSourceTreeDigest: fixture.artifactSet.artifactManifest.sourceTreeDigest,
  });

  assert.equal(result.status, 'PASS');
  assert.equal(result.value.deploymentId, expectedIdentity.sourceRevision);
  assert.equal(result.value.activeDeploymentId, expectedIdentity.sourceRevision);
});

test('site verification accepts the exact native VCS build identity without claiming the hosted tarball', async () => {
  const fixture = createFixture();
  const artifact = fixture.artifactSet.releaseEligibleArtifacts[0];
  const expectedIdentity = fixture.artifactSet.buildIdentity;
  const identityUrl = `${fixture.context.publicOrigin}/build-identity.json`;
  const publicContentDigest = `sha256:${'2'.repeat(64)}`;
  const vcsIdentity = {
    schemaVersion: 1,
    identityKind: 'git-revision',
    candidateRevision: expectedIdentity.sourceRevision,
    candidateSourceTreeDigest: fixture.artifactSet.artifactManifest.sourceTreeDigest,
    contentDigest: publicContentDigest,
    verificationManifestDigest: expectedIdentity.verifierManifestDigest,
  };
  const readerResult = createTestSiteIdentityReader({
    context: fixture.context,
    async fetchTrusted(url) {
      assert.equal(url, identityUrl);
      const response = new Response(JSON.stringify(vcsIdentity), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
      return {
        status: response.status,
        redirected: false,
        url: identityUrl,
        headers: response.headers,
        body: response.body,
      };
    },
  });
  assert.equal(readerResult.status, 'PASS');

  const result = await deployTestSiteArtifact({
    context: fixture.context,
    artifact,
    clients: Object.freeze({}),
    clock: {
      now: () => '2026-08-21T01:20:00.000Z',
      async sleep() {
        throw new Error('site VCS readback must not poll or sleep');
      },
    },
    siteIdentityReader: readerResult.value,
    expectedIdentity,
    expectedSourceTreeDigest: fixture.artifactSet.artifactManifest.sourceTreeDigest,
  });

  assert.equal(result.status, 'PASS');
  assert.equal(result.value.deploymentId, expectedIdentity.sourceRevision);
  assert.equal(result.value.artifactTransportDigest, publicContentDigest);
  assert.notEqual(result.value.artifactTransportDigest, artifact.transportDigest);

  const mismatchedTree = await deployTestSiteArtifact({
    context: fixture.context,
    artifact,
    clients: Object.freeze({}),
    clock: {
      now: () => '2026-08-21T01:20:00.000Z',
      async sleep() {
        throw new Error('site VCS readback must not poll or sleep');
      },
    },
    siteIdentityReader: readerResult.value,
    expectedIdentity,
    expectedSourceTreeDigest: `sha256:${'3'.repeat(64)}`,
  });
  assert.equal(mismatchedTree.status, 'FAIL');
  assert.equal(mismatchedTree.diagnostics[0].code, 'SITE_IDENTITY_MISMATCH');
});
