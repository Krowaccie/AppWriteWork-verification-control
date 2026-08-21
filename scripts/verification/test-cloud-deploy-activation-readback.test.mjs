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

test('function activation tolerates one bounded stale parent readback', async () => {
  const fixture = createFixture();
  const desired = new Map();
  let firstFunctionId = null;
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
  assert.equal(staleReadReturned, true);
  assert.equal(sleeps, 1);
});

test('site activation tolerates one bounded stale parent readback', async () => {
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
  let staleReadReturned = false;
  let sleeps = 0;
  const deploymentId = 'deployment-site';
  const clients = {
    operator: {
      async createSiteDeployment() {
        return { status: 'PASS', value: { deploymentId } };
      },
      async getSiteDeployment() {
        return { status: 'PASS', value: { deploymentId, status: 'ready' } };
      },
      async activateSiteDeployment() {
        return { status: 'PASS', value: { activeDeploymentId: deploymentId } };
      },
      async getSite() {
        if (!staleReadReturned) {
          staleReadReturned = true;
          return { status: 'PASS', value: { activeDeploymentId: 'prior-deployment' } };
        }
        return { status: 'PASS', value: { activeDeploymentId: deploymentId } };
      },
    },
  };
  const clock = {
    now: () => '2026-08-21T01:20:00.000Z',
    async sleep() {
      sleeps += 1;
    },
  };

  const result = await deployTestSiteArtifact({
    context: fixture.context,
    artifact,
    clients,
    clock,
    siteIdentityReader: readerResult.value,
    expectedIdentity,
  });

  assert.equal(result.status, 'PASS');
  assert.equal(result.value.activeDeploymentId, deploymentId);
  assert.equal(staleReadReturned, true);
  assert.equal(sleeps, 1);
});
