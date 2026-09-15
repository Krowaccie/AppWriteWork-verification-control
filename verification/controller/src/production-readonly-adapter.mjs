import {
  productionEnvironmentDigest,
  productionInventory,
} from './production-readonly-environment.mjs';
import { validateReleaseRecord } from './release-record-contract.mjs';

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[1-9][0-9]*$/;
const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const EXPECTED_TARGET_KEYS = Object.freeze([
  `site:web:${productionInventory.site.logicalId}`,
  ...productionInventory.productFunctions.map(
    ({ logicalId }) => `function:${logicalId}:${logicalId}`,
  ),
].sort());

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function blocked(code) {
  return deepFreeze({
    status: 'BLOCKED',
    diagnostics: [{ code, safeMessage: 'Production read-only verification is blocked.', retryable: false }],
  });
}

function hasExactKeys(value, expected) {
  try {
    return value !== null
      && typeof value === 'object'
      && !Array.isArray(value)
      && Object.getPrototypeOf(value) === Object.prototype
      && Object.getOwnPropertySymbols(value).length === 0
      && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
      && Object.values(Object.getOwnPropertyDescriptors(value))
        .every((descriptor) => Object.hasOwn(descriptor, 'value'));
  } catch {
    return false;
  }
}

function validCandidate(value) {
  return value === null || (typeof value === 'string' && SHA.test(value));
}

function validController(value) {
  return hasExactKeys(value, [
    'bundleDigest',
    'repository',
    'sha',
    'trustedBundleDigest',
    'trustedControllerSha',
  ])
    && value.repository === REPOSITORY
    && typeof value.sha === 'string'
    && SHA.test(value.sha)
    && value.sha === value.trustedControllerSha
    && typeof value.bundleDigest === 'string'
    && DIGEST.test(value.bundleDigest)
    && value.bundleDigest === value.trustedBundleDigest;
}

function validInvocation(value) {
  return hasExactKeys(value, ['artifactId', 'candidateRevision'])
    && typeof value.artifactId === 'string'
    && ID.test(value.artifactId)
    && validCandidate(value.candidateRevision);
}

function expectedEnvironmentTargetKeys(environment) {
  const site = environment?.siteTarget;
  const functions = environment?.functionTargets;
  if (
    site?.kind !== 'site'
    || typeof site.logicalId !== 'string'
    || !Array.isArray(functions)
    || functions.length !== 35
    || functions.some((target) => target?.kind !== 'function' || typeof target.logicalId !== 'string')
  ) return null;
  const keys = [`site:${site.logicalId}`, ...functions.map(({ logicalId }) => `function:${logicalId}`)];
  return new Set(keys).size === 36 ? keys.sort() : null;
}

function validTrustedRecordEnvelope(envelope) {
  if (
    !hasExactKeys(envelope, ['record', 'recordArtifactDigest', 'recordDigest'])
    || typeof envelope.recordArtifactDigest !== 'string'
    || !DIGEST.test(envelope.recordArtifactDigest)
    || typeof envelope.recordDigest !== 'string'
    || !DIGEST.test(envelope.recordDigest)
  ) return false;
  try {
    validateReleaseRecord(envelope.record);
  } catch {
    return false;
  }
  return envelope.record.recordDigest === envelope.recordDigest;
}

function validHostedSiteIdentity(identity, record, siteRecord) {
  return (
    hasExactKeys(identity, [
      'schemaVersion',
      'sitePayloadDigest',
      'sourceRevision',
      'verifierManifestDigest',
    ])
    && identity.schemaVersion === 'hosted-site-build-identity.v1'
    && typeof identity.sourceRevision === 'string'
    && SHA.test(identity.sourceRevision)
    && typeof identity.sitePayloadDigest === 'string'
    && DIGEST.test(identity.sitePayloadDigest)
    && typeof identity.verifierManifestDigest === 'string'
    && DIGEST.test(identity.verifierManifestDigest)
    && identity.sourceRevision === record.sourceRevision
    && identity.sitePayloadDigest === siteRecord.canonicalContentDigest
    && identity.verifierManifestDigest === record.verifierManifestDigest
  );
}

export function createProductionReadonlyAdapter({
  controller,
  createEnvironment,
  recordReader,
  appwrite,
  http,
  resolveTarget,
} = {}) {
  const preflight = async ({ candidateRevision = null } = {}) => {
    if (!validCandidate(candidateRevision)) return blocked('CANDIDATE_REVISION_INVALID');
    if (!validController(controller)) return blocked('CONTROLLER_ATTESTATION_MISMATCH');
    if (
      typeof createEnvironment !== 'function'
      || typeof recordReader?.readTrustedReleaseRecord !== 'function'
      || typeof appwrite?.getSiteMetadata !== 'function'
      || typeof appwrite?.getSiteDeployment !== 'function'
      || typeof appwrite?.getFunctionMetadata !== 'function'
      || typeof appwrite?.getFunctionDeployment !== 'function'
      || typeof http?.get !== 'function'
      || typeof resolveTarget !== 'function'
    ) return blocked('PRODUCTION_READONLY_COLLABORATOR_INVALID');
    return deepFreeze({ status: 'PASS', diagnostics: [] });
  };

  const execute = async (input = {}) => {
    if (!validInvocation(input)) return blocked('RELEASE_RECORD_INPUT_INVALID');
    const { candidateRevision = null, artifactId } = input;
    const ready = await preflight({ candidateRevision });
    if (ready.status !== 'PASS') return ready;

    try {
      const recordResult = await recordReader.readTrustedReleaseRecord({ artifactId });
      if (recordResult?.status !== 'PASS') return blocked('RELEASE_RECORD_BLOCKED');
      const envelope = recordResult.value;
      if (!validTrustedRecordEnvelope(envelope)) return blocked('RELEASE_RECORD_INVALID');
      const { record, recordDigest } = envelope;

      const environment = await createEnvironment();
      if (environment?.status !== 'PASS') return blocked('PRODUCTION_ENVIRONMENT_BLOCKED');
      const environmentTargetKeys = expectedEnvironmentTargetKeys(environment.value);
      const expectedDeploymentKeys = EXPECTED_TARGET_KEYS.map((key) => {
        const [kind, , deploymentLogicalTarget] = key.split(':');
        return `${kind}:${deploymentLogicalTarget}`;
      }).sort();
      if (
        environment.value.environmentDigest !== productionEnvironmentDigest
        || JSON.stringify(environmentTargetKeys) !== JSON.stringify(expectedDeploymentKeys)
      ) return blocked('PRODUCTION_ENVIRONMENT_MISMATCH');

      const siteRecord = record.targets.find(({ kind }) => kind === 'site');
      for (const targetRecord of record.targets) {
        const target = resolveTarget(targetRecord);
        if (
          target?.kind !== targetRecord.kind
          || target?.logicalId !== targetRecord.deploymentLogicalTarget
        ) return blocked('PRODUCTION_TARGET_RESOLUTION_MISMATCH');
        if (targetRecord.kind === 'site') {
          const metadata = await appwrite.getSiteMetadata(target);
          const deployment = await appwrite.getSiteDeployment(target, targetRecord.deploymentId);
          if (
            metadata.deploymentId !== targetRecord.deploymentId
            || deployment.$id !== targetRecord.deploymentId
            || deployment.status !== 'ready'
            || deployment.active !== true
          ) return blocked('PRODUCTION_SITE_READBACK_MISMATCH');
        } else {
          const metadata = await appwrite.getFunctionMetadata(target);
          const deployment = await appwrite.getFunctionDeployment(target, targetRecord.deploymentId);
          if (
            metadata.deploymentId !== targetRecord.deploymentId
            || deployment.$id !== targetRecord.deploymentId
            || deployment.status !== 'ready'
            || deployment.active !== true
          ) return blocked('PRODUCTION_FUNCTION_READBACK_MISMATCH');
        }
      }

      const identity = await http.get(environment.value.publicTargets.buildIdentity);
      if (!validHostedSiteIdentity(identity?.body, record, siteRecord)) {
        return blocked('PUBLIC_BUILD_IDENTITY_MISMATCH');
      }

      return deepFreeze({
        status: 'PASS',
        candidateRevision,
        observedDeployment: {
          revision: record.sourceRevision,
          artifactDigest: siteRecord.canonicalContentDigest,
          releaseRecordId: null,
          releaseRecordDigest: recordDigest,
          readbackSource: 'public-build-identity',
        },
        diagnostics: [],
      });
    } catch {
      return blocked('PRODUCTION_READONLY_EXECUTION_FAILED');
    }
  };

  const describeEnvironment = () => deepFreeze({
    environmentClass: 'production',
    lane: 'production-readonly',
  });

  return deepFreeze({
    describeEnvironment,
    environmentClass: 'production',
    execute,
    lane: 'production-readonly',
    preflight,
  });
}
