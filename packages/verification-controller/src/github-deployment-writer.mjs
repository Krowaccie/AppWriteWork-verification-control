import {
  buildReleaseRecord,
  canonicalReleaseRecordBytes,
  digestReleaseRecord,
  productionReleaseRecordContract,
  validateProductionReleaseBinding,
  validateReleaseExecutionResult,
  validateReleaseRecord,
} from './release-record-contract.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[1-9][0-9]*$/;
const SHA = /^[0-9a-f]{40}$/;
const SECRET_FIELD = /(?:token|secret|private|credential|api.?key|authorization|cookie|password)/i;
const PUBLISH_KEYS = Object.freeze([
  'controllerRevision',
  'recordArtifactDigest',
  'recordArtifactId',
  'releaseRecord',
].sort());

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.getOwnPropertySymbols(value).length === 0 &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}

function inspect(value, seen = new Set()) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return;
  if (typeof value !== 'object' || seen.has(value)) throw blocked('RELEASE_RECORD_INVALID');
  seen.add(value);
  for (const [key, nested] of Object.entries(value)) {
    if (SECRET_FIELD.test(key) || /APPWRITE_PRODUCTION_RELEASE_API_KEY/.test(String(nested))) {
      throw blocked('RELEASE_RECORD_SECRET_FIELD');
    }
    inspect(nested, seen);
  }
}

export {
  buildReleaseRecord,
  canonicalReleaseRecordBytes,
  digestReleaseRecord,
};

export function validateRedactedReleaseExecutionResult(result) {
  inspect(result);
  return validateReleaseExecutionResult(result);
}

export function validateRedactedReleaseRecord(record) {
  inspect(record);
  return validateReleaseRecord(record);
}

function validController(controller, repository) {
  return exactObject(controller, ['repository', 'sha', 'trustedControllerSha']) &&
    controller.repository === repository &&
    SHA.test(controller.sha) &&
    controller.sha === controller.trustedControllerSha;
}

export function createGithubDeploymentWriter({
  repository,
  controller,
  githubCredentialHandle,
  request,
}) {
  if (repository !== productionReleaseRecordContract.repository ||
      !validController(controller, repository) ||
      !githubCredentialHandle || typeof githubCredentialHandle.apply !== 'function' ||
      typeof request !== 'function') {
    throw blocked('GITHUB_DEPLOYMENT_WRITER_INPUT_INVALID');
  }
  return Object.freeze({
    async publish(input) {
      if (!exactObject(input, PUBLISH_KEYS) ||
          input.controllerRevision !== controller.sha ||
          !ID.test(input.recordArtifactId ?? '') ||
          !DIGEST.test(input.recordArtifactDigest ?? '')) {
        throw blocked('GITHUB_DEPLOYMENT_IDENTITY_INVALID');
      }
      let releaseRecord;
      try {
        releaseRecord = validateRedactedReleaseRecord(input.releaseRecord);
      } catch {
        throw blocked('GITHUB_DEPLOYMENT_RECORD_INVALID');
      }
      if (releaseRecord.github.repository !== repository ||
          releaseRecord.github.workflow !== productionReleaseRecordContract.workflow ||
          releaseRecord.github.environment !== productionReleaseRecordContract.environment ||
          releaseRecord.recordDigest !== digestReleaseRecord(releaseRecord)) {
        throw blocked('GITHUB_DEPLOYMENT_RECORD_INVALID');
      }
      const payload = Object.freeze({
        schemaVersion: productionReleaseRecordContract.bindingSchemaVersion,
        recordArtifactId: input.recordArtifactId,
        recordArtifactDigest: input.recordArtifactDigest,
        recordDigest: releaseRecord.recordDigest,
        revision: releaseRecord.sourceRevision,
        artifactManifestDigest: releaseRecord.artifactManifestDigest,
        repository: releaseRecord.github.repository,
        workflow: releaseRecord.github.workflow,
        runId: releaseRecord.github.runId,
        runAttempt: releaseRecord.github.runAttempt,
        environment: releaseRecord.github.environment,
      });
      validateProductionReleaseBinding(payload);
      const headers = githubCredentialHandle.apply({
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      });
      const deployment = await request(`/repos/${repository}/deployments`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ref: controller.sha,
          environment: productionReleaseRecordContract.environment,
          auto_merge: false,
          required_contexts: [],
          payload,
        }),
      });
      if (!Number.isSafeInteger(deployment?.id)) {
        throw blocked('GITHUB_DEPLOYMENT_CREATE_FAILED');
      }
      const status = await request(
        `/repos/${repository}/deployments/${deployment.id}/statuses`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({
            state: 'success',
            environment: productionReleaseRecordContract.environment,
          }),
        },
      );
      if (status?.state !== 'success') throw blocked('GITHUB_DEPLOYMENT_STATUS_FAILED');
      return Object.freeze({ deploymentId: deployment.id, state: 'success' });
    },
  });
}
