import { uploadArtifact as officialUploadArtifact } from '../vendor/actions-artifact/dist/official-client.bundle.mjs';

function fail() {
  throw new Error('ARTIFACT_UPLOAD_CLIENT_INVALID');
}

export function createGithubArtifactClient({
  runtimeBinding,
  uploadOperation = null,
} = {}) {
  if (
    runtimeBinding === null
    || typeof runtimeBinding !== 'object'
    || !Object.isFrozen(runtimeBinding)
    || Reflect.ownKeys(runtimeBinding).length !== 1
    || typeof runtimeBinding.runUpload !== 'function'
    || (uploadOperation !== null && typeof uploadOperation !== 'function')
  ) fail();

  return Object.freeze({
    async uploadArtifact(artifactName, files, rootDirectory, options) {
      if (
        typeof artifactName !== 'string'
        || artifactName.length === 0
        || !Array.isArray(files)
        || files.length !== 39
        || typeof rootDirectory !== 'string'
        || options === null
        || typeof options !== 'object'
        || Reflect.ownKeys(options).length !== 1
        || options.compressionLevel !== 0
      ) fail();
      const args = { artifactName, files, rootDirectory };
      return runtimeBinding.runUpload(() => uploadOperation === null
        ? officialUploadArtifact(args)
        : uploadOperation(args));
    },
  });
}
