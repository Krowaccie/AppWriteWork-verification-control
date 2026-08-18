import { DefaultArtifactClient } from '@actions/artifact';

export async function uploadArtifact({ artifactName, files, rootDirectory }) {
  const client = new DefaultArtifactClient();
  return client.uploadArtifact(artifactName, files, rootDirectory, {
    compressionLevel: 0,
  });
}
