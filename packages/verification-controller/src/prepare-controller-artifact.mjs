import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  extractBoundedZipArchive,
  MAX_VERIFICATION_ARCHIVE_BYTES,
  readBoundedResponseBytes,
} from './controller-archive-verifier.mjs';
import { verifyGithubControllerArtifact } from './github-controller-artifact-verifier.mjs';
import { createProductionExactShaGitAdapter } from './production-exact-sha-git-adapter.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const POSITIVE_ID = /^[1-9][0-9]*$/u;
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';

function safeSignedUrl(rawLocation) {
  try {
    const candidate = new URL(rawLocation);
    const hostname = candidate.hostname.toLowerCase();
    if (candidate.protocol !== 'https:'
      || !(
        hostname === 'objects.githubusercontent.com'
        || hostname.endsWith('.githubusercontent.com')
        || hostname.endsWith('.blob.core.windows.net')
      )
      || candidate.username !== ''
      || candidate.password !== ''
      || (candidate.port !== '' && candidate.port !== '443')
      || !candidate.pathname.startsWith('/')
      || candidate.pathname.length < 2
      || candidate.hash !== '') return null;
    return candidate.toString();
  } catch {
    return null;
  }
}

function validInput(input) {
  return input !== null
    && typeof input === 'object'
    && input.repository === CONTROLLER_REPOSITORY
    && FULL_SHA.test(input.sha ?? '')
    && POSITIVE_ID.test(input.artifactId ?? '')
    && DIGEST.test(input.bundleDigest ?? '')
    && typeof input.authorization === 'string'
    && input.authorization.length > 0
    && typeof input.outputDirectory === 'string'
    && path.isAbsolute(input.outputDirectory)
    && path.resolve(input.outputDirectory) === input.outputDirectory;
}

export async function prepareControllerArtifact(input, dependencies = {}) {
  if (!validInput(input)) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const root = path.resolve(dependencies.root ?? '.');
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  const proposal = JSON.parse(await (dependencies.readFile ?? readFile)(
    path.join(root, 'packages/verification-controller/controller-bundle.proposal.json'),
    'utf8',
  ));
  const git = (dependencies.createGit ?? createProductionExactShaGitAdapter)({
    repositoryRoot: root,
  });
  const verified = await verifyGithubControllerArtifact(Object.freeze({
    artifactId: input.artifactId,
    authorization: input.authorization,
    bundleDigest: input.bundleDigest,
    repository: input.repository,
    requiredEntrypoint: input.requiredEntrypoint,
    runtimeSha: input.sha,
    trustedSha: input.sha,
  }), {
    fetchImpl,
    git,
    lstat: dependencies.lstat ?? lstat,
    now: dependencies.now ?? Date.now,
    proposal,
    readFile: dependencies.readFile ?? readFile,
    realpath: dependencies.realpath ?? realpath,
    root,
  });
  if (verified.status !== 'PASS') throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');

  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${input.authorization}`,
    'User-Agent': 'appwritework-verification-controller',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  const redirectResponse = await fetchImpl(
    `https://api.github.com/repos/${input.repository}/actions/artifacts/${input.artifactId}/zip`,
    { method: 'GET', redirect: 'manual', headers },
  );
  const signedUrl = redirectResponse.status === 302
    ? safeSignedUrl(redirectResponse.headers.get('location'))
    : null;
  if (signedUrl === null) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const archiveResponse = await fetchImpl(signedUrl, {
    method: 'GET',
    redirect: 'error',
    headers: {
      Accept: 'application/octet-stream',
      'User-Agent': 'appwritework-verification-controller',
    },
  });
  if (archiveResponse.status !== 200) throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  const archive = await readBoundedResponseBytes(
    archiveResponse,
    MAX_VERIFICATION_ARCHIVE_BYTES,
  );
  const archiveDigest = `sha256:${createHash('sha256').update(archive).digest('hex')}`;
  if (archiveDigest !== input.bundleDigest) {
    throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
  }

  const outputRoot = input.outputDirectory;
  await (dependencies.mkdir ?? mkdir)(outputRoot);
  const entries = [...extractBoundedZipArchive(archive).entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  for (const [relativePath, bytes] of entries) {
    const destination = path.resolve(outputRoot, ...relativePath.split('/'));
    if (!destination.startsWith(`${outputRoot}${path.sep}`)) {
      throw new TypeError('BLOCKED TRUSTED_CONTROLLER_REQUIRED');
    }
    await (dependencies.mkdir ?? mkdir)(path.dirname(destination), { recursive: true });
    await (dependencies.writeFile ?? writeFile)(destination, bytes, { flag: 'wx', mode: 0o600 });
  }
  return Object.freeze({
    artifactId: verified.value.controllerArtifactId,
    bundleDigest: verified.value.controllerBundleDigest,
    repository: verified.value.controllerRepository,
    sha: verified.value.controllerBundleSha,
  });
}

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  if (argv.length !== 2 || argv[0] !== '--output' || typeof argv[1] !== 'string') return 2;
  const environment = dependencies.environment ?? process.env;
  try {
    const prepared = await (dependencies.prepare ?? prepareControllerArtifact)({
      artifactId: environment.TRUSTED_CONTROLLER_ARTIFACT_ID,
      authorization: environment.CONTROLLER_ARTIFACT_READ_TOKEN,
      bundleDigest: environment.TRUSTED_CONTROLLER_BUNDLE_DIGEST,
      outputDirectory: path.resolve(argv[1]),
      repository: environment.GITHUB_REPOSITORY,
      requiredEntrypoint: environment.REQUIRED_CONTROLLER_ENTRYPOINT,
      sha: environment.TRUSTED_CONTROLLER_SHA,
    });
    const append = dependencies.appendFileSync ?? appendFileSync;
    append(environment.GITHUB_ENV, [
      'PROOF_STATUS=PASS',
      `PROOF_REPOSITORY=${prepared.repository}`,
      `PROOF_SHA=${prepared.sha}`,
      `PROOF_ARTIFACT_ID=${prepared.artifactId}`,
      `PROOF_BUNDLE_DIGEST=${prepared.bundleDigest}`,
      '',
    ].join('\n'), 'utf8');
    return 0;
  } catch {
    return 2;
  }
}

if (process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
