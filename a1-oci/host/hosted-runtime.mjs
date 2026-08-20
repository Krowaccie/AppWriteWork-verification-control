import { readFile } from 'node:fs/promises';

import { createA1SupervisorClient } from './a1-supervisor-client.mjs';
import { createGithubArtifactClient } from './github-artifact-client.mjs';
import { createA1NetworkPolicyProbe } from './network-policy-probe.mjs';
import { createValidatedArtifactUploadClient } from './validated-artifact-upload.mjs';
import { createWorkspaceKernelDriver } from './workspace-kernel-driver.mjs';
import { runTrustedHostedSourceArtifact } from '../launcher/repository/packages/verification-controller/src/source-artifact-hosted-entrypoint.mjs';
import {
  createPosixSourceArtifactOutputFilesystem,
  createPosixSourceArtifactSourceFilesystem,
} from '../launcher/repository/packages/verification-controller/src/source-artifact-posix-filesystem.mjs';
import { createPosixSourceArtifactKernelHost } from '../launcher/repository/packages/verification-controller/src/source-artifact-posix-kernel-host.mjs';
import { createBoundedPosixProcessTransport } from '../launcher/repository/packages/verification-controller/src/source-artifact-posix-process-transport.mjs';
import { createBoundedPosixSandboxTransport } from '../launcher/repository/packages/verification-controller/src/source-artifact-posix-sandbox-transport.mjs';
import { createPosixSourceArtifactWorkspaceHost } from '../launcher/repository/packages/verification-controller/src/source-artifact-posix-workspace.mjs';
import { createPublicationLeaseAuthority } from '../launcher/repository/packages/verification-controller/src/source-artifact-publication-lease-authority.mjs';
import { createSameSessionSourceArtifactPublisher } from '../launcher/repository/packages/verification-controller/src/source-artifact-same-session-publisher.mjs';
import { createSameSessionSourceArtifactUploadHost } from '../launcher/repository/packages/verification-controller/src/source-artifact-same-session-upload-host.mjs';
import { createTrustedSourceSnapshotHost } from '../launcher/repository/packages/verification-controller/src/source-artifact-source-control.mjs';
import { createSourceArtifactSourceLeaseAuthority } from '../launcher/repository/packages/verification-controller/src/source-artifact-source-lease-authority.mjs';

const REQUEST_KEYS = Object.freeze([
  'repository', 'schemaVersion', 'sourceRef', 'sourceRevision', 'sourceTreeDigest',
  'workflow', 'workflowRunAttempt', 'workflowRunId',
]);
const REVISION = /^[0-9a-f]{40}$/u;
const TREE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const EMPTY_DIAGNOSTICS = Object.freeze([]);
const inventoryDecoder = new TextDecoder('utf-8', { fatal: true });
const inventoryEncoder = new TextEncoder();

export const HOSTED_RUNTIME_PATHS = Object.freeze({
  artifactOutputRoot: '/work/artifacts',
  candidateWorkspaceRoot: '/github/workspace',
  childTemp: '/work/launcher/child',
  configHome: '/work/launcher/child/config-home',
  controllerTempRoot: '/work/controller-upload',
  exportRoot: '/work/launcher/source',
  gitExecutable: '/usr/bin/git',
  launcherTempRoot: '/work/launcher',
  nodeExecutable: '/usr/local/bin/node',
  npmCache: '/work/launcher/child/npm-cache',
  npmExecutable: '/usr/local/bin/npm',
  siteOutput: '/work/launcher/site',
});

const LIMITS = Object.freeze({
  trustedInventoryBytes: 1024 * 1024,
  verifierManifestBytes: 1024 * 1024,
  artifactManifestBytes: 1024 * 1024,
  artifactHandoffBytes: 1024 * 1024,
  artifactArchiveMemberBytes: 128 * 1024 * 1024,
  outputTreeBytes: 256 * 1024 * 1024,
  outputFileMembers: 39,
  canonicalAbsolutePathBytes: 4096,
  sourceGitArchiveBytes: 256 * 1024 * 1024,
  stdoutBytes: 16 * 1024 * 1024,
  stderrBytes: 16 * 1024 * 1024,
});

function closed(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function blocked(code, safeMessage) {
  return closed({
    diagnostics: Object.freeze([closed({ code, retryable: false, safeMessage })]),
    status: 'BLOCKED',
    value: null,
  });
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalInventoryBytes(value) {
  if (!(value instanceof Uint8Array) || value.byteLength > LIMITS.trustedInventoryBytes) {
    throw new Error('TRUSTED_INVENTORY_INVALID');
  }
  let parsed;
  try {
    parsed = JSON.parse(inventoryDecoder.decode(new Uint8Array(value)));
  } catch {
    throw new Error('TRUSTED_INVENTORY_INVALID');
  }
  return inventoryEncoder.encode(canonical(parsed));
}

export function parseHostedRequest(text) {
  let value;
  try { value = JSON.parse(text); } catch { throw new Error('HOSTED_REQUEST_INVALID'); }
  if (
    typeof text !== 'string' || value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Reflect.ownKeys(value).length !== REQUEST_KEYS.length
    || !REQUEST_KEYS.every((key) => Object.hasOwn(value, key))
    || canonical(value) !== text
    || value.repository !== 'Krowaccie/AppWriteWork'
    || value.schemaVersion !== 'verification-a1-hosted-request.v1'
    || value.sourceRef !== 'refs/heads/main'
    || !REVISION.test(value.sourceRevision)
    || !TREE_DIGEST.test(value.sourceTreeDigest)
    || value.workflow !== 'Verify Main'
    || !Number.isSafeInteger(value.workflowRunAttempt) || value.workflowRunAttempt <= 0
    || typeof value.workflowRunId !== 'string' || !RUN_ID.test(value.workflowRunId)
  ) throw new Error('HOSTED_REQUEST_INVALID');
  return Object.freeze({ ...value });
}

export function captureGithubArtifactRuntimeBinding(environment) {
  if (
    environment === null || typeof environment !== 'object'
    || environment.GITHUB_ACTIONS !== 'true'
    || typeof environment.ACTIONS_RUNTIME_TOKEN !== 'string'
    || environment.ACTIONS_RUNTIME_TOKEN.length === 0
    || typeof environment.ACTIONS_RESULTS_URL !== 'string'
  ) throw new Error('ARTIFACT_UPLOAD_RUNTIME_UNAVAILABLE');
  let resultsUrl;
  try { resultsUrl = new URL(environment.ACTIONS_RESULTS_URL); } catch {
    throw new Error('ARTIFACT_UPLOAD_RUNTIME_UNAVAILABLE');
  }
  if (resultsUrl.protocol !== 'https:') throw new Error('ARTIFACT_UPLOAD_RUNTIME_UNAVAILABLE');
  const token = environment.ACTIONS_RUNTIME_TOKEN;
  const url = environment.ACTIONS_RESULTS_URL;
  delete environment.ACTIONS_RUNTIME_TOKEN;
  delete environment.ACTIONS_RESULTS_URL;
  let active = false;
  let used = false;
  return Object.freeze({
    async runUpload(operation) {
      if (active) throw new Error('ARTIFACT_UPLOAD_ACTIVE');
      if (used) throw new Error('ARTIFACT_UPLOAD_ALREADY_USED');
      if (typeof operation !== 'function') throw new Error('ARTIFACT_UPLOAD_OPERATION_INVALID');
      active = true;
      used = true;
      environment.ACTIONS_RUNTIME_TOKEN = token;
      environment.ACTIONS_RESULTS_URL = url;
      try { return await operation(); } finally {
        delete environment.ACTIONS_RUNTIME_TOKEN;
        delete environment.ACTIONS_RESULTS_URL;
        active = false;
      }
    },
  });
}

export function createHostedRuntimeConfiguration(request, trustedInventoryBytes) {
  const outputRoot = `${HOSTED_RUNTIME_PATHS.artifactOutputRoot}/.verification/artifacts/${request.sourceRevision}`;
  return Object.freeze({
    artifactOutputRoot: HOSTED_RUNTIME_PATHS.artifactOutputRoot,
    launcherTempRoot: HOSTED_RUNTIME_PATHS.launcherTempRoot,
    limits: LIMITS,
    nodeExecutable: HOSTED_RUNTIME_PATHS.nodeExecutable,
    npmExecutable: HOSTED_RUNTIME_PATHS.npmExecutable,
    producerArgv: Object.freeze([
      '--output', `.verification/artifacts/${request.sourceRevision}`,
      '--repository', request.repository,
      '--revision', request.sourceRevision,
      '--source-ref', request.sourceRef,
      '--workflow', request.workflow,
      '--workflow-run-attempt', String(request.workflowRunAttempt),
      '--workflow-run-id', request.workflowRunId,
    ]),
    publishValidatedOutput: true,
    repository: request.repository,
    sourceCheckoutRoot: HOSTED_RUNTIME_PATHS.candidateWorkspaceRoot,
    sourceRef: request.sourceRef,
    sourceRevision: request.sourceRevision,
    sourceTreeDigest: request.sourceTreeDigest,
    trustedInventoryBytes: canonicalInventoryBytes(trustedInventoryBytes),
    workflow: request.workflow,
    workflowRunAttempt: request.workflowRunAttempt,
    workflowRunId: request.workflowRunId,
    outputRoot,
  });
}

function supervisorPaths(exportRoot) {
  return closed({
    commandTemp: HOSTED_RUNTIME_PATHS.childTemp,
    configHome: HOSTED_RUNTIME_PATHS.configHome,
    exportRoot,
    git: HOSTED_RUNTIME_PATHS.gitExecutable,
    node: HOSTED_RUNTIME_PATHS.nodeExecutable,
    npm: HOSTED_RUNTIME_PATHS.npmExecutable,
    npmCache: HOSTED_RUNTIME_PATHS.npmCache,
    siteOutput: HOSTED_RUNTIME_PATHS.siteOutput,
  });
}

function composePlatform(configuration, runtimeBinding) {
  const networkPolicyProbe = createA1NetworkPolicyProbe();
  const sourceSupervisor = createA1SupervisorClient({
    networkPolicyProbe,
    paths: supervisorPaths(HOSTED_RUNTIME_PATHS.candidateWorkspaceRoot),
  });
  const buildSupervisor = createA1SupervisorClient({
    networkPolicyProbe,
    paths: supervisorPaths(HOSTED_RUNTIME_PATHS.exportRoot),
  });
  const sourceLeaseAuthority = createSourceArtifactSourceLeaseAuthority();
  const driver = createWorkspaceKernelDriver({
    paths: Object.freeze({
      outputRoot: configuration.outputRoot,
      sourceRoot: HOSTED_RUNTIME_PATHS.exportRoot,
    }),
  });
  const kernelHost = createPosixSourceArtifactKernelHost({ driver, platform: 'linux' });
  const sourceSnapshotHost = createTrustedSourceSnapshotHost({
    filesystem: createPosixSourceArtifactSourceFilesystem({ kernelHost, platform: 'linux' }),
    gitExecutable: HOSTED_RUNTIME_PATHS.gitExecutable,
    limits: configuration.limits,
    processTransport: createBoundedPosixProcessTransport({
      gitExecutable: HOSTED_RUNTIME_PATHS.gitExecutable,
      sourceCheckoutRoot: HOSTED_RUNTIME_PATHS.candidateWorkspaceRoot,
      supervisor: sourceSupervisor,
    }),
    sourceLeaseIssuer: sourceLeaseAuthority.sourceControl,
  });
  const workspaceHost = createPosixSourceArtifactWorkspaceHost({
    kernelHost,
    platform: 'linux',
    sourceLeaseClaimer: sourceLeaseAuthority.workspace,
    workspace: Object.freeze({
      childTemp: HOSTED_RUNTIME_PATHS.childTemp,
      exportRoot: HOSTED_RUNTIME_PATHS.exportRoot,
      outputRoot: configuration.outputRoot,
      siteOutput: HOSTED_RUNTIME_PATHS.siteOutput,
    }),
  });
  const sandboxTransport = createBoundedPosixSandboxTransport({
    nodeExecutable: HOSTED_RUNTIME_PATHS.nodeExecutable,
    npmExecutable: HOSTED_RUNTIME_PATHS.npmExecutable,
    supervisor: buildSupervisor,
    workspace: Object.freeze({
      commandTemp: HOSTED_RUNTIME_PATHS.childTemp,
      configHome: HOSTED_RUNTIME_PATHS.configHome,
      exportRoot: HOSTED_RUNTIME_PATHS.exportRoot,
      npmCache: HOSTED_RUNTIME_PATHS.npmCache,
      siteOutput: HOSTED_RUNTIME_PATHS.siteOutput,
    }),
  });
  const officialArtifactClient = createGithubArtifactClient({ runtimeBinding });
  const githubRuntimeBinding = Object.freeze({
    async assertAvailable() { return closed({ diagnostics: EMPTY_DIAGNOSTICS, status: 'PASS', value: null }); },
    operatingSystem: 'linux',
    protocolVersion: 'github-actions-artifact-runtime.v1',
  });
  const publicationAuthority = createPublicationLeaseAuthority();
  const artifactUploadHost = createSameSessionSourceArtifactUploadHost({
    artifactUploadClient: createValidatedArtifactUploadClient({
      candidateWorkspaceRoot: HOSTED_RUNTIME_PATHS.candidateWorkspaceRoot,
      controllerTempRoot: HOSTED_RUNTIME_PATHS.controllerTempRoot,
      githubRuntimeBinding,
      officialArtifactClient,
    }),
    publicationPublisherAuthority: publicationAuthority.publisherAuthority,
  });
  const validatedOutputSink = createSameSessionSourceArtifactPublisher({
    artifactUploadHost,
    limits: Object.freeze({
      maxArtifactBytes: 256 * 1024 * 1024,
      maxChunkBytes: 64 * 1024,
      maxMemberBytes: 128 * 1024 * 1024,
    }),
  });
  return Object.freeze({
    filesystem: createPosixSourceArtifactOutputFilesystem({ kernelHost, platform: 'linux' }),
    publicationLeaseAuthority: publicationAuthority.launcherAuthority,
    sandboxTransport,
    sourceSnapshotHost,
    validatedOutputSink,
    workspaceHost,
  });
}

export async function runHostedRuntime({ environment, requestText } = {}) {
  let request;
  let runtimeBinding;
  try {
    request = parseHostedRequest(requestText);
    runtimeBinding = captureGithubArtifactRuntimeBinding(environment);
  } catch (error) {
    const code = error?.message === 'HOSTED_REQUEST_INVALID'
      ? 'ARTIFACT_SCHEMA_INVALID'
      : 'ARTIFACT_UPLOAD_RUNTIME_UNAVAILABLE';
    return blocked(code, code === 'ARTIFACT_SCHEMA_INVALID'
      ? 'Trusted artifact session data does not match the closed contract.'
      : 'GitHub Actions artifact runtime is unavailable.');
  }
  try {
    const inventory = await readFile(new URL(
      '../launcher/repository/dev/verification/environments/test-cloud.inventory.v1.json',
      import.meta.url,
    ));
    const configuration = createHostedRuntimeConfiguration(request, inventory);
    const outputRoot = configuration.outputRoot;
    const controllerConfiguration = Object.freeze(Object.fromEntries(
      Object.entries(configuration).filter(([key]) => key !== 'outputRoot'),
    ));
    if (!outputRoot.startsWith(`${HOSTED_RUNTIME_PATHS.artifactOutputRoot}/`)) {
      return blocked('ARTIFACT_SCHEMA_INVALID', 'Trusted artifact session data does not match the closed contract.');
    }
    return await runTrustedHostedSourceArtifact(Object.freeze({
      controllerConfiguration,
      platformCapabilities: composePlatform(configuration, runtimeBinding),
    }));
  } catch {
    return blocked('ARTIFACT_BUILD_FAILED', 'Trusted artifact construction could not be completed.');
  }
}
