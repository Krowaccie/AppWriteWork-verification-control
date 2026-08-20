import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, open, readFile, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  produceControllerRunnerQualification,
  produceControllerTrustMaterials,
  TRUST_MATERIAL_PATHS,
  validateControllerRunnerQualification,
} from '../../../scripts/verification/controller-trust-materials.mjs';
import { materializeControllerBundleProposal } from '../../../scripts/verification/controller-bundle.mjs';
import { readControllerSourceAtExactSha } from './exact-sha-controller-source.mjs';
import { createProductionExactShaGitAdapter } from './production-exact-sha-git-adapter.mjs';

const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const MANIFEST_PATH = 'packages/verification-controller/controller-bundle.manifest.json';
const SHA = /^[0-9a-f]{40}$/u;
const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u;
const ARG_KEYS = [
  'proposal', 'sourceRepositoryRevision', 'controllerRevision', 'qualification',
  'qualificationDigest', 'setupBindings', 'evaluatorClosure',
  'primaryExecutionRetentionMaxSeconds', 'git',
];
const SYSTEM_CLOCK = Object.freeze({
  nowEpochSeconds: () => Math.floor(Date.now() / 1000),
});

function exactObject(value, keys) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const names = Object.keys(value).sort();
    const expected = [...keys].sort();
    return names.length === expected.length && names.every((name, index) => name === expected[index]) ? value : null;
  } catch {
    return null;
  }
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function result(status, value, code = null) {
  return Object.freeze({
    status,
    value,
    diagnostics: code === null ? [] : Object.freeze([Object.freeze({
      code,
      retryable: false,
      safeMessage: 'Controller bundle publication input is invalid.',
    })]),
  });
}

function blocked(code) {
  return result('BLOCKED', null, code);
}

function canonicalBytes(value) {
  return new TextEncoder().encode(`${canonicalJson(value)}\n`);
}

function member(pathValue, mode, bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return Object.freeze({ path: pathValue, mode, bytes: copy, sha256: digestBytes(copy) });
}

export async function buildControllerBundlePublication(args, validationContext) {
  try {
    const input = exactObject(args, ARG_KEYS);
    const context = exactObject(validationContext, ['clock']);
    const git = input === null ? null : exactObject(input.git, ['readExactSource']);
    if (
      input === null
      || context === null
      || !SHA.test(input.sourceRepositoryRevision ?? '')
      || !SHA.test(input.controllerRevision ?? '')
      || input.sourceRepositoryRevision === input.controllerRevision
      || input.qualification?.sourceRepositoryRevision !== input.sourceRepositoryRevision
      || input.qualification?.controllerRevision !== input.controllerRevision
      || input.qualification?.workflowHeadSha !== input.controllerRevision
      || git === null
      || Object.isFrozen(input.git) !== true
      || typeof git.readExactSource !== 'function'
    ) return blocked('CONTROLLER_BUNDLE_PUBLISHER_INPUT_INVALID');

    const qualificationValidation = validateControllerRunnerQualification({
      qualification: input.qualification,
      qualificationDigest: input.qualificationDigest,
      expected: {
        workflowRunId: input.qualification?.workflowRunId,
        workflowHeadSha: input.controllerRevision,
        controllerRepository: CONTROLLER_REPOSITORY,
        sourceRepository: 'Krowaccie/AppWriteWork',
        sourceRepositoryRevision: input.sourceRepositoryRevision,
        controllerRevision: input.controllerRevision,
        runnerRevision: input.qualification?.runnerRevision,
        runnerImage: 'windows-2025',
        setupBindings: input.qualification?.setupBindings,
      },
    });
    if (qualificationValidation.status !== 'PASS') {
      return blocked('CONTROLLER_BUNDLE_PUBLISHER_QUALIFICATION_INVALID');
    }

    const trust = produceControllerTrustMaterials({
      qualification: input.qualification,
      qualificationDigest: input.qualificationDigest,
      setupBindings: input.setupBindings,
      evaluatorClosure: input.evaluatorClosure,
      primaryExecutionRetentionMaxSeconds: input.primaryExecutionRetentionMaxSeconds,
    }, context);
    if (trust.status !== 'PASS') return blocked('CONTROLLER_BUNDLE_PUBLISHER_TRUST_INVALID');
    const source = await readControllerSourceAtExactSha({
      controllerRepository: CONTROLLER_REPOSITORY,
      controllerRevision: input.controllerRevision,
      proposal: input.proposal,
      git: input.git,
    });
    if (source.status !== 'PASS') return blocked('CONTROLLER_BUNDLE_PUBLISHER_SOURCE_INVALID');
    const trustBytes = Object.fromEntries(Object.entries(trust.value.materials).map(([kind, artifact]) => [kind, artifact.bytes]));
    const manifestResult = materializeControllerBundleProposal({
      proposal: input.proposal,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      controllerRevision: input.controllerRevision,
      committedFiles: source.value.files.map(({ path: filePath, bytes }) => ({ path: filePath, bytes })),
      trustMaterials: trustBytes,
      provenance: trust.value.provenance.bytes,
    });
    if (manifestResult.status !== 'PASS') {
      return blocked('CONTROLLER_BUNDLE_PUBLISHER_MANIFEST_INVALID');
    }

    const members = [
      member(MANIFEST_PATH, '100644', canonicalBytes(manifestResult.value)),
      ...source.value.files.map((record) => member(record.path, record.mode, record.bytes)),
      ...Object.entries(trust.value.materials).map(([kind, artifact]) => (
        member(TRUST_MATERIAL_PATHS[kind], '100644', artifact.bytes)
      )),
      member(TRUST_MATERIAL_PATHS.provenance, '100644', trust.value.provenance.bytes),
      member(TRUST_MATERIAL_PATHS.qualification, '100644', canonicalBytes(input.qualification)),
    ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    if (
      members.some((record) => !SAFE_PATH.test(record.path) || /\.(?:zip|tar|tgz|tar\.gz)$/iu.test(record.path))
      || new Set(members.map(({ path: memberPath }) => memberPath.toLowerCase())).size !== members.length
    ) return blocked('CONTROLLER_BUNDLE_PUBLICATION_LAYOUT_INVALID');
    const preUploadEvidence = Object.freeze({
      schemaVersion: 'controller-bundle-pre-upload-evidence.v1',
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      controllerRevision: input.controllerRevision,
      materializedManifestDigest: members.find(({ path: memberPath }) => memberPath === MANIFEST_PATH).sha256,
      qualificationDigest: input.qualificationDigest,
      members: Object.freeze(members.map(({ path: memberPath, mode, sha256 }) => Object.freeze({ path: memberPath, mode, sha256 }))),
    });
    return result('PASS', Object.freeze({
      manifest: manifestResult.value,
      members: Object.freeze(members),
      preUploadEvidence,
    }));
  } catch {
    return blocked('CONTROLLER_BUNDLE_PUBLISHER_INVALID');
  }
}

export async function writeControllerBundlePublicationDirectory(args) {
  let stagingRoot = null;
  try {
    const input = exactObject(args, ['publication', 'outputRoot']);
    if (input === null || typeof input.outputRoot !== 'string' || !path.isAbsolute(input.outputRoot) || !Array.isArray(input.publication?.members)) {
      return blocked('CONTROLLER_BUNDLE_PUBLICATION_WRITE_INVALID');
    }
    const requestedRoot = path.resolve(input.outputRoot);
    const resolvedParent = await realpath(path.dirname(requestedRoot));
    const outputRoot = path.join(resolvedParent, path.basename(requestedRoot));
    const identities = new Set();
    for (const record of input.publication.members) {
      if (
        !SAFE_PATH.test(record?.path ?? '')
        || !['100644', '100755'].includes(record?.mode)
        || !utilTypes.isUint8Array(record?.bytes)
        || identities.has(record.path.toLowerCase())
      ) return blocked('CONTROLLER_BUNDLE_PUBLICATION_WRITE_INVALID');
      identities.add(record.path.toLowerCase());
    }
    stagingRoot = await mkdtemp(path.join(resolvedParent, `.${path.basename(outputRoot)}.tmp-`));
    for (const record of input.publication.members) {
      const destination = path.join(stagingRoot, ...record.path.split('/'));
      if (!destination.startsWith(`${stagingRoot}${path.sep}`)) return blocked('CONTROLLER_BUNDLE_PUBLICATION_WRITE_INVALID');
      await mkdir(path.dirname(destination), { recursive: true });
      const handle = await open(destination, 'wx', record.mode === '100755' ? 0o755 : 0o644);
      try {
        await handle.writeFile(record.bytes);
      } finally {
        await handle.close();
      }
    }
    await rename(stagingRoot, outputRoot);
    stagingRoot = null;
    return result('PASS', input.publication.preUploadEvidence);
  } catch {
    return blocked('CONTROLLER_BUNDLE_PUBLICATION_WRITE_INVALID');
  } finally {
    if (stagingRoot !== null) {
      try {
        await rm(stagingRoot, { force: true, recursive: true });
      } catch {
        // The publication is already blocked; do not replace it with a rejected promise.
      }
    }
  }
}

function cliArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 6) return null;
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (!['--input', '--output', '--repository-root'].includes(argv[index]) || values[argv[index]] !== undefined) return null;
    values[argv[index]] = argv[index + 1];
  }
  return values;
}

export async function runControllerBundlePublisherCli(argv = process.argv.slice(2), environment = process.env) {
  let stage = 'INPUT';
  try {
    const parsed = cliArguments(argv);
    if (parsed === null) return blocked('CONTROLLER_BUNDLE_PUBLISHER_CLI_INPUT_INVALID');
    const repositoryRoot = await realpath(path.resolve(parsed['--repository-root']));
    const input = JSON.parse(await readFile(path.resolve(parsed['--input']), 'utf8'));
    const descriptor = exactObject(input, [
      'workflowRunId', 'workflowHeadSha',
      'sourceRepositoryRevision', 'controllerRevision', 'qualification',
      'qualificationDigest', 'setupBindings', 'primaryExecutionRetentionMaxSeconds',
    ]);
    if (
      descriptor === null
      || environment.GITHUB_REPOSITORY !== CONTROLLER_REPOSITORY
      || environment.GITHUB_RUN_ID !== descriptor.workflowRunId
      || environment.GITHUB_SHA !== descriptor.workflowHeadSha
      || descriptor.workflowRunId !== descriptor.qualification?.workflowRunId
      || descriptor.workflowHeadSha !== descriptor.qualification?.workflowHeadSha
      || descriptor.workflowHeadSha !== descriptor.controllerRevision
    ) return blocked('CONTROLLER_BUNDLE_PUBLISHER_CLI_INPUT_INVALID');

    stage = 'QUALIFICATION';
    const qualificationValidation = validateControllerRunnerQualification({
      qualification: descriptor.qualification,
      qualificationDigest: descriptor.qualificationDigest,
      expected: {
        workflowRunId: descriptor.workflowRunId,
        workflowHeadSha: descriptor.workflowHeadSha,
        controllerRepository: CONTROLLER_REPOSITORY,
        sourceRepository: 'Krowaccie/AppWriteWork',
        sourceRepositoryRevision: descriptor.sourceRepositoryRevision,
        controllerRevision: descriptor.controllerRevision,
        runnerRevision: descriptor.qualification?.runnerRevision,
        runnerImage: 'windows-2025',
        setupBindings: descriptor.qualification?.setupBindings,
      },
    });
    const reproducedQualification = qualificationValidation.status === 'PASS'
      ? produceControllerRunnerQualification({
        workflowRunId: descriptor.workflowRunId,
        workflowHeadSha: descriptor.workflowHeadSha,
        controllerRepository: CONTROLLER_REPOSITORY,
        sourceRepository: 'Krowaccie/AppWriteWork',
        sourceRepositoryRevision: descriptor.sourceRepositoryRevision,
        controllerRevision: descriptor.controllerRevision,
        runnerRevision: descriptor.qualification?.runnerRevision,
        runnerImage: 'windows-2025',
        setupBindings: descriptor.setupBindings,
        jobObjectQualification: descriptor.qualification?.jobObjectQualification,
      }, {
        clock: SYSTEM_CLOCK,
        primaryExecutionRetentionMaxSeconds: descriptor.primaryExecutionRetentionMaxSeconds,
      })
      : null;
    if (
      qualificationValidation.status !== 'PASS'
      || reproducedQualification?.status !== 'PASS'
      || reproducedQualification.value.digest !== descriptor.qualificationDigest
      || canonicalJson(reproducedQualification.value.qualification) !== canonicalJson(descriptor.qualification)
    ) return blocked('CONTROLLER_BUNDLE_PUBLISHER_CLI_QUALIFICATION_INVALID');

    stage = 'GIT_ADAPTER';
    const git = createProductionExactShaGitAdapter({ repositoryRoot });
    const proposalPath = 'packages/verification-controller/controller-bundle.proposal.json';
    stage = 'PROPOSAL_SOURCE';
    const proposalBlob = await git.readExactSource({
      controllerRepository: CONTROLLER_REPOSITORY,
      controllerRevision: descriptor.controllerRevision,
      paths: [proposalPath],
    });
    const proposal = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(proposalBlob.files[0].bytes));
    const evaluatorPaths = [
      'dev/verification/bootstrap/qualify-runner.mjs',
      'scripts/verification/canonical-json.mjs',
      'scripts/verification/controller-bundle.mjs',
      'scripts/verification/controller-trust-materials.mjs',
      'scripts/verification/test-cloud-bootstrap.mjs',
      'scripts/verification/test-cloud-provider-contract.mjs',
      'scripts/verification/test-cloud-setup-attestation.mjs',
    ];
    stage = 'EVALUATOR_SOURCE';
    const evaluatorSource = await git.readExactSource({
      controllerRepository: CONTROLLER_REPOSITORY,
      controllerRevision: descriptor.controllerRevision,
      paths: evaluatorPaths,
    });
    stage = 'PUBLICATION';
    const publication = await buildControllerBundlePublication({
      proposal,
      sourceRepositoryRevision: descriptor.sourceRepositoryRevision,
      controllerRevision: descriptor.controllerRevision,
      qualification: descriptor.qualification,
      qualificationDigest: descriptor.qualificationDigest,
      setupBindings: descriptor.setupBindings,
      primaryExecutionRetentionMaxSeconds: descriptor.primaryExecutionRetentionMaxSeconds,
      evaluatorClosure: {
        entrypoint: 'scripts/verification/controller-trust-materials.mjs',
        runtime: { name: 'node', version: '24.11.1', platform: 'windows-2025' },
        files: evaluatorSource.files,
      },
      git,
    }, { clock: SYSTEM_CLOCK });
    if (publication.status !== 'PASS') return publication;
    stage = 'WRITE';
    const written = await writeControllerBundlePublicationDirectory({
      publication: publication.value,
      outputRoot: path.resolve(parsed['--output']),
    });
    return written.status === 'PASS'
      ? result('PASS', publication.value.preUploadEvidence)
      : written;
  } catch {
    return blocked(`CONTROLLER_BUNDLE_PUBLISHER_CLI_${stage}_INVALID`);
  }
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cliResult = await runControllerBundlePublisherCli();
  if (cliResult.status !== 'PASS') {
    const code = cliResult.diagnostics[0]?.code;
    process.stderr.write(`BLOCKED ${
      /^CONTROLLER_BUNDLE_[A-Z_]+_INVALID$/u.test(code ?? '')
        ? code : 'CONTROLLER_BUNDLE_PUBLISHER_CLI_INVALID'
    }\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`${canonicalJson(cliResult.value)}\n`);
  }
}
