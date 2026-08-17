import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createProductionReleaseAppwriteClient } from './production-release-appwrite.mjs';
import { loadProductionReleaseEnvironment } from './production-release-environment.mjs';
import {
  canonicalPartialReleaseRecordBytes,
  executeProductionRelease,
  validatePartialReleaseRecord,
} from './production-release-executor.mjs';
import { validateVerifiedProductionHandoff } from './verified-production-handoff.mjs';

export const RELEASE_USAGE = 'Usage: release:production --revision SHA --approval-ref REF --qualifying-run-id RUN_ID --verified-handoff PATH';

const PARTIAL_RELEASE_DIRECTORY = '.release-execution';
const PARTIAL_RELEASE_PATH =
  '.release-execution/partial-release-execution-result.v1.json';
const CONTROLLER_PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY_ROOT = resolve(CONTROLLER_PACKAGE_ROOT, '..', '..');
const CONTROLLER_MANIFEST_PATH = resolve(CONTROLLER_PACKAGE_ROOT, 'package.json');
const PARTIAL_PERSISTENCE_DEPENDENCY_KEYS = Object.freeze([
  'mkdir',
  'outputRoot',
  'readFile',
  'writeFile',
]);

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function exactOptions(argv) {
  const allowed = new Set(['--revision', '--approval-ref', '--qualifying-run-id', '--verified-handoff']);
  if (!Array.isArray(argv) || argv.length !== 8) throw blocked('RELEASE_ARGUMENTS_INVALID');
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(key) || Object.hasOwn(values, key) ||
        typeof value !== 'string' || value.length === 0) {
      throw blocked('RELEASE_ARGUMENTS_INVALID');
    }
    values[key] = value;
  }
  return values;
}

export function parseReleaseArguments(argv) {
  if (Array.isArray(argv) && argv.length === 1 && argv[0] === '--help') {
    return Object.freeze({ help: true });
  }
  const values = exactOptions(argv);
  if (!/^[0-9a-f]{40}$/.test(values['--revision'])) throw blocked('CONTROLLER_REVISION_INVALID');
  if (!/^[1-9][0-9]*$/.test(values['--qualifying-run-id'])) throw blocked('QUALIFYING_RUN_ID_INVALID');
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,254}$/.test(values['--approval-ref'])) {
    throw blocked('APPROVAL_REF_INVALID');
  }
  if (/[\u0000-\u001f]/.test(values['--verified-handoff'])) throw blocked('VERIFIED_HANDOFF_PATH_INVALID');
  return Object.freeze({
    help: false,
    revision: values['--revision'],
    approvalRef: values['--approval-ref'],
    qualifyingRunId: values['--qualifying-run-id'],
    verifiedHandoffPath: values['--verified-handoff'],
  });
}

export function attestControllerExecution({ env, revision, approvalRef }) {
  if (env?.GITHUB_REPOSITORY !== 'Krowaccie/AppWriteWork-verification-control') throw blocked('CONTROLLER_REPOSITORY_MISMATCH');
  if (!/^[0-9a-f]{40}$/.test(env?.TRUSTED_CONTROLLER_SHA ?? '') ||
      env.GITHUB_SHA !== env.TRUSTED_CONTROLLER_SHA) throw blocked('CONTROLLER_SHA_MISMATCH');
  if (env.GITHUB_ENVIRONMENT !== 'production-release') throw blocked('CONTROLLER_ENVIRONMENT_MISMATCH');
  if (env.PRODUCTION_RELEASE_APPROVED !== 'true' ||
      env.PRODUCTION_RELEASE_APPROVED_SHA !== revision ||
      env.PRODUCTION_RELEASE_APPROVED_ACTION !== 'production-release' ||
      env.PRODUCTION_RELEASE_APPROVAL_REF !== approvalRef) {
    throw blocked('CONTROLLER_APPROVAL_MISMATCH');
  }
  return Object.freeze({
    controllerRepository: env.GITHUB_REPOSITORY,
    controllerRevision: env.GITHUB_SHA,
    applicationRevision: revision,
    approvalRef,
  });
}

function qualifyHandoff({ handoff, args, bytes, env }) {
  if (!handoff || typeof handoff !== 'object' || Array.isArray(handoff)) throw blocked('VERIFIED_HANDOFF_INVALID');
  if (handoff.sourceRevision !== args.revision ||
      String(handoff.sourceRunId ?? '') !== args.qualifyingRunId) throw blocked('QUALIFYING_EVIDENCE_MISMATCH');
  if (handoff.qualifyingStatus !== 'PASS' || handoff.testLeaseStatus !== 'idle' ||
      handoff.cleanupDebt !== false ||
      !/^sha256:[0-9a-f]{64}$/.test(handoff.localEvidenceDigest ?? '') ||
      !/^sha256:[0-9a-f]{64}$/.test(handoff.testCloudEvidenceDigest ?? '')) {
    throw blocked('QUALIFYING_EVIDENCE_DEBT');
  }
  const normalized = String(env?.VERIFIED_HANDOFF_SHA256 ?? '').replace(/^sha256:/, '');
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (!/^[0-9a-f]{64}$/.test(normalized) || normalized !== actual) {
    throw blocked('VERIFIED_HANDOFF_DIGEST_MISMATCH');
  }
  const trustedClassificationDigest =
    env?.EXPECTED_EXCLUDED_TEST_ONLY_CLASSIFICATION_DIGEST;
  if (!/^sha256:[0-9a-f]{64}$/.test(trustedClassificationDigest ?? '') ||
      handoff.excludedTestOnlyProof?.count !== 1 ||
      handoff.excludedTestOnlyProof?.classificationDigest !== trustedClassificationDigest) {
    throw blocked('PRODUCTION_EXCLUSION_PROOF_MISMATCH');
  }
  return Object.freeze({
    handoff,
    expectedExcludedTestOnlyProof: Object.freeze({
      count: 1,
      classificationDigest: trustedClassificationDigest,
    }),
  });
}

function safeArtifactPath(base, candidate) {
  if (typeof candidate !== 'string' || candidate.length === 0 ||
      isAbsolute(candidate) || candidate.includes('\\') ||
      candidate.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw blocked('PRODUCTION_HANDOFF_INVALID');
  }
  const resolved = resolve(base, candidate);
  const rel = relative(base, resolved);
  if (rel.startsWith('..') || isAbsolute(rel)) throw blocked('PRODUCTION_HANDOFF_INVALID');
  return resolved;
}

async function defaultReadVerifiedInput(path) {
  const absoluteHandoff = resolve(path);
  const bytes = await readFile(absoluteHandoff);
  let handoff;
  let inventory;
  try {
    handoff = JSON.parse(bytes.toString('utf8'));
    inventory = JSON.parse(await readFile(
      new URL('../../../dev/verification/environments/production.inventory.v1.json', import.meta.url),
      'utf8',
    ));
  } catch {
    throw blocked('VERIFIED_HANDOFF_INVALID');
  }
  if (!Array.isArray(handoff?.releaseEligibleArtifacts)) throw blocked('VERIFIED_HANDOFF_INVALID');
  const base = dirname(absoluteHandoff);
  const files = new Map();
  for (const record of handoff.releaseEligibleArtifacts) {
    const artifactPath = safeArtifactPath(base, record?.relativePath);
    files.set(record.relativePath, new Uint8Array(await readFile(artifactPath)));
  }
  return Object.freeze({ handoff, bytes, inventory, files });
}

export async function runReleaseProduction({
  argv,
  env,
  readVerifiedInput = defaultReadVerifiedInput,
  loadReleaseEnvironment = loadProductionReleaseEnvironment,
  validateVerifiedInput = qualifyHandoff,
  validateHandoff = validateVerifiedProductionHandoff,
  createAppwriteClient = createProductionReleaseAppwriteClient,
  executeProductionReleaseImpl = executeProductionRelease,
  executeRelease,
}) {
  const args = parseReleaseArguments(argv);
  if (args.help) return Object.freeze({ help: true, output: RELEASE_USAGE });
  const attestation = attestControllerExecution({ env, revision: args.revision, approvalRef: args.approvalRef });
  let input;
  try {
    input = await readVerifiedInput(args.verifiedHandoffPath);
  } catch (error) {
    if (error?.code) throw error;
    throw blocked('VERIFIED_HANDOFF_READ_FAILED');
  }
  const handoff = input?.handoff ?? input;
  const bytes = input?.bytes ?? Buffer.from(JSON.stringify(handoff));
  const qualified = await validateVerifiedInput({ handoff, args, bytes, env, attestation });
  const verifiedHandoff = qualified?.handoff ?? qualified;
  const expectedExcludedTestOnlyProof = qualified?.expectedExcludedTestOnlyProof;
  validateHandoff({
    handoff: verifiedHandoff,
    files: input?.files,
    inventory: input?.inventory,
    expectedExcludedTestOnlyProof,
  });
  const releaseEnvironment = loadReleaseEnvironment(env);
  if (typeof executeRelease === 'function') {
    return executeRelease({ args, attestation, handoff: verifiedHandoff, releaseEnvironment });
  }
  return executeProductionReleaseImpl({
    inventory: input?.inventory,
    handoff: verifiedHandoff,
    files: input?.files,
    expectedExcludedTestOnlyProof,
    approvalRef: args.approvalRef,
    createClient: (targets) => createAppwriteClient({
      endpoint: input?.inventory?.environment?.endpoint,
      projectId: input?.inventory?.environment?.projectId,
      credentialHandle: releaseEnvironment,
      targets,
      fetchImpl: globalThis.fetch,
    }),
  });
}

export function partialReleaseOutputPaths(outputRoot = REPOSITORY_ROOT) {
  if (typeof outputRoot !== 'string' || !isAbsolute(outputRoot)) {
    throw blocked('PARTIAL_RELEASE_OUTPUT_ROOT_INVALID');
  }
  const normalizedRoot = resolve(outputRoot);
  const packageRoot = resolve(normalizedRoot, 'packages', 'verification-controller');
  if (normalizedRoot !== REPOSITORY_ROOT || packageRoot !== CONTROLLER_PACKAGE_ROOT) {
    throw blocked('PARTIAL_RELEASE_OUTPUT_ROOT_INVALID');
  }
  return Object.freeze({
    outputRoot: normalizedRoot,
    logicalPath: PARTIAL_RELEASE_PATH,
    path: resolve(normalizedRoot, PARTIAL_RELEASE_PATH),
  });
}

async function validatePartialReleaseControllerManifest(readFileImpl) {
  let manifest;
  try {
    manifest = JSON.parse(await readFileImpl(CONTROLLER_MANIFEST_PATH, 'utf8'));
  } catch {
    throw blocked('PARTIAL_RELEASE_OUTPUT_ROOT_INVALID');
  }
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest) ||
      manifest.name !== '@appwritework/verification-controller' ||
      manifest.private !== true ||
      manifest.type !== 'module' ||
      manifest.scripts === null || typeof manifest.scripts !== 'object' ||
      Array.isArray(manifest.scripts) ||
      manifest.scripts['release:production'] !== 'node src/release-production.mjs') {
    throw blocked('PARTIAL_RELEASE_OUTPUT_ROOT_INVALID');
  }
}

export async function persistPartialReleaseRecord(record, dependencies = {
  mkdir,
  outputRoot: REPOSITORY_ROOT,
  readFile,
  writeFile,
}) {
  if (dependencies === null || typeof dependencies !== 'object' ||
      Array.isArray(dependencies) ||
      JSON.stringify(Object.keys(dependencies).sort()) !==
        JSON.stringify(PARTIAL_PERSISTENCE_DEPENDENCY_KEYS) ||
      typeof dependencies.mkdir !== 'function' ||
      typeof dependencies.readFile !== 'function' ||
      typeof dependencies.writeFile !== 'function') {
    throw blocked('PARTIAL_RELEASE_RECORD_PERSIST_FAILED');
  }
  const paths = partialReleaseOutputPaths(dependencies.outputRoot);
  validatePartialReleaseRecord(record);
  await validatePartialReleaseControllerManifest(dependencies.readFile);
  const bytes = canonicalPartialReleaseRecordBytes(record);
  await dependencies.mkdir(resolve(paths.outputRoot, PARTIAL_RELEASE_DIRECTORY), {
    recursive: true,
  });
  await dependencies.writeFile(paths.path, bytes, { flag: 'wx' });
  return Object.freeze({ path: paths.logicalPath });
}

export async function runReleaseProductionCli({
  argv,
  env,
  runRelease = runReleaseProduction,
  persistPartial = persistPartialReleaseRecord,
  writeStdout = (value) => process.stdout.write(value),
  writeStderr = (value) => process.stderr.write(value),
}) {
  try {
    const result = await runRelease({ argv, env });
    if (result.help) {
      writeStdout(`${result.output}\n`);
      return 0;
    }
    writeStdout(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    let message = typeof error?.message === 'string' &&
      error.message.startsWith('BLOCKED ')
      ? error.message
      : 'BLOCKED RELEASE_INTERNAL_ERROR';
    if (error?.code === 'PRODUCTION_RELEASE_PARTIAL_FAILURE' &&
        error.partialReleaseRecord !== undefined) {
      try {
        await persistPartial(error.partialReleaseRecord);
      } catch {
        message = 'BLOCKED PARTIAL_RELEASE_RECORD_PERSIST_FAILED';
      }
    }
    writeStderr(`${message}\n`);
    return 2;
  }
}

async function main() {
  const exitCode = await runReleaseProductionCli({
    argv: process.argv.slice(2),
    env: process.env,
  });
  if (exitCode !== 0) process.exitCode = exitCode;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
