import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import {
  CONTROLLER_SHA,
  RUNNER_SHA,
  SOURCE_SHA,
  TASK4A_EVALUATOR_PATHS,
  evaluatorClosure,
  qualificationArgs,
  qualificationContext,
  setupBindings,
} from '../../../scripts/verification/controller-trust-materials-test-helper.mjs';
import { produceControllerRunnerQualification } from '../../../scripts/verification/controller-trust-materials.mjs';
import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  buildControllerBundlePublication,
  runControllerBundlePublisherCli,
  writeControllerBundlePublicationDirectory,
} from './controller-bundle-publisher.mjs';

const encoder = new TextEncoder();
const execFile = promisify(execFileCallback);
const qualificationDigest = (value) => `sha256:${createHash('sha256')
  .update(`${canonicalJson(value)}\n`)
  .digest('hex')}`;

function qualification(options = {}) {
  return produceControllerRunnerQualification(
    qualificationArgs(options),
    qualificationContext(options),
  ).value;
}

function proposal() {
  return {
    schemaVersion: 'controller-bundle.proposal.v2',
    proposalStatus: 'BLOCKED_UNMATERIALIZED',
    sourceRepository: 'Krowaccie/AppWriteWork',
    sourceRepositoryRevision: 'UNMATERIALIZED',
    controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
    controllerRevision: 'UNMATERIALIZED',
    seedSourceSets: {
      schemaVersion: 'controller-seed-source-sets-reference.v1',
      path: 'packages/verification-controller/controller-seed-source-sets.v1.json',
      schemaPath: 'dev/verification/schemas/controller-seed-source-sets.v1.schema.json',
    },
    entrypoints: [{ path: 'src/controller.mjs', sha256: 'UNMATERIALIZED' }],
    files: [{ path: 'src/controller.mjs', sha256: 'UNMATERIALIZED' }],
    schemaDigests: [{ path: 'schemas/controller.json', sha256: 'UNMATERIALIZED' }],
    trustMaterials: [
      { kind: 'evaluator', path: 'trust/evaluator.v1.json', sha256: 'UNMATERIALIZED' },
      { kind: 'evidenceValidator', path: 'trust/evidence-validator.v1.json', sha256: 'UNMATERIALIZED' },
      { kind: 'networkPolicy', path: 'trust/network-policy.v1.json', sha256: 'UNMATERIALIZED' },
      { kind: 'transcriptCorpus', path: 'trust/transcript-corpus.v2.json', sha256: 'UNMATERIALIZED' },
    ],
    provenance: { path: 'trust/provenance.v1.json', sha256: 'UNMATERIALIZED' },
  };
}

function git(onRead = () => {}) {
  return Object.freeze({
    async readExactSource(request) {
      onRead(request);
      return {
        files: [
          { path: 'schemas/controller.json', mode: '100644', bytes: encoder.encode('{}\n') },
          { path: 'src/controller.mjs', mode: '100644', bytes: encoder.encode('export {};\n') },
        ],
      };
    },
  });
}

function args(gitAdapter = git()) {
  const q = qualification();
  return {
    proposal: proposal(),
    sourceRepositoryRevision: SOURCE_SHA,
    controllerRevision: CONTROLLER_SHA,
    qualification: q.qualification,
    qualificationDigest: q.digest,
    setupBindings: setupBindings(),
    evaluatorClosure: evaluatorClosure(),
    primaryExecutionRetentionMaxSeconds: 3600,
    git: gitAdapter,
  };
}

let publisherVariantOrdinal = 0;

async function importPublisherVariant({ blockManifest = false, blockWrite = false }) {
  const moduleUrl = new URL('./controller-bundle-publisher.mjs', import.meta.url);
  let source = await readFile(moduleUrl, 'utf8');
  if (blockManifest) {
    const materializerImport =
      "import { materializeControllerBundleProposal } from '../../../scripts/verification/controller-bundle.mjs';";
    assert.equal(source.includes(materializerImport), true);
    source = source.replace(
      materializerImport,
      "const materializeControllerBundleProposal = () => ({ status: 'BLOCKED', value: null, diagnostics: [] });",
    );
  }
  if (blockWrite) {
    const start = source.indexOf(
      'export async function writeControllerBundlePublicationDirectory(args) {',
    );
    const end = source.indexOf('\nfunction cliArguments', start);
    assert.equal(start >= 0 && end > start, true);
    source = `${source.slice(0, start)}export async function writeControllerBundlePublicationDirectory() {\n  return blocked('CONTROLLER_BUNDLE_PUBLICATION_WRITE_INVALID');\n}\n${source.slice(end + 1)}`;
  }
  const executableStart = source.indexOf('\nif (process.argv[1] !== undefined');
  assert.equal(executableStart > 0, true);
  source = source.slice(0, executableStart);
  source = source.replace(/from '(\.{1,2}\/[^']+)'/gu, (_match, relativePath) => (
    `from '${new URL(relativePath, moduleUrl).href}'`
  ));
  publisherVariantOrdinal += 1;
  const encoded = Buffer.from(source, 'utf8').toString('base64');
  return import(`data:text/javascript;base64,${encoded}#publisher-variant-${publisherVariantOrdinal}`);
}

async function createCommittedCliFixture(t, prefix) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  const repositoryRoot = path.join(root, 'repository');
  const inputPath = path.join(root, 'input.json');
  const outputPath = path.join(root, 'publication');
  t.after(() => rm(root, { force: true, recursive: true }));
  await mkdir(repositoryRoot);
  const fixtureProposal = proposal();
  const fixtureFiles = new Map([
    ['packages/verification-controller/controller-bundle.proposal.json', `${JSON.stringify(fixtureProposal)}\n`],
    ['schemas/controller.json', '{}\n'],
    ['src/controller.mjs', 'export {};\n'],
    ...TASK4A_EVALUATOR_PATHS.map((filePath) => [filePath, `${filePath}\n`]),
  ]);
  for (const [filePath, content] of fixtureFiles) {
    const absolutePath = path.join(repositoryRoot, ...filePath.split('/'));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, content);
  }
  await execFile('git', ['init', '--initial-branch=fixture'], { cwd: repositoryRoot });
  await execFile('git', ['config', 'user.name', 'Controller Publisher Test'], {
    cwd: repositoryRoot,
  });
  await execFile('git', ['config', 'user.email', 'controller-publisher@example.invalid'], {
    cwd: repositoryRoot,
  });
  await execFile('git', [
    'remote', 'add', 'origin',
    'https://github.com/Krowaccie/AppWriteWork-verification-control.git',
  ], { cwd: repositoryRoot });
  await execFile('git', ['add', '.'], { cwd: repositoryRoot });
  await execFile('git', ['commit', '-m', 'fixture'], { cwd: repositoryRoot });
  const controllerSha = (await execFile('git', ['rev-parse', 'HEAD'], {
    cwd: repositoryRoot,
  })).stdout.trim();
  const nowEpochSeconds = Math.floor(Date.now() / 1000);
  const bindings = setupBindings({ nowEpochSeconds });
  const q = qualification({ bindings, controllerSha, nowEpochSeconds });
  await writeFile(inputPath, JSON.stringify({
    workflowRunId: q.qualification.workflowRunId,
    workflowHeadSha: q.qualification.workflowHeadSha,
    sourceRepositoryRevision: SOURCE_SHA,
    controllerRevision: controllerSha,
    qualification: q.qualification,
    qualificationDigest: q.digest,
    setupBindings: bindings,
    primaryExecutionRetentionMaxSeconds: 3600,
  }));
  return {
    controllerSha,
    environment: {
      GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
      GITHUB_RUN_ID: q.qualification.workflowRunId,
      GITHUB_SHA: controllerSha,
    },
    inputPath,
    outputPath,
    repositoryRoot,
  };
}

test('publisher classifies invalid construction input at the input stage', async () => {
  const published = await buildControllerBundlePublication({}, {});
  assert.equal(published.status, 'BLOCKED');
  assert.equal(
    published.diagnostics[0].code,
    'CONTROLLER_BUNDLE_PUBLISHER_INPUT_INVALID',
  );
});

test('publisher CLI classifies invalid argv at the input stage', async () => {
  const published = await runControllerBundlePublisherCli([], {});
  assert.equal(published.status, 'BLOCKED');
  assert.equal(
    published.diagnostics[0].code,
    'CONTROLLER_BUNDLE_PUBLISHER_CLI_INPUT_INVALID',
  );
});

test('publisher classifies a recomputed invalid qualification at the qualification stage', async () => {
  const input = args();
  input.qualification = structuredClone(input.qualification);
  input.qualification.jobObjectQualification.status = 'FAIL';
  input.qualificationDigest = qualificationDigest(input.qualification);
  const published = await buildControllerBundlePublication(
    input,
    { clock: qualificationContext().clock },
  );
  assert.equal(published.status, 'BLOCKED');
  assert.equal(
    published.diagnostics[0].code,
    'CONTROLLER_BUNDLE_PUBLISHER_QUALIFICATION_INVALID',
  );
});

test('publisher classifies invalid exact-SHA source material at the source stage', async () => {
  const invalidGit = Object.freeze({
    async readExactSource() {
      return Object.freeze({ files: Object.freeze([]) });
    },
  });
  const published = await buildControllerBundlePublication(
    args(invalidGit),
    { clock: qualificationContext().clock },
  );
  assert.equal(published.status, 'BLOCKED');
  assert.equal(
    published.diagnostics[0].code,
    'CONTROLLER_BUNDLE_PUBLISHER_SOURCE_INVALID',
  );
});

test('publisher classifies materializer rejection at the manifest stage', async () => {
  const variant = await importPublisherVariant({ blockManifest: true });
  const published = await variant.buildControllerBundlePublication(
    args(),
    { clock: qualificationContext().clock },
  );
  assert.equal(published.status, 'BLOCKED');
  assert.equal(
    published.diagnostics[0].code,
    'CONTROLLER_BUNDLE_PUBLISHER_MANIFEST_INVALID',
  );
});

test('publisher CLI preserves a bounded publication writer rejection at the write stage', async (t) => {
  const fixture = await createCommittedCliFixture(t, 'controller-publisher-write-stage-');
  const variant = await importPublisherVariant({ blockWrite: true });
  const published = await variant.runControllerBundlePublisherCli(
    [
      '--input', fixture.inputPath,
      '--output', fixture.outputPath,
      '--repository-root', fixture.repositoryRoot,
    ],
    fixture.environment,
  );
  assert.equal(published.status, 'BLOCKED');
  assert.equal(
    published.diagnostics[0].code,
    'CONTROLLER_BUNDLE_PUBLICATION_WRITE_INVALID',
  );
  await assert.rejects(stat(fixture.outputPath), { code: 'ENOENT' });
});

test('publisher materializes direct canonical members from exact controller SHA and same-run trust inputs', async () => {
  const calls = [];
  const published = await buildControllerBundlePublication(
    args(git((request) => calls.push(request))),
    { clock: qualificationContext().clock },
  );
  assert.equal(published.status, 'PASS', JSON.stringify(published.diagnostics));
  assert.deepEqual(calls, [{
    controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
    controllerRevision: CONTROLLER_SHA,
    paths: ['schemas/controller.json', 'src/controller.mjs'],
  }]);
  assert.equal(published.value.manifest.schemaVersion, 'controller-bundle.v2');
  assert.equal(published.value.manifest.sourceRepositoryRevision, SOURCE_SHA);
  assert.equal(published.value.manifest.controllerRevision, CONTROLLER_SHA);
  const paths = published.value.members.map(({ path: memberPath }) => memberPath);
  assert.deepEqual(paths, [...paths].sort());
  assert.ok(paths.includes('packages/verification-controller/controller-bundle.manifest.json'));
  assert.ok(paths.includes('trust/controller-runner-qualification.v1.json'));
  assert.equal(paths.some((memberPath) => /\.(?:zip|tar|tar\.gz)$/iu.test(memberPath)), false);
  assert.equal(published.value.preUploadEvidence.providerArtifactId, undefined);
  assert.equal(published.value.preUploadEvidence.rawOuterZipDigest, undefined);
});

test('publication writer emits exactly the direct member tree and no nested archive', async (t) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'controller-publication-'));
  const outputRoot = path.join(parent, 'publication');
  t.after(() => rm(parent, { force: true, recursive: true }));
  const published = await buildControllerBundlePublication(args(), { clock: qualificationContext().clock });
  const written = await writeControllerBundlePublicationDirectory({ publication: published.value, outputRoot });
  assert.equal(written.status, 'PASS', JSON.stringify(written.diagnostics));
  const manifest = JSON.parse(await readFile(path.join(outputRoot, 'packages', 'verification-controller', 'controller-bundle.manifest.json'), 'utf8'));
  assert.equal(manifest.controllerRevision, CONTROLLER_SHA);
  assert.deepEqual((await readdir(outputRoot)).sort(), ['packages', 'schemas', 'src', 'trust']);
});

test('publisher rejects null/default/fake-shaped Git and stale or cross-run inputs before exact-source access', async () => {
  let calls = 0;
  for (const candidate of [
    { ...args(), git: null },
    { ...args(), git: {} },
    { ...args(), controllerRevision: '9'.repeat(40) },
    { ...args(), qualificationDigest: `sha256:${'0'.repeat(64)}` },
  ]) {
    const result = await buildControllerBundlePublication({
      ...candidate,
      git: candidate.git === null || Object.keys(candidate.git).length === 0
        ? candidate.git
        : git(() => { calls += 1; }),
    }, { clock: qualificationContext().clock });
    assert.equal(result.status, 'BLOCKED');
  }
  assert.equal(calls, 0);
});

test('publisher rejects forged runner qualifications before exact-source access even after digest recomputation', async () => {
  const mutations = [
    (value) => ({ ...value, jobObjectQualification: { ...value.jobObjectQualification, status: 'FAIL' } }),
    (value) => ({ ...value, jobObjectQualification: { bogus: true } }),
    (value) => ({ ...value, jobObjectQualification: { ...value.jobObjectQualification, extra: true } }),
    (value) => ({ ...value, unexpected: true }),
    (value) => ({ ...value, setupBindings: { ...value.setupBindings, extra: `sha256:${'0'.repeat(64)}` } }),
    (value) => {
      const { testCloudSetupAttestationDigest, ...setup } = value.setupBindings;
      return { ...value, setupBindings: setup };
    },
    (value) => ({ ...value, setupBindings: { ...value.setupBindings, testCloudSetupReadbackDigest: { malformed: true } } }),
    (value) => ({ ...value, runnerRevision: 'not-a-revision' }),
  ];
  let sourceReads = 0;
  for (const mutate of mutations) {
    const input = args(git(() => { sourceReads += 1; }));
    input.qualification = mutate(structuredClone(input.qualification));
    input.qualificationDigest = qualificationDigest(input.qualification);
    const published = await buildControllerBundlePublication(input, { clock: qualificationContext().clock });
    assert.equal(published.status, 'BLOCKED');
  }
  assert.equal(sourceReads, 0);
});

test('publisher rejects expired setup bindings before exact-source access', async () => {
  let sourceReads = 0;
  const input = args(git(() => { sourceReads += 1; }));
  input.setupBindings = setupBindings({ nowEpochSeconds: 998_000 });
  const published = await buildControllerBundlePublication(input, { clock: qualificationContext().clock });
  assert.equal(published.status, 'BLOCKED');
  assert.equal(sourceReads, 0);
});

test('CLI binds qualification to its protected workflow run and constructs the production adapter explicitly', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'controller-publisher-cli-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const q = qualification();
  const inputPath = path.join(root, 'input.json');
  const outputPath = path.join(root, 'output');
  await writeFile(inputPath, JSON.stringify({
    workflowRunId: q.qualification.workflowRunId,
    workflowHeadSha: q.qualification.workflowHeadSha,
    sourceRepositoryRevision: SOURCE_SHA,
    controllerRevision: CONTROLLER_SHA,
    qualification: q.qualification,
    qualificationDigest: q.digest,
    setupBindings: setupBindings(),
    primaryExecutionRetentionMaxSeconds: 3600,
  }));
  const cli = await runControllerBundlePublisherCli(
    ['--input', inputPath, '--output', outputPath, '--repository-root', root],
    { GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control', GITHUB_RUN_ID: 'different', GITHUB_SHA: CONTROLLER_SHA },
  );
  assert.equal(cli.status, 'BLOCKED');
  const source = await readFile(new URL('./controller-bundle-publisher.mjs', import.meta.url), 'utf8');
  assert.match(source, /createProductionExactShaGitAdapter\(\{ repositoryRoot \}\)/u);
  assert.doesNotMatch(source, /providerArtifactId|rawOuterZipDigest/u);
});

test('CLI rejects forged qualifications before any production Git command or output staging', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'controller-publisher-cli-gate-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const nowEpochSeconds = Math.floor(Date.now() / 1000);
  const bindings = setupBindings({ nowEpochSeconds });
  const baseline = qualification({ bindings, nowEpochSeconds });
  const mutations = [
    ['failed-job', (descriptor) => {
      descriptor.qualification.jobObjectQualification.status = 'FAIL';
    }],
    ['bogus-job', (descriptor) => {
      descriptor.qualification.jobObjectQualification = { bogus: true };
    }],
    ['extra-job-member', (descriptor) => {
      descriptor.qualification.jobObjectQualification.extra = true;
    }],
    ['malformed-job-member', (descriptor) => {
      descriptor.qualification.jobObjectQualification.killOnJobClose = 'true';
    }],
    ['invalid-runner-revision', (descriptor) => {
      descriptor.qualification.runnerRevision = 'not-a-revision';
    }],
    ['invalid-workflow-run-id', (descriptor) => {
      descriptor.workflowRunId = '0';
      descriptor.qualification.workflowRunId = '0';
    }],
    ['invalid-qualification-setup-binding', (descriptor) => {
      descriptor.qualification.setupBindings.testCloudSetupAttestationDigest = `sha256:${'0'.repeat(64)}`;
    }],
    ['invalid-input-setup-binding', (descriptor) => {
      descriptor.setupBindings.attestationDigest = `sha256:${'0'.repeat(64)}`;
    }],
  ];

  for (const [id, mutate] of mutations) {
    const caseRoot = path.join(root, id);
    const inputPath = path.join(caseRoot, 'input.json');
    const outputPath = path.join(caseRoot, 'output');
    const tracePath = path.join(caseRoot, 'git-trace.json');
    await mkdir(caseRoot, { recursive: true });
    await writeFile(tracePath, '');
    const descriptor = structuredClone({
      workflowRunId: baseline.qualification.workflowRunId,
      workflowHeadSha: baseline.qualification.workflowHeadSha,
      sourceRepositoryRevision: SOURCE_SHA,
      controllerRevision: CONTROLLER_SHA,
      qualification: baseline.qualification,
      qualificationDigest: baseline.digest,
      setupBindings: bindings,
      primaryExecutionRetentionMaxSeconds: 3600,
    });
    mutate(descriptor);
    descriptor.qualificationDigest = qualificationDigest(descriptor.qualification);
    await writeFile(inputPath, JSON.stringify(descriptor));

    const previousTrace = process.env.GIT_TRACE2_EVENT;
    process.env.GIT_TRACE2_EVENT = tracePath;
    try {
      const cli = await runControllerBundlePublisherCli(
        ['--input', inputPath, '--output', outputPath, '--repository-root', caseRoot],
        {
          GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
          GITHUB_RUN_ID: descriptor.workflowRunId,
          GITHUB_SHA: descriptor.workflowHeadSha,
        },
      );
      assert.equal(cli.status, 'BLOCKED', id);
    } finally {
      if (previousTrace === undefined) delete process.env.GIT_TRACE2_EVENT;
      else process.env.GIT_TRACE2_EVENT = previousTrace;
    }
    assert.equal(await readFile(tracePath, 'utf8'), '', `${id} invoked Git before blocking`);
    await assert.rejects(stat(outputPath), { code: 'ENOENT' });
  }
});

test('CLI stages a complete direct-member publication from an exact committed controller fixture', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'controller-publisher-e2e-'));
  const repositoryRoot = path.join(root, 'repository');
  const inputPath = path.join(root, 'input.json');
  const outputPath = path.join(root, 'publication');
  t.after(() => rm(root, { force: true, recursive: true }));
  await mkdir(repositoryRoot);

  const fixtureProposal = proposal();
  const fixtureFiles = new Map([
    ['packages/verification-controller/controller-bundle.proposal.json', `${JSON.stringify(fixtureProposal)}\n`],
    ['schemas/controller.json', '{}\n'],
    ['src/controller.mjs', 'export {};\n'],
    ...TASK4A_EVALUATOR_PATHS.map((filePath) => [filePath, `${filePath}\n`]),
  ]);
  for (const [filePath, content] of fixtureFiles) {
    const absolutePath = path.join(repositoryRoot, ...filePath.split('/'));
    await mkdir(path.dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, content);
  }
  await execFile('git', ['init', '--initial-branch=fixture'], { cwd: repositoryRoot });
  await execFile('git', ['config', 'user.name', 'Controller Publisher Test'], { cwd: repositoryRoot });
  await execFile('git', ['config', 'user.email', 'controller-publisher@example.invalid'], { cwd: repositoryRoot });
  await execFile('git', ['remote', 'add', 'origin', 'https://github.com/Krowaccie/AppWriteWork-verification-control.git'], { cwd: repositoryRoot });
  await execFile('git', ['add', '.'], { cwd: repositoryRoot });
  await execFile('git', ['commit', '-m', 'fixture'], { cwd: repositoryRoot });
  const controllerSha = (await execFile('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot })).stdout.trim();
  const nowEpochSeconds = Math.floor(Date.now() / 1000);
  const bindings = setupBindings({ nowEpochSeconds });
  const q = qualification({ bindings, controllerSha, nowEpochSeconds });
  await writeFile(inputPath, JSON.stringify({
    workflowRunId: q.qualification.workflowRunId,
    workflowHeadSha: q.qualification.workflowHeadSha,
    sourceRepositoryRevision: SOURCE_SHA,
    controllerRevision: controllerSha,
    qualification: q.qualification,
    qualificationDigest: q.digest,
    setupBindings: bindings,
    primaryExecutionRetentionMaxSeconds: 3600,
  }));

  const cli = await runControllerBundlePublisherCli(
    ['--input', inputPath, '--output', outputPath, '--repository-root', repositoryRoot],
    {
      GITHUB_REPOSITORY: 'Krowaccie/AppWriteWork-verification-control',
      GITHUB_RUN_ID: q.qualification.workflowRunId,
      GITHUB_SHA: controllerSha,
    },
  );
  assert.equal(cli.status, 'PASS', JSON.stringify(cli.diagnostics));
  const manifest = JSON.parse(await readFile(
    path.join(outputPath, 'packages', 'verification-controller', 'controller-bundle.manifest.json'),
    'utf8',
  ));
  assert.equal(manifest.controllerRevision, controllerSha);
  const stagedPaths = (await readdir(outputPath, { recursive: true, withFileTypes: true }))
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(outputPath, path.join(entry.parentPath, entry.name)).replaceAll('\\', '/'));
  assert.equal(stagedPaths.some((filePath) => /\.(?:zip|tar|tgz|tar\.gz)$/iu.test(filePath)), false);
  assert.ok(stagedPaths.includes('trust/controller-runner-qualification.v1.json'));
  assert.ok(stagedPaths.includes('trust/evaluator.v1.json'));
});

const PREPUBLICATION_TESTS = Object.freeze([
  'packages/verification-controller/src/test-cloud-cleanup-driver.test.mjs',
  'packages/verification-controller/src/test-cloud-controller.test.mjs',
  'scripts/verification/test-cloud-control-store.test.mjs',
  'scripts/verification/test-cloud-lane.test.mjs',
  'packages/verification-controller/src/test-cloud-controller-source-diagnostics.test.mjs',
]);

function publicationIndentation(line) {
  return line.length - line.trimStart().length;
}

function parsePublicationScalar(value) {
  const trimmed = value.trim();
  if (trimmed === 'null' || trimmed === '~') return null;
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^-?(?:0|[1-9][0-9]*)$/u.test(trimmed)) return Number(trimmed);
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1).trim();
    return inner === '' ? [] : inner.split(',').map(parsePublicationScalar);
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) return JSON.parse(trimmed);
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  return trimmed;
}

function parsePublicationWorkflow(source) {
  assert.equal(source.includes('\t'), false, 'publication workflow YAML must not contain tabs');
  const lines = source.replaceAll('\r\n', '\n').split('\n');

  function skipIgnored(start) {
    let index = start;
    while (index < lines.length) {
      const trimmed = lines[index].trim();
      if (trimmed !== '' && !trimmed.startsWith('#')) break;
      index += 1;
    }
    return index;
  }

  function parseBlockScalar(start, parentIndent) {
    let index = start;
    let contentIndent = null;
    const values = [];
    while (index < lines.length) {
      const line = lines[index];
      if (line.trim() !== '' && publicationIndentation(line) <= parentIndent) break;
      if (line.trim() !== '' && contentIndent === null) contentIndent = publicationIndentation(line);
      if (line.trim() === '') values.push('');
      else {
        assert.ok(
          publicationIndentation(line) >= contentIndent,
          'invalid publication block-scalar indentation',
        );
        values.push(line.slice(contentIndent));
      }
      index += 1;
    }
    return [values.join('\n').replace(/\n+$/u, ''), index];
  }

  function assign(target, key, value) {
    assert.equal(Object.hasOwn(target, key), false, `duplicate publication YAML key: ${key}`);
    target[key] = value;
  }

  function parseMapping(start, expectedIndent, seed = Object.create(null)) {
    const result = seed;
    let index = start;
    while (index < lines.length) {
      index = skipIgnored(index);
      if (index >= lines.length) break;
      const line = lines[index];
      const currentIndent = publicationIndentation(line);
      if (currentIndent < expectedIndent) break;
      assert.equal(currentIndent, expectedIndent, `unexpected YAML indentation at line ${index + 1}`);
      const content = line.slice(currentIndent);
      if (content.startsWith('- ')) break;
      const match = /^([A-Za-z0-9_-]+):(?:\s*(.*))?$/u.exec(content);
      assert.ok(match, `unsupported publication YAML mapping at line ${index + 1}`);
      const [, key, rawValue = ''] = match;
      index += 1;
      if (rawValue === '|') {
        const [parsed, nextIndex] = parseBlockScalar(index, currentIndent);
        assign(result, key, parsed);
        index = nextIndex;
      } else if (rawValue !== '') {
        assign(result, key, parsePublicationScalar(rawValue));
      } else {
        const next = skipIgnored(index);
        if (next < lines.length && publicationIndentation(lines[next]) > currentIndent) {
          const [parsed, nextIndex] = parseNode(next, publicationIndentation(lines[next]));
          assign(result, key, parsed);
          index = nextIndex;
        } else {
          assign(result, key, null);
          index = next;
        }
      }
    }
    return [result, index];
  }

  function parseSequence(start, expectedIndent) {
    const result = [];
    let index = start;
    while (index < lines.length) {
      index = skipIgnored(index);
      if (index >= lines.length) break;
      const line = lines[index];
      const currentIndent = publicationIndentation(line);
      if (currentIndent < expectedIndent) break;
      assert.equal(currentIndent, expectedIndent, `unexpected sequence indentation at line ${index + 1}`);
      const content = line.slice(currentIndent);
      if (!content.startsWith('- ')) break;
      const inline = content.slice(2);
      const match = /^([A-Za-z0-9_-]+):(?:\s*(.*))?$/u.exec(inline);
      if (match === null) {
        result.push(parsePublicationScalar(inline));
        index += 1;
        continue;
      }
      const item = Object.create(null);
      const [, key, rawValue = ''] = match;
      assign(item, key, rawValue === '' ? null : parsePublicationScalar(rawValue));
      index += 1;
      const next = skipIgnored(index);
      if (next < lines.length && publicationIndentation(lines[next]) > currentIndent) {
        const [parsed, nextIndex] = parseMapping(next, publicationIndentation(lines[next]), item);
        result.push(parsed);
        index = nextIndex;
      } else {
        result.push(item);
        index = next;
      }
    }
    return [result, index];
  }

  function parseNode(start, expectedIndent) {
    return lines[start].slice(expectedIndent).startsWith('- ')
      ? parseSequence(start, expectedIndent)
      : parseMapping(start, expectedIndent);
  }

  const start = skipIgnored(0);
  const [parsed, end] = parseNode(start, 0);
  assert.equal(skipIgnored(end), lines.length, 'publication workflow contains unparsed YAML');
  return parsed;
}

function publicationStepIndex(steps, predicate, description) {
  const indexes = steps.flatMap((step, index) => (predicate(step) ? [index] : []));
  assert.equal(indexes.length, 1, `expected one exact ${description} step`);
  return indexes[0];
}

function namedStep(workflow, name) {
  const marker = `      - name: ${name}`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `missing step ${name}`);
  const next = workflow.indexOf('\n      - name: ', start + marker.length);
  return workflow.slice(start, next === -1 ? workflow.length : next);
}

function assertPrepublicationGate(workflow) {
  workflow = workflow.replaceAll('\r\n', '\n');
  const parsed = parsePublicationWorkflow(workflow);
  assert.deepEqual(Object.keys(parsed.jobs), ['publish-controller-bundle']);
  const job = parsed.jobs['publish-controller-bundle'];
  assert.equal(Array.isArray(job.steps), true);
  assert.equal(job.steps.length, 8);
  assert.equal(job.steps.some((step) => Object.hasOwn(step, 'continue-on-error')), false);
  const expectedCommand = [
    'npm ci --ignore-scripts --no-audit --no-fund',
    `node --test --test-isolation=none ${PREPUBLICATION_TESTS.join(' ')}`,
  ].join('\n');
  const gateIndex = publicationStepIndex(
    job.steps,
    (step) => step.run === expectedCommand,
    'prepublication gate',
  );
  const gate = job.steps[gateIndex];
  assert.deepEqual(Object.keys(gate).sort(), ['name', 'run', 'shell']);
  assert.equal(gate.shell, 'pwsh');
  assert.doesNotMatch(gate.run, /[*?\[]/u, 'prepublication command must not use a glob');
  assert.doesNotMatch(gate.run, /\|\|\s*true|;\s*true|exit\s+0/u);

  const setupIndex = publicationStepIndex(
    job.steps,
    (step) => step.uses === 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
    'setup-node',
  );
  const bindingIndex = publicationStepIndex(
    job.steps,
    (step) => typeof step.run === 'string'
      && step.run.includes('node packages/verification-controller/src/test-cloud-binding-artifact-verifier.mjs --input'),
    'binding verification',
  );
  const qualificationIndex = publicationStepIndex(
    job.steps,
    (step) => typeof step.run === 'string'
      && step.run.includes('node packages/verification-controller/src/controller-runner-qualification-cli.mjs --input'),
    'runner qualification',
  );
  const stagingIndex = publicationStepIndex(
    job.steps,
    (step) => typeof step.run === 'string'
      && step.run.includes('node packages/verification-controller/src/controller-bundle-publisher.mjs --input'),
    'publication staging',
  );
  const uploadIndex = publicationStepIndex(
    job.steps,
    (step) => step.uses === 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
    'publication upload',
  );
  assert.deepEqual(
    [setupIndex, gateIndex, bindingIndex, qualificationIndex, stagingIndex, uploadIndex],
    [2, 3, 4, 5, 6, 7],
  );

  const routePattern = /binding|qualif|stag|publish|publication|upload/iu;
  for (const [index, step] of job.steps.entries()) {
    if (index === gateIndex) continue;
    const material = `${step.uses ?? ''}\n${step.run ?? ''}`;
    if (routePattern.test(material)) assert.equal(index > gateIndex, true);
  }
}

test('manual protected workflow uploads direct members under the exact trusted controller SHA', async () => {
  const workflow = await readFile(new URL('../workflows/publish-controller-bundle.yml', import.meta.url), 'utf8');
  assertPrepublicationGate(workflow);
  assert.match(workflow, /workflow_dispatch:/u);
  assert.match(workflow, /initial_seed:/u);
  assert.match(workflow, /runs-on: windows-2025/u);
  assert.match(workflow, /environment: controller-promotion/u);
  assert.match(workflow, /verification-controller-bundle-\$\{\{ inputs\.trusted_controller_sha \}\}/u);
  assert.match(workflow, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/u);
  assert.match(workflow, /controller-runner-qualification-cli\.mjs --input \$env:QUALIFICATION_INPUT --output \$env:PUBLISHER_INPUT/u);
  assert.match(workflow, /controller-bundle-publisher-input\.json/u);
  assert.match(workflow, /PUBLICATION_ROOT: \$\{\{ runner\.temp \}\}\\controller-bundle-publication/u);
  assert.match(workflow, /--output \$env:PUBLICATION_ROOT/u);
  assert.match(workflow, /path: \$\{\{ runner\.temp \}\}\\controller-bundle-publication/u);
  for (const binding of [
    'TEST_CLOUD_SETUP_READBACK_JSON',
    'TEST_CLOUD_SETUP_READBACK_DIGEST',
    'TEST_CLOUD_SETUP_ATTESTATION_JSON',
    'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
    'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
    'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
    'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
  ]) assert.match(workflow, new RegExp(`\\b${binding}\\b`, 'u'));
  assert.match(workflow, /qualifyExecutionObservationReadback/u);
  assert.match(workflow, /checkInitialTestCloudSetup/u);
  assert.match(workflow, /inputs\.initial_seed/u);
  assert.match(workflow, /checked\.value\.controllerBundleSha !== process\.env\.CONTROLLER_REVISION/u);
  assert.match(workflow, /checked\.value\.sourceRepositoryRevision !== process\.env\.SOURCE_REPOSITORY_REVISION/u);
  assert.match(workflow, /validateTestCloudHostedSetupAttestationDocument/u);
  assert.match(workflow, /sha256Bytes\(encoder\.encode\(raw\)\) !== digest/u);
  assert.match(workflow, /canonicalJson\(value\) !== raw/u);
  assert.match(workflow, /const hostedReadback = parseBinding\(\s*'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',\s*'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST'/u);
  assert.match(workflow, /const hostedAttestation = parseBinding\(\s*'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',\s*'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST'/u);
  assert.match(workflow, /canonicalJson\(hostedReadback\.value\.executionObservation\)/u);
  assert.match(workflow, /readback: hostedReadback\.value\.executionObservation/u);
  assert.match(workflow, /readback: hostedReadback\.value,/u);
  assert.match(workflow, /expectedProviderSetupReadbackDigest: bindingValues\.TEST_CLOUD_SETUP_READBACK_DIGEST/u);
  assert.match(workflow, /TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_ID/u);
  assert.match(workflow, /TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_DIGEST/u);
  assert.match(workflow, /test-cloud-binding-artifact-verifier\.mjs/u);
  assert.doesNotMatch(workflow, /vars\.TEST_CLOUD_(?:HOSTED_)?SETUP_/u);
  assert.match(workflow, /expectedHostedSetupReadbackDigest: hostedReadback\.digest/u);
  assert.match(workflow, /expectedExecutionObservationPolicyDigest: checked\.value\.executionObservationPolicyDigest/u);
  assert.match(workflow, /expectedPrimaryExecutionRetentionMaxSeconds: checked\.value\.primaryExecutionRetentionMaxSeconds/u);
  assert.match(workflow, /primaryExecutionRetentionMaxSeconds: checked\.value\.primaryExecutionRetentionMaxSeconds/u);
  assert.doesNotMatch(workflow, /PRIMARY_EXECUTION_RETENTION_MAX_SECONDS/u);
  assert.doesNotMatch(workflow, /\.zip|Compress-Archive|tar\s/u);
});

test('protected publication rejects missing, weakened, reordered, or bypassable prepublication gates', async (t) => {
  const workflow = (await readFile(
    new URL('../workflows/publish-controller-bundle.yml', import.meta.url),
    'utf8',
  )).replaceAll('\r\n', '\n');
  const cases = [
    ['dependency flags removed', workflow.replace(' --ignore-scripts --no-audit --no-fund', '')],
    ['gate made conditional', workflow.replace(
      '      - name: Install and run exact prepublication verification\n        shell: pwsh',
      '      - name: Install and run exact prepublication verification\n        if: success()\n        shell: pwsh',
    )],
    ['gate allowed to fail', workflow.replace(
      '      - name: Install and run exact prepublication verification\n        shell: pwsh',
      '      - name: Install and run exact prepublication verification\n        continue-on-error: true\n        shell: pwsh',
    )],
    ['gate moved after binding', (() => {
      const gate = namedStep(workflow, 'Install and run exact prepublication verification');
      const binding = namedStep(workflow, 'Verify exact Appwrite Test binding artifact');
      return workflow.replace(gate, '__GATE__').replace(binding, gate).replace('__GATE__', binding);
    })()],
    ['test list replaced by glob', workflow.replace(PREPUBLICATION_TESTS.join(' '), '**/*.test.mjs')],
    ['alternate early publisher step', workflow.replace(
      '      - name: Install and run exact prepublication verification\n',
      '      - name: Alternate preparation\n'
        + '        shell: pwsh\n'
        + '        run: node packages/verification-controller/src/controller-bundle-publisher.mjs --input early.json\n\n'
        + '      - name: Install and run exact prepublication verification\n',
    )],
    ['alternate early upload action', workflow.replace(
      '      - name: Install and run exact prepublication verification\n',
      '      - name: Alternate handoff\n'
        + '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n'
        + '        with:\n'
        + '          name: early\n'
        + '          path: early\n\n'
        + '      - name: Install and run exact prepublication verification\n',
    )],
    ['alternate earlier publication job', workflow.replace(
      '  publish-controller-bundle:\n',
      '  alternate-route:\n'
        + '    runs-on: ubuntu-24.04\n'
        + '    steps:\n'
        + '      - name: Alternate route\n'
        + '        run: node alternate-qualification.mjs\n\n'
        + '  publish-controller-bundle:\n',
    )],
    ...PREPUBLICATION_TESTS.map((testPath) => [
      `removed ${testPath}`,
      workflow.replace(` ${testPath}`, ''),
    ]),
  ];
  for (const [name, mutation] of cases) {
    await t.test(name, () => {
      assert.notEqual(mutation, workflow, 'mutation fixture must change workflow');
      assert.throws(() => assertPrepublicationGate(mutation));
    });
  }
});
