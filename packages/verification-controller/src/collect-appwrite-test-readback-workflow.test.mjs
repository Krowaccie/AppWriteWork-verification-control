import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflows = ['packages/verification-controller/workflows/collect-appwrite-test-readback.yml'];
const COLLECTOR_WORKFLOW_SEAL = Object.freeze({
  bytes: 7685,
  digest: '3c11873d57945367cc95a48375953637e321f865bcbbc81b8b41532de8f2bca3',
});

try {
  await readFile('.github/workflows/collect-appwrite-test-readback.yml', 'utf8');
  workflows.unshift('.github/workflows/collect-appwrite-test-readback.yml');
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
}

function canonicalWorkflow(text) {
  assert.equal(text.startsWith('\uFEFF'), false, 'workflow YAML must not have a BOM');
  assert.equal(text.includes('\t'), false, 'workflow YAML must not contain tabs');
  const canonical = text.replaceAll('\r\n', '\n');
  assert.equal(canonical.includes('\r'), false, 'workflow YAML has a stray carriage return');
  return canonical;
}

function assertWorkflowSeal(text) {
  const canonical = canonicalWorkflow(text);
  assert.equal(
    Buffer.byteLength(canonical, 'utf8'),
    COLLECTOR_WORKFLOW_SEAL.bytes,
    'workflow byte count changed',
  );
  assert.equal(
    createHash('sha256').update(canonical, 'utf8').digest('hex'),
    COLLECTOR_WORKFLOW_SEAL.digest,
    'workflow digest changed',
  );
  return canonical;
}

function flatMapping(text, name, indent) {
  const lines = text.split('\n');
  const marker = `${' '.repeat(indent)}${name}:`;
  const matches = lines.flatMap((line, index) => (line === marker ? [index] : []));
  assert.equal(matches.length, 1, `expected one ${name} mapping`);
  const entries = [];
  for (let index = matches[0] + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === '') continue;
    const leading = /^ */u.exec(line)[0].length;
    if (leading <= indent) break;
    const match = new RegExp(`^ {${indent + 2}}([^:#]+): ([^#]+)$`, 'u').exec(line);
    assert.notEqual(match, null, `non-flat ${name} entry: ${line}`);
    entries.push([match[1], match[2].trimEnd()]);
  }
  return entries;
}

function scopedBlock(text, marker, indent) {
  const lines = text.split('\n');
  const prefix = `${' '.repeat(indent)}${marker}`;
  const start = lines.findIndex((line) => line === prefix);
  assert.notEqual(start, -1, `missing ${marker}`);
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (lines[index] === '') continue;
    const leading = /^ */u.exec(lines[index])[0].length;
    if (leading <= indent) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

function stepBlock(text, name) {
  const marker = `      - name: ${name}`;
  const start = text.indexOf(marker);
  assert.notEqual(start, -1, `missing step ${name}`);
  const next = text.indexOf('\n      - name: ', start + marker.length);
  return text.slice(start, next === -1 ? text.length : next);
}

function stepEnvironmentEntries(block) {
  const lines = block.split('\n');
  const start = lines.indexOf('        env:');
  assert.notEqual(start, -1, 'missing step environment');
  const entries = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const match = /^ {10}([A-Z][A-Z0-9_]+): (.+)$/u.exec(lines[index]);
    if (match === null) break;
    entries.push([match[1], match[2]]);
  }
  return entries;
}

function runScalars(text) {
  const lines = text.split('\n');
  const scalars = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^( *)run: ?(.*)$/u.exec(lines[index]);
    if (match === null) continue;
    const indent = match[1].length;
    if (match[2] !== '|') {
      scalars.push(match[2]);
      continue;
    }
    const body = [];
    for (index += 1; index < lines.length; index += 1) {
      const leading = /^ */u.exec(lines[index])[0].length;
      if (lines[index] !== '' && leading <= indent) {
        index -= 1;
        break;
      }
      body.push(lines[index]);
    }
    scalars.push(body.join('\n'));
  }
  return scalars;
}

function isInside(text, block, index) {
  const start = text.indexOf(block);
  return start !== -1 && index >= start && index < start + block.length;
}

const EXPECTED_VALIDATION_RUN = [
  '        run: |',
  "          $ErrorActionPreference = 'Stop'",
  '          foreach ($value in @($env:REQUESTED_CONTROLLER_SHA, $env:SOURCE_REPOSITORY_REVISION, $env:RUNNER_REVISION)) {',
  "            if ($value -cnotmatch '^[0-9a-f]{40}$') { throw 'BLOCKED READBACK_TUPLE_INVALID' }",
  '          }',
  "          if ($env:SOURCE_RUN_ID -cnotmatch '^[1-9][0-9]*$' -or $env:SOURCE_RUN_ATTEMPT -cnotmatch '^[1-9][0-9]*$') {",
  "            throw 'BLOCKED READBACK_TUPLE_INVALID'",
  '          }',
  '          if ($env:REQUESTED_CONTROLLER_SHA -cne $env:TRUSTED_CONTROLLER_SHA -or $env:WORKFLOW_HEAD_SHA -cne $env:TRUSTED_CONTROLLER_SHA) {',
  "            throw 'BLOCKED CONTROLLER_REVISION_MISMATCH'",
  '          }',
  "          if ($env:INITIAL_SEED -ceq 'true') {",
  "            if ($env:CONTROLLER_ARTIFACT_ID -or $env:CONTROLLER_ARTIFACT_DIGEST) { throw 'BLOCKED INITIAL_SEED_TUPLE_INVALID' }",
  "          } elseif ($env:INITIAL_SEED -ceq 'false') {",
  "            if ($env:CONTROLLER_ARTIFACT_ID -cnotmatch '^[1-9][0-9]*$' -or $env:CONTROLLER_ARTIFACT_DIGEST -cnotmatch '^sha256:[0-9a-f]{64}$') {",
  "              throw 'BLOCKED CONTROLLER_ARTIFACT_TUPLE_INVALID'",
  '            }',
  '          } else {',
  "            throw 'BLOCKED INITIAL_SEED_TUPLE_INVALID'",
  '          }',
].join('\n');
const EXPECTED_VALIDATION_PREFIX = [
  '      - name: Validate immutable requested tuple',
  '        shell: pwsh',
  '        env:',
  '          REQUESTED_CONTROLLER_SHA: ${{ inputs.trusted_controller_sha }}',
  '          SOURCE_REPOSITORY_REVISION: ${{ inputs.source_repository_revision }}',
  '          RUNNER_REVISION: ${{ inputs.runner_revision }}',
  '          SOURCE_RUN_ID: ${{ inputs.source_run_id }}',
  '          SOURCE_RUN_ATTEMPT: ${{ inputs.source_run_attempt }}',
  '          INITIAL_SEED: ${{ inputs.initial_seed }}',
  '          CONTROLLER_ARTIFACT_ID: ${{ inputs.controller_artifact_id }}',
  '          CONTROLLER_ARTIFACT_DIGEST: ${{ inputs.controller_artifact_digest }}',
  '          TRUSTED_CONTROLLER_SHA: ${{ vars.TRUSTED_CONTROLLER_SHA }}',
  '          WORKFLOW_HEAD_SHA: ${{ github.sha }}',
].join('\n');
const EXPECTED_COLLECTOR_ENVIRONMENT = Object.freeze([
  ['CONTROLLER_REVISION', '${{ inputs.trusted_controller_sha }}'],
  ['SOURCE_REPOSITORY_REVISION', '${{ inputs.source_repository_revision }}'],
  ['SOURCE_RUN_ID', '${{ inputs.source_run_id }}'],
  ['SOURCE_RUN_ATTEMPT', '${{ inputs.source_run_attempt }}'],
  ['RUNNER_REVISION', '${{ inputs.runner_revision }}'],
  ['INITIAL_SEED', '${{ inputs.initial_seed }}'],
  ['CONTROLLER_ARTIFACT_ID', '${{ inputs.controller_artifact_id }}'],
  ['CONTROLLER_ARTIFACT_DIGEST', '${{ inputs.controller_artifact_digest }}'],
  ['SOURCE_ARTIFACT_READER_APP_ID', '${{ vars.SOURCE_ARTIFACT_READER_APP_ID }}'],
  ['SOURCE_ARTIFACT_READER_INSTALLATION_ID', '${{ vars.SOURCE_ARTIFACT_READER_INSTALLATION_ID }}'],
  ['SOURCE_REPOSITORY_ID', '${{ vars.SOURCE_REPOSITORY_ID }}'],
  ['SOURCE_VERIFY_MAIN_WORKFLOW_ID', '${{ vars.SOURCE_VERIFY_MAIN_WORKFLOW_ID }}'],
  ['SOURCE_ARTIFACT_READER_PRIVATE_KEY', '${{ secrets.SOURCE_ARTIFACT_READER_PRIVATE_KEY }}'],
  ['APPWRITE_TEST_OPERATOR_API_KEY', '${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}'],
  ['APPWRITE_TEST_FIXTURE_API_KEY', '${{ secrets.APPWRITE_TEST_FIXTURE_API_KEY }}'],
  ['E2E_EDITOR_EMAIL', '${{ secrets.E2E_EDITOR_EMAIL }}'],
  ['E2E_OWNER_EMAIL', '${{ secrets.E2E_OWNER_EMAIL }}'],
  ['E2E_VIEWER_EMAIL', '${{ secrets.E2E_VIEWER_EMAIL }}'],
  ['COLLECTOR_INPUT', '${{ runner.temp }}\\appwrite-test-readback-input.json'],
  ['COLLECTOR_OUTPUT', '${{ runner.temp }}\\appwrite-test-readback'],
]);
const EXPECTED_COLLECTOR_COMMAND = 'node packages/verification-controller/src/collect-appwrite-test-readback.mjs --input $env:COLLECTOR_INPUT --output $env:COLLECTOR_OUTPUT';
const EXPECTED_COLLECTOR_SECRET_NAMES = Object.freeze([
  'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
  'APPWRITE_TEST_OPERATOR_API_KEY',
  'APPWRITE_TEST_FIXTURE_API_KEY',
  'E2E_EDITOR_EMAIL',
  'E2E_OWNER_EMAIL',
  'E2E_VIEWER_EMAIL',
]);

function assertProtectedAdmission(text) {
  assert.deepEqual(
    [...text.matchAll(/^ {6}- name: (.+)$/gmu)].map((match) => match[1]),
    [
      'Validate immutable requested tuple',
      'Checkout only the requested controller commit',
      'Set up exact Node.js runtime',
      'Verify exact runtime',
      'Collect canonical read-only Appwrite Test bindings',
      'Upload exact binding artifact',
    ],
  );
  const jobGuard = /^    if: (.+)$/mu.exec(text)?.[1];
  assert.equal(
    jobGuard,
    "github.repository == 'Krowaccie/AppWriteWork-verification-control'",
  );
  assert.equal(jobGuard.includes('vars.'), false);
  const validation = text.indexOf('      - name: Validate immutable requested tuple');
  const checkout = text.indexOf('      - name: Checkout only the requested controller commit');
  const runtime = text.indexOf('      - name: Set up exact Node.js runtime');
  assert.notEqual(validation, -1);
  assert.equal(validation < checkout && checkout < runtime, true);
  const validationBlock = text.slice(validation, checkout);
  const checkoutBlock = text.slice(checkout, runtime);
  for (const block of [validationBlock, checkoutBlock]) {
    assert.doesNotMatch(block, /^ {8}(?:if|continue-on-error)\s*:/mu);
  }
  assert.equal(
    /^ {10}ref: (.+)$/mu.exec(checkoutBlock)?.[1],
    '${{ inputs.trusted_controller_sha }}',
  );
  assert.equal(
    /^ {10}persist-credentials: (.+)$/mu.exec(checkoutBlock)?.[1],
    'false',
  );
  assert.match(
    validationBlock,
    /WORKFLOW_HEAD_SHA -cne \$env:TRUSTED_CONTROLLER_SHA/u,
  );
  const runStart = validationBlock.indexOf('        run: |');
  assert.notEqual(runStart, -1);
  assert.equal(
    validationBlock.slice(runStart).replaceAll('\r', '').trimEnd(),
    EXPECTED_VALIDATION_RUN,
  );
  assert.equal(
    validationBlock.replaceAll('\r', '').trimEnd(),
    `${EXPECTED_VALIDATION_PREFIX}\n${EXPECTED_VALIDATION_RUN}`,
  );
}

function assertProtectedWorkflow(text) {
  text = assertWorkflowSeal(text);
  assert.deepEqual(flatMapping(text, 'permissions', 0), [
    ['contents', 'read'],
    ['actions', 'read'],
  ]);
  assert.doesNotMatch(scopedBlock(text, 'collect:', 2), /^ {4}permissions:/mu);
  assertProtectedAdmission(text);

  const collector = stepBlock(text, 'Collect canonical read-only Appwrite Test bindings');
  assert.deepEqual(stepEnvironmentEntries(collector), EXPECTED_COLLECTOR_ENVIRONMENT);
  assert.equal(collector.trimEnd().endsWith(EXPECTED_COLLECTOR_COMMAND), true);
  const secretExpressions = [...text.matchAll(/\$\{\{ secrets\.([A-Z0-9_]+) \}\}/gu)]
    .map((match) => ({ index: match.index, value: match[1] }));
  assert.deepEqual(secretExpressions.map(({ value }) => value), EXPECTED_COLLECTOR_SECRET_NAMES);
  assert.equal(secretExpressions.every(({ index }) => isInside(text, collector, index)), true);
  assert.doesNotMatch(text, /\$\{\{ github\.token \}\}/u);
  for (const run of runScalars(text)) {
    assert.doesNotMatch(run, /\$\{\{\s*(?:github\.token|secrets\.)/u);
  }
}

test('protected readback workflow is manual, fixed-target, pinned, and secret-minimal', async () => {
  for (const workflow of workflows) {
    const text = await readFile(workflow, 'utf8');
    assert.match(text, /^on:\r?\n  workflow_dispatch:/mu);
    assert.doesNotMatch(text, /^  (?:push|pull_request|pull_request_target|schedule):/mu);
    assert.match(text, /runs-on: windows-2025/u);
    assert.match(text, /environment: appwrite-test/u);
    assertProtectedWorkflow(text);
    assert.match(text, /node-version: '24\.11\.1'/u);
    assert.match(text, /retention-days: 7/u);
    assert.match(text, /actions\/checkout@[0-9a-f]{40}/u);
    assert.match(text, /actions\/setup-node@[0-9a-f]{40}/u);
    assert.match(text, /actions\/upload-artifact@[0-9a-f]{40}/u);
    assert.doesNotMatch(text, /APPWRITE_TEST_RECOVERY_API_KEY/u);
    assert.doesNotMatch(text, /69eb4818000afa64a7fa|69eb4a020024c520642e|branch production/iu);
    const mappedSecrets = [...text.matchAll(/secrets\.([A-Z0-9_]+)/gu)].map((match) => match[1]);
    assert.deepEqual([...new Set(mappedSecrets)].sort(), [
      'APPWRITE_TEST_FIXTURE_API_KEY',
      'APPWRITE_TEST_OPERATOR_API_KEY',
      'E2E_EDITOR_EMAIL',
      'E2E_OWNER_EMAIL',
      'E2E_VIEWER_EMAIL',
      'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
    ]);
  }
});

test('protected readback admission rejects pre-environment SHA and ordering mutations', async () => {
  const text = await readFile(
    'packages/verification-controller/workflows/collect-appwrite-test-readback.yml',
    'utf8',
  );
  const validationStart = text.indexOf('      - name: Validate immutable requested tuple');
  const checkoutStart = text.indexOf('      - name: Checkout only the requested controller commit');
  const runtimeStart = text.indexOf('      - name: Set up exact Node.js runtime');
  const validation = text.slice(validationStart, checkoutStart);
  const checkout = text.slice(checkoutStart, runtimeStart);
  const mutations = [
    text.replace(
      "if: github.repository == 'Krowaccie/AppWriteWork-verification-control'",
      "if: github.repository == 'Krowaccie/AppWriteWork-verification-control' && github.sha == vars.TRUSTED_CONTROLLER_SHA",
    ),
    text.replace(validation, '__VALIDATION__').replace(checkout, validation)
      .replace('__VALIDATION__', checkout),
    text.replace(
      validation,
      validation.replace('        shell: pwsh', '        if: false\n        shell: pwsh'),
    ),
    text.replace(
      validation,
      validation.replace(
        '        shell: pwsh',
        '        continue-on-error: true\n        shell: pwsh',
      ),
    ),
    text.replace(
      checkout,
      checkout.replace('          ref: ${{ inputs.trusted_controller_sha }}', '          ref: main'),
    ),
    text.replace(
      checkout,
      checkout.replace('          persist-credentials: false', '          persist-credentials: true'),
    ),
    text.replace(
      checkout,
      checkout.replace(
        '        uses: actions/checkout@',
        '        if: false\n        uses: actions/checkout@',
      ),
    ),
    text.replace(
      checkout,
      checkout.replace(
        '        uses: actions/checkout@',
        '        continue-on-error: true\n        uses: actions/checkout@',
      ),
    ),
    text.replace(
      '$env:REQUESTED_CONTROLLER_SHA -cne $env:TRUSTED_CONTROLLER_SHA -or ',
      '',
    ),
    text.replace(
      '          REQUESTED_CONTROLLER_SHA: ${{ inputs.trusted_controller_sha }}',
      '          REQUESTED_CONTROLLER_SHA: ${{ vars.TRUSTED_CONTROLLER_SHA }}',
    ),
    text.replace(
      "          $ErrorActionPreference = 'Stop'",
      "          $ErrorActionPreference = 'Stop'\n          return",
    ),
    text.replace(
      '      - name: Set up exact Node.js runtime',
      '      - name: Persist operator credential\n        run: echo "APPWRITE_TEST_OPERATOR_API_KEY=${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}" >> "$GITHUB_ENV"\n\n      - name: Set up exact Node.js runtime',
    ),
    text.replace(
      '$env:WORKFLOW_HEAD_SHA -cne $env:TRUSTED_CONTROLLER_SHA',
      '$env:WORKFLOW_HEAD_SHA -ceq $env:TRUSTED_CONTROLLER_SHA',
    ),
  ];
  for (const mutation of mutations) {
    assert.throws(() => assertProtectedAdmission(mutation));
  }
});

test('protected readback workflow contract rejects permission and secret-command mutations', async (t) => {
  const text = await readFile(
    'packages/verification-controller/workflows/collect-appwrite-test-readback.yml',
    'utf8',
  );
  const cases = [
    [
      'workflow-wide write permission',
      text.replace(
        /permissions:\r?\n  contents: read\r?\n  actions: read/u,
        'permissions: write-all',
      ),
    ],
    [
      'operator secret referenced by collector command',
      text.replace(
        'node packages/verification-controller/src/collect-appwrite-test-readback.mjs --input $env:COLLECTOR_INPUT --output $env:COLLECTOR_OUTPUT',
        'node packages/verification-controller/src/collect-appwrite-test-readback.mjs --input $env:COLLECTOR_INPUT --output $env:COLLECTOR_OUTPUT --operator-api-key $env:APPWRITE_TEST_OPERATOR_API_KEY',
      ),
    ],
  ];
  for (const [name, mutation] of cases) {
    await t.test(name, () => {
      assert.notEqual(mutation, text, 'mutation fixture must change the workflow');
      assert.throws(() => assertProtectedWorkflow(mutation));
    });
  }
});
