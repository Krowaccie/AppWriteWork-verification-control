import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const packagePaths = [
  'packages/verification-controller/workflows/publish-controller-bundle.yml',
  'packages/verification-controller/workflows/verify-test-cloud.yml',
];
const rootPaths = [
  '.github/workflows/publish-controller-bundle.yml',
  '.github/workflows/verify-test-cloud.yml',
];
const HOSTED_WORKFLOW_SEAL = Object.freeze({
  bytes: 7611,
  digest: '116490c6a255b765b754cd701d4655f15e64d1c16796bf5c7e773cc09ce9ec5c',
});

function canonicalWorkflow(workflow) {
  assert.equal(workflow.startsWith('\uFEFF'), false, 'workflow YAML must not have a BOM');
  assert.equal(workflow.includes('\t'), false, 'workflow YAML must not contain tabs');
  const canonical = workflow.replaceAll('\r\n', '\n');
  assert.equal(canonical.includes('\r'), false, 'workflow YAML has a stray carriage return');
  return canonical;
}

function assertWorkflowSeal(workflow, seal) {
  const canonical = canonicalWorkflow(workflow);
  assert.equal(Buffer.byteLength(canonical, 'utf8'), seal.bytes, 'workflow byte count changed');
  assert.equal(
    createHash('sha256').update(canonical, 'utf8').digest('hex'),
    seal.digest,
    'workflow digest changed',
  );
  return canonical;
}

function flatMapping(workflow, name, indent) {
  const lines = workflow.split('\n');
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

function scopedBlock(workflow, marker, indent) {
  const lines = workflow.split('\n');
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

function runScalars(workflow) {
  const lines = workflow.split('\n');
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

function expressionOffsets(workflow, pattern) {
  return [...workflow.matchAll(pattern)].map((match) => ({
    index: match.index,
    value: match[1],
  }));
}

function isInside(workflow, block, index) {
  const start = workflow.indexOf(block);
  return start !== -1 && index >= start && index < start + block.length;
}

function stepBlock(workflow, name) {
  const marker = `      - name: ${name}`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `missing step ${name}`);
  const next = workflow.indexOf('\n      - name: ', start + marker.length);
  return workflow.slice(start, next === -1 ? workflow.length : next);
}

function stepEnvironmentNames(block) {
  return [...block.matchAll(/^          ([A-Z][A-Z0-9_]+):/gmu)]
    .map((match) => match[1]);
}

function isolatedEnvironmentNames(block) {
  const lines = block.replaceAll('\r', '').split('\n');
  const start = lines.findIndex((line) => line === '          env -i \\');
  const end = lines.findIndex((line, index) => (
    index > start
    && line === '            node packages/verification-controller/src/prepare-controller-artifact.mjs \\'
  ));
  assert.notEqual(start, -1, 'missing isolated environment start');
  assert.equal(end > start + 1, true, 'missing isolated environment assignments');
  return lines.slice(start + 1, end).map((line) => {
    const match = /^ {12}([A-Z][A-Z0-9_]*)="\$([A-Z][A-Z0-9_]*)" \\$/u.exec(line);
    assert.notEqual(match, null, `unsafe isolated environment assignment: ${line}`);
    assert.equal(match[1], match[2], `remapped isolated environment assignment: ${line}`);
    return match[1];
  });
}

const PREPARATION_ENVIRONMENT = Object.freeze([
  'CONTROLLER_ARTIFACT_DIRECTORY',
  'CONTROLLER_ARTIFACT_READ_TOKEN',
  'GITHUB_REPOSITORY',
  'REQUIRED_CONTROLLER_ENTRYPOINT',
  'TRUSTED_CONTROLLER_ARTIFACT_ID',
  'TRUSTED_CONTROLLER_BUNDLE_DIGEST',
  'TRUSTED_CONTROLLER_SHA',
]);
const EXPECTED_PREPARATION_RUN = [
  '        run: |',
  '          set -euo pipefail',
  '          env -i \\',
  '            PATH="$PATH" \\',
  '            GITHUB_ENV="$GITHUB_ENV" \\',
  '            CONTROLLER_ARTIFACT_READ_TOKEN="$CONTROLLER_ARTIFACT_READ_TOKEN" \\',
  '            CONTROLLER_ARTIFACT_DIRECTORY="$CONTROLLER_ARTIFACT_DIRECTORY" \\',
  '            GITHUB_REPOSITORY="$GITHUB_REPOSITORY" \\',
  '            REQUIRED_CONTROLLER_ENTRYPOINT="$REQUIRED_CONTROLLER_ENTRYPOINT" \\',
  '            TRUSTED_CONTROLLER_ARTIFACT_ID="$TRUSTED_CONTROLLER_ARTIFACT_ID" \\',
  '            TRUSTED_CONTROLLER_BUNDLE_DIGEST="$TRUSTED_CONTROLLER_BUNDLE_DIGEST" \\',
  '            TRUSTED_CONTROLLER_SHA="$TRUSTED_CONTROLLER_SHA" \\',
  '            node packages/verification-controller/src/prepare-controller-artifact.mjs \\',
  '              --output "$CONTROLLER_ARTIFACT_DIRECTORY"',
].join('\n');
const EXPECTED_HOSTED_VALIDATION = [
  '      - name: Validate immutable controller revision',
  '        shell: bash',
  '        env:',
  '          GITHUB_SHA: ${{ github.sha }}',
  '          TRUSTED_CONTROLLER_SHA: ${{ vars.TRUSTED_CONTROLLER_SHA }}',
  '        run: |',
  '          set -euo pipefail',
  '          test "$GITHUB_SHA" != ""',
  '          test "$TRUSTED_CONTROLLER_SHA" != ""',
  '          [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]',
  '          [[ "$TRUSTED_CONTROLLER_SHA" =~ ^[0-9a-f]{40}$ ]]',
  '          test "$GITHUB_SHA" = "$TRUSTED_CONTROLLER_SHA"',
].join('\n');
const EXPECTED_INSTALL_STEP = [
  '      - name: Install the exact trusted controller dependencies',
  '        shell: bash',
  '        run: npm ci --ignore-scripts --no-audit --no-fund',
].join('\n');
const EXPECTED_PLAYWRIGHT_STEP = [
  '      - name: Install pinned Playwright Chromium',
  '        shell: bash',
  '        run: npm exec --package=playwright@1.61.1 -- playwright install chromium',
].join('\n');
const EXPECTED_FINAL_ENVIRONMENT = Object.freeze([
  ['GITHUB_REPOSITORY', '${{ github.repository }}'],
  ['GITHUB_SHA', '${{ github.sha }}'],
  ['GITHUB_RUN_ID', '${{ github.run_id }}'],
  ['GITHUB_RUN_ATTEMPT', '${{ github.run_attempt }}'],
  ['REQUESTED_REVISION', '${{ inputs.revision }}'],
  ['SOURCE_RUN_ID', '${{ inputs.source_run_id }}'],
  ['SOURCE_RUN_ATTEMPT', '${{ inputs.source_run_attempt }}'],
  ['TRUSTED_CONTROLLER_SHA', '${{ vars.TRUSTED_CONTROLLER_SHA }}'],
  ['TRUSTED_CONTROLLER_ARTIFACT_ID', '${{ vars.TRUSTED_CONTROLLER_ARTIFACT_ID }}'],
  ['TRUSTED_CONTROLLER_BUNDLE_DIGEST', '${{ vars.TRUSTED_CONTROLLER_BUNDLE_DIGEST }}'],
  ['CONTROLLER_ARTIFACT_DIRECTORY', '${{ runner.temp }}\\trusted-controller-artifact'],
  ['SOURCE_ARTIFACT_READER_APP_ID', '${{ vars.SOURCE_ARTIFACT_READER_APP_ID }}'],
  ['SOURCE_ARTIFACT_READER_INSTALLATION_ID', '${{ vars.SOURCE_ARTIFACT_READER_INSTALLATION_ID }}'],
  ['SOURCE_REPOSITORY_ID', '${{ vars.SOURCE_REPOSITORY_ID }}'],
  ['SOURCE_VERIFY_MAIN_WORKFLOW_ID', '${{ vars.SOURCE_VERIFY_MAIN_WORKFLOW_ID }}'],
  ['BINDING_DIRECTORY', '${{ runner.temp }}\\test-cloud-bindings'],
  ['SOURCE_ARTIFACT_READER_PRIVATE_KEY', '${{ secrets.SOURCE_ARTIFACT_READER_PRIVATE_KEY }}'],
  ['APPWRITE_TEST_OPERATOR_API_KEY', '${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}'],
  ['APPWRITE_TEST_FIXTURE_API_KEY', '${{ secrets.APPWRITE_TEST_FIXTURE_API_KEY }}'],
  ['E2E_OWNER_EMAIL', '${{ secrets.E2E_OWNER_EMAIL }}'],
  ['E2E_OWNER_PASSWORD', '${{ secrets.E2E_OWNER_PASSWORD }}'],
  ['E2E_EDITOR_EMAIL', '${{ secrets.E2E_EDITOR_EMAIL }}'],
  ['E2E_EDITOR_PASSWORD', '${{ secrets.E2E_EDITOR_PASSWORD }}'],
  ['E2E_VIEWER_EMAIL', '${{ secrets.E2E_VIEWER_EMAIL }}'],
  ['E2E_VIEWER_PASSWORD', '${{ secrets.E2E_VIEWER_PASSWORD }}'],
]);
const EXPECTED_FINAL_SECRET_NAMES = Object.freeze([
  'SOURCE_ARTIFACT_READER_PRIVATE_KEY',
  'APPWRITE_TEST_OPERATOR_API_KEY',
  'APPWRITE_TEST_FIXTURE_API_KEY',
  'E2E_OWNER_EMAIL',
  'E2E_OWNER_PASSWORD',
  'E2E_EDITOR_EMAIL',
  'E2E_EDITOR_PASSWORD',
  'E2E_VIEWER_EMAIL',
  'E2E_VIEWER_PASSWORD',
]);

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

function assertHostedArtifactStaging(workflow) {
  workflow = assertWorkflowSeal(workflow, HOSTED_WORKFLOW_SEAL);
  assert.deepEqual(flatMapping(workflow, 'permissions', 0), [
    ['contents', 'read'],
    ['actions', 'read'],
  ]);
  assert.doesNotMatch(
    scopedBlock(workflow, 'verify-test-cloud:', 2),
    /^ {4}permissions:/mu,
  );
  assert.deepEqual(
    [...workflow.matchAll(/^ {6}- name: (.+)$/gmu)].map((match) => match[1]),
    [
      'Validate immutable controller revision',
      'Checkout only the trusted controller',
      'Set up exact Node.js runtime',
      'Verify exact Node.js and npm versions',
      'Prepare the verified controller artifact',
      'Install the exact trusted controller dependencies',
      'Verify exact Appwrite Test binding artifact',
      'Install pinned Playwright Chromium',
      'Run the one-process staged controller',
    ],
  );
  const jobGuard = /^    if: (.+)$/mu.exec(workflow)?.[1];
  assert.equal(
    jobGuard,
    "github.repository == 'Krowaccie/AppWriteWork-verification-control'",
  );
  assert.equal(jobGuard.includes('vars.'), false);

  const validation = stepBlock(workflow, 'Validate immutable controller revision');
  const checkout = stepBlock(workflow, 'Checkout only the trusted controller');
  const preparation = stepBlock(workflow, 'Prepare the verified controller artifact');
  const install = stepBlock(workflow, 'Install the exact trusted controller dependencies');
  const binding = stepBlock(workflow, 'Verify exact Appwrite Test binding artifact');
  const playwright = stepBlock(workflow, 'Install pinned Playwright Chromium');
  const final = stepBlock(workflow, 'Run the one-process staged controller');
  assert.equal(workflow.indexOf(validation) < workflow.indexOf(checkout), true);
  assert.equal(workflow.indexOf(checkout) < workflow.indexOf(preparation), true);
  assert.equal(workflow.indexOf(preparation) < workflow.indexOf(install), true);
  for (const block of [validation, checkout, preparation, install, final]) {
    assert.doesNotMatch(block, /^ {8}(?:if|continue-on-error)\s*:/mu);
  }
  assert.equal(
    validation.replaceAll('\r', '').trimEnd(),
    EXPECTED_HOSTED_VALIDATION,
  );
  assert.match(validation, /GITHUB_SHA.*TRUSTED_CONTROLLER_SHA/su);
  assert.match(validation, /test "\$GITHUB_SHA" = "\$TRUSTED_CONTROLLER_SHA"/u);
  assert.equal(
    /^ {10}ref: (.+)$/mu.exec(checkout)?.[1],
    '${{ vars.TRUSTED_CONTROLLER_SHA }}',
  );
  assert.equal(/^ {10}persist-credentials: (.+)$/mu.exec(checkout)?.[1], 'false');

  assert.match(preparation, /env -i/u);
  assert.match(preparation, /prepare-controller-artifact\.mjs/u);
  assert.match(preparation, /--output "\$CONTROLLER_ARTIFACT_DIRECTORY"/u);
  assert.match(preparation, /\$\{\{ runner\.temp \}\}/u);
  assert.deepEqual(stepEnvironmentNames(preparation).sort(), PREPARATION_ENVIRONMENT);
  assert.deepEqual(isolatedEnvironmentNames(preparation).sort(), [
    ...PREPARATION_ENVIRONMENT,
    'GITHUB_ENV',
    'PATH',
  ].sort());
  for (const name of PREPARATION_ENVIRONMENT) {
    assert.match(preparation, new RegExp(`${name}="\\$${name}"`, 'u'));
  }
  const preparationRunStart = preparation.indexOf('        run: |');
  assert.notEqual(preparationRunStart, -1);
  assert.equal(
    preparation.slice(preparationRunStart).replaceAll('\r', '').trimEnd(),
    EXPECTED_PREPARATION_RUN,
  );
  assert.equal(install.trimEnd(), EXPECTED_INSTALL_STEP);
  assert.equal(playwright.trimEnd(), EXPECTED_PLAYWRIGHT_STEP);
  assert.doesNotMatch(workflow, /actions\/download-artifact/u);
  assert.doesNotMatch(workflow, /^(?:env| {4}env)\s*:/mu);
  assert.doesNotMatch(workflow, /^\s*-\s*$/mu);
  assert.doesNotMatch(workflow, /^ {6}- (?!name: )/mu);

  assert.match(final, /^          CONTROLLER_ARTIFACT_DIRECTORY:/mu);
  assert.doesNotMatch(final, /CONTROLLER_ARTIFACT_READ_TOKEN|GITHUB_TOKEN/u);
  assert.doesNotMatch(final, /CONTROLLER_ARTIFACT_DIRECTORY[^\n]*node/u);
  assert.doesNotMatch(final, /node[^\n]*CONTROLLER_ARTIFACT_DIRECTORY/u);
  assert.equal(
    /^ {8}run: (.+)$/mu.exec(final)?.[1],
    'node packages/verification-controller/src/test-cloud-controller.mjs --hosted --revision "$REQUESTED_REVISION" --source-run-id "$SOURCE_RUN_ID" --source-run-attempt "$SOURCE_RUN_ATTEMPT" --binding-directory "$BINDING_DIRECTORY"',
  );
  assert.deepEqual(stepEnvironmentEntries(final), EXPECTED_FINAL_ENVIRONMENT);
  for (const run of runScalars(workflow)) {
    assert.doesNotMatch(run, /\$\{\{\s*(?:github\.token|secrets\.)/u);
  }
  const secretExpressions = expressionOffsets(
    workflow,
    /\$\{\{ secrets\.([A-Z0-9_]+) \}\}/gu,
  );
  assert.deepEqual(secretExpressions.map(({ value }) => value), EXPECTED_FINAL_SECRET_NAMES);
  assert.equal(secretExpressions.every(({ index }) => isInside(workflow, final, index)), true);
  const tokenExpressions = expressionOffsets(workflow, /(\$\{\{ github\.token \}\})/gu);
  assert.equal(tokenExpressions.length, 2);
  assert.equal(
    tokenExpressions.every(({ index }) => (
      isInside(workflow, preparation, index) || isInside(workflow, binding, index)
    )),
    true,
  );
  assert.equal(
    (workflow.match(/CONTROLLER_ARTIFACT_READ_TOKEN: \$\{\{ github\.token \}\}/gu) ?? []).length,
    1,
  );
}

test('publisher and hosted workflow consume a verified artifact directory, not oversized variables', async () => {
  for (let index = 0; index < packagePaths.length; index += 1) {
    const packagePath = packagePaths[index];
    const packaged = await readFile(packagePath, 'utf8');
    let root = packaged;
    try {
      root = await readFile(rootPaths[index], 'utf8');
      assert.equal(root, packaged);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    assert.match(packaged, /TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_ID/u);
    assert.match(packaged, /TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_DIGEST/u);
    assert.match(packaged, /test-cloud-binding-artifact-verifier\.mjs/u);
    assert.match(packaged, /BINDING_DIRECTORY/u);
    assert.doesNotMatch(packaged, /vars\.TEST_CLOUD_(?:HOSTED_)?SETUP_(?:READBACK|ATTESTATION)_(?:JSON|DIGEST)/u);
    assert.doesNotMatch(packaged, /APPWRITE_TEST_RECOVERY_API_KEY/u);
  }
});

test('hosted workflow passes the exact verified directory to the controller CLI', async () => {
  const workflow = await readFile(
    'packages/verification-controller/workflows/verify-test-cloud.yml', 'utf8',
  );
  assert.match(workflow, /--binding-directory "\$BINDING_DIRECTORY"/u);
});

test('hosted workflow stages one verified controller artifact after environment admission', async () => {
  const workflow = await readFile(
    'packages/verification-controller/workflows/verify-test-cloud.yml', 'utf8',
  );
  assertHostedArtifactStaging(workflow);
});

test('hosted artifact staging rejects admission, ordering, environment, and execution mutations', async () => {
  const workflow = await readFile(
    'packages/verification-controller/workflows/verify-test-cloud.yml', 'utf8',
  );
  const validation = stepBlock(workflow, 'Validate immutable controller revision');
  const checkout = stepBlock(workflow, 'Checkout only the trusted controller');
  const preparation = stepBlock(workflow, 'Prepare the verified controller artifact');
  const install = stepBlock(workflow, 'Install the exact trusted controller dependencies');
  const mutations = [
    workflow.replace(
      "if: github.repository == 'Krowaccie/AppWriteWork-verification-control'",
      "if: github.repository == 'Krowaccie/AppWriteWork-verification-control' && github.sha == vars.TRUSTED_CONTROLLER_SHA",
    ),
    workflow.replace(
      'test "$GITHUB_SHA" = "$TRUSTED_CONTROLLER_SHA"',
      'test "$GITHUB_SHA" != "$TRUSTED_CONTROLLER_SHA"',
    ),
    workflow.replace(
      '          GITHUB_SHA: ${{ github.sha }}',
      '          GITHUB_SHA: ${{ vars.TRUSTED_CONTROLLER_SHA }}',
    ),
    workflow.replace(
      '          set -euo pipefail',
      '          set -euo pipefail\n          exit 0',
    ),
    workflow.replace(validation, '__VALIDATION__').replace(checkout, validation)
      .replace('__VALIDATION__', checkout),
    workflow.replace('env -i', 'env'),
    workflow.replace(/^          REQUIRED_CONTROLLER_ENTRYPOINT:.*\r?\n/mu, ''),
    workflow.replace(/\$\{\{ runner\.temp \}\}\\trusted-controller-artifact/gu, 'C:\\unsafe'),
    workflow.replace(
      /(- name: Run the one-process staged controller\r?\n\s+shell: bash\r?\n\s+env:\r?\n)/u,
      '$1          CONTROLLER_ARTIFACT_READ_TOKEN: ${{ github.token }}\n',
    ),
    workflow.replace(
      'run: node packages/verification-controller/src/test-cloud-controller.mjs',
      'run: node "$CONTROLLER_ARTIFACT_DIRECTORY/test-cloud-controller.mjs"',
    ),
    workflow.replace(preparation, '__PREPARATION__').replace(install, preparation)
      .replace('__PREPARATION__', install),
    workflow.replace('    steps:', '    env:\n      GITHUB_TOKEN: ${{ github.token }}\n    steps:'),
    workflow.replace('    steps:', '    env :\n      EXTRA: value\n    steps:'),
    workflow.replace('    steps:', '    steps:\n      -'),
    workflow.replace('    steps:', '    steps:\n      - uses: actions/download-artifact@deadbeef'),
    workflow.replace(
      preparation,
      preparation.replace('        shell: bash', '        if: false\n        shell: bash'),
    ),
    workflow.replace(
      preparation,
      preparation.replace('        shell: bash', '        continue-on-error: true\n        shell: bash'),
    ),
    workflow.replace(
      '          ref: ${{ vars.TRUSTED_CONTROLLER_SHA }}',
      '          ref: main',
    ),
    workflow.replace(
      '            GITHUB_ENV="$GITHUB_ENV" \\',
      '            GITHUB_ENV="$GITHUB_ENV" \\\n            GITHUB_TOKEN="$CONTROLLER_ARTIFACT_READ_TOKEN" \\',
    ),
    workflow.replace(
      ' --binding-directory "$BINDING_DIRECTORY"',
      ' --binding-directory "$BINDING_DIRECTORY" || true',
    ),
    workflow.replace(
      '              --output "$CONTROLLER_ARTIFACT_DIRECTORY"',
      '              --output "$CONTROLLER_ARTIFACT_DIRECTORY"\n          echo "GITHUB_TOKEN=$CONTROLLER_ARTIFACT_READ_TOKEN" >> "$GITHUB_ENV"',
    ),
    workflow.replace(
      '      - name: Install the exact trusted controller dependencies',
      '      - run: echo "GITHUB_TOKEN=$CONTROLLER_ARTIFACT_READ_TOKEN" >> "$GITHUB_ENV"\n\n      - name: Install the exact trusted controller dependencies',
    ),
    workflow.replace(
      '      - name: Install the exact trusted controller dependencies',
      '      - name: Persist controller token\n        run: echo "GITHUB_TOKEN=${{ github.token }}" >> "$GITHUB_ENV"\n\n      - name: Install the exact trusted controller dependencies',
    ),
  ];
  for (const mutation of mutations) {
    assert.throws(() => assertHostedArtifactStaging(mutation));
  }
});

test('hosted workflow contract rejects permission, secret, install, and staged execution mutations', async (t) => {
  const workflow = await readFile(
    'packages/verification-controller/workflows/verify-test-cloud.yml', 'utf8',
  );
  const cases = [
    [
      'workflow-wide write permission',
      workflow.replace(
        /permissions:\r?\n  contents: read\r?\n  actions: read/u,
        'permissions: write-all',
      ),
    ],
    [
      'unplanned final-step secret',
      workflow.replace(
        '          SOURCE_ARTIFACT_READER_PRIVATE_KEY: ${{ secrets.SOURCE_ARTIFACT_READER_PRIVATE_KEY }}',
        '          SOURCE_ARTIFACT_READER_PRIVATE_KEY: ${{ secrets.SOURCE_ARTIFACT_READER_PRIVATE_KEY }}\n          UNPLANNED_FINAL_SECRET: ${{ secrets.UNPLANNED_FINAL_SECRET }}',
      ),
    ],
    [
      'token expression in npm install command',
      workflow.replace(
        '        run: npm ci --ignore-scripts --no-audit --no-fund',
        '        run: npm ci --ignore-scripts --no-audit --no-fund && echo "${{ github.token }}"',
      ),
    ],
    [
      'Playwright step executes the staged controller',
      workflow.replace(
        '        run: npm exec --package=playwright@1.61.1 -- playwright install chromium',
        '        env:\n          CONTROLLER_ARTIFACT_DIRECTORY: ${{ runner.temp }}\\trusted-controller-artifact\n        run: |\n          npm exec --package=playwright@1.61.1 -- playwright install chromium\n          node "$CONTROLLER_ARTIFACT_DIRECTORY/test-cloud-controller.mjs"',
      ),
    ],
  ];
  for (const [name, mutation] of cases) {
    await t.test(name, () => {
      assert.notEqual(mutation, workflow, 'mutation fixture must change the workflow');
      assert.throws(() => assertHostedArtifactStaging(mutation));
    });
  }
});
