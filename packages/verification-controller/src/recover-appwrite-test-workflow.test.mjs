import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowPath = 'packages/verification-controller/workflows/recover-appwrite-test.yml';
const REVIEWED_WORKFLOW_BYTES = 8164;
const REVIEWED_WORKFLOW_SHA256 = '40147edb5d53ba43f815090f07bfb47840695911b13b91aa9ed31a37cfd34178';

function indentedBlock(lines, exactHeader, indent) {
  const header = `${' '.repeat(indent)}${exactHeader}:`;
  const indexes = lines.flatMap((line, index) => line === header ? [index] : []);
  assert.deepEqual(indexes.length, 1, `expected exactly one ${exactHeader} block`);
  let end = lines.length;
  for (let index = indexes[0] + 1; index < lines.length; index += 1) {
    if (lines[index].trim().length === 0) continue;
    const leading = lines[index].length - lines[index].trimStart().length;
    if (leading <= indent) {
      end = index;
      break;
    }
  }
  return lines.slice(indexes[0] + 1, end);
}

function immediateMappings(lines, indent) {
  const prefix = ' '.repeat(indent);
  return lines.flatMap((line) => {
    if (!line.startsWith(prefix) || line.startsWith(`${prefix} `)) return [];
    const match = /^([^:#]+):(?:\s+(.*))?$/u.exec(line.slice(indent));
    return match === null ? [] : [[match[1], match[2] ?? null]];
  });
}

function environmentMappings(lines, indent) {
  const prefix = ' '.repeat(indent);
  return lines.flatMap((line, index) => {
    if (!line.startsWith(prefix) || line.startsWith(`${prefix} `)) return [];
    const match = /^(?:env|"env"|'env')\s*:(?:\s+(.*))?$/u.exec(line.slice(indent));
    return match === null ? [] : [{ index, value: match[1] ?? null }];
  });
}

function workflowSteps(jobLines) {
  const stepsIndex = jobLines.findIndex((line) => line === '    steps:');
  assert.notEqual(stepsIndex, -1, 'recovery job must have steps');
  const lines = jobLines.slice(stepsIndex + 1);
  const starts = lines.flatMap((line, index) => (
    /^      -(?:\s|$)/u.test(line) ? [index] : []
  ));
  assert.ok(starts.length > 0, 'recovery job must have steps');
  return starts.map((start, ordinal) => {
    const end = starts[ordinal + 1] ?? lines.length;
    assert.match(lines[start], /^      - name: [^\s].*$/u, 'every recovery step must be named');
    return Object.freeze({
      name: lines[start].slice('      - name: '.length),
      lines: lines.slice(start, end),
    });
  });
}

function stepEnvironment(step) {
  const mappings = environmentMappings(step.lines, 8);
  assert.ok(mappings.length <= 1, `${step.name} has duplicate env blocks`);
  if (mappings.length === 0) return [];
  assert.equal(mappings[0].value, null, `${step.name} env must be a block mapping`);
  const envLines = [];
  for (let index = mappings[0].index + 1; index < step.lines.length; index += 1) {
    const line = step.lines[index];
    if (line.trim().length === 0) continue;
    const leading = line.length - line.trimStart().length;
    if (leading <= 8) break;
    if (leading === 10) envLines.push(line);
  }
  return immediateMappings(envLines, 10);
}

function exactGuardClauses(step, blockedCode) {
  const terminal = `) throw new Error('${blockedCode}');`;
  const terminalIndexes = step.lines.flatMap((line, index) => (
    line.trim() === terminal ? [index] : []
  ));
  assert.equal(terminalIndexes.length, 1, `expected one ${blockedCode} guard`);
  let start = terminalIndexes[0] - 1;
  while (start >= 0 && step.lines[start].trim() !== 'if (') start -= 1;
  assert.ok(start >= 0, `missing ${blockedCode} if guard`);
  return step.lines.slice(start + 1, terminalIndexes[0]).map((line) => line.trim());
}

function assertRecoveryWorkflowContract(workflow) {
  assert.equal(workflow.startsWith('\uFEFF'), false, 'workflow must not contain a BOM');
  assert.doesNotMatch(workflow, /\t/u, 'workflow must not contain tabs');
  const lines = workflow.replaceAll('\r\n', '\n').split('\n');
  assert.deepEqual(environmentMappings(lines, 0), [], 'workflow-level env is forbidden');
  const triggerLines = indentedBlock(lines, 'on', 0);
  assert.deepEqual(immediateMappings(triggerLines, 2), [['workflow_dispatch', null]]);
  const dispatchLines = indentedBlock(lines, 'workflow_dispatch', 2);
  assert.deepEqual(immediateMappings(dispatchLines, 4), [['inputs', null]]);
  const inputLines = indentedBlock(lines, 'inputs', 4);
  assert.deepEqual(
    immediateMappings(inputLines, 6).map(([name]) => name),
    [
      'revision',
      'source_run_id',
      'source_run_attempt',
      'original_workflow_run_id',
      'original_controller_sha',
    ],
  );

  const concurrencyLines = indentedBlock(lines, 'concurrency', 0);
  assert.deepEqual(immediateMappings(concurrencyLines, 2), [
    ['group', 'appwrite-test-verification'],
    ['cancel-in-progress', 'false'],
  ]);

  const jobsLines = indentedBlock(lines, 'jobs', 0);
  assert.deepEqual(immediateMappings(jobsLines, 2), [['recover', null]]);
  const recoverLines = indentedBlock(lines, 'recover', 2);
  assert.deepEqual(environmentMappings(recoverLines, 4), [], 'job-level env is forbidden');
  assert.ok(recoverLines.includes('    environment: appwrite-test'));
  assert.deepEqual(
    immediateMappings(recoverLines, 4).filter(([name]) => name === 'if'),
    [['if', "github.repository == 'Krowaccie/AppWriteWork-verification-control'"]],
  );
  const steps = workflowSteps(recoverLines);
  assert.equal(new Set(steps.map(({ name }) => name)).size, steps.length, 'step names must be unique');
  const finalStep = steps.at(-1);
  assert.equal(finalStep.name, 'Recover only the expired Appwrite Test lease');
  assert.deepEqual(stepEnvironment(finalStep), [
    ['GITHUB_REPOSITORY', '${{ github.repository }}'],
    ['GITHUB_SHA', '${{ github.sha }}'],
    ['TRUSTED_CONTROLLER_SHA', '${{ vars.TRUSTED_CONTROLLER_SHA }}'],
    ['BINDING_DIRECTORY', '${{ runner.temp }}\\test-cloud-bindings'],
    ['APPWRITE_TEST_RECOVERY_API_KEY', '${{ secrets.APPWRITE_TEST_RECOVERY_API_KEY }}'],
  ]);
  const recoveryKeyBindings = steps.flatMap((step) => stepEnvironment(step)
    .filter(([name]) => name === 'APPWRITE_TEST_RECOVERY_API_KEY')
    .map(([, value]) => [step.name, value]));
  assert.deepEqual(recoveryKeyBindings, [[
    finalStep.name,
    '${{ secrets.APPWRITE_TEST_RECOVERY_API_KEY }}',
  ]]);
  assert.deepEqual(
    lines.filter((line) => line.includes('APPWRITE_TEST_RECOVERY_API_KEY')),
    ['          APPWRITE_TEST_RECOVERY_API_KEY: ${{ secrets.APPWRITE_TEST_RECOVERY_API_KEY }}'],
  );
  assert.doesNotMatch(finalStep.lines.join('\n'), /GITHUB_TOKEN|github\.token|CONTROLLER_ARTIFACT_READ_TOKEN/u);

  const approvalStep = steps.find(({ name }) => (
    name === 'Validate the failed owner and protected signed controller'
  ));
  assert.ok(approvalStep, 'failed-owner validation step is required');
  const approvalScript = approvalStep.lines.join('\n');
  assert.deepEqual(exactGuardClauses(approvalStep, 'BLOCKED RECOVERY_APPROVAL_INVALID'), [
    'run.id !== Number(process.env.ORIGINAL_WORKFLOW_RUN_ID)',
    "|| run.name !== 'Verify Test Cloud'",
    '|| run.workflow_id !== 336735803',
    "|| run.event !== 'workflow_dispatch'",
    "|| run.status !== 'completed'",
    "|| run.conclusion !== 'failure'",
    '|| run.head_sha !== process.env.ORIGINAL_CONTROLLER_SHA',
    '|| run.repository?.full_name !== process.env.GITHUB_REPOSITORY',
  ]);
  assert.deepEqual(exactGuardClauses(approvalStep, 'BLOCKED RECOVERY_CONTROLLER_INVALID'), [
    "mainRef.object?.type !== 'commit'",
    '|| mainRef.object.sha !== process.env.TRUSTED_CONTROLLER_SHA',
    '|| commit.sha !== process.env.TRUSTED_CONTROLLER_SHA',
    '|| commit.commit?.verification?.verified !== true',
    "|| commit.commit.verification.reason !== 'valid'",
  ]);
  for (const sourceRead of [
    'read(`actions/runs/${process.env.ORIGINAL_WORKFLOW_RUN_ID}`)',
    "read('git/ref/heads/main')",
    'read(`commits/${process.env.TRUSTED_CONTROLLER_SHA}`)',
  ]) {
    assert.equal(
      approvalScript.split(sourceRead).length - 1,
      1,
      `expected one exact protected source read: ${sourceRead}`,
    );
  }
}

test('packaged recovery workflow remains manual-only', async () => {
  const bytes = await readFile(workflowPath);
  assert.equal(bytes.byteLength, REVIEWED_WORKFLOW_BYTES);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), REVIEWED_WORKFLOW_SHA256);
  const workflow = bytes.toString('utf8');
  assertRecoveryWorkflowContract(workflow);
});

test('recovery workflow proves the failed owner, old binding, and protected signed controller separately', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  const controller = await readFile(
    'packages/verification-controller/src/test-cloud-recovery-controller.mjs',
    'utf8',
  );
  assert.match(workflow, /run\.workflow_id !== 336735803/u);
  assert.match(workflow, /run\.conclusion !== 'failure'/u);
  assert.match(workflow, /CONTROLLER_REVISION: \$\{\{ inputs\.original_controller_sha \}\}/u);
  assert.match(workflow, /TRUSTED_CONTROLLER_SHA: \$\{\{ vars\.TRUSTED_CONTROLLER_SHA \}\}/u);
  assert.match(workflow, /git\/ref\/heads\/main/u);
  assert.match(workflow, /commit\.commit\?\.verification\?\.verified !== true/u);
  assert.doesNotMatch(workflow, /prepare-controller-artifact\.mjs|TRUSTED_CONTROLLER_ARTIFACT_ID|TRUSTED_CONTROLLER_BUNDLE_DIGEST/u);
  assert.match(workflow, /test-cloud-binding-artifact-verifier\.mjs/u);
  assert.match(workflow, /test-cloud-recovery-controller\.mjs/u);
  assert.match(workflow, /--revision "\$\{\{ inputs\.revision \}\}"/u);
  assert.match(workflow, /--source-workflow-run-id "\$\{\{ inputs\.source_run_id \}\}"/u);
  assert.match(workflow, /--source-run-attempt "\$\{\{ inputs\.source_run_attempt \}\}"/u);
  assert.match(workflow, /--original-workflow-run-id "\$\{\{ inputs\.original_workflow_run_id \}\}"/u);
  assert.doesNotMatch(controller, /reattestLocalControllerArtifact|CONTROLLER_ARTIFACT_DIRECTORY/u);
});

test('recovery credential is exposed only to the final recovery step', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  const finalStep = workflow.slice(workflow.indexOf('- name: Recover only the expired Appwrite Test lease'));
  const prefix = workflow.slice(0, workflow.indexOf('- name: Recover only the expired Appwrite Test lease'));
  assert.doesNotMatch(prefix, /APPWRITE_TEST_RECOVERY_API_KEY/u);
  assert.match(finalStep, /APPWRITE_TEST_RECOVERY_API_KEY: \$\{\{ secrets\.APPWRITE_TEST_RECOVERY_API_KEY \}\}/u);
  assert.doesNotMatch(finalStep, /GITHUB_TOKEN|github\.token|CONTROLLER_ARTIFACT_READ_TOKEN/u);
});

test('workflow guard mutations are rejected structurally', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  const approvalPredicates = [
    'run.id !== Number(process.env.ORIGINAL_WORKFLOW_RUN_ID)',
    "run.name !== 'Verify Test Cloud'",
    'run.workflow_id !== 336735803',
    "run.event !== 'workflow_dispatch'",
    "run.status !== 'completed'",
    "run.conclusion !== 'failure'",
    'run.head_sha !== process.env.ORIGINAL_CONTROLLER_SHA',
    'run.repository?.full_name !== process.env.GITHUB_REPOSITORY',
    "mainRef.object?.type !== 'commit'",
    'mainRef.object.sha !== process.env.TRUSTED_CONTROLLER_SHA',
    'commit.sha !== process.env.TRUSTED_CONTROLLER_SHA',
    'commit.commit?.verification?.verified !== true',
    "commit.commit.verification.reason !== 'valid'",
  ];
  const sourceReads = [
    'read(`actions/runs/${process.env.ORIGINAL_WORKFLOW_RUN_ID}`)',
    "read('git/ref/heads/main')",
    'read(`commits/${process.env.TRUSTED_CONTROLLER_SHA}`)',
  ];
  const keyLine = '          APPWRITE_TEST_RECOVERY_API_KEY: ${{ secrets.APPWRITE_TEST_RECOVERY_API_KEY }}';
  const mutations = [
    ['scheduled trigger', workflow.replace('  workflow_dispatch:', '  workflow_dispatch:\n  schedule:')],
    ['cancelling concurrency', workflow.replace('  cancel-in-progress: false', '  cancel-in-progress: true')],
    ['later benign step', `${workflow}\n      - name: Later benign step\n        run: exit 1\n`],
    ['later unnamed step', `${workflow}\n      - run: exit 1\n`],
    ['later recovery-key step', `${workflow}\n      - name: Later key-bearing step\n        env:\n          APPWRITE_TEST_RECOVERY_API_KEY: \${{ secrets.APPWRITE_TEST_RECOVERY_API_KEY }}\n        run: exit 1\n`],
    ['recovery key moved earlier', workflow
      .replace(`${keyLine}\n`, '')
      .replace('          TRUSTED_CONTROLLER_SHA: ${{ vars.TRUSTED_CONTROLLER_SHA }}\n', (
        `          TRUSTED_CONTROLLER_SHA: \${{ vars.TRUSTED_CONTROLLER_SHA }}\n${keyLine}\n`
      ))],
    ['recovery key renamed', workflow.replace(
      keyLine,
      '          RENAMED_RECOVERY_KEY: ${{ secrets.APPWRITE_TEST_RECOVERY_API_KEY }}',
    )],
    ['extra operator credential', workflow.replace(
      keyLine,
      `${keyLine}\n          APPWRITE_TEST_OPERATOR_API_KEY: \${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}`,
    )],
    ['extra fixture credential', workflow.replace(
      keyLine,
      `${keyLine}\n          APPWRITE_TEST_FIXTURE_API_KEY: \${{ secrets.APPWRITE_TEST_FIXTURE_API_KEY }}`,
    )],
    ['extra API token', workflow.replace(
      keyLine,
      `${keyLine}\n          APPWRITE_TEST_API_TOKEN: \${{ secrets.APPWRITE_TEST_API_TOKEN }}`,
    )],
    ['extra noncredential env key', workflow.replace(
      keyLine,
      `${keyLine}\n          EXTRA_METADATA: forbidden`,
    )],
    ['duplicate inline final env', workflow.replace(
      '        run: |\n          set -euo pipefail',
      '        env: { EXTRA_METADATA: forbidden }\n        run: |\n          set -euo pipefail',
    )],
    ['inherited job credential', workflow.replace(
      '    environment: appwrite-test',
      '    environment: appwrite-test\n    env:\n      APPWRITE_TEST_OPERATOR_API_KEY: ${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}',
    )],
    ['anchored inherited job credential', workflow.replace(
      '    environment: appwrite-test',
      '    environment: appwrite-test\n    env: &forbidden-credentials\n      APPWRITE_TEST_OPERATOR_API_KEY: ${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}',
    )],
    ['later bare-marker step', `${workflow}\n      -\n        name: Later bare-marker step\n        run: exit 1\n`],
    ['spaced inherited job credential', workflow.replace(
      '    environment: appwrite-test',
      '    environment: appwrite-test\n    env :\n      APPWRITE_TEST_OPERATOR_API_KEY: ${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}',
    )],
    ['inherited workflow credential', workflow.replace(
      'permissions:',
      'env:\n  APPWRITE_TEST_OPERATOR_API_KEY: ${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}\n\npermissions:',
    )],
    ['spaced inherited workflow credential', workflow.replace(
      'permissions:',
      'env :\n  APPWRITE_TEST_OPERATOR_API_KEY: ${{ secrets.APPWRITE_TEST_OPERATOR_API_KEY }}\n\npermissions:',
    )],
    ['missing repository owner binding', workflow.replace("    if: github.repository == 'Krowaccie/AppWriteWork-verification-control'\n", '')],
    ...approvalPredicates.map((predicate) => [
      `missing ${predicate}`,
      workflow.replace(predicate, 'false'),
    ]),
    ...sourceReads.map((sourceRead) => [
      `changed ${sourceRead}`,
      workflow.replace(sourceRead, "read('forged/source')"),
    ]),
  ];
  for (const [name, mutation] of mutations) {
    assert.throws(
      () => assertRecoveryWorkflowContract(mutation),
      undefined,
      `${name} must be rejected`,
    );
  }
});
