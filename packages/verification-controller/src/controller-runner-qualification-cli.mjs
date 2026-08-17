import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { produceControllerRunnerQualification } from '../../../scripts/verification/controller-trust-materials.mjs';
import { runContainedProcess } from '../../../scripts/verification/process-containment.mjs';

const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const SOURCE_REPOSITORY = 'Krowaccie/AppWriteWork';
const SHA = /^[0-9a-f]{40}$/u;
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

function result(status, value, code = null) {
  return Object.freeze({
    status,
    value,
    diagnostics: code === null ? [] : Object.freeze([Object.freeze({
      code, retryable: false, safeMessage: 'Controller runner qualification is unavailable.',
    })]),
  });
}

export async function buildSameRunControllerPublisherInput(args, validationContext) {
  try {
    const outer = exactObject(args, ['input', 'environment', 'runContainedProcessImpl', 'cwd']);
    const context = exactObject(validationContext, ['clock']);
    const input = outer === null ? null : exactObject(outer.input, [
      'sourceRepositoryRevision', 'controllerRevision', 'runnerRevision',
      'setupReadback', 'setupReadbackDigest', 'setupAttestation',
      'setupAttestationDigest', 'primaryExecutionRetentionMaxSeconds',
    ]);
    const environment = outer === null ? null : exactObject(outer.environment, [
      'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_SHA',
    ]);
    if (
      outer === null || input === null || environment === null || context === null
      || environment.GITHUB_REPOSITORY !== CONTROLLER_REPOSITORY
      || !/^[1-9][0-9]{0,19}$/u.test(environment.GITHUB_RUN_ID ?? '')
      || !SHA.test(environment.GITHUB_SHA ?? '')
      || input.controllerRevision !== environment.GITHUB_SHA
      || !SHA.test(input.sourceRepositoryRevision ?? '')
      || !SHA.test(input.runnerRevision ?? '')
      || input.sourceRepositoryRevision === input.controllerRevision
      || typeof outer.cwd !== 'string' || !path.isAbsolute(outer.cwd)
      || typeof outer.runContainedProcessImpl !== 'function'
    ) return result('BLOCKED', null, 'CONTROLLER_RUNNER_QUALIFICATION_INVALID');
    const containment = await outer.runContainedProcessImpl({
      executable: 'C:\\Windows\\System32\\cmd.exe',
      args: ['/d', '/s', '/c', 'exit /b 0'],
      cwd: outer.cwd,
      env: {},
      timeoutMs: 30_000,
      maxOutputBytes: 4096,
    });
    if (
      !exactObject(containment, ['status', 'exitCode', 'signal', 'stdout', 'stderr'])
      || containment.status !== 'exited' || containment.exitCode !== 0
      || containment.signal !== null || containment.stdout !== '' || containment.stderr !== ''
    ) return result('BLOCKED', null, 'CONTROLLER_RUNNER_QUALIFICATION_INVALID');
    const setupBindings = {
      readback: input.setupReadback,
      readbackDigest: input.setupReadbackDigest,
      attestation: input.setupAttestation,
      attestationDigest: input.setupAttestationDigest,
    };
    const qualification = produceControllerRunnerQualification({
      workflowRunId: environment.GITHUB_RUN_ID,
      workflowHeadSha: environment.GITHUB_SHA,
      controllerRepository: CONTROLLER_REPOSITORY,
      sourceRepository: SOURCE_REPOSITORY,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      controllerRevision: input.controllerRevision,
      runnerRevision: input.runnerRevision,
      runnerImage: 'windows-2025',
      setupBindings,
      jobObjectQualification: {
        schemaVersion: 'windows-job-object-qualification.v1',
        status: 'PASS',
        killOnJobClose: true,
        breakawayDisabled: true,
      },
    }, {
      clock: context.clock,
      primaryExecutionRetentionMaxSeconds: input.primaryExecutionRetentionMaxSeconds,
    });
    if (qualification.status !== 'PASS') return result('BLOCKED', null, 'CONTROLLER_RUNNER_QUALIFICATION_INVALID');
    return result('PASS', {
      workflowRunId: environment.GITHUB_RUN_ID,
      workflowHeadSha: environment.GITHUB_SHA,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      controllerRevision: input.controllerRevision,
      qualification: qualification.value.qualification,
      qualificationDigest: qualification.value.digest,
      setupBindings,
      primaryExecutionRetentionMaxSeconds: input.primaryExecutionRetentionMaxSeconds,
    });
  } catch {
    return result('BLOCKED', null, 'CONTROLLER_RUNNER_QUALIFICATION_INVALID');
  }
}

export async function runControllerRunnerQualificationCli(argv = process.argv.slice(2), environment = process.env) {
  try {
    if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--input' || argv[2] !== '--output') return result('BLOCKED', null, 'CONTROLLER_RUNNER_QUALIFICATION_CLI_INVALID');
    const input = JSON.parse(await readFile(path.resolve(argv[1]), 'utf8'));
    const produced = await buildSameRunControllerPublisherInput({
      input,
      environment: {
        GITHUB_REPOSITORY: environment.GITHUB_REPOSITORY,
        GITHUB_RUN_ID: environment.GITHUB_RUN_ID,
        GITHUB_SHA: environment.GITHUB_SHA,
      },
      runContainedProcessImpl: runContainedProcess,
      cwd: path.resolve('.'),
    }, { clock: SYSTEM_CLOCK });
    if (produced.status !== 'PASS') return produced;
    await writeFile(path.resolve(argv[3]), `${canonicalJson(produced.value)}\n`, { flag: 'wx' });
    return result('PASS', null);
  } catch {
    return result('BLOCKED', null, 'CONTROLLER_RUNNER_QUALIFICATION_CLI_INVALID');
  }
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cli = await runControllerRunnerQualificationCli();
  if (cli.status !== 'PASS') {
    process.stderr.write('BLOCKED CONTROLLER_RUNNER_QUALIFICATION_CLI_INVALID\n');
    process.exitCode = 1;
  }
}
