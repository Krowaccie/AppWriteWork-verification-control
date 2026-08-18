import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from './canonical-json.mjs';
import { validateTestCloudSetupReadbackBytes } from './test-cloud-provider-contract.mjs';
import { validateTestCloudSetupAttestationDocument } from './test-cloud-setup-attestation.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u;
const SECRET_KEY = /(?:authorization|api.?key|password|secret|lease.?token|run.?id|duration(?:ms)?)/iu;
const SOURCE_REPOSITORY = 'Krowaccie/AppWriteWork';
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const QUALIFICATION_KEYS = Object.freeze([
  'schemaVersion', 'workflowRunId', 'workflowHeadSha', 'controllerRepository',
  'sourceRepository', 'sourceRepositoryRevision', 'controllerRevision', 'runnerRevision',
  'runnerImage', 'setupBindings', 'jobObjectQualification',
]);
const QUALIFICATION_EXPECTED_KEYS = Object.freeze([
  'workflowRunId', 'workflowHeadSha', 'controllerRepository', 'sourceRepository',
  'sourceRepositoryRevision', 'controllerRevision', 'runnerRevision', 'runnerImage',
  'setupBindings',
]);
const QUALIFICATION_SETUP_KEYS = Object.freeze([
  'testCloudSetupReadbackJsonDigest', 'testCloudSetupReadbackDigest',
  'testCloudSetupAttestationJsonDigest', 'testCloudSetupAttestationDigest',
]);
const JOB_OBJECT_QUALIFICATION_KEYS = Object.freeze([
  'schemaVersion', 'status', 'killOnJobClose', 'breakawayDisabled',
]);
const REQUIRED_EVALUATOR_PATHS = Object.freeze([
  'dev/verification/bootstrap/qualify-runner.mjs',
  'scripts/verification/canonical-json.mjs',
  'scripts/verification/controller-bundle.mjs',
  'scripts/verification/controller-trust-materials.mjs',
  'scripts/verification/test-cloud-bootstrap.mjs',
  'scripts/verification/test-cloud-provider-contract.mjs',
  'scripts/verification/test-cloud-setup-attestation.mjs',
]);
const NETWORK_ROW_KEYS = Object.freeze([
  'credentialCarrier', 'exactCount', 'expectedResponseStatus', 'finalUrl',
  'lifecyclePhase', 'method', 'ordinal', 'profileId', 'requestClass',
  'requestHeaderBindings', 'requestOpaqueHeaderRules', 'resourceType',
  'responseBodyDigest', 'responseByteLength', 'responseHeaderBindings',
  'responseMimeEssence', 'responseOpaqueHeaderRules',
]);

export const TRUST_MATERIAL_PATHS = Object.freeze({
  evaluator: 'trust/evaluator.v1.json',
  evidenceValidator: 'trust/evidence-validator.v1.json',
  networkPolicy: 'trust/network-policy.v1.json',
  transcriptCorpus: 'trust/transcript-corpus.v2.json',
  provenance: 'trust/provenance.v1.json',
  qualification: 'trust/controller-runner-qualification.v1.json',
});

function exactObject(value, keys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return null;
    const names = Object.getOwnPropertyNames(value).sort();
    const expected = [...keys].sort();
    if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
      return null;
    }
    const snapshot = {};
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
      snapshot[name] = descriptor.value;
    }
    return snapshot;
  } catch {
    return null;
  }
}

function deepFreeze(value, seen = new WeakSet()) {
  if (utilTypes.isUint8Array(value)) return value;
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function result(status, value, code = null) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null ? [] : [{
      code,
      retryable: false,
      safeMessage: 'Controller trust material is invalid.',
    }],
  });
}

function blocked(code) {
  return result('BLOCKED', null, code);
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function canonicalArtifact(value) {
  const bytes = new TextEncoder().encode(`${canonicalJson(value)}\n`);
  return deepFreeze({ value, bytes, digest: digestBytes(bytes) });
}

function canonicalInputArtifact(value) {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  return deepFreeze({ value, bytes, digest: digestBytes(bytes) });
}

function closedJson(value, { rejectRuntime = false } = {}, seen = new WeakSet()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || utilTypes.isProxy(value) || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) return false;
    return value.every((item) => closedJson(item, { rejectRuntime }, seen));
  }
  if (Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length !== 0) return false;
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEY.test(key) && (rejectRuntime || /(?:authorization|api.?key|password|secret|lease.?token)/iu.test(key))) return false;
    if (!closedJson(child, { rejectRuntime }, seen)) return false;
  }
  return true;
}

function validSetupBindings(value, primaryExecutionRetentionMaxSeconds, clock) {
  const input = exactObject(value, [
    'readback', 'readbackDigest', 'attestation', 'attestationDigest',
  ]);
  if (
    input === null
    || !closedJson(input.readback, { rejectRuntime: true })
    || !closedJson(input.attestation, { rejectRuntime: true })
    || !DIGEST.test(input.readbackDigest ?? '')
    || !DIGEST.test(input.attestationDigest ?? '')
  ) return null;
  const readbackInput = canonicalInputArtifact(input.readback);
  const readback = canonicalArtifact(input.readback);
  const attestation = canonicalArtifact(input.attestation);
  const readbackDocument = exactObject(input.readback, [
    'browserRequestPolicy', 'controlDatabase', 'coreBindings', 'environmentDigest',
    'expectedRunnerVariables', 'genesis', 'identityBindings', 'nodeResponseFormat',
    'providerContractDigest', 'pythonRuntimeResponseFormat', 'schemaVersion',
  ]);
  const identityBindings = readbackDocument === null ? null : exactObject(
    readbackDocument.identityBindings,
    ['identityBindingsDigest', 'sessionCounts'],
  );
  const attestationValidation = readbackDocument === null || identityBindings === null
    ? null
    : validateTestCloudSetupAttestationDocument({
      attestation: input.attestation,
      attestationDigest: input.attestationDigest,
      clock,
      expectedEnvironmentDigest: readbackDocument.environmentDigest,
      expectedProviderContractDigest: readbackDocument.providerContractDigest,
      expectedIdentityBindingsDigest: identityBindings.identityBindingsDigest,
      expectedProviderSetupReadbackDigest: input.readbackDigest,
      expectedPrimaryExecutionRetentionMaxSeconds: primaryExecutionRetentionMaxSeconds,
      maximumRetentionSeconds: 86400,
    });
  if (
    readbackInput.digest !== input.readbackDigest
    || readbackDocument === null
    || identityBindings === null
    || attestationValidation?.status !== 'PASS'
    || validateTestCloudSetupReadbackBytes({
      bytes: readbackInput.bytes,
      expectedDigest: input.readbackDigest,
      expectedEnvironmentDigest: readbackDocument.environmentDigest,
      expectedProviderContractDigest: readbackDocument.providerContractDigest,
    }).status !== 'PASS'
  ) return null;
  return { input, readback, attestation };
}

function snapshotBytes(value) {
  try {
    if (!utilTypes.isUint8Array(value) || utilTypes.isProxy(value)) return null;
    const copy = new Uint8Array(value.byteLength);
    copy.set(value);
    return copy;
  } catch {
    return null;
  }
}

export function validateControllerRunnerQualification(args) {
  try {
    const input = exactObject(args, ['qualification', 'qualificationDigest', 'expected']);
    const qualification = input === null ? null : exactObject(input.qualification, QUALIFICATION_KEYS);
    const expected = input === null ? null : exactObject(input.expected, QUALIFICATION_EXPECTED_KEYS);
    const setup = qualification === null ? null : exactObject(
      qualification.setupBindings,
      QUALIFICATION_SETUP_KEYS,
    );
    const expectedSetup = expected === null ? null : exactObject(
      expected.setupBindings,
      QUALIFICATION_SETUP_KEYS,
    );
    const job = qualification === null ? null : exactObject(
      qualification.jobObjectQualification,
      JOB_OBJECT_QUALIFICATION_KEYS,
    );
    const artifact = qualification === null ? null : canonicalArtifact(qualification);
    if (
      input === null
      || qualification === null
      || expected === null
      || setup === null
      || expectedSetup === null
      || job === null
      || qualification.schemaVersion !== 'controller-runner-qualification.v1'
      || !RUN_ID.test(qualification.workflowRunId ?? '')
      || !SHA.test(qualification.workflowHeadSha ?? '')
      || qualification.controllerRepository !== CONTROLLER_REPOSITORY
      || qualification.sourceRepository !== SOURCE_REPOSITORY
      || !SHA.test(qualification.sourceRepositoryRevision ?? '')
      || !SHA.test(qualification.controllerRevision ?? '')
      || qualification.sourceRepositoryRevision === qualification.controllerRevision
      || qualification.workflowHeadSha !== qualification.controllerRevision
      || !SHA.test(qualification.runnerRevision ?? '')
      || qualification.runnerImage !== 'windows-2025'
      || Object.values(setup).some((value) => !DIGEST.test(value))
      || job.schemaVersion !== 'windows-job-object-qualification.v1'
      || job.status !== 'PASS'
      || job.killOnJobClose !== true
      || job.breakawayDisabled !== true
      || !closedJson(qualification, { rejectRuntime: false })
      || artifact.digest !== input.qualificationDigest
      || QUALIFICATION_EXPECTED_KEYS.some((key) => (
        key === 'setupBindings'
          ? canonicalJson(setup) !== canonicalJson(expectedSetup)
          : qualification[key] !== expected[key]
      ))
    ) return blocked('CONTROLLER_RUNNER_QUALIFICATION_INVALID');
    return result('PASS', { qualification, ...artifact });
  } catch {
    return blocked('CONTROLLER_RUNNER_QUALIFICATION_INVALID');
  }
}

export function produceControllerRunnerQualification(args, validationContext) {
  try {
    const input = exactObject(args, [
      'workflowRunId', 'workflowHeadSha', 'controllerRepository', 'sourceRepository',
      'sourceRepositoryRevision', 'controllerRevision', 'runnerRevision', 'runnerImage',
      'setupBindings', 'jobObjectQualification',
    ]);
    const context = exactObject(validationContext, ['clock', 'primaryExecutionRetentionMaxSeconds']);
    const setup = input === null || context === null ? null : validSetupBindings(
      input.setupBindings,
      context.primaryExecutionRetentionMaxSeconds,
      context.clock,
    );
    const job = input === null ? null : exactObject(
      input.jobObjectQualification,
      JOB_OBJECT_QUALIFICATION_KEYS,
    );
    if (
      input === null
      || setup === null
      || job === null
      || !RUN_ID.test(input.workflowRunId ?? '')
      || !SHA.test(input.workflowHeadSha ?? '')
      || input.controllerRepository !== CONTROLLER_REPOSITORY
      || input.sourceRepository !== SOURCE_REPOSITORY
      || !SHA.test(input.sourceRepositoryRevision ?? '')
      || !SHA.test(input.controllerRevision ?? '')
      || input.sourceRepositoryRevision === input.controllerRevision
      || input.workflowHeadSha !== input.controllerRevision
      || !SHA.test(input.runnerRevision ?? '')
      || input.runnerImage !== 'windows-2025'
      || job.schemaVersion !== 'windows-job-object-qualification.v1'
      || job.status !== 'PASS'
      || job.killOnJobClose !== true
      || job.breakawayDisabled !== true
    ) return blocked('CONTROLLER_RUNNER_QUALIFICATION_INVALID');

    const qualification = deepFreeze({
      schemaVersion: 'controller-runner-qualification.v1',
      workflowRunId: input.workflowRunId,
      workflowHeadSha: input.workflowHeadSha,
      controllerRepository: input.controllerRepository,
      sourceRepository: input.sourceRepository,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      controllerRevision: input.controllerRevision,
      runnerRevision: input.runnerRevision,
      runnerImage: input.runnerImage,
      setupBindings: {
        testCloudSetupReadbackJsonDigest: setup.readback.digest,
        testCloudSetupReadbackDigest: setup.input.readbackDigest,
        testCloudSetupAttestationJsonDigest: setup.attestation.digest,
        testCloudSetupAttestationDigest: setup.input.attestationDigest,
      },
      jobObjectQualification: job,
    });
    return validateControllerRunnerQualification({
      qualification,
      qualificationDigest: canonicalArtifact(qualification).digest,
      expected: {
        workflowRunId: input.workflowRunId,
        workflowHeadSha: input.workflowHeadSha,
        controllerRepository: input.controllerRepository,
        sourceRepository: input.sourceRepository,
        sourceRepositoryRevision: input.sourceRepositoryRevision,
        controllerRevision: input.controllerRevision,
        runnerRevision: input.runnerRevision,
        runnerImage: input.runnerImage,
        setupBindings: qualification.setupBindings,
      },
    });
  } catch {
    return blocked('CONTROLLER_RUNNER_QUALIFICATION_INVALID');
  }
}

function evaluatorMaterial(closure) {
  const input = exactObject(closure, ['entrypoint', 'runtime', 'files']);
  const runtime = input === null ? null : exactObject(input.runtime, ['name', 'version', 'platform']);
  if (
    input === null
    || runtime === null
    || !SAFE_PATH.test(input.entrypoint ?? '')
    || runtime.name !== 'node'
    || runtime.version !== '24.11.1'
    || runtime.platform !== 'windows-2025'
    || !Array.isArray(input.files)
  ) return null;
  const files = [];
  for (const candidate of input.files) {
    const record = exactObject(candidate, ['path', 'mode', 'bytes']);
    const bytes = record === null ? null : snapshotBytes(record.bytes);
    if (record === null || bytes === null || !SAFE_PATH.test(record.path) || record.mode !== '100644') return null;
    files.push({ path: record.path, mode: record.mode, sha256: digestBytes(bytes) });
  }
  files.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  if (
    files.length !== REQUIRED_EVALUATOR_PATHS.length
    || files.some((record, index) => record.path !== REQUIRED_EVALUATOR_PATHS[index])
  ) return null;
  const closureDigest = digestBytes(new TextEncoder().encode(`${canonicalJson(files)}\n`));
  return {
    schemaVersion: 'controller-trust-evaluator.v1',
    entrypoint: input.entrypoint,
    runtime,
    files,
    closureDigest,
  };
}

function networkPolicyMaterial(readback) {
  const outer = exactObject(readback, [
    'browserRequestPolicy', 'controlDatabase', 'coreBindings', 'environmentDigest',
    'expectedRunnerVariables', 'genesis', 'identityBindings', 'nodeResponseFormat',
    'providerContractDigest', 'pythonRuntimeResponseFormat', 'schemaVersion',
  ]);
  const policy = outer === null ? null : exactObject(outer.browserRequestPolicy, [
    'schemaVersion', 'timeoutMilliseconds', 'rows', 'digest',
  ]);
  if (
    outer === null
    || policy === null
    || !DIGEST.test(outer.environmentDigest ?? '')
    || policy.schemaVersion !== 'test-cloud.browser-request-policy.v1'
    || policy.timeoutMilliseconds !== 5000
    || !DIGEST.test(policy.digest ?? '')
    || !Array.isArray(policy.rows)
    || policy.rows.length !== 56
  ) return null;
  const rows = [];
  for (let index = 0; index < policy.rows.length; index += 1) {
    const row = exactObject(policy.rows[index], NETWORK_ROW_KEYS);
    if (row === null || row.ordinal !== index || !/^[A-Z]+$/u.test(row.method ?? '')) return null;
    try {
      if (new URL(row.finalUrl).protocol !== 'https:') return null;
    } catch {
      return null;
    }
    rows.push({
      ...row,
      rowDigest: digestBytes(new TextEncoder().encode(`${canonicalJson(row)}\n`)),
    });
  }
  if (!['GET', 'OPTIONS', 'PATCH', 'POST'].every((method) => rows.some((row) => row.method === method))) return null;
  const contract = {
    schemaVersion: 'controller-network-policy-material.v1',
    environmentDigest: outer.environmentDigest,
    browserRequestPolicyDigest: policy.digest,
    timeoutMilliseconds: policy.timeoutMilliseconds,
    rows,
  };
  return { ...contract, contractDigest: digestBytes(new TextEncoder().encode(`${canonicalJson(contract)}\n`)) };
}

function transcriptMaterial(qualification, environmentDigest, retention) {
  return {
    schemaVersion: 'verification-runner-transcript-corpus.v2',
    binding: {
      environmentDigest,
      runnerRevision: qualification.runnerRevision,
      primaryExecutionRetentionMaxSeconds: retention,
    },
    matchers: [
      {
        id: 'health-positive',
        requestedScenario: 'health',
        response: {
          protocolVersion: 'verification-runner.v1',
          scenarioId: 'health',
          status: 'passed',
          data: { ready: true, runnerRevision: qualification.runnerRevision },
        },
      },
      ...['future', 'unknown_scenario'].map((requestedScenario) => ({
        id: `${requestedScenario}-negative`,
        requestedScenario,
        response: {
          protocolVersion: 'verification-runner.v1',
          scenarioId: 'invalid',
          status: 'failed',
          error: {
            code: 'unknown_scenario',
            retryable: false,
            safeMessage: 'Scenario is outside the closed runner protocol.',
          },
        },
      })),
    ],
  };
}

export function produceControllerTrustMaterials(args, validationContext) {
  try {
    const input = exactObject(args, [
      'qualification', 'qualificationDigest', 'setupBindings', 'evaluatorClosure',
      'primaryExecutionRetentionMaxSeconds',
    ]);
    const context = exactObject(validationContext, ['clock']);
    const setup = input === null || context === null ? null : validSetupBindings(
      input.setupBindings,
      input.primaryExecutionRetentionMaxSeconds,
      context.clock,
    );
    const qualification = input?.qualification;
    const qualificationValidation = input === null || setup === null ? null : validateControllerRunnerQualification({
      qualification,
      qualificationDigest: input.qualificationDigest,
      expected: {
        workflowRunId: qualification?.workflowRunId,
        workflowHeadSha: qualification?.controllerRevision,
        controllerRepository: CONTROLLER_REPOSITORY,
        sourceRepository: SOURCE_REPOSITORY,
        sourceRepositoryRevision: qualification?.sourceRepositoryRevision,
        controllerRevision: qualification?.controllerRevision,
        runnerRevision: qualification?.runnerRevision,
        runnerImage: 'windows-2025',
        setupBindings: {
          testCloudSetupReadbackJsonDigest: setup.readback.digest,
          testCloudSetupReadbackDigest: setup.input.readbackDigest,
          testCloudSetupAttestationJsonDigest: setup.attestation.digest,
          testCloudSetupAttestationDigest: setup.input.attestationDigest,
        },
      },
    });
    const evaluator = input === null ? null : evaluatorMaterial(input.evaluatorClosure);
    if (
      input === null
      || setup === null
      || qualificationValidation?.status !== 'PASS'
      || evaluator === null
      || !Number.isInteger(input.primaryExecutionRetentionMaxSeconds)
      || input.primaryExecutionRetentionMaxSeconds < 1
      || input.primaryExecutionRetentionMaxSeconds > 86400
    ) return blocked('CONTROLLER_TRUST_MATERIAL_INVALID');

    const networkPolicy = networkPolicyMaterial(setup.input.readback);
    if (networkPolicy === null) return blocked('CONTROLLER_TRUST_MATERIAL_INVALID');
    const materials = {
      evaluator: canonicalArtifact(evaluator),
      evidenceValidator: canonicalArtifact({
        schemaVersion: 'verification-runner-evidence-validator.v1',
        transportStatus: 201,
        evidence: {
          protocolVersion: 'verification-runner.v1',
          status: 'completed',
          requiredFields: ['protocolVersion', 'scenarioId', 'status', 'data'],
        },
      }),
      networkPolicy: canonicalArtifact(networkPolicy),
      transcriptCorpus: canonicalArtifact(transcriptMaterial(
        qualification,
        setup.input.readback.environmentDigest,
        input.primaryExecutionRetentionMaxSeconds,
      )),
    };
    const provenance = canonicalArtifact({
      schemaVersion: 'controller-trust-provenance.v1',
      workflowRunId: qualification.workflowRunId,
      workflowHeadSha: qualification.workflowHeadSha,
      controllerRepository: qualification.controllerRepository,
      sourceRepository: qualification.sourceRepository,
      sourceRepositoryRevision: qualification.sourceRepositoryRevision,
      controllerRevision: qualification.controllerRevision,
      qualificationDigest: input.qualificationDigest,
      setupBindings: { ...qualification.setupBindings },
      materials: Object.entries(materials)
        .map(([kind, artifact]) => ({ kind, path: TRUST_MATERIAL_PATHS[kind], sha256: artifact.digest }))
        .sort((left, right) => left.kind < right.kind ? -1 : left.kind > right.kind ? 1 : 0),
    });
    return result('PASS', { materials: deepFreeze(materials), provenance });
  } catch {
    return blocked('CONTROLLER_TRUST_MATERIAL_INVALID');
  }
}

export function validatePublishedControllerTrustArtifacts(args) {
  try {
    const input = exactObject(args, ['qualification', 'provenance', 'materials']);
    const qualification = input?.qualification;
    const materials = input === null ? null : exactObject(input.materials, [
      'evaluator', 'evidenceValidator', 'networkPolicy', 'transcriptCorpus',
    ]);
    const provenance = input === null ? null : exactObject(input.provenance, [
      'schemaVersion', 'workflowRunId', 'workflowHeadSha', 'controllerRepository',
      'sourceRepository', 'sourceRepositoryRevision', 'controllerRevision',
      'qualificationDigest', 'setupBindings', 'materials',
    ]);
    const qualificationValidation = provenance === null ? null : validateControllerRunnerQualification({
      qualification,
      qualificationDigest: provenance.qualificationDigest,
      expected: {
        workflowRunId: provenance.workflowRunId,
        workflowHeadSha: provenance.workflowHeadSha,
        controllerRepository: provenance.controllerRepository,
        sourceRepository: provenance.sourceRepository,
        sourceRepositoryRevision: provenance.sourceRepositoryRevision,
        controllerRevision: provenance.controllerRevision,
        runnerRevision: qualification?.runnerRevision,
        runnerImage: 'windows-2025',
        setupBindings: provenance.setupBindings,
      },
    });
    const setup = qualificationValidation?.value?.qualification.setupBindings;
    if (
      qualificationValidation?.status !== 'PASS' || setup === undefined || materials === null || provenance === null
      || !closedJson(input, { rejectRuntime: false })
      || provenance.schemaVersion !== 'controller-trust-provenance.v1'
      || provenance.workflowRunId !== qualification.workflowRunId
      || provenance.workflowHeadSha !== qualification.workflowHeadSha
      || provenance.controllerRepository !== qualification.controllerRepository
      || provenance.sourceRepository !== qualification.sourceRepository
      || provenance.sourceRepositoryRevision !== qualification.sourceRepositoryRevision
      || provenance.controllerRevision !== qualification.controllerRevision
      || canonicalJson(provenance.setupBindings) !== canonicalJson(setup)
    ) return blocked('CONTROLLER_TRUST_ARTIFACT_INVALID');

    const evaluator = exactObject(materials.evaluator, ['schemaVersion', 'entrypoint', 'runtime', 'files', 'closureDigest']);
    const runtime = evaluator === null ? null : exactObject(evaluator.runtime, ['name', 'version', 'platform']);
    const evaluatorFiles = evaluator === null || !Array.isArray(evaluator.files) ? null : evaluator.files.map((record) => exactObject(record, ['path', 'mode', 'sha256']));
    if (
      evaluator === null || runtime === null || evaluatorFiles === null || evaluatorFiles.some((record) => record === null)
      || evaluator.schemaVersion !== 'controller-trust-evaluator.v1'
      || evaluator.entrypoint !== 'scripts/verification/controller-trust-materials.mjs'
      || runtime.name !== 'node' || runtime.version !== '24.11.1' || runtime.platform !== 'windows-2025'
      || evaluatorFiles.length !== REQUIRED_EVALUATOR_PATHS.length
      || evaluatorFiles.some((record, index) => record.path !== REQUIRED_EVALUATOR_PATHS[index] || record.mode !== '100644' || !DIGEST.test(record.sha256))
      || evaluator.closureDigest !== digestBytes(new TextEncoder().encode(`${canonicalJson(evaluatorFiles)}\n`))
    ) return blocked('CONTROLLER_TRUST_ARTIFACT_INVALID');

    const evidenceExpected = {
      schemaVersion: 'verification-runner-evidence-validator.v1', transportStatus: 201,
      evidence: { protocolVersion: 'verification-runner.v1', status: 'completed', requiredFields: ['protocolVersion', 'scenarioId', 'status', 'data'] },
    };
    const network = exactObject(materials.networkPolicy, [
      'schemaVersion', 'environmentDigest', 'browserRequestPolicyDigest',
      'timeoutMilliseconds', 'rows', 'contractDigest',
    ]);
    const networkRows = network === null || !Array.isArray(network.rows)
      ? null
      : network.rows.map((row) => exactObject(row, [...NETWORK_ROW_KEYS, 'rowDigest']));
    const policyRows = networkRows === null ? null : networkRows.map(({ rowDigest, ...row }) => row);
    if (
      canonicalJson(materials.evidenceValidator) !== canonicalJson(evidenceExpected)
      || network === null || networkRows === null || networkRows.length !== 56 || networkRows.some((row) => row === null)
      || network.schemaVersion !== 'controller-network-policy-material.v1'
      || !DIGEST.test(network.environmentDigest ?? '')
      || !DIGEST.test(network.browserRequestPolicyDigest ?? '')
      || network.timeoutMilliseconds !== 5000
      || networkRows.some((row, index) => row.ordinal !== index
        || !/^[A-Z]+$/u.test(row.method ?? '')
        || row.rowDigest !== digestBytes(new TextEncoder().encode(`${canonicalJson(policyRows[index])}\n`)))
      || !['GET', 'OPTIONS', 'PATCH', 'POST'].every((method) => networkRows.some((row) => row.method === method))
      || network.browserRequestPolicyDigest !== digestBytes(new TextEncoder().encode(canonicalJson({
        schemaVersion: 'test-cloud.browser-request-policy.v1',
        timeoutMilliseconds: network.timeoutMilliseconds,
        rows: policyRows,
      })))
      || network.contractDigest !== digestBytes(new TextEncoder().encode(`${canonicalJson({
        schemaVersion: network.schemaVersion,
        environmentDigest: network.environmentDigest,
        browserRequestPolicyDigest: network.browserRequestPolicyDigest,
        timeoutMilliseconds: network.timeoutMilliseconds,
        rows: network.rows,
      })}\n`))
      || canonicalJson(materials.transcriptCorpus) !== canonicalJson(transcriptMaterial(
        qualification,
        network.environmentDigest,
        materials.transcriptCorpus?.binding?.primaryExecutionRetentionMaxSeconds,
      ))
    ) return blocked('CONTROLLER_TRUST_ARTIFACT_INVALID');
    const expectedRecords = Object.entries(materials).map(([kind, value]) => ({
      kind, path: TRUST_MATERIAL_PATHS[kind], sha256: canonicalArtifact(value).digest,
    })).sort((left, right) => left.kind < right.kind ? -1 : left.kind > right.kind ? 1 : 0);
    if (canonicalJson(provenance.materials) !== canonicalJson(expectedRecords)) return blocked('CONTROLLER_TRUST_ARTIFACT_INVALID');
    return result('PASS', null);
  } catch {
    return blocked('CONTROLLER_TRUST_ARTIFACT_INVALID');
  }
}

export function evaluateRunnerTranscript(args) {
  try {
    const input = exactObject(args, ['corpus', 'observation']);
    const observation = input === null ? null : exactObject(input.observation, ['request', 'response']);
    const request = observation === null ? null : exactObject(observation.request, [
      'scenarioId', 'environmentDigest', 'primaryExecutionRetentionMaxSeconds',
    ]);
    if (
      input === null
      || observation === null
      || request === null
      || input.corpus?.schemaVersion !== 'verification-runner-transcript-corpus.v2'
      || request.environmentDigest !== input.corpus.binding.environmentDigest
      || request.primaryExecutionRetentionMaxSeconds !== input.corpus.binding.primaryExecutionRetentionMaxSeconds
    ) return blocked('RUNNER_TRANSCRIPT_MISMATCH');
    const matcher = input.corpus.matchers.find(({ requestedScenario }) => requestedScenario === request.scenarioId);
    if (matcher === undefined || canonicalJson(matcher.response) !== canonicalJson(observation.response)) {
      return blocked('RUNNER_TRANSCRIPT_MISMATCH');
    }
    return result('PASS', null);
  } catch {
    return blocked('RUNNER_TRANSCRIPT_MISMATCH');
  }
}
