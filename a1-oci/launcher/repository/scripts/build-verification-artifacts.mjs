import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { fileURLToPath } from 'node:url';

import { buildVerificationArtifactSet } from './verification/artifact-set.mjs';

const ARGUMENTS = Object.freeze([
  '--output',
  '--repository',
  '--revision',
  '--source-ref',
  '--workflow',
  '--workflow-run-attempt',
  '--workflow-run-id',
]);
const ARGUMENT_ERROR = 'Invalid closed artifact producer arguments.';
const FULL_REVISION = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const PORT_KEYS = Object.freeze(['identity', 'runCommand', 'workspace', 'writeOutputMember']);
const IDENTITY_KEYS = Object.freeze([
  'repository', 'sourceRef', 'sourceRevision', 'sourceTreeDigest',
  'verifierManifestDigest', 'workflow', 'workflowRunAttempt', 'workflowRunId',
]);
const WORKSPACE_KEYS = Object.freeze(['childTemp', 'exportRoot', 'outputRoot', 'siteOutput']);
const MESSAGES = Object.freeze({
  ARTIFACT_BUILD_FAILED: 'Verification artifacts could not be built.',
  ARTIFACT_CLEANUP_INCOMPLETE: 'Verification artifact cleanup could not be completed safely.',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'Trusted build network isolation is unavailable.',
  ARTIFACT_PATH_UNSAFE: 'Artifact source or output path is unsafe.',
  ARTIFACT_SCHEMA_INVALID: 'Artifact build input does not match the closed contract.',
});
const STATUS_BY_CODE = Object.freeze({
  ARTIFACT_BUILD_FAILED: 'FAIL',
  ARTIFACT_CLEANUP_INCOMPLETE: 'BLOCKED',
  ARTIFACT_NETWORK_POLICY_UNAVAILABLE: 'BLOCKED',
  ARTIFACT_PATH_UNSAFE: 'BLOCKED',
  ARTIFACT_SCHEMA_INVALID: 'BLOCKED',
});
const UNAVAILABLE_COMMAND_PORT = Object.freeze(Object.create(null));

function closedRecord(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function result(status, code = null) {
  return closedRecord({
    status,
    value: null,
    diagnostics: code === null ? Object.freeze([]) : Object.freeze([closedRecord({
      code,
      safeMessage: MESSAGES[code],
      retryable: false,
    })]),
  });
}

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactDataObject(value, expectedKeys, expectedPrototype) {
  try {
    if (utilTypes.isProxy(value) || value === null || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    if (Object.getPrototypeOf(value) !== expectedPrototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== 'string')) return null;
    const actual = [...ownKeys].sort(ordinalCompare);
    const expected = [...expectedKeys].sort(ordinalCompare);
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
      return null;
    }
    const copy = Object.create(null);
    for (const key of expectedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function exactOrdinary(value, expectedKeys) {
  return exactDataObject(value, expectedKeys, Object.prototype);
}

function exactTrusted(value, expectedKeys) {
  const copy = exactDataObject(value, expectedKeys, null);
  try {
    return copy !== null && Object.isFrozen(value) ? copy : null;
  } catch {
    return null;
  }
}

function exactFrozenArray(value, expectedLength) {
  try {
    if (!Array.isArray(value) || !Object.isFrozen(value) || value.length !== expectedLength) return null;
    const ownKeys = Reflect.ownKeys(value);
    const expected = [...Array.from({ length: expectedLength }, (_, index) => `${index}`), 'length'];
    if (ownKeys.length !== expected.length || ownKeys.some((key, index) => key !== expected[index])) {
      return null;
    }
    const copy = [];
    for (let index = 0; index < expectedLength; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      copy.push(descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function snapshotArgv(argv) {
  try {
    if (!Array.isArray(argv) || utilTypes.isProxy(argv)) return null;
    const lengthDescriptor = Object.getOwnPropertyDescriptor(argv, 'length');
    const length = lengthDescriptor?.value;
    if (!Number.isSafeInteger(length) || length < 0 || length % 2 !== 0) return null;
    const ownKeys = Reflect.ownKeys(argv);
    const expected = [...Array.from({ length }, (_, index) => `${index}`), 'length'];
    if (ownKeys.length !== expected.length || ownKeys.some((key, index) => key !== expected[index])) {
      return null;
    }
    const values = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(argv, index);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      values.push(descriptor.value);
    }
    return values;
  } catch {
    return null;
  }
}

function failArguments() {
  throw new TypeError(ARGUMENT_ERROR);
}

export function parseArtifactProducerArgs(argv) {
  const snapshot = snapshotArgv(argv);
  if (snapshot === null) failArguments();
  const values = new Map();
  for (let index = 0; index < snapshot.length; index += 2) {
    const name = snapshot[index];
    const value = snapshot[index + 1];
    if (
      typeof name !== 'string'
      || !ARGUMENTS.includes(name)
      || values.has(name)
      || typeof value !== 'string'
      || value.length === 0
    ) failArguments();
    values.set(name, value);
  }
  if (values.size !== ARGUMENTS.length) failArguments();
  const revision = values.get('--revision');
  const attemptText = values.get('--workflow-run-attempt');
  const runAttempt = Number(attemptText);
  const output = values.get('--output');
  if (
    !FULL_REVISION.test(revision)
    || output !== `.verification/artifacts/${revision}`
    || values.get('--repository') !== 'Krowaccie/AppWriteWork'
    || values.get('--workflow') !== 'Verify Main'
    || !RUN_ID.test(values.get('--workflow-run-id'))
    || !RUN_ID.test(attemptText)
    || !Number.isSafeInteger(runAttempt)
    || values.get('--source-ref') !== 'refs/heads/main'
  ) failArguments();
  return {
    revision,
    output,
    github: {
      repository: 'Krowaccie/AppWriteWork',
      workflow: 'Verify Main',
      runId: values.get('--workflow-run-id'),
      runAttempt,
      ref: 'refs/heads/main',
    },
  };
}

function snapshotProducerArgs(args) {
  try {
    if (utilTypes.isProxy(args) || args === null || typeof args !== 'object' || Array.isArray(args)) {
      return null;
    }
    if (Object.getPrototypeOf(args) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(args);
    if (ownKeys.some((key) => typeof key !== 'string')) return null;
    const hasCommandPort = ownKeys.includes('commandPort');
    return exactOrdinary(args, hasCommandPort ? ['argv', 'commandPort'] : ['argv']);
  } catch {
    return null;
  }
}

function snapshotPortForProducer(commandPort, parsed) {
  const port = exactTrusted(commandPort, PORT_KEYS);
  if (port === null) return null;
  const identity = exactTrusted(port.identity, IDENTITY_KEYS);
  const workspace = exactTrusted(port.workspace, WORKSPACE_KEYS);
  if (
    identity === null
    || workspace === null
    || typeof workspace.outputRoot !== 'string'
    || !path.isAbsolute(workspace.outputRoot)
    || identity.repository !== parsed.github.repository
    || identity.workflow !== parsed.github.workflow
    || identity.sourceRef !== parsed.github.ref
    || identity.sourceRevision !== parsed.revision
    || identity.workflowRunId !== parsed.github.runId
    || identity.workflowRunAttempt !== parsed.github.runAttempt
    || typeof identity.sourceTreeDigest !== 'string'
    || !/^sha256:[0-9a-f]{64}$/u.test(identity.sourceTreeDigest)
  ) return null;
  if (
    parsed.output !== `.verification/artifacts/${parsed.revision}`
    || path.basename(workspace.outputRoot) !== parsed.revision
    || path.basename(path.dirname(workspace.outputRoot)) !== 'artifacts'
    || path.basename(path.dirname(path.dirname(workspace.outputRoot))) !== '.verification'
  ) return null;
  return { sourceTreeDigest: identity.sourceTreeDigest };
}

export async function runArtifactProducer(args = {}) {
  try {
    const input = snapshotProducerArgs(args);
    if (input === null) return result('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
    const parsed = parseArtifactProducerArgs(input.argv);
    const commandPort = Object.hasOwn(input, 'commandPort')
      ? input.commandPort
      : UNAVAILABLE_COMMAND_PORT;
    if (commandPort === UNAVAILABLE_COMMAND_PORT) {
      return result('BLOCKED', 'ARTIFACT_NETWORK_POLICY_UNAVAILABLE');
    }
    const projection = snapshotPortForProducer(commandPort, parsed);
    if (projection === null) {
      return result('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
    }
    return await buildVerificationArtifactSet({
      commandPort,
      github: parsed.github,
      inventorySource: 'validated-repository-collector',
      revision: parsed.revision,
      sourceTreeDigest: projection.sourceTreeDigest,
    });
  } catch {
    return result('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
  }
}

function normalizeCliResult(candidate) {
  const envelope = exactTrusted(candidate, ['diagnostics', 'status', 'value']);
  if (envelope !== null && envelope.status === 'PASS' && exactFrozenArray(envelope.diagnostics, 0) !== null) {
    return { status: 'PASS', diagnostics: [] };
  }
  if (envelope !== null && envelope.value === null) {
    const diagnostics = exactFrozenArray(envelope.diagnostics, 1);
    const diagnostic = diagnostics === null ? null : exactTrusted(
      diagnostics[0],
      ['code', 'retryable', 'safeMessage'],
    );
    if (
      diagnostic !== null
      && Object.hasOwn(STATUS_BY_CODE, diagnostic.code)
      && STATUS_BY_CODE[diagnostic.code] === envelope.status
      && diagnostic.retryable === false
      && typeof diagnostic.safeMessage === 'string'
    ) {
      return {
        status: envelope.status,
        diagnostics: [{
          code: diagnostic.code,
          safeMessage: MESSAGES[diagnostic.code],
          retryable: false,
        }],
      };
    }
  }
  return {
    status: 'BLOCKED',
    diagnostics: [{
      code: 'ARTIFACT_SCHEMA_INVALID',
      safeMessage: MESSAGES.ARTIFACT_SCHEMA_INVALID,
      retryable: false,
    }],
  };
}

export function formatArtifactProducerCliResult(candidate) {
  const normalized = normalizeCliResult(candidate);
  return `${JSON.stringify({ status: normalized.status, diagnostics: normalized.diagnostics })}\n`;
}

export function artifactProducerExitCode(candidate) {
  const status = normalizeCliResult(candidate).status;
  return status === 'PASS' ? 0 : status === 'FAIL' ? 1 : 2;
}

async function main() {
  const produced = await runArtifactProducer({ argv: process.argv.slice(2) });
  process.stdout.write(formatArtifactProducerCliResult(produced));
  process.exitCode = artifactProducerExitCode(produced);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
