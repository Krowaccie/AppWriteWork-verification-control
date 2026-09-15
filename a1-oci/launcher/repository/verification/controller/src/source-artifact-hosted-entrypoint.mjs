import { types as utilTypes } from 'node:util';

import { createTrustedSourceArtifactLauncher } from './source-artifact-launcher.mjs';
import { runTrustedSourceArtifactSession } from './source-artifact-launcher-orchestrator.mjs';
import { createHostedSourceArtifactCandidateRunner } from './source-artifact-hosted-candidate-runner.mjs';

const NativeArray = Array;
const ObjectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const isProxy = utilTypes.isProxy;

const ARGUMENT_KEYS = objectFreeze(['controllerConfiguration', 'platformCapabilities']);
const CONTROLLER_KEYS = objectFreeze([
  'artifactOutputRoot',
  'launcherTempRoot',
  'limits',
  'nodeExecutable',
  'npmExecutable',
  'producerArgv',
  'publishValidatedOutput',
  'repository',
  'sourceCheckoutRoot',
  'sourceRef',
  'sourceRevision',
  'sourceTreeDigest',
  'trustedInventoryBytes',
  'workflow',
  'workflowRunAttempt',
  'workflowRunId',
]);
const PARENT_CONFIGURATION_KEYS = objectFreeze([
  'artifactOutputRoot',
  'launcherTempRoot',
  'nodeExecutable',
  'npmExecutable',
  'repository',
  'sourceCheckoutRoot',
  'sourceRef',
  'sourceRevision',
  'sourceTreeDigest',
  'trustedInventoryBytes',
  'workflow',
  'workflowRunAttempt',
  'workflowRunId',
]);
const PLATFORM_KEYS = objectFreeze([
  'filesystem',
  'sandboxTransport',
  'sourceSnapshotHost',
  'validatedOutputSink',
  'workspaceHost',
]);
const PLATFORM_KEYS_WITH_PUBLICATION_AUTHORITY = objectFreeze([
  'filesystem',
  'publicationLeaseAuthority',
  'sandboxTransport',
  'sourceSnapshotHost',
  'validatedOutputSink',
  'workspaceHost',
]);
const MESSAGES = objectFreeze({
  ARTIFACT_BUILD_FAILED: 'Trusted artifact construction could not be completed.',
  ARTIFACT_SCHEMA_INVALID: 'Trusted artifact session data does not match the closed contract.',
});

function ordinalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortOrdinally(values) {
  return reflectApply(arraySort, values, [ordinalCompare]);
}

function hasOwn(value, key) {
  return reflectApply(objectHasOwn, undefined, [value, key]);
}

function dataDescriptor(value, {
  configurable = true,
  enumerable = true,
  writable = true,
} = {}) {
  return {
    configurable,
    enumerable,
    value,
    writable,
  };
}

function defineData(object, key, value, options) {
  objectDefineProperty(object, key, dataDescriptor(value, options));
}

function copyArray(values) {
  const copy = new NativeArray(values.length);
  for (let index = 0; index < values.length; index += 1) {
    defineData(copy, `${index}`, values[index]);
  }
  return copy;
}

function closedRecord(fields) {
  const record = objectCreate(null);
  const keys = reflectOwnKeys(fields);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = objectGetOwnPropertyDescriptor(fields, key);
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) {
      throw new TypeError('Hosted entrypoint records require own data properties.');
    }
    defineData(record, key, descriptor.value, {
      configurable: false,
      enumerable: true,
      writable: false,
    });
  }
  return objectFreeze(record);
}

function result(status, code) {
  return closedRecord({
    status,
    value: null,
    diagnostics: objectFreeze([closedRecord({
      code,
      safeMessage: MESSAGES[code],
      retryable: false,
    })]),
  });
}

const INVALID = result('BLOCKED', 'ARTIFACT_SCHEMA_INVALID');
const BUILD_FAILED = result('FAIL', 'ARTIFACT_BUILD_FAILED');

function exactFrozenOrdinary(value, expectedKeys) {
  try {
    if (
      isProxy(value)
      || value === null
      || typeof value !== 'object'
      || arrayIsArray(value)
      || objectGetPrototypeOf(value) !== ObjectPrototype
      || !objectIsFrozen(value)
    ) return null;
    const ownKeys = reflectOwnKeys(value);
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (typeof ownKeys[index] !== 'string') return null;
    }
    const actual = sortOrdinally(copyArray(ownKeys));
    const expected = sortOrdinally(copyArray(expectedKeys));
    if (actual.length !== expected.length) return null;
    for (let index = 0; index < actual.length; index += 1) {
      if (actual[index] !== expected[index]) return null;
    }
    const copy = objectCreate(null);
    for (let index = 0; index < expectedKeys.length; index += 1) {
      const key = expectedKeys[index];
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || descriptor.enumerable !== true
        || !hasOwn(descriptor, 'value')
      ) return null;
      defineData(copy, key, descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function exactCapability(value, methodNames) {
  const copy = exactFrozenOrdinary(value, methodNames);
  if (copy === null) return null;
  try {
    const capability = objectCreate(null);
    defineData(capability, 'receiver', value);
    for (let index = 0; index < methodNames.length; index += 1) {
      const name = methodNames[index];
      if (typeof copy[name] !== 'function' || isProxy(copy[name])) return null;
      defineData(capability, name, copy[name]);
    }
    return objectFreeze(capability);
  } catch {
    return null;
  }
}

function snapshotParentConfiguration(input) {
  const parentConfiguration = {};
  for (let index = 0; index < PARENT_CONFIGURATION_KEYS.length; index += 1) {
    const key = PARENT_CONFIGURATION_KEYS[index];
    defineData(parentConfiguration, key, input[key]);
  }
  return objectFreeze(parentConfiguration);
}

function snapshotPlatform(value) {
  let expectedKeys;
  try {
    expectedKeys = value !== null
      && typeof value === 'object'
      && !isProxy(value)
      && hasOwn(value, 'publicationLeaseAuthority')
      ? PLATFORM_KEYS_WITH_PUBLICATION_AUTHORITY
      : PLATFORM_KEYS;
  } catch {
    return null;
  }
  const input = exactFrozenOrdinary(value, expectedKeys);
  if (input === null) return null;
  const sourceSnapshotHost = exactCapability(input.sourceSnapshotHost, ['openSnapshot']);
  const workspaceHost = exactCapability(input.workspaceHost, ['openWorkspace']);
  const sandboxTransport = exactCapability(input.sandboxTransport, ['run']);
  const filesystem = exactCapability(input.filesystem, [
    'inspectTreeAtomically',
    'writeMemberAtomically',
  ]);
  const validatedOutputSink = input.validatedOutputSink === null
    ? null
    : exactCapability(input.validatedOutputSink, ['streamValidatedArtifact']);
  const capabilities = [
    sourceSnapshotHost,
    workspaceHost,
    sandboxTransport,
    filesystem,
    validatedOutputSink,
  ].filter((entry) => entry !== null);
  for (let index = 0; index < capabilities.length; index += 1) {
    for (let other = index + 1; other < capabilities.length; other += 1) {
      if (capabilities[index].receiver === capabilities[other].receiver) return null;
    }
  }
  if (
    sourceSnapshotHost === null
    || workspaceHost === null
    || sandboxTransport === null
    || filesystem === null
    || (input.validatedOutputSink !== null && validatedOutputSink === null)
  ) return null;
  const output = {
    sourceSnapshotHost: sourceSnapshotHost.receiver,
    workspaceHost: workspaceHost.receiver,
    sandboxTransport: sandboxTransport.receiver,
    filesystem: filesystem.receiver,
    validatedOutputSink: validatedOutputSink === null ? null : validatedOutputSink.receiver,
  };
  if (hasOwn(input, 'publicationLeaseAuthority')) {
    defineData(output, 'publicationLeaseAuthority', input.publicationLeaseAuthority);
  }
  return objectFreeze(output);
}

function snapshotEntrypointArguments(args) {
  const input = exactFrozenOrdinary(args, ARGUMENT_KEYS);
  if (input === null) return null;
  const controllerConfiguration = exactFrozenOrdinary(
    input.controllerConfiguration,
    CONTROLLER_KEYS,
  );
  const platformCapabilities = snapshotPlatform(input.platformCapabilities);
  if (
    controllerConfiguration === null
    || platformCapabilities === null
    || typeof controllerConfiguration.publishValidatedOutput !== 'boolean'
  ) return null;
  return objectFreeze({
    controllerConfiguration,
    platformCapabilities,
  });
}

function launcherArguments(controllerConfiguration, platformCapabilities) {
  const args = {
    parentConfiguration: snapshotParentConfiguration(controllerConfiguration),
    sourceSnapshotHost: platformCapabilities.sourceSnapshotHost,
    workspaceHost: platformCapabilities.workspaceHost,
    sandboxTransport: platformCapabilities.sandboxTransport,
    filesystem: platformCapabilities.filesystem,
    validatedOutputSink: platformCapabilities.validatedOutputSink,
    limits: controllerConfiguration.limits,
  };
  if (hasOwn(platformCapabilities, 'publicationLeaseAuthority')) {
    defineData(args, 'publicationLeaseAuthority', platformCapabilities.publicationLeaseAuthority);
  }
  return objectFreeze(args);
}

export async function runTrustedHostedSourceArtifact(args) {
  const input = snapshotEntrypointArguments(args);
  if (input === null) return INVALID;
  let runner;
  let launcher;
  try {
    runner = createHostedSourceArtifactCandidateRunner(objectFreeze({
      argv: input.controllerConfiguration.producerArgv,
    }));
    launcher = createTrustedSourceArtifactLauncher(launcherArguments(
      input.controllerConfiguration,
      input.platformCapabilities,
    ));
  } catch {
    return INVALID;
  }
  try {
    return await reflectApply(runTrustedSourceArtifactSession, undefined, [
      objectFreeze({
        launcher,
        runCandidate: runner.runCandidate,
        publishValidatedOutput: input.controllerConfiguration.publishValidatedOutput,
      }),
    ]);
  } catch {
    return BUILD_FAILED;
  }
}
