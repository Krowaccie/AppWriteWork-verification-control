import { types as utilTypes } from 'node:util';

import {
  captureSourceArtifactSourceLeaseClaimer,
} from './source-artifact-source-lease-authority.mjs';
import { bindPosixSourceArtifactKernelHost } from './source-artifact-posix-kernel-host.mjs';

const freeze = Object.freeze;
const isProxy = utilTypes.isProxy;

function exactData(value, keys) {
  try {
    if (
      value === null || typeof value !== 'object' || isProxy(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== keys.length
    ) return null;
    const copy = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !Object.hasOwn(descriptor, 'value')) return null;
      copy[key] = descriptor.value;
    }
    return copy;
  } catch {
    return null;
  }
}

function closedRecord(fields) {
  const value = Object.create(null);
  for (const [key, field] of Object.entries(fields)) value[key] = field;
  return freeze(value);
}

function result(status, value = null, code = null) {
  return closedRecord({
    status,
    value,
    diagnostics: code === null ? freeze([]) : freeze([closedRecord({
      code,
      retryable: false,
      safeMessage: code === 'ARTIFACT_CLEANUP_INCOMPLETE'
        ? 'Trusted artifact cleanup could not be completed.'
        : code === 'ARTIFACT_SCHEMA_INVALID'
          ? 'Trusted artifact session data does not match the closed contract.'
          : 'Trusted artifact construction could not be completed.',
    })]),
  });
}

const invalid = () => result('BLOCKED', null, 'ARTIFACT_SCHEMA_INVALID');
const failed = () => result('FAIL', null, 'ARTIFACT_BUILD_FAILED');
const cleanupIncomplete = () => result('BLOCKED', null, 'ARTIFACT_CLEANUP_INCOMPLETE');

function passValue(candidate) {
  try {
    if (
      candidate === null || typeof candidate !== 'object'
      || candidate.status !== 'PASS' || !Array.isArray(candidate.diagnostics)
      || candidate.diagnostics.length !== 0
    ) return null;
    return candidate.value;
  } catch {
    return null;
  }
}

function workspaceProjection(value) {
  const keys = ['childTemp', 'exportRoot', 'outputRoot', 'siteOutput'];
  const input = exactData(value, keys);
  if (input === null) return null;
  const projection = {};
  for (const key of keys) {
    if (
      typeof input[key] !== 'string' || !input[key].startsWith('/')
      || input[key].includes('\\') || input[key].includes('/../')
    ) return null;
    projection[key] = input[key];
  }
  return freeze(projection);
}

async function rollback(kernel, resources) {
  let complete = true;
  for (let index = resources.length - 1; index >= 0; index -= 1) {
    const resource = resources[index];
    try {
      const outcome = resource.kind === 'handle'
        ? await kernel.closeHandle(resource.token)
        : await kernel.removeRoot(resource.token);
      if (outcome?.status !== 'PASS' || outcome?.diagnostics?.length !== 0) complete = false;
    } catch {
      complete = false;
    }
  }
  return complete;
}

async function closeClaimedSourceLease(sourceLease) {
  try {
    const outcome = await Reflect.apply(sourceLease.close, sourceLease, []);
    return outcome?.status === 'PASS' && outcome?.diagnostics?.length === 0;
  } catch {
    return false;
  }
}

export function createPosixSourceArtifactWorkspaceHost(config) {
  const input = exactData(config, [
    'kernelHost', 'platform', 'sourceLeaseClaimer', 'workspace',
  ]);
  const projection = input?.platform === 'linux'
    ? workspaceProjection(input.workspace)
    : null;
  const kernel = bindPosixSourceArtifactKernelHost(input?.kernelHost);
  if (projection === null || kernel === null) {
    throw new TypeError('Authenticated POSIX workspace configuration is invalid.');
  }
  const claimer = captureSourceArtifactSourceLeaseClaimer(input.sourceLeaseClaimer);
  if (claimer === null) throw new TypeError('Authenticated POSIX workspace configuration is invalid.');

  async function openWorkspace(sourceLease) {
    const claimed = claimer.claimSourceLease(sourceLease);
    if (claimed === null) return invalid();

    const resources = [];
    let operationFailure = null;
    try {
      const sourceRootResult = await kernel.createRoot('source');
      const sourceRoot = passValue(sourceRootResult);
      if (sourceRoot === null) {
        operationFailure = sourceRootResult;
        throw new Error('source root');
      }
      resources.push({ kind: 'root', token: sourceRoot });

      const sourceHandleResult = await kernel.openRoot(sourceRoot);
      const sourceHandle = passValue(sourceHandleResult);
      if (sourceHandle === null) {
        operationFailure = sourceHandleResult;
        throw new Error('source handle');
      }
      resources.push({ kind: 'handle', token: sourceHandle });

      const outputRootResult = await kernel.createRoot('output');
      const outputRoot = passValue(outputRootResult);
      if (outputRoot === null) {
        operationFailure = outputRootResult;
        throw new Error('output root');
      }
      resources.push({ kind: 'root', token: outputRoot });

      const outputHandleResult = await kernel.openRoot(outputRoot);
      const outputHandle = passValue(outputHandleResult);
      if (outputHandle === null) {
        operationFailure = outputHandleResult;
        throw new Error('output handle');
      }
      resources.push({ kind: 'handle', token: outputHandle });

      const cacheResult = await kernel.createCache(outputHandle);
      if (cacheResult?.status !== 'PASS') {
        operationFailure = cacheResult;
        throw new Error('cache');
      }

      const exportResult = await Reflect.apply(claimed.exportSnapshot, claimed, [sourceHandle]);
      if (exportResult?.status !== 'PASS') {
        operationFailure = exportResult;
        throw new Error('export');
      }

      let closePromise = null;
      const workspaceLease = freeze({
        close() {
          if (closePromise !== null) return closePromise;
          closePromise = (async () => (
            await rollback(kernel, resources) ? result('PASS') : cleanupIncomplete()
          ))();
          return closePromise;
        },
        outputRootHandle: outputHandle,
        sourceRootHandle: sourceHandle,
        workspace: projection,
      });
      return result('PASS', workspaceLease);
    } catch {
      const workspaceClean = await rollback(kernel, resources);
      const sourceClean = await closeClaimedSourceLease(claimed);
      if (!workspaceClean || !sourceClean) return cleanupIncomplete();
      if (operationFailure?.status === 'BLOCKED' || operationFailure?.status === 'FAIL') {
        return operationFailure;
      }
      return failed();
    }
  }

  return freeze({ openWorkspace });
}
