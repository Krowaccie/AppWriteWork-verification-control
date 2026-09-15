import {
  extractSourceArtifactZip,
  readBoundedSourceArtifactArchive,
  readSourceArtifact,
} from './source-artifact-reader.mjs';
import { types as utilTypes } from 'node:util';

export {
  extractSourceArtifactZip,
  readBoundedSourceArtifactArchive,
};

const SNAPSHOT_INVALID = Symbol('snapshot-invalid');
const MAX_SNAPSHOT_DEPTH = 16;
const MAX_SNAPSHOT_VALUES = 2_048;
const MAX_SNAPSHOT_STRING_UNITS = 1_048_576;

function ownDataValue(value, key) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || utilTypes.isProxy(value)
    ) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && Object.hasOwn(descriptor, 'value')
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function snapshotJsonValue(value, state, depth = 0) {
  if (state.values < 1 || depth > MAX_SNAPSHOT_DEPTH) return SNAPSHOT_INVALID;
  state.values -= 1;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (value.length > state.stringUnits) return SNAPSHOT_INVALID;
    state.stringUnits -= value.length;
    return value;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : SNAPSHOT_INVALID;
  }
  if (typeof value !== 'object' || utilTypes.isProxy(value)) return SNAPSHOT_INVALID;
  try {
    if (Object.getOwnPropertySymbols(value).length !== 0) return SNAPSHOT_INVALID;
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return SNAPSHOT_INVALID;
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
      const length = lengthDescriptor?.value;
      const names = Object.getOwnPropertyNames(value);
      if (
        !Number.isSafeInteger(length)
        || length < 0
        || length > MAX_SNAPSHOT_VALUES
        || names.length !== length + 1
      ) return SNAPSHOT_INVALID;
      const output = [];
      for (let index = 0; index < length; index += 1) {
        const name = String(index);
        const descriptor = Object.getOwnPropertyDescriptor(value, name);
        if (
          descriptor === undefined
          || !Object.hasOwn(descriptor, 'value')
          || descriptor.enumerable !== true
        ) return SNAPSHOT_INVALID;
        const child = snapshotJsonValue(descriptor.value, state, depth + 1);
        if (child === SNAPSHOT_INVALID) return SNAPSHOT_INVALID;
        output.push(child);
      }
      return output;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) return SNAPSHOT_INVALID;
    const output = {};
    for (const name of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (
        descriptor === undefined
        || !Object.hasOwn(descriptor, 'value')
        || descriptor.enumerable !== true
      ) return SNAPSHOT_INVALID;
      const child = snapshotJsonValue(descriptor.value, state, depth + 1);
      if (child === SNAPSHOT_INVALID) return SNAPSHOT_INVALID;
      Object.defineProperty(output, name, {
        configurable: true,
        enumerable: true,
        value: child,
        writable: true,
      });
    }
    return output;
  } catch {
    return SNAPSHOT_INVALID;
  }
}

function deepFreezeSnapshot(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreezeSnapshot(child);
    Object.freeze(value);
  }
  return value;
}

function invalidTokenResponse(response) {
  const providerBody = ownDataValue(response, 'body');
  const providerToken = ownDataValue(providerBody, 'token');
  const providerStatus = ownDataValue(response, 'status');
  const body = { permissions: {} };
  if (typeof providerToken === 'string') body.token = providerToken;
  return deepFreezeSnapshot({
    status: Number.isSafeInteger(providerStatus) ? providerStatus : 201,
    body,
  });
}

function normalizedTestPermissions(value) {
  try {
    if (utilTypes.isProxy(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.getOwnPropertySymbols(value).length !== 0 ||
        JSON.stringify(Object.getOwnPropertyNames(value).sort()) !==
          JSON.stringify(['actions', 'metadata'])) {
      return {};
    }
    const actions = Object.getOwnPropertyDescriptor(value, 'actions');
    const metadata = Object.getOwnPropertyDescriptor(value, 'metadata');
    if (!actions || !metadata || !('value' in actions) || !('value' in metadata) ||
        actions.value !== 'read' || metadata.value !== 'read') {
      return {};
    }
    return { actions: 'read' };
  } catch {
    return {};
  }
}

function normalizedTokenResponse(response) {
  const snapshot = snapshotJsonValue(response, {
    stringUnits: MAX_SNAPSHOT_STRING_UNITS,
    values: MAX_SNAPSHOT_VALUES,
  });
  if (
    snapshot === SNAPSHOT_INVALID
    || snapshot === null
    || typeof snapshot !== 'object'
    || Array.isArray(snapshot)
    || snapshot.body === null
    || typeof snapshot.body !== 'object'
    || Array.isArray(snapshot.body)
  ) return invalidTokenResponse(response);
  snapshot.body.permissions = normalizedTestPermissions(snapshot.body.permissions);
  return deepFreezeSnapshot(snapshot);
}

export function readTestCloudSourceArtifact(args) {
  const configInput = args?.config;
  const config = Object.freeze({
    appId: configInput?.appId,
    installationId: configInput?.installationId,
    sourceRepositoryId: configInput?.sourceRepositoryId,
    sourceWorkflowId: configInput?.sourceWorkflowId,
  });
  const originalRequest = args?.request;
  const captured = Object.freeze({
    config,
    revision: args?.revision,
    qualifyingRunId: args?.qualifyingRunId,
    runAttempt: args?.runAttempt,
    privateKey: args?.privateKey,
    readZip: args?.readZip,
    nowSeconds: args?.nowSeconds,
  });
  const tokenPath = `/app/installations/${String(config.installationId)}/access_tokens`;
  const request = async (requestPath, options) => {
    const normalizeTokenResponse = requestPath === tokenPath && options.method === 'POST';
    const response = await originalRequest(requestPath, options);
    if (!normalizeTokenResponse) return response;
    return normalizedTokenResponse(response);
  };
  return readSourceArtifact({
    ...captured,
    request,
  });
}
