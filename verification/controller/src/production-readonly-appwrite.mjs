import { executeClosedAppwriteRead } from './production-readonly-environment.mjs';

const DEPLOYMENT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const EXACT_ENDPOINT = 'https://api.salmora.net/v1';

function blocked() {
  const error = new Error('Production read-only request blocked.');
  error.code = 'PRODUCTION_READONLY_REQUEST_BLOCKED';
  return error;
}

function authenticTarget(target, kind) {
  try {
    return (
      typeof target === 'function'
      && Object.isFrozen(target)
      && target.kind === kind
      && typeof target.logicalId === 'string'
      && typeof target.providerId === 'string'
      && Object.getOwnPropertySymbols(target).length === 0
    );
  } catch {
    return false;
  }
}

function safeSegment(value) {
  return (
    typeof value === 'string'
    && /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value)
    && !/%2f|%5c/i.test(value)
  );
}

async function read(target, operation, deploymentId, path) {
  const expectedUrl = new URL(path, EXACT_ENDPOINT).href;
  let response;
  try {
    response = await executeClosedAppwriteRead(target, operation, deploymentId);
  } catch {
    throw blocked();
  }
  if (
    response === null
    || typeof response !== 'object'
    || response.ok !== true
    || response.status !== 200
    || response.redirected === true
    || response.url !== expectedUrl
  ) {
    throw blocked();
  }
  let value;
  try {
    value = await response.json();
  } catch {
    throw blocked();
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw blocked();
  return value;
}

function metadataProjection(value) {
  return Object.freeze({
    $id: typeof value.$id === 'string' ? value.$id : null,
    deploymentId: typeof value.deploymentId === 'string' ? value.deploymentId : null,
  });
}

function deploymentProjection(value, active) {
  return Object.freeze({
    $id: typeof value.$id === 'string' ? value.$id : null,
    active,
    status: typeof value.status === 'string' ? value.status : null,
  });
}

export async function getSiteMetadata(target) {
  if (!authenticTarget(target, 'site') || !safeSegment(target.providerId)) throw blocked();
  const path = `/v1/sites/${target.providerId}`;
  return metadataProjection(await read(target, 'site-metadata', undefined, path));
}

export async function getSiteDeployment(target, deploymentId) {
  if (!authenticTarget(target, 'site') || !safeSegment(target.providerId) || !DEPLOYMENT_ID.test(deploymentId)) {
    throw blocked();
  }
  const path = `/v1/sites/${target.providerId}/deployments/${deploymentId}`;
  const parent = await getSiteMetadata(target);
  const deployment = await read(target, 'site-deployment', deploymentId, path);
  return deploymentProjection(
    deployment,
    parent.deploymentId === deploymentId
      && deployment.$id === deploymentId && deployment.status === 'ready',
  );
}

export async function getFunctionMetadata(target) {
  if (!authenticTarget(target, 'function') || !safeSegment(target.providerId)) throw blocked();
  const path = `/v1/functions/${target.providerId}`;
  return metadataProjection(await read(target, 'function-metadata', undefined, path));
}

export async function getFunctionDeployment(target, deploymentId) {
  if (!authenticTarget(target, 'function') || !safeSegment(target.providerId) || !DEPLOYMENT_ID.test(deploymentId)) {
    throw blocked();
  }
  const path = `/v1/functions/${target.providerId}/deployments/${deploymentId}`;
  const parent = await getFunctionMetadata(target);
  const deployment = await read(target, 'function-deployment', deploymentId, path);
  return deploymentProjection(
    deployment,
    parent.deploymentId === deploymentId
      && deployment.$id === deploymentId && deployment.status === 'ready',
  );
}
