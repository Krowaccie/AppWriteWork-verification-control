const FIXED_ENDPOINT = 'https://api.salmora.net/v1';
const FIXED_PROJECT_ID = '69eb4818000afa64a7fa';
const SAFE_ID = /^[A-Za-z0-9._-]+$/;

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function exactTargetKey(target) {
  return `${target?.kind ?? ''}:${target?.logicalTarget ?? ''}`;
}

function targetId(target) {
  const value = target?.id ?? target?.siteId ?? target?.functionId ?? target?.providerId;
  if (typeof value !== 'string' || !SAFE_ID.test(value)) {
    throw blocked('PRODUCTION_RELEASE_TARGET_INVALID');
  }
  return value;
}

function deploymentId(value) {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) {
    throw blocked('PRODUCTION_RELEASE_DEPLOYMENT_ID_INVALID');
  }
  return value;
}

async function readJson(response) {
  if (!response || typeof response.status !== 'number') {
    throw blocked('APPWRITE_RELEASE_RESPONSE_INVALID');
  }
  if (!response.ok) throw blocked(`APPWRITE_RELEASE_HTTP_${response.status}`);
  let body;
  try {
    body = await response.json();
  } catch {
    throw blocked('APPWRITE_RELEASE_RESPONSE_INVALID');
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw blocked('APPWRITE_RELEASE_RESPONSE_INVALID');
  }
  return body;
}

export function createProductionReleaseAppwriteClient({
  endpoint,
  projectId,
  credentialHandle,
  targets,
  fetchImpl,
}) {
  if (endpoint !== FIXED_ENDPOINT || projectId !== FIXED_PROJECT_ID) {
    throw blocked('PRODUCTION_RELEASE_IDENTITY_MISMATCH');
  }
  if (!credentialHandle || typeof credentialHandle.apply !== 'function') {
    throw blocked('RELEASE_CREDENTIAL_HANDLE_INVALID');
  }
  if (!Array.isArray(targets) || typeof fetchImpl !== 'function') {
    throw blocked('PRODUCTION_RELEASE_CLIENT_INPUT_INVALID');
  }

  const allowlist = new Map();
  for (const target of targets) {
    if (!target || !['site', 'function'].includes(target.kind) ||
        typeof target.logicalTarget !== 'string' || target.logicalTarget.length === 0) {
      throw blocked('PRODUCTION_RELEASE_TARGET_INVALID');
    }
    const key = exactTargetKey(target);
    if (allowlist.has(key)) throw blocked('PRODUCTION_RELEASE_TARGET_DUPLICATE');
    allowlist.set(key, Object.freeze({
      kind: target.kind,
      logicalTarget: target.logicalTarget,
      id: targetId(target),
    }));
  }

  function allowed(target, kind) {
    if (!target || target.kind !== kind) throw blocked('PRODUCTION_RELEASE_TARGET_NOT_ALLOWED');
    const selected = allowlist.get(exactTargetKey(target));
    if (!selected || targetId(target) !== selected.id) {
      throw blocked('PRODUCTION_RELEASE_TARGET_NOT_ALLOWED');
    }
    return selected;
  }

  function headers(extra = {}) {
    return credentialHandle.apply({
      Accept: 'application/json',
      'X-Appwrite-Project': FIXED_PROJECT_ID,
      ...extra,
    });
  }

  async function request(path, init) {
    const response = await fetchImpl(`${FIXED_ENDPOINT}${path}`, init);
    return readJson(response);
  }

  async function upload(kind, target, artifactBytes) {
    const selected = allowed(target, kind);
    if (!(artifactBytes instanceof Uint8Array) || artifactBytes.byteLength === 0) {
      throw blocked('PRODUCTION_RELEASE_ARTIFACT_INVALID');
    }
    const body = new FormData();
    body.append('code', new Blob([artifactBytes], { type: 'application/octet-stream' }), 'code.tar.gz');
    body.append('activate', 'false');
    const plural = kind === 'site' ? 'sites' : 'functions';
    return request(`/${plural}/${selected.id}/deployments`, {
      method: 'POST',
      headers: headers(),
      body,
      redirect: 'error',
    });
  }

  async function readDeployment(kind, target, id) {
    const selected = allowed(target, kind);
    const plural = kind === 'site' ? 'sites' : 'functions';
    return request(`/${plural}/${selected.id}/deployments/${deploymentId(id)}`, {
      method: 'GET',
      headers: headers(),
      redirect: 'error',
    });
  }

  async function activate(kind, target, id) {
    const selected = allowed(target, kind);
    const plural = kind === 'site' ? 'sites' : 'functions';
    return request(`/${plural}/${selected.id}/deployment`, {
      method: 'PATCH',
      headers: headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ deploymentId: deploymentId(id) }),
      redirect: 'error',
    });
  }

  async function readMetadata(kind, target) {
    const selected = allowed(target, kind);
    const plural = kind === 'site' ? 'sites' : 'functions';
    return request(`/${plural}/${selected.id}`, {
      method: 'GET',
      headers: headers(),
      redirect: 'error',
    });
  }

  return Object.freeze({
    uploadSiteDeployment: (target, bytes) => upload('site', target, bytes),
    readSiteDeployment: (target, id) => readDeployment('site', target, id),
    activateSiteDeployment: (target, id) => activate('site', target, id),
    readSiteMetadata: (target) => readMetadata('site', target),
    uploadFunctionDeployment: (target, bytes) => upload('function', target, bytes),
    readFunctionDeployment: (target, id) => readDeployment('function', target, id),
    activateFunctionDeployment: (target, id) => activate('function', target, id),
    readFunctionMetadata: (target) => readMetadata('function', target),
  });
}
