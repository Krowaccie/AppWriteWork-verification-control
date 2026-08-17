const RELEASE_KEY = 'APPWRITE_PRODUCTION_RELEASE_API_KEY';
const CREDENTIAL_NAME = /(?:TOKEN|SECRET|KEY|PRIVATE|CREDENTIAL|PASSWORD|COOKIE|AUTHORIZATION)/i;
const secrets = new WeakMap();

class ProductionReleaseCredentialHandle {
  apply(headers = {}) {
    const secret = secrets.get(this);
    if (typeof secret !== 'string') throw blocked('RELEASE_CREDENTIAL_HANDLE_INVALID');
    return { ...headers, 'X-Appwrite-Key': secret };
  }

  toJSON() {
    throw blocked('SERIALIZATION_FORBIDDEN');
  }

  [Symbol.for('nodejs.util.inspect.custom')]() {
    return '[ProductionReleaseCredentialHandle]';
  }
}

function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function ownEntries(env) {
  if (env === null || typeof env !== 'object' || Array.isArray(env)) {
    throw blocked('RELEASE_ENVIRONMENT_INVALID');
  }
  return Object.entries(env);
}

export function loadProductionReleaseEnvironment(env) {
  const entries = ownEntries(env);
  for (const [name, value] of entries) {
    if (name !== RELEASE_KEY && value !== undefined && value !== '' && CREDENTIAL_NAME.test(name)) {
      throw blocked('RELEASE_ENVIRONMENT_FORBIDDEN_CREDENTIAL');
    }
  }
  const secret = env[RELEASE_KEY];
  if (typeof secret !== 'string' || secret.length === 0 || secret.trim() !== secret) {
    throw blocked('RELEASE_CREDENTIAL_MISSING');
  }
  const handle = new ProductionReleaseCredentialHandle();
  secrets.set(handle, secret);
  return Object.freeze(handle);
}
