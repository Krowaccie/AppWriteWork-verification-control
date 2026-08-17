import { createA1SupervisorSession } from './a1-supervisor-client.mjs';

const PROCESS_PROTOCOL = 'source-artifact-posix-supervisor.v1';
const PROBE_PROTOCOL = 'source-artifact-posix-network-probe.v1';
const PROBE_ROOT = '/opt/appwritework/verification-a1/probe';
const PROBE_PATHS = Object.freeze([
  '/usr/local/bin/node',
  '/usr/local/bin/npm',
  '/usr/bin/git',
  PROBE_ROOT,
  '/work/probe/command-temp',
  '/work/probe/config-home',
  '/work/probe/npm-cache',
  '/work/probe/site-output',
]);

function closed(fields) {
  return Object.freeze(Object.assign(Object.create(null), fields));
}

function policy(value) {
  if (
    value !== null
    && typeof value === 'object'
    && Object.isFrozen(value)
    && Reflect.ownKeys(value).length === 1
    && value.mode === 'deny'
  ) return closed({ mode: 'deny' });
  if (
    value !== null
    && typeof value === 'object'
    && Object.isFrozen(value)
    && Reflect.ownKeys(value).length === 4
    && value.host === 'registry.npmjs.org'
    && value.mode === 'registry-only'
    && value.port === 443
    && value.protocol === 'tls'
  ) return closed({
    host: 'registry.npmjs.org', mode: 'registry-only', port: 443, protocol: 'tls',
  });
  return null;
}

function evidence(enforced, value) {
  return closed({ enforced, policy: value, protocolVersion: PROBE_PROTOCOL });
}

export function createA1NetworkPolicyProbe({ spawnProcess } = {}) {
  if (spawnProcess !== undefined && typeof spawnProcess !== 'function') {
    throw new TypeError('A1 network policy probe configuration is invalid.');
  }
  const cache = new Map();

  async function execute(value) {
    const profile = value.mode === 'deny' ? 'bundle-catalog' : 'root-npm-ci';
    const session = createA1SupervisorSession({
      args: [PROCESS_PROTOCOL, profile, ...PROBE_PATHS],
      maxResponseBytes: 16 * 1024 * 1024,
      mode: 1,
      ...(spawnProcess === undefined ? {} : { spawnProcess }),
    });
    try {
      const response = await session.request(Buffer.alloc(0));
      session.closeInput();
      const close = await session.waitForClose();
      const accepted = response.status === 0
        && response.start.length === 8
        && response.start.readInt32BE(0) === 0
        && response.start.subarray(4).every((byte) => byte === 0 || byte === 1)
        && response.start[5] === 0
        && response.start[7] === 1
        && close.code === 0
        && close.signal === null;
      return evidence(accepted, value);
    } catch {
      try { await session.terminate(); } catch { /* Failed closed below. */ }
      return evidence(false, value);
    }
  }

  async function run(request) {
    if (
      request === null
      || typeof request !== 'object'
      || !Object.isFrozen(request)
      || Reflect.ownKeys(request).length !== 2
      || request.protocolVersion !== PROBE_PROTOCOL
    ) return evidence(false, closed({ mode: 'deny' }));
    const selected = policy(request.policy);
    if (selected === null) return evidence(false, closed({ mode: 'deny' }));
    if (!cache.has(selected.mode)) cache.set(selected.mode, execute(selected));
    return cache.get(selected.mode);
  }

  return Object.freeze({ run });
}
