import { assertVerificationAdapter } from '../../core/adapter-contract.mjs';
import { isProxy } from 'node:util/types';
import { isTrustedControllerContext } from '../../core/controller-bundle.mjs';
import { canonicalJson, sha256Bytes } from '../../core/canonical-json.mjs';
import inventory from '../../fixtures/environments/test-cloud.inventory.v1.json' with { type: 'json' };

const DEPENDENCY_KEYS = Object.freeze([
  'transport',
  'describeEnvironment',
  'preflight',
  'execute',
].sort());
const CONTROLLER_RESULT_KEYS = Object.freeze(['diagnostics', 'status', 'value']);
const COMMON_STATUSES = Object.freeze(['PASS', 'FAIL', 'BLOCKED', 'INFRA_ERROR']);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const MANAGED_FACT_IDS = Object.freeze({
  'managed-project-provider-settings': 'test-cloud.managed-project-provider-settings.v1',
  'managed-function-site-domains': 'test-cloud.managed-function-site-domains.v1',
  'public-tls-dns': 'test-cloud.public-tls-dns.v1',
  'managed-scaling-regions-backups-cdn': 'test-cloud.managed-scaling-regions-backups-cdn.v1',
  'external-sandbox-behavior': 'test-cloud.external-sandbox-behavior.v1',
  'appwrite-cloud-self-host-policy-differences': 'test-cloud.appwrite-cloud-self-host-policy-differences.v1',
});
const ENVIRONMENT_KEYS = Object.freeze([
  'controllerBundleSha',
  'environmentClass',
  'lane',
]);

function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || seen.has(value)
  ) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

function freezePlainData(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || seen.has(value)
  ) return value;
  const prototype = Object.getPrototypeOf(value);
  if (
    prototype !== Object.prototype
    && prototype !== null
    && prototype !== Array.prototype
  ) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      freezePlainData(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

function result(status, value, code = null, retryable = false) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null
      ? []
      : [{ code, retryable }],
  });
}

function exactDataObject(value, expectedKeys) {
  if (
    isProxy(value)
    || value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Object.getOwnPropertySymbols(value).length !== 0
  ) return false;
  const keys = Object.getOwnPropertyNames(value).sort();
  if (
    keys.length !== expectedKeys.length
    || keys.some((key, index) => key !== expectedKeys[index])
  ) return false;
  return keys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && Object.hasOwn(descriptor, 'value');
  });
}

function dependencyError() {
  const error = new TypeError('Test-cloud adapter dependencies are invalid');
  error.code = 'ADAPTER_DEPENDENCIES_INVALID';
  return error;
}

function validateDependencies(dependencies) {
  if (
    !exactDataObject(dependencies, DEPENDENCY_KEYS)
    || dependencies.transport !== 'fake-provider'
    || typeof dependencies.describeEnvironment !== 'function'
    || typeof dependencies.preflight !== 'function'
    || typeof dependencies.execute !== 'function'
  ) throw dependencyError();
}

function retryableDiagnostic(diagnostics) {
  return diagnostics.some((diagnostic) => {
    if (diagnostic === null || typeof diagnostic !== 'object') return false;
    return Object.getOwnPropertyDescriptor(diagnostic, 'retryable')?.value === true;
  });
}

function infrastructureCode(diagnostics) {
  if (diagnostics.length !== 1) return 'INFRA_ERROR';
  const diagnostic = diagnostics[0];
  if (diagnostic === null || typeof diagnostic !== 'object') return 'INFRA_ERROR';
  const code = Object.getOwnPropertyDescriptor(diagnostic, 'code')?.value;
  return ['TIMEOUT', 'RETRY_EXHAUSTED'].includes(code) ? code : 'INFRA_ERROR';
}

function safeManagedFacts(value) {
  if (isProxy(value) || !Array.isArray(value) || value.length > 6
      || Reflect.ownKeys(value).length !== value.length + 1) return null;
  const facts = [];
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const fact = Object.getOwnPropertyDescriptor(value, String(index))?.value;
    if (!exactDataObject(fact, ['category', 'evidenceDigest', 'factId', 'publicOrigin', 'status'])
        || typeof fact.category !== 'string'
        || !Object.hasOwn(MANAGED_FACT_IDS, fact.category)
        || fact.factId !== MANAGED_FACT_IDS[fact.category]
        || !COMMON_STATUSES.includes(fact.status) || seen.has(fact.factId)
        || fact.publicOrigin !== inventory.environment.publicOrigin) return null;
    const record = { category: fact.category, factId: fact.factId,
      status: fact.status, publicOrigin: fact.publicOrigin };
    const evidenceDigest = sha256Bytes(new TextEncoder().encode(canonicalJson(record)));
    if (fact.evidenceDigest !== evidenceDigest) return null;
    seen.add(fact.factId);
    facts.push({ ...record, evidenceDigest });
  }
  return facts;
}

function safeEvidenceValue(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Object.getOwnPropertySymbols(value).length !== 0
  ) return null;
  const evidenceDigest = Object.getOwnPropertyDescriptor(value, 'evidenceDigest')?.value;
  if (typeof evidenceDigest !== 'string' || !DIGEST.test(evidenceDigest)) return null;
  const descriptor = Object.getOwnPropertyDescriptor(value, 'managedCloudFacts');
  if (descriptor === undefined) return { evidenceDigest };
  if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) return null;
  const managedCloudFacts = safeManagedFacts(descriptor.value);
  return managedCloudFacts === null ? null : { evidenceDigest, managedCloudFacts };
}

function normalizeDependencyResult(value, { requireEvidence = false } = {}) {
  if (
    !exactDataObject(value, CONTROLLER_RESULT_KEYS)
    || !COMMON_STATUSES.includes(value.status)
    || !Array.isArray(value.diagnostics)
  ) return result('BLOCKED', null, 'PREREQUISITE_UNAVAILABLE');

  if (value.status === 'PASS') {
    if (value.diagnostics.length !== 0) {
      return result('BLOCKED', null, 'PREREQUISITE_UNAVAILABLE');
    }
    if (!requireEvidence) return result('PASS', null);
    const evidence = safeEvidenceValue(value.value);
    return evidence === null
      ? result('BLOCKED', null, 'PREREQUISITE_UNAVAILABLE')
      : result('PASS', evidence);
  }
  if (value.value !== null || value.diagnostics.length === 0) {
    return result('BLOCKED', null, 'PREREQUISITE_UNAVAILABLE');
  }
  const retryable = retryableDiagnostic(value.diagnostics);
  if (value.status === 'FAIL') return result('FAIL', null, 'CHECK_FAILED', retryable);
  if (value.status === 'BLOCKED') {
    return result('BLOCKED', null, 'PREREQUISITE_UNAVAILABLE', retryable);
  }
  return result('INFRA_ERROR', null, infrastructureCode(value.diagnostics), retryable);
}

export function createTestCloudAdapter({ controller, dependencies } = {}) {
  if (!isTrustedControllerContext(controller)) {
    return result('BLOCKED', null, 'PREREQUISITE_UNAVAILABLE');
  }
  validateDependencies(dependencies);
  const closedDependencies = deepFreeze({
    transport: dependencies.transport,
    describeEnvironment: dependencies.describeEnvironment,
    preflight: dependencies.preflight,
    execute: dependencies.execute,
  });

  const adapter = {
    lane: 'test-cloud',
    environmentClass: 'test',
    async preflight(input) {
      try {
        return normalizeDependencyResult(
          await closedDependencies.preflight(freezePlainData({ controller, input })),
        );
      } catch {
        return result('INFRA_ERROR', null, 'INFRA_ERROR');
      }
    },
    async execute(input) {
      try {
        return normalizeDependencyResult(
          await closedDependencies.execute(freezePlainData({ controller, input })),
          { requireEvidence: true },
        );
      } catch {
        return result('INFRA_ERROR', null, 'INFRA_ERROR');
      }
    },
    describeEnvironment() {
      const closed = {
        lane: 'test-cloud',
        environmentClass: 'test',
        controllerBundleSha: controller.controllerBundleSha,
      };
      try {
        const described = closedDependencies.describeEnvironment(Object.freeze({ controller }));
        if (
          exactDataObject(described, ENVIRONMENT_KEYS)
          && described.lane === closed.lane
          && described.environmentClass === closed.environmentClass
          && described.controllerBundleSha === closed.controllerBundleSha
        ) return deepFreeze({ ...described });
      } catch {
        // The immutable controller metadata below remains the only safe description.
      }
      return deepFreeze(closed);
    },
  };
  return result('PASS', assertVerificationAdapter(adapter));
}
