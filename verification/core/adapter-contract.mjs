const ADAPTER_KEYS = Object.freeze([
  'describeEnvironment',
  'environmentClass',
  'execute',
  'lane',
  'preflight',
]);

const ENVIRONMENT_BY_LANE = Object.freeze({
  local: 'local',
  'test-cloud': 'test',
  'production-readonly': 'production',
});

function contractError() {
  const error = new TypeError('Verification adapter contract is invalid');
  error.code = 'ADAPTER_CONTRACT_INVALID';
  return error;
}

function hasExactDataProperties(value) {
  const names = Object.getOwnPropertyNames(value).sort();
  if (
    names.length !== ADAPTER_KEYS.length
    || names.some((name, index) => name !== ADAPTER_KEYS[index])
    || Object.getOwnPropertySymbols(value).length !== 0
  ) {
    return false;
  }

  return names.every((name) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return descriptor !== undefined && Object.hasOwn(descriptor, 'value');
  });
}

function deepFreeze(value, seen = new WeakSet()) {
  if (
    value === null
    || (typeof value !== 'object' && typeof value !== 'function')
    || seen.has(value)
  ) {
    return value;
  }

  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

export function assertVerificationAdapter(adapter) {
  try {
    if (
      adapter === null
      || typeof adapter !== 'object'
      || Array.isArray(adapter)
      || !hasExactDataProperties(adapter)
    ) {
      throw contractError();
    }

    if (!Object.hasOwn(ENVIRONMENT_BY_LANE, adapter.lane)) {
      throw contractError();
    }
    const expectedEnvironment = ENVIRONMENT_BY_LANE[adapter.lane];
    if (
      expectedEnvironment === undefined
      || adapter.environmentClass !== expectedEnvironment
      || typeof adapter.preflight !== 'function'
      || typeof adapter.execute !== 'function'
      || typeof adapter.describeEnvironment !== 'function'
    ) {
      throw contractError();
    }

    return deepFreeze(adapter);
  } catch {
    throw contractError();
  }
}
