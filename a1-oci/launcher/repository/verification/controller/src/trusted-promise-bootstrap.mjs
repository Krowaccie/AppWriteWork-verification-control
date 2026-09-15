import { types as utilTypes } from 'node:util';

const GlobalObject = globalThis;
const ObjectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const arrayEvery = Array.prototype.every;
const functionToString = Function.prototype.toString;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const reflectOwnKeys = Reflect.ownKeys;
const isPromise = utilTypes.isPromise;
const isProxy = utilTypes.isProxy;

function hasOwn(value, key) {
  return reflectApply(objectHasOwn, undefined, [value, key]);
}

const INVALID_DESCRIPTOR_FIELD = objectFreeze(objectCreate(null));

function ownDataField(record, key) {
  if (record === undefined || record === null || isProxy(record)) {
    return INVALID_DESCRIPTOR_FIELD;
  }
  const fieldDescriptor = objectGetOwnPropertyDescriptor(record, key);
  if (fieldDescriptor === undefined || !hasOwn(fieldDescriptor, 'value')) {
    return INVALID_DESCRIPTOR_FIELD;
  }
  return fieldDescriptor.value;
}

function dataDescriptor(value, writable, configurable, enumerable = false) {
  const descriptor = objectCreate(null);
  descriptor.configurable = configurable;
  descriptor.enumerable = enumerable;
  descriptor.value = value;
  descriptor.writable = writable;
  return objectFreeze(descriptor);
}

function exactDataDescriptor(
  descriptor,
  value,
  writable,
  configurable,
  enumerable = false,
) {
  return descriptor !== undefined
    && ownDataField(descriptor, 'value') === value
    && ownDataField(descriptor, 'enumerable') === enumerable
    && ownDataField(descriptor, 'writable') === writable
    && ownDataField(descriptor, 'configurable') === configurable
    && objectGetOwnPropertyDescriptor(descriptor, 'get') === undefined
    && objectGetOwnPropertyDescriptor(descriptor, 'set') === undefined;
}

function exactStandardOrHardenedDescriptor(descriptor, value) {
  return exactDataDescriptor(descriptor, value, true, true)
    || exactDataDescriptor(descriptor, value, false, false);
}

function exactNativePromiseConstructor(value, prototype) {
  try {
    return typeof value === 'function'
      && !isProxy(value)
      && reflectApply(functionToString, value, [])
        === 'function Promise() { [native code] }'
      && exactDataDescriptor(
        objectGetOwnPropertyDescriptor(value, 'prototype'),
        prototype,
        false,
        false,
      );
  } catch {
    return false;
  }
}

async function createIntrinsicPromiseProbe() {
  return null;
}

const intrinsicPromiseProbe = createIntrinsicPromiseProbe();
let NativePromise = null;
let NativePromisePrototype = null;
let bootstrapReady = false;

try {
  const intrinsicPrototype = objectGetPrototypeOf(intrinsicPromiseProbe);
  const constructorDescriptor = objectGetOwnPropertyDescriptor(
    intrinsicPrototype,
    'constructor',
  );
  const constructor = ownDataField(constructorDescriptor, 'value');
  const globalDescriptor = objectGetOwnPropertyDescriptor(
    GlobalObject,
    'Promise',
  );
  if (
    isPromise(intrinsicPromiseProbe)
    && !isProxy(intrinsicPromiseProbe)
    && !isProxy(intrinsicPrototype)
    && exactNativePromiseConstructor(constructor, intrinsicPrototype)
    && exactStandardOrHardenedDescriptor(constructorDescriptor, constructor)
    && exactStandardOrHardenedDescriptor(globalDescriptor, constructor)
  ) {
    NativePromise = constructor;
    NativePromisePrototype = intrinsicPrototype;
    if (exactDataDescriptor(constructorDescriptor, constructor, false, false)) {
      bootstrapReady = true;
    } else {
      objectDefineProperty(
        NativePromisePrototype,
        'constructor',
        dataDescriptor(NativePromise, false, false),
      );
      bootstrapReady = exactDataDescriptor(
        objectGetOwnPropertyDescriptor(
          NativePromisePrototype,
          'constructor',
        ),
        NativePromise,
        false,
        false,
      );
    }
  }
} catch {
  bootstrapReady = false;
}

function observation(fulfilled, value) {
  const record = objectCreate(null);
  objectDefineProperty(record, 'fulfilled', dataDescriptor(fulfilled, false, false, true));
  objectDefineProperty(record, 'value', dataDescriptor(value, false, false, true));
  return objectFreeze(record);
}

const UNOBSERVED = observation(false, null);

function isExactFrozenNullRecord(value) {
  if (reflectApply(objectIsFrozen, undefined, [value]) !== true) return false;
  const ownKeys = reflectOwnKeys(value);
  for (let index = 0; index < ownKeys.length; index += 1) {
    const key = ownKeys[index];
    if (typeof key !== 'string' || key === 'then') return false;
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    const fieldValue = ownDataField(descriptor, 'value');
    if (
      fieldValue === INVALID_DESCRIPTOR_FIELD
      || !exactDataDescriptor(descriptor, fieldValue, false, false, true)
    ) return false;
  }
  return true;
}

function isClosedSynchronousData(value) {
  try {
    if (value === null || typeof value !== 'object' || isProxy(value)) return false;
    const prototype = objectGetPrototypeOf(value);
    if (prototype === null) return isExactFrozenNullRecord(value);
    if (
      prototype !== ObjectPrototype
      || objectGetOwnPropertyDescriptor(ObjectPrototype, 'then') !== undefined
      || objectGetOwnPropertyDescriptor(value, 'then') !== undefined
    ) return false;
    const ownKeys = reflectOwnKeys(value);
    return reflectApply(arrayEvery, ownKeys, [
      (key) => typeof key === 'string',
    ]);
  } catch {
    return false;
  }
}

function isAwaitSafeBrandedPromise(value) {
  try {
    if (
      !isPromise(value)
      || isProxy(value)
      || objectGetPrototypeOf(value) !== NativePromisePrototype
      || objectGetOwnPropertyDescriptor(value, 'then') !== undefined
    ) return false;
    const ownConstructor = objectGetOwnPropertyDescriptor(value, 'constructor');
    return ownConstructor === undefined || exactDataDescriptor(
      ownConstructor,
      NativePromise,
      false,
      false,
    );
  } catch {
    return false;
  }
}

async function observeReadyOperation(value) {
  if (isAwaitSafeBrandedPromise(value)) {
    try {
      return observation(true, await value);
    } catch {
      return UNOBSERVED;
    }
  }
  return isClosedSynchronousData(value)
    ? observation(true, value)
    : UNOBSERVED;
}

export function isTrustedPromiseBootstrapReady() {
  return bootstrapReady;
}

export function observeTrustedOperation(value) {
  return bootstrapReady ? observeReadyOperation(value) : UNOBSERVED;
}
