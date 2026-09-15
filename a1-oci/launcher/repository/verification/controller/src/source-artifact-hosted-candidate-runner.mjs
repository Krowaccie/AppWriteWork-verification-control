import { types as utilTypes } from 'node:util';

import { runArtifactProducer } from '../../../scripts/build-verification-artifacts.mjs';

const NativeArray = Array;
const ArrayPrototype = Array.prototype;
const ObjectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const arrayIsArray = Array.isArray;
const arraySort = Array.prototype.sort;
const numberIsSafeInteger = Number.isSafeInteger;
const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const isProxy = utilTypes.isProxy;

const ARGUMENT_KEYS = objectFreeze(['argv']);
const ERROR = 'Hosted source artifact candidate runner configuration is invalid.';

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

function snapshotArgv(argv) {
  try {
    if (
      isProxy(argv)
      || !arrayIsArray(argv)
      || objectGetPrototypeOf(argv) !== ArrayPrototype
      || !objectIsFrozen(argv)
    ) return null;
    const lengthDescriptor = objectGetOwnPropertyDescriptor(argv, 'length');
    const length = lengthDescriptor?.value;
    if (!numberIsSafeInteger(length) || length < 0) return null;
    const ownKeys = reflectOwnKeys(argv);
    const expected = new NativeArray(length + 1);
    for (let index = 0; index < length; index += 1) expected[index] = `${index}`;
    expected[length] = 'length';
    if (ownKeys.length !== expected.length) return null;
    for (let index = 0; index < ownKeys.length; index += 1) {
      if (ownKeys[index] !== expected[index]) return null;
    }
    const copy = new NativeArray(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = objectGetOwnPropertyDescriptor(argv, `${index}`);
      if (
        descriptor === undefined
        || descriptor.enumerable !== true
        || !hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'string'
      ) return null;
      defineData(copy, `${index}`, descriptor.value);
    }
    return objectFreeze(copy);
  } catch {
    return null;
  }
}

function failArguments() {
  throw new TypeError(ERROR);
}

export function createHostedSourceArtifactCandidateRunner(args) {
  const input = exactFrozenOrdinary(args, ARGUMENT_KEYS);
  const argv = input === null ? null : snapshotArgv(input.argv);
  if (argv === null) failArguments();
  function runCandidate(candidatePort) {
    return reflectApply(runArtifactProducer, undefined, [
      objectFreeze({
        argv,
        commandPort: candidatePort,
      }),
    ]);
  }
  return objectFreeze({ runCandidate });
}
