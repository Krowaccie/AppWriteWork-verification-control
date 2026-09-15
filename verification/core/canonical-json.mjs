import { createHash } from 'node:crypto';

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const FILE_MODES = new Set(['100644', '100755', '120000']);
const FILE_ENTRY_KEYS = ['contentDigest', 'mode', 'path'];

function ordinalCompare(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertPlainDataProperties(value, allowedArrayLength = false) {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === 'symbol') throw new TypeError('Canonical JSON does not permit symbol keys.');
    if (allowedArrayLength && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError('Canonical JSON accepts only enumerable data properties.');
    }
  }
}

function encodeCanonical(value, ancestors) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('Canonical JSON accepts only finite numbers.');
      return JSON.stringify(value);
    case 'undefined':
    case 'bigint':
    case 'function':
    case 'symbol':
      throw new TypeError('Value is outside the canonical JSON domain.');
    default:
      break;
  }

  if (ancestors.has(value)) throw new TypeError('Canonical JSON must be acyclic.');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      assertPlainDataProperties(value, true);
      const encoded = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new TypeError('Canonical JSON arrays must be dense.');
        encoded.push(encodeCanonical(value[index], ancestors));
      }
      for (const key of Object.keys(value)) {
        if (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) {
          throw new TypeError('Canonical JSON arrays cannot have named properties.');
        }
      }
      return `[${encoded.join(',')}]`;
    }

    if (!isPlainObject(value)) throw new TypeError('Canonical JSON accepts only plain objects.');
    assertPlainDataProperties(value);
    const keys = Object.keys(value).sort(ordinalCompare);
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${encodeCanonical(value[key], ancestors)}`)
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function assertExactPlainObject(value, expectedKeys, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain object.`);
  assertPlainDataProperties(value);
  const actualKeys = Object.keys(value).sort(ordinalCompare);
  const sortedExpected = [...expectedKeys].sort(ordinalCompare);
  if (
    actualKeys.length !== sortedExpected.length
    || actualKeys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new TypeError(`${label} has an invalid shape.`);
  }
}

function assertDigest(value, label) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

function assertRepositoryPath(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty repository-relative path.`);
  }
  if (
    value.includes('\\')
    || value.includes('\0')
    || /[\u0000-\u001f\u007f]/u.test(value)
    || value.startsWith('/')
    || /^[A-Za-z]:\//u.test(value)
  ) {
    throw new TypeError(`${label} must be a safe POSIX repository-relative path.`);
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new TypeError(`${label} must not contain empty or traversal segments.`);
  }
  return value;
}

function assertDenseArray(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array.`);
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) throw new TypeError(`${label} must be dense.`);
  }
  return value;
}

export function canonicalJson(value) {
  return encodeCanonical(value, new Set());
}

export function sha256Bytes(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes must be a Uint8Array.');
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return `sha256:${createHash('sha256').update(view).digest('hex')}`;
}

export function digestFileSet(entries, options = {}) {
  assertDenseArray(entries, 'entries');
  assertExactPlainObject(options, Object.hasOwn(options, 'excludePaths') ? ['excludePaths'] : [], 'options');

  const excludePaths = Object.hasOwn(options, 'excludePaths')
    ? assertDenseArray(options.excludePaths, 'excludePaths')
    : [];
  const exclusions = new Set();
  for (const excludePath of excludePaths) {
    const safePath = assertRepositoryPath(excludePath, 'excludePaths entry');
    if (exclusions.has(safePath)) throw new TypeError('excludePaths must not contain duplicates.');
    exclusions.add(safePath);
  }

  const normalized = [];
  const paths = new Set();
  for (const entry of entries) {
    assertExactPlainObject(entry, FILE_ENTRY_KEYS, 'FileDigestEntry');
    const safePath = assertRepositoryPath(entry.path, 'FileDigestEntry.path');
    if (paths.has(safePath)) throw new TypeError('FileDigestEntry paths must be unique.');
    paths.add(safePath);
    if (typeof entry.mode !== 'string' || !FILE_MODES.has(entry.mode)) {
      throw new TypeError('FileDigestEntry.mode is invalid.');
    }
    assertDigest(entry.contentDigest, 'FileDigestEntry.contentDigest');
    if (!exclusions.has(safePath)) {
      normalized.push({
        path: safePath,
        mode: entry.mode,
        contentDigest: entry.contentDigest,
      });
    }
  }

  normalized.sort((left, right) => ordinalCompare(left.path, right.path));
  return sha256Bytes(new TextEncoder().encode(canonicalJson(normalized)));
}
