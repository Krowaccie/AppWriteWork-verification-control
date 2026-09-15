import { canonicalJson, sha256Bytes } from './canonical-json.mjs';

const FULL_GIT_SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const LOGICAL_TARGET_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const INPUT_KEYS = ['candidateIdentity', 'entries', 'verificationManifestDigest'];
const CANDIDATE_KEYS = ['candidateRevision', 'candidateSourceTreeDigest', 'kind'];
const ENTRY_KEYS = [
  'canonicalContentDigest',
  'kind',
  'logicalTarget',
  'relativePath',
  'sizeBytes',
  'sourcePath',
  'transportDigest',
];
const MANIFEST_KEYS = [
  'artifactManifestDigest',
  'artifacts',
  'schemaVersion',
  'sourceRevision',
  'sourceTreeDigest',
  'verifierManifestDigest',
];

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

function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key === 'symbol')) return false;
  for (const key of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  const actual = Object.keys(value).sort(ordinalCompare);
  const expected = [...keys].sort(ordinalCompare);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function assertExactKeys(value, keys, label) {
  if (!hasExactKeys(value, keys)) throw new TypeError(`${label} has an invalid shape.`);
}

function isDenseArray(value) {
  if (!Array.isArray(value)) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) return false;
  }
  return Object.keys(value).every((key) => /^(0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length);
}

function assertDenseArray(value, label) {
  if (!isDenseArray(value)) throw new TypeError(`${label} must be a dense array.`);
}

function isDigest(value) {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function assertDigest(value, label) {
  if (!isDigest(value)) throw new TypeError(`${label} must be a lowercase SHA-256 digest.`);
}

function isSafePath(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (
    value.includes('\\')
    || /[\u0000-\u001f\u007f]/u.test(value)
    || value.startsWith('/')
    || /^[A-Za-z]:\//u.test(value)
  ) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function isLogicalTarget(value) {
  return typeof value === 'string' && LOGICAL_TARGET_PATTERN.test(value);
}

function isSize(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function artifactKey(entry) {
  return `${entry.kind}\0${entry.logicalTarget}`;
}

function assertEntry(entry) {
  assertExactKeys(entry, ENTRY_KEYS, 'ArtifactManifest entry');
  if (entry.kind !== 'function' && entry.kind !== 'site') throw new TypeError('Artifact kind is invalid.');
  if (!isLogicalTarget(entry.logicalTarget)) throw new TypeError('Artifact logicalTarget is unsafe.');
  if (!isSafePath(entry.sourcePath)) throw new TypeError('Artifact sourcePath is unsafe.');
  if (!isSafePath(entry.relativePath)) throw new TypeError('Artifact relativePath is unsafe.');
  assertDigest(entry.canonicalContentDigest, 'canonicalContentDigest');
  assertDigest(entry.transportDigest, 'transportDigest');
  if (!isSize(entry.sizeBytes)) throw new TypeError('Artifact sizeBytes is invalid.');
}

function assertSortedUniqueEntries(entries) {
  assertDenseArray(entries, 'entries');
  let previous = null;
  for (const entry of entries) {
    assertEntry(entry);
    const key = artifactKey(entry);
    if (previous !== null && ordinalCompare(previous, key) >= 0) {
      throw new TypeError('Artifact entries must be ordinal-sorted and unique.');
    }
    previous = key;
  }
}

function copyEntry(entry) {
  return {
    kind: entry.kind,
    logicalTarget: entry.logicalTarget,
    sourcePath: entry.sourcePath,
    relativePath: entry.relativePath,
    canonicalContentDigest: entry.canonicalContentDigest,
    transportDigest: entry.transportDigest,
    sizeBytes: entry.sizeBytes,
  };
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function diagnostic(path, code = 'ARTIFACT_MANIFEST_SCHEMA_INVALID') {
  return {
    path,
    code,
    message: code === 'ARTIFACT_MANIFEST_DIGEST_MISMATCH'
      ? 'Artifact manifest digest does not match its canonical content.'
      : 'Artifact manifest does not match the closed v1 schema.',
  };
}

function createValidation(errors) {
  errors.sort((left, right) => ordinalCompare(
    `${left.path}\0${left.code}\0${left.message}`,
    `${right.path}\0${right.code}\0${right.message}`,
  ));
  for (const error of errors) Object.freeze(error);
  Object.freeze(errors);
  return Object.freeze({ ok: errors.length === 0, errors });
}

function canonicalManifestCore(value) {
  return {
    schemaVersion: value.schemaVersion,
    sourceRevision: value.sourceRevision,
    sourceTreeDigest: value.sourceTreeDigest,
    verifierManifestDigest: value.verifierManifestDigest,
    artifacts: value.artifacts.map(copyEntry),
  };
}

function digestCore(core) {
  return sha256Bytes(new TextEncoder().encode(canonicalJson(core)));
}

export function createArtifactManifest(input) {
  assertExactKeys(input, INPUT_KEYS, 'ArtifactManifestInput');
  assertExactKeys(input.candidateIdentity, CANDIDATE_KEYS, 'candidateIdentity');
  const candidate = input.candidateIdentity;
  if (candidate.kind !== 'git-revision') {
    throw new TypeError('Artifact production requires a git-revision identity.');
  }
  if (typeof candidate.candidateRevision !== 'string' || !FULL_GIT_SHA_PATTERN.test(candidate.candidateRevision)) {
    throw new TypeError('Artifact production requires a full lowercase Git SHA.');
  }
  assertDigest(candidate.candidateSourceTreeDigest, 'candidateSourceTreeDigest');
  assertDigest(input.verificationManifestDigest, 'verificationManifestDigest');
  assertSortedUniqueEntries(input.entries);

  const core = {
    schemaVersion: 1,
    sourceRevision: candidate.candidateRevision,
    sourceTreeDigest: candidate.candidateSourceTreeDigest,
    verifierManifestDigest: input.verificationManifestDigest,
    artifacts: input.entries.map(copyEntry),
  };
  return deepFreeze({
    ...core,
    artifactManifestDigest: digestCore(core),
  });
}

export function validateArtifactManifest(value) {
  try {
    const errors = [];
    if (!hasExactKeys(value, MANIFEST_KEYS)) {
      errors.push(diagnostic('/'));
      return createValidation(errors);
    }
    if (value.schemaVersion !== 1) errors.push(diagnostic('/schemaVersion'));
    if (typeof value.sourceRevision !== 'string' || !FULL_GIT_SHA_PATTERN.test(value.sourceRevision)) {
      errors.push(diagnostic('/sourceRevision'));
    }
    if (!isDigest(value.sourceTreeDigest)) errors.push(diagnostic('/sourceTreeDigest'));
    if (!isDigest(value.verifierManifestDigest)) errors.push(diagnostic('/verifierManifestDigest'));
    if (!isDigest(value.artifactManifestDigest)) errors.push(diagnostic('/artifactManifestDigest'));

    let entriesValid = isDenseArray(value.artifacts);
    if (!entriesValid) {
      errors.push(diagnostic('/artifacts'));
    } else {
      let previous = null;
      for (let index = 0; index < value.artifacts.length; index += 1) {
        const entry = value.artifacts[index];
        if (!hasExactKeys(entry, ENTRY_KEYS)) {
          errors.push(diagnostic(`/artifacts/${index}`));
          entriesValid = false;
          continue;
        }
        const entryValid = (entry.kind === 'function' || entry.kind === 'site')
          && isLogicalTarget(entry.logicalTarget)
          && isSafePath(entry.sourcePath)
          && isSafePath(entry.relativePath)
          && isDigest(entry.canonicalContentDigest)
          && isDigest(entry.transportDigest)
          && isSize(entry.sizeBytes);
        if (!entryValid) {
          errors.push(diagnostic(`/artifacts/${index}`));
          entriesValid = false;
          continue;
        }
        const key = artifactKey(entry);
        if (previous !== null && ordinalCompare(previous, key) >= 0) {
          errors.push(diagnostic(`/artifacts/${index}`));
          entriesValid = false;
        }
        previous = key;
      }
    }

    const coreFieldsValid = value.schemaVersion === 1
      && typeof value.sourceRevision === 'string'
      && FULL_GIT_SHA_PATTERN.test(value.sourceRevision)
      && isDigest(value.sourceTreeDigest)
      && isDigest(value.verifierManifestDigest)
      && entriesValid;
    if (coreFieldsValid && isDigest(value.artifactManifestDigest)) {
      const expected = digestCore(canonicalManifestCore(value));
      if (expected !== value.artifactManifestDigest) {
        errors.push(diagnostic('/artifactManifestDigest', 'ARTIFACT_MANIFEST_DIGEST_MISMATCH'));
      }
    }
    return createValidation(errors);
  } catch {
    return createValidation([diagnostic('/')]);
  }
}
