import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

const FULL_SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ARTIFACT_ID = /^[1-9][0-9]*$/u;
const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u;
const WINDOWS_RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu;
const SOURCE_REPOSITORY = 'Krowaccie/AppWriteWork';
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const TRUST_KINDS = Object.freeze([
  'evaluator', 'evidenceValidator', 'networkPolicy', 'transcriptCorpus',
]);
const MANIFEST_KEYS = Object.freeze([
  'schemaVersion', 'sourceRepository', 'sourceRepositoryRevision',
  'controllerRepository', 'controllerRevision', 'entrypoints', 'files',
  'schemaDigests', 'trustMaterials', 'provenance',
].sort());
const PROPOSAL_KEYS = Object.freeze([
  ...MANIFEST_KEYS, 'proposalStatus', 'seedSourceSets',
].sort());
const RECORD_KEYS = Object.freeze(['path', 'sha256']);
const TRUST_RECORD_KEYS = Object.freeze(['kind', 'path', 'sha256']);
const SEED_SOURCE_SET_REFERENCE_KEYS = Object.freeze(['path', 'schemaPath', 'schemaVersion']);
const MATERIALIZER_KEYS = Object.freeze([
  'committedFiles', 'controllerRevision', 'proposal', 'provenance',
  'sourceRepositoryRevision', 'trustMaterials',
].sort());
const COMMITTED_FILE_KEYS = Object.freeze(['bytes', 'path']);
const TRUST_INPUT_KEYS = Object.freeze([
  'evaluator', 'evidenceValidator', 'networkPolicy', 'transcriptCorpus',
]);
const FACTORY_KEYS = Object.freeze([
  'manifest', 'controllerArtifactId', 'controllerBundleDigest',
].sort());
const CONTEXT_KEYS = Object.freeze([
  'environment', 'controllerRepository', 'controllerBundleSha',
  'sourceRepositoryRevision', 'controllerArtifactId', 'controllerBundleDigest',
].sort());
const trustedControllerBrand = Symbol('trusted-controller-context');
const AUTHENTIC_CONTEXTS = new WeakSet();

function exactDataObject(value, expectedKeys) {
  try {
    if (
      utilTypes.isProxy(value)
      || value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return false;
    const keys = Object.getOwnPropertyNames(value).sort();
    if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) return false;
    return keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
  } catch {
    return false;
  }
}

function denseValues(value) {
  try {
    if (
      utilTypes.isProxy(value)
      || !Array.isArray(value)
      || Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return null;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || !names.includes('length')) return null;
    const output = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return null;
      output.push(descriptor.value);
    }
    return output;
  } catch {
    return null;
  }
}

function safePath(value) {
  return typeof value === 'string'
    && SAFE_PATH.test(value)
    && value.split('/').every((segment) => (
      !segment.endsWith('.')
      && !segment.endsWith(' ')
      && !WINDOWS_RESERVED.test(segment)
    ));
}

function pathIdentity(value) {
  return value.toLowerCase();
}

function collisionFree(paths) {
  const identities = paths.map(pathIdentity);
  if (new Set(identities).size !== identities.length) return false;
  for (let left = 0; left < identities.length; left += 1) {
    for (let right = left + 1; right < identities.length; right += 1) {
      if (
        identities[left].startsWith(`${identities[right]}/`)
        || identities[right].startsWith(`${identities[left]}/`)
      ) return false;
    }
  }
  return true;
}

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function validRecord(record, sentinel = false) {
  return exactDataObject(record, RECORD_KEYS)
    && safePath(record.path)
    && (sentinel ? record.sha256 === 'UNMATERIALIZED' : DIGEST.test(record.sha256));
}

function validRecords(value, sentinel = false) {
  const records = denseValues(value);
  if (records === null || records.length === 0 || records.some((record) => !validRecord(record, sentinel))) return null;
  const paths = records.map(({ path }) => path);
  if (!collisionFree(paths) || paths.some((item, index) => index > 0 && ordinal(paths[index - 1], item) >= 0)) return null;
  return records;
}

function validTrustRecords(value, sentinel = false) {
  const records = denseValues(value);
  if (records === null || records.length !== TRUST_KINDS.length) return null;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (
      !exactDataObject(record, TRUST_RECORD_KEYS)
      || record.kind !== TRUST_KINDS[index]
      || !safePath(record.path)
      || (sentinel ? record.sha256 !== 'UNMATERIALIZED' : !DIGEST.test(record.sha256))
    ) return null;
  }
  return collisionFree(records.map(({ path }) => path)) ? records : null;
}

function validRevisionPair(sourceRepositoryRevision, controllerRevision, sentinel = false) {
  if (sentinel) {
    return sourceRepositoryRevision === 'UNMATERIALIZED' && controllerRevision === 'UNMATERIALIZED';
  }
  return FULL_SHA.test(sourceRepositoryRevision)
    && FULL_SHA.test(controllerRevision)
    && sourceRepositoryRevision !== controllerRevision;
}

function validSeedSourceSetReference(value) {
  return exactDataObject(value, SEED_SOURCE_SET_REFERENCE_KEYS)
    && value.schemaVersion === 'controller-seed-source-sets-reference.v1'
    && value.path === 'packages/verification-controller/controller-seed-source-sets.v1.json'
    && value.schemaPath === 'dev/verification/schemas/controller-seed-source-sets.v1.schema.json';
}

function validateInventory(value, { proposal }) {
  const keys = proposal ? PROPOSAL_KEYS : MANIFEST_KEYS;
  const sentinel = proposal;
  if (
    !exactDataObject(value, keys)
    || value.schemaVersion !== (proposal ? 'controller-bundle.proposal.v2' : 'controller-bundle.v2')
    || (proposal && value.proposalStatus !== 'BLOCKED_UNMATERIALIZED')
    || value.sourceRepository !== SOURCE_REPOSITORY
    || value.controllerRepository !== CONTROLLER_REPOSITORY
    || !validRevisionPair(value.sourceRepositoryRevision, value.controllerRevision, sentinel)
    || (proposal && !validSeedSourceSetReference(value.seedSourceSets))
  ) return null;
  const entrypoints = validRecords(value.entrypoints, sentinel);
  const files = validRecords(value.files, sentinel);
  const schemas = validRecords(value.schemaDigests, sentinel);
  const trustMaterials = validTrustRecords(value.trustMaterials, sentinel);
  if (
    entrypoints === null
    || files === null
    || schemas === null
    || trustMaterials === null
    || !validRecord(value.provenance, sentinel)
  ) return null;
  const allMaterialPaths = [
    ...files.map(({ path }) => path),
    ...schemas.map(({ path }) => path),
    ...trustMaterials.map(({ path }) => path),
    value.provenance.path,
  ];
  if (!collisionFree(allMaterialPaths)) return null;
  const filesByPath = new Map(files.map((record) => [pathIdentity(record.path), record]));
  for (const entrypoint of entrypoints) {
    const file = filesByPath.get(pathIdentity(entrypoint.path));
    if (file?.path !== entrypoint.path || file.sha256 !== entrypoint.sha256) return null;
  }
  return { entrypoints, files, schemas, trustMaterials };
}

function cloneRecord(record) {
  return { path: record.path, sha256: record.sha256 };
}

function cloneManifest(manifest) {
  return {
    schemaVersion: manifest.schemaVersion,
    sourceRepository: manifest.sourceRepository,
    sourceRepositoryRevision: manifest.sourceRepositoryRevision,
    controllerRepository: manifest.controllerRepository,
    controllerRevision: manifest.controllerRevision,
    entrypoints: manifest.entrypoints.map(cloneRecord),
    files: manifest.files.map(cloneRecord),
    schemaDigests: manifest.schemaDigests.map(cloneRecord),
    trustMaterials: manifest.trustMaterials.map((record) => ({ ...record })),
    provenance: cloneRecord(manifest.provenance),
  };
}

function deepFreeze(value, seen = new WeakSet()) {
  if (utilTypes.isUint8Array(value)) return value;
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function result(status, value, code = null) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null ? [] : [{
      code,
      safeMessage: code === 'CONTROLLER_BUNDLE_INVALID'
        ? 'The protected controller bundle manifest or immutable tuple is invalid.'
        : 'A protected controller is required.',
      retryable: false,
    }],
  });
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function snapshotBytes(value, allowEmpty = true) {
  try {
    if (
      !utilTypes.isUint8Array(value)
      || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
      || ['buffer', 'byteLength', 'byteOffset', 'length'].some((key) => Object.hasOwn(value, key))
    ) return null;
    const byteLength = Reflect.apply(
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get,
      value,
      [],
    );
    const buffer = Reflect.apply(
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'buffer').get,
      value,
      [],
    );
    if ((!allowEmpty && byteLength === 0) || byteLength > 64 * 1024 * 1024 || utilTypes.isSharedArrayBuffer(buffer)) return null;
    const copy = new Uint8Array(byteLength);
    Reflect.apply(Uint8Array.prototype.set, copy, [value]);
    return copy;
  } catch {
    return null;
  }
}

export function validateControllerBundleProposal(proposal) {
  try {
    return validateInventory(proposal, { proposal: true }) === null
      ? result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID')
      : result('PASS', deepFreeze({
        ...proposal,
        entrypoints: proposal.entrypoints.map(cloneRecord),
        files: proposal.files.map(cloneRecord),
        schemaDigests: proposal.schemaDigests.map(cloneRecord),
        trustMaterials: proposal.trustMaterials.map((record) => ({ ...record })),
        provenance: cloneRecord(proposal.provenance),
      }));
  } catch {
    return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
  }
}

export function materializeControllerBundleProposal(args) {
  try {
    if (
      !exactDataObject(args, MATERIALIZER_KEYS)
      || validateControllerBundleProposal(args.proposal).status !== 'PASS'
      || !validRevisionPair(args.sourceRepositoryRevision, args.controllerRevision)
      || !exactDataObject(args.trustMaterials, TRUST_INPUT_KEYS)
    ) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
    const proposal = args.proposal;
    const expectedPaths = [...proposal.files, ...proposal.schemaDigests]
      .map(({ path }) => path)
      .sort(ordinal);
    const committedFiles = denseValues(args.committedFiles);
    if (committedFiles === null || committedFiles.length !== expectedPaths.length) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
    const digestByPath = new Map();
    for (let index = 0; index < committedFiles.length; index += 1) {
      const record = committedFiles[index];
      if (!exactDataObject(record, COMMITTED_FILE_KEYS) || record.path !== expectedPaths[index]) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
      const bytes = snapshotBytes(record.bytes);
      if (bytes === null) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
      digestByPath.set(record.path, digestBytes(bytes));
    }
    const trustMaterials = [];
    for (let index = 0; index < TRUST_KINDS.length; index += 1) {
      const kind = TRUST_KINDS[index];
      const bytes = snapshotBytes(args.trustMaterials[kind], false);
      if (bytes === null) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
      trustMaterials.push({
        kind,
        path: proposal.trustMaterials[index].path,
        sha256: digestBytes(bytes),
      });
    }
    const provenanceBytes = snapshotBytes(args.provenance, false);
    if (provenanceBytes === null) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
    const materialize = (records) => records.map(({ path }) => ({ path, sha256: digestByPath.get(path) }));
    const manifest = {
      schemaVersion: 'controller-bundle.v2',
      sourceRepository: SOURCE_REPOSITORY,
      sourceRepositoryRevision: args.sourceRepositoryRevision,
      controllerRepository: CONTROLLER_REPOSITORY,
      controllerRevision: args.controllerRevision,
      entrypoints: materialize(proposal.entrypoints),
      files: materialize(proposal.files),
      schemaDigests: materialize(proposal.schemaDigests),
      trustMaterials,
      provenance: { path: proposal.provenance.path, sha256: digestBytes(provenanceBytes) },
    };
    return validateControllerBundleManifest(manifest);
  } catch {
    return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
  }
}

export function validateControllerBundleManifest(manifest) {
  try {
    return validateInventory(manifest, { proposal: false }) === null
      ? result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID')
      : result('PASS', deepFreeze(cloneManifest(manifest)));
  } catch {
    return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
  }
}

export function issueTrustedControllerContextForArtifactVerifier(args) {
  try {
    if (!exactDataObject(args, FACTORY_KEYS)) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
    const validated = validateControllerBundleManifest(args.manifest);
    if (
      validated.status !== 'PASS'
      || typeof args.controllerArtifactId !== 'string'
      || !ARTIFACT_ID.test(args.controllerArtifactId)
      || typeof args.controllerBundleDigest !== 'string'
      || !DIGEST.test(args.controllerBundleDigest)
    ) return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
    const context = {
      environment: 'appwrite-test',
      controllerRepository: CONTROLLER_REPOSITORY,
      controllerBundleSha: validated.value.controllerRevision,
      sourceRepositoryRevision: validated.value.sourceRepositoryRevision,
      controllerArtifactId: args.controllerArtifactId,
      controllerBundleDigest: args.controllerBundleDigest,
    };
    Object.defineProperty(context, 'brand', {
      value: trustedControllerBrand,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    deepFreeze(context);
    AUTHENTIC_CONTEXTS.add(context);
    return result('PASS', context);
  } catch {
    return result('BLOCKED', null, 'CONTROLLER_BUNDLE_INVALID');
  }
}

export function isTrustedControllerContext(value) {
  if (value === null || typeof value !== 'object' || !AUTHENTIC_CONTEXTS.has(value) || !Object.isFrozen(value)) return false;
  const keys = Object.keys(value).sort();
  const brand = Object.getOwnPropertyDescriptor(value, 'brand');
  return keys.length === CONTEXT_KEYS.length
    && keys.every((key, index) => key === CONTEXT_KEYS[index])
    && brand?.enumerable === false
    && brand.value === trustedControllerBrand
    && value.environment === 'appwrite-test'
    && value.controllerRepository === CONTROLLER_REPOSITORY
    && FULL_SHA.test(value.controllerBundleSha)
    && FULL_SHA.test(value.sourceRepositoryRevision)
    && value.controllerBundleSha !== value.sourceRepositoryRevision
    && ARTIFACT_ID.test(value.controllerArtifactId)
    && DIGEST.test(value.controllerBundleDigest);
}
