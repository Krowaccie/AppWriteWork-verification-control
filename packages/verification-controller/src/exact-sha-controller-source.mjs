import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import {
  materializeControllerBundleProposal,
  validateControllerBundleProposal,
} from '../../../scripts/verification/controller-bundle.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const MODES = new Set(['100644', '100755']);
const SOURCE_KEYS = ['controllerRepository', 'controllerRevision', 'git', 'proposal'];
const GIT_KEYS = ['readExactSource'];
const RESPONSE_KEYS = ['files'];
const FILE_KEYS = ['bytes', 'mode', 'path'];
const MATERIALIZE_KEYS = [
  'archiveManifestBytes', 'controllerRevision', 'proposal', 'provenance', 'source',
  'sourceRepositoryRevision', 'trustMaterials',
];
const SOURCE_PAYLOADS = new WeakMap();
const MAX_SAFE_PATH_BYTES = 4096;
const MAX_RECORDS_PER_GROUP = 256;
const MAX_TOTAL_PROPOSAL_RECORDS = 384;
const MAX_PROPOSAL_BYTES = 1024 * 1024;
const APPLY = Reflect.apply;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_BUFFER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'buffer').get;
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength').get;
const TYPED_ARRAY_BYTE_OFFSET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteOffset').get;
const TYPED_ARRAY_SET = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'set').value;
const ARRAY_BUFFER_BYTE_LENGTH = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const ARRAY_BUFFER_RESIZABLE = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get ?? null;
const BYTE_OVERRIDE_KEYS = ['buffer', 'byteLength', 'byteOffset', 'length'];

function exactObject(value, keys) {
  try {
    if (
      value === null
      || typeof value !== 'object'
      || Array.isArray(value)
      || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
    ) return null;
    const names = Object.getOwnPropertyNames(value).sort();
    const expected = [...keys].sort();
    if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) return null;
    const output = {};
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return null;
      output[name] = descriptor.value;
    }
    return output;
  } catch {
    return null;
  }
}

function denseArray(value) {
  try {
    if (!Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
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

function snapshotBytes(value, maximum = 16 * 1024 * 1024) {
  try {
    if (
      !utilTypes.isUint8Array(value)
      || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Uint8Array.prototype
      || Object.getOwnPropertySymbols(value).length !== 0
      || BYTE_OVERRIDE_KEYS.some((key) => Object.hasOwn(value, key))
    ) return null;
    const byteLength = APPLY(TYPED_ARRAY_BYTE_LENGTH, value, []);
    const byteOffset = APPLY(TYPED_ARRAY_BYTE_OFFSET, value, []);
    const buffer = APPLY(TYPED_ARRAY_BUFFER, value, []);
    if (
      byteLength > maximum
      || utilTypes.isSharedArrayBuffer(buffer)
      || (ARRAY_BUFFER_RESIZABLE !== null && APPLY(ARRAY_BUFFER_RESIZABLE, buffer, []) === true)
      || byteOffset + byteLength > APPLY(ARRAY_BUFFER_BYTE_LENGTH, buffer, [])
    ) return null;
    const copy = new Uint8Array(byteLength);
    APPLY(TYPED_ARRAY_SET, copy, [value]);
    if (
      APPLY(TYPED_ARRAY_BYTE_LENGTH, value, []) !== byteLength
      || APPLY(TYPED_ARRAY_BYTE_OFFSET, value, []) !== byteOffset
      || APPLY(TYPED_ARRAY_BUFFER, value, []) !== buffer
    ) return null;
    return copy;
  } catch {
    return null;
  }
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
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
      retryable: false,
      safeMessage: 'The exact protected controller source is invalid.',
    }],
  });
}

function blocked(code) {
  return result('BLOCKED', null, code);
}

function proposalInventory(proposal) {
  const validated = validateControllerBundleProposal(proposal);
  if (validated.status !== 'PASS') return null;
  const groups = [proposal.entrypoints, proposal.files, proposal.schemaDigests];
  if (
    groups.some((group) => group.length > MAX_RECORDS_PER_GROUP)
    || groups.reduce((total, group) => total + group.length, 0) > MAX_TOTAL_PROPOSAL_RECORDS
    || groups.flat().some(({ path: recordPath }) => Buffer.byteLength(recordPath, 'utf8') > MAX_SAFE_PATH_BYTES)
    || Buffer.byteLength(canonicalJson(proposal), 'utf8') > MAX_PROPOSAL_BYTES
  ) return null;
  const paths = [...proposal.files, ...proposal.schemaDigests]
    .map(({ path }) => path)
    .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  return { proposal, paths };
}

export async function readControllerSourceAtExactSha(args) {
  try {
    const input = exactObject(args, SOURCE_KEYS);
    const inventory = input === null ? null : proposalInventory(input.proposal);
    const git = input === null ? null : exactObject(input.git, GIT_KEYS);
    if (
      input === null
      || inventory === null
      || input.controllerRepository !== CONTROLLER_REPOSITORY
      || !SHA.test(input.controllerRevision ?? '')
      || git === null
      || Object.isFrozen(input.git) !== true
      || typeof git.readExactSource !== 'function'
      || utilTypes.isProxy(git.readExactSource)
    ) return blocked('EXACT_SHA_CONTROLLER_SOURCE_INVALID');
    const response = exactObject(await Reflect.apply(git.readExactSource, input.git, [Object.freeze({
      controllerRepository: input.controllerRepository,
      controllerRevision: input.controllerRevision,
      paths: Object.freeze([...inventory.paths]),
    })]), RESPONSE_KEYS);
    const files = response === null ? null : denseArray(response.files);
    if (files === null || files.length !== inventory.paths.length) return blocked('EXACT_SHA_CONTROLLER_SOURCE_INVALID');
    const publicFiles = [];
    const committedFiles = [];
    for (let index = 0; index < files.length; index += 1) {
      const record = exactObject(files[index], FILE_KEYS);
      const bytes = record === null ? null : snapshotBytes(record.bytes);
      if (
        record === null
        || bytes === null
        || record.path !== inventory.paths[index]
        || !MODES.has(record.mode)
      ) return blocked('EXACT_SHA_CONTROLLER_SOURCE_INVALID');
      committedFiles.push({ path: record.path, bytes });
      publicFiles.push({ path: record.path, mode: record.mode, sha256: digestBytes(bytes), bytes });
    }
    const value = deepFreeze({
      controllerRepository: input.controllerRepository,
      controllerRevision: input.controllerRevision,
      files: publicFiles,
    });
    SOURCE_PAYLOADS.set(value, { proposal: input.proposal, committedFiles });
    return result('PASS', value);
  } catch {
    return blocked('EXACT_SHA_CONTROLLER_SOURCE_INVALID');
  }
}

function equalBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

export function materializeAndVerifyControllerBundle(args) {
  try {
    const input = exactObject(args, MATERIALIZE_KEYS);
    const payload = input === null ? null : SOURCE_PAYLOADS.get(input.source);
    const manifestBytes = input === null ? null : snapshotBytes(input.archiveManifestBytes, 1024 * 1024);
    if (
      input === null
      || payload === null
      || payload === undefined
      || payload.proposal !== input.proposal
      || input.source.controllerRevision !== input.controllerRevision
      || !SHA.test(input.sourceRepositoryRevision ?? '')
      || !SHA.test(input.controllerRevision ?? '')
      || input.sourceRepositoryRevision === input.controllerRevision
      || manifestBytes === null
    ) return blocked('CONTROLLER_BUNDLE_MATERIALIZATION_INVALID');
    const materialized = materializeControllerBundleProposal({
      proposal: input.proposal,
      sourceRepositoryRevision: input.sourceRepositoryRevision,
      controllerRevision: input.controllerRevision,
      committedFiles: payload.committedFiles,
      trustMaterials: input.trustMaterials,
      provenance: input.provenance,
    });
    if (materialized.status !== 'PASS') return blocked('CONTROLLER_BUNDLE_MATERIALIZATION_INVALID');
    const expectedBytes = new TextEncoder().encode(`${canonicalJson(materialized.value)}\n`);
    if (!equalBytes(expectedBytes, manifestBytes)) return blocked('CONTROLLER_BUNDLE_MATERIALIZATION_INVALID');
    const output = {
      manifest: materialized.value,
      materializedManifestDigest: digestBytes(expectedBytes),
    };
    if (!DIGEST.test(output.materializedManifestDigest)) return blocked('CONTROLLER_BUNDLE_MATERIALIZATION_INVALID');
    return result('PASS', output);
  } catch {
    return blocked('CONTROLLER_BUNDLE_MATERIALIZATION_INVALID');
  }
}
