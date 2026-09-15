import { types as utilTypes } from 'node:util';

import { canonicalJson } from './canonical-json.mjs';
import { validateArtifactManifest } from './artifact-manifest.mjs';

const NativeArray = Array;
const NativeNumber = Number;
const NativeObject = Object;
const NativeReflect = Reflect;
const NativeSet = Set;
const ObjectPrototype = NativeObject.prototype;
const arrayIsArray = NativeArray.isArray;
const numberIsFinite = NativeNumber.isFinite;
const numberIsSafeInteger = NativeNumber.isSafeInteger;
const objectCreate = NativeObject.create;
const objectDefineProperty = NativeObject.defineProperty;
const objectFreeze = NativeObject.freeze;
const objectGetOwnPropertyDescriptor = NativeObject.getOwnPropertyDescriptor;
const objectGetPrototypeOf = NativeObject.getPrototypeOf;
const objectHasOwn = NativeObject.hasOwn;
const objectIsFrozen = NativeObject.isFrozen;
const reflectApply = NativeReflect.apply;
const reflectOwnKeys = NativeReflect.ownKeys;
const regexpExec = RegExp.prototype.exec;
const setAdd = NativeSet.prototype.add;
const setDelete = NativeSet.prototype.delete;
const setHas = NativeSet.prototype.has;
const isProxy = utilTypes.isProxy;

const FULL_REVISION_PATTERN = /^[0-9a-f]{40}$/;
const POSITIVE_DECIMAL_PATTERN = /^[1-9][0-9]*$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ARRAY_INDEX_PATTERN = /^(0|[1-9][0-9]*)$/;
const ARG_KEYS = objectFreeze(['github', 'manifest', 'revision']);
const GITHUB_KEYS = objectFreeze(['ref', 'repository', 'runAttempt', 'runId', 'workflow']);
const VALIDATION_ARG_KEYS = objectFreeze(['handoff', 'manifest', 'trustedSource']);
const TRUSTED_SOURCE_KEYS = objectFreeze([
  'repository',
  'sourceRef',
  'sourceRevision',
  'workflow',
  'workflowRunAttempt',
  'workflowRunId',
]);
const MANIFEST_KEYS = objectFreeze([
  'artifactManifestDigest',
  'artifacts',
  'schemaVersion',
  'sourceRevision',
  'sourceTreeDigest',
  'verifierManifestDigest',
]);
const HANDOFF_KEYS = objectFreeze([
  'artifactManifestDigest',
  'artifactName',
  'schemaVersion',
  'sourceRef',
  'sourceRepository',
  'sourceRevision',
  'sourceWorkflow',
  'sourceWorkflowRunAttempt',
  'sourceWorkflowRunId',
  'verifierManifestDigest',
]);
const DIAGNOSTIC_KEYS = objectFreeze(['code', 'retryable', 'safeMessage']);
const RESULT_KEYS = objectFreeze(['diagnostics', 'status', 'value']);

function matches(pattern, value) {
  return reflectApply(regexpExec, pattern, [value]) !== null;
}

function defineData(target, key, value) {
  const descriptor = objectCreate(null);
  descriptor.configurable = false;
  descriptor.enumerable = true;
  descriptor.value = value;
  descriptor.writable = false;
  objectDefineProperty(target, key, descriptor);
}

function frozenRecord(fields, keys) {
  const record = objectCreate(ObjectPrototype);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    defineData(record, key, fields[key]);
  }
  return objectFreeze(record);
}

function exactDataObject(value, expectedKeys) {
  try {
    if (
      isProxy(value)
      || value === null
      || typeof value !== 'object'
      || arrayIsArray(value)
    ) return null;
    const prototype = objectGetPrototypeOf(value);
    if (prototype !== ObjectPrototype && prototype !== null) return null;
    const ownKeys = reflectOwnKeys(value);
    if (ownKeys.length !== expectedKeys.length) return null;
    for (let index = 0; index < ownKeys.length; index += 1) {
      const actualKey = ownKeys[index];
      if (typeof actualKey !== 'string') return null;
      let found = false;
      for (let expectedIndex = 0; expectedIndex < expectedKeys.length; expectedIndex += 1) {
        if (actualKey === expectedKeys[expectedIndex]) {
          found = true;
          break;
        }
      }
      if (!found) return null;
    }
    const copy = objectCreate(null);
    for (let index = 0; index < expectedKeys.length; index += 1) {
      const key = expectedKeys[index];
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || descriptor.enumerable !== true
        || !objectHasOwn(descriptor, 'value')
      ) return null;
      defineData(copy, key, descriptor.value);
    }
    return copy;
  } catch {
    return null;
  }
}

function isDeeplyFrozenCanonicalData(value, ancestors = new NativeSet()) {
  if (value === null) return true;
  const valueType = typeof value;
  if (valueType === 'string' || valueType === 'boolean') return true;
  if (valueType === 'number') return numberIsFinite(value);
  if (valueType !== 'object') return false;
  let added = false;
  try {
    if (
      isProxy(value)
      || !objectIsFrozen(value)
      || reflectApply(setHas, ancestors, [value])
    ) return false;
    reflectApply(setAdd, ancestors, [value]);
    added = true;
    if (arrayIsArray(value)) {
      const ownKeys = reflectOwnKeys(value);
      for (let keyIndex = 0; keyIndex < ownKeys.length; keyIndex += 1) {
        const key = ownKeys[keyIndex];
        if (typeof key !== 'string') return false;
        if (key === 'length') continue;
        if (!matches(ARRAY_INDEX_PATTERN, key)) return false;
      }
      for (let index = 0; index < value.length; index += 1) {
        const key = String(index);
        if (!objectHasOwn(value, key)) return false;
        const descriptor = objectGetOwnPropertyDescriptor(value, key);
        if (
          descriptor === undefined
          || descriptor.enumerable !== true
          || !objectHasOwn(descriptor, 'value')
          || !isDeeplyFrozenCanonicalData(descriptor.value, ancestors)
        ) return false;
      }
      return ownKeys.length === value.length + 1;
    }
    const prototype = objectGetPrototypeOf(value);
    if (prototype !== ObjectPrototype && prototype !== null) return false;
    const ownKeys = reflectOwnKeys(value);
    for (let index = 0; index < ownKeys.length; index += 1) {
      const key = ownKeys[index];
      if (typeof key !== 'string') return false;
      const descriptor = objectGetOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined
        || descriptor.enumerable !== true
        || !objectHasOwn(descriptor, 'value')
        || !isDeeplyFrozenCanonicalData(descriptor.value, ancestors)
      ) return false;
    }
    return true;
  } catch {
    return false;
  } finally {
    if (added) reflectApply(setDelete, ancestors, [value]);
  }
}

function operationResult(status, value, code = null) {
  let diagnostics;
  if (code === null) {
    diagnostics = objectFreeze([]);
  } else {
    const diagnosticFields = objectCreate(null);
    defineData(diagnosticFields, 'code', code);
    defineData(
      diagnosticFields,
      'safeMessage',
      'Hosted artifact handoff does not match the closed trusted contract.',
    );
    defineData(diagnosticFields, 'retryable', false);
    diagnostics = objectFreeze([frozenRecord(diagnosticFields, DIAGNOSTIC_KEYS)]);
  }
  const fields = objectCreate(null);
  defineData(fields, 'status', status);
  defineData(fields, 'value', value);
  defineData(fields, 'diagnostics', diagnostics);
  return frozenRecord(fields, RESULT_KEYS);
}

function blocked() {
  return operationResult('BLOCKED', null, 'ARTIFACT_HANDOFF_INVALID');
}

function validTrustedSource(fields) {
  return (
    fields.repository === 'Krowaccie/AppWriteWork'
    && fields.workflow === 'Verify Main'
    && typeof fields.workflowRunId === 'string'
    && matches(POSITIVE_DECIMAL_PATTERN, fields.workflowRunId)
    && numberIsSafeInteger(fields.workflowRunAttempt)
    && fields.workflowRunAttempt > 0
    && fields.sourceRef === 'refs/heads/main'
    && typeof fields.sourceRevision === 'string'
    && matches(FULL_REVISION_PATTERN, fields.sourceRevision)
  );
}

function validManifestProjection(fields) {
  return (
    fields.schemaVersion === 1
    && typeof fields.sourceRevision === 'string'
    && matches(FULL_REVISION_PATTERN, fields.sourceRevision)
    && typeof fields.sourceTreeDigest === 'string'
    && matches(DIGEST_PATTERN, fields.sourceTreeDigest)
    && typeof fields.artifactManifestDigest === 'string'
    && matches(DIGEST_PATTERN, fields.artifactManifestDigest)
    && typeof fields.verifierManifestDigest === 'string'
    && matches(DIGEST_PATTERN, fields.verifierManifestDigest)
    && !isProxy(fields.artifacts)
    && arrayIsArray(fields.artifacts)
  );
}

function validHandoff(fields) {
  return (
    fields.schemaVersion === 'artifact-handoff.v1'
    && fields.sourceRepository === 'Krowaccie/AppWriteWork'
    && fields.sourceWorkflow === 'Verify Main'
    && typeof fields.sourceWorkflowRunId === 'string'
    && matches(POSITIVE_DECIMAL_PATTERN, fields.sourceWorkflowRunId)
    && numberIsSafeInteger(fields.sourceWorkflowRunAttempt)
    && fields.sourceWorkflowRunAttempt > 0
    && fields.sourceRef === 'refs/heads/main'
    && typeof fields.sourceRevision === 'string'
    && matches(FULL_REVISION_PATTERN, fields.sourceRevision)
    && fields.artifactName === `verification-artifacts-${fields.sourceRevision}`
    && typeof fields.artifactManifestDigest === 'string'
    && matches(DIGEST_PATTERN, fields.artifactManifestDigest)
    && typeof fields.verifierManifestDigest === 'string'
    && matches(DIGEST_PATTERN, fields.verifierManifestDigest)
  );
}

export function validateHostedArtifactHandoff(args) {
  const input = exactDataObject(args, VALIDATION_ARG_KEYS);
  if (input === null) return blocked();
  const handoff = exactDataObject(input.handoff, HANDOFF_KEYS);
  const manifest = exactDataObject(input.manifest, MANIFEST_KEYS);
  const trustedSource = exactDataObject(input.trustedSource, TRUSTED_SOURCE_KEYS);
  if (
    handoff === null
    || manifest === null
    || trustedSource === null
    || !validHandoff(handoff)
    || !validManifestProjection(manifest)
    || !validTrustedSource(trustedSource)
    || manifest.sourceRevision !== trustedSource.sourceRevision
    || handoff.sourceRepository !== trustedSource.repository
    || handoff.sourceWorkflow !== trustedSource.workflow
    || handoff.sourceWorkflowRunId !== trustedSource.workflowRunId
    || handoff.sourceWorkflowRunAttempt !== trustedSource.workflowRunAttempt
    || handoff.sourceRef !== trustedSource.sourceRef
    || handoff.sourceRevision !== trustedSource.sourceRevision
    || handoff.artifactName !== `verification-artifacts-${trustedSource.sourceRevision}`
    || handoff.artifactManifestDigest !== manifest.artifactManifestDigest
    || handoff.verifierManifestDigest !== manifest.verifierManifestDigest
  ) return blocked();
  return operationResult('PASS', frozenRecord(handoff, HANDOFF_KEYS));
}

export function createHostedArtifactHandoff(args) {
  const input = exactDataObject(args, ARG_KEYS);
  if (input === null) return blocked();

  const github = exactDataObject(input.github, GITHUB_KEYS);
  if (
    github === null
    || github.repository !== 'Krowaccie/AppWriteWork'
    || github.workflow !== 'Verify Main'
    || typeof github.runId !== 'string'
    || !matches(POSITIVE_DECIMAL_PATTERN, github.runId)
    || !numberIsSafeInteger(github.runAttempt)
    || github.runAttempt <= 0
    || github.ref !== 'refs/heads/main'
  ) return blocked();

  if (
    typeof input.revision !== 'string'
    || !matches(FULL_REVISION_PATTERN, input.revision)
    || !isDeeplyFrozenCanonicalData(input.manifest)
  ) return blocked();

  let manifestValidation;
  try {
    canonicalJson(input.manifest);
    manifestValidation = validateArtifactManifest(input.manifest);
  } catch {
    return blocked();
  }
  if (
    manifestValidation.ok !== true
    || input.manifest.sourceRevision !== input.revision
    || !matches(DIGEST_PATTERN, input.manifest.artifactManifestDigest)
    || !matches(DIGEST_PATTERN, input.manifest.verifierManifestDigest)
  ) return blocked();

  return validateHostedArtifactHandoff({
    handoff: {
      schemaVersion: 'artifact-handoff.v1',
      sourceRepository: 'Krowaccie/AppWriteWork',
      sourceWorkflow: 'Verify Main',
      sourceWorkflowRunId: github.runId,
      sourceWorkflowRunAttempt: github.runAttempt,
      sourceRef: 'refs/heads/main',
      sourceRevision: input.revision,
      artifactName: `verification-artifacts-${input.revision}`,
      artifactManifestDigest: input.manifest.artifactManifestDigest,
      verifierManifestDigest: input.manifest.verifierManifestDigest,
    },
    manifest: input.manifest,
    trustedSource: {
      repository: github.repository,
      workflow: github.workflow,
      workflowRunId: github.runId,
      workflowRunAttempt: github.runAttempt,
      sourceRef: github.ref,
      sourceRevision: input.revision,
    },
  });
}
