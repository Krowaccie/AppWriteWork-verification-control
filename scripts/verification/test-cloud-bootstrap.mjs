import { createHash } from 'node:crypto';

import { qualifyRunner } from '../../dev/verification/bootstrap/qualify-runner.mjs';

const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const REF = 'refs/heads/main';
const PROTOCOL_VERSION = 'verification-runner.v1';
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const RECORD_KEYS = [
  'artifactId', 'bundleDigest', 'cleanupProtocolDigest', 'controllerArchiveDigest',
  'controllerRepository', 'controllerRevision', 'evidenceValidatorDigest',
  'materializedManifestDigest', 'protocolVersion', 'providerContractDigest',
  'requestSchemaDigest', 'responseSchemaDigest', 'scenarioSchemaDigest',
  'sourceRevision', 'timeoutMs', 'transcriptCorpusDigest',
];
const ARCHIVE_PATHS = [
  'bootstrap-manifest.v1.json',
  'evidence-validator.v1.json',
  'provider-contract/test-cloud.provider-contract.v1.json',
  'request.v1.schema.json',
  'response.v1.schema.json',
  'scenarios.v1.schema.json',
  'transcripts.v1.json',
];
const PAYLOAD_PATHS = ARCHIVE_PATHS.slice(1);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}
function hasExactKeys(value, keys) {
  return isPlainObject(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}
function hasPromotionCapability(value) {
  return isPlainObject(value)
    && Object.keys(value).some((key) => /(promot|successor|write|update|setactive)/i.test(key));
}
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
function pass(value) {
  return deepFreeze({ diagnostics: [], status: 'PASS', value });
}
function blocked(code, safeMessage) {
  return deepFreeze({ diagnostics: [{ code, retryable: false, safeMessage }], status: 'BLOCKED', value: null });
}
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('value is not closed JSON');
}
function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
function readScenarioCleanupProtocolDigest(bytes) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = JSON.parse(text);
    const digest = isPlainObject(parsed) ? parsed['x-cleanupProtocolDigest'] : null;
    return DIGEST_PATTERN.test(digest) ? digest : null;
  } catch {
    return null;
  }
}
function archiveDigest(entries) {
  const inventory = entries
    .map((entry) => ({ digest: digestBytes(entry.bytes), path: entry.path }))
    .sort((left, right) => left.path.localeCompare(right.path));
  return digestBytes(new TextEncoder().encode(canonicalJson(inventory)));
}
function validateRecordShape(record) {
  return hasExactKeys(record, RECORD_KEYS)
    && typeof record.artifactId === 'string' && /^[1-9][0-9]{0,19}$/.test(record.artifactId)
    && typeof record.bundleDigest === 'string' && DIGEST_PATTERN.test(record.bundleDigest)
    && typeof record.cleanupProtocolDigest === 'string' && DIGEST_PATTERN.test(record.cleanupProtocolDigest)
    && typeof record.controllerArchiveDigest === 'string' && DIGEST_PATTERN.test(record.controllerArchiveDigest)
    && typeof record.controllerRepository === 'string' && record.controllerRepository.length > 0
    && typeof record.controllerRevision === 'string' && SHA_PATTERN.test(record.controllerRevision)
    && typeof record.evidenceValidatorDigest === 'string' && DIGEST_PATTERN.test(record.evidenceValidatorDigest)
    && typeof record.materializedManifestDigest === 'string'
    && DIGEST_PATTERN.test(record.materializedManifestDigest)
    && typeof record.protocolVersion === 'string'
    && typeof record.providerContractDigest === 'string' && DIGEST_PATTERN.test(record.providerContractDigest)
    && typeof record.requestSchemaDigest === 'string' && DIGEST_PATTERN.test(record.requestSchemaDigest)
    && typeof record.responseSchemaDigest === 'string' && DIGEST_PATTERN.test(record.responseSchemaDigest)
    && typeof record.scenarioSchemaDigest === 'string' && DIGEST_PATTERN.test(record.scenarioSchemaDigest)
    && typeof record.sourceRevision === 'string' && SHA_PATTERN.test(record.sourceRevision)
    && Number.isInteger(record.timeoutMs) && record.timeoutMs > 0 && record.timeoutMs <= 300_000
    && DIGEST_PATTERN.test(record.transcriptCorpusDigest);
}
function validateDependencies(args) {
  if (!hasExactKeys(args, ['clock', 'controller', 'github', 'pointer'])) {
    throw new TypeError('resolveTrustedBootstrap requires the closed resolver argument shape');
  }
  if (hasPromotionCapability(args.controller) || hasPromotionCapability(args.github)) return false;
  if (!hasExactKeys(args.controller, ['ref', 'repository'])
      || typeof args.controller.ref !== 'string' || typeof args.controller.repository !== 'string') {
    throw new TypeError('controller trust root is invalid');
  }
  if (!hasExactKeys(args.github, ['getArtifactById']) || typeof args.github.getArtifactById !== 'function') {
    throw new TypeError('github reader must expose only getArtifactById');
  }
  if (!hasExactKeys(args.clock, ['now']) || typeof args.clock.now !== 'function') {
    throw new TypeError('clock must expose only now');
  }
  return true;
}
function validateArtifactMetadata(artifact) {
  return hasExactKeys(artifact, [
    'artifactId', 'entries', 'expiresAt', 'extractedBundleRoot', 'ref', 'repository', 'run',
  ])
    && typeof artifact.artifactId === 'string'
    && Array.isArray(artifact.entries)
    && typeof artifact.expiresAt === 'string'
    && typeof artifact.extractedBundleRoot === 'string' && artifact.extractedBundleRoot.length > 0
    && typeof artifact.ref === 'string'
    && typeof artifact.repository === 'string'
    && hasExactKeys(artifact.run, ['conclusion', 'sourceRevision', 'status'])
    && typeof artifact.run.conclusion === 'string'
    && typeof artifact.run.sourceRevision === 'string'
    && typeof artifact.run.status === 'string';
}
function validateArchive(entries) {
  if (entries.length !== ARCHIVE_PATHS.length) return false;
  for (const entry of entries) {
    if (!hasExactKeys(entry, ['bytes', 'path', 'type'])
        || entry.type !== 'file'
        || typeof entry.path !== 'string'
        || !ARCHIVE_PATHS.includes(entry.path)
        || entry.path.includes('..')
        || entry.path.includes('\\')
        || entry.path.startsWith('/')
        || !(entry.bytes instanceof Uint8Array)
        || entry.bytes.byteLength === 0) return false;
  }
  const paths = entries.map((entry) => entry.path).sort();
  return new Set(paths).size === paths.length && paths.join('\0') === ARCHIVE_PATHS.join('\0');
}
function parseManifest(bytes) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = JSON.parse(text);
    if (text !== canonicalJson(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}
function validateManifest(manifest, record, entries) {
  if (!hasExactKeys(manifest, ['files', 'protocolVersion', 'schemaVersion', 'sourceRevision'])
      || manifest.schemaVersion !== 'verification-bootstrap-bundle.v1'
      || typeof manifest.protocolVersion !== 'string'
      || typeof manifest.sourceRevision !== 'string'
      || !Array.isArray(manifest.files)
      || manifest.files.length !== PAYLOAD_PATHS.length) return { code: 'BOOTSTRAP_RECORD_INVALID' };
  if (manifest.protocolVersion !== PROTOCOL_VERSION) return { code: 'BOOTSTRAP_PROTOCOL_MISMATCH' };
  if (manifest.sourceRevision !== record.sourceRevision) return { code: 'BOOTSTRAP_RECORD_INVALID' };
  const sortedFiles = [...manifest.files].sort((left, right) => String(left?.path).localeCompare(String(right?.path)));
  if (JSON.stringify(manifest.files) !== JSON.stringify(sortedFiles)) return { code: 'BOOTSTRAP_ARCHIVE_UNSAFE' };
  const entryMap = new Map(entries.map((entry) => [entry.path, entry.bytes]));
  const manifestMap = new Map();
  for (const file of manifest.files) {
    if (!hasExactKeys(file, ['digest', 'path'])
        || typeof file.path !== 'string'
        || !PAYLOAD_PATHS.includes(file.path)
        || !DIGEST_PATTERN.test(file.digest)
        || manifestMap.has(file.path)) return { code: 'BOOTSTRAP_ARCHIVE_UNSAFE' };
    manifestMap.set(file.path, file.digest);
  }
  if (PAYLOAD_PATHS.some((path) => !manifestMap.has(path))) return { code: 'BOOTSTRAP_ARCHIVE_UNSAFE' };
  const expected = new Map([
    ['evidence-validator.v1.json', record.evidenceValidatorDigest],
    ['provider-contract/test-cloud.provider-contract.v1.json', record.providerContractDigest],
    ['request.v1.schema.json', record.requestSchemaDigest],
    ['response.v1.schema.json', record.responseSchemaDigest],
    ['scenarios.v1.schema.json', record.scenarioSchemaDigest],
    ['transcripts.v1.json', record.transcriptCorpusDigest],
  ]);
  for (const path of PAYLOAD_PATHS) {
    const actual = digestBytes(entryMap.get(path));
    if (manifestMap.get(path) !== actual || expected.get(path) !== actual) {
      return { code: 'BOOTSTRAP_DIGEST_MISMATCH' };
    }
  }
  if (readScenarioCleanupProtocolDigest(entryMap.get('scenarios.v1.schema.json'))
      !== record.cleanupProtocolDigest) {
    return { code: 'BOOTSTRAP_DIGEST_MISMATCH' };
  }
  return { code: null };
}

export async function resolveTrustedBootstrap(args) {
  if (!validateDependencies(args)) {
    return blocked('BOOTSTRAP_PROMOTION_FORBIDDEN', 'Promotion capability is forbidden during bootstrap resolution.');
  }
  if (args.pointer === null || args.pointer === undefined) {
    return blocked('BOOTSTRAP_POINTER_MISSING', 'No active bootstrap pointer is available.');
  }
  if (!validateRecordShape(args.pointer)) {
    return blocked('BOOTSTRAP_RECORD_INVALID', 'Active bootstrap record is invalid.');
  }
  if (args.pointer.protocolVersion !== PROTOCOL_VERSION) {
    return blocked('BOOTSTRAP_PROTOCOL_MISMATCH', 'Bootstrap protocol is not supported.');
  }
  if (args.controller.repository !== REPOSITORY
      || args.controller.ref !== REF
      || args.pointer.controllerRepository !== REPOSITORY) {
    return blocked('BOOTSTRAP_REPOSITORY_MISMATCH', 'Bootstrap trust root does not match the approved controller repository.');
  }
  let artifact;
  try {
    artifact = await args.github.getArtifactById({ artifactId: args.pointer.artifactId, repository: REPOSITORY });
  } catch {
    return blocked('BOOTSTRAP_RECORD_INVALID', 'Bootstrap artifact metadata could not be resolved.');
  }
  if (!validateArtifactMetadata(artifact)
      || artifact.artifactId !== args.pointer.artifactId
      || artifact.run.sourceRevision !== args.pointer.sourceRevision) {
    return blocked('BOOTSTRAP_RECORD_INVALID', 'Bootstrap artifact metadata is invalid.');
  }
  if (artifact.repository !== REPOSITORY || artifact.ref !== REF) {
    return blocked('BOOTSTRAP_REPOSITORY_MISMATCH', 'Bootstrap artifact is outside the approved repository or ref.');
  }
  if (artifact.run.status !== 'completed' || artifact.run.conclusion !== 'success') {
    return blocked('BOOTSTRAP_RUN_NOT_GREEN', 'Bootstrap artifact does not come from a completed successful run.');
  }
  const expiresAt = Date.parse(artifact.expiresAt);
  const now = args.clock.now();
  if (!Number.isFinite(now)) throw new TypeError('clock.now must return a finite number');
  if (!Number.isFinite(expiresAt)) return blocked('BOOTSTRAP_RECORD_INVALID', 'Bootstrap artifact expiry is invalid.');
  if (expiresAt <= now) return blocked('BOOTSTRAP_ARTIFACT_EXPIRED', 'Bootstrap artifact has expired.');
  if (!validateArchive(artifact.entries)) {
    return blocked('BOOTSTRAP_ARCHIVE_UNSAFE', 'Bootstrap archive is not a closed safe archive.');
  }
  if (archiveDigest(artifact.entries) !== args.pointer.bundleDigest) {
    return blocked('BOOTSTRAP_DIGEST_MISMATCH', 'Bootstrap archive digest does not match its active record.');
  }
  const manifestEntry = artifact.entries.find((entry) => entry.path === 'bootstrap-manifest.v1.json');
  const manifestResult = validateManifest(parseManifest(manifestEntry.bytes), args.pointer, artifact.entries);
  if (manifestResult.code) {
    const messages = {
      BOOTSTRAP_ARCHIVE_UNSAFE: 'Bootstrap manifest is not closed and deterministic.',
      BOOTSTRAP_DIGEST_MISMATCH: 'Bootstrap payload digest does not match its active record.',
      BOOTSTRAP_PROTOCOL_MISMATCH: 'Bootstrap manifest protocol is not supported.',
      BOOTSTRAP_RECORD_INVALID: 'Bootstrap manifest is invalid.',
    };
    return blocked(manifestResult.code, messages[manifestResult.code]);
  }
  return pass({
    extractedBundleRoot: artifact.extractedBundleRoot,
    record: { ...args.pointer },
    verifiedBundleDigest: args.pointer.bundleDigest,
  });
}

export async function qualifyDeployedRunner(args) {
  return qualifyRunner(args);
}
