#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import { validateTestCloudHostedSetupAttestationDocument } from
  '../../../scripts/verification/test-cloud-hosted-setup-attestation.mjs';
import { validateTestCloudSetupAttestationDocument } from
  '../../../scripts/verification/test-cloud-setup-attestation.mjs';
import {
  checkInitialTestCloudSetup,
  checkTestCloudSetup,
  qualifyExecutionObservationReadback,
} from '../../../scripts/verification/test-cloud-setup-check.mjs';
import { validateTestCloudSetupReadbackBytes } from
  '../../../scripts/verification/test-cloud-provider-contract.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import {
  MAX_VERIFICATION_ARCHIVE_BYTES,
  extractBoundedZipArchive,
  readBoundedResponseBytes,
} from './controller-archive-verifier.mjs';

const API_ORIGIN = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const ID = /^[1-9][0-9]*$/u;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const EXPECTED_ENVIRONMENT_DIGEST =
  'sha256:02560e84745ed7b577b334a3412885f6a547b2a22f164f4978b255d3b35c0044';
const EXPECTED_PROVIDER_CONTRACT_DIGEST =
  'sha256:47a1d778ca8b8cea333b10574ffbc2db488fd711c12a1c40faf9da5235e27184';
const RETENTION_SECONDS = 86_400;
const BINDING_NAMES = Object.freeze([
  'TEST_CLOUD_SETUP_READBACK_JSON',
  'TEST_CLOUD_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
  'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
  'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
]);
const EXPECTED_FILES = Object.freeze([
  ...BINDING_NAMES.map((name) => `${name}.txt`),
  'evidence.json',
].sort());
const EXPECTED_ARCHIVE_FILES = Object.freeze([...EXPECTED_FILES, 'binding-manifest.json'].sort());

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function result(status, value = null, code = null) {
  return deepFreeze({
    status,
    value,
    diagnostics: code === null ? [] : [{
      code,
      retryable: false,
      safeMessage: 'The trusted Appwrite Test binding artifact is invalid.',
    }],
  });
}

function blocked(code = 'TEST_CLOUD_BINDING_ARTIFACT_INVALID') {
  return result('BLOCKED', null, code);
}

function exactObject(value, keys) {
  try {
    return value !== null
      && typeof value === 'object'
      && !Array.isArray(value)
      && !utilTypes.isProxy(value)
      && Object.getPrototypeOf(value) === Object.prototype
      && Object.getOwnPropertySymbols(value).length === 0
      && Object.keys(value).sort().every((name, index) => name === [...keys].sort()[index])
      && Object.keys(value).length === keys.length;
  } catch {
    return false;
  }
}

function ownData(value, key) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function sha256Bytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function parseCanonicalJsonText(text, newline) {
  if (typeof text !== 'string' || text.length < 2 || text.includes('\0')) return null;
  const canonical = newline ? (text.endsWith('\n') ? text.slice(0, -1) : null) : text;
  if (canonical === null || (newline && canonical.includes('\n') && canonical.length === 0)) return null;
  try {
    const value = JSON.parse(canonical);
    return canonicalJson(value) === canonical ? value : null;
  } catch {
    return null;
  }
}

function parseBinding(bindings, jsonName, digestName) {
  const json = bindings[jsonName];
  const digest = bindings[digestName];
  if (
    typeof json !== 'string'
    || typeof digest !== 'string'
    || !DIGEST.test(digest)
    || sha256Bytes(Buffer.from(json, 'utf8')) !== digest
  ) return null;
  const value = parseCanonicalJsonText(json, false);
  return value === null ? null : { value, digest };
}

function validateManifest(manifest, input) {
  if (!exactObject(manifest, [
    'controllerArtifact', 'controllerRevision', 'files', 'initialSeed',
    'runnerRevision', 'schemaVersion', 'sourceRepositoryRevision',
  ])) return false;
  if (
    manifest.schemaVersion !== 'appwrite-test-binding-artifact-manifest.v1'
    || manifest.controllerRevision !== input.trustedSha
    || manifest.sourceRepositoryRevision !== input.sourceRepositoryRevision
    || manifest.runnerRevision !== input.runnerRevision
    || manifest.initialSeed !== input.initialSeed
    || !Array.isArray(manifest.files)
    || manifest.files.length !== EXPECTED_FILES.length
  ) return false;
  if (input.initialSeed) {
    if (manifest.controllerArtifact !== null) return false;
  } else if (
    !exactObject(manifest.controllerArtifact, ['artifactId', 'digest'])
    || !ID.test(manifest.controllerArtifact.artifactId ?? '')
    || !DIGEST.test(manifest.controllerArtifact.digest ?? '')
  ) return false;
  return manifest.files.every((record, index) => (
    exactObject(record, ['byteLength', 'path', 'sha256'])
    && record.path === EXPECTED_FILES[index]
    && Number.isSafeInteger(record.byteLength)
    && record.byteLength > 0
    && record.byteLength <= 2 * 1024 * 1024
    && DIGEST.test(record.sha256 ?? '')
  ));
}

function validateEvidence(evidence, input, bindings, nowEpochSeconds) {
  if (!exactObject(evidence, [
    'controllerRevision', 'environmentDigest', 'expiresAtEpochSeconds',
    'hostedSetupReadbackDigest', 'identityBindingsDigest', 'initialSeed',
    'issuedAtEpochSeconds', 'providerContractDigest', 'providerSetupReadbackDigest',
    'runnerRevision', 'runnerVariableReadbackDigest', 'schemaVersion',
    'sourceRepositoryRevision',
  ])) return false;
  return evidence.schemaVersion === 'appwrite-test-setup-binding-evidence.v1'
    && evidence.controllerRevision === input.trustedSha
    && evidence.sourceRepositoryRevision === input.sourceRepositoryRevision
    && evidence.runnerRevision === input.runnerRevision
    && evidence.initialSeed === input.initialSeed
    && evidence.environmentDigest === EXPECTED_ENVIRONMENT_DIGEST
    && evidence.providerContractDigest === EXPECTED_PROVIDER_CONTRACT_DIGEST
    && DIGEST.test(evidence.identityBindingsDigest ?? '')
    && DIGEST.test(evidence.runnerVariableReadbackDigest ?? '')
    && evidence.providerSetupReadbackDigest === bindings.TEST_CLOUD_SETUP_READBACK_DIGEST
    && evidence.hostedSetupReadbackDigest === bindings.TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST
    && Number.isSafeInteger(evidence.issuedAtEpochSeconds)
    && Number.isSafeInteger(evidence.expiresAtEpochSeconds)
    && evidence.issuedAtEpochSeconds <= nowEpochSeconds
    && nowEpochSeconds < evidence.expiresAtEpochSeconds
    && evidence.expiresAtEpochSeconds - evidence.issuedAtEpochSeconds <= 21_600;
}

export function validateTestCloudBindingSet(args) {
  try {
    if (!exactObject(args, ['bindings', 'evidence', 'input', 'manifest', 'nowEpochSeconds'])) {
      return blocked();
    }
    const { bindings, evidence, input, manifest, nowEpochSeconds } = args;
    if (
      !exactObject(input, [
        'artifactId', 'authorization', 'bundleDigest', 'initialSeed', 'repository',
        'runnerRevision', 'sourceRepositoryRevision', 'trustedSha',
      ])
      || !exactObject(bindings, BINDING_NAMES)
      || !Number.isSafeInteger(nowEpochSeconds)
      || !validateManifest(manifest, input)
      || !validateEvidence(evidence, input, bindings, nowEpochSeconds)
    ) return blocked();

    const providerReadback = parseBinding(
      bindings, 'TEST_CLOUD_SETUP_READBACK_JSON', 'TEST_CLOUD_SETUP_READBACK_DIGEST',
    );
    const providerAttestation = parseBinding(
      bindings, 'TEST_CLOUD_SETUP_ATTESTATION_JSON', 'TEST_CLOUD_SETUP_ATTESTATION_DIGEST',
    );
    const hostedReadback = parseBinding(
      bindings, 'TEST_CLOUD_HOSTED_SETUP_READBACK_JSON',
      'TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST',
    );
    const hostedAttestation = parseBinding(
      bindings, 'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON',
      'TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST',
    );
    if ([providerReadback, providerAttestation, hostedReadback, hostedAttestation].includes(null)) {
      return blocked();
    }
    if (validateTestCloudSetupReadbackBytes({
      bytes: new TextEncoder().encode(bindings.TEST_CLOUD_SETUP_READBACK_JSON),
      expectedDigest: providerReadback.digest,
      expectedEnvironmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
      expectedProviderContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
    }).status !== 'PASS') return blocked();
    const clock = Object.freeze({ nowEpochSeconds: () => nowEpochSeconds });
    if (validateTestCloudSetupAttestationDocument({
      attestation: providerAttestation.value,
      attestationDigest: providerAttestation.digest,
      clock,
      expectedEnvironmentDigest: EXPECTED_ENVIRONMENT_DIGEST,
      expectedProviderContractDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
      expectedIdentityBindingsDigest: evidence.identityBindingsDigest,
      expectedProviderSetupReadbackDigest: providerReadback.digest,
      expectedPrimaryExecutionRetentionMaxSeconds: RETENTION_SECONDS,
      maximumRetentionSeconds: RETENTION_SECONDS,
    }).status !== 'PASS') return blocked();
    const observationDigest = sha256Bytes(Buffer.from(
      canonicalJson(hostedReadback.value.executionObservation), 'utf8',
    ));
    const observation = qualifyExecutionObservationReadback({
      inventory,
      readback: hostedReadback.value.executionObservation,
      expectedReadbackDigest: observationDigest,
    });
    const checked = observation.status === 'PASS'
      ? (input.initialSeed ? checkInitialTestCloudSetup : checkTestCloudSetup)({
        inventory,
        readback: hostedReadback.value,
        expectedProviderSchemaDigest: EXPECTED_PROVIDER_CONTRACT_DIGEST,
        executionObservationQualification: observation.value,
      })
      : observation;
    if (
      checked.status !== 'PASS'
      || checked.value.controllerBundleSha !== input.trustedSha
      || checked.value.sourceRepositoryRevision !== input.sourceRepositoryRevision
    ) return blocked();
    if (validateTestCloudHostedSetupAttestationDocument({
      attestation: hostedAttestation.value,
      attestationDigest: hostedAttestation.digest,
      clock,
      expectedExecutionObservationPolicyDigest: checked.value.executionObservationPolicyDigest,
      expectedHostedSetupReadbackDigest: hostedReadback.digest,
      expectedPrimaryExecutionRetentionMaxSeconds: RETENTION_SECONDS,
      expectedProviderSetupReadbackDigest: providerReadback.digest,
    }).status !== 'PASS') return blocked();
    return result('PASS', { bindings: { ...bindings }, evidence, manifest });
  } catch {
    return blocked();
  }
}

function githubHeaders(authorization) {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${authorization}`,
    'User-Agent': 'appwritework-verification-controller',
    'X-GitHub-Api-Version': API_VERSION,
  };
}

function artifactUrl(artifactId) {
  return `${API_ORIGIN}/repos/${REPOSITORY}/actions/artifacts/${artifactId}/zip`;
}

function signedArtifactUrl(value) {
  try {
    const url = new URL(value);
    const hostname = url.hostname.toLowerCase();
    return url.protocol === 'https:'
      && (hostname === 'objects.githubusercontent.com'
        || hostname.endsWith('.githubusercontent.com')
        || hostname.endsWith('.blob.core.windows.net'))
      && url.username === ''
      && url.password === ''
      && (url.port === '' || url.port === '443')
      && url.pathname.startsWith('/')
      && url.pathname.length > 1
      && url.hash === ''
      ? url.toString()
      : null;
  } catch {
    return null;
  }
}

async function readJson(response) {
  if (response?.status !== 200) throw new Error('metadata status');
  const contentType = response?.headers?.get?.('content-type');
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|$)/iu.test(contentType)) {
    throw new Error('metadata content type');
  }
  const bytes = await readBoundedResponseBytes(response, 1024 * 1024);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function validInput(input) {
  return exactObject(input, [
    'artifactId', 'authorization', 'bundleDigest', 'initialSeed', 'repository',
    'runnerRevision', 'sourceRepositoryRevision', 'trustedSha',
  ])
    && input.repository === REPOSITORY
    && ID.test(input.artifactId ?? '')
    && DIGEST.test(input.bundleDigest ?? '')
    && SHA.test(input.trustedSha ?? '')
    && SHA.test(input.sourceRepositoryRevision ?? '')
    && SHA.test(input.runnerRevision ?? '')
    && typeof input.initialSeed === 'boolean'
    && typeof input.authorization === 'string'
    && input.authorization.length >= 1
    && input.authorization.length <= 4096
    && !/[\u0000-\u001f\u007f]/u.test(input.authorization)
    && !/^Bearer\s/iu.test(input.authorization);
}

function validMetadata(metadata, input, nowMilliseconds) {
  const workflowRun = ownData(metadata, 'workflow_run');
  const expiresAt = ownData(metadata, 'expires_at');
  const size = ownData(metadata, 'size_in_bytes');
  const providerId = (value) => typeof value === 'number'
    ? (Number.isSafeInteger(value) && value > 0 ? String(value) : null)
    : (typeof value === 'string' && ID.test(value) ? value : null);
  return providerId(ownData(metadata, 'id')) === input.artifactId
    && ownData(metadata, 'name') === `appwrite-test-setup-readback-${input.trustedSha}-${input.sourceRepositoryRevision}`
    && ownData(metadata, 'expired') === false
    && typeof expiresAt === 'string'
    && UTC_TIMESTAMP.test(expiresAt)
    && Number.isFinite(Date.parse(expiresAt))
    && Date.parse(expiresAt) > nowMilliseconds
    && Number.isSafeInteger(size)
    && size >= 22
    && size <= MAX_VERIFICATION_ARCHIVE_BYTES
    && ownData(metadata, 'digest') === input.bundleDigest
    && ownData(metadata, 'archive_download_url') === artifactUrl(input.artifactId)
    && providerId(ownData(workflowRun, 'id')) !== null
    && ownData(workflowRun, 'head_sha') === input.trustedSha;
}

function entriesToBindingSet(entries, input, nowEpochSeconds) {
  if (
    entries.size !== EXPECTED_ARCHIVE_FILES.length
    || [...entries.keys()].sort().some((name, index) => name !== EXPECTED_ARCHIVE_FILES[index])
  ) return blocked();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const manifestText = decoder.decode(entries.get('binding-manifest.json'));
  const manifest = parseCanonicalJsonText(manifestText, true);
  if (manifest === null || !validateManifest(manifest, input)) return blocked();
  for (const record of manifest.files) {
    const bytes = entries.get(record.path);
    if (
      bytes === undefined
      || bytes.length !== record.byteLength
      || sha256Bytes(bytes) !== record.sha256
    ) return blocked();
  }
  const bindings = Object.fromEntries(BINDING_NAMES.map((name) => [
    name, decoder.decode(entries.get(`${name}.txt`)),
  ]));
  const evidence = parseCanonicalJsonText(decoder.decode(entries.get('evidence.json')), true);
  if (evidence === null) return blocked();
  return validateTestCloudBindingSet({ bindings, evidence, input, manifest, nowEpochSeconds });
}

export async function verifyGithubTestCloudBindingArtifact(input, dependencies = {}) {
  try {
    const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
    const now = dependencies.now ?? Date.now;
    if (!validInput(input) || typeof fetchImpl !== 'function' || typeof now !== 'function') {
      return blocked();
    }
    const nowMilliseconds = now();
    if (!Number.isFinite(nowMilliseconds)) return blocked();
    const metadata = await readJson(await fetchImpl(
      `${API_ORIGIN}/repos/${REPOSITORY}/actions/artifacts/${input.artifactId}`,
      { method: 'GET', redirect: 'error', headers: githubHeaders(input.authorization) },
    ));
    if (!validMetadata(metadata, input, nowMilliseconds)) return blocked();
    const redirect = await fetchImpl(artifactUrl(input.artifactId), {
      method: 'GET', redirect: 'manual', headers: githubHeaders(input.authorization),
    });
    const location = redirect?.status === 302
      ? signedArtifactUrl(redirect?.headers?.get?.('location'))
      : null;
    if (location === null) return blocked();
    const response = await fetchImpl(location, {
      method: 'GET',
      redirect: 'error',
      headers: { Accept: 'application/octet-stream', 'User-Agent': 'appwritework-verification-controller' },
    });
    if (response?.status !== 200) return blocked();
    const archive = await readBoundedResponseBytes(response, MAX_VERIFICATION_ARCHIVE_BYTES);
    if (
      archive.length !== ownData(metadata, 'size_in_bytes')
      || sha256Bytes(archive) !== input.bundleDigest
    ) return blocked();
    return entriesToBindingSet(
      extractBoundedZipArchive(archive), input, Math.floor(nowMilliseconds / 1000),
    );
  } catch {
    return blocked();
  }
}

export async function runTestCloudBindingArtifactVerifierCli(
  argv = process.argv.slice(2),
  environment = process.env,
  dependencies = {},
) {
  try {
    if (
      !Array.isArray(argv)
      || argv.length !== 4
      || argv[0] !== '--input'
      || argv[2] !== '--output'
    ) return blocked('TEST_CLOUD_BINDING_ARTIFACT_CLI_INVALID');
    const inputText = await readFile(path.resolve(argv[1]), 'utf8');
    if (!inputText.endsWith('\n') || Buffer.byteLength(inputText, 'utf8') > 65_536) {
      return blocked('TEST_CLOUD_BINDING_ARTIFACT_CLI_INVALID');
    }
    const cliInput = parseCanonicalJsonText(inputText, true);
    if (!exactObject(cliInput, [
      'artifactId', 'bundleDigest', 'initialSeed', 'runnerRevision',
      'sourceRepositoryRevision', 'trustedSha',
    ])) return blocked('TEST_CLOUD_BINDING_ARTIFACT_CLI_INVALID');
    const artifactVerifier = dependencies.artifactVerifier
      ?? verifyGithubTestCloudBindingArtifact;
    if (typeof artifactVerifier !== 'function') {
      return blocked('TEST_CLOUD_BINDING_ARTIFACT_CLI_INVALID');
    }
    const verified = await artifactVerifier({
      ...cliInput,
      authorization: environment.GITHUB_TOKEN,
      repository: environment.GITHUB_REPOSITORY,
    }, dependencies);
    if (verified.status !== 'PASS') return verified;
    const outputPath = path.resolve(argv[3]);
    await mkdir(outputPath, { recursive: false });
    for (const name of BINDING_NAMES) {
      await writeFile(path.join(outputPath, `${name}.txt`), verified.value.bindings[name], {
        encoding: 'utf8', flag: 'wx', mode: 0o600,
      });
    }
    return result('PASS');
  } catch {
    return blocked('TEST_CLOUD_BINDING_ARTIFACT_CLI_INVALID');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outcome = await runTestCloudBindingArtifactVerifierCli();
  if (outcome.status !== 'PASS') {
    process.stderr.write(`BLOCKED ${outcome.diagnostics[0].code}\n`);
    process.exitCode = 1;
  }
}
