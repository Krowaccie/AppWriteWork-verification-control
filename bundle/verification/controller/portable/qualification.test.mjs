import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { canonical, digest } from './bundle.mjs';
import { cacheInputs, validateNodeCache } from './dependency-cache.mjs';
import { controllerVerdict, runSourcePolicyAudit } from './source-policy.mjs';

const verifierRoot = path.resolve(import.meta.dirname, '../../..');
function fixture(t) {
  const base = path.resolve('.local/portable-controller-fixtures'); mkdirSync(base, { recursive: true });
  const root = mkdtempSync(path.join(base, 'qualification-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'verification/core'), { recursive: true });
  writeFileSync(path.join(root, 'verification/core/verification-manifest.v2.json'), readFileSync(path.join(verifierRoot, 'verification/core/verification-manifest.v2.json')));
  writeFileSync(path.join(root, 'package.json'), '{"name":"fixture","version":"1.0.0"}');
  writeFileSync(path.join(root, 'package-lock.json'), '{"name":"fixture","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"}}}');
  execFileSync('git', ['init', '-q', root]);
  execFileSync('git', ['-C', root, '-c', 'user.name=Qualification fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'fixture']);
  return root;
}
test('trusted source-policy audit passes valid source independently without executing candidate tests', (t) => {
  const root = fixture(t);
  const result = runSourcePolicyAudit({ candidateRoot: root, verifierRoot });
  assert.equal(result.status, 'PASS', JSON.stringify(result.errors));
  const verdict = controllerVerdict({ scope: 'source-policy', sourcePolicy: result });
  assert.equal(verdict.status, 'PASS'); assert.equal(verdict.independent, true);
  assert.equal(verdict.independentProductAcceptance, false); assert.equal(verdict.independentRuntimeAcceptance, false);
});
test('candidate policy cannot remove or weaken pinned obligations', (t) => {
  const root = fixture(t); const filename = path.join(root, 'verification/core/verification-manifest.v2.json');
  const original = JSON.parse(readFileSync(filename));
  const removed = structuredClone(original); removed.suites.pop(); writeFileSync(filename, JSON.stringify(removed));
  assert.ok(runSourcePolicyAudit({ candidateRoot: root, verifierRoot }).errors.some((entry) => entry.code === 'PINNED_OBLIGATION_REMOVED'));
  const weakened = structuredClone(original); weakened.suites[0].collection.minimumTests += 1; writeFileSync(filename, JSON.stringify(weakened));
  assert.ok(runSourcePolicyAudit({ candidateRoot: root, verifierRoot }).errors.some((entry) => entry.code === 'PINNED_OBLIGATION_CHANGED'));
});

test('candidate policy JSON is bounded before parsing or unbounded file reads', (t) => {
  const root = fixture(t);
  writeFileSync(path.join(root, 'verification/core/verification-manifest.v2.json'), Buffer.alloc(4 * 1024 * 1024 + 1, 32));
  const result = runSourcePolicyAudit({ candidateRoot: root, verifierRoot });
  assert.equal(result.status, 'BLOCKED');
  assert.ok(result.errors.some(entry => entry.reason === 'CANDIDATE_POLICY_SIZE_LIMIT'));
});

test('malformed candidate policy cannot quote private input bytes in public failure evidence', t => {
  const root = fixture(t), sentinel = 'synthetic-private-payload';
  writeFileSync(path.join(root, 'verification/core/verification-manifest.v2.json'), sentinel);
  const result = runSourcePolicyAudit({ candidateRoot: root, verifierRoot });
  assert.equal(result.status, 'BLOCKED');
  assert.ok(result.errors.some(entry => entry.reason === 'CANDIDATE_POLICY_JSON_INVALID'));
  assert.equal(JSON.stringify(result).includes(sentinel.slice(0, 8)), false);
});
test('unowned runtime input and private configuration prevent a source-policy PASS', (t) => {
  const root = fixture(t);
  writeFileSync(path.join(root, 'unknown-runtime.py'), 'print(1)');
  assert.equal(runSourcePolicyAudit({ candidateRoot: root, verifierRoot }).status, 'BLOCKED');
  writeFileSync(path.join(root, '.env'), 'FIXTURE=true');
  assert.equal(runSourcePolicyAudit({ candidateRoot: root, verifierRoot }).status, 'FAIL');
});
test('runtime verdict enumerates pending capabilities and never upgrades candidate-authored tests', () => {
  const sourcePolicy = { status: 'PASS', policy: 'pinned-source-policy.v1', errors: [], pendingCapabilities: [] };
  const verdict = controllerVerdict({ scope: 'repository', sourcePolicy, result: { status: 'PASS' }, selectedSuites: [{ id: 'native', capabilities: ['docker-linux', 'windows-supervisor'] }] });
  assert.equal(verdict.status, 'BLOCKED'); assert.equal(verdict.independent, false);
  assert.deepEqual(verdict.pendingCapabilities.map((entry) => entry.capability), ['docker-linux', 'windows-supervisor', 'trusted-runtime-assertions:native']);
  assert.equal(controllerVerdict({ scope: 'repository', sourcePolicy, result: { status: 'FAIL' }, selectedSuites: [] }).status, 'FAIL');
});
function prepared(root) {
  const inputs = cacheInputs({ candidateRoot: root, roots: [''] });
  const generation = digest('fixture generation'); const imageId = digest('fixture image');
  const descriptor = { schemaVersion: 'portable-node-cache.v1', imageId, baseImage: imageId, inputDigest: inputs.digest, roots: inputs.roots,
    files: inputs.files.map(({ content: _content, ...entry }) => entry), builderDigest: digest(readFileSync(path.join(import.meta.dirname, 'dependency-cache.mjs'))), verifierManifestDigest: generation,
    installPolicy: 'npm-ci-ignore-scripts-no-private-config.v1' };
  const review = { schemaVersion: 'portable-node-cache-review.v1', descriptorDigest: digest(canonical(descriptor)), imageId, verifierManifestDigest: generation,
    decision: 'APPROVED', reviewer: 'fixture reviewer', reference: 'fixture qualification only', qualificationDigest: digest('fixture qualification') };
  const image = { Id: imageId, Config: { Labels: { 'appwritework.cache.policy': descriptor.installPolicy, 'appwritework.cache.inputs': descriptor.inputDigest,
    'appwritework.cache.builder': descriptor.builderDigest, 'appwritework.cache.verifier': generation } } };
  return { descriptor, review, candidateRoot: root, verifierManifestDigest: generation, inspectImage: () => image };
}
test('cache requires explicit review and exact immutable image identity in addition to labels', (t) => {
  const root = fixture(t); const options = prepared(root);
  assert.equal(validateNodeCache(options).imageId, options.descriptor.imageId);
  assert.throws(() => validateNodeCache({ ...options, review: { ...options.review, decision: 'PENDING' } }), /CACHE_REVIEW_REQUIRED/u);
  assert.throws(() => validateNodeCache({ ...options, inspectImage: () => ({ Id: digest('forged image'), Config: { Labels: {} } }) }), /CACHE_IMAGE_MISMATCH/u);
  assert.throws(() => validateNodeCache({ ...options, verifierManifestDigest: digest('other generation') }), /CACHE_DESCRIPTOR_INVALID/u);
});
test('cache rejects stale lock or package bytes and private/nonregistry dependency sources', (t) => {
  const root = fixture(t); const options = prepared(root);
  writeFileSync(path.join(root, 'package.json'), '{"name":"changed"}');
  assert.throws(() => validateNodeCache(options), /CACHE_STALE_LOCK/u);
  const lock = { lockfileVersion: 3, packages: { 'node_modules/private': { resolved: 'https://user:password@example.invalid/private.tgz', integrity: 'sha512-YQ==' } } };
  writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify(lock));
  assert.throws(() => cacheInputs({ candidateRoot: root, roots: [''] }), /DEPENDENCY_SOURCE_FORBIDDEN/u);
});
