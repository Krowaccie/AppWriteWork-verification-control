import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { MANIFEST_NAME, canonical, digest, exportBundle, resolveTrustedPath, verifyBundle, verifyPin } from './bundle.mjs';
import { containmentPlan, readObservationTar, validateContainedRuntime } from './contained-runner.mjs';
import { controllerMain } from './cli.mjs';

const FILES = ['verification/controller/portable/bundle.mjs', 'verification/controller/portable/cli.mjs', 'verification/controller/portable/source-set.v1.json',
  'verification/portable/cli.mjs', 'verification/core/portable-registry.mjs', 'verification/core/verification-manifest.v2.json'];
function fixture(t) {
  const fixtureBase = path.resolve('.local/portable-controller-fixtures');
  mkdirSync(fixtureBase, { recursive: true });
  const root = mkdtempSync(path.join(fixtureBase, 'aww-verifier-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'); mkdirSync(source);
  for (const filename of FILES) {
    mkdirSync(path.dirname(path.join(source, filename)), { recursive: true });
    const bytes = filename.endsWith('source-set.v1.json') ? canonical({ schemaVersion: 'portable-verifier-source-set.v1', files: FILES })
      : filename.endsWith('.json') ? '{"required":["trusted"]}' : 'export const version = 1;\n';
    writeFileSync(path.join(source, filename), bytes);
  }
  execFileSync('git', ['init', '-q', source]);
  execFileSync('git', ['-C', source, '-c', 'user.name=Verifier fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'fixture']);
  return { root, source, output: path.join(root, 'bundle') };
}
function reviewed(exported) {
  const checked = verifyBundle({ bundleRoot: exported.output, expectedDigest: exported.manifestDigest });
  return { schemaVersion: 'portable-verifier-pin.v1', manifestDigest: checked.manifestDigest, sourceRevision: checked.manifest.source.baseRevision,
    registryDigest: checked.registryDigest, review: { decision: 'APPROVED', reviewer: 'fixture reviewer', reference: 'fixture-only review', qualificationDigest: digest('fixture qualification') } };
}
function changeManifest(exported, mutate) {
  const filename = path.join(exported.output, MANIFEST_NAME);
  const manifest = JSON.parse(readFileSync(filename)); mutate(manifest);
  writeFileSync(filename, `${canonical(manifest)}\n`);
  return digest(canonical(manifest));
}

test('minimal bundle exports only explicit verifier files, has byte identity and verifies reviewed pin', (t) => {
  const fixtureValue = fixture(t);
  writeFileSync(path.join(fixtureValue.source, 'private-product.txt'), 'private product');
  const exported = exportBundle({ sourceRoot: fixtureValue.source, output: fixtureValue.output });
  const checked = verifyBundle({ bundleRoot: exported.output, expectedDigest: exported.manifestDigest });
  assert.equal(checked.manifest.source.binding, 'base-revision-and-exported-bytes');
  assert.deepEqual(checked.manifest.files.map((entry) => entry.path), [...FILES].sort());
  assert.equal(verifyPin({ bundleRoot: exported.output, pin: reviewed(exported) }).manifestDigest, exported.manifestDigest);
});
test('changed candidate registry is never consulted when verifying pinned bundle', (t) => {
  const value = fixture(t); const exported = exportBundle({ sourceRoot: value.source, output: value.output }); const pin = reviewed(exported);
  writeFileSync(path.join(value.source, 'verification/core/verification-manifest.v2.json'), '{"required":[]}');
  assert.equal(verifyPin({ bundleRoot: value.output, pin, candidateRoot: value.source }).registryDigest, pin.registryDigest);
});
test('unreviewed and stale pins fail; review-template is never activation', (t) => {
  const value = fixture(t); const exported = exportBundle({ sourceRoot: value.source, output: value.output }); const pin = reviewed(exported);
  assert.throws(() => verifyPin({ bundleRoot: value.output, pin: { ...pin, review: { ...pin.review, decision: 'PENDING' } } }), /PIN_REVIEW_REQUIRED/u);
  assert.throws(() => verifyPin({ bundleRoot: value.output, pin: { ...pin, registryDigest: digest('wrong') } }), /PIN_IDENTITY_MISMATCH/u);
  assert.throws(() => verifyPin({ bundleRoot: value.output, pin: { ...pin, sourceRevision: 'f'.repeat(40) } }), /PIN_IDENTITY_MISMATCH/u);
  assert.throws(() => verifyPin({ bundleRoot: value.output, pin, candidateRoot: value.root }), /CANDIDATE_VERIFIER_OVERLAP/u);
});

test('a different launcher cannot execute its own imported executor against an approved bundle', async t => {
  const value = fixture(t); const exported = exportBundle({ sourceRoot: value.source, output: value.output });
  const pin = path.join(value.root, 'external-pin.json'); writeFileSync(pin, canonical(reviewed(exported)));
  await assert.rejects(controllerMain(['run', '--bundle', value.output, '--pin', pin, '--candidate', value.source,
    '--output', path.join(value.root, 'evidence'), '--scope', 'source-policy'], { print: () => {} }), /PINNED_BUNDLE_LAUNCHER_REQUIRED/);
});
test('file or manifest tampering, unlisted files and weakened runtime fail verification', (t) => {
  const value = fixture(t); const exported = exportBundle({ sourceRoot: value.source, output: value.output });
  writeFileSync(path.join(value.output, 'verification/portable/cli.mjs'), 'weakened');
  assert.throws(() => verifyBundle({ bundleRoot: value.output, expectedDigest: exported.manifestDigest }), /BUNDLE_FILE_DIGEST_MISMATCH/u);
  writeFileSync(path.join(value.output, 'verification/portable/cli.mjs'), 'export const version = 1;\n');
  writeFileSync(path.join(value.output, 'private.env'), 'private');
  assert.throws(() => verifyBundle({ bundleRoot: value.output, expectedDigest: exported.manifestDigest }), /BUNDLE_INVENTORY_MISMATCH/u);
  rmSync(path.join(value.output, 'private.env'));
  const weakened = changeManifest(exported, (manifest) => { manifest.runtime.dockerRequiredForIndependentExecution = false; });
  assert.throws(() => verifyBundle({ bundleRoot: value.output, expectedDigest: weakened }), /BUNDLE_MANIFEST_INVALID/u);
});
test('private paths and traversal cannot enter source set', (t) => {
  const value = fixture(t);
  for (const extra of ['apps/web/src/private.ts', '.env', 'verification/core/../private.json', 'verification/core/private.json']) {
    writeFileSync(path.join(value.source, 'verification/controller/portable/source-set.v1.json'), canonical({ schemaVersion: 'portable-verifier-source-set.v1', files: [...FILES, extra] }));
    assert.throws(() => exportBundle({ sourceRoot: value.source, output: value.output }), /PRIVATE_OR_UNREVIEWED_EXPORT_PATH|UNSAFE_EXPORT_PATH/u);
  }
});
test('missing import and embedded credentials reject export', (t) => {
  const value = fixture(t); const filename = path.join(value.source, 'verification/portable/cli.mjs');
  writeFileSync(filename, "import './missing.mjs';\n");
  assert.throws(() => exportBundle({ sourceRoot: value.source, output: value.output }), /EXPORT_IMPORT_MISSING/u);
  writeFileSync(filename, `const key = "${'-----BEGIN ' + 'PRIVATE KEY-----'}";`);
  assert.throws(() => exportBundle({ sourceRoot: value.source, output: value.output }), /EXPORT_SECRET_DETECTED/u);
});
test('symlink source escaping the source root fails closed', (t) => {
  const value = fixture(t); const filename = path.join(value.source, 'verification/portable/cli.mjs');
  rmSync(filename);
  try { symlinkSync(path.join(value.root, 'outside'), filename); }
  catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t.skip('host has no symlink capability'); return; } throw error; }
  assert.throws(() => exportBundle({ sourceRoot: value.source, output: value.output }), /EXPORT_SYMLINK_OR_ESCAPE/u);
});
test('trusted evidence paths reject output ancestors redirected into the candidate', (t) => {
  const value = fixture(t);
  const alias = path.join(value.root, 'candidate-alias');
  try { symlinkSync(value.source, alias, process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t.skip('host has no link capability'); return; } throw error; }
  assert.throws(() => resolveTrustedPath(path.join(alias, 'new/evidence'), [value.source]), /TRUSTED_PATH_LINK_FORBIDDEN/u);
  assert.throws(() => resolveTrustedPath(path.join(value.source, 'new/evidence'), [value.source]), /TRUSTED_PATH_OVERLAP/u);
  assert.equal(resolveTrustedPath(path.join(value.root, 'new/evidence'), [value.source]), path.join(value.root, 'new/evidence'));
});
test('container plan strips secrets, maps only candidate/output and rejects privileged capabilities', () => {
  const candidateRoot = path.resolve('candidate'); const output = path.resolve('observations');
  const command = { executable: process.execPath, cwd: candidateRoot, args: ['--test', path.join(candidateRoot, 'test.mjs')], env: { CI: '1', SECRET_TOKEN: 'never-copy' } };
  const images = { node: `node@sha256:${'a'.repeat(64)}` };
  const plan = containmentPlan(command, { candidateRoot, output, images, suite: { prerequisites: ['node-24'] } });
  assert.deepEqual(plan.env, { CI: '1' }); assert.equal(plan.args[1], '/work/test.mjs');
  assert.throws(() => containmentPlan(command, { candidateRoot, output, images: { node: 'node:latest' } }), /IMAGE_DIGEST_REQUIRED/u);
  assert.throws(() => containmentPlan(command, { candidateRoot, output, images, suite: { prerequisites: ['docker-linux'] } }), /PRIVILEGED_CAPABILITY/u);
});
test('malformed archive observations cannot be extracted', () => {
  assert.throws(() => readObservationTar(Buffer.alloc(512, 65)), /OBSERVATION_ARCHIVE_TRUNCATED/u);
  assert.throws(() => readObservationTar(Buffer.alloc(9 * 1024 * 1024)), /OBSERVATION_ARCHIVE_LIMIT/u);
});
test('container runtime probes require exact Node and supported Python minor', () => {
  assert.equal(validateContainedRuntime('node', 'v24.11.1\n'), 'v24.11.1');
  assert.equal(validateContainedRuntime('python', 'Python 3.12.13'), 'Python 3.12.13');
  assert.throws(() => validateContainedRuntime('node', 'v24.12.0'), /RUNTIME_MISMATCH/u);
  assert.throws(() => validateContainedRuntime('python', 'Python 3.14.0'), /RUNTIME_MISMATCH/u);
});

function observationTar(name, type = '0', body = '<testsuite/>') {
  const header = Buffer.alloc(512);
  header.write(name, 0); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
  header.write(`${Buffer.byteLength(body).toString(8).padStart(11, '0')}\0`, 124);
  header.write('00000000000\0', 136); header.fill(32, 148, 156); header.write(type, 156);
  const checksum = [...header].reduce((sum, value) => sum + value, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
  return Buffer.concat([header, Buffer.from(body), Buffer.alloc((512 - Buffer.byteLength(body) % 512) % 512), Buffer.alloc(1024)]);
}
test('bounded observation tar accepts data and rejects traversal, links, duplicates and trailing entries', () => {
  const archive = observationTar('observations/junit.xml');
  assert.equal(readObservationTar(archive).get('junit.xml').toString(), '<testsuite/>');
  assert.throws(() => readObservationTar(observationTar('observations/../result.json')), /UNSAFE_ENTRY/u);
  assert.throws(() => readObservationTar(observationTar('observations/junit.xml', '2')), /UNSAFE_ENTRY/u);
  assert.throws(() => readObservationTar(Buffer.concat([archive.subarray(0, archive.length - 1024), archive])), /UNSAFE_ENTRY/u);
  assert.throws(() => readObservationTar(Buffer.concat([archive, observationTar('observations/result.json')])), /TRAILING_DATA/u);
});

function editTar(archive, edit) {
  const copy = Buffer.from(archive);
  edit(copy);
  copy.fill(32, 148, 156);
  const checksum = [...copy.subarray(0, 512)].reduce((sum, value) => sum + value, 0);
  copy.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148);
  return copy;
}
test('observation parser rejects truncation, missing end markers and malformed fields before host writes', () => {
  const archive = observationTar('observations/junit.xml');
  for (const missing of [1, 511, 512, 513, 1024, archive.length - 500]) {
    assert.throws(() => readObservationTar(archive.subarray(0, archive.length - missing)), /TRUNCATED|TERMINATOR_REQUIRED/u);
  }
  assert.throws(() => readObservationTar(editTar(archive, (bytes) => { bytes[512 + 12] = 1; })), /PADDING_INVALID/u);
  assert.throws(() => readObservationTar(editTar(archive, (bytes) => { bytes.write('target', 157); })), /ARCHIVE_INVALID/u);
  assert.throws(() => readObservationTar(editTar(archive, (bytes) => { bytes.write('nested', 345); })), /ARCHIVE_INVALID/u);
  assert.throws(() => readObservationTar(editTar(archive, (bytes) => { bytes[124] = 0xb0; })), /ARCHIVE_INVALID/u);
  const badChecksum = Buffer.from(archive); badChecksum[100] ^= 1;
  assert.throws(() => readObservationTar(badChecksum), /CHECKSUM/u);
});
test('only bounded flat expected observation members are accepted', () => {
  for (const name of ['/result.json', '../result.json', 'observations/nested/result.json', 'observations\\result.json', 'observations/other.json']) {
    assert.throws(() => readObservationTar(observationTar(name)), /UNSAFE_ENTRY/u);
  }
  for (const type of ['1', '2', '3', '4', '6', 'x', 'g']) assert.throws(() => readObservationTar(observationTar('observations/result.json', type)), /UNSAFE_ENTRY/u);
  assert.throws(() => readObservationTar(observationTar('observations/result.json', '0', 'x'.repeat(4 * 1024 * 1024 + 1))), /ARCHIVE_INVALID/u);
  const first = observationTar('observations/result.json', '0', 'x'.repeat(3 * 1024 * 1024));
  const second = observationTar('observations/junit.xml', '0', 'x'.repeat(2 * 1024 * 1024));
  assert.throws(() => readObservationTar(Buffer.concat([first.subarray(0, first.length - 1024), second])), /ARCHIVE_LIMIT/u);
});

