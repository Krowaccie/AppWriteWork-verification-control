import assert from 'node:assert/strict';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  SOURCE_ARTIFACT_UPLOAD_LIMITS,
  SOURCE_ARTIFACT_UPLOAD_MEMBERS,
  createValidatedArtifactUploadClient,
} from '../host/validated-artifact-upload.mjs';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const REVISION = 'b'.repeat(40);

function pass(value = null) {
  return Object.freeze({ diagnostics: Object.freeze([]), status: 'PASS', value });
}

function deferred() {
  let resolve;
  const promise = new Promise((settle) => { resolve = settle; });
  return { promise, resolve };
}

function statView(stat, { linked = false, mode = null } = {}) {
  return Object.freeze({
    isDirectory: () => stat.isDirectory(),
    isFile: () => stat.isFile(),
    isSymbolicLink: () => linked || stat.isSymbolicLink(),
    mode: mode === null ? stat.mode : ((stat.mode & ~0o777) | mode),
  });
}

function filesystemFixture({ writeGate = null } = {}) {
  const overrides = { linkedPath: null, modePath: null };
  let writeDelayed = false;
  const fileSystem = Object.freeze({
    chmod,
    async lstat(target) {
      const stat = await lstat(target);
      const resolved = path.resolve(target);
      return statView(stat, {
        linked: overrides.linkedPath === resolved,
        mode: stat.isFile()
          ? (overrides.modePath === resolved ? 0o644 : 0o600)
          : null,
      });
    },
    mkdir,
    mkdtemp,
    async open(...args) {
      const handle = await open(...args);
      return Object.freeze({
        close: () => handle.close(),
        async write(...writeArgs) {
          if (writeGate !== null && !writeDelayed) {
            writeDelayed = true;
            writeGate.started.resolve();
            await writeGate.release.promise;
          }
          return handle.write(...writeArgs);
        },
      });
    },
    readdir,
    realpath,
    rm,
  });
  return { fileSystem, overrides };
}

async function fixture(t, { officialUpload = null, runtime = true, writeGate = null } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'a1-upload-test-'));
  const candidateWorkspaceRoot = path.join(root, 'candidate');
  const controllerTempRoot = path.join(root, 'controller');
  await mkdir(candidateWorkspaceRoot, { recursive: true });
  await mkdir(controllerTempRoot, { recursive: true });
  t.after(() => rm(root, { force: true, recursive: true }));
  const calls = [];
  const { fileSystem, overrides } = filesystemFixture({ writeGate });
  const officialArtifactClient = Object.freeze({
    async uploadArtifact(...args) {
      calls.push(args);
      if (officialUpload !== null) return officialUpload(...args);
      return Object.freeze({ digest: DIGEST, id: 17, size: 39 });
    },
  });
  const githubRuntimeBinding = runtime
    ? Object.freeze({
      async assertAvailable() { return pass(); },
      operatingSystem: 'linux',
      protocolVersion: 'github-actions-artifact-runtime.v1',
    })
    : null;
  const client = createValidatedArtifactUploadClient({
    candidateWorkspaceRoot,
    controllerTempRoot,
    fileSystem,
    githubRuntimeBinding,
    officialArtifactClient,
  });
  return {
    calls,
    candidateWorkspaceRoot,
    client,
    controllerTempRoot,
    fileSystem,
    overrides,
  };
}

function details(overrides = {}) {
  return Object.freeze({
    artifactManifestDigest: DIGEST,
    artifactName: `verification-artifacts-${REVISION}`,
    memberCount: 39,
    ...overrides,
  });
}

function chunk(memberIndex, bytes = Uint8Array.of(memberIndex + 1), overrides = {}) {
  return Object.freeze({
    bytes,
    endOfArtifact: memberIndex === SOURCE_ARTIFACT_UPLOAD_MEMBERS.length - 1,
    endOfMember: true,
    memberId: SOURCE_ARTIFACT_UPLOAD_MEMBERS[memberIndex].memberId,
    offset: 0,
    ...overrides,
  });
}

async function writeAll(session) {
  for (let index = 0; index < SOURCE_ARTIFACT_UPLOAD_MEMBERS.length; index += 1) {
    assert.equal((await session.writeMemberChunk(chunk(index))).status, 'PASS');
  }
}

test('exposes an exact frozen upload client and fails closed without GitHub runtime', async (t) => {
  const { client } = await fixture(t, { runtime: false });

  assert.equal(Object.isFrozen(client), true);
  assert.deepEqual(Object.keys(client), ['openArtifact']);
  assert.equal(await client.openArtifact(details()), null);
  assert.equal(await client.openArtifact(details({ memberCount: 38 })), null);
});

test('maps the exact 39 members to direct private files and uploads them once', async (t) => {
  let observedStage = null;
  const state = await fixture(t, {
    officialUpload: async (name, exactFiles, stagingRoot, options) => {
      observedStage = stagingRoot;
      assert.equal(name, `verification-artifacts-${REVISION}`);
      assert.deepEqual(options, { compressionLevel: 0 });
      assert.equal(exactFiles.length, 39);
      assert.equal(path.relative(state.candidateWorkspaceRoot, stagingRoot).startsWith('..'), true);
      assert.deepEqual(
        exactFiles.map((file) => path.relative(stagingRoot, file).replaceAll('\\', '/')),
        SOURCE_ARTIFACT_UPLOAD_MEMBERS.map(({ relativePath }) => relativePath),
      );
      for (let index = 0; index < exactFiles.length; index += 1) {
        const stat = await state.fileSystem.lstat(exactFiles[index]);
        assert.equal(stat.isFile(), true);
        assert.equal(stat.isSymbolicLink(), false);
        assert.equal(stat.mode & 0o777, 0o600);
        assert.deepEqual(await readFile(exactFiles[index]), Buffer.of(index + 1));
      }
      return Object.freeze({ digest: DIGEST, id: 42, size: 39 });
    },
  });
  const session = await state.client.openArtifact(details());

  assert.equal(Object.isFrozen(session), true);
  assert.deepEqual(Object.keys(session).sort(), ['abortAndJoin', 'complete', 'writeMemberChunk']);
  await writeAll(session);
  assert.equal((await session.complete()).status, 'PASS');
  assert.equal(state.calls.length, 1);
  await assert.rejects(lstat(observedStage), { code: 'ENOENT' });
});

test('rejects wrong keys, member order, offsets, end flags, and fixed limits', async (t) => {
  assert.deepEqual(SOURCE_ARTIFACT_UPLOAD_LIMITS, Object.freeze({
    maxArtifactBytes: 256 * 1024 * 1024,
    maxMemberBytes: 128 * 1024 * 1024,
  }));

  for (const invalidChunk of [
    Object.freeze({ ...chunk(0), extra: true }),
    chunk(1),
    chunk(0, Uint8Array.of(1), { offset: 1 }),
    chunk(0, Uint8Array.of(1), { endOfArtifact: true }),
    chunk(0, Uint8Array.of(1), { endOfMember: false, endOfArtifact: true }),
  ]) {
    const { client } = await fixture(t);
    const session = await client.openArtifact(details());
    assert.equal((await session.writeMemberChunk(invalidChunk)).status, 'FAIL');
    assert.equal((await session.abortAndJoin()).status, 'PASS');
  }

  const { client } = await fixture(t);
  const session = await client.openArtifact(details());
  const oversized = new Uint8Array(SOURCE_ARTIFACT_UPLOAD_LIMITS.maxMemberBytes + 1);
  assert.equal((await session.writeMemberChunk(chunk(0, oversized))).status, 'FAIL');
  assert.equal((await session.abortAndJoin()).status, 'PASS');
});

test('copies chunk bytes and enforces monotonically exact offsets', async (t) => {
  let observed;
  const writeGate = { release: deferred(), started: deferred() };
  const state = await fixture(t, {
    officialUpload: async (_name, exactFiles) => {
      observed = await readFile(exactFiles[0]);
      return Object.freeze({ digest: DIGEST, id: 19, size: 41 });
    },
    writeGate,
  });
  const session = await state.client.openArtifact(details());
  const original = Uint8Array.of(1, 2);
  const firstWrite = session.writeMemberChunk(chunk(0, original, {
    endOfArtifact: false,
    endOfMember: false,
  }));
  await writeGate.started.promise;
  original.fill(9);
  writeGate.release.resolve();
  assert.equal((await firstWrite).status, 'PASS');
  assert.equal((await session.writeMemberChunk(chunk(0, Uint8Array.of(3), {
    endOfArtifact: false,
    endOfMember: true,
    offset: 2,
  }))).status, 'PASS');
  for (let index = 1; index < SOURCE_ARTIFACT_UPLOAD_MEMBERS.length; index += 1) {
    assert.equal((await session.writeMemberChunk(chunk(index))).status, 'PASS');
  }
  assert.equal((await session.complete()).status, 'PASS');
  assert.deepEqual(observed, Buffer.of(1, 2, 3));
});

test('rejects linked or non-private staged members before upload', async (t) => {
  for (const defect of ['link', 'mode']) {
    const state = await fixture(t, {
      officialUpload: async () => assert.fail('upload must not run for an unsafe stage'),
    });
    const session = await state.client.openArtifact(details());
    await writeAll(session);
    const candidates = [];
    async function findFirst(root) {
      for (const entry of await readdir(root, { withFileTypes: true })) {
        const target = path.join(root, entry.name);
        if (entry.isDirectory()) await findFirst(target);
        else candidates.push(path.resolve(await realpath(target)));
      }
    }
    await findFirst(state.controllerTempRoot);
    if (defect === 'link') state.overrides.linkedPath = candidates[0];
    else state.overrides.modePath = candidates[0];
    assert.equal((await session.complete()).status, 'FAIL');
    assert.equal(state.calls.length, 0, defect);
  }
});

test('complete and abort are single-flight, join upload, and remove staging', async (t) => {
  const gate = deferred();
  const started = deferred();
  let stagingRoot;
  const state = await fixture(t, {
    officialUpload: async (_name, _files, root) => {
      stagingRoot = root;
      started.resolve();
      await gate.promise;
      return Object.freeze({ digest: DIGEST, id: 23, size: 39 });
    },
  });
  const session = await state.client.openArtifact(details());
  await writeAll(session);

  const firstComplete = session.complete();
  const secondComplete = session.complete();
  const firstAbort = session.abortAndJoin();
  const secondAbort = session.abortAndJoin();
  assert.equal(firstComplete, secondComplete);
  assert.equal(firstAbort, secondAbort);
  await started.promise;
  assert.equal(state.calls.length, 1);
  gate.resolve();
  assert.deepEqual(
    (await Promise.all([firstComplete, secondComplete, firstAbort, secondAbort])).map(({ status }) => status),
    ['PASS', 'PASS', 'PASS', 'PASS'],
  );
  await assert.rejects(lstat(stagingRoot), { code: 'ENOENT' });
});

test('abort without completion closes and removes the private stage', async (t) => {
  const state = await fixture(t);
  const session = await state.client.openArtifact(details());
  assert.equal((await session.writeMemberChunk(chunk(0))).status, 'PASS');
  const first = session.abortAndJoin();
  const second = session.abortAndJoin();
  assert.equal(first, second);
  assert.deepEqual((await Promise.all([first, second])).map(({ status }) => status), ['PASS', 'PASS']);
  assert.equal(state.calls.length, 0);
});
