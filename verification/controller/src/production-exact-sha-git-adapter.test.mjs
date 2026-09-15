import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { createProductionExactShaGitAdapter } from './production-exact-sha-git-adapter.mjs';

const exec = promisify(execFile);
const REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';

async function fixture(t, { origin = `https://github.com/${REPOSITORY}.git` } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'controller-exact-git-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  await exec('git', ['init', '-q'], { cwd: root });
  await exec('git', ['config', 'user.name', 'Task 4A Test'], { cwd: root });
  await exec('git', ['config', 'user.email', 'task4a@example.invalid'], { cwd: root });
  await exec('git', ['remote', 'add', 'origin', origin], { cwd: root });
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, 'src', 'a.mjs'), 'alpha\n');
  await writeFile(path.join(root, 'src', 'run.sh'), 'run\n');
  if (process.platform !== 'win32') await chmod(path.join(root, 'src', 'run.sh'), 0o755);
  await exec('git', ['add', '.'], { cwd: root });
  await exec('git', ['update-index', '--chmod=+x', 'src/run.sh'], { cwd: root });
  await exec('git', ['commit', '-q', '-m', 'fixture'], { cwd: root });
  const { stdout } = await exec('git', ['rev-parse', 'HEAD'], { cwd: root });
  return { root, sha: stdout.trim() };
}

test('production adapter reads only exact commit blobs and canonical modes for the fixed controller repository', async (t) => {
  const { root, sha } = await fixture(t);
  const adapter = createProductionExactShaGitAdapter({ repositoryRoot: root });
  const result = await adapter.readExactSource({
    controllerRepository: REPOSITORY,
    controllerRevision: sha,
    paths: ['src/a.mjs', 'src/run.sh'],
  });
  assert.deepEqual(result.files.map(({ path: filePath, mode }) => [filePath, mode]), [
    ['src/a.mjs', '100644'],
    ['src/run.sh', '100755'],
  ]);
  assert.equal(new TextDecoder().decode(result.files[0].bytes), 'alpha\n');
  assert.equal(Object.isFrozen(adapter), true);
});

test('production adapter admits the exact HTTPS controller origin without dot-git suffix', async (t) => {
  const { root, sha } = await fixture(t, {
    origin: `https://github.com/${REPOSITORY}`,
  });
  const adapter = createProductionExactShaGitAdapter({ repositoryRoot: root });
  const result = await adapter.readExactSource({
    controllerRepository: REPOSITORY,
    controllerRevision: sha,
    paths: ['src/a.mjs'],
  });
  assert.equal(new TextDecoder().decode(result.files[0].bytes), 'alpha\n');
});

test('production adapter rejects mutable refs, repository substitution, unsafe paths, missing paths, and dirty inputs', async (t) => {
  const { root, sha } = await fixture(t);
  const adapter = createProductionExactShaGitAdapter({ repositoryRoot: root });
  const cases = [
    { controllerRepository: REPOSITORY, controllerRevision: 'HEAD', paths: ['src/a.mjs'] },
    { controllerRepository: 'Krowaccie/AppWriteWork', controllerRevision: sha, paths: ['src/a.mjs'] },
    { controllerRepository: REPOSITORY, controllerRevision: sha, paths: ['../src/a.mjs'] },
    { controllerRepository: REPOSITORY, controllerRevision: sha, paths: ['src/missing.mjs'] },
    { controllerRepository: REPOSITORY, controllerRevision: sha, paths: ['src/A.mjs', 'src/a.mjs'] },
  ];
  for (const candidate of cases) {
    await assert.rejects(() => adapter.readExactSource(candidate));
  }
  await writeFile(path.join(root, 'src', 'a.mjs'), 'dirty\n');
  await assert.rejects(() => adapter.readExactSource({
    controllerRepository: REPOSITORY,
    controllerRevision: sha,
    paths: ['src/a.mjs'],
  }));
});
