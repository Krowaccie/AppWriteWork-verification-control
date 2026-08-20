import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import { createProductionExactShaGitAdapter } from './production-exact-sha-git-adapter.mjs';

const execFile = promisify(execFileCallback);

test('accepts the exact checkout HTTPS origin without a dot-git suffix', async () => {
  const repositoryRoot = await mkdtemp(path.join(os.tmpdir(), 'controller-origin-test-'));
  try {
    const git = (...args) => execFile('git', args, { cwd: repositoryRoot });
    await git('init');
    await git('config', 'user.email', 'controller-test@example.invalid');
    await git('config', 'user.name', 'Controller Test');
    await writeFile(path.join(repositoryRoot, 'member.txt'), 'trusted member\n', 'utf8');
    await git('add', 'member.txt');
    await git('commit', '-m', 'Add trusted member');
    await git(
      'remote',
      'add',
      'origin',
      'https://github.com/Krowaccie/AppWriteWork-verification-control',
    );
    const revision = (await git('rev-parse', 'HEAD')).stdout.trim();
    const adapter = createProductionExactShaGitAdapter({ repositoryRoot });

    const result = await adapter.readExactSource({
      controllerRepository: 'Krowaccie/AppWriteWork-verification-control',
      controllerRevision: revision,
      paths: ['member.txt'],
    });

    assert.equal(new TextDecoder().decode(result.files[0].bytes), 'trusted member\n');
  } finally {
    await rm(repositoryRoot, { force: true, recursive: true });
  }
});
