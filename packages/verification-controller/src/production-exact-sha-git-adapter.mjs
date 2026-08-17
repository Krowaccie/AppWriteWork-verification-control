import { execFile as execFileCallback } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const CONTROLLER_REPOSITORY = 'Krowaccie/AppWriteWork-verification-control';
const SHA = /^[0-9a-f]{40}$/u;
const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u;
const WINDOWS_RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu;

export class ExactShaGitAdapterError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ExactShaGitAdapterError';
    this.code = code;
  }
}

function fail(code) {
  throw new ExactShaGitAdapterError(code);
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

function exactObject(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const names = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) return null;
  return value;
}

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function validPaths(paths) {
  if (!Array.isArray(paths) || paths.length === 0) return null;
  const copy = [...paths];
  if (copy.some((value) => !safePath(value))) return null;
  if (copy.some((value, index) => index > 0 && ordinal(copy[index - 1], value) >= 0)) return null;
  const identities = copy.map((value) => value.toLowerCase());
  if (new Set(identities).size !== identities.length) return null;
  for (let left = 0; left < identities.length; left += 1) {
    for (let right = left + 1; right < identities.length; right += 1) {
      if (
        identities[left].startsWith(`${identities[right]}/`)
        || identities[right].startsWith(`${identities[left]}/`)
      ) return null;
    }
  }
  return copy;
}

function validOrigin(value) {
  return value === `https://github.com/${CONTROLLER_REPOSITORY}.git`
    || value === `git@github.com:${CONTROLLER_REPOSITORY}.git`
    || value === `ssh://git@github.com/${CONTROLLER_REPOSITORY}.git`;
}

export function createProductionExactShaGitAdapter(args) {
  const input = exactObject(args, ['repositoryRoot']);
  if (input === null || typeof input.repositoryRoot !== 'string' || !path.isAbsolute(input.repositoryRoot)) {
    fail('EXACT_SHA_GIT_ADAPTER_CONFIG_INVALID');
  }
  const repositoryRoot = path.resolve(input.repositoryRoot);
  const rootIdentity = realpath(path.resolve(repositoryRoot));

  const adapter = {
    async readExactSource(request) {
      const candidate = exactObject(request, [
        'controllerRepository', 'controllerRevision', 'paths',
      ]);
      const paths = candidate === null ? null : validPaths(candidate.paths);
      if (
        candidate === null
        || candidate.controllerRepository !== CONTROLLER_REPOSITORY
        || !SHA.test(candidate.controllerRevision ?? '')
        || paths === null
      ) fail('EXACT_SHA_GIT_REQUEST_INVALID');

      const expectedRoot = await rootIdentity;
      if (await realpath(repositoryRoot) !== expectedRoot) fail('EXACT_SHA_GIT_ROOT_INVALID');
      const options = { cwd: expectedRoot, encoding: 'buffer', maxBuffer: 80 * 1024 * 1024 };
      const origin = (await execFile('git', ['remote', 'get-url', 'origin'], options)).stdout.toString('utf8').trim();
      if (!validOrigin(origin)) fail('EXACT_SHA_GIT_REPOSITORY_INVALID');
      const status = (await execFile('git', ['status', '--porcelain=v1', '-uall'], options)).stdout;
      if (status.length !== 0) fail('EXACT_SHA_GIT_DIRTY');
      const type = (await execFile('git', ['cat-file', '-t', candidate.controllerRevision], options)).stdout.toString('ascii').trim();
      if (type !== 'commit') fail('EXACT_SHA_GIT_REVISION_INVALID');
      const resolved = (await execFile('git', ['rev-parse', `${candidate.controllerRevision}^{commit}`], options)).stdout.toString('ascii').trim();
      if (resolved !== candidate.controllerRevision) fail('EXACT_SHA_GIT_REVISION_INVALID');

      const files = [];
      for (const requestedPath of paths) {
        const tree = (await execFile(
          'git',
          ['ls-tree', '-z', candidate.controllerRevision, '--', requestedPath],
          options,
        )).stdout;
        const match = /^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40})\t([^\0]+)\0$/u.exec(tree.toString('utf8'));
        if (
          match === null
          || match[4] !== requestedPath
          || !['100644', '100755'].includes(match[1])
          || match[2] !== 'blob'
        ) fail('EXACT_SHA_GIT_ENTRY_INVALID');
        const blob = (await execFile('git', ['cat-file', 'blob', match[3]], options)).stdout;
        files.push(Object.freeze({
          path: requestedPath,
          mode: match[1],
          bytes: new Uint8Array(blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength)),
        }));
      }
      return Object.freeze({ files: Object.freeze(files) });
    },
  };
  return Object.freeze(adapter);
}
