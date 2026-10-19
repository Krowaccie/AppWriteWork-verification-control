import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCommandEnvironment } from './process.mjs';

const NULL_FILE = process.platform === 'win32' ? 'NUL' : '/dev/null';
const SAFE_GIT_ARGUMENTS = Object.freeze([
  '--no-pager', '--no-optional-locks', '--no-replace-objects',
  '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
  '-c', 'core.longpaths=true',
  // A trusted regular file cannot contain executable hook children.
  '-c', `core.hooksPath=${fileURLToPath(import.meta.url)}`,
  '-c', 'protocol.allow=never', '-c', 'submodule.recurse=false',
  '-c', 'diff.external=', '-c', `core.attributesFile=${NULL_FILE}`,
  '-c', `core.excludesFile=${NULL_FILE}`,
]);

export function portableGitEnvironment(env = process.env) {
  return {
    ...buildCommandEnvironment(env), LANG: 'C', LC_ALL: 'C', TZ: 'UTC',
    GIT_ATTR_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: NULL_FILE, GIT_CONFIG_NOSYSTEM: '1',
    GIT_NO_LAZY_FETCH: '1', GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0', GIT_LITERAL_PATHSPECS: '1',
  };
}

function runGit(root, args, { allowAbsentConfig = false, bindWorkTree = true } = {}) {
  try {
    return execFileSync('git', [...SAFE_GIT_ARGUMENTS, '-c', `safe.directory=${path.resolve(root)}`, '-C', root, ...(bindWorkTree ? [`--work-tree=${path.resolve(root)}`] : []), ...args], { encoding: 'utf8', env: portableGitEnvironment(), maxBuffer: 32 * 1024 * 1024, timeout: 30_000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    if (allowAbsentConfig && error.status === 1) return '';
    throw new Error(`GIT_SOURCE_UNAVAILABLE:${error.code ?? error.status ?? 'unknown'}`);
  }
}

export function git(root, args) {
  // Reading names invokes no configured command. Override every local filter
  // before status/diff can refresh the index or normalize working-tree bytes.
  const names = runGit(root, ['config', '--null', '--name-only', '--get-regexp', '^filter\\..*\\.(clean|process|smudge|required)$'], { allowAbsentConfig: true }).split('\0').filter(Boolean);
  const filters = new Set(names.map((name) => name.match(/^(filter\..+)\.(?:clean|process|smudge|required)$/u)?.[1]).filter(Boolean));
  const overrides = [...filters].flatMap((name) => ['-c', `${name}.clean=`, '-c', `${name}.process=`, '-c', `${name}.smudge=`, '-c', `${name}.required=false`]);
  return runGit(root, [...overrides, ...args]);
}

export function validatePaths(paths) {
  if (!Array.isArray(paths) || paths.some((p) => typeof p !== 'string' || !p || p.includes('\\') || p.includes('\0') || /[\r\n]/u.test(p) || p.startsWith('/') || /^[A-Za-z]:/u.test(p) || p.split('/').some((part) => !part || part === '.' || part === '..'))) {
    throw new Error('INVALID_CHANGED_PATHS: expected safe repository-relative paths');
  }
  return [...new Set(paths)].sort();
}

export const SOURCE_LIMITS = Object.freeze({ maxFiles: 20_000, maxFileBytes: 32 * 1024 * 1024, maxSourceBytes: 512 * 1024 * 1024 });

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function checkedRoot(root) {
  const resolved = path.resolve(root);
  const metadata = lstatSync(resolved);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || !samePath(realpathSync(resolved), resolved)) throw new Error('SOURCE_ROOT_UNSAFE');
  // Establish the real repository root before binding --work-tree. Otherwise
  // Git can discover a parent repository and reinterpret its index below an
  // arbitrary subdirectory, falsely hashing the parent files as deletions.
  const gitRoot = runGit(resolved, ['rev-parse', '--show-toplevel'], { bindWorkTree: false }).trim();
  if (!gitRoot || !samePath(path.resolve(gitRoot), resolved) || !samePath(realpathSync(gitRoot), resolved)) throw new Error('SOURCE_ROOT_NOT_REPOSITORY_TOPLEVEL');
  return resolved;
}

function checkedSourceFile(root, relative) {
  let filename = root;
  const parts = relative.split('/');
  for (let index = 0; index < parts.length; index += 1) {
    filename = path.join(filename, parts[index]);
    let metadata;
    try { metadata = lstatSync(filename); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    if (metadata.isSymbolicLink() || !samePath(realpathSync(filename), filename)) throw new Error('SOURCE_PATH_ESCAPE');
    if (index < parts.length - 1 && !metadata.isDirectory()) throw new Error('SOURCE_ANCESTOR_NOT_DIRECTORY');
    if (index === parts.length - 1) {
      if (!metadata.isFile()) throw new Error('SOURCE_FILE_KIND_UNSUPPORTED');
      return { filename, metadata };
    }
  }
  throw new Error('SOURCE_PATH_INVALID');
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function boundedFileDigest(root, relative, checked, limits) {
  const descriptor = openSync(checked.filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor);
    const current = checkedSourceFile(root, relative);
    if (!opened.isFile() || !current || !sameFile(opened, checked.metadata) || !sameFile(opened, current.metadata)) throw new Error('SOURCE_FILE_CHANGED_BEFORE_READ');
    if (opened.size > limits.maxFileBytes) throw new Error('SOURCE_FILE_SIZE_LIMIT');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(Math.min(64 * 1024, opened.size + 1));
    let readBytes = 0;
    while (true) {
      // One sentinel byte detects growth; memory and total I/O stay bounded.
      const length = Math.min(buffer.length, opened.size - readBytes + 1);
      const count = readSync(descriptor, buffer, 0, length, null);
      if (!count) break;
      readBytes += count;
      if (readBytes > opened.size) throw new Error('SOURCE_FILE_GREW_DURING_READ');
      hash.update(buffer.subarray(0, count));
    }
    if (readBytes !== opened.size || !sameFile(opened, fstatSync(descriptor))) throw new Error('SOURCE_FILE_CHANGED_DURING_READ');
    return hash.digest('hex');
  } finally { closeSync(descriptor); }
}

export function snapshotSource(root, options = {}) {
  const limits = { ...SOURCE_LIMITS, ...options };
  for (const [key, maximum] of Object.entries(SOURCE_LIMITS)) if (!Number.isSafeInteger(limits[key]) || limits[key] <= 0 || limits[key] > maximum) throw new Error('SOURCE_LIMIT_INVALID');
  if (Object.keys(options).some((key) => !Object.hasOwn(SOURCE_LIMITS, key))) throw new Error('SOURCE_LIMIT_INVALID');
  const resolved = checkedRoot(root);
  const listed = git(resolved, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean);
  const selected = validatePaths(listed);
  if (selected.length > limits.maxFiles) throw new Error('SOURCE_FILE_COUNT_LIMIT');
  const hash = createHash('sha256');
  const files = [];
  let sourceBytes = 0;
  for (const relative of selected) {
    const checked = checkedSourceFile(resolved, relative);
    const kind = checked ? 'file' : 'deleted';
    let digest;
    if (checked) {
      if (!Number.isSafeInteger(checked.metadata.size) || checked.metadata.size > limits.maxFileBytes) throw new Error('SOURCE_FILE_SIZE_LIMIT');
      sourceBytes += checked.metadata.size;
      if (sourceBytes > limits.maxSourceBytes) throw new Error('SOURCE_TOTAL_SIZE_LIMIT');
      digest = boundedFileDigest(resolved, relative, checked, limits);
    } else digest = createHash('sha256').update(Buffer.alloc(0)).digest('hex');
    hash.update(JSON.stringify([relative, kind, digest])).update('\n');
    files.push({ path: relative, kind, digest: `sha256:${digest}` });
  }
  return {
    root: resolved,
    head: git(resolved, ['rev-parse', 'HEAD']).trim(),
    dirty: Boolean(git(resolved, ['status', '--porcelain', '--untracked-files=normal', '--ignore-submodules=all']).trim()),
    digest: `sha256:${hash.digest('hex')}`,
    files,
    limits,
    sourceBytes,
    exclusions: 'git ignored untracked files; tracked files remain included, including deletions',
  };
}

export function changedPathsFromGit(root, { base, head } = {}) {
  root = checkedRoot(root);
  if (Boolean(base) !== Boolean(head)) throw new Error('BASE_HEAD_REQUIRED: supply both revisions');
  if (base) {
    if (![base, head].every((sha) => /^[a-f0-9]{40}$/u.test(sha))) throw new Error('FULL_SHA_REQUIRED');
    return validatePaths(git(root, ['diff', '--no-ext-diff', '--no-textconv', '--ignore-submodules=all', '--name-only', '-z', '--no-renames', base, head, '--']).split('\0').filter(Boolean));
  }
  return validatePaths([
    ...git(root, ['diff', '--no-ext-diff', '--no-textconv', '--ignore-submodules=all', '--name-only', '-z', '--no-renames', 'HEAD', '--']).split('\0'),
    ...git(root, ['ls-files', '-z', '--others', '--exclude-standard']).split('\0'),
  ].filter(Boolean));
}
