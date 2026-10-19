#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { changedPathsFromGit, validatePaths } from './source.mjs';
import { explainPortableVerification, runPortableVerification } from './executor.mjs';

export function parsePortableArgs(argv, env = process.env) {
  const options = {};
  const values = new Map([['--profile', 'profile'], ['--candidate', 'candidateRoot'], ['--base', 'base'], ['--head', 'head'], ['--paths-env', 'pathsEnv'], ['--paths-file', 'pathsFile'], ['--group', 'group'], ['--output', 'outputRoot']]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--explain') { options.explain = true; continue; }
    if (argument === '--require-independent') { options.requireIndependent = true; continue; }
    if (argument === '--help' || argument === '-h') { options.help = true; continue; }
    const name = values.get(argument);
    if (!name || Object.hasOwn(options, name) || !argv[index + 1] || argv[index + 1].startsWith('--')) throw new Error(`INVALID_ARGUMENT:${argument}`);
    options[name] = argv[++index];
  }
  if (options.help) return options;
  if (!['changes', 'repository'].includes(options.profile)) throw new Error('UNKNOWN_PROFILE: --profile changes|repository required');
  if (options.candidateRoot && !path.isAbsolute(options.candidateRoot)) throw new Error('ABSOLUTE_CANDIDATE_REQUIRED');
  if ([Boolean(options.pathsEnv), Boolean(options.pathsFile), Boolean(options.base || options.head)].filter(Boolean).length > 1) throw new Error('CONFLICTING_CHANGE_INPUTS');
  if (options.profile === 'repository' && (options.pathsEnv || options.pathsFile || options.base || options.head)) throw new Error('REPOSITORY_PROFILE_HAS_NO_DIFF');
  if (options.pathsFile) {
    if (!statSync(options.pathsFile).isFile() || statSync(options.pathsFile).size > 8 * 1024 * 1024) throw new Error('PATHS_FILE_INVALID_OR_TOO_LARGE');
    const bytes = readFileSync(options.pathsFile);
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    if (env.VERIFY_PATHS_DIGEST && env.VERIFY_PATHS_DIGEST !== digest) throw new Error('PATHS_FILE_DIGEST_MISMATCH');
    try { options.changedPaths = validatePaths(JSON.parse(bytes.toString('utf8'))); } catch { throw new Error('INVALID_CHANGED_PATHS'); }
  } else if (env.VERIFY_PATHS_DIGEST) throw new Error('PATHS_FILE_REQUIRED_FOR_DIGEST');
  if (options.pathsEnv) {
    if (!/^[A-Z_][A-Z0-9_]*$/u.test(options.pathsEnv)) throw new Error('INVALID_PATHS_ENV');
    const text = env[options.pathsEnv];
    if (typeof text !== 'string' || text.length > 2 * 1024 * 1024) throw new Error('PATHS_ENV_MISSING_OR_TOO_LARGE');
    try { options.changedPaths = validatePaths(JSON.parse(text)); } catch { throw new Error('INVALID_CHANGED_PATHS'); }
  }
  if (Boolean(options.base) !== Boolean(options.head)) throw new Error('BASE_HEAD_REQUIRED');
  return options;
}

export async function portableMain(argv = [], deps = {}) {
  const stdout = deps.stdout ?? process.stdout;
  const stderr = deps.stderr ?? process.stderr;
  try {
    const options = parsePortableArgs(argv, deps.env ?? process.env);
    if (options.help) {
      stdout.write('Portable verify: --profile changes|repository [--candidate absolute-path] [--base SHA --head SHA | --paths-env NAME | --paths-file JSON] [--group web|python|mcp|quick|portable|windows] [--explain] [--output path] [--require-independent]\nRepository audits run only on explicit invocation. Same-user results are development evidence.\n');
      return 0;
    }
    const root = deps.root ?? path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
    const candidateRoot = options.candidateRoot ?? deps.candidateRoot ?? process.cwd();
    const changedPaths = options.changedPaths ?? (options.profile === 'repository' ? [] : changedPathsFromGit(candidateRoot, options));
    const input = { ...options, root, candidateRoot, changedPaths, env: deps.env ?? process.env, expectedRegistryDigest: (deps.env ?? process.env).VERIFY_REGISTRY_DIGEST, ...deps.executorOptions };
    if (options.explain) {
      const explanation = (deps.explain ?? explainPortableVerification)(input);
      stdout.write(`${JSON.stringify(explanation, null, 2)}\n`);
      return explanation.errors.length ? 2 : 0;
    }
    const abort = new AbortController();
    const interrupt = () => abort.abort();
    process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
    try {
      const result = await (deps.run ?? runPortableVerification)({ ...input, signal: abort.signal });
      stdout.write(`${result.status} ${result.profile} ${result.scope}\n`);
      return ['PASS', 'NOT_APPLICABLE'].includes(result.status) ? 0 : result.status === 'FAIL' ? 1 : 2;
    } finally { process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt); }
  } catch (error) { stderr.write(`BLOCKED ${error.message}\n`); return 2; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await portableMain(process.argv.slice(2));
