import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { validateProductionBrowserPolicy } from './production-readonly-browser.mjs';

const FORBIDDEN_NAME = /TOKEN|SECRET|KEY|PRIVATE|CREDENTIAL/i;
const SAFE_ENV = new Set(['CI', 'PATH', 'SYSTEMROOT', 'TEMP', 'TMP']);
const TAG = '@production-readonly';
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const controllerRoot = path.resolve(packageRoot, '..', '..');
const defaultPolicyPath = path.join(
  controllerRoot,
  '.production-browser-policy',
  'production-browser-policy.v1.json',
);

function blocked(code) {
  const error = new Error('Production Playwright launcher blocked.');
  error.code = code;
  return error;
}

function digestBytes(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function resolvePlaywrightCli() {
  return path.join(packageRoot, 'node_modules', '@playwright', 'test', 'cli.js');
}

export async function runProductionReadonlyPlaywright({
  argv = process.argv.slice(2),
  env = process.env,
  spawn,
  policyPath = defaultPolicyPath,
  readPolicy,
} = {}) {
  if (!Array.isArray(argv) || argv.length !== 1 || !['--list', '--run'].includes(argv[0])) {
    throw blocked('PRODUCTION_PLAYWRIGHT_ARGUMENT_INVALID');
  }

  let validatedPolicyPath;
  let validatedPolicyDigest;
  if (argv[0] === '--run') {
    let raw;
    let policy;
    try {
      const loaded = readPolicy
        ? await readPolicy(policyPath)
        : await readFile(policyPath, 'utf8');
      raw = typeof loaded === 'string' ? loaded : JSON.stringify(loaded);
      policy = typeof loaded === 'string' ? JSON.parse(loaded) : loaded;
    } catch {
      throw blocked('PRODUCTION_BROWSER_POLICY_UNAVAILABLE');
    }
    if (!validateProductionBrowserPolicy(policy)) throw blocked('PRODUCTION_BROWSER_POLICY_INVALID');
    validatedPolicyPath = path.resolve(policyPath);
    validatedPolicyDigest = digestBytes(raw);
  }

  const executable = process.execPath;
  const playwrightCli = path.join(packageRoot, 'node_modules', '@playwright', 'test', 'cli.js');
  const config = path.join(packageRoot, 'playwright.config.mjs');
  const childEnv = Object.create(null);
  for (const [name, value] of Object.entries(env ?? {})) {
    if (SAFE_ENV.has(name) && !FORBIDDEN_NAME.test(name) && typeof value === 'string') childEnv[name] = value;
  }
  if (argv[0] === '--run') {
    childEnv.PRODUCTION_BROWSER_POLICY_PATH = validatedPolicyPath;
    childEnv.PRODUCTION_BROWSER_POLICY_DIGEST = validatedPolicyDigest;
  }

  const args = [playwrightCli, 'test', `--config=${config}`, '--grep', TAG];
  if (argv[0] === '--list') args.push('--list');
  const invoke = spawn ?? ((command, commandArgs, options) => spawnSync(command, commandArgs, options));
  const result = await invoke(executable, args, {
    cwd: packageRoot,
    env: childEnv,
    shell: false,
    stdio: 'inherit',
  });
  const status = Number.isInteger(result?.status) ? result.status : 2;
  return status;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runProductionReadonlyPlaywright()
    .then((status) => { process.exitCode = status; })
    .catch((error) => {
      process.stderr.write(`BLOCKED ${error?.code ?? 'PRODUCTION_PLAYWRIGHT_BLOCKED'}\n`);
      process.exitCode = 2;
    });
}
