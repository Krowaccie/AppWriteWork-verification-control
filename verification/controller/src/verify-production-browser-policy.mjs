import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateProductionBrowserPolicy } from './production-readonly-browser.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
function blocked(code) {
  const error = new Error(`BLOCKED ${code}`);
  error.code = code;
  return error;
}

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function verifyProductionBrowserPolicy({ bytes, expectedDigest, env = {} } = {}) {
  if (!(bytes instanceof Uint8Array) || !DIGEST.test(expectedDigest ?? '')) {
    throw blocked('PRODUCTION_BROWSER_POLICY_INPUT_INVALID');
  }
  if (Object.keys(env).some((name) => /^APPWRITE_|^E2E_/u.test(name))) {
    throw blocked('PRODUCTION_BROWSER_ENVIRONMENT_NOT_SECRETLESS');
  }
  if (digestBytes(bytes) !== expectedDigest) {
    throw blocked('PRODUCTION_BROWSER_POLICY_DIGEST_MISMATCH');
  }
  let policy;
  const raw = Buffer.from(bytes).toString('utf8');
  try {
    policy = JSON.parse(raw);
  } catch {
    throw blocked('PRODUCTION_BROWSER_POLICY_INVALID');
  }
  if (!validateProductionBrowserPolicy(policy) || JSON.stringify(policy) !== raw) {
    throw blocked('PRODUCTION_BROWSER_POLICY_INVALID');
  }
  return Object.freeze({ policy: Object.freeze(policy), policyDigest: expectedDigest });
}

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return Object.freeze({ help: true });
  if (argv.length !== 4 || argv[0] !== '--policy' || argv[2] !== '--expected-digest' ||
      typeof argv[1] !== 'string' || argv[1].length === 0 || path.isAbsolute(argv[1]) ||
      argv[1].includes('\\') || argv[1].split('/').some((part) => part === '' || part === '.' || part === '..') ||
      !DIGEST.test(argv[3])) {
    throw blocked('PRODUCTION_BROWSER_POLICY_ARGUMENT_INVALID');
  }
  return Object.freeze({ help: false, policyPath: argv[1], expectedDigest: argv[3] });
}

async function main() {
  try {
    const args = parseArguments(process.argv.slice(2));
    if (args.help) {
      process.stdout.write('Usage: verify-production-browser-policy --policy PATH --expected-digest SHA256\n');
      return;
    }
    const bytes = new Uint8Array(await readFile(args.policyPath));
    const verified = verifyProductionBrowserPolicy({
      bytes,
      expectedDigest: args.expectedDigest,
      env: process.env,
    });
    process.stdout.write(`${verified.policyDigest}\n`);
  } catch (error) {
    process.stderr.write(`${error?.message?.startsWith('BLOCKED ') ? error.message : 'BLOCKED PRODUCTION_BROWSER_POLICY_VERIFY_FAILED'}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
