import { randomUUID } from 'node:crypto';
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';

import { validateVerificationResult } from './evidence.mjs';

const OUTPUT_DIR = '.verification/results';
const ERROR_MESSAGES = Object.freeze({
  EVIDENCE_OUTPUT_UNSAFE: 'Verification evidence output is not safely contained.',
  EVIDENCE_SCHEMA_INVALID: 'Verification evidence does not match the required schema.',
  EVIDENCE_WRITE_BLOCKED: 'Verification evidence could not be written safely.',
});

function evidenceError(code) {
  const error = new Error(ERROR_MESSAGES[code]);
  error.code = code;
  return error;
}

function isEvidenceError(error) {
  return error !== null && typeof error === 'object' &&
    Object.hasOwn(ERROR_MESSAGES, error.code) &&
    error.message === ERROR_MESSAGES[error.code];
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort(lexicalCompare)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' ||
    (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

async function lstatIfPresent(target) {
  try {
    return await lstat(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function assertRepositoryIgnore(root, rootReal) {
  const ignorePath = path.join(root, '.gitignore');
  try {
    const stats = await lstat(ignorePath);
    if (!stats.isFile() || stats.isSymbolicLink()) {
      throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
    }
    const ignoreReal = await realpath(ignorePath);
    if (!isWithin(rootReal, ignoreReal)) {
      throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
    }
    const lines = (await readFile(ignorePath, 'utf8')).split(/\r?\n/u);
    if (!lines.includes('.verification/')) {
      throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
    }
  } catch (error) {
    if (isEvidenceError(error)) throw error;
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }
}

async function assertDirectoryComponentSafe(component, rootReal) {
  let stats;
  try {
    stats = await lstatIfPresent(component);
  } catch {
    throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  }
  if (stats === null) return false;
  if (stats.isSymbolicLink()) throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  if (!stats.isDirectory()) throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  try {
    const resolved = await realpath(component);
    if (!isWithin(rootReal, resolved)) throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  } catch (error) {
    if (isEvidenceError(error)) throw error;
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }
  return true;
}

async function assertOutputTreeSafe(root, rootReal) {
  const verificationDir = path.join(root, '.verification');
  const resultsDir = path.join(verificationDir, 'results');
  await assertDirectoryComponentSafe(verificationDir, rootReal);
  await assertDirectoryComponentSafe(resultsDir, rootReal);
  return { verificationDir, resultsDir };
}

async function readExistingFinal(finalPath, expectedBytes, rootReal) {
  let stats;
  try {
    stats = await lstatIfPresent(finalPath);
  } catch {
    throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  }
  if (stats === null) return false;
  if (stats.isSymbolicLink()) throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  if (!stats.isFile()) throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  try {
    const finalReal = await realpath(finalPath);
    if (!isWithin(rootReal, finalReal)) throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
    const existingBytes = await readFile(finalPath);
    if (!existingBytes.equals(expectedBytes)) throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  } catch (error) {
    if (isEvidenceError(error)) throw error;
    throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  }
  return true;
}

async function writeAtomic({ resultsDir, finalPath, bytes }) {
  const tempPath = path.join(resultsDir, `.evidence-${process.pid}-${randomUUID()}.tmp`);
  let handle = null;
  try {
    handle = await open(tempPath, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(tempPath, finalPath);
  } catch {
    if (handle !== null) {
      try {
        await handle.close();
      } catch {
        // The public failure stays a fixed safe diagnostic.
      }
    }
    try {
      await unlink(tempPath);
    } catch {
      // The public failure stays a fixed safe diagnostic.
    }
    throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  }
}

function prepareWrite(options) {
  let callerResult;
  try {
    callerResult = options?.result;
  } catch {
    throw evidenceError('EVIDENCE_SCHEMA_INVALID');
  }

  let snapshot;
  try {
    snapshot = structuredClone(callerResult);
  } catch {
    throw evidenceError('EVIDENCE_SCHEMA_INVALID');
  }
  const validation = validateVerificationResult(snapshot);
  if (!validation.ok) throw evidenceError('EVIDENCE_SCHEMA_INVALID');

  let root;
  let outputDir;
  try {
    root = options?.root;
    outputDir = options?.outputDir === undefined ? OUTPUT_DIR : options.outputDir;
  } catch {
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }
  if (typeof outputDir !== 'string' ||
      outputDir !== OUTPUT_DIR ||
      outputDir.includes('\\') ||
      path.isAbsolute(outputDir)) {
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }
  if (typeof root !== 'string' || root.trim().length === 0) {
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }

  let absoluteRoot;
  try {
    absoluteRoot = path.resolve(root);
  } catch {
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }

  const hex = snapshot.resultId.slice('sha256:'.length);
  const filename = `sha256-${hex}.json`;
  const bytes = Buffer.from(`${canonicalJson(snapshot)}\n`, 'utf8');
  return {
    absoluteRoot,
    bytes,
    evidenceDigest: snapshot.evidenceDigest,
    filename,
  };
}

function assertFinalPathContained(resultsDir, finalPath, filename) {
  const resolvedResultsDir = path.resolve(resultsDir);
  const resolvedFinalPath = path.resolve(finalPath);
  if (!/^sha256-[0-9a-f]{64}\.json$/u.test(filename) ||
      path.dirname(resolvedFinalPath) !== resolvedResultsDir ||
      path.basename(resolvedFinalPath) !== filename ||
      !isWithin(resolvedResultsDir, resolvedFinalPath)) {
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }
}

export async function writeVerificationResult(options) {
  const {
    absoluteRoot,
    bytes,
    evidenceDigest,
    filename,
  } = prepareWrite(options);

  let rootReal;
  try {
    rootReal = await realpath(absoluteRoot);
  } catch {
    throw evidenceError('EVIDENCE_OUTPUT_UNSAFE');
  }
  await assertRepositoryIgnore(absoluteRoot, rootReal);

  let outputTree = await assertOutputTreeSafe(absoluteRoot, rootReal);
  try {
    await mkdir(outputTree.resultsDir, { recursive: true });
  } catch {
    throw evidenceError('EVIDENCE_WRITE_BLOCKED');
  }
  outputTree = await assertOutputTreeSafe(absoluteRoot, rootReal);

  const finalPath = path.join(outputTree.resultsDir, filename);
  assertFinalPathContained(outputTree.resultsDir, finalPath, filename);

  if (!await readExistingFinal(finalPath, bytes, rootReal)) {
    await writeAtomic({
      resultsDir: outputTree.resultsDir,
      finalPath,
      bytes,
    });
  }

  return {
    path: finalPath,
    evidenceDigest,
  };
}
