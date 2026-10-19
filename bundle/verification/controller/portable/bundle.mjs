import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export const MANIFEST_NAME = 'portable-verifier.bundle.v1.json';
export const ENTRYPOINT = 'verification/portable/cli.mjs';
export const REGISTRY = 'verification/core/verification-manifest.v2.json';
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const SHA = /^[a-f0-9]{40}$/u;
const MAX_FILE = 4 * 1024 * 1024;
const MAX_TOTAL = 16 * 1024 * 1024;
const MAX_FILES = 512;
const ownRoot = path.resolve(import.meta.dirname, '../../..');
// Reviewed generic local installer/qualification closure. This list never grants
// access to application sources, private configuration or arbitrary infra paths.
const OPERATOR_FILES = new Set([
  'api.mjs', 'appwrite-compose.mjs', 'compose.mjs', 'operator.mjs', 'deployment.mjs',
  'upgrade-contract.mjs', 'public-edge.mjs', 'public-lifecycle.mjs', 'product.mjs',
  'clean-provision.mjs', 'source.mjs', 'mcp-profile.mjs', 'native-functions.mjs',
  'images.lock.json', 'product-manifest.json', 'Caddyfile', 'Caddyfile.product',
  'clickhouse-config.xml', 'clickhouse-init.sh', 'postgres-tls.sh', 'pg_hba.conf',
  'temporal-server.sh', 'temporal-schema.sh', 'temporal-namespace.sh', 'temporal-init.sh',
  'health.py', 'init-cert.sh', 'migrate.py', 'clean_bootstrap.py',
].map((name) => `infra/portable/${name}`));
const GENERIC_SUPPORT_FILES = new Set(['tools/build/native_function.py',
  'verification/adapters/portable/sentinel.mjs', 'verification/adapters/portable/sentinel.test.mjs',
  'dev/labs/clean-install-m10/cleanup-trial.mjs', 'dev/labs/clean-install-m10/cleanup-builds.mjs',
  'verification/portable/pytest_reporter.py']);

function fail(code) { throw new Error(code); }
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
export function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function exact(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) fail(code);
}
function safe(relative) {
  if (typeof relative !== 'string' || !relative || /[\\\x00-\x20\x7f:]/u.test(relative) || relative.startsWith('/') || relative.split('/').some((part) => !part || part === '.' || part === '..')) fail('UNSAFE_EXPORT_PATH');
  return relative;
}
function allowed(relative) {
  safe(relative);
  return /^verification\/portable\/[A-Za-z0-9_-]+(?:\.test)?\.mjs$/u.test(relative)
    || /^verification\/controller\/portable\/[A-Za-z0-9_-]+(?:\.test)?\.mjs$/u.test(relative)
    || ['verification/controller/portable/README.md', 'verification/controller/portable/source-set.v1.json',
      'verification/core/portable-registry.mjs', REGISTRY,
      'verification/schemas/verification-manifest.v2.schema.json',
      'verification/controller/portable/product-browser.cjs', 'verification/controller/portable/product-browser.Dockerfile',
      'verification/controller/portable/operator-native-functions.mjs.template'].includes(relative)
    || OPERATOR_FILES.has(relative) || GENERIC_SUPPORT_FILES.has(relative);
}
function inside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
export function resolveTrustedPath(filename, forbiddenRoots = []) {
  const absolute = path.resolve(filename);
  const anchor = path.parse(absolute).root;
  const segments = absolute.slice(anchor.length).split(path.sep).filter(Boolean);
  let current = anchor; let index = 0;
  for (; index < segments.length; index += 1) {
    const next = path.join(current, segments[index]);
    let info;
    try { info = lstatSync(next); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
    if (info.isSymbolicLink()) fail('TRUSTED_PATH_LINK_FORBIDDEN');
    current = realpathSync(next);
    if (index < segments.length - 1 && !info.isDirectory()) fail('TRUSTED_PATH_ANCESTOR_NOT_DIRECTORY');
  }
  const resolved = path.join(current, ...segments.slice(index));
  for (const root of forbiddenRoots) {
    const canonicalRoot = realpathSync(root);
    if (inside(canonicalRoot, resolved) || inside(resolved, canonicalRoot)) fail('TRUSTED_PATH_OVERLAP');
  }
  return resolved;
}
function regular(root, relative) {
  safe(relative);
  const resolvedRoot = realpathSync(root);
  let filename = resolvedRoot;
  const parts = relative.split('/');
  for (let index = 0; index < parts.length; index += 1) {
    filename = path.join(filename, parts[index]);
    const info = lstatSync(filename);
    if (info.isSymbolicLink() || !inside(resolvedRoot, realpathSync(filename))) fail('EXPORT_SYMLINK_OR_ESCAPE');
    if (index < parts.length - 1 ? !info.isDirectory() : !info.isFile()) fail('EXPORT_NOT_REGULAR');
    if (index === parts.length - 1 && (info.size > MAX_FILE || info.nlink > 1)) fail('EXPORT_FILE_LIMIT_OR_HARDLINK');
  }
  return filename;
}
function sourceSet(sourceRoot) {
  const value = JSON.parse(readFileSync(regular(sourceRoot, 'verification/controller/portable/source-set.v1.json'), 'utf8'));
  exact(value, ['schemaVersion', 'files'], 'EXPORT_SOURCE_SET_INVALID');
  if (value.schemaVersion !== 'portable-verifier-source-set.v1' || !Array.isArray(value.files) || !value.files.length || value.files.length > MAX_FILES) fail('EXPORT_SOURCE_SET_INVALID');
  const folded = new Set(); const files = [];
  for (const entry of value.files) {
    const descriptor = typeof entry === 'string' ? { source: entry, path: entry } : entry;
    exact(descriptor, ['source', 'path'], 'EXPORT_SOURCE_MAPPING_INVALID');
    if (!allowed(descriptor.source) || !allowed(descriptor.path)) fail('PRIVATE_OR_UNREVIEWED_EXPORT_PATH');
    if ((descriptor.path === 'infra/portable/native-functions.mjs' && descriptor.source !== 'verification/controller/portable/operator-native-functions.mjs.template')
      || (descriptor.path === 'infra/portable/mcp-profile.mjs' && descriptor.source !== 'verification/controller/portable/operator-mcp-profile.mjs')) fail('EXPORT_SOURCE_MAPPING_UNAPPROVED');
    if (descriptor.source !== descriptor.path && !(
      descriptor.source === 'verification/controller/portable/operator-native-functions.mjs.template' && descriptor.path === 'infra/portable/native-functions.mjs'
      || descriptor.source === 'verification/controller/portable/operator-mcp-profile.mjs' && descriptor.path === 'infra/portable/mcp-profile.mjs'
    )) fail('EXPORT_SOURCE_MAPPING_UNAPPROVED');
    if (folded.has(descriptor.path.toLowerCase())) fail('DUPLICATE_EXPORT_PATH');
    folded.add(descriptor.path.toLowerCase()); files.push(descriptor);
  }
  if (![ENTRYPOINT, REGISTRY, 'verification/controller/portable/bundle.mjs', 'verification/controller/portable/cli.mjs'].every((required) => files.some((entry) => entry.path === required))) fail('EXPORT_REQUIRED_FILE_MISSING');
  return files.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
}
function inspectSources(sourceRoot, filenames) {
  let total = 0;
  return filenames.map((file) => {
    const entry = typeof file === 'string' ? { source: file, path: file } : file;
    const bytes = readFileSync(regular(sourceRoot, entry.source));
    total += bytes.length;
    if (total > MAX_TOTAL) fail('EXPORT_TOTAL_LIMIT');
    // Product files and private configuration cannot enter this explicit source set.
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,})/u.test(bytes.toString('utf8'))) fail('EXPORT_SECRET_DETECTED');
    return { path: entry.path, bytes: bytes.length, digest: digest(bytes), content: bytes };
  });
}
function revision(sourceRoot) {
  const value = execFileSync('git', ['-C', sourceRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true }).trim();
  if (!SHA.test(value)) fail('EXPORT_SOURCE_REVISION_INVALID');
  return value;
}
function assertImportClosure(records) {
  const files = new Set(records.map((entry) => entry.path));
  for (const entry of records.filter((record) => record.path.endsWith('.mjs'))) {
    const source = entry.content.toString('utf8');
    // Only literal builtins/relative imports are permitted in the reviewed runner.
    for (const match of source.matchAll(/^(?:import\s+(?:[^;\r\n]*?\s+from\s+)?|export\s+[^;\r\n]*?\s+from\s+)["']([^"']+)["']/gmu)) {
      const specifier = match[1];
      if (specifier.startsWith('node:')) continue;
      if (!specifier.startsWith('.')) fail('EXPORT_EXTERNAL_DEPENDENCY_UNDECLARED');
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(entry.path), specifier));
      if (!files.has(resolved)) fail(`EXPORT_IMPORT_MISSING:${resolved}`);
    }
  }
}

export function exportBundle({ sourceRoot = ownRoot, output }) {
  const root = realpathSync(sourceRoot);
  const outputRoot = resolveTrustedPath(output);
  if (inside(path.join(root, 'verification'), outputRoot) || inside(outputRoot, root)) fail('EXPORT_OUTPUT_OVERLAP');
  const sourceRevision = revision(root);
  const files = sourceSet(root);
  const records = inspectSources(root, files);
  assertImportClosure(records);
  const inventory = records.map(({ content: _content, ...record }) => record);
  const manifest = {
    schemaVersion: 'portable-verifier-bundle.v1',
    source: { repository: 'Krowaccie/AppWriteWork', baseRevision: sourceRevision, binding: 'base-revision-and-exported-bytes', exportDigest: digest(canonical(inventory)) },
    entrypoint: ENTRYPOINT, registry: REGISTRY,
    runtime: { node: '24.11.1', externalNodePackages: [], dockerRequiredForIndependentExecution: true },
    files: inventory,
  };
  // Exclusive creation prevents overlaying a previous generation or private tree.
  mkdirSync(outputRoot);
  for (const record of records) {
    const filename = path.join(outputRoot, record.path);
    mkdirSync(path.dirname(filename), { recursive: true });
    writeFileSync(filename, record.content, { flag: 'wx' });
  }
  const after = inspectSources(root, files).map(({ content: _content, ...record }) => record);
  if (revision(root) !== sourceRevision || canonical(after) !== canonical(inventory)) fail('EXPORT_SOURCE_CHANGED');
  writeFileSync(path.join(outputRoot, MANIFEST_NAME), `${canonical(manifest)}\n`, { flag: 'wx' });
  return { manifest, manifestDigest: digest(canonical(manifest)), output: outputRoot };
}

function walk(root, relative = '') {
  const results = [];
  for (const name of readdirSync(path.join(root, relative)).sort()) {
    const filename = relative ? `${relative}/${name}` : name;
    safe(filename);
    const info = lstatSync(path.join(root, filename));
    if (info.isSymbolicLink()) fail('BUNDLE_SYMLINK_REJECTED');
    if (info.isDirectory()) results.push(...walk(root, filename));
    else if (info.isFile()) results.push(filename);
    else fail('BUNDLE_NOT_REGULAR');
    if (results.length > MAX_FILES + 1) fail('BUNDLE_FILE_LIMIT');
  }
  return results;
}
export function verifyBundle({ bundleRoot, expectedDigest }) {
  if (!DIGEST.test(expectedDigest)) fail('BUNDLE_EXPECTED_DIGEST_REQUIRED');
  const root = realpathSync(bundleRoot);
  const raw = readFileSync(regular(root, MANIFEST_NAME), 'utf8');
  const manifest = JSON.parse(raw);
  if (raw !== `${canonical(manifest)}\n` || digest(canonical(manifest)) !== expectedDigest) fail('BUNDLE_MANIFEST_DIGEST_MISMATCH');
  exact(manifest, ['schemaVersion', 'source', 'entrypoint', 'registry', 'runtime', 'files'], 'BUNDLE_MANIFEST_INVALID');
  exact(manifest.source, ['repository', 'baseRevision', 'binding', 'exportDigest'], 'BUNDLE_SOURCE_INVALID');
  if (manifest.schemaVersion !== 'portable-verifier-bundle.v1' || manifest.entrypoint !== ENTRYPOINT || manifest.registry !== REGISTRY
    || manifest.source.repository !== 'Krowaccie/AppWriteWork' || !SHA.test(manifest.source.baseRevision) || manifest.source.binding !== 'base-revision-and-exported-bytes'
    || canonical(manifest.runtime) !== canonical({ node: '24.11.1', externalNodePackages: [], dockerRequiredForIndependentExecution: true })
    || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > MAX_FILES) fail('BUNDLE_MANIFEST_INVALID');
  const filenames = [];
  for (const entry of manifest.files) {
    exact(entry, ['path', 'bytes', 'digest'], 'BUNDLE_FILE_INVALID');
    if (!allowed(entry.path) || !DIGEST.test(entry.digest) || !Number.isInteger(entry.bytes) || entry.bytes < 0) fail('BUNDLE_FILE_INVALID');
    filenames.push(entry.path);
  }
  if (new Set(filenames.map((filename) => filename.toLowerCase())).size !== filenames.length) fail('DUPLICATE_EXPORT_PATH');
  if (canonical(filenames) !== canonical([...filenames].sort()) || canonical(walk(root)) !== canonical([...filenames, MANIFEST_NAME].sort())) fail('BUNDLE_INVENTORY_MISMATCH');
  const records = inspectSources(root, filenames);
  if (canonical(records.map(({ content: _content, ...record }) => record)) !== canonical(manifest.files)) fail('BUNDLE_FILE_DIGEST_MISMATCH');
  if (digest(canonical(manifest.files)) !== manifest.source.exportDigest) fail('BUNDLE_EXPORT_DIGEST_MISMATCH');
  if (canonical(sourceSet(root).map((entry) => entry.path)) !== canonical(filenames)) fail('BUNDLE_SOURCE_SET_MISMATCH');
  assertImportClosure(records);
  return { bundleRoot: root, manifest, manifestDigest: expectedDigest, registryDigest: records.find((record) => record.path === REGISTRY)?.digest };
}

export function verifyPin({ bundleRoot, pin, candidateRoot }) {
  exact(pin, ['schemaVersion', 'manifestDigest', 'sourceRevision', 'registryDigest', 'review'], 'PIN_INVALID');
  exact(pin.review, ['decision', 'reviewer', 'reference', 'qualificationDigest'], 'PIN_REVIEW_INVALID');
  if (pin.schemaVersion !== 'portable-verifier-pin.v1' || pin.review.decision !== 'APPROVED'
    || ![pin.review.reviewer, pin.review.reference].every((value) => typeof value === 'string' && value.trim().length >= 3)
    || !DIGEST.test(pin.review.qualificationDigest)) fail('PIN_REVIEW_REQUIRED');
  const checked = verifyBundle({ bundleRoot, expectedDigest: pin.manifestDigest });
  if (pin.sourceRevision !== checked.manifest.source.baseRevision || pin.registryDigest !== checked.registryDigest) fail('PIN_IDENTITY_MISMATCH');
  if (candidateRoot) {
    const candidate = realpathSync(candidateRoot);
    if (inside(candidate, checked.bundleRoot) || inside(checked.bundleRoot, candidate)) fail('CANDIDATE_VERIFIER_OVERLAP');
  }
  return checked;
}
