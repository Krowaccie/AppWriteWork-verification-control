import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { canonical, digest, resolveTrustedPath } from './bundle.mjs';

const ROOTS = ['', 'apps/web', 'apps/mcp-bridge', 'apps/local-runtime', 'packages/local-runtime-protocol'];
const SHA = /^sha256:[a-f0-9]{64}$/u;
const IMAGE = /^(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64})$/u;
const INSTALL_POLICY = 'npm-ci-ignore-scripts-no-private-config.v1';
function fail(code) { throw new Error(code); }
function docker(args, options = {}) {
  if (process.env.DOCKER_HOST || process.env.DOCKER_TLS_VERIFY || process.env.DOCKER_CERT_PATH) fail('CACHE_REMOTE_DOCKER_FORBIDDEN');
  return execFileSync('docker', args, { encoding: 'utf8', windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024, ...options });
}
function regular(root, relative) {
  let current = realpathSync(root);
  for (const segment of relative.split('/')) {
    current = path.join(current, segment);
    if (lstatSync(current).isSymbolicLink()) fail('CACHE_INPUT_SYMLINK');
  }
  const info = lstatSync(current);
  if (!info.isFile() || info.size > 4 * 1024 * 1024) fail('CACHE_INPUT_INVALID');
  return readFileSync(current);
}
function validateLock(lock) {
  if (lock.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== 'object') fail('CACHE_LOCK_VERSION_UNSUPPORTED');
  for (const entry of Object.values(lock.packages)) {
    if (!entry.resolved) continue;
    if (entry.link === true && entry.resolved === '../../packages/local-runtime-protocol') continue;
    let url;
    try { url = new URL(entry.resolved); } catch { fail('CACHE_DEPENDENCY_SOURCE_FORBIDDEN'); }
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || !/^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/u.test(entry.integrity ?? '')) fail('CACHE_DEPENDENCY_SOURCE_FORBIDDEN');
  }
}
export function cacheInputs({ candidateRoot, roots = ROOTS }) {
  if (!Array.isArray(roots) || !roots.length || new Set(roots).size !== roots.length || roots.some((root) => !ROOTS.includes(root))) fail('CACHE_ROOTS_INVALID');
  const expanded = new Set(roots);
  if (roots.includes('apps/local-runtime') || roots.includes('apps/mcp-bridge')) expanded.add('packages/local-runtime-protocol');
  const files = [];
  for (const root of [...expanded].sort()) for (const name of ['package.json', 'package-lock.json']) {
    const filename = root ? `${root}/${name}` : name;
    const content = regular(candidateRoot, filename);
    const data = JSON.parse(content);
    if (name === 'package-lock.json') validateLock(data);
    files.push({ path: filename, digest: digest(content), content });
  }
  const identity = files.map(({ content: _content, ...entry }) => entry);
  return { roots: [...expanded].sort(), files, digest: digest(canonical(identity)) };
}
export function prepareNodeCache({ candidateRoot, output, baseImage, verifierManifestDigest, roots = ROOTS }) {
  if (!IMAGE.test(baseImage ?? '') || !SHA.test(verifierManifestDigest ?? '')) fail('CACHE_IMMUTABLE_RUNTIME_AND_VERIFIER_REQUIRED');
  const endpoint = JSON.parse(docker(['context', 'inspect']))[0]?.Endpoints?.docker?.Host;
  if (!/^(?:unix:\/\/\/|npipe:\/\/\/\/\.\/pipe\/)/u.test(endpoint ?? '') || docker(['info', '--format', '{{.OSType}}']).trim() !== 'linux') fail('CACHE_LOCAL_LINUX_DOCKER_REQUIRED');
  const inputs = cacheInputs({ candidateRoot, roots });
  const builderDigest = digest(readFileSync(import.meta.filename));
  const owned = resolveTrustedPath(output, [candidateRoot]);
  mkdirSync(owned);
  const context = path.join(owned, 'context'); mkdirSync(context);
  for (const file of inputs.files) {
    const filename = path.join(context, file.path);
    mkdirSync(path.dirname(filename), { recursive: true }); writeFileSync(filename, file.content, { flag: 'wx' });
  }
  const copies = inputs.files.map((entry) => `COPY ${JSON.stringify([entry.path, `/dependencies/${entry.path}`])}`);
  const installs = inputs.roots.map((root) => `RUN cd /dependencies${root ? `/${root}` : ''} && npm ci --ignore-scripts --no-audit --no-fund --cache /tmp/npm-cache && rm -rf /tmp/npm-cache`);
  const labels = { 'appwritework.cache.policy': INSTALL_POLICY, 'appwritework.cache.inputs': inputs.digest, 'appwritework.cache.builder': builderDigest, 'appwritework.cache.verifier': verifierManifestDigest };
  const dockerfile = [`FROM ${baseImage}`, 'ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 NPM_CONFIG_UPDATE_NOTIFIER=false',
    'RUN test "$(node --version)" = v24.11.1', ...copies, ...installs,
    `LABEL ${Object.entries(labels).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join(' ')}`, 'USER 1000:1000', 'WORKDIR /work', 'CMD ["node"]', ''].join('\n');
  writeFileSync(path.join(context, 'Dockerfile'), dockerfile, { flag: 'wx' });
  const iidFile = path.join(owned, 'image.id');
  const log = docker(['build', '--network', 'default', '--memory', '1g', '--iidfile', iidFile, context], { timeout: 900_000 });
  writeFileSync(path.join(owned, 'build.log'), log, { flag: 'wx' });
  const imageId = readFileSync(iidFile, 'utf8').trim();
  if (!SHA.test(imageId)) fail('CACHE_IMAGE_ID_INVALID');
  if (cacheInputs({ candidateRoot, roots }).digest !== inputs.digest) fail('CACHE_INPUT_CHANGED_DURING_BUILD');
  const descriptor = { schemaVersion: 'portable-node-cache.v1', imageId, baseImage, inputDigest: inputs.digest, roots: inputs.roots,
    files: inputs.files.map(({ content: _content, ...entry }) => entry), builderDigest, verifierManifestDigest, installPolicy: INSTALL_POLICY };
  writeFileSync(path.join(owned, 'node-cache.json'), `${canonical(descriptor)}\n`, { flag: 'wx' });
  const review = { schemaVersion: 'portable-node-cache-review.v1', descriptorDigest: digest(canonical(descriptor)), imageId, verifierManifestDigest,
    decision: 'PENDING', reviewer: '', reference: '', qualificationDigest: '' };
  writeFileSync(path.join(owned, 'node-cache-review.template.json'), `${canonical(review)}\n`, { flag: 'wx' });
  return { descriptor, review, output: owned };
}
export function validateNodeCache({ descriptor, review, candidateRoot, verifierManifestDigest, inspectImage = (imageId) => JSON.parse(docker(['image', 'inspect', imageId]))[0] }) {
  if (descriptor?.schemaVersion !== 'portable-node-cache.v1' || descriptor.installPolicy !== INSTALL_POLICY || !SHA.test(descriptor.imageId ?? '') || !IMAGE.test(descriptor.baseImage ?? '')
    || descriptor.verifierManifestDigest !== verifierManifestDigest || descriptor.builderDigest !== digest(readFileSync(import.meta.filename))) fail('TRUSTED_NODE_CACHE_DESCRIPTOR_INVALID');
  if (review?.schemaVersion !== 'portable-node-cache-review.v1' || review.decision !== 'APPROVED' || review.descriptorDigest !== digest(canonical(descriptor))
    || review.imageId !== descriptor.imageId || review.verifierManifestDigest !== verifierManifestDigest || !SHA.test(review.qualificationDigest ?? '')
    || ![review.reviewer, review.reference].every((value) => typeof value === 'string' && value.trim().length >= 3)) fail('TRUSTED_NODE_CACHE_REVIEW_REQUIRED');
  const inputs = cacheInputs({ candidateRoot, roots: descriptor.roots });
  if (inputs.digest !== descriptor.inputDigest || canonical(inputs.files.map(({ content: _content, ...file }) => file)) !== canonical(descriptor.files)) fail('TRUSTED_NODE_CACHE_STALE_LOCK');
  const image = inspectImage(descriptor.imageId);
  const labels = image?.Config?.Labels;
  if (image?.Id !== descriptor.imageId || labels?.['appwritework.cache.policy'] !== INSTALL_POLICY || labels?.['appwritework.cache.inputs'] !== descriptor.inputDigest
    || labels?.['appwritework.cache.builder'] !== descriptor.builderDigest || labels?.['appwritework.cache.verifier'] !== verifierManifestDigest) fail('TRUSTED_NODE_CACHE_IMAGE_MISMATCH');
  return descriptor;
}

export const linkCacheScript = `
const fs = require('node:fs'); const path = require('node:path');
const roots = JSON.parse(process.argv[1]);
for (const root of roots) {
 const from = path.posix.join('/dependencies', root, 'node_modules');
 if (!fs.existsSync(from)) continue;
 const to = path.posix.join('/work', root, 'node_modules'); fs.mkdirSync(to,{recursive:true});
 const link = (source,dest) => {const info = fs.lstatSync(source); const target = info.isSymbolicLink() ? fs.realpathSync(source).replace(/^\\/dependencies(?=\\/)/,'/work') : source; fs.symlinkSync(target,dest);};
 for (const name of fs.readdirSync(from)) {
  if (name.startsWith('@')) { fs.mkdirSync(path.join(to,name),{recursive:true}); for(const child of fs.readdirSync(path.join(from,name))) link(path.join(from,name,child),path.join(to,name,child)); }
  else link(path.join(from,name),path.join(to,name));
 }
}`;
