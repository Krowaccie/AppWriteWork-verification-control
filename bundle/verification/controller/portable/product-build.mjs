import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { cacheInputs } from './dependency-cache.mjs';
import { digest, canonical } from './bundle.mjs';
import { snapshotSource } from '../../portable/source.mjs';
import { docker, read, write, save, render, dc, refreshEndpoint, load } from '../../../infra/portable/operator.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TRUSTED_INFRA = path.resolve(HERE, '../../../infra/portable');
const IMAGE = /^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$/u;
const SHA = /^sha256:[a-f0-9]{64}$/u;
const WORKER_ROOTS = ['packages/backend-core-py/src', 'packages/catalog', 'services/execution-worker-py/salmora_worker'];
const WEB_ROOTS = ['apps/web', 'apps/mcp-bridge', 'packages/catalog', 'packages/shared-contracts', 'packages/contracts', 'packages/local-runtime-protocol', 'dev/tests/fixtures', 'services/appwrite-functions/runs-create-py', 'tools/build', 'infra/portable'];
function check(value, code) { if (!value) throw new Error(code); }

// Dependency installation sees this small, declarative grammar only. In
// particular pip options, editable paths, URLs, extras and source archives do
// not enter the network-enabled preparation container.
export function parsePythonLock(content) {
  check(typeof content === 'string' && Buffer.byteLength(content) <= 256 * 1024, 'PRODUCT_PYTHON_LOCK_INVALID');
  const lines = [], names = new Set();
  for (const raw of content.split(/\r?\n/u)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.!+_-]*)(;\s*sys_platform\s*==\s*"win32")?$/u.exec(line);
    check(match, 'PRODUCT_PYTHON_LOCK_NONDECLARATIVE');
    const name = match[1].toLowerCase().replaceAll(/[-_.]+/gu, '-');
    check(!names.has(name), 'PRODUCT_PYTHON_LOCK_DUPLICATE'); names.add(name);
    lines.push(match[1] + '==' + match[2] + (match[3] ? '; sys_platform == "win32"' : ''));
  }
  check(lines.length > 0 && lines.length <= 512, 'PRODUCT_PYTHON_LOCK_INVALID');
  return lines.join('\n') + '\n';
}

export function pythonDependencyRecipe(baseImage) {
  check(IMAGE.test(baseImage), 'PRODUCT_PINNED_BASE_REQUIRED');
  return [`FROM ${baseImage}`, 'COPY requirements.lock /requirements.lock',
    'RUN python -I -c "import sys; assert sys.version_info[:2] == (3, 12)"',
    'RUN python -I -m pip --isolated install --no-cache-dir --only-binary=:all: --no-deps --index-url https://pypi.org/simple -r /requirements.lock', ''].join('\n');
}
export function nodeDependencyRecipe(baseImage, inputs) {
  check(IMAGE.test(baseImage), 'PRODUCT_PINNED_BASE_REQUIRED');
  return [`FROM ${baseImage}`, 'ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 NPM_CONFIG_UPDATE_NOTIFIER=false',
    'RUN test "$(node --version)" = v24.11.1',
    ...inputs.files.map((file) => `COPY ${JSON.stringify([file.path, '/source/' + file.path])}`),
    ...inputs.roots.map((root) => `RUN cd /source${root ? '/' + root : ''} && npm ci --ignore-scripts --no-audit --no-fund --cache /tmp/npm-cache && rm -rf /tmp/npm-cache`), ''].join('\n');
}
export function workerRecipe(dependencyTag) {
  check(/^salmora-verifier-deps:[a-z0-9-]+$/u.test(dependencyTag), 'PRODUCT_DEPENDENCY_TAG_INVALID');
  return [`FROM ${dependencyTag}`, 'ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app/packages/backend-core-py/src:/app/services/execution-worker-py SALMORA_WORKER_CONFIG=/run/m3/worker/worker.private.json',
    'WORKDIR /app', ...WORKER_ROOTS.map((root) => `COPY ${JSON.stringify([root, '/app/' + root])}`),
    'CMD ["python", "-m", "salmora_worker.worker"]', ''].join('\n');
}
export function webRecipe({ dependencyTag, nodeImage, caddyImage }) {
  check(/^salmora-verifier-deps:[a-z0-9-]+$/u.test(dependencyTag) && IMAGE.test(nodeImage) && IMAGE.test(caddyImage), 'PRODUCT_PINNED_BASE_REQUIRED');
  return [`FROM ${caddyImage} AS caddy`, `FROM ${dependencyTag} AS build`, 'COPY . /source', 'WORKDIR /source',
    'RUN node /source/tools/build/bundle-catalog.mjs && node /source/infra/portable/web-build.mjs',
    `FROM ${nodeImage}`, 'COPY --from=caddy /usr/bin/caddy /usr/bin/caddy', 'COPY --from=build /source/apps/web/dist /srv',
    'COPY --from=build /source/apps/mcp-bridge/src /opt/apps/mcp-bridge/src',
    'COPY --from=build /source/apps/mcp-bridge/package.json /opt/apps/mcp-bridge/package.json',
    'COPY --from=build /source/apps/mcp-bridge/node_modules /opt/apps/mcp-bridge/node_modules',
    'COPY --from=build /source/packages/local-runtime-protocol /opt/packages/local-runtime-protocol',
    'ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data', 'ENTRYPOINT ["caddy"]',
    'CMD ["run","--config","/etc/caddy/Caddyfile","--adapter","caddyfile"]', ''].join('\n');
}
export function productBuildArguments({ context, recipe, iidFile, tag, online }) {
  return ['build', '--pull=false', '--network', online ? 'default' : 'none', '--memory', '1g', '--iidfile', iidFile, '--file', recipe, '--tag', tag, context];
}
export function selectedProductFiles(snapshot, roots) {
  return snapshot.files.filter((file) => file.kind === 'file' && roots.some((root) => file.path === root || file.path.startsWith(root + '/')))
    .filter((file) => !file.path.split('/').some((part) => part === 'node_modules' || part.startsWith('.') || ['__pycache__', 'dist', 'Dockerfile', 'Web.Dockerfile'].includes(part)))
    .filter((file) => !/\.private\.|\.env$|\.(?:pem|key)$/u.test(file.path));
}
async function copyInputs(source, context, files) {
  for (const file of files) {
    const bytes = await fs.readFile(path.join(source, file.path));
    check(digest(bytes) === file.digest, 'PRODUCT_BUILD_SOURCE_DRIFT');
    const target = path.join(context, file.path); await fs.mkdir(path.dirname(target), { recursive: true }); await fs.writeFile(target, bytes, { flag: 'wx' });
  }
}
async function buildImage(s, { context, recipeText, tag, online }) {
  const recipe = path.join(context, 'Dockerfile'), iidFile = path.join(path.dirname(context), path.basename(context) + '.image-id');
  await fs.writeFile(recipe, recipeText, { flag: 'wx' });
  await docker(s, productBuildArguments({ context, recipe, iidFile, tag, online }), { timeout: 900_000 });
  const imageId = (await fs.readFile(iidFile, 'utf8')).trim(); check(SHA.test(imageId), 'PRODUCT_IMAGE_ID_INVALID');
  check(await docker(s, ['image', 'inspect', tag, '--format', '{{.Id}}']) === imageId, 'PRODUCT_IMAGE_TAG_DRIFT');
  return { imageId, tag, recipeDigest: digest(recipeText), network: online ? 'default' : 'none' };
}
async function directories(privateRoot, type) {
  const root = path.join(privateRoot, type + '-build-' + randomBytes(6).toString('hex'));
  await fs.mkdir(root, { mode: 0o700 });
  const dependencies = path.join(root, 'dependencies'), product = path.join(root, 'product');
  await fs.mkdir(dependencies); await fs.mkdir(product); return { root, dependencies, product };
}
async function trustedPins() { return read(path.join(TRUSTED_INFRA, 'images.lock.json')); }
const scope = { candidateDockerfilesExecuted: false, candidateInstallerQualified: false, dependencySource: 'manifest-only', productBuildNetwork: 'none', recipe: 'reviewed-verifier-fixture' };

export async function buildTrustedWorker(s, sourceRoot, privateRoot) {
  const pins = await trustedPins(), snapshot = snapshotSource(sourceRoot), dirs = await directories(privateRoot, 'worker');
  const name = 'services/execution-worker-py/requirements.lock', entry = snapshot.files.find((file) => file.path === name && file.kind === 'file');
  check(entry, 'PRODUCT_WORKER_LOCK_REQUIRED'); const bytes = await fs.readFile(path.join(sourceRoot, name)); check(digest(bytes) === entry.digest, 'PRODUCT_BUILD_SOURCE_DRIFT');
  const lock = parsePythonLock(bytes.toString('utf8')); await fs.writeFile(path.join(dirs.dependencies, 'requirements.lock'), lock, { flag: 'wx' });
  const suffix = s.project + '-' + randomBytes(4).toString('hex'), dependencyTag = 'salmora-verifier-deps:' + suffix;
  const dependencies = await buildImage(s, { context: dirs.dependencies, recipeText: pythonDependencyRecipe(pins['worker-base'].reference), tag: dependencyTag, online: true });
  const files = selectedProductFiles(snapshot, WORKER_ROOTS); check(files.length, 'PRODUCT_WORKER_SOURCE_REQUIRED'); await copyInputs(sourceRoot, dirs.product, files);
  const product = await buildImage(s, { context: dirs.product, recipeText: workerRecipe(dependencyTag), tag: 'salmora-portable-worker:' + suffix, online: false });
  check(await docker(s, ['image', 'inspect', dependencyTag, '--format', '{{.Id}}']) === dependencies.imageId, 'PRODUCT_DEPENDENCY_IMAGE_DRIFT');
  check(snapshotSource(sourceRoot).digest === snapshot.digest, 'PRODUCT_BUILD_SOURCE_DRIFT');
  s.workerImage = product.imageId; s.sourceDigest = digest(canonical(files)); await save(s); await render(s);
  const receipt = { status: 'BUILT', ...scope, imageId: product.imageId, sourceDigest: s.sourceDigest, sourceIdentity: snapshot.digest, inputs: files, lockDigest: entry.digest, normalizedLockDigest: digest(lock), dependencies, product };
  await write(path.join(s.dir, 'evidence', 'trusted-worker-build.json'), receipt); return receipt;
}

export async function buildTrustedWeb(s, sourceRoot, privateRoot) {
  const pins = await trustedPins(), manifest = await read(path.join(TRUSTED_INFRA, 'product-manifest.json')), snapshot = snapshotSource(sourceRoot), dirs = await directories(privateRoot, 'web');
  const inputs = cacheInputs({ candidateRoot: sourceRoot, roots: ['', 'apps/web', 'apps/mcp-bridge'] });
  for (const file of inputs.files) { const target = path.join(dirs.dependencies, file.path); await fs.mkdir(path.dirname(target), { recursive: true }); await fs.writeFile(target, file.content, { flag: 'wx' }); }
  const suffix = s.project + '-' + randomBytes(4).toString('hex'), dependencyTag = 'salmora-verifier-deps:' + suffix;
  const dependencies = await buildImage(s, { context: dirs.dependencies, recipeText: nodeDependencyRecipe(pins.node.reference, inputs), tag: dependencyTag, online: true });
  const files = selectedProductFiles(snapshot, [...WEB_ROOTS, 'package.json', 'package-lock.json']); await copyInputs(sourceRoot, dirs.product, files);
  const identity = { schemaVersion: 'salmora.portable-build.v1', sourceCommit: snapshot.head, sourceInputs: Object.fromEntries(files.map((file) => [file.path, file.digest.replace('sha256:', '')])), projectId: s.product.projectId, profile: manifest.profile, components: manifest.functions };
  await write(path.join(dirs.product, 'public-build.json'), identity);
  const product = await buildImage(s, { context: dirs.product, recipeText: webRecipe({ dependencyTag, nodeImage: pins.node.reference, caddyImage: pins.caddy.reference }), tag: 'salmora-portable-web:' + suffix, online: false });
  check(await docker(s, ['image', 'inspect', dependencyTag, '--format', '{{.Id}}']) === dependencies.imageId, 'PRODUCT_DEPENDENCY_IMAGE_DRIFT');
  check(cacheInputs({ candidateRoot: sourceRoot, roots: inputs.roots }).digest === inputs.digest && snapshotSource(sourceRoot).digest === snapshot.digest, 'PRODUCT_BUILD_SOURCE_DRIFT');
  Object.assign(s, await load(s.dir)); s.product.webImage = product.imageId; s.product.webSourceDigest = digest(canonical(files)); s.product.webMcpVersion = 1;
  check(!s.product.mcpOAuth, 'PRODUCT_TRUSTED_WEB_PROVIDER_OAUTH_UNSUPPORTED');
  await fs.writeFile(path.join(s.dir, 'config', 'Caddyfile'), (await fs.readFile(path.join(TRUSTED_INFRA, 'Caddyfile.product'), 'utf8')).replaceAll('\r\n', '\n').replace('# F09_MCP_ROUTES', ''));
  await save(s); await dc(s, ['up', '-d', '--no-deps', '--pull', 'never', 'gateway']); await refreshEndpoint(s);
  const receipt = { status: 'BUILT', ...scope, imageId: product.imageId, sourceIdentity: snapshot.digest, inputs: files, dependencyInputs: inputs.files.map(({ content: _content, ...file }) => file), dependencyInputDigest: inputs.digest, dependencies, product };
  await write(path.join(s.dir, 'evidence', 'trusted-web-build.json'), receipt); return receipt;
}
