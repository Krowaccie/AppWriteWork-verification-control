import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePythonLock, pythonDependencyRecipe, nodeDependencyRecipe, workerRecipe, webRecipe, productBuildArguments, selectedProductFiles } from './product-build.mjs';

const pinned = 'registry.example/image@sha256:' + 'a'.repeat(64);
const tag = 'salmora-verifier-deps:sm9-test-fixture-abc123';

test('Python dependency grammar retains exact versions and supported platform marker', () => {
  assert.equal(parsePythonLock('# comment\npsycopg-binary==3.3.6\r\ntzdata==2026.5; sys_platform == "win32"\n'), 'psycopg-binary==3.3.6\ntzdata==2026.5; sys_platform == "win32"\n');
});
test('Python network preparation rejects executable and unpinned requirement forms', () => {
  for (const text of ['--index-url https://private.invalid', '-e .', 'pkg @ https://private.invalid/pkg.whl', 'https://private.invalid/pkg.whl', './setup.py', 'pkg>=1', 'pkg==1 --hash=sha256:123', 'pkg[extra]==1', 'pkg==1; os_name == "nt"', 'pkg==1\nPKG==2', 'pkg==1\npkg_foo==1\npkg-foo==2', 'pkg==1\nRUN touch /evil', '']) {
    assert.throws(() => parsePythonLock(text), /PRODUCT_PYTHON_LOCK/u, text);
  }
});
test('Python dependency recipe downloads wheels only without dependency or project hooks', () => {
  const recipe = pythonDependencyRecipe(pinned);
  assert.match(recipe, /COPY requirements\.lock \/requirements\.lock/u);
  assert.match(recipe, /--isolated install .*--only-binary=:all: --no-deps --index-url https:\/\/pypi\.org\/simple/u);
  assert.equal((recipe.match(/^COPY /gmu) ?? []).length, 1);
  assert.doesNotMatch(recipe, /COPY \.|setup\.py|services\//u);
  assert.throws(() => pythonDependencyRecipe('python:latest'), /PINNED_BASE/u);
});
test('Node dependency preparation copies only validated metadata and disables lifecycle scripts', () => {
  const inputs = { roots: ['', 'apps/web'], files: [{ path: 'package.json' }, { path: 'package-lock.json' }, { path: 'apps/web/package.json' }, { path: 'apps/web/package-lock.json' }] };
  const recipe = nodeDependencyRecipe(pinned, inputs);
  const copies = recipe.split('\n').filter((line) => line.startsWith('COPY '));
  assert.equal(copies.length, 4);
  assert.ok(copies.every((line) => /package(?:-lock)?\.json/u.test(line)));
  assert.equal((recipe.match(/npm ci --ignore-scripts --no-audit --no-fund/gu) ?? []).length, 2);
  assert.doesNotMatch(recipe, /COPY \.|\.npmrc|npm run/u);
});
test('candidate product contexts exclude Docker recipes, caches and private files', () => {
  const paths = ['services/execution-worker-py/Dockerfile', 'services/execution-worker-py/salmora_worker/worker.py', 'apps/web/src/main.tsx', 'apps/web/node_modules/evil.js', 'apps/web/.npmrc', 'apps/web/dist/main.js', 'apps/web/key.pem', 'apps/web/credentials.private.json', 'apps/web/.env', 'infra/portable/Web.Dockerfile', 'elsewhere/secret.txt'];
  const selected = selectedProductFiles({ files: paths.map((path) => ({ path, kind: 'file', digest: 'sha256:' + 'a'.repeat(64) })) }, ['services/execution-worker-py', 'apps/web', 'infra/portable']);
  assert.deepEqual(selected.map((file) => file.path), ['services/execution-worker-py/salmora_worker/worker.py', 'apps/web/src/main.tsx']);
});
test('candidate source build always has explicit network none, dependency preparation is separate', () => {
  const options = { context: '/owned/product', recipe: '/owned/product/Dockerfile', iidFile: '/owned/product.id', tag: 'fixture:test' };
  const offline = productBuildArguments({ ...options, online: false }), online = productBuildArguments({ ...options, online: true });
  assert.deepEqual(offline.slice(0, 6), ['build', '--pull=false', '--network', 'none', '--memory', '1g']);
  assert.equal(online[online.indexOf('--network') + 1], 'default');
  assert.equal(offline.at(-1), '/owned/product');
});
test('trusted worker recipe copies fixed runtime source and never executes candidate Dockerfile', () => {
  const recipe = workerRecipe(tag);
  assert.equal((recipe.match(/^COPY /gmu) ?? []).length, 3);
  assert.match(recipe, /CMD \["python", "-m", "salmora_worker\.worker"\]/u);
  assert.doesNotMatch(recipe, /RUN |pip |Dockerfile/u);
  assert.throws(() => workerRecipe('untrusted:latest'), /DEPENDENCY_TAG/u);
});
test('trusted web recipe executes source inside offline stage and uses fixed final bases', () => {
  const recipe = webRecipe({ dependencyTag: tag, nodeImage: pinned, caddyImage: pinned });
  assert.match(recipe, /FROM salmora-verifier-deps:/u);
  assert.match(recipe, /RUN node \/source\/tools\/build\/bundle-catalog\.mjs && node \/source\/infra\/portable\/web-build\.mjs/u);
  assert.doesNotMatch(recipe, /npm ci|apt-get|pip install/u);
  assert.match(recipe, /COPY --from=build \/source\/apps\/web\/dist \/srv/u);
});
test('dependency metadata limits reject oversized and excessive locks', () => {
  assert.throws(() => parsePythonLock('#'.repeat(256 * 1024 + 1)), /PRODUCT_PYTHON_LOCK_INVALID/u);
  assert.throws(() => parsePythonLock(Array.from({ length: 513 }, (_, index) => 'package' + index + '==1').join('\n')), /PRODUCT_PYTHON_LOCK_INVALID/u);
});
