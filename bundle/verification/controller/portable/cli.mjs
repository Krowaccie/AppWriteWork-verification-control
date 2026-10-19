import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { canonical, digest, exportBundle, resolveTrustedPath, verifyBundle, verifyPin } from './bundle.mjs';
import { createContainedRunner } from './contained-runner.mjs';
import { prepareNodeCache } from './dependency-cache.mjs';
import { controllerVerdict, runSourcePolicyAudit } from './source-policy.mjs';
import { loadPortableRegistry, selectPortableChecks } from '../../core/portable-registry.mjs';
import { runPortableVerification } from '../../portable/executor.mjs';

function parse(argv) {
  const [mode, ...remaining] = argv;
  if (!['export', 'verify', 'review-template', 'build-cache', 'run'].includes(mode)) throw new Error('USAGE: export|verify|review-template|build-cache|run with named options');
  const result = { mode };
  const allowed = new Set(['source', 'output', 'bundle', 'digest', 'pin', 'candidate', 'node-image', 'python-image', 'group', 'scope', 'node-cache', 'node-cache-review', 'base-image', 'cache-roots']);
  for (let index = 0; index < remaining.length; index += 2) {
    const key = remaining[index]?.replace(/^--/u, ''); const value = remaining[index + 1];
    if (!remaining[index]?.startsWith('--') || !allowed.has(key) || result[key] !== undefined || !value || value.startsWith('--')) throw new Error('CLI_OPTION_INVALID');
    result[key] = value;
  }
  return result;
}
function required(options, key) { if (!options[key]) throw new Error(`CLI_${key.toUpperCase()}_REQUIRED`); return options[key]; }
function under(root, filename) {
  const relative = path.relative(root, filename);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export async function controllerMain(argv, { print = (value) => process.stdout.write(`${canonical(value)}\n`) } = {}) {
  const options = parse(argv);
  if (options.mode === 'export') {
    const result = exportBundle({ sourceRoot: options.source, output: required(options, 'output') });
    print({ status: 'PREPARED_LOCAL', manifestDigest: result.manifestDigest, source: result.manifest.source, output: result.output, activated: false });
    return 0;
  }
  if (options.mode === 'verify' || options.mode === 'review-template') {
    const checked = verifyBundle({ bundleRoot: required(options, 'bundle'), expectedDigest: required(options, 'digest') });
    if (options.mode === 'verify') print({ status: 'PASS', claim: 'bundle-integrity-only', manifestDigest: checked.manifestDigest, independentProductAcceptance: false });
    else {
      const template = { schemaVersion: 'portable-verifier-pin.v1', manifestDigest: checked.manifestDigest, sourceRevision: checked.manifest.source.baseRevision, registryDigest: checked.registryDigest,
        review: { decision: 'PENDING', reviewer: '', reference: '', qualificationDigest: '' } };
      writeFileSync(required(options, 'output'), `${canonical(template)}\n`, { flag: 'wx' });
      print({ status: 'PENDING_REVIEW', automaticActivation: false });
    }
    return 0;
  }
  const candidateRoot = realpathSync(required(options, 'candidate'));
  const pinFilename = resolveTrustedPath(required(options, 'pin'), [candidateRoot]);
  if (under(candidateRoot, pinFilename)) throw new Error('CANDIDATE_WRITABLE_PIN_FORBIDDEN');
  const pinBytes = readFileSync(pinFilename);
  const pin = JSON.parse(pinBytes.toString('utf8'));
  const checked = verifyPin({ bundleRoot: required(options, 'bundle'), pin, candidateRoot });
  if (realpathSync(path.resolve(import.meta.dirname, '../../..')) !== checked.bundleRoot) throw new Error('PINNED_BUNDLE_LAUNCHER_REQUIRED');
  if (process.versions.node !== checked.manifest.runtime.node) throw new Error('PINNED_NODE_RUNTIME_REQUIRED');
  const outputRoot = resolveTrustedPath(required(options, 'output'), [candidateRoot, checked.bundleRoot]);
  if (under(candidateRoot, outputRoot) || under(checked.bundleRoot, outputRoot) || under(outputRoot, checked.bundleRoot) || under(outputRoot, candidateRoot)) throw new Error('TRUSTED_OUTPUT_OVERLAP');
  if (options.mode === 'build-cache') {
    const result = prepareNodeCache({ candidateRoot, output: outputRoot, baseImage: required(options, 'base-image'), verifierManifestDigest: checked.manifestDigest,
      ...(options['cache-roots'] ? { roots: options['cache-roots'].split(',').map((value) => value === 'root' ? '' : value) } : {}) });
    print({ status: 'PREPARED_LOCAL', imageId: result.descriptor.imageId, inputDigest: result.descriptor.inputDigest, review: 'PENDING', activated: false, output: result.output });
    return 0;
  }
  const scope = options.scope ?? 'repository';
  if (!['repository', 'source-policy', 'portable-product'].includes(scope) || (scope !== 'repository' && options.group)) throw new Error('CONTROLLER_SCOPE_INVALID');
  const sourcePolicy = runSourcePolicyAudit({ candidateRoot, verifierRoot: checked.bundleRoot });
  if (scope === 'portable-product' && sourcePolicy.status === 'PASS') {
    const { runTrustedProductAudit } = await import('./product-driver.mjs');
    const product = await runTrustedProductAudit({ candidateRoot, bundleRoot: checked.bundleRoot, pin, output: outputRoot });
    verifyPin({ bundleRoot: checked.bundleRoot, pin, candidateRoot });
    if (digest(readFileSync(pinFilename)) !== digest(pinBytes)) throw new Error('PIN_CHANGED_DURING_RUN');
    const receipt = { schemaVersion: 'portable-controller-run.v1', status: product.status, independent: product.status === 'PASS', scope,
      independentProductAcceptance: product.status === 'PASS', independentWholeRepositoryAcceptance: false, releaseEligible: false,
      manifestDigest: checked.manifestDigest, candidateSourceDigest: sourcePolicy.candidateSourceDigest, sourcePolicy, product,
      limitations: ['Trusted fixture recipes qualify product behavior; candidate installer Dockerfiles/native build recipes are separate obligations', 'Native Windows restricted execution and provider integrations are separate capabilities'] };
    writeFileSync(path.join(outputRoot, 'controller-result.json'), `${canonical(receipt)}\n`, { flag: 'wx' }); print(receipt);
    return product.status === 'PASS' ? 0 : product.status === 'FAIL' ? 1 : 2;
  }
  let contained; let result; let selectedSuites = [];
  if (scope === 'repository') {
    selectedSuites = selectPortableChecks({ registry: loadPortableRegistry({ root: checked.bundleRoot }), profile: 'repository' }).suites.filter((suite) => !options.group || suite.group === options.group);
  }
  if (scope === 'repository' && sourcePolicy.status === 'PASS') {
    if (Boolean(options['node-cache']) !== Boolean(options['node-cache-review'])) throw new Error('NODE_CACHE_DESCRIPTOR_AND_REVIEW_REQUIRED');
    const readCacheDocument = (name) => {
      if (!options[name]) return undefined;
      const filename = resolveTrustedPath(options[name], [candidateRoot, checked.bundleRoot]);
      if (under(candidateRoot, filename)) throw new Error('CANDIDATE_WRITABLE_CACHE_REVIEW_FORBIDDEN');
      return JSON.parse(readFileSync(filename, 'utf8'));
    };
    contained = createContainedRunner({ candidateRoot, images: { node: options['node-image'], python: options['python-image'] },
      nodeCache: readCacheDocument('node-cache'), nodeCacheReview: readCacheDocument('node-cache-review'), verifierManifestDigest: checked.manifestDigest });
    try {
      result = await runPortableVerification({ root: checked.bundleRoot, candidateRoot, profile: 'repository', outputRoot, group: options.group, runner: contained.runner, cleanup: contained.cleanup });
    } finally { contained.cleanup(); }
  } else {
    if (existsSync(outputRoot) && readdirSync(outputRoot).length) throw new Error('OUTPUT_NOT_EMPTY');
    mkdirSync(outputRoot, { recursive: true });
  }
  verifyPin({ bundleRoot: checked.bundleRoot, pin, candidateRoot });
  if (digest(readFileSync(pinFilename)) !== digest(pinBytes)) throw new Error('PIN_CHANGED_DURING_RUN');
  const receipt = { schemaVersion: 'portable-controller-run.v1', ...controllerVerdict({ scope, sourcePolicy, selectedSuites, result }),
    manifestDigest: checked.manifestDigest, candidateSourceDigest: sourcePolicy.candidateSourceDigest, containedCommands: contained?.receipts ?? [] };
  writeFileSync(path.join(outputRoot, 'controller-result.json'), `${canonical(receipt)}\n`, { flag: 'wx' });
  print(receipt);
  return receipt.status === 'PASS' ? 0 : receipt.status === 'FAIL' ? 1 : 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  controllerMain(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`${canonical({ status: 'BLOCKED', error: error.message, independent: false })}\n`); process.exitCode = 2;
  });
}
