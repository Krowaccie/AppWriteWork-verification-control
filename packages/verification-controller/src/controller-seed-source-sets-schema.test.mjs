import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { parse } from 'acorn';

import {
  CONTROLLER_VALIDATION_TEST_PATHS,
  VALIDATION_CONTROLLER_RELOCATIONS,
  validateControllerSourceSetDescriptor,
} from '../../../scripts/verification/controller-source-set-contract.mjs';

const TEST_READER = 'packages/verification-controller/src/test-cloud-source-artifact-reader.mjs';
const TEST_READER_TEST = 'packages/verification-controller/src/test-cloud-source-artifact-reader.test.mjs';
const REPOSITORY_ATTRIBUTES = '.gitattributes';
const REPOSITORY_IGNORE = '.gitignore';
const SOURCE_VERIFY_MAIN_WORKFLOW = '.github/workflows/verify-main.yml';
const TEST_PROVIDER_CORPUS = 'dev/verification/fixtures/test-cloud-provider-contract.v1.corpus.json';
const TEST_SETUP_CORPUS = 'dev/verification/fixtures/test-cloud-setup-readback.v1.corpus.json';
const APPWRITE_TEST_SETUP_DOCUMENT = 'docs/verification/APPWRITE-TEST-SETUP.md';
const CONTROLLER_SETUP_DOCUMENT = 'docs/verification/CONTROLLER-SETUP.md';
const TRUST_MATERIALS_TEST_HELPER = 'scripts/verification/controller-trust-materials-test-helper.mjs';
const HOSTED_ARTIFACT_HANDOFF = 'scripts/verification/hosted-artifact-handoff.mjs';
const TEST_CONTROL_HELPER = 'scripts/verification/test-cloud-control-test-helper.mjs';
const TEST_REAL_COMPOSITION_FIXTURE = 'scripts/verification/test-cloud-real-composition-fixture.mjs';
const VALIDATION_WORKFLOW = 'packages/verification-controller/workflows/controller-validation.yml';
const CONTROLLER_VALIDATION_TESTS = Object.freeze([
  'packages/verification-controller/src/appwrite-test-browser-policy.test.mjs',
  'packages/verification-controller/src/appwrite-test-live-readback.test.mjs',
  'packages/verification-controller/src/appwrite-test-setup-bindings.test.mjs',
  'packages/verification-controller/src/collect-appwrite-test-readback-workflow.test.mjs',
  'packages/verification-controller/src/collect-appwrite-test-readback.test.mjs',
  'packages/verification-controller/src/controller-bundle-publisher.test.mjs',
  'packages/verification-controller/src/controller-seed-source-sets-schema.test.mjs',
  'packages/verification-controller/src/prepare-controller-artifact.test.mjs',
  'packages/verification-controller/src/production-exact-sha-git-adapter.test.mjs',
  'packages/verification-controller/src/recover-appwrite-test-workflow.test.mjs',
  'packages/verification-controller/src/source-artifact-reader.test.mjs',
  'packages/verification-controller/src/test-cloud-binding-artifact-verifier.test.mjs',
  'packages/verification-controller/src/test-cloud-binding-workflows.test.mjs',
  'packages/verification-controller/src/test-cloud-browser-artifact-set.test.mjs',
  'packages/verification-controller/src/test-cloud-browser-route-adapter.test.mjs',
  'packages/verification-controller/src/test-cloud-cleanup-driver.test.mjs',
  'packages/verification-controller/src/test-cloud-contained-browser-scenario-adapter.test.mjs',
  'packages/verification-controller/src/test-cloud-controller-binding-directory.test.mjs',
  'packages/verification-controller/src/test-cloud-controller-source-diagnostics.test.mjs',
  'packages/verification-controller/src/test-cloud-controller.test.mjs',
  'packages/verification-controller/src/test-cloud-fixture-clock.test.mjs',
  'packages/verification-controller/src/test-cloud-fixture-intent-producer.test.mjs',
  'packages/verification-controller/src/test-cloud-provider-bootstrap.test.mjs',
  'packages/verification-controller/src/test-cloud-recovery-controller.test.mjs',
  TEST_READER_TEST,
]);
const CONTROLLER_VALIDATION_SUPPORT = Object.freeze([
  REPOSITORY_ATTRIBUTES,
  REPOSITORY_IGNORE,
  SOURCE_VERIFY_MAIN_WORKFLOW,
  TEST_PROVIDER_CORPUS,
  TEST_SETUP_CORPUS,
  APPWRITE_TEST_SETUP_DOCUMENT,
  CONTROLLER_SETUP_DOCUMENT,
  TRUST_MATERIALS_TEST_HELPER,
  HOSTED_ARTIFACT_HANDOFF,
  TEST_CONTROL_HELPER,
  TEST_REAL_COMPOSITION_FIXTURE,
].sort());
const GENERATED_VALIDATION_DESTINATIONS = Object.freeze([
  'seed-content-manifest.v1.json',
]);

function visitAst(ast, visitor) {
  const pending = [ast];
  const seen = new WeakSet();
  while (pending.length > 0) {
    const node = pending.pop();
    if (seen.has(node)) continue;
    seen.add(node);
    visitor(node);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child !== null && typeof child?.type === 'string') pending.push(child);
        }
      } else if (value !== null && typeof value?.type === 'string') {
        pending.push(value);
      }
    }
  }
}

function patternIdentifiers(pattern) {
  if (pattern?.type === 'Identifier') return [pattern];
  if (pattern?.type === 'RestElement') return patternIdentifiers(pattern.argument);
  if (pattern?.type === 'AssignmentPattern') return patternIdentifiers(pattern.left);
  if (pattern?.type === 'ArrayPattern') {
    return pattern.elements.flatMap((element) => patternIdentifiers(element));
  }
  if (pattern?.type === 'ObjectPattern') {
    return pattern.properties.flatMap((property) => (
      property.type === 'RestElement'
        ? patternIdentifiers(property.argument)
        : patternIdentifiers(property.value)
    ));
  }
  return [];
}

function lexicalContext(ast) {
  const nodeScopes = new WeakMap();
  const functionBindings = new WeakMap();
  const createScope = (parent, type) => ({ parent, type, bindings: new Map() });
  const rootScope = createScope(null, 'program');
  const declare = (scope, identifier, binding) => {
    const previous = scope.bindings.get(identifier.name);
    if (previous === undefined) {
      scope.bindings.set(identifier.name, binding);
      return binding;
    }
    previous.ambiguous = true;
    return previous;
  };
  const nearestVarScope = (scope) => {
    let current = scope;
    while (current.parent !== null && !['function', 'program'].includes(current.type)) {
      current = current.parent;
    }
    return current;
  };
  const walk = (node, incomingScope) => {
    if (node === null || typeof node?.type !== 'string') return;
    let scope = incomingScope;
    let functionBinding;
    if (node.type === 'FunctionDeclaration' && node.id !== null) {
      functionBinding = declare(incomingScope, node.id, {
        kind: 'function',
        node,
        scope: incomingScope,
        ambiguous: false,
      });
      functionBindings.set(node, functionBinding);
    } else if (node.type === 'ClassDeclaration' && node.id !== null) {
      declare(incomingScope, node.id, {
        kind: 'class', node, scope: incomingScope, ambiguous: false,
      });
    }
    if (node.type === 'Program') scope = rootScope;
    else if (
      node.type === 'FunctionDeclaration'
      || node.type === 'FunctionExpression'
      || node.type === 'ArrowFunctionExpression'
    ) {
      scope = createScope(incomingScope, 'function');
      if (functionBinding !== undefined && node.id !== null) {
        scope.bindings.set(node.id.name, functionBinding);
      }
      for (const parameter of node.params) {
        for (const identifier of patternIdentifiers(parameter)) {
          declare(scope, identifier, {
            kind: 'parameter', node: identifier, scope, ambiguous: false,
          });
        }
      }
    } else if (node.type === 'BlockStatement') {
      scope = createScope(incomingScope, 'block');
    } else if (node.type === 'CatchClause') {
      scope = createScope(incomingScope, 'catch');
      for (const identifier of patternIdentifiers(node.param)) {
        declare(scope, identifier, {
          kind: 'catch', node: identifier, scope, ambiguous: false,
        });
      }
    }
    nodeScopes.set(node, scope);
    if (node.type === 'ImportDeclaration') {
      const source = typeof node.source.value === 'string' ? node.source.value : undefined;
      for (const specifier of node.specifiers) {
        const importedName = specifier.type === 'ImportSpecifier'
          ? specifier.imported.name
          : specifier.type === 'ImportNamespaceSpecifier'
            ? '*'
            : 'default';
        declare(scope, specifier.local, {
          kind: 'import', node: specifier, scope, source, importedName, ambiguous: false,
        });
      }
    }
    if (node.type === 'VariableDeclaration') {
      const declarationScope = node.kind === 'var' ? nearestVarScope(scope) : scope;
      for (const declaration of node.declarations) {
        for (const identifier of patternIdentifiers(declaration.id)) {
          declare(declarationScope, identifier, {
            kind: node.kind,
            node: declaration,
            init: declaration.id.type === 'Identifier' ? declaration.init : null,
            scope: declarationScope,
            ambiguous: false,
          });
        }
      }
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'type') continue;
      if (Array.isArray(value)) {
        for (const child of value) walk(child, scope);
      } else {
        walk(value, scope);
      }
    }
  };
  walk(ast, rootScope);
  const resolve = (identifier) => {
    let scope = nodeScopes.get(identifier);
    while (scope !== undefined && scope !== null) {
      const binding = scope.bindings.get(identifier.name);
      if (binding !== undefined) return binding;
      scope = scope.parent;
    }
    return undefined;
  };
  return Object.freeze({ nodeScopes, functionBindings, resolve, rootScope });
}

function constantString(node, lexical, resolving = new Set()) {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node?.type === 'Identifier') {
    const binding = lexical.resolve(node);
    if (
      binding === undefined
      || binding.ambiguous
      || binding.kind !== 'const'
      || binding.init === null
      || resolving.has(binding)
    ) return undefined;
    resolving.add(binding);
    const value = constantString(binding.init, lexical, resolving);
    resolving.delete(binding);
    return value;
  }
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked;
  }
  if (node?.type === 'BinaryExpression' && node.operator === '+') {
    const left = constantString(node.left, lexical, resolving);
    const right = constantString(node.right, lexical, resolving);
    if (typeof left === 'string' && typeof right === 'string') return left + right;
  }
  return undefined;
}

function importedBinding(identifier, lexical, source, importedName) {
  const binding = lexical.resolve(identifier);
  return binding?.kind === 'import'
    && binding.ambiguous === false
    && binding.source === source
    && (importedName === undefined || binding.importedName === importedName);
}

function pathCall(node, lexical, method) {
  return node?.type === 'CallExpression'
    && node.callee.type === 'MemberExpression'
    && !node.callee.computed
    && node.callee.object.type === 'Identifier'
    && importedBinding(node.callee.object, lexical, 'node:path')
    && node.callee.property?.name === method;
}

function verifiedRepositoryRoot(identifier, lexical, sourcePath) {
  const binding = lexical.resolve(identifier);
  if (
    binding === undefined
    || binding.ambiguous
    || binding.kind !== 'const'
    || binding.scope.type !== 'program'
    || !pathCall(binding.init, lexical, 'resolve')
  ) return false;
  const [base, ...segments] = binding.init.arguments;
  if (
    !pathCall(base, lexical, 'dirname')
    || base.arguments.length !== 1
    || base.arguments[0].type !== 'CallExpression'
    || base.arguments[0].callee.type !== 'Identifier'
    || !importedBinding(base.arguments[0].callee, lexical, 'node:url', 'fileURLToPath')
    || base.arguments[0].arguments.length !== 1
    || !isImportMeta(base.arguments[0].arguments[0])
  ) return false;
  const values = segments.map((segment) => constantString(segment, lexical));
  if (
    values.some((segment) => typeof segment !== 'string')
    || values.some((segment) => path.posix.isAbsolute(segment) || path.win32.isAbsolute(segment))
  ) return false;
  return path.posix.resolve('/repository', path.posix.dirname(sourcePath), ...values)
    === '/repository';
}

function rootRelativePath(node, lexical, sourcePath, resolving = new Set()) {
  if (node?.type === 'Identifier') {
    const binding = lexical.resolve(node);
    if (
      binding === undefined
      || binding.ambiguous
      || binding.kind !== 'const'
      || binding.init === null
      || resolving.has(binding)
    ) return undefined;
    resolving.add(binding);
    const value = rootRelativePath(binding.init, lexical, sourcePath, resolving);
    resolving.delete(binding);
    return value;
  }
  if (
    node?.type !== 'CallExpression'
    || node.callee.type !== 'MemberExpression'
    || node.callee.computed
    || node.callee.object.type !== 'Identifier'
    || !['join', 'resolve'].includes(node.callee.property?.name)
    || !importedBinding(node.callee.object, lexical, 'node:path')
    || node.arguments.length < 2
    || node.arguments[0].type !== 'Identifier'
    || !['ROOT', 'repositoryRoot', 'root'].includes(node.arguments[0].name)
  ) return undefined;
  const suffix = node.arguments.slice(1)
    .map((argument) => constantString(argument, lexical));
  if (suffix.some((segment) => typeof segment !== 'string')) return undefined;
  if (suffix.some((segment) => (
    segment.includes('\\')
    || path.posix.isAbsolute(segment)
    || path.win32.isAbsolute(segment)
  ))) {
    throw new TypeError(`escaping repository-root path: ${sourcePath}`);
  }
  const normalized = path.posix.normalize(path.posix.join(...suffix));
  if (
    normalized === '.'
    || normalized === '..'
    || normalized.startsWith('../')
    || path.posix.isAbsolute(normalized)
  ) throw new TypeError(`escaping repository-root path: ${sourcePath}`);
  // A statically named but unverified root is never trusted as containment
  // evidence. Conservatively retaining its literal suffix makes the closed
  // seed graph reject an unseeded dependency instead of silently ignoring it.
  if (!verifiedRepositoryRoot(node.arguments[0], lexical, sourcePath)) {
    const rootBinding = lexical.resolve(node.arguments[0]);
    if (rootBinding?.kind === 'const' && rootBinding.scope.type === 'program') {
      throw new TypeError(`unverified repository-root binding: ${sourcePath}`);
    }
    return normalized;
  }
  return normalized;
}

function isImportMeta(node) {
  const meta = node?.type === 'MemberExpression' && !node.computed
    && node.property?.name === 'url'
    ? node.object
    : node;
  return meta?.type === 'MetaProperty'
    && meta.meta?.name === 'import'
    && meta.property?.name === 'meta';
}

function localTarget(sourcePath, specifier) {
  if (typeof specifier !== 'string' || specifier.length === 0) return null;
  const withoutSuffix = specifier.split(/[?#]/u, 1)[0];
  if (withoutSuffix.endsWith('/')) return null;
  if (!withoutSuffix.startsWith('./') && !withoutSuffix.startsWith('../')) return null;
  const target = path.posix.normalize(path.posix.join(path.posix.dirname(sourcePath), withoutSuffix));
  if (target === '..' || target.startsWith('../') || path.posix.isAbsolute(target)) {
    throw new TypeError(`escaping validation dependency: ${sourcePath} -> ${specifier}`);
  }
  return target;
}

function barePackageName(specifier) {
  if (
    typeof specifier !== 'string'
    || specifier.startsWith('./')
    || specifier.startsWith('../')
    || specifier.startsWith('node:')
    || specifier.startsWith('data:')
    || specifier.startsWith('file:')
  ) return null;
  const segments = specifier.split('/');
  return specifier.startsWith('@') ? segments.slice(0, 2).join('/') : segments[0];
}

function containsBinding(node, expectedBinding, lexical) {
  let found = false;
  visitAst(node, (candidate) => {
    if (candidate.type === 'Identifier' && lexical.resolve(candidate) === expectedBinding) found = true;
  });
  return found;
}

function fsReaderCall(node, lexical) {
  if (node?.type !== 'CallExpression') return false;
  if (node.callee.type === 'Identifier') {
    const binding = lexical.resolve(node.callee);
    return binding?.kind === 'import'
      && binding.ambiguous === false
      && ['node:fs', 'node:fs/promises'].includes(binding.source)
      && ['readFile', 'readFileSync'].includes(binding.importedName);
  }
  if (
    node.callee.type === 'MemberExpression'
    && !node.callee.computed
    && node.callee.object.type === 'Identifier'
    && ['readFile', 'readFileSync'].includes(node.callee.property?.name)
  ) {
    const binding = lexical.resolve(node.callee.object);
    return binding?.kind === 'import'
      && binding.ambiguous === false
      && ['node:fs', 'node:fs/promises'].includes(binding.source)
      && binding.importedName === '*';
  }
  return false;
}

function fileReadWrapperBindings(ast, lexical) {
  const wrappers = new Set();
  visitAst(ast, (node) => {
    if (
      node.type !== 'FunctionDeclaration'
      || node.id === null
      || node.params.length === 0
      || node.params[0].type !== 'Identifier'
    ) return;
    const parameterBinding = lexical.resolve(node.params[0]);
    const functionBinding = lexical.functionBindings.get(node);
    if (parameterBinding === undefined || functionBinding === undefined) return;
    visitAst(node.body, (candidate) => {
      if (
        !fsReaderCall(candidate, lexical)
        || candidate.arguments.length === 0
        || !containsBinding(candidate.arguments[0], parameterBinding, lexical)
      ) return;
      wrappers.add(functionBinding);
    });
  });
  return wrappers;
}

function repositoryReadPath(node, lexical, sourcePath) {
  const literal = constantString(node, lexical);
  if (typeof literal === 'string') {
    if (literal.includes('\\') || path.posix.isAbsolute(literal) || path.win32.isAbsolute(literal)) {
      throw new TypeError(`escaping repository-root path: ${sourcePath}`);
    }
    const normalized = path.posix.normalize(literal);
    if (normalized === '..' || normalized.startsWith('../')) {
      throw new TypeError(`escaping repository-root path: ${sourcePath}`);
    }
    return normalized.startsWith('./') ? normalized.slice(2) : normalized;
  }
  return rootRelativePath(node, lexical, sourcePath);
}

function staticReferences(sourcePath, sourceText) {
  const ast = parse(sourceText, {
    ecmaVersion: 'latest',
    sourceType: 'module',
    allowHashBang: true,
  });
  const lexical = lexicalContext(ast);
  const readWrappers = fileReadWrapperBindings(ast, lexical);
  const local = new Set();
  const packages = new Set();
  const addSpecifier = (specifier) => {
    const target = localTarget(sourcePath, specifier);
    if (target !== null) local.add(target);
    const packageName = barePackageName(specifier);
    if (packageName !== null) packages.add(packageName);
  };
  visitAst(ast, (node) => {
    if (
      node.type === 'ImportDeclaration'
      || node.type === 'ExportAllDeclaration'
      || (node.type === 'ExportNamedDeclaration' && node.source !== null)
    ) {
      addSpecifier(constantString(node.source, lexical));
      return;
    }
    if (node.type === 'ImportExpression') {
      addSpecifier(constantString(node.source, lexical));
      return;
    }
    if (
      node.type === 'NewExpression'
      && node.callee.type === 'Identifier'
      && node.callee.name === 'URL'
      && node.arguments.length >= 2
      && isImportMeta(node.arguments[1])
    ) {
      addSpecifier(constantString(node.arguments[0], lexical));
      return;
    }
    if (node.type !== 'CallExpression' || node.arguments.length === 0) return;
    if (
      !fsReaderCall(node, lexical)
      && !(
        node.callee.type === 'Identifier'
        && readWrappers.has(lexical.resolve(node.callee))
      )
    ) return;
    const literalPath = repositoryReadPath(node.arguments[0], lexical, sourcePath);
    if (
      typeof literalPath === 'string'
      && !literalPath.startsWith('./')
      && !literalPath.startsWith('../')
      && /^[a-z0-9._-]+(?:\/[a-z0-9._-]+)*$/iu.test(literalPath)
    ) {
      local.add(path.posix.normalize(literalPath));
    }
  });
  return {
    local: [...local].sort(),
    packages: [...packages].sort(),
  };
}

async function validationDependencyGraph(sourceSets) {
  const validated = validateControllerSourceSetDescriptor(sourceSets);
  assert.notEqual(validated, null);
  const overlaySourceRoot = 'packages/verification-controller/controller-repository-seed';
  let sourceLayout = true;
  try {
    const metadata = await lstat(overlaySourceRoot);
    assert.equal(metadata.isSymbolicLink(), false);
    assert.equal(metadata.isDirectory(), true);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    sourceLayout = false;
  }
  const mapping = new Map(validated.mappings.flatMap(({ sourcePath, destinationPath }) => (
    sourceLayout
      ? [[sourcePath, destinationPath], [destinationPath, destinationPath]]
      : [[destinationPath, destinationPath]]
  )));
  const generated = new Set(GENERATED_VALIDATION_DESTINATIONS);
  const packageJson = JSON.parse(await readFile('packages/verification-controller/package.json', 'utf8'));
  const allowedPackages = new Set([
    ...Object.keys(packageJson.dependencies ?? {}),
    ...Object.keys(packageJson.devDependencies ?? {}),
  ]);
  const pending = [...CONTROLLER_VALIDATION_TEST_PATHS];
  const visited = new Set();
  const packageReferences = new Set();
  while (pending.length > 0) {
    const currentPath = pending.pop();
    if (visited.has(currentPath)) continue;
    visited.add(currentPath);
    assert.equal(
      mapping.has(currentPath) || generated.has(currentPath),
      true,
      `unseeded validation dependency: ${currentPath}`,
    );
    if (generated.has(currentPath) || !currentPath.endsWith('.mjs')) continue;
    const references = staticReferences(currentPath, await readFile(currentPath, 'utf8'));
    for (const packageName of references.packages) packageReferences.add(packageName);
    pending.push(...references.local);
  }
  for (const packageName of packageReferences) {
    assert.equal(allowedPackages.has(packageName), true, `unlocked validation package: ${packageName}`);
  }
  return Object.freeze({
    files: Object.freeze([...visited].sort()),
    packages: Object.freeze([...packageReferences].sort()),
  });
}

async function plainFileInventory(root, relative = '') {
  const directory = relative === '' ? root : path.join(root, ...relative.split('/'));
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = relative === '' ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) files.push(...await plainFileInventory(root, entryPath));
    else if (entry.isFile()) files.push(entryPath);
    else throw new TypeError(`non-plain overlay member: ${entryPath}`);
  }
  return files.sort();
}

async function readPlainFile(filePath, dependencies = {}) {
  const inspect = dependencies.lstatFile ?? lstat;
  const readBytes = dependencies.readBytes ?? readFile;
  const metadata = await inspect(filePath);
  assert.equal(metadata.isSymbolicLink(), false, `linked materialized member: ${filePath}`);
  assert.equal(metadata.isFile(), true, `non-file materialized member: ${filePath}`);
  return readBytes(filePath);
}

async function validateMaterializedOverlayInventory(
  overlayFiles,
  seedManifest,
  dependencies = {},
) {
  const overlayRecords = seedManifest.files.filter(({ owner }) => owner === 'overlay');
  assert.deepEqual(overlayRecords.map(({ path: filePath }) => filePath), overlayFiles);
  for (const record of overlayRecords) {
    assert.equal(record.mode, '100644', `non-regular overlay mode: ${record.path}`);
    const bytes = await readPlainFile(record.path, dependencies);
    assert.equal(
      `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
      record.sha256,
      record.path,
    );
  }
}

test('controller seed schema and descriptor select only the final validation closure', async () => {
  const [schema, sourceSets] = await Promise.all([
    readFile('dev/verification/schemas/controller-seed-source-sets.v1.schema.json', 'utf8')
      .then(JSON.parse),
    readFile('packages/verification-controller/controller-seed-source-sets.v1.json', 'utf8')
      .then(JSON.parse),
  ]);
  const closure = schema.$defs.controller.allOf[1];
  assert.equal(Object.hasOwn(closure, 'oneOf'), false);
  const expected = closure.properties.relocations.const;
  const actual = sourceSets.sets.find(({ name }) => name === 'controller').relocations;
  assert.deepEqual(actual, expected);
  assert.deepEqual(actual, VALIDATION_CONTROLLER_RELOCATIONS);
  assert.deepEqual(actual.map(({ destination }) => destination), [
    'package-lock.json',
    'package.json',
    '.github/workflows/collect-appwrite-test-readback.yml',
    '.github/workflows/controller-validation.yml',
    '.github/workflows/production-readonly.yml',
    '.github/workflows/publish-controller-bundle.yml',
    '.github/workflows/recover-appwrite-test.yml',
    '.github/workflows/release-production.yml',
    '.github/workflows/verify-test-cloud.yml',
  ]);
  const requiredFiles = closure.properties.files.allOf.map(({ contains }) => contains.const);
  assert.equal(requiredFiles.includes('packages/verification-controller/workflows/recover-appwrite-test.yml'), true);
  assert.equal(requiredFiles.includes(VALIDATION_WORKFLOW), true);
});

test('Tasks 10-11 descriptor closes the approved validation inventory and literal validation relocation', async () => {
  const sourceSets = JSON.parse(await readFile(
    'packages/verification-controller/controller-seed-source-sets.v1.json',
    'utf8',
  ));
  assert.deepEqual(sourceSets.sets.map(({ name }) => name), [
    'overlay',
    'controller',
    'tooling',
    'validation-only',
  ]);
  const controller = sourceSets.sets[1];
  const validationOnly = sourceSets.sets[3];
  assert.equal(controller.files.includes(TEST_READER), true);
  assert.equal(controller.files.includes(TEST_READER_TEST), false);
  assert.deepEqual(validationOnly, {
    name: 'validation-only',
    sourceRoot: '',
    files: [...CONTROLLER_VALIDATION_TESTS, ...CONTROLLER_VALIDATION_SUPPORT].sort(),
    relocations: [],
  });
  assert.deepEqual(controller.relocations.find(({ source }) => source === VALIDATION_WORKFLOW), {
    source: VALIDATION_WORKFLOW,
    destination: '.github/workflows/controller-validation.yml',
  });
  assert.notEqual(validateControllerSourceSetDescriptor(sourceSets), null);

  const missingValidationOnly = structuredClone(sourceSets);
  missingValidationOnly.sets.pop();
  assert.equal(validateControllerSourceSetDescriptor(missingValidationOnly), null);

  const inferredFromSuffix = structuredClone(sourceSets);
  inferredFromSuffix.sets[3].files = [
    'packages/verification-controller/src/arbitrary.test.mjs',
  ];
  assert.equal(validateControllerSourceSetDescriptor(inferredFromSuffix), null);

  const duplicateOwner = structuredClone(sourceSets);
  duplicateOwner.sets[1].files.push(TEST_READER_TEST);
  duplicateOwner.sets[1].files.sort();
  assert.equal(validateControllerSourceSetDescriptor(duplicateOwner), null);

  const wrongValidationDestination = structuredClone(sourceSets);
  wrongValidationDestination.sets[1].relocations.find(
    ({ source }) => source === VALIDATION_WORKFLOW,
  ).destination = '.github/workflows/not-controller-validation.yml';
  assert.equal(validateControllerSourceSetDescriptor(wrongValidationDestination), null);
});

test('all 25 protected controller tests close their recursive local dependency graph', async () => {
  assert.deepEqual(CONTROLLER_VALIDATION_TESTS, CONTROLLER_VALIDATION_TEST_PATHS);
  const sourceSets = JSON.parse(await readFile(
    'packages/verification-controller/controller-seed-source-sets.v1.json',
    'utf8',
  ));
  const graph = await validationDependencyGraph(sourceSets);
  for (const supportPath of CONTROLLER_VALIDATION_SUPPORT) {
    assert.equal(graph.files.includes(supportPath), true, supportPath);
  }
  assert.equal(graph.files.length >= CONTROLLER_VALIDATION_TESTS.length, true);
});

test('static validation dependency discovery is scope-aware and fails closed on root ambiguity', () => {
  const shadowed = staticReferences('packages/verification-controller/src/example.test.mjs', `
    import { readFile } from 'node:fs/promises';
    const TARGET = 'unseeded.json';
    {
      const TARGET = 'seeded.json';
      void TARGET;
    }
    await readFile(TARGET);
  `);
  assert.equal(shadowed.local.includes('unseeded.json'), true);
  assert.equal(shadowed.local.includes('seeded.json'), false);

  const directRelative = staticReferences('packages/verification-controller/src/example.test.mjs', `
    import { readFile } from 'node:fs/promises';
    await readFile('./root-relative.json');
  `);
  assert.deepEqual(directRelative.local, ['root-relative.json']);

  const wrapperCollision = staticReferences('packages/verification-controller/src/example.test.mjs', `
    import { readFile } from 'node:fs/promises';
    function load(filePath) { return readFile(filePath); }
    {
      const load = () => undefined;
      load('inert.json');
    }
    await load('real.json');
  `);
  assert.equal(wrapperCollision.local.includes('real.json'), true);
  assert.equal(wrapperCollision.local.includes('inert.json'), false);

  assert.throws(
    () => staticReferences('packages/verification-controller/src/example.test.mjs', `
      import { readFile } from 'node:fs/promises';
      import path from 'node:path';
      import { fileURLToPath } from 'node:url';
      const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
      await readFile(path.resolve(ROOT, 'safe', '/outside.json'));
    `),
    /escaping repository-root path/u,
  );
  assert.throws(
    () => staticReferences('packages/verification-controller/src/example.test.mjs', `
      import { readFile } from 'node:fs/promises';
      import path from 'node:path';
      const ROOT = '/unverified';
      await readFile(path.join(ROOT, 'untrusted.json'));
    `),
    /unverified repository-root binding/u,
  );
});

test('tracked overlay descriptor classifies every committed candidate member exactly once', async () => {
  const sourceSets = JSON.parse(await readFile(
    'packages/verification-controller/controller-seed-source-sets.v1.json',
    'utf8',
  ));
  const overlay = sourceSets.sets.find(({ name }) => name === 'overlay');
  const overlaySourceRoot = 'packages/verification-controller/controller-repository-seed';
  let overlaySourceMetadata;
  try {
    overlaySourceMetadata = await lstat(overlaySourceRoot);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    overlaySourceMetadata = null;
  }
  if (overlaySourceMetadata !== null) {
    assert.equal(overlaySourceMetadata.isSymbolicLink(), false);
    assert.equal(overlaySourceMetadata.isDirectory(), true);
    assert.deepEqual(
      overlay.files,
      await plainFileInventory(overlaySourceRoot),
    );
    return;
  }
  const seedManifest = JSON.parse(
    await readPlainFile('seed-content-manifest.v1.json'),
  );
  await validateMaterializedOverlayInventory(overlay.files, seedManifest);
});

test('materialized overlay fallback rejects missing, extra, linked, mode-shifted, and drifted members', async () => {
  const bytes = Buffer.from('overlay-member', 'utf8');
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const record = Object.freeze({
    owner: 'overlay',
    path: 'a1-oci/entrypoint.mjs',
    mode: '100644',
    sha256: digest,
  });
  const regular = Object.freeze({
    isFile: () => true,
    isSymbolicLink: () => false,
  });
  const linked = Object.freeze({
    isFile: () => false,
    isSymbolicLink: () => true,
  });
  const dependencies = Object.freeze({
    lstatFile: async () => regular,
    readBytes: async () => bytes,
  });
  await validateMaterializedOverlayInventory(
    [record.path],
    { files: [record] },
    dependencies,
  );

  const cases = [
    ['missing record', [], dependencies],
    ['extra record', [record, { ...record, path: 'a1-oci/extra.mjs' }], dependencies],
    ['linked member', [record], { ...dependencies, lstatFile: async () => linked }],
    ['mode shift', [{ ...record, mode: '100755' }], dependencies],
    ['digest drift', [{ ...record, sha256: `sha256:${'0'.repeat(64)}` }], dependencies],
    ['missing file', [record], {
      ...dependencies,
      lstatFile: async () => {
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
    }],
  ];
  for (const [label, records, candidateDependencies] of cases) {
    await assert.rejects(
      validateMaterializedOverlayInventory(
        [record.path],
        { files: records },
        candidateDependencies,
      ),
      label,
    );
  }
});
