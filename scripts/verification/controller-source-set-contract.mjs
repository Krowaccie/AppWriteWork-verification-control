const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[\x21-\x7e]+$/u;
const SET_CONTRACT = Object.freeze([
  Object.freeze({
    name: 'overlay',
    sourceRoot: 'packages/verification-controller/controller-repository-seed',
  }),
  Object.freeze({ name: 'controller', sourceRoot: '' }),
  Object.freeze({ name: 'tooling', sourceRoot: '' }),
  Object.freeze({ name: 'validation-only', sourceRoot: '' }),
]);
const MATERIALIZER_SOURCE_PATH = 'scripts/verification/controller-seed-materializer-v1.mjs';
const SOURCE_SET_CONTRACT_PATH = 'scripts/verification/controller-source-set-contract.mjs';
export const CONTROLLER_VALIDATION_TEST_PATHS = Object.freeze([
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
  'packages/verification-controller/src/test-cloud-source-artifact-reader.test.mjs',
]);
export const CONTROLLER_VALIDATION_SUPPORT_PATHS = Object.freeze([
  '.gitattributes',
  '.gitignore',
  '.github/workflows/verify-main.yml',
  'dev/verification/fixtures/test-cloud-provider-contract.v1.corpus.json',
  'dev/verification/fixtures/test-cloud-setup-readback.v1.corpus.json',
  'docs/verification/APPWRITE-TEST-SETUP.md',
  'docs/verification/CONTROLLER-SETUP.md',
  'scripts/verification/controller-trust-materials-test-helper.mjs',
  'scripts/verification/hosted-artifact-handoff.mjs',
  'scripts/verification/test-cloud-control-test-helper.mjs',
  'scripts/verification/test-cloud-real-composition-fixture.mjs',
]);
export const CONTROLLER_VALIDATION_SEED_PATHS = Object.freeze([
  ...CONTROLLER_VALIDATION_TEST_PATHS,
  ...CONTROLLER_VALIDATION_SUPPORT_PATHS,
].sort());

export const RECOVERY_WORKFLOW_RELOCATION = Object.freeze({
  source: 'packages/verification-controller/workflows/recover-appwrite-test.yml',
  destination: '.github/workflows/recover-appwrite-test.yml',
});

export const CONTROLLER_VALIDATION_WORKFLOW_RELOCATION = Object.freeze({
  source: 'packages/verification-controller/workflows/controller-validation.yml',
  destination: '.github/workflows/controller-validation.yml',
});

export const PRODUCTION_READONLY_WORKFLOW_RELOCATION = Object.freeze({
  source: 'packages/verification-controller/workflows/production-readonly.yml',
  destination: '.github/workflows/production-readonly.yml',
});

export const RELEASE_PRODUCTION_WORKFLOW_RELOCATION = Object.freeze({
  source: 'packages/verification-controller/workflows/release-production.yml',
  destination: '.github/workflows/release-production.yml',
});

export const VALIDATION_CONTROLLER_RELOCATIONS = Object.freeze([
  Object.freeze({
    source: 'packages/verification-controller/package-lock.json',
    destination: 'package-lock.json',
  }),
  Object.freeze({
    source: 'packages/verification-controller/package.json',
    destination: 'package.json',
  }),
  Object.freeze({
    source: 'packages/verification-controller/workflows/collect-appwrite-test-readback.yml',
    destination: '.github/workflows/collect-appwrite-test-readback.yml',
  }),
  CONTROLLER_VALIDATION_WORKFLOW_RELOCATION,
  PRODUCTION_READONLY_WORKFLOW_RELOCATION,
  Object.freeze({
    source: 'packages/verification-controller/workflows/publish-controller-bundle.yml',
    destination: '.github/workflows/publish-controller-bundle.yml',
  }),
  Object.freeze({
    source: 'packages/verification-controller/workflows/verify-test-cloud.yml',
    destination: '.github/workflows/verify-test-cloud.yml',
  }),
  RECOVERY_WORKFLOW_RELOCATION,
  RELEASE_PRODUCTION_WORKFLOW_RELOCATION,
].sort((left, right) => (
  left.source < right.source ? -1 : left.source > right.source ? 1 : 0
)));

function exactObject(value, keys) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) return false;
  const names = Object.keys(value).sort();
  const expected = [...keys].sort();
  return names.length === expected.length
    && names.every((name, index) => name === expected[index]);
}

function ordinal(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function identity(value) {
  return value.toLowerCase();
}

export function isSafeControllerSourcePath(value, allowEmpty = false) {
  if (allowEmpty && value === '') return true;
  return typeof value === 'string'
    && SAFE_PATH.test(value)
    && !value.endsWith('/')
    && value.split('/').every((segment) => (
      segment !== ''
      && segment !== '.'
      && segment !== '..'
      && !segment.endsWith('.')
      && !segment.endsWith(' ')
    ));
}

function isSecretBearing(filePath) {
  const lower = filePath.toLowerCase();
  const segments = lower.split('/');
  const name = segments.at(-1);
  return name === '.env'
    || name.startsWith('.env.')
    || name === 'id_rsa'
    || name === 'id_ed25519'
    || name.endsWith('.pem')
    || name.endsWith('.key')
    || segments.some((segment) => (
      segment === 'credentials'
      || segment === 'secrets'
      || segment.includes('secret')
    ));
}

export function isProductionWorkflowPath(filePath) {
  const lower = filePath.toLowerCase();
  return (lower.startsWith('packages/verification-controller/workflows/')
      || lower.startsWith('.github/workflows/'))
    && (lower.includes('production') || lower.includes('release-production'));
}

export function isForbiddenControllerSourcePath(filePath) {
  const lower = filePath.toLowerCase();
  return lower.startsWith('src/web/src/')
    || lower.startsWith('packages/salmora-mcp/')
    || isSecretBearing(lower);
}

function joinSourcePath(sourceRoot, filePath) {
  return sourceRoot === '' ? filePath : `${sourceRoot}/${filePath}`;
}

function acceptedRelocations(relocations) {
  return JSON.stringify(relocations) === JSON.stringify(VALIDATION_CONTROLLER_RELOCATIONS);
}

export function validateControllerSourceSetDescriptor(value) {
  try {
    if (
      !exactObject(value, ['schemaVersion', 'sets'])
      || value.schemaVersion !== 'controller-seed-source-sets.v1'
      || !Array.isArray(value.sets)
      || value.sets.length !== SET_CONTRACT.length
    ) return null;
    const sets = [];
    const allMappings = [];
    const sourceOwners = new Map();
    for (let setIndex = 0; setIndex < value.sets.length; setIndex += 1) {
      const sourceSet = value.sets[setIndex];
      const expected = SET_CONTRACT[setIndex];
      if (
        !exactObject(sourceSet, ['name', 'sourceRoot', 'files', 'relocations'])
        || sourceSet.name !== expected.name
        || sourceSet.sourceRoot !== expected.sourceRoot
        || !Array.isArray(sourceSet.files)
        || sourceSet.files.length === 0
        || !Array.isArray(sourceSet.relocations)
      ) return null;
      const files = [...sourceSet.files];
      if (
        sourceSet.name === 'validation-only'
        && JSON.stringify(files) !== JSON.stringify(CONTROLLER_VALIDATION_SEED_PATHS)
      ) return null;
      if (files.some((filePath) => !isSafeControllerSourcePath(filePath))) return null;
      if (files.some((filePath) => (
        isForbiddenControllerSourcePath(filePath)
        || isForbiddenControllerSourcePath(joinSourcePath(sourceSet.sourceRoot, filePath))
      ))) return null;
      if (files.some((filePath, index) => index > 0 && ordinal(files[index - 1], filePath) >= 0)) {
        return null;
      }
      const fileIdentities = new Set(files.map(identity));
      if (fileIdentities.size !== files.length) return null;
      if (
        sourceSet.name === 'tooling'
        && files.includes(MATERIALIZER_SOURCE_PATH)
        && !files.includes(SOURCE_SET_CONTRACT_PATH)
      ) return null;

      const relocations = [];
      for (const candidate of sourceSet.relocations) {
        if (
          !exactObject(candidate, ['source', 'destination'])
          || !isSafeControllerSourcePath(candidate.source)
          || !isSafeControllerSourcePath(candidate.destination)
          || isForbiddenControllerSourcePath(candidate.source)
          || isForbiddenControllerSourcePath(candidate.destination)
          || !sourceSet.files.includes(candidate.source)
        ) return null;
        relocations.push({ source: candidate.source, destination: candidate.destination });
      }
      if (
        (sourceSet.name !== 'controller' && relocations.length !== 0)
        || (sourceSet.name === 'controller' && !acceptedRelocations(relocations))
      ) return null;
      if (sourceSet.name === 'controller') {
        const hasRecoveryFile = files.includes(RECOVERY_WORKFLOW_RELOCATION.source);
        const hasRecoveryRelocation = relocations.some(({ source, destination }) => (
          source === RECOVERY_WORKFLOW_RELOCATION.source
          && destination === RECOVERY_WORKFLOW_RELOCATION.destination
        ));
        if (hasRecoveryFile !== hasRecoveryRelocation) return null;
        const hasValidationFile = files.includes(
          CONTROLLER_VALIDATION_WORKFLOW_RELOCATION.source,
        );
        const hasValidationRelocation = relocations.some(({ source, destination }) => (
          source === CONTROLLER_VALIDATION_WORKFLOW_RELOCATION.source
          && destination === CONTROLLER_VALIDATION_WORKFLOW_RELOCATION.destination
        ));
        if (hasValidationFile !== hasValidationRelocation) return null;
      }

      const mappings = [
        ...files.map((filePath) => ({
          sourcePath: joinSourcePath(sourceSet.sourceRoot, filePath),
          destinationPath: filePath,
          relocated: false,
          validationOnly: sourceSet.name === 'validation-only',
        })),
        ...relocations.map(({ source, destination }) => ({
          sourcePath: joinSourcePath(sourceSet.sourceRoot, source),
          destinationPath: destination,
          relocated: true,
          validationOnly: false,
        })),
      ].sort((left, right) => (
        ordinal(left.sourcePath, right.sourcePath)
        || ordinal(left.destinationPath, right.destinationPath)
      ));
      for (const { sourcePath } of mappings) {
        const sourceIdentity = identity(sourcePath);
        const owner = sourceOwners.get(sourceIdentity);
        if (owner !== undefined && owner !== sourceSet.name) return null;
        sourceOwners.set(sourceIdentity, sourceSet.name);
      }
      allMappings.push(...mappings);
      sets.push(Object.freeze({
        name: sourceSet.name,
        sourceRoot: sourceSet.sourceRoot,
        files: Object.freeze(files),
        relocations: Object.freeze(relocations.map(Object.freeze)),
        mappings: Object.freeze(mappings.map(Object.freeze)),
      }));
    }
    const destinationIdentities = allMappings.map(({ destinationPath }) => identity(destinationPath));
    if (new Set(destinationIdentities).size !== destinationIdentities.length) return null;
    return Object.freeze({
      schemaVersion: value.schemaVersion,
      sets: Object.freeze(sets),
      mappings: Object.freeze([...allMappings].sort((left, right) => (
        ordinal(left.sourcePath, right.sourcePath)
        || ordinal(left.destinationPath, right.destinationPath)
      )).map(Object.freeze)),
    });
  } catch {
    return null;
  }
}
