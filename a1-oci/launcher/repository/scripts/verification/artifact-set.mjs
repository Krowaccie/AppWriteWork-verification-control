import { buildArtifactSetInternal } from './artifact-set-build.mjs';
import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};

const RUNNER_ID = 'verification-runner-py';
const PRODUCT_IDS = Object.freeze(
  inventory.productFunctions.map(({ logicalId }) => logicalId).sort(),
);

const MESSAGES = Object.freeze({
  ARTIFACT_SCHEMA_INVALID: 'Artifact inventory does not match the validated repository collector.',
});

function diagnostic(code) {
  return Object.freeze({ code, safeMessage: MESSAGES[code], retryable: false });
}

function blocked(code) {
  return Object.freeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: Object.freeze([diagnostic(code)]),
  });
}

function pass(value) {
  return Object.freeze({ status: 'PASS', value, diagnostics: Object.freeze([]) });
}

function artifactUnit(entry) {
  try {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return null;
    const id = Object.getOwnPropertyDescriptor(entry, 'id')?.value;
    const sourcePath = Object.getOwnPropertyDescriptor(entry, 'path')?.value;
    const productionApplicable = Object.getOwnPropertyDescriptor(entry, 'productionApplicable')?.value;
    const testOnly = Object.getOwnPropertyDescriptor(entry, 'testOnly')?.value;
    if (
      typeof id !== 'string'
      || sourcePath !== `src/functions/${id}`
      || typeof productionApplicable !== 'boolean'
      || typeof testOnly !== 'boolean'
    ) return null;
    return Object.freeze({
      logicalId: id,
      sourcePath,
      runtime: 'python-3.12',
      entrypoint: 'main.py',
      productionApplicable,
      testOnly,
    });
  } catch {
    return null;
  }
}

export function collectValidatedRepositoryUnits(manifest) {
  try {
    if (
      manifest === null
      || typeof manifest !== 'object'
      || Array.isArray(manifest)
      || !Array.isArray(manifest.deployableUnits)
    ) return blocked('ARTIFACT_SCHEMA_INVALID');
    const units = manifest.deployableUnits.map(artifactUnit);
    if (units.some((entry) => entry === null)) return blocked('ARTIFACT_SCHEMA_INVALID');
    const ids = units.map(({ logicalId }) => logicalId);
    if (new Set(ids).size !== ids.length) return blocked('ARTIFACT_SCHEMA_INVALID');
    const releaseUnits = units
      .filter(({ productionApplicable, testOnly }) => productionApplicable && !testOnly)
      .sort((left, right) => left.logicalId < right.logicalId ? -1 : 1);
    const testOnlyUnits = units
      .filter(({ productionApplicable, testOnly }) => !productionApplicable && testOnly);
    if (
      releaseUnits.length !== PRODUCT_IDS.length
      || releaseUnits.some(({ logicalId }, index) => logicalId !== PRODUCT_IDS[index])
      || testOnlyUnits.length !== 1
      || testOnlyUnits[0].logicalId !== RUNNER_ID
      || units.length !== PRODUCT_IDS.length + 1
    ) return blocked('ARTIFACT_SCHEMA_INVALID');
    return pass(Object.freeze({
      releaseUnits: Object.freeze(releaseUnits),
      testOnlyUnits: Object.freeze(testOnlyUnits),
    }));
  } catch {
    return blocked('ARTIFACT_SCHEMA_INVALID');
  }
}

export function buildVerificationArtifactSet(args) {
  return buildArtifactSetInternal(args, collectValidatedRepositoryUnits);
}
