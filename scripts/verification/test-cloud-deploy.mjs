import inventory from '../../dev/verification/environments/test-cloud.inventory.v1.json' with { type: 'json' };
import { validateArtifactManifest } from './artifact-manifest.mjs';
import { sha256Bytes } from './canonical-json.mjs';
import {
  createHostedSiteBuildIdentity,
  validateHostedSiteBuildIdentity,
} from './hosted-site-build-identity.mjs';
import { isAuthenticTestEnvironmentContext } from './test-cloud-environment.mjs';

const MAX_IDENTITY_BYTES = 16_384;
const POLL_INTERVAL_MS = 1_000;
const MAX_POLLS = 60;
const FUNCTION_IDS = new Map(inventory.productFunctions.map((entry) => [
  entry.logicalId, entry.functionId,
]));
FUNCTION_IDS.set('verification-runner-py', 'verification-runner-py');
const PRODUCT_IDS = Object.freeze([...FUNCTION_IDS.keys()]
  .filter((id) => id !== 'verification-runner-py')
  .sort((left, right) => left < right ? -1 : left > right ? 1 : 0));
const SOURCE_PATHS = new Map(inventory.productFunctions.map((entry) => [entry.logicalId, entry.sourcePath]));
SOURCE_PATHS.set('verification-runner-py', 'src/functions/verification-runner-py');
const ARTIFACT_KEYS = Object.freeze(['bytes', 'canonicalContentDigest', 'kind', 'logicalTarget', 'relativePath', 'sizeBytes', 'transportDigest']);
const SET_KEYS = Object.freeze(['artifactManifest', 'artifactManifestDigest', 'buildIdentity', 'handoff', 'releaseEligibleArtifacts', 'testOnlyArtifacts']);
const AUTHENTIC_READERS = new WeakSet();
const READER_CONTEXTS = new WeakMap();

const MESSAGES = Object.freeze({
  ARTIFACT_HANDOFF_INVALID: 'Artifact bytes do not match their trusted handoff.',
  DEPLOYMENT_ACTIVATION_MISMATCH: 'Activated deployment does not match exact readback.',
  DEPLOYMENT_CREATE_FAILED: 'Deployment creation failed.',
  DEPLOYMENT_TERMINAL_FAILURE: 'Deployment reached a terminal failure state.',
  DEPLOYMENT_TIMEOUT: 'Deployment did not become ready before the fixed timeout.',
  SITE_IDENTITY_MISMATCH: 'Hosted Site identity does not match the trusted artifact identity.',
  SITE_IDENTITY_READBACK_FAILED: 'Hosted Site identity could not be read safely.',
  TEST_IDENTITY_BLOCKED: 'Test context or client identity is invalid.',
});

function operation(status, value, code = null) {
  return Object.freeze({
    status,
    value,
    diagnostics: code === null ? Object.freeze([]) : Object.freeze([Object.freeze({
      code,
      safeMessage: MESSAGES[code],
      retryable: false,
    })]),
  });
}

function blocked(code) { return operation('BLOCKED', null, code); }
function failed(code) { return operation('FAIL', null, code); }
function pass(value) { return operation('PASS', Object.freeze(value)); }

function validArtifact(artifact, kind = null) {
  try {
    return artifact !== null
      && typeof artifact === 'object'
      && (kind === null || artifact.kind === kind)
      && (artifact.kind === 'site' || artifact.kind === 'function')
      && typeof artifact.logicalTarget === 'string'
      && artifact.bytes instanceof Uint8Array
      && artifact.bytes.byteLength > 0
      && artifact.sizeBytes === artifact.bytes.byteLength
      && /^sha256:[0-9a-f]{64}$/u.test(artifact.transportDigest)
      && /^sha256:[0-9a-f]{64}$/u.test(artifact.canonicalContentDigest)
      && sha256Bytes(artifact.bytes) === artifact.transportDigest;
  } catch {
    return false;
  }
}


function exactKeys(value, expected) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const actual = Reflect.ownKeys(value).sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
  } catch {
    return false;
  }
}

function exactArray(value, length) {
  try {
    return Array.isArray(value)
      && value.length === length
      && Object.keys(value).length === length;
  } catch {
    return false;
  }
}

function validClock(clock) {
  return clock !== null
    && typeof clock === 'object'
    && typeof clock.now === 'function'
    && typeof clock.sleep === 'function';
}

function isJsonMediaType(value) {
  return typeof value === 'string'
    && /^application\/json(?:[\t ]*;[\t ]*[!#$%&'*+.^_`|~0-9A-Za-z-]+[\t ]*=[\t ]*(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"[^"\r\n]*"))*[\t ]*$/u.test(value);
}

async function readBounded(response) {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/u.test(declaredLength)) throw new TypeError('invalid length');
    if (Number(declaredLength) > MAX_IDENTITY_BYTES) throw new TypeError('oversize');
  }
  if (response.body === null || typeof response.body?.getReader !== 'function') {
    throw new TypeError('missing body');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!(value instanceof Uint8Array)) throw new TypeError('invalid body chunk');
    length += value.byteLength;
    if (length > MAX_IDENTITY_BYTES) {
      await reader.cancel().catch(() => {});
      throw new TypeError('oversize');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export function createTestSiteIdentityReader(args) {
  try {
    if (
      args === null
      || typeof args !== 'object'
      || Array.isArray(args)
      || Reflect.ownKeys(args).length !== 2
      || !Object.hasOwn(args, 'context')
      || !Object.hasOwn(args, 'fetchTrusted')
      || !isAuthenticTestEnvironmentContext(args.context)
      || typeof args.fetchTrusted !== 'function'
    ) return blocked('TEST_IDENTITY_BLOCKED');
    const context = args.context;
    const fetchTrusted = args.fetchTrusted;
    const exactUrl = `${context.publicOrigin}/build-identity.json`;
    const reader = Object.freeze({
      async read() {
        try {
          const response = await fetchTrusted(exactUrl, {
            method: 'GET',
            redirect: 'error',
            credentials: 'omit',
            cache: 'no-store',
            headers: { Accept: 'application/json' },
          });
          if (
            response === null
            || typeof response !== 'object'
            || response.status !== 200
            || response.redirected !== false
            || response.url !== exactUrl
            || typeof response.headers?.get !== 'function'
            || !isJsonMediaType(response.headers.get('content-type'))
          ) return blocked('SITE_IDENTITY_READBACK_FAILED');
          const text = new TextDecoder('utf-8', { fatal: true }).decode(await readBounded(response));
          const parsed = JSON.parse(text);
          if (!validateHostedSiteBuildIdentity(parsed).ok) {
            return blocked('SITE_IDENTITY_READBACK_FAILED');
          }
          return pass(createHostedSiteBuildIdentity(parsed));
        } catch {
          return blocked('SITE_IDENTITY_READBACK_FAILED');
        }
      },
    });
    AUTHENTIC_READERS.add(reader);
    READER_CONTEXTS.set(reader, context);
    return pass(reader);
  } catch {
    return blocked('TEST_IDENTITY_BLOCKED');
  }
}

async function pollDeployment(getDeployment, deploymentId, clock) {
  for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
    const observed = await getDeployment(deploymentId);
    if (observed?.status !== 'PASS' || observed.value?.deploymentId !== deploymentId) {
      if (attempt < MAX_POLLS - 1) await clock.sleep(POLL_INTERVAL_MS);
      continue;
    }
    if (observed.value.status === 'ready') return pass(observed.value);
    if (['failed', 'canceled', 'cancelled'].includes(observed.value.status)) {
      return failed('DEPLOYMENT_TERMINAL_FAILURE');
    }
    if (attempt < MAX_POLLS - 1) await clock.sleep(POLL_INTERVAL_MS);
  }
  return failed('DEPLOYMENT_TIMEOUT');
}

async function pollActiveDeployment(getParent, deploymentId, clock) {
  for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
    const observed = await getParent();
    if (observed?.status !== 'PASS') return failed('DEPLOYMENT_ACTIVATION_MISMATCH');
    if (observed.value?.activeDeploymentId === deploymentId) return pass(observed.value);
    if (attempt < MAX_POLLS - 1) await clock.sleep(POLL_INTERVAL_MS);
  }
  return failed('DEPLOYMENT_ACTIVATION_MISMATCH');
}

function observation(kind, logicalTarget, deploymentId, transportDigest) {
  return Object.freeze({
    kind,
    logicalTarget,
    deploymentId,
    activeDeploymentId: deploymentId,
    artifactTransportDigest: transportDigest,
    status: 'ready',
  });
}

function validateFullArtifactSet(context, artifactSet) {
  try {
    if (!exactKeys(artifactSet, SET_KEYS) || !Object.isFrozen(artifactSet)) return null;
    const release = artifactSet.releaseEligibleArtifacts;
    const testOnly = artifactSet.testOnlyArtifacts;
    if (
      !exactArray(release, PRODUCT_IDS.length + 1)
      || !exactArray(testOnly, 1)
      || !Object.isFrozen(release)
      || !Object.isFrozen(testOnly)
    ) return null;
    const site = release[0];
    if (
      !exactKeys(site, ARTIFACT_KEYS)
      || !Object.isFrozen(site)
      || !validArtifact(site, 'site')
      || site.logicalTarget !== 'web'
      || site.relativePath !== 'site/site.tar.gz'
    ) return null;
    const productFunctions = release.slice(1);
    for (let index = 0; index < PRODUCT_IDS.length; index += 1) {
      const artifact = productFunctions[index];
      const logicalId = PRODUCT_IDS[index];
      if (
        !exactKeys(artifact, ARTIFACT_KEYS)
        || !Object.isFrozen(artifact)
        || !validArtifact(artifact, 'function')
        || artifact.logicalTarget !== logicalId
        || artifact.relativePath !== `functions/${logicalId}.tar.gz`
      ) return null;
    }
    const runner = testOnly[0];
    if (
      !exactKeys(runner, ARTIFACT_KEYS)
      || !Object.isFrozen(runner)
      || !validArtifact(runner, 'function')
      || runner.logicalTarget !== 'verification-runner-py'
      || runner.relativePath !== 'functions/verification-runner-py.tar.gz'
    ) return null;

    const manifest = artifactSet.artifactManifest;
    const manifestValidation = validateArtifactManifest(manifest);
    if (
      manifestValidation.ok !== true
      || manifest.sourceRevision !== context.candidateRevision
      || manifest.artifactManifestDigest !== artifactSet.artifactManifestDigest
      || manifest.verifierManifestDigest !== artifactSet.buildIdentity?.verifierManifestDigest
    ) return null;
    if (
      !validateHostedSiteBuildIdentity(artifactSet.buildIdentity).ok
      || artifactSet.buildIdentity.sourceRevision !== context.candidateRevision
      || artifactSet.buildIdentity.sitePayloadDigest !== site.canonicalContentDigest
    ) return null;

    const allArtifacts = [...productFunctions, runner, site].sort((left, right) => {
      const a = `${left.kind}\0${left.logicalTarget}`;
      const b = `${right.kind}\0${right.logicalTarget}`;
      return a < b ? -1 : a > b ? 1 : 0;
    });
    if (manifest.artifacts.length !== allArtifacts.length) return null;
    for (let index = 0; index < allArtifacts.length; index += 1) {
      const artifact = allArtifacts[index];
      const entry = manifest.artifacts[index];
      if (
        entry.kind !== artifact.kind
        || entry.logicalTarget !== artifact.logicalTarget
        || entry.sourcePath !== (artifact.kind === 'site' ? 'src/web' : SOURCE_PATHS.get(artifact.logicalTarget))
        || entry.relativePath !== artifact.relativePath
        || entry.canonicalContentDigest !== artifact.canonicalContentDigest
        || entry.transportDigest !== artifact.transportDigest
        || entry.sizeBytes !== artifact.sizeBytes
      ) return null;
    }

    const handoff = artifactSet.handoff;
    if (
      !exactKeys(handoff, [
        'artifactManifestDigest', 'artifactName', 'schemaVersion', 'sourceRef', 'sourceRepository',
        'sourceRevision', 'sourceWorkflow', 'sourceWorkflowRunAttempt', 'sourceWorkflowRunId',
        'verifierManifestDigest',
      ])
      || handoff.schemaVersion !== 'artifact-handoff.v1'
      || handoff.sourceRepository !== 'Krowaccie/AppWriteWork'
      || handoff.sourceWorkflow !== 'Verify Main'
      || handoff.sourceRef !== 'refs/heads/main'
      || handoff.sourceRevision !== context.candidateRevision
      || handoff.artifactName !== `verification-artifacts-${context.candidateRevision}`
      || handoff.artifactManifestDigest !== manifest.artifactManifestDigest
      || handoff.verifierManifestDigest !== manifest.verifierManifestDigest
      || !/^[1-9][0-9]*$/u.test(handoff.sourceWorkflowRunId)
      || !Number.isSafeInteger(handoff.sourceWorkflowRunAttempt)
      || handoff.sourceWorkflowRunAttempt <= 0
    ) return null;
    return Object.freeze([...productFunctions, runner]);
  } catch {
    return null;
  }
}

export async function deployTestFunctionArtifacts({ context, artifactSet, clients, clock }) {
  if (!isAuthenticTestEnvironmentContext(context) || !validClock(clock)) {
    return blocked('TEST_IDENTITY_BLOCKED');
  }
  const operator = clients?.operator;
  if (
    typeof operator?.createFunctionDeployment !== 'function'
    || typeof operator?.getFunctionDeployment !== 'function'
    || typeof operator?.activateFunctionDeployment !== 'function'
    || typeof operator?.getFunction !== 'function'
  ) return blocked('TEST_IDENTITY_BLOCKED');
  const artifacts = validateFullArtifactSet(context, artifactSet);
  if (artifacts === null) return blocked('ARTIFACT_HANDOFF_INVALID');
  const observations = [];
  for (const artifact of artifacts) {
    if (!validArtifact(artifact, 'function') || !FUNCTION_IDS.has(artifact.logicalTarget)) {
      return blocked('ARTIFACT_HANDOFF_INVALID');
    }
    const functionId = FUNCTION_IDS.get(artifact.logicalTarget);
    const created = await operator.createFunctionDeployment({
      functionId,
      code: artifact.bytes,
      activate: false,
    });
    if (created?.status !== 'PASS' || typeof created.value?.deploymentId !== 'string') {
      return failed('DEPLOYMENT_CREATE_FAILED');
    }
    const deploymentId = created.value.deploymentId;
    const polled = await pollDeployment(
      (id) => operator.getFunctionDeployment({ functionId, deploymentId: id }),
      deploymentId,
      clock,
    );
    if (polled.status !== 'PASS') return polled;
    const activated = await operator.activateFunctionDeployment({ functionId, deploymentId });
    if (activated?.status !== 'PASS' || activated.value?.activeDeploymentId !== deploymentId) {
      return failed('DEPLOYMENT_ACTIVATION_MISMATCH');
    }
    const parent = await pollActiveDeployment(
      () => operator.getFunction({ functionId }),
      deploymentId,
      clock,
    );
    if (parent.status !== 'PASS') return parent;
    observations.push(observation(
      'function', artifact.logicalTarget, deploymentId, artifact.transportDigest,
    ));
  }
  return pass(Object.freeze(observations));
}

export async function deployTestSiteArtifact({
  context,
  artifact,
  clients,
  clock,
  siteIdentityReader,
  expectedIdentity,
}) {
  if (
    !isAuthenticTestEnvironmentContext(context)
    || !validClock(clock)
    || !validArtifact(artifact, 'site')
    || !AUTHENTIC_READERS.has(siteIdentityReader)
    || READER_CONTEXTS.get(siteIdentityReader) !== context
  ) return blocked('TEST_IDENTITY_BLOCKED');
  if (
    !validateHostedSiteBuildIdentity(expectedIdentity).ok
    || expectedIdentity.sourceRevision !== context.candidateRevision
    || expectedIdentity.sitePayloadDigest !== artifact.canonicalContentDigest
  ) return blocked('SITE_IDENTITY_MISMATCH');
  const operator = clients?.operator;
  if (
    typeof operator?.createSiteDeployment !== 'function'
    || typeof operator?.getSiteDeployment !== 'function'
    || typeof operator?.activateSiteDeployment !== 'function'
    || typeof operator?.getSite !== 'function'
  ) return blocked('TEST_IDENTITY_BLOCKED');
  const created = await operator.createSiteDeployment({ code: artifact.bytes, activate: false });
  if (created?.status !== 'PASS' || typeof created.value?.deploymentId !== 'string') {
    return failed('DEPLOYMENT_CREATE_FAILED');
  }
  const deploymentId = created.value.deploymentId;
  const polled = await pollDeployment(
    (id) => operator.getSiteDeployment({ deploymentId: id }),
    deploymentId,
    clock,
  );
  if (polled.status !== 'PASS') return polled;
  const activated = await operator.activateSiteDeployment({ deploymentId });
  if (activated?.status !== 'PASS' || activated.value?.activeDeploymentId !== deploymentId) {
    return failed('DEPLOYMENT_ACTIVATION_MISMATCH');
  }
  const parent = await pollActiveDeployment(
    () => operator.getSite({}),
    deploymentId,
    clock,
  );
  if (parent.status !== 'PASS') return parent;
  const readback = await siteIdentityReader.read();
  if (readback?.status !== 'PASS') return blocked('SITE_IDENTITY_READBACK_FAILED');
  const actual = readback.value;
  if (
    actual.schemaVersion !== expectedIdentity.schemaVersion
    || actual.sourceRevision !== expectedIdentity.sourceRevision
    || actual.sitePayloadDigest !== expectedIdentity.sitePayloadDigest
    || actual.verifierManifestDigest !== expectedIdentity.verifierManifestDigest
  ) return failed('SITE_IDENTITY_MISMATCH');
  return pass(observation('site', artifact.logicalTarget, deploymentId, artifact.transportDigest));
}
