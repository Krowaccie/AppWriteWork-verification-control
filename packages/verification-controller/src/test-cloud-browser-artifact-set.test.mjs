import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { mock } from 'node:test';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const HARNESS_MODE = process.env.APPWRITEWORK_ARTIFACT_SET_HARNESS;
const IS_LIFECYCLE_HARNESS = [
  '1',
  'cap',
  'retained',
  'abort',
  'payload-mismatch',
].includes(HARNESS_MODE);
const providerNamespace = IS_LIFECYCLE_HARNESS ? null
  : await import('../../../scripts/verification/test-cloud-provider-contract.mjs');
const readTestCloudRuntimeLifecycle = providerNamespace?.readTestCloudRuntimeLifecycle;
const artifactSet = IS_LIFECYCLE_HARNESS ? null : await import('./test-cloud-browser-artifact-set.mjs');

const BOOTSTRAP_HUB = '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__';

const EXPECTED_EXPORTS = Object.freeze([
  'armQualifiedTestCloudBrowserArtifactMembers',
  'closeQualifiedTestCloudBrowserArtifactMembers',
  'consumeQualifiedTestCloudBrowserArtifactSet',
  'projectTestCloudBrowserArtifactPolicyRows',
  'qualifyTestCloudBrowserArtifactSet',
  'readQualifiedTestCloudBrowserArtifactMember',
  'registerTestCloudBrowserArtifactSetBootstrap',
]);

const EXPECTED_BLOCKED = Object.freeze({
  status: 'BLOCKED',
  value: null,
  diagnostics: Object.freeze([
    Object.freeze({
      code: 'TEST_BROWSER_ARTIFACT_SET_MISMATCH',
      retryable: false,
      safeMessage: 'The immutable browser artifact set did not match the trusted setup policy.',
    }),
  ]),
});

function assertBlocked(value) {
  assert.deepEqual(value, EXPECTED_BLOCKED);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.diagnostics), true);
  assert.equal(Object.isFrozen(value.diagnostics[0]), true);
}

if (!IS_LIFECYCLE_HARNESS) {
test('4C-pre: import exposes the exact inert seven-export artifact namespace', () => {
  assert.deepEqual(Object.keys(artifactSet).sort(), EXPECTED_EXPORTS);
  assert.equal(readTestCloudRuntimeLifecycle(), 'EMPTY');
  assert.equal(Object.getOwnPropertyDescriptor(globalThis, BOOTSTRAP_HUB), undefined);

  assert.equal(artifactSet.qualifyTestCloudBrowserArtifactSet.length, 1);
  assert.equal(artifactSet.consumeQualifiedTestCloudBrowserArtifactSet.length, 1);
  assert.equal(artifactSet.armQualifiedTestCloudBrowserArtifactMembers.length, 1);
  assert.equal(artifactSet.readQualifiedTestCloudBrowserArtifactMember.length, 1);
  assert.equal(artifactSet.closeQualifiedTestCloudBrowserArtifactMembers.length, 1);
  assert.equal(artifactSet.registerTestCloudBrowserArtifactSetBootstrap.length, 0);
});

test('4C-pre: future artifact operations remain non-activatable and do not inspect arguments', async () => {
  const forbiddenArgs = new Proxy({}, {
    get() {
      assert.fail('4C-pre placeholder inspected caller data');
    },
    ownKeys() {
      assert.fail('4C-pre placeholder enumerated caller data');
    },
    getOwnPropertyDescriptor() {
      assert.fail('4C-pre placeholder inspected caller descriptors');
    },
  });

  assertBlocked(await artifactSet.qualifyTestCloudBrowserArtifactSet(forbiddenArgs));
  assertBlocked(artifactSet.consumeQualifiedTestCloudBrowserArtifactSet(forbiddenArgs));
  assertBlocked(artifactSet.armQualifiedTestCloudBrowserArtifactMembers(forbiddenArgs));
  assertBlocked(artifactSet.readQualifiedTestCloudBrowserArtifactMember(forbiddenArgs));
  assertBlocked(await artifactSet.closeQualifiedTestCloudBrowserArtifactMembers(forbiddenArgs));

  assert.equal(readTestCloudRuntimeLifecycle(), 'EMPTY');
  assert.equal(Object.getOwnPropertyDescriptor(globalThis, BOOTSTRAP_HUB), undefined);
});
test('4C-pre: registrar structurally fail-stops every pre-registration failure and retry', async () => {
  const source = await readFile(new URL('./test-cloud-browser-artifact-set.mjs', import.meta.url), 'utf8');
  assert.match(source, /function terminallyBlockRegistration\(\)/);
  assert.match(
    source,
    /function terminallyBlockRegistration\(\) \{[\s\S]*registrationState = 'BLOCKED';[\s\S]*readTestCloudRuntimeLifecycle\(BLOCKED\);[\s\S]*return false;/,
  );
  assert.match(
    source,
    /registerTestCloudBrowserArtifactSetBootstrap\(\) \{[\s\S]*if \(registrationState !== 'EMPTY'\) return terminallyBlockRegistration\(\);/,
  );
  assert.match(source, /receiver === undefined \|\| register === undefined\) return terminallyBlockRegistration\(\);/);
  assert.match(source, /result !== true[\s\S]*return terminallyBlockRegistration\(\);/);
  assert.match(source, /catch \{[\s\S]*return terminallyBlockRegistration\(\);[\s\S]*\}/);
  assert.doesNotMatch(
    source,
    /receiver === undefined \|\| register === undefined\) \{\s*registrationState = 'BLOCKED'/,
  );
});


test('4C-pre: registrar called outside BOOTSTRAPPING fails closed and terminally blocks runtime', () => {
  assert.equal(readTestCloudRuntimeLifecycle(), 'EMPTY');
  assert.equal(artifactSet.registerTestCloudBrowserArtifactSetBootstrap(), false);
  assert.equal(readTestCloudRuntimeLifecycle(), 'BLOCKED');
  assert.equal(artifactSet.registerTestCloudBrowserArtifactSetBootstrap(), false);
  assert.equal(readTestCloudRuntimeLifecycle(), 'BLOCKED');
  assert.equal(Object.getOwnPropertyDescriptor(globalThis, BOOTSTRAP_HUB), undefined);
});
}
function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return JSON.stringify(Object.is(value, -0) ? 0 : value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function writeString(target, offset, length, value) {
  Buffer.from(value, 'ascii').copy(target, offset, 0, length);
}

function writeOctal(target, offset, length, value) {
  writeString(target, offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`);
}

function tarEntry(name, bytes) {
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, bytes.length);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeString(header, 257, 6, 'ustar\0');
  writeString(header, 263, 2, '00');
  writeOctal(header, 148, 8, [...header].reduce((sum, byte) => sum + byte, 0));
  return Buffer.concat([
    header,
    bytes,
    Buffer.alloc((512 - (bytes.length % 512)) % 512),
  ]);
}

function hostedPayloadDigest(members) {
  const records = [...members.entries()]
    .filter(([memberPath]) => memberPath !== 'build-identity.json')
    .map(([memberPath, bytes]) => ({
      path: memberPath,
      mode: '100644',
      contentDigest: sha256(bytes),
    }))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return sha256(Buffer.from(canonicalJson(records), 'utf8'));
}

function buildSourceArtifactSet(
  payloadSize = 0,
  { identityNonce = 'baseline', mutatePayloadAfterDigest = false } = {},
) {
  const manifest = {
    'index.html': {
      file: 'assets/index.js', name: 'index', src: 'index.html', isEntry: true,
      imports: ['terminal', 'xyflow'], dynamicImports: ['App'], css: ['assets/index.css'],
    },
    App: {
      file: 'assets/App.js', name: 'App', isDynamicEntry: true,
      imports: ['appwrite-runtime', 'Callout', 'useTheme'],
      dynamicImports: ['Dashboard'], css: ['assets/App.css'],
    },
    Dashboard: {
      file: 'assets/Dashboard.js', name: 'Dashboard', isDynamicEntry: true,
      imports: ['apiClient', 'external-link', 'mcpConnect', 'play', 'publicProjectLinks', 'refresh'],
      css: ['assets/Dashboard.css'],
    },
    apiClient: { file: 'assets/apiClient.js', name: 'apiClient' },
    'appwrite-runtime': {
      file: 'assets/appwrite-runtime.js', name: 'appwrite', isDynamicEntry: true,
      imports: ['appwrite-vendor'],
    },
    'appwrite-vendor': { file: 'assets/appwrite-vendor.js', name: 'appwrite' },
    Callout: { file: 'assets/Callout.js', name: 'Callout', css: ['assets/Callout.css'] },
    'external-link': { file: 'assets/external-link.js', name: 'external-link' },
    mcpConnect: { file: 'assets/mcpConnect.js', name: 'mcpConnect' },
    play: { file: 'assets/play.js', name: 'play' },
    publicProjectLinks: { file: 'assets/publicProjectLinks.js', name: 'publicProjectLinks' },
    refresh: { file: 'assets/refresh.js', name: 'refresh-cw' },
    terminal: { file: 'assets/terminal.js', name: 'terminal' },
    useTheme: { file: 'assets/useTheme.js', name: 'useTheme' },
    xyflow: { file: 'assets/xyflow.js', name: 'xyflow' },
  };
  const members = new Map();
  const payload = (name) => payloadSize === 0
    ? Buffer.from('immutable:' + name)
    : Buffer.alloc(payloadSize, (name.length % 251) + 1);
  for (const entry of Object.values(manifest)) {
    members.set(entry.file, payload(entry.file));
    for (const css of entry.css ?? []) members.set(css, payload(css));
  }
  for (const name of [
    'index.html', 'theme-init.js', 'salmora-mark.svg',
    'catalog/catalog-bundle.json', 'templates/registry.json', 'templates/entitlements.json',
  ]) members.set(name, payload(name));
  members.set('.vite/manifest.json', Buffer.from(JSON.stringify(manifest)));
  members.set('build-identity.json', Buffer.from(JSON.stringify({
    schemaVersion: 'hosted-site-build-identity.v1',
    nonce: identityNonce,
  })));
  const canonicalContentDigest = hostedPayloadDigest(members);
  if (mutatePayloadAfterDigest) {
    members.set('index.html', Buffer.from('mutated-after-declared-payload-digest'));
  }
  const entries = [...members.entries()].sort(([left], [right]) => left.localeCompare(right));
  const tar = Buffer.concat([
    ...entries.map(([name, bytes]) => tarEntry(name, bytes)),
    Buffer.alloc(1024),
  ]);
  const siteBytes = gzipSync(tar, { level: 9, mtime: 0 });
  return Object.freeze({
    releaseEligibleArtifacts: Object.freeze([Object.freeze({
      bytes: Uint8Array.from(siteBytes),
      canonicalContentDigest,
      kind: 'site',
      logicalTarget: 'web',
      relativePath: 'site/site.tar.gz',
      sizeBytes: siteBytes.length,
      transportDigest: sha256(siteBytes),
    })]),
  });
}

function lowerOriginFreeRow(row, origin) {
  return Object.freeze(Object.assign(Object.create(null), {
    credentialCarrier: row.credentialCarrier,
    exactCount: row.exactCount,
    expectedResponseStatus: row.expectedResponseStatus,
    finalUrl: new URL(`/${row.memberPath}`, origin).href,
    lifecyclePhase: row.lifecyclePhase,
    method: row.method,
    ordinal: row.ordinal,
    profileId: row.profileId,
    requestClass: row.requestClass,
    requestHeaderBindings: row.requestHeaderBindings,
    requestOpaqueHeaderRules: row.requestOpaqueHeaderRules,
    resourceType: row.resourceType,
    responseBodyDigest: row.responseBodyDigest,
    responseByteLength: row.responseByteLength,
    responseHeaderBindings: row.responseHeaderBindings,
    responseMimeEssence: row.responseMimeEssence,
    responseOpaqueHeaderRules: row.responseOpaqueHeaderRules,
  }));
}

async function runLifecycleHarness() {
  const encodedScratch = [];
  const NativeTextEncoder = globalThis.TextEncoder;
  if (HARNESS_MODE === '1') {
    globalThis.TextEncoder = class extends NativeTextEncoder {
      encode(value) {
        const bytes = super.encode(value);
        encodedScratch.push(bytes);
        return bytes;
      }
    };
  }
  let lifecycle = 'BOOTSTRAPPING';
  let bridge;
  let currentPolicy;
  const runtimeQualification = Object.freeze(Object.create(null));
  const context = Object.freeze(Object.create(null));
  const providerContractQualification = Object.freeze(Object.create(null));
  const identityBindingsQualification = Object.freeze(Object.create(null));
  const providerSetupReadbackQualification = Object.freeze(Object.create(null));
  const browserScenarioQualification = Object.freeze(Object.create(null));
  const bridgeReceiver = Object.freeze(Object.create(null));
  const hub = Object.freeze(Object.assign(Object.create(null), {
    bridgeReceiver,
    registerBrowserArtifactSetSetupBridge(registration) {
      bridge = registration;
      return true;
    },
    authenticateProviderQualification(args) {
      return args.providerContractQualification === providerContractQualification;
    },
    authenticateBrowserScenarioQualification(args) {
      return args.browserScenarioQualification === browserScenarioQualification
        && ['arm', 'read', 'complete'].includes(args.operation);
    },
    readBrowserRequestPolicy(args) {
      if (
        args.providerContractQualification !== providerContractQualification
        || args.providerSetupReadbackQualification !== providerSetupReadbackQualification
      ) return null;
      return Object.freeze({ browserRequestPolicy: currentPolicy });
    },
  }));
  Object.defineProperty(globalThis, BOOTSTRAP_HUB, {
    value: hub, enumerable: false, configurable: true, writable: false,
  });
  const providerUrl = new URL(
    '../../../scripts/verification/test-cloud-provider-contract.mjs',
    import.meta.url,
  ).href;
  mock.module(providerUrl, { namedExports: {
    authenticateTestCloudRuntimeActive(args) {
      return lifecycle === 'ACTIVE'
        && Object.keys(args).length === 1
        && args.runtimeQualification === runtimeQualification;
    },
    isAuthenticTestCloudBootstrapHub(value) {
      return lifecycle === 'BOOTSTRAPPING' && value === hub;
    },
    readTestCloudRuntimeLifecycle(...args) {
      if (args.length !== 0) lifecycle = 'BLOCKED';
      return lifecycle;
    },
  } });
  const implementation = await import('./test-cloud-browser-artifact-set.mjs');
  assert.deepEqual(Object.keys(implementation).sort(), EXPECTED_EXPORTS);
  assert.equal(implementation.registerTestCloudBrowserArtifactSetBootstrap(), true);
  assert.ok(bridge);
  lifecycle = 'ACTIVE';

  if (HARNESS_MODE === 'cap') {
    let pullCount = 0;
    const emitted = [];
    const originalDecompressionStream = globalThis.DecompressionStream;
    globalThis.DecompressionStream = class {
      constructor() {
        const readable = new ReadableStream({
          pull(controller) {
            pullCount += 1;
            if (pullCount <= 3) {
              const size = pullCount < 3 ? 32 * 1024 * 1024 : 1;
              const chunk = new Uint8Array(size);
              chunk.fill(0x5a);
              emitted.push(chunk);
              controller.enqueue(chunk);
            } else {
              controller.close();
            }
          },
        }, { highWaterMark: 0 });
        return { readable, writable: new WritableStream() };
      }
    };
    try {
      assertBlocked(await implementation.qualifyTestCloudBrowserArtifactSet({
        runtimeQualification, context, sourceArtifactSet: buildSourceArtifactSet(),
      }));
      assert.equal(pullCount, 3);
      assert.equal(emitted.every((chunk) => chunk[0] === 0 && chunk[chunk.length - 1] === 0), true);
    } finally {
      globalThis.DecompressionStream = originalDecompressionStream;
    }
    return;
  }

  if (HARNESS_MODE === 'retained') {
    assertBlocked(await implementation.qualifyTestCloudBrowserArtifactSet({
      runtimeQualification,
      context,
      sourceArtifactSet: buildSourceArtifactSet(700 * 1024),
    }));
    return;
  }

  if (HARNESS_MODE === 'abort') {
    let releasePull;
    let markSecondPull;
    const secondPull = new Promise((resolve) => { markSecondPull = resolve; });
    const release = new Promise((resolve) => { releasePull = resolve; });
    const emitted = new Uint8Array(64);
    emitted.fill(0x5a);
    const lateEmitted = new Uint8Array(64);
    lateEmitted.fill(0x6b);
    const originalDecompressionStream = globalThis.DecompressionStream;
    globalThis.DecompressionStream = class {
      constructor() {
        const readable = new ReadableStream();
        Object.defineProperty(readable, 'getReader', {
          value() {
            let readCount = 0;
            return {
              read() {
                readCount += 1;
                if (readCount === 1) return Promise.resolve({ done: false, value: emitted });
                markSecondPull();
                return release.then(() => ({ done: false, value: lateEmitted }));
              },
              cancel() {
                return release;
              },
              releaseLock() {},
            };
          },
        });
        return { readable, writable: new WritableStream() };
      }
    };
    try {
      const qualificationPromise = implementation.qualifyTestCloudBrowserArtifactSet({
        runtimeQualification, context, sourceArtifactSet: buildSourceArtifactSet(),
      });
      await secondPull;
      let closeSettled = false;
      const closePromise = implementation.closeQualifiedTestCloudBrowserArtifactMembers({
        runtimeQualification,
        context,
        qualification: null,
        outcome: 'abort',
        providerContractQualification: null,
        providerSetupReadbackQualification: null,
        browserScenarioQualification: null,
      }).then((result) => {
        closeSettled = true;
        return result;
      });
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(closeSettled, false);
      releasePull();
      assertBlocked(await qualificationPromise);
      const closed = await closePromise;
      assert.deepEqual(closed.value, { closed: true });
      assert.equal(emitted.every((byte) => byte === 0), true);
      assert.equal(lateEmitted.every((byte) => byte === 0), true);
    } finally {
      releasePull();
      globalThis.DecompressionStream = originalDecompressionStream;
    }
    return;
  }

  if (HARNESS_MODE === 'payload-mismatch') {
    assertBlocked(await implementation.qualifyTestCloudBrowserArtifactSet({
      runtimeQualification,
      context,
      sourceArtifactSet: buildSourceArtifactSet(0, { mutatePayloadAfterDigest: true }),
    }));
    return;
  }

  const qualified = await implementation.qualifyTestCloudBrowserArtifactSet({
    runtimeQualification, context, sourceArtifactSet: buildSourceArtifactSet(),
  });
  assert.equal(qualified.status, 'PASS');
  assert.match(qualified.value.browserArtifactSetDigest, /^sha256:[0-9a-f]{64}$/);
  const consumed = implementation.consumeQualifiedTestCloudBrowserArtifactSet({
    runtimeQualification, context, qualification: qualified.value.qualification,
  });
  assert.equal(consumed.status, 'PASS');
  assert.equal(Object.getPrototypeOf(consumed.value.browserArtifactSetHandoff), null);
  assert.equal(Reflect.ownKeys(consumed.value.browserArtifactSetHandoff).length, 0);

  const begin = Reflect.apply(bridge.beginBrowserArtifactSetSetupBinding, bridge.receiver, [{
    runtimeQualification,
    context,
    browserArtifactSetHandoff: consumed.value.browserArtifactSetHandoff,
    providerContractQualification,
    identityBindingsQualification,
    expectedEnvironmentDigest: `sha256:${'1'.repeat(64)}`,
    expectedProviderContractDigest: `sha256:${'2'.repeat(64)}`,
    expectedIdentityBindingsDigest: `sha256:${'3'.repeat(64)}`,
  }]);
  assert.deepEqual(Object.keys(begin), [
    'browserArtifactSetDigest', 'originFreeArtifactPolicyDigest', 'originFreeArtifactPolicyRows',
  ]);
  assert.equal(begin.originFreeArtifactPolicyRows.length, 25);
  const protectedRows = Object.freeze(begin.originFreeArtifactPolicyRows.map((row) => (
    lowerOriginFreeRow(row, 'https://web.test')
  )));
  const protectedArtifactPolicyDigest = sha256(Buffer.from(canonicalJson(protectedRows)));
  const policyWithoutDigest = Object.freeze(Object.assign(Object.create(null), {
    schemaVersion: 'test-cloud.browser-request-policy.v1',
    timeoutMilliseconds: 5000,
    rows: protectedRows,
  }));
  const browserRequestPolicyDigest = sha256(Buffer.from(canonicalJson(policyWithoutDigest)));
  currentPolicy = Object.freeze(Object.assign(Object.create(null), {
    ...policyWithoutDigest,
    digest: browserRequestPolicyDigest,
  }));
  assert.equal(Reflect.apply(bridge.commitBrowserArtifactSetSetupBinding, bridge.receiver, [{
    runtimeQualification,
    context,
    browserArtifactSetHandoff: consumed.value.browserArtifactSetHandoff,
    providerContractQualification,
    identityBindingsQualification,
    providerSetupReadbackQualification,
    browserArtifactSetDigest: begin.browserArtifactSetDigest,
    originFreeArtifactPolicyDigest: begin.originFreeArtifactPolicyDigest,
    protectedArtifactPolicyDigest,
    browserRequestPolicyDigest,
  }]), true);

  const armed = implementation.armQualifiedTestCloudBrowserArtifactMembers({
    runtimeQualification,
    context,
    qualification: qualified.value.qualification,
    providerContractQualification,
    providerSetupReadbackQualification,
    browserScenarioQualification,
  });
  assert.deepEqual(armed.value, { armed: true });
  let catalogRead;
  for (const row of protectedRows) {
    for (let occurrenceIndex = 0; occurrenceIndex < row.exactCount; occurrenceIndex += 1) {
      const read = implementation.readQualifiedTestCloudBrowserArtifactMember({
        runtimeQualification,
        context,
        providerContractQualification,
        providerSetupReadbackQualification,
        browserScenarioQualification,
        policyOrdinal: row.ordinal,
        occurrenceIndex,
      });
      assert.equal(read.status, 'PASS');
      if (row.ordinal === 22 && occurrenceIndex === 0) catalogRead = read.value;
    }
  }
  assert.equal(
    Buffer.from(catalogRead.bodyBase64, 'base64').toString(),
    'immutable:catalog/catalog-bundle.json',
  );
  assert.equal(catalogRead.responseBodyDigest, protectedRows[22].responseBodyDigest);
  assert.equal(catalogRead.responseByteLength, protectedRows[22].responseByteLength);
  const closed = await implementation.closeQualifiedTestCloudBrowserArtifactMembers({
    runtimeQualification,
    context,
    qualification: qualified.value.qualification,
    outcome: 'complete',
    providerContractQualification,
    providerSetupReadbackQualification,
    browserScenarioQualification,
  });
  assert.deepEqual(closed.value, { closed: true });
  assert.equal(encodedScratch.length > 0, true);
  assert.equal(
    encodedScratch.every((bytes) => bytes.every((byte) => byte === 0)),
    true,
  );
}

if (IS_LIFECYCLE_HARNESS) {
  await runLifecycleHarness();
} else {
  test('hosted payload identity excludes only root build identity bytes', () => {
    const first = buildSourceArtifactSet(0, { identityNonce: 'first' })
      .releaseEligibleArtifacts[0];
    const second = buildSourceArtifactSet(0, { identityNonce: 'second' })
      .releaseEligibleArtifacts[0];
    assert.equal(first.canonicalContentDigest, second.canonicalContentDigest);
    assert.notEqual(first.transportDigest, second.transportDigest);
  });
  test('4C-final: setup bridge and all five operations close 27 authenticated reads', () => {
    const result = spawnSync(
      process.execPath,
      ['--experimental-test-module-mocks', fileURLToPath(import.meta.url)],
      {
        cwd: process.cwd(),
        encoding: 'utf8',
        env: { ...process.env, APPWRITEWORK_ARTIFACT_SET_HARNESS: '1', NODE_NO_WARNINGS: '1' },
        timeout: 30_000,
      },
    );
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  });
  test('4C-final: inflation cap and abort join wipe record-owned stream bytes', () => {
    for (const mode of ['cap', 'retained', 'abort', 'payload-mismatch']) {
      const result = spawnSync(
        process.execPath,
        ['--experimental-test-module-mocks', fileURLToPath(import.meta.url)],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
          env: { ...process.env, APPWRITEWORK_ARTIFACT_SET_HARNESS: mode, NODE_NO_WARNINGS: '1' },
          timeout: 30_000,
        },
      );
      assert.equal(
        result.status,
        0,
        mode + '\n' + result.stdout + '\n' + result.stderr,
      );
    }
  });
}
