import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};
import { createAppwriteTestBrowserPolicy } from './appwrite-test-browser-policy.mjs';
import { projectTestCloudBrowserArtifactPolicyRows } from
  './test-cloud-browser-artifact-set.mjs';

const ENVIRONMENT_DIGEST =
  'sha256:e83dac9cc615ccf37fd027683690edb2ff7332ac523d57130c1e86fa8617f302';
const PROVIDER_CONTRACT_DIGEST =
  'sha256:eaa6c314b13daa4c56a75bfc29eb8b3c66b7315ad6f114475db4d5f9aee75cd8';

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
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

function sourceArtifactSet() {
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
      imports: [
        'apiClient', 'external-link', 'mcpConnect', 'play', 'publicProjectLinks', 'refresh',
      ],
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
  const payload = (name) => Buffer.from(`immutable:${name}`);
  for (const entry of Object.values(manifest)) {
    members.set(entry.file, payload(entry.file));
    for (const css of entry.css ?? []) members.set(css, payload(css));
  }
  for (const name of [
    'index.html', 'theme-init.js', 'salmora-mark.svg',
    'catalog/catalog-bundle.json', 'templates/registry.json', 'templates/entitlements.json',
  ]) members.set(name, payload(name));
  members.set('.vite/manifest.json', Buffer.from(JSON.stringify(manifest)));
  const tar = Buffer.concat([
    ...[...members.entries()]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([name, bytes]) => tarEntry(name, bytes)),
    Buffer.alloc(1024),
  ]);
  const siteBytes = gzipSync(tar, { level: 9, mtime: 0 });
  return {
    releaseEligibleArtifacts: [{
      bytes: Uint8Array.from(siteBytes),
      canonicalContentDigest: digest(tar),
      kind: 'site',
      logicalTarget: 'web',
      relativePath: 'site/site.tar.gz',
      sizeBytes: siteBytes.length,
      transportDigest: digest(siteBytes),
    }],
  };
}

function originFreeRows() {
  return Array.from({ length: 25 }, (_, ordinal) => ({
    credentialCarrier: 'none',
    exactCount: ordinal === 22 ? 3 : 1,
    expectedResponseStatus: 200,
    lifecyclePhase: ordinal <= 12
      ? 'APPLICATION_NAVIGATION'
      : ordinal <= 21 ? 'OWNER_LOGIN' : 'APPLICATION_READ',
    memberPath: ordinal === 0 ? 'index.html' : `assets/member-${ordinal}.js`,
    method: 'GET',
    ordinal,
    profileId: 'synthetic-immutable-asset',
    requestClass: ordinal === 0 ? 'main-document' : 'build-asset',
    requestHeaderBindings: [],
    requestOpaqueHeaderRules: [],
    resourceType: ordinal === 0 ? 'document' : ordinal >= 22 ? 'fetch' : 'script',
    responseBodyDigest: digest(`member-${ordinal}`),
    responseByteLength: ordinal + 1,
    responseHeaderBindings: [],
    responseMimeEssence: ordinal === 0 ? 'text/html' : 'text/javascript',
    responseOpaqueHeaderRules: [],
    role: ordinal === 0 ? 'index-html' : `member-${ordinal}`,
  }));
}

function projection(rows = originFreeRows()) {
  return {
    browserArtifactSetDigest: digest(canonicalJson(rows.map((row) => ({
      ordinal: row.ordinal,
      memberPath: row.memberPath,
      responseBodyDigest: row.responseBodyDigest,
      responseByteLength: row.responseByteLength,
      exactCount: row.exactCount,
    })))),
    originFreeArtifactPolicyDigest: digest(canonicalJson(rows)),
    originFreeArtifactPolicyRows: rows,
  };
}

function create(browserArtifactProjection = projection()) {
  return createAppwriteTestBrowserPolicy({
    browserArtifactProjection,
    environmentDigest: ENVIRONMENT_DIGEST,
    providerContractDigest: PROVIDER_CONTRACT_DIGEST,
  });
}

test('creates 25 exact source-member rows and 31 fixed Appwrite Test rows', () => {
  const result = create();
  assert.equal(result.status, 'PASS', result.diagnostics?.[0]?.code);
  const policy = result.value.browserRequestPolicy;
  assert.equal(policy.rows.length, 56);
  assert.equal(policy.rows.reduce((total, row) => total + row.exactCount, 0), 58);
  assert.equal(policy.rows[0].finalUrl, `${inventory.environment.publicOrigin}/index.html`);
  assert.equal(policy.rows[24].finalUrl,
    `${inventory.environment.publicOrigin}/assets/member-24.js`);
  assert.equal(policy.rows[25].finalUrl,
    `${inventory.environment.endpoint}/account/sessions/email`);
  assert.equal(policy.rows[55].finalUrl,
    `${inventory.environment.endpoint}/functions/sharing-py/executions`);
  assert.equal(policy.rows[25].expectedResponseStatus, 204);
  assert.equal(policy.rows[26].credentialCarrier, 'raw-playwright-request-body-only');
  assert.equal(policy.rows[28].credentialCarrier, 'browser-cookie-jar-only');
  assert.equal(policy.rows[46].method, 'PATCH');
  assert.equal(policy.digest, digest(canonicalJson({
    schemaVersion: policy.schemaVersion,
    timeoutMilliseconds: policy.timeoutMilliseconds,
    rows: policy.rows,
  })));
  assert.match(result.value.protectedArtifactPolicyDigest, /^sha256:[0-9a-f]{64}$/);
  const serialized = canonicalJson(policy);
  for (const forbidden of ['test-only.invalid', '.example', 'salmora.net', '69eb4818000afa64a7fa']) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test('projects the exact 25 rows from a bounded source site artifact', async () => {
  const projected = await projectTestCloudBrowserArtifactPolicyRows({
    sourceArtifactSet: sourceArtifactSet(),
  });
  assert.equal(projected.status, 'PASS', projected.diagnostics?.[0]?.code);
  assert.equal(projected.value.originFreeArtifactPolicyRows.length, 25);
  assert.equal(projected.value.originFreeArtifactPolicyRows[0].memberPath, 'index.html');
  assert.equal(projected.value.originFreeArtifactPolicyRows[22].exactCount, 3);
  assert.equal(
    projected.value.originFreeArtifactPolicyDigest,
    digest(canonicalJson(projected.value.originFreeArtifactPolicyRows)),
  );
  const policy = create(projected.value);
  assert.equal(policy.status, 'PASS');
  assert.equal(policy.value.browserRequestPolicy.rows.length, 56);
});

test('substitutes the exact public origin and project header digests', () => {
  const result = create();
  assert.equal(result.status, 'PASS');
  const rows = result.value.browserRequestPolicy.rows;
  const originDigest = digest(inventory.environment.publicOrigin);
  const projectDigest = digest(inventory.environment.projectId);
  assert.equal(rows[25].requestHeaderBindings.find(({ name }) => name === 'origin').valueDigest,
    originDigest);
  assert.equal(rows[26].requestHeaderBindings.find(
    ({ name }) => name === 'x-appwrite-project',
  ).valueDigest, projectDigest);
  assert.equal(rows[25].responseHeaderBindings.find(
    ({ name }) => name === 'access-control-allow-origin',
  ).valueDigest, originDigest);
});

test('rejects a modified origin-free digest or row count', () => {
  const modified = projection();
  modified.originFreeArtifactPolicyRows[0].responseByteLength += 1;
  assert.equal(create(modified).status, 'BLOCKED');
  const short = projection(originFreeRows().slice(0, 24));
  assert.equal(create(short).status, 'BLOCKED');
});

test('rejects a fixture or production member path', () => {
  for (const memberPath of ['https://test-only.invalid/a.js', '../salmora.net/a.js']) {
    const rows = originFreeRows();
    rows[0].memberPath = memberPath;
    assert.equal(create(projection(rows)).status, 'BLOCKED');
  }
});
