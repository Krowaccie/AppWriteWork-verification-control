import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../../../scripts/verification/canonical-json.mjs';
import inventory from '../../../dev/verification/environments/test-cloud.inventory.v1.json' with {
  type: 'json',
};

const INPUT_KEYS = Object.freeze([
  'browserArtifactProjection', 'environmentDigest', 'providerContractDigest',
]);
const PROJECTION_KEYS = Object.freeze([
  'browserArtifactSetDigest',
  'originFreeArtifactPolicyDigest',
  'originFreeArtifactPolicyRows',
]);
const ORIGIN_ROW_KEYS = Object.freeze([
  'credentialCarrier', 'exactCount', 'expectedResponseStatus', 'lifecyclePhase',
  'memberPath', 'method', 'ordinal', 'profileId', 'requestClass',
  'requestHeaderBindings', 'requestOpaqueHeaderRules', 'resourceType',
  'responseBodyDigest', 'responseByteLength', 'responseHeaderBindings',
  'responseMimeEssence', 'responseOpaqueHeaderRules', 'role',
]);
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)(?!.*[?#])[\x20-\x7e]+$/u;
const ENVIRONMENT_DIGEST =
  'sha256:02560e84745ed7b577b334a3412885f6a547b2a22f164f4978b255d3b35c0044';
const PROVIDER_CONTRACT_DIGEST =
  'sha256:47a1d778ca8b8cea333b10574ffbc2db488fd711c12a1c40faf9da5235e27184';

const STATIC_HEADER_DIGESTS = Object.freeze({
  preflightJsonHeaders:
    'sha256:694878954043c10b79f33d9664b01d4755472d34e669e66b53b7b4901929f94e',
  preflightSdkHeaders:
    'sha256:4b8ac062f00c6756066f62c74d3892aa7a5022dd00b2ff680de40b7c2f7236e4',
  get: 'sha256:14e30cd163c732912e048c4c837e15c4e90c062ebb795ab947d57706e2d10dd8',
  post: 'sha256:9aee6b1bcdf617d8e39bb1f2b624c68ea33deb9d48e0364aeaded836d3d00293',
  patch: 'sha256:8dce33b49f31396a100fb4baf9f8a5dd5d27a4e29d3e244b8eb7b3ae3e619d2c',
  contentType:
    'sha256:bacb769b46f6d169fb227ea026550f411d46cbe66a9c2a6ba36449c8cf8e4dea',
  responseFormat:
    'sha256:6754fcea32b88564b0879ceb065063ff5c69d08e65a6046a9f07edb5b324d3e9',
  sdkLanguage:
    'sha256:4b5e57f6eb2f42b9039b3d1e13929295f231749c510cbe341cd68036d9af97e2',
  sdkName:
    'sha256:2975104784a401e3880e2215550e9490eda7e67db5fc2b35e1a244acb092ced3',
  sdkPlatform:
    'sha256:948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d',
  sdkVersion:
    'sha256:86995d1efab7362ae9c47e678403b4c202b8dad51eb3ec3c854925e247524266',
  allowCredentials:
    'sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b',
  allowMethods:
    'sha256:0d56d6af3afd946638ff6fd158328314e22bfa563af2f0a1d829f52796645bec',
  exposeHeaders:
    'sha256:d007751ae00e39c0b9db72ca543e610bab2b993e7850f1215df02b6022a6d204',
  maxAge:
    'sha256:b045dd9c18caa8be1e17a4b902152cc1fd292b242b7b9dd74ba8c40896239424',
});

// The allow-headers digest is fixed by the Appwrite Cloud CORS contract. Keep the
// exact audited value separate from the descriptive constant above.
const APPWRITE_ALLOW_HEADERS_DIGEST =
  'sha256:f05abc62ccc4f904e51d2631f67cdc520edbf2e880ae9f51d72f8fc1bdaf96a1';

const REQUEST_HEADER_PATTERN_IDS = Object.freeze([
  0, 1, 2, 3, 2, 3, 4, 0, 0, 0, 5, 5, 5, 0, 3, 3, 1, 1, 1, 1, 1, 3, 1, 1, 3, 1, 1, 1, 3, 1, 1, 1, 1,
]);
const REQUEST_OPAQUE_PATTERN_IDS = Object.freeze([
  0, 1, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
]);
const RESPONSE_OPAQUE_PATTERN_IDS = Object.freeze([
  0, 1, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2,
]);

const TAIL = Object.freeze([
  ['cors-preflight-owner-session-post', 'none', 204, '/account/sessions/email', 'OPTIONS', 'cors-preflight', 'other', null],
  ['owner-session-create', 'raw-playwright-request-body-only', 201, '/account/sessions/email', 'POST', 'owner-session-create', 'fetch', 'application/json'],
  ['cors-preflight-appwrite-account-get', 'none', 204, '/account', 'OPTIONS', 'cors-preflight', 'other', null],
  ['authenticated-appwrite-account-read', 'browser-cookie-jar-only', 200, '/account', 'GET', 'appwrite-read', 'fetch', 'application/json'],
  ['cors-preflight-appwrite-prefs-get', 'none', 204, '/account/prefs', 'OPTIONS', 'cors-preflight', 'other', null],
  ['authenticated-appwrite-read', 'browser-cookie-jar-only', 200, '/account/prefs', 'GET', 'appwrite-read', 'fetch', 'application/json'],
  ['cors-preflight-appwrite-multipart-post', 'none', 204, '/storage/buckets/project-files/files', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-json-post', 'none', 204, '/tablesdb/project/tables/project_artifacts/rows', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-json-post', 'none', 204, '/tablesdb/project/tables/project_artifact_versions/rows', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-json-post', 'none', 204, '/tablesdb/project/tables/projects/rows', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-json-patch', 'none', 204, '/tablesdb/project/tables/project_artifacts/rows/entrypoint-row', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-json-patch', 'none', 204, '/tablesdb/project/tables/project_artifacts/rows/root-row', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-json-patch', 'none', 204, '/tablesdb/project/tables/projects/rows/project-row', 'OPTIONS', 'cors-preflight', 'other', null],
  ['cors-preflight-appwrite-function-json-post', 'none', 204, '/functions/sharing-py/executions', 'OPTIONS', 'cors-preflight', 'other', null],
  ['authenticated-appwrite-multipart-mutation', 'browser-cookie-jar-only', 201, '/storage/buckets/project-files/files', 'POST', 'appwrite-multipart-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-multipart-mutation', 'browser-cookie-jar-only', 201, '/storage/buckets/project-files/files', 'POST', 'appwrite-multipart-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifacts/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifacts/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifact_versions/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifact_versions/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/projects/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-multipart-mutation', 'browser-cookie-jar-only', 201, '/storage/buckets/project-files/files', 'POST', 'appwrite-multipart-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifact_versions/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 200, '/tablesdb/project/tables/project_artifacts/rows/entrypoint-row', 'PATCH', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-multipart-mutation', 'browser-cookie-jar-only', 201, '/storage/buckets/project-files/files', 'POST', 'appwrite-multipart-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifact_versions/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 200, '/tablesdb/project/tables/project_artifacts/rows/root-row', 'PATCH', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 200, '/tablesdb/project/tables/projects/rows/project-row', 'PATCH', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-multipart-mutation', 'browser-cookie-jar-only', 201, '/storage/buckets/project-files/files', 'POST', 'appwrite-multipart-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifacts/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-json-mutation', 'browser-cookie-jar-only', 201, '/tablesdb/project/tables/project_artifact_versions/rows', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-function-json-mutation', 'browser-cookie-jar-only', 201, '/functions/sharing-py/executions', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
  ['authenticated-appwrite-function-json-mutation', 'browser-cookie-jar-only', 201, '/functions/sharing-py/executions', 'POST', 'appwrite-json-mutation', 'fetch', 'application/json'],
]);

function digestText(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestJson(value) {
  return digestText(canonicalJson(value));
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.getOwnPropertySymbols(value).length === 0;
}

function exactObject(value, keys) {
  if (!isPlainObject(value)) return null;
  const names = Object.keys(value).sort();
  const expected = [...keys].sort();
  return names.length === expected.length
    && names.every((name, index) => name === expected[index]) ? value : null;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function blocked(code) {
  return deepFreeze({
    status: 'BLOCKED',
    value: null,
    diagnostics: [{
      code,
      retryable: false,
      safeMessage: 'The exact Appwrite Test browser policy could not be produced.',
    }],
  });
}

function pass(value) {
  return deepFreeze({ status: 'PASS', value, diagnostics: [] });
}

function binding(name, valueDigest) {
  return { name, valueDigest };
}

function opaque(name, minimumCount = 0, maximumCount = 1, kind = 'opaque-transport') {
  return { kind, maximumCount, minimumCount, name };
}

function requestHeaderPatterns() {
  const origin = digestText(inventory.environment.publicOrigin);
  const project = digestText(inventory.environment.projectId);
  const sdk = [
    binding('x-appwrite-project', project),
    binding('x-appwrite-response-format', STATIC_HEADER_DIGESTS.responseFormat),
    binding('x-sdk-language', STATIC_HEADER_DIGESTS.sdkLanguage),
    binding('x-sdk-name', STATIC_HEADER_DIGESTS.sdkName),
    binding('x-sdk-platform', STATIC_HEADER_DIGESTS.sdkPlatform),
    binding('x-sdk-version', STATIC_HEADER_DIGESTS.sdkVersion),
  ];
  const preflight = (headers, method) => [
    binding('access-control-request-headers', headers),
    binding('access-control-request-method', method),
    binding('origin', origin),
  ];
  return [
    preflight(STATIC_HEADER_DIGESTS.preflightJsonHeaders, STATIC_HEADER_DIGESTS.post),
    [binding('content-type', STATIC_HEADER_DIGESTS.contentType), ...sdk],
    preflight(STATIC_HEADER_DIGESTS.preflightSdkHeaders, STATIC_HEADER_DIGESTS.get),
    sdk,
    preflight(STATIC_HEADER_DIGESTS.preflightSdkHeaders, STATIC_HEADER_DIGESTS.post),
    preflight(STATIC_HEADER_DIGESTS.preflightJsonHeaders, STATIC_HEADER_DIGESTS.patch),
  ];
}

function requestOpaquePatterns() {
  const common = ['accept', 'accept-encoding', 'accept-language'];
  const browser = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'];
  const tail = ['sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'user-agent'];
  return [
    [...common, 'referer', ...tail].map((name) => opaque(name)),
    [...common, 'content-length', 'origin', 'referer', ...browser, ...tail]
      .map((name) => opaque(name)),
    [
      ...common.map((name) => opaque(name)),
      opaque('cookie', 1, 1, 'opaque-browser-cookie'),
      ...['origin', 'referer', ...browser, ...tail].map((name) => opaque(name)),
    ],
    [
      ...[...common, 'content-length'].map((name) => opaque(name)),
      opaque('cookie', 1, 1, 'opaque-browser-cookie'),
      ...['origin', 'referer', ...browser, ...tail].map((name) => opaque(name)),
    ],
  ];
}

function responseHeaderBindings() {
  return [
    binding('access-control-allow-credentials', STATIC_HEADER_DIGESTS.allowCredentials),
    binding('access-control-allow-headers', APPWRITE_ALLOW_HEADERS_DIGEST),
    binding('access-control-allow-methods', STATIC_HEADER_DIGESTS.allowMethods),
    binding('access-control-allow-origin', digestText(inventory.environment.publicOrigin)),
    binding('access-control-expose-headers', STATIC_HEADER_DIGESTS.exposeHeaders),
    binding('access-control-max-age', STATIC_HEADER_DIGESTS.maxAge),
  ];
}

function responseOpaquePatterns() {
  const base = [opaque('server'), opaque('strict-transport-security'), opaque('x-content-type-options')];
  const limits = [
    opaque('x-ratelimit-limit', 1),
    opaque('x-ratelimit-remaining', 1),
    opaque('x-ratelimit-reset', 1),
  ];
  return [
    [opaque('server'), opaque('x-debug-speed', 1)],
    [
      opaque('server'),
      opaque('set-cookie', 2, 2, 'opaque-browser-set-cookie'),
      opaque('strict-transport-security'),
      opaque('x-content-type-options'),
      opaque('x-debug-fallback', 2, 2),
      opaque('x-debug-speed', 1),
      ...limits,
      opaque('x-utopia-compression'),
    ],
    [...base, opaque('x-debug-fallback', 1), opaque('x-debug-speed', 1), opaque('x-utopia-compression')],
    [
      ...base,
      opaque('x-debug-fallback', 1),
      opaque('x-debug-speed', 1),
      ...limits,
      opaque('x-utopia-compression'),
    ],
  ];
}

function protectArtifactRows(rows) {
  return rows.map((row, ordinal) => {
    if (
      exactObject(row, ORIGIN_ROW_KEYS) === null
      || row.ordinal !== ordinal
      || row.profileId !== 'synthetic-immutable-asset'
      || row.credentialCarrier !== 'none'
      || row.method !== 'GET'
      || !SAFE_PATH.test(row.memberPath)
      || !DIGEST.test(row.responseBodyDigest ?? '')
      || !Number.isSafeInteger(row.responseByteLength)
      || row.responseByteLength < 1
      || !Number.isSafeInteger(row.exactCount)
      || row.exactCount < 1
    ) throw new TypeError('origin-free row');
    const { memberPath, role: _role, ...protectedRow } = structuredClone(row);
    return {
      ...protectedRow,
      finalUrl: `${inventory.environment.publicOrigin}/${memberPath}`,
    };
  });
}

function buildNetworkRows() {
  const requestHeaders = requestHeaderPatterns();
  const requestOpaque = requestOpaquePatterns();
  const responseHeaders = responseHeaderBindings();
  const responseOpaque = responseOpaquePatterns();
  return TAIL.map((descriptor, index) => {
    const [
      profileId,
      credentialCarrier,
      expectedResponseStatus,
      path,
      method,
      requestClass,
      resourceType,
      responseMimeEssence,
    ] = descriptor;
    return {
      credentialCarrier,
      exactCount: 1,
      expectedResponseStatus,
      finalUrl: `${inventory.environment.endpoint}${path}`,
      lifecyclePhase: index < 6 ? 'OWNER_LOGIN' : 'APPLICATION_MUTATION',
      method,
      ordinal: index + 25,
      profileId,
      requestClass,
      requestHeaderBindings: structuredClone(requestHeaders[REQUEST_HEADER_PATTERN_IDS[index]]),
      requestOpaqueHeaderRules: structuredClone(requestOpaque[REQUEST_OPAQUE_PATTERN_IDS[index]]),
      resourceType,
      responseBodyDigest: null,
      responseByteLength: null,
      responseHeaderBindings: structuredClone(responseHeaders),
      responseMimeEssence,
      responseOpaqueHeaderRules: structuredClone(responseOpaque[RESPONSE_OPAQUE_PATTERN_IDS[index]]),
    };
  });
}

export function createAppwriteTestBrowserPolicy(args) {
  try {
    const input = exactObject(args, INPUT_KEYS);
    const projection = input === null
      ? null : exactObject(input.browserArtifactProjection, PROJECTION_KEYS);
    if (
      input === null
      || projection === null
      || input.environmentDigest !== ENVIRONMENT_DIGEST
      || input.providerContractDigest !== PROVIDER_CONTRACT_DIGEST
      || !DIGEST.test(projection.browserArtifactSetDigest ?? '')
      || !DIGEST.test(projection.originFreeArtifactPolicyDigest ?? '')
      || !Array.isArray(projection.originFreeArtifactPolicyRows)
      || projection.originFreeArtifactPolicyRows.length !== 25
      || digestJson(projection.originFreeArtifactPolicyRows)
        !== projection.originFreeArtifactPolicyDigest
    ) return blocked('APPWRITE_TEST_BROWSER_POLICY_INPUT_INVALID');
    const protectedRows = protectArtifactRows(projection.originFreeArtifactPolicyRows);
    const protectedArtifactPolicyDigest = digestJson(protectedRows);
    const rows = [...protectedRows, ...buildNetworkRows()];
    if (
      rows.length !== 58
      || rows.some((row, ordinal) => row.ordinal !== ordinal)
      || rows.some((row, ordinal) => {
        const url = new URL(row.finalUrl);
        const expectedOrigin = ordinal < 25
          ? inventory.environment.publicOrigin
          : new URL(inventory.environment.endpoint).origin;
        return url.protocol !== 'https:' || url.origin !== expectedOrigin
          || /(?:test-only\.invalid|\.example|salmora\.net|69eb4818000afa64a7fa|69eb4a020024c520642e)/iu
            .test(row.finalUrl);
      })
    ) return blocked('APPWRITE_TEST_BROWSER_POLICY_INVALID');
    const withoutDigest = {
      schemaVersion: 'test-cloud.browser-request-policy.v1',
      timeoutMilliseconds: 5000,
      rows,
    };
    const browserRequestPolicy = {
      ...withoutDigest,
      digest: digestJson(withoutDigest),
    };
    return pass({
      browserArtifactSetDigest: projection.browserArtifactSetDigest,
      originFreeArtifactPolicyDigest: projection.originFreeArtifactPolicyDigest,
      protectedArtifactPolicyDigest,
      browserRequestPolicy,
    });
  } catch {
    return blocked('APPWRITE_TEST_BROWSER_POLICY_INVALID');
  }
}
