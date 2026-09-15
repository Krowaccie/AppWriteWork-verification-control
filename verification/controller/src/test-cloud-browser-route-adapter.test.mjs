import assert from "node:assert/strict";
import test from "node:test";
import { Worker } from "node:worker_threads";

const workerProviderSource = String.raw`
const state = globalThis.__routeAdapterTestState;
export function readTestCloudRuntimeLifecycle() { return state.lifecycle; }
export function authenticateTestCloudRuntimeActive(args) {
  state.calls.push(['active', args?.runtimeQualification === state.runtimeQualification]);
  return state.lifecycle === 'ACTIVE'
    && args?.runtimeQualification === state.runtimeQualification;
}
export function consumeTestCloudBrowserFactoryAuthorization() {
  state.calls.push(['authorize', state.factoryAuthorization]);
  if (state.lifecycle !== 'BOOTSTRAPPING' || state.factoryAuthorization !== true) return false;
  state.factoryAuthorization = false;
  return true;
}
export function isAuthenticTestCloudBootstrapHub(hub) { return hub === state.hub; }
`;

const workerArtifactSource = String.raw`
const state = globalThis.__routeAdapterTestState;
export function readQualifiedTestCloudBrowserArtifactMember(args) {
  state.calls.push(['artifact', args?.policyOrdinal, args?.occurrenceIndex]);
  return Object.freeze(Object.assign(Object.create(null), {
    status: 'PASS',
    value: Object.freeze(Object.assign(Object.create(null), {
      bodyBase64: state.mainArtifact.bodyBase64,
      responseBodyDigest: state.mainArtifact.responseBodyDigest,
      responseByteLength: state.mainArtifact.responseByteLength,
    })),
    diagnostics: Object.freeze([]),
  }));
}
state.artifactMemberReader = readQualifiedTestCloudBrowserArtifactMember;
`;

const workerPlaywrightSource = String.raw`
const state = globalThis.__routeAdapterTestState;
import { createHash } from 'node:crypto';
state.playwrightModuleLoads += 1;
class TimeoutError extends Error {}
export const errors = Object.freeze({
  TimeoutError,
});
const closed = (value) => Object.freeze(Object.assign(Object.create(null), value));
const sha = (value) => 'sha256:' + createHash('sha256').update(value).digest('hex');
const canonical = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
};
const valueDigest = (value) => sha(typeof value === 'string' ? value : canonical(value));
function multipartRootManifest() {
  const manifest = {
    schemaVersion: 1,
    projectId: 'project-id',
    artifactId: 'root-artifact-id',
    containerProfile: 'project-root',
    name: 'Hello World',
    parentContainerId: null,
    children: [{
      relationship: 'owned',
      ref: {
        projectId: 'project-id',
        artifactId: 'entrypoint-artifact-id',
        artifactType: 'workflow.dag.v1',
        artifactVersionId: 'entrypoint-version-id',
        contentHash: sha('workflow-content'),
      },
    }],
    lifecycleState: 'published',
  };
  const source = Buffer.from(JSON.stringify(manifest));
  const boundary = '----appwritework-source-operation-boundary';
  const prefix = Buffer.from(
    '--' + boundary + '\r\n'
      + 'Content-Disposition: form-data; name="fileId"\r\n\r\n'
      + 'file-0\r\n'
      + '--' + boundary + '\r\n'
      + 'Content-Disposition: form-data; name="file"; filename="root.container.json"\r\n'
      + 'Content-Type: application/vnd.salmora.container+json\r\n\r\n',
  );
  const suffix = Buffer.from('\r\n--' + boundary + '--\r\n');
  return {
    bytes: Buffer.concat([prefix, source, suffix]),
    contentType: 'multipart/form-data; boundary=' + boundary,
    source,
  };
}
function producer(args) {
  return state.safeReflectApply(
    state.routeProducer.implementation,
    state.routeProducer.receiver,
    [closed(args)],
  );
}
function requestAuthority(ordinal, role) {
  if (typeof state.realRequestAuthority === 'function') {
    return state.realRequestAuthority(ordinal, role ?? null);
  }
  const isShare = ordinal >= 17;
  const rootManifestUpload = ordinal === 0 ? multipartRootManifest() : null;
  const rootArtifactCreate = {
    artifactId: 'root-artifact-id', artifactRole: 'source', artifactType: 'container.v1',
    containerProfile: 'project-root', createdBy: 'owner-api', latestDraftVersionId: null,
    latestPublishedVersionId: 'root-version-initial', lifecycleState: 'published',
    name: 'Hello World', parentContainerId: null, projectId: 'project-id', updatedBy: 'owner-api',
  };
  const body = isShare
    ? { email: role + '@example.test', role, canRun: role === 'editor' }
    : ordinal === 0
      ? {
        fileId: 'file-0', fileName: 'root.container.json',
        mimeType: 'application/vnd.salmora.container+json',
        permissionsDigest: sha(canonical([])),
        sizeBytes: rootManifestUpload.source.byteLength,
        sourceBytesDigest: sha(rootManifestUpload.source),
      }
    : ordinal === 2
      ? { rowId: 'row-2', data: rootArtifactCreate, permissions: [] }
      : ordinal === 12
        ? { data: { latestPublishedVersionId: 'root-version-saved', lifecycleState: 'published', name: 'Hello World', parentContainerId: null, updatedBy: 'owner-api' } }
    : {
      rowId: 'row-' + ordinal,
      data: { ordinal },
      ...(ordinal === 1 ? { sourceBytesDigest: sha('source-1') } : {}),
    };
  const pathValues = isShare
    ? { 'path.functionId': 'sharing-py' }
    : ordinal === 0
      ? { 'path.bucketId': 'project-files-id' }
    : ordinal === 12
      ? { 'path.databaseId': 'primary', 'path.tableId': 'project-artifacts', 'path.rowId': 'row-2' }
      : ordinal === 2
        ? { 'path.databaseId': 'primary', 'path.tableId': 'project-artifacts' }
    : { 'path.databaseId': 'primary', 'path.tableId': 'table-' + ordinal };
  const bodyValues = isShare
    ? { 'body.email': body.email, 'body.role': body.role, 'body.canRun': body.canRun }
    : ordinal === 0
      ? Object.fromEntries(Object.entries(body).map(([key, value]) => ['body.' + key, value]))
    : ordinal === 12
      ? Object.fromEntries(Object.entries(body.data).map(([key, value]) => ['body.' + key, value]))
      : {
      'body.rowId': body.rowId,
      'body.data': body.data,
      ...(ordinal === 1 ? { 'body.sourceBytesDigest': body.sourceBytesDigest } : {}),
    };
  const values = { ...pathValues, ...bodyValues };
  const bindingNames = Object.freeze(Object.keys(values));
  const executionEnvelopeTemplate = isShare
    ? closed({ async: false, path: '/', method: 'POST' })
    : null;
  const requestTemplate = closed({
    bindingNames,
    bodyKind: isShare ? 'share-create' : ordinal === 0 ? 'file-create' : ordinal === 12 ? 'row-update' : 'row-create',
    bodyTemplate: null,
    executionEnvelopeTemplate,
    method: ordinal === 12 ? 'PATCH' : 'POST',
    mutationOrdinal: ordinal,
    pathBindings: Object.freeze(Object.keys(pathValues)),
    pathTemplate: isShare
      ? '/functions/{functionId}/executions'
      : ordinal === 0
        ? '/storage/buckets/{bucketId}/files'
      : ordinal === 12
        ? '/tablesdb/{databaseId}/tables/{tableId}/rows/{rowId}'
      : '/tablesdb/{databaseId}/tables/{tableId}/rows',
    query: null,
    routeId: isShare ? 'share-create' : 'row-create-' + ordinal,
    schemaVersion: 'verification-provider-request-template.v1',
  });
  const logicalValueBindings = Object.freeze(bindingNames.map((name) => closed({
    name, value: values[name], valueDigest: valueDigest(values[name]),
  })));
  const initialSourceOperationBindings = Object.freeze([]);
  const url = isShare
    ? 'https://api.example/functions/sharing-py/executions'
    : ordinal === 0
      ? 'https://api.example/storage/buckets/project-files-id/files'
    : ordinal === 12
      ? 'https://api.example/tablesdb/primary/tables/project-artifacts/rows/row-2'
      : ordinal === 2
        ? 'https://api.example/tablesdb/primary/tables/project-artifacts/rows'
    : 'https://api.example/tablesdb/primary/tables/table-' + ordinal + '/rows';
  const rootArtifactApplicationKeys = Object.freeze([
    'artifactId', 'artifactRole', 'artifactType', 'containerProfile', 'createdBy',
    'description', 'importedAt', 'latestDraftVersionId', 'latestPublishedVersionId',
    'latestValidationId', 'lifecycleState', 'name', 'originArtifactId', 'originChecksum',
    'originProjectId', 'originVersionId', 'parentContainerId', 'projectId', 'updatedBy',
  ]);
  const applicationKeys = ordinal === 0
    ? Object.freeze(['bucketBinding', 'fileName', 'mimeType', 'sizeBytes'])
    : ordinal === 2 || ordinal === 12
      ? rootArtifactApplicationKeys
      : Object.freeze(Object.keys(body.data ?? {}));
  const rowSystemKeys = Object.freeze([
    '$id', '$sequence', '$tableId', '$databaseId', '$createdAt', '$updatedAt', '$permissions',
  ]);
  const shareProjectionKeys = Object.freeze([
    ...rowSystemKeys,
    'projectId', 'userId', 'userEmail', 'userName', 'role', 'canRun', 'sharedBy',
  ]);
  const shareContractOverrides = state.releaseMode === 'private-readback-share-wrong-database'
    ? { databaseId: 'wrong-primary' }
    : state.releaseMode === 'private-readback-share-wrong-table'
      ? { tableId: 'wrong-shares' }
      : state.releaseMode === 'private-readback-share-wrong-projection'
        ? { projectionKeys: Object.freeze([...shareProjectionKeys, 'unexpected']) }
        : state.releaseMode === 'private-readback-share-wrong-limit'
          ? { limit: 4 }
          : state.releaseMode === 'private-readback-share-wrong-mode'
            ? { transactionMode: 'stale' }
            : {};
  const fixedShareQueryContract = isShare ? closed({
    bindingName: 'project-shares',
    databaseBinding: 'VERIFICATION_PRIMARY_DATABASE_ID',
    databaseId: 'primary',
    filterField: 'projectId',
    limit: 3,
    projectionKeys: shareProjectionKeys,
    tableId: 'shares-qualified',
    tableIdSource: 'VERIFICATION_SHARES_TABLE_ID',
    total: true,
    transactionId: null,
    transactionMode: 'committed',
    ...shareContractOverrides,
  }) : null;
  const semanticBody = JSON.stringify(body);
  const bytes = ordinal === 0 ? rootManifestUpload.bytes : Buffer.from(isShare
    ? JSON.stringify({ body: semanticBody, async: false, path: '/', method: 'POST' })
    : semanticBody);
  return {
    authority: closed({
      operationQualification: Object.freeze(Object.create(null)),
      requestTemplate,
      requestTemplateDigest: sha(canonical(requestTemplate)),
      exactDeploymentOrigin: 'https://api.example',
      fixedShareQueryContract,
      initialSourceOperationBindings,
      logicalValueBindings,
      memberReadbackContract: isShare ? null : closed({
        applicationKeys,
        databaseBinding: ordinal === 0 ? null : 'VERIFICATION_PRIMARY_DATABASE_ID',
        logicalResource: ordinal % 2 === 0 ? 'primary-project' : 'primary-graph',
        ownerSlot: 'slot-' + ordinal,
        projectionKeys: ordinal === 0 ? applicationKeys : Object.freeze([...rowSystemKeys, ...applicationKeys]),
        providerKind: ordinal === 0 ? 'storage-file' : 'tablesdb-row',
        tableBinding: ordinal === 0 ? 'project-files' : ordinal === 2 || ordinal === 12 ? 'project-artifacts' : 'table-' + ordinal,
        transactionId: null,
        transactionMode: ordinal === 0 ? null : 'committed',
      }),
    }),
    bytes,
    headers: rootManifestUpload === null ? Object.freeze([]) : Object.freeze([
      Object.freeze({ name: 'content-type', value: rootManifestUpload.contentType }),
    ]),
    url,
  };
}
function makeResponse(label, url, status, headers, body) {
  return Object.freeze({
    url() { return url; },
    status() { return status; },
    async headersArray() { return headers; },
    async body() {
      state.calls.push([label + 'BodyRead']);
      return Buffer.from(body ?? '');
    },
    async dispose() { state.calls.push(['dispose', label]); },
  });
}
function mutateShareReadback(fields, ordinal) {
  const suffix = state.releaseMode.replace('private-readback-share-', '');
  if (suffix === 'wrong-user-id') fields.userId = 'wrong-user';
  if (suffix === 'wrong-user-name') fields.userName = 'Wrong User';
  if (suffix === 'wrong-shared-by') fields.sharedBy = 'wrong-owner';
  if (suffix === 'wrong-permissions') fields.$permissions = Object.freeze(['read("any")']);
  if (suffix === 'alias' && ordinal === 18) fields.userId = 'editor-api';
  return fields;
}
function makeRequest(label, url, method, resourceType, headers, bytes) {
  return Object.freeze({
    url() { return url; },
    method() { return method; },
    resourceType() { return resourceType; },
    async headersArray() { return headers; },
    postDataBuffer() {
      state.calls.push([label + 'RequestBodyRead']);
      return bytes ?? null;
    },
  });
}
function makeRoute(label, request, response) {
  return Object.freeze({
    request() { return request; },
    async fetch(options) {
      state.calls.push(['fetch', label, options]);
      if (label === 'mutation-0' && state.releaseMode === 'timeout') {
        throw new TimeoutError('focused timeout');
      }
      if (state.releaseMode.startsWith('private-readback') && label === 'mutation-0') {
        state.backendRows.set('file-0', closed({
          $id: 'file-0', bucketId: 'project-files-id', name: 'root.container.json',
          mimeType: 'application/vnd.salmora.container+json',
          sizeOriginal: multipartRootManifest().source.byteLength,
          $permissions: Object.freeze([]),
        }));
      }
      if (state.releaseMode.startsWith('private-readback')
        && label.startsWith('mutation-')
        && typeof state.realBackendRowForOrdinal === 'function') {
        const ordinal = Number(label.slice(9));
        const row = state.realBackendRowForOrdinal(ordinal);
        if (row !== null) state.backendRows.set(row.$id, closed(row));
      }
      if (state.releaseMode.startsWith('private-readback') && label === 'mutation-17') {
        state.shareBackendRows.push(closed(mutateShareReadback({
          $id: 'share-row-17', $sequence: 17,
          $tableId: state.sharesTableId ?? 'shares-qualified',
          $databaseId: state.primaryDatabaseId ?? 'primary',
          $createdAt: '2026-07-28T00:00:17.000Z',
          $updatedAt: '2026-07-28T00:00:17.000Z',
          $permissions: expectedShareRow('editorShare').permissions,
          projectId: 'row-6', userId: 'editor-user', userEmail: 'editor@example.test',
          userName: 'Editor', role: 'editor', canRun: true, sharedBy: 'owner-user',
        }, 17)));
      }
      if (state.releaseMode.startsWith('private-readback') && label === 'mutation-18') {
        state.shareBackendRows.push(closed(mutateShareReadback({
          $id: 'share-row-18', $sequence: 18,
          $tableId: state.sharesTableId ?? 'shares-qualified',
          $databaseId: state.primaryDatabaseId ?? 'primary',
          $createdAt: '2026-07-28T00:00:18.000Z',
          $updatedAt: '2026-07-28T00:00:18.000Z',
          $permissions: expectedShareRow('viewerShare').permissions,
          projectId: 'row-6', userId: 'viewer-user', userEmail: 'viewer@example.test',
          userName: 'Viewer', role: 'viewer', canRun: false, sharedBy: 'owner-user',
        }, 18)));
      }
      if (state.releaseMode.startsWith('private-readback') && label === 'mutation-2'
        && typeof state.realBackendRowForOrdinal !== 'function') {
        state.backendRows.set('row-2', closed({
          $id: 'row-2', $sequence: 2, $tableId: 'project-artifacts',
          $databaseId: 'primary', $createdAt: '2026-07-28T00:00:02.000Z',
          $updatedAt: '2026-07-28T00:00:02.000Z', $permissions: Object.freeze([]),
          artifactId: 'root-artifact-id', artifactRole: 'source',
          artifactType: 'container.v1', containerProfile: 'project-root',
          createdBy: 'owner-api', description: null, importedAt: null,
          latestDraftVersionId: null, latestPublishedVersionId: 'root-version-initial',
          latestValidationId: null, lifecycleState: 'published', name: 'Hello World',
          originArtifactId: null, originChecksum: null, originProjectId: null,
          originVersionId: null, parentContainerId: null, projectId: 'project-id',
          updatedBy: 'owner-api',
        }));
      }
      if (state.releaseMode.startsWith('private-readback') && label === 'mutation-12'
        && typeof state.realBackendRowForOrdinal !== 'function') {
        const prior = state.backendRows.get('row-2');
        state.backendRows.set('row-2', closed({
          ...prior,
          $updatedAt: '2026-07-28T00:00:12.000Z',
          latestPublishedVersionId: 'root-version-saved',
          lifecycleState: 'published', name: 'Hello World', parentContainerId: null,
          updatedBy: 'owner-api',
        }));
      }
      return response;
    },
    async fulfill(options) {
      if (options.response === undefined) state.calls.push(['fulfill', options.status, options.contentType]);
      else if (label.startsWith('mutation-')) state.calls.push(['fulfillResponse', Number(label.slice(9))]);
      else state.calls.push(['fulfillBenignResponse', label]);
    },
    async abort(reason) { state.calls.push(['abort', label, reason]); },
  });
}
async function dispatchBenign(label, url, method, resourceType, headers, response) {
  const route = makeRoute(label, makeRequest(label, url, method, resourceType, headers), response);
  state.calls.push(['dispatchBenign', label, url, headers.map(({ name }) => name)]);
  try {
    await state.routeHandler(route);
  } catch (error) {
    state.calls.push(['dispatchBenignError', label, String(error?.message ?? error)]);
    throw error;
  }
}
function assertOrdinal(ordinal) {
  if (ordinal !== state.nextOrdinal) {
    throw new Error('ordinal ' + ordinal + ' after ' + state.nextOrdinal);
  }
}
function expectedShareRow(ownerSlot) {
  const editor = ownerSlot === 'editorShare';
  const targetUserId = editor ? 'editor-user' : 'viewer-user';
  return closed({
    projectId: 'row-6',
    userId: targetUserId,
    userEmail: editor ? 'editor@example.test' : 'viewer@example.test',
    userName: editor ? 'Editor' : 'Viewer',
    role: editor ? 'editor' : 'viewer',
    canRun: editor,
    sharedBy: 'owner-user',
    permissions: Object.freeze([
      'delete("user:owner-user")',
      'read("user:' + targetUserId + '")',
      'read("user:owner-user")',
      'update("user:owner-user")',
    ].sort()),
  });
}
async function runMutation(ordinal, role = undefined) {
  assertOrdinal(ordinal);
  const built = requestAuthority(ordinal, role);
  const method = built.authority.requestTemplate.method;
  const response = makeResponse(
    'mutation-' + ordinal,
    built.url,
    method === 'PATCH' ? 200 : 201,
    Object.freeze([]),
    '{}',
  );
  const route = makeRoute(
    'mutation-' + ordinal,
    makeRequest('mutation-' + ordinal, built.url, method, 'fetch', built.headers, built.bytes),
    response,
  );
  state.calls.push(['capture', ordinal]);
  const handler = state.routeHandler(route);
  await new Promise((resolve) => setImmediate(resolve));
  if (typeof state.publicProviderMutation === 'function') {
    const result = await state.publicProviderMutation(closed({
      authority: built.authority,
      handler,
      mutationOrdinal: ordinal,
      role: role ?? null,
    }));
    if (result?.status !== 'PASS') {
      throw new Error('public provider lifecycle blocked ' + ordinal);
    }
    state.calls.push(['publicProviderLifecycle', ordinal]);
    state.nextOrdinal += 1;
    return;
  }
  let captured;
  try { captured = producer({
    runtimeQualification: state.runtimeQualification,
    context: state.context,
    sessionIntentQualification: state.sessionIntentQualification,
    mutationOrdinal: ordinal,
    requestAuthority: built.authority,
  }); } catch (error) {
    state.calls.push(['captureError', ordinal, String(error?.stack ?? error)]);
    throw error;
  }
  if (captured?.observationQualification === undefined) {
    throw new Error('capture blocked ' + ordinal);
  }
  if (state.releaseMode === 'review-abort-after-capture' && ordinal === 0) {
    let handlerSettled = false;
    handler.then(() => { handlerSettled = true; }, () => { handlerSettled = true; });
    const aborted = producer({
      operation: 'abort-delivery',
      runtimeQualification: state.runtimeQualification,
      context: state.context,
      sessionIntentQualification: state.sessionIntentQualification,
      mutationOrdinal: ordinal,
      observationQualification: captured.observationQualification,
    });
    await new Promise((resolve) => setImmediate(resolve));
    state.calls.push(['reviewAbort', ordinal, aborted?.aborted, handlerSettled]);
    throw new Error('intentional review interruption');
  }
  if (state.releaseMode.startsWith('private-readback') && ordinal <= 16) {
    const updateOrdinal = ordinal === 12;
    const binding = updateOrdinal ? undefined : producer({
      operation: 'read-provider-binding',
      runtimeQualification: state.runtimeQualification,
      context: state.context,
      sessionIntentQualification: state.sessionIntentQualification,
      mutationOrdinal: ordinal,
      observationQualification: captured.observationQualification,
    });
    if (!updateOrdinal) state.calls.push(['privateBinding', ordinal, binding?.providerId]);
    if (!updateOrdinal && binding?.providerId !== (ordinal === 0 ? 'file-0' : 'row-' + ordinal)) {
      throw new Error('private binding readback blocked');
    }
    if (ordinal === 0) {
      const projectValues = producer({
        operation: 'read-provider-values',
        runtimeQualification: state.runtimeQualification,
        context: state.context,
        sessionIntentQualification: state.sessionIntentQualification,
        mutationOrdinal: ordinal,
        observationQualification: captured.observationQualification,
        logicalResource: 'primary-project',
        batchIndex: 0,
      });
      const graphValues = producer({
        operation: 'read-provider-values',
        runtimeQualification: state.runtimeQualification,
        context: state.context,
        sessionIntentQualification: state.sessionIntentQualification,
        mutationOrdinal: ordinal,
        observationQualification: captured.observationQualification,
        logicalResource: 'primary-graph',
        batchIndex: 1,
      });
      state.calls.push([
        'privateInitialValues',
        projectValues?.bindings?.map(({ ownerSlot, name }) => ownerSlot + '.' + name),
        graphValues?.bindings?.map(({ ownerSlot, name }) => ownerSlot + '.' + name),
      ]);
      if (projectValues?.bindings?.length !== 4 || graphValues?.bindings?.length !== 3) {
        throw new Error('authenticated ordinal 0 source-operation handoff blocked');
      }
    }
    if (ordinal === 1) {
      const values = producer({
        operation: 'read-provider-values',
        runtimeQualification: state.runtimeQualification,
        context: state.context,
        sessionIntentQualification: state.sessionIntentQualification,
        mutationOrdinal: ordinal,
        observationQualification: captured.observationQualification,
        logicalResource: 'primary-graph',
        batchIndex: 2,
      });
      state.calls.push(['privateValues', values?.bindings?.length]);
      if (values?.bindings?.[0]?.name !== 'sourceBytesDigest') {
        throw new Error('private values readback blocked');
      }
    }
  }
  if (state.releaseMode.startsWith('private-readback') && ordinal >= 17) {
    const ownerSlot = ordinal === 17 ? 'editorShare' : 'viewerShare';
    const baseline = await producer({
      operation: 'read-share-baseline',
      runtimeQualification: state.runtimeQualification,
      context: state.context,
      sessionIntentQualification: state.sessionIntentQualification,
      providerQualification: state.providerQualification,
      ownerSlot,
      mutationOrdinal: ordinal,
      expectedShareRow: expectedShareRow(ownerSlot),
    });
    state.calls.push(['privateShareBaseline', ordinal, baseline?.baselineDigest]);
    if (typeof baseline?.baselineDigest !== 'string') throw new Error('share baseline blocked');
  }
  const issue = Object.freeze(Object.create(null));
  const share = ordinal >= 17;
  state.calls.push(['issue', ordinal, share ? 'share' : 'provider']);
  const bound = producer(share ? {
    operation: 'bind-share-issue',
    runtimeQualification: state.runtimeQualification,
    observationQualification: captured.observationQualification,
    shareIssue: issue,
  } : {
    operation: 'bind-provider-issue',
    runtimeQualification: state.runtimeQualification,
    observationQualification: captured.observationQualification,
    providerMutationIssue: issue,
  });
  if (bound !== true) throw new Error('bind blocked ' + ordinal);
  await handler;
  const released = producer(share ? {
    operation: 'consume-share-release-disposition',
    runtimeQualification: state.runtimeQualification,
    shareIssue: issue,
  } : {
    operation: 'consume-release-disposition',
    runtimeQualification: state.runtimeQualification,
    providerMutationIssue: issue,
  });
  state.calls.push(['release', ordinal, released?.releaseDisposition]);
  if (released?.releaseDisposition !== 'returned') {
    throw new Error('release blocked ' + ordinal);
  }
  let memberIdentity;
  if (state.releaseMode.startsWith('private-readback') && ordinal <= 16) {
    const providerId = ordinal === 0 ? 'file-0' : ordinal === 12 ? 'row-2' : 'row-' + ordinal;
    memberIdentity = {
      logicalResource: ordinal % 2 === 0 ? 'primary-project' : 'primary-graph',
      ownerSlot: 'slot-' + ordinal,
      providerKind: ordinal === 0 ? 'storage-file' : 'tablesdb-row',
      providerId,
      providerCompositeIdentity: 'binding-' + ordinal + '|' + providerId,
    };
    const proof = await producer({
      operation: 'read-provider-result',
      runtimeQualification: state.runtimeQualification,
      context: state.context,
      sessionIntentQualification: state.sessionIntentQualification,
      mutationOrdinal: ordinal,
      observationQualification: captured.observationQualification,
      ...memberIdentity,
    });
    state.calls.push(['privateProviderResult', ordinal, proof?.providerId]);
    if (ordinal === 2 || ordinal === 12) {
      state.calls.push(['completeRowResult', ordinal, proof?.observedResultState]);
    }
    if (ordinal !== 0 && ordinal !== 2 && ordinal !== 12
      && proof?.observedResultState?.ordinal !== ordinal) {
      throw new Error('provider result blocked');
    }
  } else if (state.releaseMode.startsWith('private-readback') && ordinal >= 17) {
    const proof = await producer({
      operation: 'read-share-result',
      runtimeQualification: state.runtimeQualification,
      context: state.context,
      sessionIntentQualification: state.sessionIntentQualification,
      mutationOrdinal: ordinal,
      observationQualification: captured.observationQualification,
    });
    state.calls.push(['privateShareResult', ordinal, proof?.providerId]);
    if (proof?.providerId !== 'share-row-' + ordinal) throw new Error('share result blocked');
  }
  state.calls.push(['reconcile', ordinal, released.releaseDisposition]);
  state.calls.push(['delivery', ordinal]);
  const delivered = await producer({
    operation: 'complete-delivery',
    runtimeQualification: state.runtimeQualification,
    issueKind: share ? 'share' : 'provider',
    issue,
    reconciliationQualification: Object.freeze(Object.create(null)),
  });
  if (delivered?.delivered !== true) throw new Error('delivery blocked ' + ordinal);
  if (state.releaseMode.startsWith('private-readback') && ordinal <= 16) {
    const member = await producer({
      operation: 'read-provider-member-state',
      runtimeQualification: state.runtimeQualification,
      context: state.context,
      sessionIntentQualification: state.sessionIntentQualification,
      logicalResource: memberIdentity.logicalResource,
      ownerSlot: memberIdentity.ownerSlot,
      mutationOrdinal: ordinal,
      providerId: memberIdentity.providerId,
    });
    state.calls.push(['privateMemberState', ordinal, member?.memberState?.presence]);
    if (member?.memberState?.presence !== 'present') throw new Error('member state blocked');
  }
  state.calls.push(['quiesce', ordinal]);
  state.nextOrdinal += 1;
}
state.runMutation = runMutation;
state.runMutationRange = async (first, last) => {
  for (let ordinal = first; ordinal <= last; ordinal += 1) await runMutation(ordinal);
};
function locator(name) {
  state.calls.push(['locate', name]);
  if (name.startsWith('role:group:Shared user ')) {
    state.calls.push([
      'shareRow', state.shareEmail, state.shareRole,
      state.shareRole === 'editor', name,
    ]);
  }
  return Object.freeze({
    async count() { return 1; },
    async isVisible() { return true; },
    async isEnabled() { return true; },
    async isEditable() { return true; },
    async isChecked() { state.calls.push(['isChecked', name]); return false; },
    async fill(value) {
      state.calls.push(['fill', name, value]);
      if (name === 'locator:[aria-label="Share user email"]') state.shareEmail = value;
      if (name.includes('[data-id="n_11111111-1111-4111-8111-111111111111"]')) {
        if (state.releaseMode !== 'private-readback-real-composition') {
          await state.runMutationRange(9, 10);
        }
      }
    },
    async click() {
      state.calls.push(['click', name]);
      if (name === 'role:button:Login') {
        await dispatchBenign(
          'session', state.endpointUrl ?? 'https://api.example/account/sessions/email', 'POST', 'fetch',
          state.ownerSessionRequestHeaders ?? Object.freeze([]),
          makeResponse(
            'session', state.endpointUrl ?? 'https://api.example/account/sessions/email', 201,
            state.ownerSessionResponseHeaders
              ?? Object.freeze([{ name: 'set-cookie', value: 'opaque-session' }]),
            '{"secret":"must-not-read"}',
          ),
        );
        await dispatchBenign(
          'account', state.accountUrl ?? 'https://api.example/account', 'GET', 'fetch',
          state.ownerAccountRequestHeaders
            ?? Object.freeze([{ name: 'cookie', value: 'opaque-cookie' }]),
          makeResponse(
            'account', state.accountUrl ?? 'https://api.example/account', 200,
            state.ownerAccountResponseHeaders
              ?? Object.freeze([{ name: 'content-type', value: 'application/json; charset=utf-8' }]),
            JSON.stringify({
              $id: state.ownerAccount?.$id ?? 'owner-api',
              email: state.ownerAccount?.email ?? 'owner@example.test',
              name: state.ownerAccount?.name ?? 'Owner API',
              status: true, extra: 'ignored',
            }),
          ),
        );
      }
      if (name === 'role:button:Create') await state.runMutationRange(0, 2);
      if (name === 'role:button:Add Input: Text') await state.runMutationRange(3, 5);
      if (name === 'role:button:Add Output: Display') {
        await state.runMutationRange(
          6,
          state.releaseMode === 'private-readback-real-composition' ? 7 : 8,
        );
      }
      if (name === 'role:button:Share') {
        const ordinal = state.shareRole === 'editor' ? 17 : 18;
        state.calls.push(['baseline', ordinal, state.shareRole]);
        await runMutation(ordinal, state.shareRole);
      }
    },
    async selectOption(value) {
      state.calls.push(['select', name, value]);
      state.shareRole = value;
    },
    async dragTo(target) {
      state.calls.push(['connect', name, target.name]);
      if (state.releaseMode !== 'private-readback-real-composition') {
        await state.runMutationRange(11, 12);
      }
    },
    name,
  });
}
const request = Object.freeze({
  url() { return state.pageUrl; }, method() { return 'GET'; }, resourceType() { return 'document'; },
});
const route = Object.freeze({
  request() { return request; },
  async fulfill(options) {
    state.calls.push(options.response === undefined
      ? ['fulfill', options.status, options.contentType]
      : ['fulfillResponse']);
  },
  async abort(reason) { state.calls.push(['abort', reason]); },
});
let context;
let page;
const apiRequest = Object.freeze({
  async get(url, options) {
    state.calls.push(['backendGet', url, options]);
    const share = url.includes('/tables/' + (state.sharesTableId ?? 'shares-qualified') + '/rows?');
    const id = decodeURIComponent(new URL(url).pathname.split('/').at(-1));
    const stored = state.backendRows.get(id);
    const shareRows = state.releaseMode === 'private-readback-share-extra-rows'
      && state.shareBackendRows.length > 0
      ? Object.freeze(Array.from({ length: 4 }, (_, index) => closed({
        ...state.shareBackendRows[0], $id: 'extra-share-' + index, $sequence: 30 + index,
      })))
      : state.releaseMode === 'private-readback-share-total-over-limit'
        && state.shareBackendRows.length > 0
        ? Object.freeze([
          ...state.shareBackendRows,
          ...Array.from({ length: Math.max(0, 3 - state.shareBackendRows.length) },
            (_, index) => closed({
              ...state.shareBackendRows[0],
              $id: 'truncated-extra-' + index,
              $sequence: 40 + index,
            })),
        ].slice(0, 3))
        : state.shareBackendRows;
    const body = share
      ? JSON.stringify({
        total: state.releaseMode === 'private-readback-share-total-over-limit'
          && shareRows.length === 3 ? 4 : shareRows.length,
        rows: shareRows,
      })
      : JSON.stringify(stored ?? {
        $id: id, $sequence: 1, $tableId: 'table-' + Number(id.slice(4)),
        $databaseId: 'primary', $createdAt: '2026-07-28T00:00:00.000Z',
        $updatedAt: '2026-07-28T00:00:00.000Z', $permissions: [],
        ordinal: Number(id.slice(4)),
      });
    return makeResponse('backend', url, 200, Object.freeze([]), body);
  },
});
const browser = Object.freeze({
  contexts() { return context === undefined ? [] : [context]; },
  async newContext(options) {
    state.calls.push(['newContext', options]);
    context = Object.freeze({
      get request() { return apiRequest; },
      pages() { return page === undefined ? [] : [page]; },
      serviceWorkers() { return []; },
      async route(pattern, handler) { state.calls.push(['route', pattern]); state.routeHandler = handler; },
      async routeWebSocket(pattern, handler) { state.calls.push(['routeWebSocket', pattern]); state.webSocketHandler = handler; },
      async newPage() {
        state.calls.push(['newPage']);
        const pageValue = {
          context() { return context; }, url() { return state.pageUrl; }, workers() { return []; },
          async goto(url, options) {
            state.calls.push(['goto', url, options]);
            const mainResponse = makeResponse('main', url, 200, Object.freeze([]), '');
            const mainRoute = makeRoute(
              'main', makeRequest('main', url, 'GET', 'document', Object.freeze([])), mainResponse,
            );
            await state.routeHandler(mainRoute);
            state.pageUrl = url;
            return Object.freeze({ url() { return url; }, status() { return 200; } });
          },
          locator(selector) { return locator('locator:' + selector); },
          getByRole(role, options) { return locator('role:' + role + ':' + options.name); },
          async addInitScript() { state.calls.push(['initScript']); },
          async waitForTimeout(milliseconds) {
            state.calls.push(['waitForTimeout', milliseconds]);
            if (milliseconds === 800
              && state.releaseMode === 'private-readback-real-composition'
              && state.nextOrdinal === 8) {
              await state.runMutationRange(8, 16);
            }
          },
          async close(options) { state.calls.push(['pageClose', options]); page = undefined; },
        };
        page = state.releaseMode === 'mutate-page-url' ? pageValue : Object.freeze(pageValue);
        state.mutateCapturedPage = () => {
          page.url = function mutatedUrl() { state.calls.push(['mutatedPageAction']); return state.pageUrl; };
        };
        return page;
      },
      async unrouteAll(options) { state.calls.push(['unrouteAll', options]); },
      async close(options) { state.calls.push(['contextClose', options]); context = undefined; },
    });
    return context;
  },
  async close(options) { state.calls.push(['browserClose', options]); },
});
class SyntheticBrowserType {
  async launch(options) { state.calls.push(['launch', options]); return browser; }
}
export const chromium = Object.freeze(new SyntheticBrowserType());
`;

function runFinalLifecycleWorker(releaseMode = 'normal') {
  const workerSource = String.raw`
import { registerHooks } from 'node:module';
import { parentPort, workerData } from 'node:worker_threads';
import { createHash } from 'node:crypto';
const state = globalThis.__routeAdapterTestState = {
  calls: [], lifecycle: 'BOOTSTRAPPING', factoryAuthorization: true,
  playwrightModuleLoads: 0, pageUrl: 'about:blank', nextOrdinal: 0,
  clockOperationsCreated: 0, shareEmail: undefined, shareRole: 'viewer', releaseMode: workerData.releaseMode,
  runtimeQualification: Object.freeze(Object.create(null)),
};
state.backendRows = new Map();
state.shareBackendRows = [];
state.providerQualification = Object.freeze(Object.create(null));
state.safeReflectApply = Reflect.apply;
state.reflectApplyPoisonCalls = [];
const encoded = (source) => 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
const urls = {
  provider: encoded(workerData.providerSource),
  artifact: encoded(workerData.artifactSource),
  playwright: encoded(workerData.playwrightSource),
};
registerHooks({ resolve(specifier, context, nextResolve) {
  if (specifier === 'playwright') return { url: urls.playwright, shortCircuit: true };
  if (specifier.endsWith('test-cloud-provider-contract.mjs')) return { url: urls.provider, shortCircuit: true };
  if (specifier.endsWith('test-cloud-browser-artifact-set.mjs')) return { url: urls.artifact, shortCircuit: true };
  return nextResolve(specifier, context);
} });
const closed = (value) => Object.freeze(Object.assign(Object.create(null), value));
const hubFrom = (properties) => {
  const hub = Object.create(null);
  for (const [name, value] of Object.entries(properties)) Object.defineProperty(hub, name, {
    value, enumerable: true, configurable: false, writable: false,
  });
  return Object.freeze(hub);
};
try {
const sha = (value) => 'sha256:' + createHash('sha256').update(value).digest('hex');
const mainBytes = Buffer.from('<!doctype html>');
state.mainArtifact = closed({
  bodyBase64: mainBytes.toString('base64'),
  responseBodyDigest: sha(mainBytes),
  responseByteLength: mainBytes.byteLength,
});
const empty = Object.freeze([]);
state.policy = closed({
  schemaVersion: 'test-cloud.browser-request-policy.v1',
  timeoutMilliseconds: 5000,
  rows: Object.freeze([
    closed({
      ordinal: 0,
      requestClass: 'main-document',
      method: 'GET',
      finalUrl: 'https://app.example/',
      resourceType: 'document',
      requestHeaderBindings: empty,
      requestOpaqueHeaderRules: empty,
      credentialCarrier: 'none',
      expectedResponseStatus: 200,
      responseMimeEssence: 'text/html',
      responseHeaderBindings: empty,
      responseOpaqueHeaderRules: empty,
      responseBodyDigest: state.mainArtifact.responseBodyDigest,
      responseByteLength: state.mainArtifact.responseByteLength,
    }),
    closed({
      ordinal: 1,
      requestClass: 'owner-session-create',
      method: 'POST',
      finalUrl: 'https://api.example/account/sessions/email',
      resourceType: 'fetch',
      requestHeaderBindings: empty,
      requestOpaqueHeaderRules: empty,
      credentialCarrier: 'owner-login-body-only',
      expectedResponseStatus: 201,
      responseMimeEssence: null,
      responseHeaderBindings: empty,
      responseOpaqueHeaderRules: Object.freeze([
        closed({ name: 'set-cookie', minimumCount: 1, maximumCount: 16 }),
      ]),
    }),
    closed({
      ordinal: 2,
      requestClass: 'appwrite-read',
      method: 'GET',
      finalUrl: 'https://api.example/account',
      resourceType: 'fetch',
      requestHeaderBindings: empty,
      requestOpaqueHeaderRules: Object.freeze([
        closed({ name: 'cookie', minimumCount: 1, maximumCount: 1 }),
      ]),
      credentialCarrier: 'browser-cookie-jar-only',
      expectedResponseStatus: 200,
      responseMimeEssence: 'application/json',
      responseHeaderBindings: Object.freeze([
        closed({ name: 'content-type', valueDigest: sha('application/json; charset=utf-8') }),
      ]),
      responseOpaqueHeaderRules: empty,
    }),
  ]),
  digest: sha('focused-policy'),
});
  const adapter = await import(workerData.adapterUrl);
  const created = await adapter.createTestCloudBrowserFacade();
  const launchesAfterFactory = state.calls.filter(([call]) => call === 'launch').length;
  const bridgeReceiver = Object.freeze(Object.create(null));
  state.hub = hubFrom({
    bridgeReceiver,
    registerProviderMutationRouteProducer(envelope) {
      state.routeProducer = envelope;
      return Reflect.ownKeys(envelope).join(',') === 'receiver,implementation,moduleUrl,artifactMemberReader'
        && envelope.artifactMemberReader === state.artifactMemberReader;
    },
    registerBrowserRouteAdapterImplementation(implementation) { state.implementation = implementation; return true; },
    registerBrowserScenarioAutosaveCompletionReceiver(envelope) {
      state.autosave = envelope;
      return Reflect.ownKeys(envelope).join(',') === 'receiver,implementation,moduleUrl';
    },
    readBrowserRequestPolicy() {
      state.calls.push(['policy']);
      if (workerData.releaseMode === 'mutate-page-url') {
        state.mutateCapturedPage();
      }
      return closed({
        browserRequestPolicy: state.policy,
      });
    },
    readAuthenticatedBrowserIdentityEmail(args) {
      state.calls.push(['identity', args.role]);
      return args.role + '@example.test';
    },
    authenticateBrowserScenarioQualification(args) {
      return args.browserScenarioQualification === created.browserScenarioQualification;
    },
    browserFacade: created.browserFacade,
    browserScenarioQualification: created.browserScenarioQualification,
  });
  Object.defineProperty(globalThis, '__APPWRITEWORK_TEST_CLOUD_BOOTSTRAP_HUB_V1__', {
    value: state.hub, enumerable: false, configurable: true, writable: false,
  });
  if (workerData.releaseMode === 'poison-reflect-apply') {
    Reflect.apply = function poisonedReflectApply(target, receiver, args) {
      state.reflectApplyPoisonCalls.push([target, receiver, args]);
      return state.safeReflectApply(target, receiver, args);
    };
  }
  const registered = adapter.registerTestCloudBrowserRouteAdapterBootstrap();
  const committed = await created.finalizeBootstrap(closed({ outcome: 'commit' }));
  const launchesAfterCommit = state.calls.filter(([call]) => call === 'launch').length;
  state.lifecycle = 'ACTIVE';
  const clock = Object.freeze(Object.create(null));
  const pass = (value) => closed({
    status: 'PASS', value: closed(value), diagnostics: Object.freeze([]),
  });
  function freshClockOperations() {
    const id = state.clockOperationsCreated + 1;
    state.clockOperationsCreated = id;
    state.calls.push(['clockOperations', id]);
    const receiver = Object.freeze(Object.create(null));
    return closed({
      receiver,
      async installTestCloudFixtureClock(args) {
        state.calls.push(['clockInstall', id, args.clock === clock]);
        state.facadeInstall = await created.browserFacade.installPausedBeforeNavigation(
          closed({ baseUtc: '2026-08-01T00:00:00.000Z' }),
        );
        return pass({ clock: args.clock });
      },
      async authenticateTestCloudFixtureClock(args) {
        state.calls.push([
          'clockAuthenticate', id, args.clock === clock,
          args.sessionIntentQualification === state.sessionIntentQualification,
        ]);
        return pass({ clock: args.clock });
      },
      async advanceTestCloudFixtureClock(args) {
        state.calls.push(['clockAdvance', id, args.clock === clock]);
        await state.runMutationRange(13, 16);
        const delivered = state.safeReflectApply(
          state.autosave.implementation,
          state.autosave.receiver,
          [closed({ runtimeQualification: state.runtimeQualification, clock })],
        );
        if (delivered !== true) throw new Error('autosave delivery blocked');
        return pass({ clock: args.clock });
      },
      async sealTestCloudFixtureClock(args) {
        state.calls.push(['clockSeal', id, args.clock === clock]);
        return pass({ clock: args.clock });
      },
    });
  }
  state.context = closed({ environmentDigest: 'sha256:' + '1'.repeat(64) });
  const common = {
    runtimeQualification: state.runtimeQualification,
    context: state.context,
    browserScenarioQualification: created.browserScenarioQualification,
    providerContractQualification: Object.freeze(Object.create(null)),
    sessionIntentQualification: state.sessionIntentQualification,
  };
  const ownerLoginResult = await state.safeReflectApply(
    state.implementation.performOwnerLogin,
    state.implementation.receiver,
    [closed({
      ...common,
      clock,
      clockOperations: freshClockOperations(),
      ownerLoginInput: closed({ password: 'secret-for-test' }),
      identityBindingsQualification: state.identityBindingsQualification,
      providerSetupReadbackQualification: state.providerSetupReadbackQualification,
    })],
  );
  const launchesAfterOwnerLogin = state.calls.filter(([call]) => call === 'launch').length;
  const operationResults = [
    ownerLoginResult,
    await state.safeReflectApply(state.implementation.performProjectCreateAndGraphEditPrefix, state.implementation.receiver, [closed({
      ...common, clock, clockOperations: freshClockOperations(),
    })]),
    await state.safeReflectApply(state.implementation.performEditorShare, state.implementation.receiver, [closed({
      ...common, identityBindingsQualification: state.identityBindingsQualification,
    })]),
    await state.safeReflectApply(state.implementation.performViewerShare, state.implementation.receiver, [closed({
      ...common, identityBindingsQualification: state.identityBindingsQualification,
    })]),
  ];
  const facadeResults = [
    state.facadeInstall,
    await created.browserFacade.proveOwnerUiReady(closed({})),
    await created.browserFacade.readOwnerAccount(closed({})),
    await created.browserFacade.runForExactly800Milliseconds(closed({})),
    await created.browserFacade.sealClock(closed({})),
  ];
  const duplicate = await adapter.createTestCloudBrowserFacade();
  parentPort.postMessage({
    exports: Object.keys(adapter).sort(), createdKeys: Reflect.ownKeys(created),
    createdNullPrototype: Object.getPrototypeOf(created) === null,
    createdFrozen: Object.isFrozen(created), scenarioKeys: Reflect.ownKeys(created.browserScenarioQualification),
    facadeKeys: Reflect.ownKeys(created.browserFacade), registered, committed,
    operationResults, facadeResults, duplicate, calls: state.calls,
    launchesAfterFactory, launchesAfterCommit, launchesAfterOwnerLogin,
    playwrightModuleLoads: state.playwrightModuleLoads,
    reflectApplyPoisonCallCount: state.reflectApplyPoisonCalls.length,
  });
} catch (error) {
  parentPort.postMessage({ error: String(error?.stack ?? error), calls: state.calls });
}
`;
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerSource, { eval: true, type: 'module', workerData: {
      adapterUrl: new URL('./test-cloud-browser-route-adapter.mjs', import.meta.url).href,
      providerSource: workerProviderSource,
      artifactSource: workerArtifactSource,
      playwrightSource: workerPlaywrightSource,
      releaseMode,
    } });
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.once('exit', (code) => { if (code !== 0) reject(new Error(`worker exited ${code}`)); });
  });
}

test('hosted parent browser adapter completes the fixed owner project graph and share route sequence', async () => {
  const result = await runFinalLifecycleWorker();
  assert.equal(result.error, undefined, result.error);
  assert.deepEqual(result.exports, [
    'createTestCloudBrowserFacade',
    'registerTestCloudBrowserRouteAdapterBootstrap',
  ]);
  assert.deepEqual(result.createdKeys, [
    'browserFacade', 'browserScenarioQualification', 'finalizeBootstrap',
  ]);
  assert.equal(result.createdNullPrototype, true);
  assert.equal(result.createdFrozen, true);
  assert.deepEqual(result.scenarioKeys, []);
  assert.deepEqual(result.facadeKeys, [
    'installPausedBeforeNavigation', 'proveOwnerUiReady', 'readOwnerAccount',
    'runForExactly800Milliseconds', 'sealClock',
  ]);
  assert.equal(result.registered, true);
  assert.equal(result.committed, true);
  assert.equal(result.playwrightModuleLoads, 1);
  assert.equal(result.launchesAfterFactory, 0);
  assert.equal(result.launchesAfterCommit, 0);
  assert.equal(result.launchesAfterOwnerLogin, 1);
  assert.deepEqual(
    result.operationResults.map((value) => value.status),
    ['PASS', 'PASS', 'PASS', 'PASS'],
  );
  assert.equal(result.facadeResults.length, 5);
  for (const name of ['launch', 'newContext', 'route', 'routeWebSocket', 'newPage']) {
    assert.equal(result.calls.filter(([call]) => call === name).length, 1, name);
  }
  assert.equal(
    result.calls.filter(([call]) => call === 'fulfillResponse').length,
    19,
  );
  assert.deepEqual(
    result.calls.filter(([call]) => call === 'capture').map(([, ordinal]) => ordinal),
    Array.from({ length: 19 }, (_, ordinal) => ordinal),
  );
  for (const name of ['pageClose', 'contextClose', 'browserClose']) {
    assert.equal(result.calls.filter(([call]) => call === name).length, 1, name);
  }
  assert.equal(result.duplicate.status, 'BLOCKED');
  assert.equal(result.calls.filter(([call]) => call === 'launch').length, 1);
});

test('hosted parent browser adapter registration and both share roles ignore poisoned ambient Reflect.apply', async () => {
  const result = await runFinalLifecycleWorker('poison-reflect-apply');
  assert.equal(result.error, undefined, result.error);
  assert.equal(result.registered, true);
  assert.deepEqual(
    result.operationResults.map((value) => value.status),
    ['PASS', 'PASS', 'PASS', 'PASS'],
  );
  assert.equal(result.reflectApplyPoisonCallCount, 0);
});

test('Task 8 review RED: private broker abort settles the captured route without physical release', async () => {
  const result = await runFinalLifecycleWorker('review-abort-after-capture');
  assert.equal(result.error, undefined, result.error);
  assert.deepEqual(
    result.calls.find(([name]) => name === 'reviewAbort'),
    ['reviewAbort', 0, true, true],
  );
  assert.deepEqual(
    result.calls.filter(([name, label]) => name === 'abort' && label === 'mutation-0'),
    [['abort', 'mutation-0', 'blockedbyclient']],
  );
  assert.equal(result.calls.some(([name, label]) => (
    name === 'fetch' && label === 'mutation-0'
  )), false, 'abort before issue must not perform the physical create');
  for (const name of ['pageClose', 'contextClose', 'browserClose']) {
    assert.equal(
      result.calls.filter(([call]) => call === name).length,
      1,
      `${name} must settle the owned browser graph`,
    );
  }
});

test('real browser route adapter owns the closed private provider readback capability', async () => {
  const result = await runFinalLifecycleWorker('private-readback');
  assert.equal(result.error, undefined, result.error);
  assert.deepEqual(
    result.calls.find(([kind]) => kind === 'privateInitialValues')?.slice(1),
    [[
      'rootManifestInitial.sourceBytesDigest',
      'rootArtifact.rootArtifactId',
      'rootVersionInitial.rootContentHash',
      'projectFacade.projectId',
    ], [
      'entrypointArtifact.entrypointArtifactId',
      'entrypointVersionInitial.initialEntrypointVersionId',
      'entrypointVersionInitial.workflowContentHash',
    ]],
    JSON.stringify(result.calls),
  );
  assert.deepEqual(
    result.calls.filter(([kind]) => kind === 'privateBinding')
      .map(([, ordinal]) => ordinal),
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16],
    JSON.stringify(result.calls.slice(-30)),
  );
  const rowCreateState = result.calls.find(
    ([kind, ordinal]) => kind === 'completeRowResult' && ordinal === 2,
  )?.[2];
  const rowUpdateState = result.calls.find(
    ([kind, ordinal]) => kind === 'completeRowResult' && ordinal === 12,
  )?.[2];
  const completeArtifactKeys = [
    'artifactId', 'artifactRole', 'artifactType', 'containerProfile', 'createdBy',
    'description', 'importedAt', 'latestDraftVersionId', 'latestPublishedVersionId',
    'latestValidationId', 'lifecycleState', 'name', 'originArtifactId', 'originChecksum',
    'originProjectId', 'originVersionId', 'parentContainerId', 'projectId', 'updatedBy',
  ];
  assert.deepEqual(Object.keys(rowCreateState), completeArtifactKeys);
  assert.deepEqual(Object.keys(rowUpdateState), completeArtifactKeys);
  assert.equal(rowCreateState.description, null);
  assert.equal(rowCreateState.latestPublishedVersionId, 'root-version-initial');
  assert.equal(rowUpdateState.artifactId, 'root-artifact-id');
  assert.equal(rowUpdateState.description, null);
  assert.equal(rowUpdateState.projectId, 'project-id');
  assert.equal(rowUpdateState.latestPublishedVersionId, 'root-version-saved');
  assert.equal(result.calls.filter(([kind]) => kind === 'privateValues').length, 1);
  assert.equal(result.calls.filter(([kind]) => kind === 'privateProviderResult').length, 17);
  assert.equal(result.calls.filter(([kind]) => kind === 'privateMemberState').length, 17);
  assert.deepEqual(
    result.calls.filter(([kind]) => kind === 'privateShareBaseline').map(([, ordinal]) => ordinal),
    [17, 18],
  );
  assert.deepEqual(
    result.calls.filter(([kind]) => kind === 'privateShareResult').map(([, ordinal]) => ordinal),
    [17, 18],
  );
  assert.equal(result.calls.filter(([kind]) => kind === 'backendGet').length, 38);
  const shareReads = result.calls.filter(
    ([kind, url]) => kind === 'backendGet' && url.includes('/tables/shares-qualified/rows?'),
  );
  assert.equal(shareReads.length, 4);
  for (const [, rawUrl] of shareReads) {
    const readUrl = new URL(rawUrl);
    assert.equal(readUrl.pathname, '/tablesdb/primary/tables/shares-qualified/rows');
    assert.equal(readUrl.searchParams.get('total'), 'true');
    assert.deepEqual(readUrl.searchParams.getAll('queries[]').map(JSON.parse), [{
      method: 'select', values: [
        '$id', '$sequence', '$tableId', '$databaseId', '$createdAt', '$updatedAt', '$permissions',
        'projectId', 'userId', 'userEmail', 'userName', 'role', 'canRun', 'sharedBy',
      ],
    }, { method: 'equal', attribute: 'projectId', values: ['row-6'] }, {
      method: 'limit', values: [3],
    }]);
  }
});

test('qualified share query rejects wrong bindings, shape, mode, and excess rows', async () => {
  for (const suffix of [
    'wrong-database', 'wrong-table', 'wrong-projection', 'wrong-limit',
    'wrong-mode', 'extra-rows', 'wrong-user-id', 'wrong-user-name',
    'wrong-shared-by', 'wrong-permissions', 'alias', 'total-over-limit',
  ]) {
    const result = await runFinalLifecycleWorker('private-readback-share-' + suffix);
    const statuses = result.operationResults?.map(({ status }) => status) ?? [];
    assert.equal(
      result.error !== undefined || statuses.some((status) => status === 'BLOCKED'),
      true,
      suffix,
    );
    assert.equal(
      result.calls.some(([kind, ordinal]) => kind === 'fulfillResponse'
        && ordinal >= (suffix === 'alias' ? 18 : 17)),
      false,
      suffix,
    );
  }
});
