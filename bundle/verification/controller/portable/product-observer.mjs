import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonical, connect, hash, operation, pause, requireThat } from './product-client.mjs';

const OWNER = 'io.appwritework.portable';
const ID = /^[A-Za-z0-9_-]{1,128}$/;
function identifier(value) { requireThat(typeof value === 'string' && ID.test(value), 'OBSERVER_BINDING_ID_INVALID'); return value; }
function quote(value) { return "'" + identifier(value) + "'"; }

export function resolveRestoredResource(inventory, { projectId, rootId, name, bytes }) {
  requireThat(inventory?.projectId === projectId && inventory.nextCursor === null && Array.isArray(inventory.artifacts)
    && inventory.artifacts.every(artifact => artifact && artifact.projectId === projectId), 'OBSERVER_RESTORED_INVENTORY_INCOMPLETE');
  const candidates = inventory.artifacts.filter(artifact => artifact.artifactType === 'resource.file.v1'
    && artifact.name === name && artifact.parentContainerId === rootId);
  requireThat(candidates.length === 1, 'OBSERVER_RESTORED_RESOURCE_BINDING');
  const artifact = candidates[0];
  requireThat(artifact.contentHash === hash(bytes) && artifact.sizeBytes === bytes.length
    && artifact.stability === 'stable' && artifact.lifecycleState === 'published', 'OBSERVER_RESTORED_RESOURCE_BINDING');
  return { artifactId: identifier(artifact.artifactId), alias: 'stable' };
}

export function assertRunReadback(row, { tenantId, ownerId, projectId, runId, value, resultValue, queued = false }) {
  requireThat(row && row.tenant_id === tenantId && row.caller_principal_id === ownerId
    && row.project_id === projectId && row.run_id === runId && row.engine_id === 'temporal', 'OBSERVER_SQL_RUN_BINDING');
  requireThat(typeof row.workflow_id === 'string' && row.workflow_id.length > 0
    && typeof row.engine_attempt_ref === 'string' && row.engine_attempt_ref.length > 0, 'OBSERVER_SQL_ENGINE_BINDING');
  if (queued) requireThat(row.state === 'accepted' && row.terminal_receipt === null && row.first_execution_ref === null
    && row.terminal_proof === null && row.terminal_result === null, 'OBSERVER_SQL_QUEUE_NOT_DURABLE');
  else {
    const ref = row.step_output_ref, encoded = canonical(resultValue);
    const terminalRef = row.terminal_result?.output_ref;
    requireThat(row.state === 'succeeded' && row.terminal_receipt && typeof row.first_execution_ref === 'string' && row.first_execution_ref.length > 0 && row.terminal_proof
      && terminalRef && /^execution-artifact-[a-f0-9]{64}$/.test(terminalRef.artifact_ref ?? '')
      && /^sha256:[a-f0-9]{64}$/.test(terminalRef.digest ?? '') && Number.isSafeInteger(terminalRef.size_bytes) && terminalRef.size_bytes > 0
      && /^sha256:[a-f0-9]{64}$/.test(row.terminal_result?.plan_digest ?? '')
      && ref && /^execution-artifact-[a-f0-9]{64}$/.test(ref.artifact_ref ?? '')
      && typeof encoded === 'string' && resultValue && canonical(resultValue) === canonical({ value })
      && ref.digest === hash(encoded) && ref.size_bytes === Buffer.byteLength(encoded), 'OBSERVER_SQL_RESULT_NOT_DURABLE');
  }
  return { runId, workflowId: row.workflow_id, engineAttemptRef: row.engine_attempt_ref,
    ...(queued ? {} : { firstExecutionRef: row.first_execution_ref, terminalResultDigest: hash(canonical(row.terminal_result)) }), state: row.state };
}

// Driver supplies only fresh state and the already scoped Docker capability.
// This module does not load profile files, candidate JavaScript or stdout receipts.
export async function observePortableProduct({ state: s, credentials: c, ca, docker, output }) {
  requireThat(/^sm[89]-[a-z0-9-]{6,36}$/.test(s?.project) && typeof docker === 'function', 'OBSERVER_FRESH_SCOPE_REQUIRED');
  for (const field of ['projectId', 'ownerId', 'tenantId']) identifier(c?.[field]);
  requireThat(c.owner?.email && c.owner?.password && c.apiKey, 'OBSERVER_SYNTHETIC_CREDENTIALS_REQUIRED');
  const report = { schemaVersion: 'portable-product-observation.v1', status: 'IN_PROGRESS',
    project: s.project, endpoint: s.endpoint, checks: [], bindings: {},
    coverage: ['real-auth', 'authoring-publication', 'access-denial', 'storage-range', 'sql-temporal-queued-recovery', 'snapshot-copy-restore', 'mcp'],
    limitations: ['HTTP/API journeys do not qualify visual browser interaction', 'Native Windows and provider services are separate capabilities'],
    cleanup: { status: 'NOT_RUN', owner: 'trusted-product-driver' } };
  const x = connect({ state: s, credentials: c, ca, checks: report.checks });
  const attempt = 'obs' + randomBytes(6).toString('hex');
  const guestId = 'auditguest' + randomBytes(8).toString('hex');
  let workerId, workerStopped = false, guestCreated = false, failed;
  const inspectService = async service => {
    const ids = String(await docker(['ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + s.project,
      '--filter', 'label=com.docker.compose.service=' + service])).trim().split(/\s+/).filter(Boolean);
    requireThat(ids.length === 1 && /^[a-f0-9]{64}$/.test(ids[0]), 'OBSERVER_SERVICE_ID_REQUIRED');
    const rows = JSON.parse(await docker(['inspect', ids[0]]));
    requireThat(rows.length === 1 && rows[0].Id === ids[0]
      && rows[0].Config?.Labels?.[OWNER] === s.project
      && rows[0].Config?.Labels?.['com.docker.compose.project'] === s.project
      && rows[0].Config?.Labels?.['com.docker.compose.service'] === service, 'OBSERVER_SERVICE_OWNERSHIP');
    return rows[0];
  };
  const sqlRun = async runId => {
    const pg = await inspectService('app-postgres');
    const query = 'SELECT row_to_json(r) FROM (SELECT e.*, c.first_execution_ref, c.terminal_proof, c.terminal_result,'
      + " (SELECT receipt->'output_ref' FROM salmora_app.execution_runtime_steps st WHERE st.tenant_id=e.tenant_id AND st.run_id=e.run_id AND st.node_id='start') AS step_output_ref"
      + ' FROM salmora_app.execution_runs e LEFT JOIN salmora_app.execution_runtime_control c USING (tenant_id,run_id)'
      + ' WHERE e.tenant_id=' + quote(c.tenantId) + ' AND e.run_id=' + quote(runId) + ') r;';
    const text = String(await docker(['exec', pg.Id, 'psql', '-U', 'salmora_operator', '-d', 'salmora', '-XAt',
      '-v', 'ON_ERROR_STOP=1', '-c', query], { timeout: 30_000 })).trim();
    requireThat(Buffer.byteLength(text) <= 1024 * 1024, 'OBSERVER_SQL_RESPONSE_LIMIT');
    requireThat(text && !text.includes('\n'), 'OBSERVER_SQL_SINGLE_RUN_REQUIRED');
    try { return JSON.parse(text); } catch { throw new Error('OBSERVER_SQL_RESPONSE_INVALID'); }
  };
  try {
    const guest = { email: guestId + '@portable.invalid', password: randomBytes(24).toString('hex') };
    const madeGuest = await x.operator('POST', '/users', { userId: guestId, ...guest, name: 'Synthetic verifier guest' });
    guestCreated = true;
    requireThat(madeGuest.value?.$id === guestId, 'OBSERVER_GUEST_BINDING');
    const owner = await x.login(c.ownerId, c.owner), outsider = await x.login(guestId, guest);
    const invoke = x.invoke;
    const author = (label, kind, payload, options) => invoke(label, 'salmora-authoring-py', owner,
      operation(attempt + '_' + label, kind, payload, options));
    async function job(label, body) {
      for (let n = 0; n < 80; n++) {
        const result = await invoke(label + '-' + n, 'salmora-authoring-py', owner, body, { status: [200, 202], envelope: false });
        requireThat(result.contract === 'salmora.operation-result.v1' && result.operationId === body.operationId, 'OBSERVER_JOB_BINDING');
        if (result.status === 'succeeded') return result;
        requireThat(result.status === 'uncertain' && result.error?.code === 'OPERATION_PENDING', 'OBSERVER_JOB_FAILED');
        await pause(500);
      }
      throw new Error('OBSERVER_JOB_TIMEOUT');
    }
    const created = await author('create', 'projects.create.v1', { name: 'Independent portable verifier', initialWorkflow: {
      nodes: [{ id: 'start', templateId: 'input.text', fields: { value: 'Initial independent source' } }], edges: [],
    } }, { selector: c.tenantId });
    const projectId = identifier(created.result.projectId);
    const artifactId = identifier(created.result.sourceRef?.artifactId ?? created.result.defaultEntrypointRef?.artifactId ?? created.result.project?.defaultEntrypointRef?.artifactId);
    const rootId = identifier(created.result.rootContainerArtifactId ?? created.result.project?.rootContainerArtifactId);
    await invoke('guest-project-denied', 'salmora-authoring-py', outsider,
      operation(attempt + '_guest', 'projects.read.v1', { projectId }), { status: 403, code: 'AUTHORITY_DENIED' });
    const value = 'Independent verifier result ' + randomBytes(16).toString('hex');
    const edit = operation(attempt + '_edit', 'artifacts.edit-workflow.v1', { projectId, artifactId,
      edits: [{ kind: 'node.replace', node: { id: 'start', templateId: 'input.text', fields: { value } } }] }, { revision: created.revision });
    const edited = await invoke('edit', 'salmora-authoring-py', owner, edit);
    requireThat(canonical(edited) === canonical(await invoke('edit-replay', 'salmora-authoring-py', owner, edit)), 'OBSERVER_EDIT_REPLAY_DRIFT');
    const validation = await author('validate', 'artifacts.validate.v1', { projectId, artifactId, draftVersionId: edited.result.draftVersionId });
    await author('publish', 'artifacts.publish.v1', { projectId, artifactId, draftVersionId: edited.result.draftVersionId,
      validationSnapshotId: validation.result.validationSnapshot.snapshotId, activateAlias: 'stable' }, { revision: edited.revision });
    const source = await author('source', 'artifacts.read.v1', { projectId, artifactId, alias: 'stable' });
    requireThat(JSON.parse(Buffer.from(source.result.bytesBase64, 'base64')).nodes[0].fields.value === value, 'OBSERVER_PUBLISHED_BYTES_MISMATCH');

    const project = await author('resource-revision', 'projects.read.v1', { projectId });
    const bytes = Buffer.from('Independent resource ' + randomBytes(16).toString('hex') + '\nZażółć gęślą\n');
    const resourceBody = operation(attempt + '_resource', 'artifacts.create.v1', { projectId, parentContainerId: rootId,
      artifactType: 'resource.file.v1', name: 'observer.txt', resource: { byteDigest: hash(bytes), byteSize: bytes.length, mimeType: 'text/plain' } },
    { revision: project.revision });
    const pending = await invoke('resource-reserve', 'salmora-authoring-py', owner, resourceBody);
    requireThat(pending.result.state === 'pending', 'OBSERVER_UPLOAD_INTENT_REQUIRED');
    const content = (label, kind, payload) => invoke(label, 'salmora-content-py', owner,
      operation(attempt + '_' + label, kind, payload, { scope: 'content', tenant: c.tenantId, caller: c.ownerId }));
    await content('stage', 'content.stage-chunked.v1', { ownerUploadIntentRef: pending.result.ownerUploadIntentRef });
    await content('upload', 'content.upload-chunk.v1', { uploadIntentRef: pending.result.uploadIntentRef, chunkIndex: 0,
      chunkDigest: hash(bytes), chunkByteSize: bytes.length, bytesBase64: bytes.toString('base64') });
    await content('finalize', 'content.finalize-chunked.v1', { uploadIntentRef: pending.result.uploadIntentRef });
    const resource = await invoke('resource-commit', 'salmora-authoring-py', owner, resourceBody);
    const ranged = await author('resource-range', 'artifacts.read-range.v1', { projectId, artifactId: resource.result.artifactId,
      alias: 'stable', byteOffset: 3, byteSize: bytes.length - 3 });
    requireThat(Buffer.from(ranged.result.bytesBase64, 'base64').equals(bytes.subarray(3)), 'OBSERVER_STORAGE_RANGE_MISMATCH');

    const worker = await inspectService('execution-worker'); workerId = worker.Id;
    requireThat(worker.State?.Running === true, 'OBSERVER_WORKER_NOT_RUNNING');
    await docker(['stop', '-t', '20', workerId], { timeout: 45_000 }); workerStopped = true;
    requireThat((await inspectService('execution-worker')).State?.Running === false, 'OBSERVER_WORKER_NOT_STOPPED');
    const runBody = { projectId, operationId: attempt + '_run', runKind: 'entrypoint', targetProjectId: projectId, targetArtifactId: artifactId,
      targetArtifactRole: 'entrypoint', targetArtifactType: 'workflow.dag.v1', targetArtifactVersionId: source.result.sourceRef.artifactVersionId, targetOperation: 'invoke' };
    const admitted = await invoke('run-stopped', 'runs-create-py', owner, runBody, { envelope: false });
    const runId = identifier(admitted.runId);
    requireThat(canonical(admitted) === canonical(await invoke('run-replay', 'runs-create-py', owner, runBody, { envelope: false })), 'OBSERVER_RUN_REPLAY_DRIFT');
    const queued = await invoke('queued-status', 'runs-status-py', owner, { runId }, { envelope: false });
    requireThat(queued.status === 'queued', 'OBSERVER_RUN_NOT_QUEUED');
    assertRunReadback(await sqlRun(runId), { tenantId: c.tenantId, ownerId: c.ownerId, projectId, runId, queued: true });
    report.checks.push({ label: 'sql-durable-queue', status: 'PASS' });
    await docker(['start', workerId]); workerStopped = false;
    let status;
    for (let n = 0; n < 120; n++) {
      status = await invoke('run-status-' + n, 'runs-status-py', owner, { runId }, { envelope: false });
      if (['success', 'failed', 'cancelled', 'interrupted'].includes(status.status)) break;
      await pause(500);
    }
    requireThat(status.status === 'success', 'OBSERVER_RECOVERED_RUN_NOT_SUCCESS');
    const detail = await invoke('run-detail', 'runs-detail-py', owner, { runId }, { envelope: false });
    requireThat(detail.steps?.[0]?.valueFieldId, 'OBSERVER_RUN_VALUE_HANDLE_REQUIRED');
    const result = await invoke('run-value', 'runs-detail-py', owner, { handle: detail.steps[0].valueFieldId }, { envelope: false });
    requireThat(JSON.stringify(result).includes(value), 'OBSERVER_RESULT_MISMATCH');
    const sql = assertRunReadback(await sqlRun(runId), { tenantId: c.tenantId, ownerId: c.ownerId, projectId, runId, value, resultValue: result.value });
    report.checks.push({ label: 'sql-temporal-bound-result', status: 'PASS' });
    await invoke('guest-result-denied', 'runs-detail-py', outsider, { handle: detail.steps[0].valueFieldId }, { status: 403, code: 'forbidden', envelope: false });
    await invoke('missing-auth-denied', 'runs-status-py', x.operator, { runId }, { status: 401, code: 'AUTHENTICATION_REQUIRED', envelope: false });
    const snapshot = await invoke('snapshot', 'project-snapshots-py', owner,
      { action: 'create', projectId, name: 'Independent verifier snapshot', operationKey: attempt + '_snapshot_001' }, { envelope: false });
    const snapshotId = identifier(snapshot.snapshot.$id);
    const copied = await job('copy', operation(attempt + '_copy', 'projects.copy.v1', { sourceProjectId: projectId, snapshotId, name: 'Independent copy' }));
    requireThat(identifier(copied.result.projectId) !== projectId, 'OBSERVER_COPY_ID_REUSED');
    const current = await author('restore-revision', 'projects.read.v1', { projectId });
    const restored = await job('restore', operation(attempt + '_restore', 'projects.restore.v1', { projectId, snapshotId }, { revision: current.revision }));
    requireThat(restored.result.safetySnapshotId, 'OBSERVER_RESTORE_SAFETY_SNAPSHOT_REQUIRED');
    const afterRestore = await author('restored-source', 'artifacts.read.v1', { projectId, artifactId, alias: 'stable' });
    requireThat(afterRestore.result.bytesBase64 === source.result.bytesBase64, 'OBSERVER_RESTORED_SOURCE_DRIFT');
    const restoredInventory = await author('restored-artifacts', 'artifacts.list.v1', { projectId });
    const restoredResource = resolveRestoredResource(restoredInventory.result, { projectId, rootId, name: 'observer.txt', bytes });
    const restoredBytes = await author('restored-resource', 'artifacts.read-range.v1', { projectId, ...restoredResource,
      byteOffset: 0, byteSize: bytes.length });
    requireThat(Buffer.from(restoredBytes.result.bytesBase64, 'base64').equals(bytes), 'OBSERVER_RESTORED_STORAGE_DRIFT');
    const code = await invoke('mcp-code', 'mcp-gateway-py', owner, { action: 'create_auth_code', payload: { clientName: 'Independent verifier',
      scopes: ['projects:read', 'projects:write', 'files:read', 'runs:create', 'runs:read'] } }, { envelope: false });
    const session = await invoke('mcp-exchange', 'mcp-gateway-py', x.anonymous,
      { action: 'exchange_auth_code', payload: { authorizationCode: code.authorizationCode } }, { envelope: false });
    const token = session.sessionToken;
    await invoke('mcp-project', 'mcp-gateway-py', x.anonymous, { action: 'describe_project', payload: { projectId }, mcpSessionToken: token }, { envelope: false });
    const mcpRun = await invoke('mcp-run', 'mcp-gateway-py', x.anonymous, { action: 'run_project', payload: { projectId },
      operationId: attempt + '_mcp_run', mcpSessionToken: token }, { envelope: false });
    identifier(mcpRun.run?.runId);
    Object.assign(report.bindings, { projectId, artifactId, runId, snapshotId, copyProjectId: copied.result.projectId, mcpRunId: mcpRun.run.runId, sql });
    report.status = 'PASS';
  } catch (error) {
    failed = error; report.status = 'FAIL';
    report.firstFailure = { code: /^OBSERVER_[A-Z0-9_]+$/.test(error.message) ? error.message : 'OBSERVER_JOURNEY_FAILED' };
  } finally {
    const failures = [];
    if (workerStopped) try { await docker(['start', workerId]); } catch { failures.push('worker-restart'); }
    try { await x.close(); } catch { failures.push('session-close'); }
    if (guestCreated) try { await x.operator('DELETE', '/users/' + guestId); } catch { failures.push('guest-delete'); }
    report.observerCleanup = { status: failures.length ? 'FAIL' : 'PASS', failures };
    if (failures.length) report.status = 'FAIL';
    if (output) {
      await fs.mkdir(output, { recursive: true });
      await fs.writeFile(path.join(output, 'product-observer.json'), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    }
  }
  // Failure is a structured observation. Driver still owns all installation cleanup.
  if (failed) report.failureObserved = true;
  return report;
}
