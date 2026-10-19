import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { canonical, digest, resolveTrustedPath, verifyPin } from './bundle.mjs';
import { portableGitEnvironment, snapshotSource } from '../../portable/source.mjs';
import { executeCommand } from '../../portable/process.mjs';
import { assertRunReadback, observePortableProduct } from './product-observer.mjs';
import { connect } from './product-client.mjs';
import { ROOT, init, load, up, docker, dc, read, write, save, inventory, engine, redact } from '../../../infra/portable/operator.mjs';
import { installFunctions, configureWorker } from '../../../infra/portable/product.mjs';
import { provisionClean } from '../../../infra/portable/clean-provision.mjs';
import { configureOfflinePackaging } from './native-functions.mjs';
import { buildTrustedWorker, buildTrustedWeb } from './product-build.mjs';
import { observeProductBrowser } from './product-browser.mjs';
import { allocateFixtureNetworks } from './network-allocation.mjs';
import { SENTINEL_IMAGE, SENTINEL_OWNER, assertOwnedRemovalTarget, assertSentinel, createSentinel, exactContainerAbsent, minimalContainerInventory, observeForeignDrift, releaseSentinel } from '../../adapters/portable/sentinel.mjs';

const execute = promisify(execFile);
const OWNER = 'io.appwritework.portable';
const ownedToolProjections = new Map();
function requireThat(value, code) { if (!value) throw new Error(code); }
export function publicFailureCode(error) {
  // Native JSON parsers may quote untrusted payload bytes in error messages.
  // Public evidence carries symbolic operator failures, never those excerpts.
  return /^(?:INDEPENDENT|OBSERVER|BROWSER|PRODUCT|M1|M5|PORTABLE|SENTINEL)_[A-Z0-9_]{1,100}$/u.test(error?.message ?? '')
    ? error.message : 'INDEPENDENT_PRODUCT_OPERATOR_FAILED';
}
const safeId = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
const words = (value) => value.split(/\s+/u).filter(Boolean);
export function uninitializedCleanupVerdict({ sentinelAttempted, sentinel }) {
  return sentinelAttempted && !sentinel
    ? { status: 'FAIL', reason: 'SENTINEL_CREATE_UNCONFIRMED', recovery: 'Exact run-label intent retained privately; no installation was initialized' }
    : { status: 'PASS', detail: 'No installation initialized' };
}
export async function retainPrivateDiagnostic({ error, stage, output, redactor }) {
  const directory = path.join(output, 'private-diagnostics'); await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  let details;
  try { details = String(await redactor(String(error.stack ?? error.message ?? error))).slice(0, 64 * 1024); }
  catch { details = 'Protected diagnostic redaction unavailable; raw failure omitted'; }
  await fs.writeFile(path.join(directory, 'operator-error.json'), JSON.stringify({ stage, code: publicFailureCode(error), details, policy: 'PRIVATE_REDACTED_LOCAL_ONLY_NEVER_PUBLISH' }) + '\n', { flag: 'wx', mode: 0o600 });
  return { retained: true, path: 'private-diagnostics/operator-error.json', policy: 'PRIVATE_REDACTED_LOCAL_ONLY_NEVER_PUBLISH' };
}
export async function retainProjectedToolObservation({ output, script, observed, container, redactor }) {
  requireThat(['migrate.py', 'clean_bootstrap.py'].includes(script), 'INDEPENDENT_TOOL_NOT_ALLOWED');
  const directory = path.join(output, 'private-diagnostics'); await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stdout = typeof observed.stdout === 'string' ? observed.stdout : '', stderr = typeof observed.stderr === 'string' ? observed.stderr : '';
  const inputBytes = Buffer.byteLength(stdout) + Buffer.byteLength(stderr);
  let details, truncated = false;
  try {
    if (inputBytes > 1024 * 1024) { details = 'Tool output exceeded protected diagnostic input limit; raw output omitted'; truncated = true; }
    else {
      const redacted = await redactor(stdout + '\n' + stderr);
      requireThat(typeof redacted === 'string', 'INDEPENDENT_DIAGNOSTIC_REDACTION_INVALID');
      const bytes = Buffer.from(redacted); truncated = bytes.length > 64 * 1024;
      details = bytes.subarray(0, 64 * 1024).toString('utf8');
      while (Buffer.byteLength(details) > 64 * 1024) details = details.slice(0, -1);
    }
  } catch { details = 'Protected tool diagnostic redaction unavailable; raw output omitted'; }
  const filename = 'tool-' + script.replace('.py', '.json');
  const record = { script, exitCode: Number.isInteger(observed.exitCode) ? observed.exitCode : null,
    containerExitCode: Number.isInteger(container?.State?.ExitCode) ? container.State.ExitCode : null,
    timedOut: observed.timedOut === true, interrupted: observed.interrupted === true, spawnFailed: Boolean(observed.spawnError),
    signal: /^SIG[A-Z0-9]+$/u.test(observed.signal ?? '') ? observed.signal : null, outputTruncated: truncated,
    details, policy: 'PRIVATE_REDACTED_LOCAL_ONLY_NEVER_PUBLISH' };
  await fs.writeFile(path.join(directory, filename), JSON.stringify(record) + '\n', { flag: 'wx', mode: 0o600 });
  return { retained: true, path: 'private-diagnostics/' + filename, policy: record.policy, outputTruncated: truncated };
}
export function readCandidateFile(root, entry, maximum = 32 * 1024 * 1024) {
  requireThat(Number.isSafeInteger(maximum) && maximum > 0 && maximum <= 32 * 1024 * 1024, 'INDEPENDENT_PRODUCT_READ_LIMIT_INVALID');
  let filename = realpathSync(root);
  requireThat(typeof entry.path === 'string' && !path.isAbsolute(entry.path) && !entry.path.includes('\\') && !entry.path.split('/').some(part => !part || part === '.' || part === '..'), 'INDEPENDENT_PRODUCT_SOURCE_PATH_INVALID');
  for (const part of entry.path.split('/')) {
    filename = path.join(filename, part); const info = lstatSync(filename);
    requireThat(!info.isSymbolicLink() && realpathSync(filename).toLowerCase() === filename.toLowerCase(), 'INDEPENDENT_PRODUCT_SOURCE_LINK');
  }
  const before = lstatSync(filename);
  requireThat(before.isFile() && before.size <= maximum, 'INDEPENDENT_PRODUCT_SOURCE_SIZE_LIMIT');
  const fd = openSync(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd);
    requireThat(opened.ino === before.ino && opened.dev === before.dev && opened.size === before.size && opened.mtimeMs === before.mtimeMs && opened.ctimeMs === before.ctimeMs, 'INDEPENDENT_PRODUCT_SOURCE_CHANGED');
    const bytes = Buffer.alloc(before.size + 1); let length = 0;
    while (length < bytes.length) { const count = readSync(fd, bytes, length, Math.min(64 * 1024, bytes.length - length), null); if (!count) break; length += count; }
    const after = fstatSync(fd);
    requireThat(length === before.size && after.size === opened.size && after.mtimeMs === opened.mtimeMs && after.ctimeMs === opened.ctimeMs, 'INDEPENDENT_PRODUCT_SOURCE_CHANGED');
    const result = bytes.subarray(0, length); requireThat(digest(result) === entry.digest, 'INDEPENDENT_PRODUCT_SOURCE_CHANGED'); return result;
  } finally { closeSync(fd); }
}
function mountPath(value) {
  const slash = String(value).replaceAll('\\', '/');
  const desktop = slash.match(/^\/(?:run\/desktop\/mnt\/host|host_mnt)\/([A-Za-z])(?:\/|$)(.*)$/u);
  if (desktop) return (desktop[1] + ':/' + desktop[2]).replace(/\/$/u, '').toLowerCase();
  if (/^[A-Za-z]:\//u.test(slash)) return slash.replace(/\/$/u, '').toLowerCase();
  return path.resolve(value).replaceAll('\\', '/').replace(/\/$/u, '').toLowerCase();
}

export async function freezeProductSource(candidateRoot, destination) {
  const before = snapshotSource(candidateRoot);
  await fs.mkdir(destination, { mode: 0o700 });
  let copiedBytes = 0;
  for (const entry of before.files) {
    if (entry.kind === 'deleted') continue;
    requireThat(entry.kind === 'file', 'INDEPENDENT_PRODUCT_SOURCE_NOT_REGULAR');
    const bytes = readCandidateFile(candidateRoot, entry);
    copiedBytes += bytes.length; requireThat(copiedBytes <= 512 * 1024 * 1024, 'INDEPENDENT_PRODUCT_SOURCE_TOTAL_LIMIT');
    const filename = path.join(destination, entry.path);
    await fs.mkdir(path.dirname(filename), { recursive: true }); await fs.writeFile(filename, bytes, { flag: 'wx' });
  }
  requireThat(snapshotSource(candidateRoot).digest === before.digest, 'INDEPENDENT_PRODUCT_SOURCE_CHANGED');
  const git = (args) => execute('git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', '-C', destination, ...args], {
    windowsHide: true, env: portableGitEnvironment(), timeout: 120_000, maxBuffer: 2 * 1024 * 1024,
  });
  await git(['init', '--quiet', '--initial-branch=codex/verifier-input-snapshot']);
  // The core source reader later runs Git status without this command's -c
  // arguments. Keep long-path handling local to this newly owned fixture repo.
  await git(['config', '--local', 'core.longpaths', 'true']);
  await git(['add', '--force', '--all']);
  await git(['-c', 'commit.gpgsign=false', '-c', 'user.name=Independent verifier snapshot', '-c', 'user.email=verifier@portable.invalid', 'commit', '--quiet', '-m', 'Owned candidate product input snapshot']);
  const omittedDeletedEntries = before.files.filter(entry => entry.kind === 'deleted').length;
  return { originalHead: before.head, originalDigest: before.digest, snapshotCommit: (await git(['rev-parse', 'HEAD'])).stdout.trim(),
    files: before.files.length - omittedDeletedEntries, trackedEntries: before.files.length, omittedDeletedEntries, sourceBytes: before.sourceBytes };
}

export function validateToolMounts(row, { project, bundleRoot, projectedState }) {
  requireThat(row.Config?.Labels?.[OWNER] === project && row.HostConfig?.ReadonlyRootfs === true && row.HostConfig?.Privileged !== true
    && row.HostConfig?.CapDrop?.includes('ALL') && row.Config?.User === '1000:1000', 'INDEPENDENT_TOOL_BOUNDARY_INVALID');
  const expected = new Map([['/source', mountPath(bundleRoot)], ['/run/portable', mountPath(projectedState)]]);
  const binds = row.Mounts.filter((mount) => mount.Type === 'bind');
  requireThat(binds.length === 2 && binds.every((mount) => expected.get(mount.Destination) === mountPath(mount.Source) && mount.RW === false)
    && row.Mounts.every((mount) => ['bind', 'tmpfs'].includes(mount.Type)), 'INDEPENDENT_TOOL_MOUNT_INVALID');
}

export function projectedToolArguments(script, args, { diagnosticTraceback = false } = {}) {
  requireThat(['migrate.py', 'clean_bootstrap.py'].includes(script) && Array.isArray(args), 'INDEPENDENT_TOOL_NOT_ALLOWED');
  if (diagnosticTraceback) {
    requireThat(script === 'migrate.py' && args.length === 0, 'INDEPENDENT_TOOL_DIAGNOSTIC_NOT_ALLOWED');
    return ['-B', '-c', "import runpy; runpy.run_path('/source/infra/portable/migrate.py', run_name='trusted_migration_diagnostic')['main']()"];
  }
  return ['-B', '/source/infra/portable/' + script, ...args];
}
function readProjectedInput(filename, maximum) {
  const resolved = resolveTrustedPath(filename), before = lstatSync(resolved);
  requireThat(before.isFile() && before.size > 0 && before.size <= maximum, 'INDEPENDENT_TOOL_INPUT_INVALID');
  const fd = openSync(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(fd);
    requireThat(opened.ino === before.ino && opened.dev === before.dev && opened.size === before.size
      && opened.mtimeMs === before.mtimeMs && opened.ctimeMs === before.ctimeMs, 'INDEPENDENT_TOOL_INPUT_CHANGED');
    const bytes = Buffer.alloc(before.size + 1); let length = 0;
    while (length < bytes.length) { const count = readSync(fd, bytes, length, bytes.length - length, null); if (!count) break; length += count; }
    const after = fstatSync(fd);
    requireThat(length === before.size && after.size === opened.size && after.mtimeMs === opened.mtimeMs
      && after.ctimeMs === opened.ctimeMs, 'INDEPENDENT_TOOL_INPUT_CHANGED');
    return bytes.subarray(0, length);
  } finally { closeSync(fd); }
}
export async function createProjectedToolState(s, privateRoot) {
  privateRoot = resolveTrustedPath(privateRoot);
  const parent = lstatSync(privateRoot), relative = path.relative(privateRoot, resolveTrustedPath(s.dir));
  requireThat(parent.isDirectory() && (process.platform === 'win32' || (parent.mode & 0o077) === 0)
    && relative && !path.isAbsolute(relative) && relative !== '..' && !relative.startsWith('..' + path.sep), 'INDEPENDENT_TOOL_PRIVATE_PARENT_REQUIRED');
  const c = JSON.parse(readProjectedInput(path.join(s.dir, 'private/appwrite.private.json'), 64 * 1024));
  const projected = path.join(privateRoot, 'tool-' + randomBytes(6).toString('hex'));
  await fs.mkdir(projected, { mode: 0o700 });
  for (const name of ['private', 'secrets']) await fs.mkdir(path.join(projected, name), { mode: 0o700 });
  const ownedDirectories = ['', 'private', 'secrets'].map(name => {
    const filename = path.join(projected, name), stat = lstatSync(filename);
    return { filename, dev: stat.dev, ino: stat.ino };
  });
  const records = ownedToolProjections.get(privateRoot) ?? []; records.push({ projected, directories: ownedDirectories });
  ownedToolProjections.set(privateRoot, records);
  const files = {
    'profile.json': Buffer.from(canonical({ deploymentBinding: s.deploymentBinding })),
    'private/appwrite.private.json': Buffer.from(canonical({ cleanBinding: c.cleanBinding, tenantId: c.tenantId, ownerId: c.ownerId })),
  };
  for (const file of ['ca.crt', 'app-postgres.password', 'app-migrator.password', 'app-runtime.password']) {
    files['secrets/' + file] = readProjectedInput(path.join(s.dir, 'secrets', file), file === 'ca.crt' ? 32 * 1024 : 1024);
  }
  // Materialize fresh bytes: copying a Linux-created 0600 CA on Docker Desktop
  // preserves root-only metadata. Only this minimal read-only projection is
  // readable by the tool UID; its enclosing host-private directory stays 0700.
  for (const [name, bytes] of Object.entries(files)) await fs.writeFile(path.join(projected, name), bytes, { flag: 'wx', mode: 0o444 });
  for (const name of Object.keys(files)) await fs.chmod(path.join(projected, name), 0o444);
  for (const name of ['private', 'secrets', '']) await fs.chmod(path.join(projected, name), 0o555);
  return projected;
}
export async function restoreProjectedDirectoryModes(privateRoot) {
  privateRoot = resolveTrustedPath(privateRoot);
  for (const record of ownedToolProjections.get(privateRoot) ?? []) {
    const projected = resolveTrustedPath(record.projected);
    requireThat(path.dirname(projected) === privateRoot, 'INDEPENDENT_TOOL_PROJECTION_DIRECTORY_INVALID');
    // Called only after owned containers have gone. Restore host traversal and
    // deletion rights for these generated directories, never the source state.
    for (const owned of record.directories) {
      const directory = resolveTrustedPath(owned.filename), stat = lstatSync(directory);
      requireThat(stat.isDirectory() && stat.dev === owned.dev && stat.ino === owned.ino, 'INDEPENDENT_TOOL_PROJECTION_DIRECTORY_INVALID');
      await fs.chmod(directory, 0o700);
    }
  }
}
export async function runProjectedTool(s, script, args, privateRoot, diagnostics = {}) {
  requireThat(['migrate.py', 'clean_bootstrap.py'].includes(script), 'INDEPENDENT_TOOL_NOT_ALLOWED');
  const toolArguments = projectedToolArguments(script, args, diagnostics);
  const projected = await createProjectedToolState(s, privateRoot);
  // No executor/jobs secret, operator API key, profile mutation path or trusted
  // report is visible to candidate worker code. All mounts are read-only.
  const name = s.project + '-trusted-tool-' + randomBytes(5).toString('hex');
  let created = false;
  try {
    await docker(s, ['create', '--name', name, '--label', `${OWNER}=${s.project}`, '--network', `${s.project}_private`, '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--pids-limit', '128', '--memory', '512m', '--tmpfs', '/tmp:rw,nosuid,nodev,uid=1000,gid=1000,size=67108864',
      '--mount', `type=bind,source=${ROOT},target=/source,readonly`, '--mount', `type=bind,source=${projected},target=/run/portable,readonly`,
      '--entrypoint', 'python', s.workerImage, ...toolArguments]);
    created = true;
    const row = JSON.parse(await docker(s, ['inspect', name]))[0];
    validateToolMounts(row, { project: s.project, bundleRoot: ROOT, projectedState: projected });
    const observed = await executeCommand({ executable: 'docker', args: ['--context', s.context, 'start', '--attach', name], cwd: privateRoot, env: portableGitEnvironment() }, { timeoutMs: 180_000 });
    let stopped;
    try { stopped = JSON.parse(await docker(s, ['inspect', name]))[0]; }
    catch (error) {
      await retainProjectedToolObservation({ output: path.dirname(privateRoot), script, observed, container: null, redactor: message => redact(s, message) });
      throw error;
    }
    await retainProjectedToolObservation({ output: path.dirname(privateRoot), script, observed, container: stopped, redactor: message => redact(s, message) });
    requireThat(!observed.timedOut && !observed.interrupted && !observed.spawnError && stopped.State.ExitCode === 0 && !stopped.State.Running, 'INDEPENDENT_TOOL_FAILED');
    // Tool stdout is useful diagnostics only. Independent API/SQL observations
    // below determine acceptance; candidate worker output is never a certificate.
    return { projectedState: projected };
  } finally {
    if (created) {
      const row = JSON.parse(await docker(s, ['inspect', name]))[0];
      requireThat(row.Config?.Labels?.[OWNER] === s.project, 'INDEPENDENT_TOOL_CLEANUP_OWNER');
      await docker(s, ['rm', '--force', row.Id]);
    }
  }
}

export function validateObserverAction(args, ownedRows) {
  requireThat(Array.isArray(args) && args.every((value) => typeof value === 'string'), 'INDEPENDENT_OBSERVER_ARGV_INVALID');
  if (args[0] === 'ps') {
    const project = ownedRows[0]?.Config?.Labels?.[OWNER];
    requireThat(args.length === 7 && canonical(args.slice(0, 5)) === canonical(['ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + project])
      && args[5] === '--filter' && /^label=com\.docker\.compose\.service=(?:execution-worker|app-postgres)$/u.test(args[6]), 'INDEPENDENT_OBSERVER_ARGV_INVALID');
    return;
  }
  const target = args[0] === 'stop' && args[1] === '-t' && args[2] === '20' && args.length === 4 ? args[3] : args[1];
  const row = ownedRows.find((entry) => entry.Id === target);
  requireThat(row && safeId(target), 'INDEPENDENT_OBSERVER_TARGET_NOT_OWNED');
  if (args[0] === 'inspect') { requireThat(args.length === 2, 'INDEPENDENT_OBSERVER_ARGV_INVALID'); return; }
  const service = row.Config.Labels['com.docker.compose.service'];
  if (args[0] === 'stop' || args[0] === 'start') requireThat(service === 'execution-worker' && (args.length === 2 || args[0] === 'stop' && args.length === 4 && args[1] === '-t' && args[2] === '20'), 'INDEPENDENT_OBSERVER_MUTATION_FORBIDDEN');
  else requireThat(args[0] === 'exec' && service === 'app-postgres' && args.length === 12 && canonical(args.slice(2, 11)) === canonical(['psql', '-U', 'salmora_operator', '-d', 'salmora', '-XAt', '-v', 'ON_ERROR_STOP=1', '-c'])
    && /^SELECT\b/u.test(args[11]) && !args.some((value) => /(?:^|\s)(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|COPY|TRUNCATE)(?:\s|$)/iu.test(value)), 'INDEPENDENT_OBSERVER_SQL_NOT_READONLY');
}

export function assertTemporalDescription(value, binding) {
  const info = value?.workflowExecutionInfo;
  requireThat(info?.execution?.workflowId === binding.workflowId && info.execution.runId === binding.firstExecutionRef
    && info.type?.name === 'SalmoraDagWorkflowV1' && ['WORKFLOW_EXECUTION_STATUS_COMPLETED', 'COMPLETED'].includes(info.status)
    && Number(info.historyLength) >= 3, 'INDEPENDENT_TEMPORAL_READBACK_MISMATCH');
  return { workflowId: info.execution.workflowId, runId: info.execution.runId, workflowType: info.type.name, status: info.status, historyEvents: Number(info.historyLength) };
}

function decodePayload(payload) {
  requireThat(typeof payload?.data === 'string' && payload.data.length <= 128 * 1024 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(payload.data), 'INDEPENDENT_TEMPORAL_PAYLOAD_INVALID');
  return JSON.parse(Buffer.from(payload.data, 'base64').toString('utf8'));
}
export function assertTemporalHistory(value, binding) {
  const events = value?.events;
  requireThat(Array.isArray(events) && events.length >= 3 && events.length <= 10_000
    && events.every((event, index) => Number(event.eventId) === index + 1), 'INDEPENDENT_TEMPORAL_HISTORY_INVALID');
  const first = events[0]?.workflowExecutionStartedEventAttributes;
  const last = events.at(-1)?.workflowExecutionCompletedEventAttributes;
  requireThat(first?.workflowType?.name === 'SalmoraDagWorkflowV1' && first.input?.payloads?.length === 1 && last?.result?.payloads?.length === 1, 'INDEPENDENT_TEMPORAL_HISTORY_NOT_COMPLETED');
  const input = decodePayload(first.input.payloads[0]), result = decodePayload(last.result.payloads[0]);
  requireThat(input.tenant_id === binding.tenantId && input.run_id === binding.runId && input.workflow_id === binding.workflowId
    && input.engine_id === 'temporal' && input.engine_attempt_ref === binding.engineAttemptRef, 'INDEPENDENT_TEMPORAL_INPUT_BINDING');
  requireThat(result.run_id === binding.runId && result.state === 'succeeded' && result.result_digest === binding.terminalResultDigest, 'INDEPENDENT_TEMPORAL_RESULT_BINDING');
  return { historyEvents: events.length, inputDigest: digest(canonical(input)), completionDigest: digest(canonical(result)), runId: result.run_id, terminalResultDigest: result.result_digest };
}

async function observeTemporal(s, binding) {
  const pins = await read(path.join(s.dir, 'images.lock.json'));
  requireThat(typeof binding?.workflowId === 'string' && binding.workflowId.length <= 512 && typeof binding?.firstExecutionRef === 'string' && /^[a-f0-9-]{36}$/u.test(binding.firstExecutionRef), 'INDEPENDENT_TEMPORAL_BINDING_REQUIRED');
  const observe = async operation => {
    const name = s.project + '-trusted-temporal-' + randomBytes(4).toString('hex');
    const raw = await docker(s, ['run', '--rm', '--name', name, '--label', `${OWNER}=${s.project}`, '--network', s.project + '_private', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16777216',
      '--entrypoint', 'temporal', pins.admin.reference, '--disable-config-file', '--disable-config-env', '--address', 'temporal:7233', '--namespace', 'salmora', '--command-timeout', '30s', '--output', 'json', '--no-json-shorthand-payloads', 'workflow', ...operation, '--workflow-id', binding.workflowId, '--run-id', binding.firstExecutionRef], { timeout: 45_000 });
    requireThat(Buffer.byteLength(raw) <= 1024 * 1024, 'INDEPENDENT_TEMPORAL_RESPONSE_LIMIT'); return JSON.parse(raw);
  };
  return { description: assertTemporalDescription(await observe(['describe', '--raw']), binding), history: assertTemporalHistory(await observe(['show']), binding) };
}

async function observeBrowserRun(s, credentials, browser, ownedRows) {
  const runId = browser.observation.runId;
  requireThat(/^[A-Za-z0-9_-]{1,128}$/u.test(runId), 'INDEPENDENT_BROWSER_RUN_ID_INVALID');
  const pg = ownedRows.find(row => row.Config.Labels['com.docker.compose.service'] === 'app-postgres');
  const query = "SELECT row_to_json(r) FROM (SELECT e.*, c.first_execution_ref, c.terminal_proof, c.terminal_result,"
    + " (SELECT receipt->'output_ref' FROM salmora_app.execution_runtime_steps st WHERE st.tenant_id=e.tenant_id AND st.run_id=e.run_id AND st.node_id='start') AS step_output_ref"
    + " FROM salmora_app.execution_runs e LEFT JOIN salmora_app.execution_runtime_control c USING (tenant_id,run_id) WHERE e.tenant_id='" + credentials.tenantId + "' AND e.run_id='" + runId + "') r";
  const argv = ['exec', pg.Id, 'psql', '-U', 'salmora_operator', '-d', 'salmora', '-XAt', '-v', 'ON_ERROR_STOP=1', '-c', query];
  validateObserverAction(argv, ownedRows);
  const row = JSON.parse(await docker(s, argv));
  const client = connect({ state: s, credentials, ca: await fs.readFile(path.join(s.dir, 'secrets/ca.crt')), checks: [] });
  try {
    const owner = await client.login(credentials.ownerId, { email: credentials.owner.email, password: credentials.owner.password });
    const detail = await client.invoke('browser-detail', 'runs-detail-py', owner, { runId }, { envelope: false });
    requireThat(detail.steps?.[0]?.valueFieldId, 'INDEPENDENT_BROWSER_VALUE_HANDLE_REQUIRED');
    const value = await client.invoke('browser-value', 'runs-detail-py', owner, { handle: detail.steps[0].valueFieldId }, { envelope: false });
    const binding = assertRunReadback(row, { tenantId: credentials.tenantId, ownerId: credentials.ownerId, projectId: browser.observation.projectId, runId,
      value: browser.expectedValue, resultValue: value.value });
    return { sql: binding, temporal: await observeTemporal(s, { ...binding, tenantId: credentials.tenantId }) };
  } finally { await client.close(); }
}

export function isCleanupContainerCandidate(summary, { project, executor, projectId }) {
  return summary.Names.startsWith(project + '-') || summary.Names.startsWith(executor + '-')
    || summary.Names === executor || Boolean(projectId && summary.Names.startsWith('job-' + projectId + '-'));
}

export function ownsComposeCleanupContainer(row, { project, executor }) {
  const labels = row.Config.Labels ?? {};
  return labels[OWNER] === project && (row.Name !== '/' + executor
    || labels['com.docker.compose.project'] === project && labels['com.docker.compose.service'] === 'executor');
}

export function assertNoCleanupCandidates(rows, context) {
  requireThat(!rows.some(row => isCleanupContainerCandidate(row, context)), 'INDEPENDENT_CLEANUP_CONTAINER_RESIDUE');
}

export async function removeValidatedContainers({ docker: runDocker, ownedIds, sentinelId }) {
  requireThat(new Set(ownedIds).size === ownedIds.length, 'INDEPENDENT_CLEANUP_DUPLICATE_ID');
  for (const id of ownedIds) assertOwnedRemovalTarget(id, ownedIds, sentinelId);
  const receipt = { status: 'PASS', removedIds: [], alreadyAbsentIds: [], failures: [] };
  let firstError;
  for (const id of ownedIds) {
    try { await runDocker(['rm', '--force', id]); receipt.removedIds.push(id); }
    catch (error) {
      let absent = false, proof = 'PRESENT';
      try { absent = await exactContainerAbsent({ docker: runDocker, id, ownedIds, sentinelId }); }
      catch { proof = 'UNCONFIRMED'; }
      if (absent) { receipt.alreadyAbsentIds.push(id); continue; }
      firstError ??= error;
      receipt.status = 'FAIL'; receipt.failures.push({ id, firstFailureCode: publicFailureCode(error), absence: proof });
    }
  }
  Object.defineProperty(receipt, 'firstError', { value: firstError, enumerable: false });
  return receipt;
}

export async function cleanupFixture(s, before, output, sentinel) {
  const optional = filename => read(filename).catch(error => { if (error.code === 'ENOENT') return {}; throw error; });
  const c = await optional(path.join(s.dir, 'private/appwrite.private.json'));
  const secrets = await optional(path.join(s.dir, 'private/secrets.private.json'));
  const pins = await read(path.join(s.dir, 'images.lock.json'));
  const executor = 'r0e-' + digest(Buffer.from(s.project)).slice(7, 17);
  const callDocker = args => docker(s, args);
  await assertSentinel({ docker: callDocker, record: sentinel });
  const rows = await minimalContainerInventory(callDocker);
  const beforeIds = before.map(row => row.ID);
  const selected = [];
  for (const summary of rows) {
    if (!isCleanupContainerCandidate(summary, { project: s.project, executor, projectId: c.projectId })) continue;
    const row = JSON.parse(await docker(s, ['inspect', summary.ID]))[0];
    requireThat(!beforeIds.includes(row.Id) && Date.parse(row.Created) >= Date.parse(s.createdAt), 'INDEPENDENT_CLEANUP_FOREIGN_RESOURCE');
    const labels = row.Config.Labels ?? {};
    const composeOwned = ownsComposeCleanupContainer(row, { project: s.project, executor });
    const childOwned = labels['openruntimes-executor'] === executor && row.Name.startsWith('/' + executor + '-');
    let buildOwned = false;
    if (c.projectId && labels['managed-by'] === 'jobs-service') {
      const type = labels['job.type'];
      if (type === 'worker') {
        const meta = JSON.parse(labels['job.meta'] ?? '{}');
        const receipts = { ...s.product?.functions, ...s.product?.pendingFunctions };
        buildOwned = typeof secrets.R0_JOBS_SECRET === 'string' && secrets.R0_JOBS_SECRET.length >= 16
          && meta.projectId === c.projectId && meta.resourceType === 'functions' && receipts[meta.resourceId]?.deploymentId === meta.deploymentId && labels['job.callback.key'] === secrets.R0_JOBS_SECRET;
      } else if (type === 'sidecar') buildOwned = Object.values({ ...s.product?.functions, ...s.product?.pendingFunctions }).some((receipt) => {
        const stem = `job-${c.projectId}-${receipt.deploymentId}-build`;
        return row.Name === `/${stem}-sidecar` && row.Config.Image === pins.jobSidecar.reference && labels['job.id'] === stem.slice(4)
          && row.Mounts.length === 1 && row.Mounts[0].Type === 'volume' && row.Mounts[0].Name === stem + '-workspace';
      });
    }
    requireThat(composeOwned || childOwned || buildOwned, 'INDEPENDENT_CLEANUP_OWNER_MISMATCH'); selected.push(row);
  }
  const ownedIds = selected.map(row => row.Id);
  const removals = await removeValidatedContainers({ docker: callDocker, ownedIds, sentinelId: sentinel.id });
  await write(path.join(output, 'product-cleanup-containers.json'), removals);
  if (removals.status !== 'PASS') {
    await retainPrivateDiagnostic({ error: removals.firstError, stage: 'cleanup-containers', output: path.join(output, 'cleanup-diagnostics'), redactor: message => redact(s, message) });
    requireThat(false, 'INDEPENDENT_CLEANUP_CONTAINER_REMOVAL_FAILED');
  }
  const knownJobs = Object.values({ ...s.product?.functions, ...s.product?.pendingFunctions }).map((receipt) => `job-${c.projectId}-${receipt.deploymentId}-build-workspace`);
  for (const name of words(await docker(s, ['volume', 'ls', '--format', '{{.Name}}']))) {
    if (!name.startsWith(s.project + '-') && !knownJobs.includes(name)) continue;
    const volume = JSON.parse(await docker(s, ['volume', 'inspect', name]))[0];
    requireThat(volume.Labels?.[OWNER] === s.project || knownJobs.includes(name) && Date.parse(volume.CreatedAt) >= Date.parse(s.createdAt), 'INDEPENDENT_CLEANUP_VOLUME_OWNER');
    requireThat(!(await docker(s, ['ps', '-aq', '--filter', `volume=${name}`])), 'INDEPENDENT_CLEANUP_VOLUME_BUSY');
    await docker(s, ['volume', 'rm', name]);
  }
  for (const name of words(await docker(s, ['network', 'ls', '--filter', `label=${OWNER}=${s.project}`, '--format', '{{.Name}}']))) {
    const network = JSON.parse(await docker(s, ['network', 'inspect', name]))[0];
    requireThat(network.Labels?.[OWNER] === s.project, 'INDEPENDENT_CLEANUP_NETWORK_OWNER'); await docker(s, ['network', 'rm', network.Id]);
  }
  const after = await minimalContainerInventory(callDocker);
  const sentinelSurvival = await assertSentinel({ docker: callDocker, record: sentinel });
  assertNoCleanupCandidates(after, { project: s.project, executor, projectId: c.projectId });
  requireThat(!(await docker(s, ['ps', '-aq', '--filter', `label=${OWNER}=${s.project}`])), 'INDEPENDENT_CLEANUP_CONTAINER_RESIDUE');
  const removedImages = [];
  for (const tag of words(await docker(s, ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}']))) {
    if (!['salmora-portable-worker:', 'salmora-portable-web:', 'salmora-verifier-deps:'].some(prefix => tag.startsWith(prefix + s.project + '-'))) continue;
    // Remove only an unguessable per-attempt tag, never force-delete shared image
    // IDs or prune the daemon's dependency/build caches.
    await docker(s, ['image', 'rm', tag]); removedImages.push(tag);
  }
  const result = { status: 'PASS', containersRemoved: removals.removedIds.length, alreadyAbsentContainerIds: removals.alreadyAbsentIds, sentinel: sentinelSurvival,
    foreignInventoryDrift: observeForeignDrift(before, after, [sentinel.id]), ownedImageTagsRemoved: removedImages,
    coverage: ['owned containers', 'owned volumes', 'owned networks', 'per-attempt worker/web/dependency image tags'], sharedBuildCaches: 'retained; not pruned' };
  await write(path.join(output, 'product-cleanup.json'), result); return result;
}

export async function runTrustedProductAudit({ candidateRoot, bundleRoot, pin, output, python = 'python' }) {
  const checked = verifyPin({ bundleRoot, pin, candidateRoot });
  requireThat(await fs.realpath(ROOT) === checked.bundleRoot, 'INDEPENDENT_PRODUCT_OPERATOR_NOT_PINNED');
  const outputRoot = resolveTrustedPath(output, [candidateRoot, bundleRoot]);
  await fs.mkdir(outputRoot, { mode: 0o700 });
  const privateRoot = path.join(outputRoot, 'private'); await fs.mkdir(privateRoot, { mode: 0o700 });
  const project = 'sm9-m10-clean-' + randomBytes(6).toString('hex');
  const stateDir = path.join(privateRoot, 'state');
  const result = { schemaVersion: 'trusted-portable-product.v1', status: 'IN_PROGRESS', independent: false, scope: 'portable-product', independentWholeRepositoryAcceptance: false,
    manifestDigest: checked.manifestDigest, project, cleanup: { status: 'NOT_RUN' }, releaseEligible: false };
  await write(path.join(outputRoot, 'product-result.json'), result);
  let s; let sentinel; let sentinelAttempted = false; let controllerDocker; let before = []; let stage = 'freeze-source';
  try {
    result.source = await freezeProductSource(candidateRoot, path.join(privateRoot, 'candidate'));
    const source = path.join(privateRoot, 'candidate');
    const binding = digest(canonical({ verifier: checked.manifestDigest, candidate: result.source.originalDigest, project })).slice(7);
    const context = process.platform === 'win32' ? 'desktop-linux' : 'default';
    const controller = { context, dir: privateRoot };
    controllerDocker = args => docker(controller, args);
    // Verify the named context is a local Linux engine before creating even
    // the task-owned foreign-relative sentinel.
    await engine(controller);
    stage = 'cleanup-sentinel';
    await write(path.join(privateRoot, 'cleanup-sentinel-intent.json'), { runId: project, context, label: SENTINEL_OWNER, image: SENTINEL_IMAGE });
    sentinelAttempted = true;
    sentinel = await createSentinel({ docker: controllerDocker, runId: project, onCreated: async record => {
      sentinel = record; await write(path.join(privateRoot, 'cleanup-sentinel.json'), record);
    } });
    before = await minimalContainerInventory(controllerDocker);
    stage = 'initialize';
    result.networkAllocation = await allocateFixtureNetworks({ docker: controllerDocker, seed: project });
    s = await init({ dir: stateDir, project, context, port: 0, networkSubnets: result.networkAllocation.networkSubnets, deploymentBinding: binding });
    stage = 'build-worker'; result.workerBuild = await buildTrustedWorker(s, source, privateRoot);
    // Candidate source is introduced only after the task networks are internal.
    // The public gateway alone bridges ingress and cannot act as a forward proxy.
    s.cloudBlocked = true; await save(s);
    stage = 'start-core'; await up(s);
    stage = 'migrate'; await runProjectedTool(s, 'migrate.py', [], privateRoot);
    stage = 'provision'; await provisionClean(s, { owner: { email: 'owner@portable.invalid', name: 'Independent portable fixture' } });
    stage = 'bootstrap'; await runProjectedTool(s, 'clean_bootstrap.py', ['bootstrap'], privateRoot);
    stage = 'functions'; configureOfflinePackaging({ sourceRoot: source, project: s.project, context: s.context, cacheRoot: path.join(privateRoot, 'function-wheels') });
    await installFunctions(s, { source, python, fixtureMode: false });
    stage = 'web'; result.webBuild = await buildTrustedWeb(s, source, privateRoot);
    stage = 'worker'; s = await load(stateDir); const credentials = await read(path.join(s.dir, 'private/appwrite.private.json'));
    await configureWorker(s, [credentials.tenantId]);
    stage = 'seal'; s = await load(stateDir);
    const network = JSON.parse(await docker(s, ['network', 'inspect', s.project + '-network']))[0];
    requireThat(network.Internal === true && network.Labels?.[OWNER] === s.project, 'INDEPENDENT_PRODUCT_NETWORK_NOT_INTERNAL');
    await dc(s, ['up', '-d', '--no-deps', '--pull', 'never', '--wait', '--wait-timeout', '90', 'execution-worker'], { timeout: 120_000 });
    stage = 'observe';
    const ownedRows = await inventory(s);
    const pins = await read(path.join(s.dir, 'images.lock.json'));
    const postgresId = await docker(s, ['image', 'inspect', pins['app-postgres'].reference, '--format', '{{.Id}}']);
    requireThat(ownedRows.find((row) => row.Config.Labels['com.docker.compose.service'] === 'app-postgres')?.Image === postgresId, 'INDEPENDENT_POSTGRES_IMAGE_NOT_PINNED');
    const scopedDocker = async (args, options) => { validateObserverAction(args, ownedRows); return docker(s, args, options); };
    result.observation = await observePortableProduct({ state: s, credentials, ca: await fs.readFile(path.join(s.dir, 'secrets/ca.crt')), docker: scopedDocker, output: outputRoot });
    requireThat(result.observation.status === 'PASS', 'INDEPENDENT_PRODUCT_ASSERTION_FAILED');
    stage = 'temporal'; result.temporal = await observeTemporal(s, { ...result.observation.bindings.sql, tenantId: credentials.tenantId });
    stage = 'browser'; result.browser = await observeProductBrowser({ state: s, credentials, bindings: result.observation.bindings, bundleRoot: ROOT, privateRoot, output: outputRoot,
      docker: (args, options) => docker(s, args, options) });
    requireThat(result.browser.status === 'PASS', result.browser.reason ?? 'INDEPENDENT_PRODUCT_BROWSER_FAILED');
    stage = 'browser-durable-result'; result.browserDurability = await observeBrowserRun(s, credentials, result.browser, ownedRows);
    verifyPin({ bundleRoot, pin, candidateRoot });
    requireThat(snapshotSource(candidateRoot).digest === result.source.originalDigest, 'INDEPENDENT_PRODUCT_SOURCE_CHANGED');
    result.status = 'PASS'; result.independent = true;
  } catch (error) {
    result.status = 'FAIL'; result.failedStage = stage; result.reason = publicFailureCode(error);
    try {
      const diagnosticState = s ?? await load(stateDir).catch(() => undefined);
      result.privateDiagnostics = await retainPrivateDiagnostic({ error, stage, output: outputRoot,
        redactor: message => diagnosticState ? redact(diagnosticState, message) : Promise.resolve('Operator failed before installation initialization; raw failure omitted') });
    } catch { result.privateDiagnostics = { retained: false, reason: 'INDEPENDENT_DIAGNOSTIC_WRITE_FAILED' }; }
  }
  finally {
    try {
      if (!s && await fs.stat(path.join(stateDir, 'profile.json')).then(() => true, () => false)) s = await load(stateDir);
      if (s) { s = await load(stateDir); result.cleanup = await cleanupFixture(s, before, outputRoot, sentinel); }
      else result.cleanup = uninitializedCleanupVerdict({ sentinelAttempted, sentinel });
    } catch (error) { result.cleanup = { status: 'FAIL', reason: publicFailureCode(error) }; result.status = 'FAIL'; }
    if (sentinel) {
      try { result.sentinelRelease = await releaseSentinel({ docker: controllerDocker, record: sentinel }); }
      catch (error) { result.sentinelRelease = { status: 'FAIL', reason: publicFailureCode(error) }; result.cleanup.status = 'FAIL'; result.status = 'FAIL'; }
    }
    if (result.cleanup.status === 'PASS') {
      try {
        const info = await fs.lstat(privateRoot); requireThat(info.isDirectory() && !info.isSymbolicLink() && path.dirname(privateRoot) === outputRoot, 'INDEPENDENT_PRIVATE_CLEANUP_PATH');
        await restoreProjectedDirectoryModes(privateRoot);
        await fs.rm(privateRoot, { recursive: true }); result.privateState = 'SCRUBBED';
      } catch (error) { result.status = 'FAIL'; result.privateState = 'SCRUB_FAILED'; result.cleanup = { ...result.cleanup, status: 'FAIL', reason: publicFailureCode(error) }; }
    } else result.privateState = 'RETAINED_FOR_OWNED_RESOURCE_RECOVERY_DO_NOT_PUBLISH';
    if (result.observation) {
      result.observation.cleanup = result.cleanup;
      await write(path.join(outputRoot, 'product-observation.json'), result.observation);
    }
    if (result.status !== 'PASS') result.independent = false;
    result.finalized = true; await write(path.join(outputRoot, 'product-result.json'), result);
  }
  return result;
}
