import test from 'node:test';
import assert from 'node:assert/strict';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { assertNoCleanupCandidates, assertTemporalDescription, assertTemporalHistory, createProjectedToolState, freezeProductSource, isCleanupContainerCandidate, ownsComposeCleanupContainer, projectedToolArguments, publicFailureCode, readCandidateFile, removeValidatedContainers, restoreProjectedDirectoryModes, retainPrivateDiagnostic, retainProjectedToolObservation, uninitializedCleanupVerdict, validateObserverAction, validateToolMounts } from './product-driver.mjs';
import { portableGitEnvironment, snapshotSource } from '../../portable/source.mjs';
import { validateHashedLock } from './native-functions.mjs';
import { canonical, digest } from './bundle.mjs';
import { buildCompose } from '../../../infra/portable/appwrite-compose.mjs';

const worker = 'a'.repeat(64), postgres = 'b'.repeat(64), project = 'sm9-independent-fixture';
const rows = ['execution-worker', 'app-postgres'].map((service, index) => ({ Id: index ? postgres : worker, Config: { Labels: { 'io.appwritework.portable': project, 'com.docker.compose.service': service } } }));
const binding = { tenantId: 'tenant', runId: 'current-run', workflowId: 'current-workflow', engineAttemptRef: 'attempt', firstExecutionRef: 'f'.repeat(36), terminalResultDigest: 'sha256:' + '1'.repeat(64) };
const payload = value => ({ metadata: { encoding: 'anNvbi9wbGFpbg==' }, data: Buffer.from(canonical(value)).toString('base64') });
test('cleanup includes the exact rendered executor name and requires its exact Compose ownership', () => {
  const executor = buildCompose({ project, runId: project }).services.executor.container_name;
  assert.equal(executor, 'r0e-' + digest(Buffer.from(project)).slice(7, 17));
  const options = { project, executor, projectId: 'owned-appwrite-project' };
  assert.equal(isCleanupContainerCandidate({ Names: executor }, options), true);
  assert.equal(isCleanupContainerCandidate({ Names: executor + '-function' }, options), true);
  assert.equal(isCleanupContainerCandidate({ Names: project + '-app-postgres-1' }, options), true);
  for (const name of [executor + 'other', 'foreign-' + executor, 'r0e-' + 'f'.repeat(10), 'job-other-deployment']) {
    assert.equal(isCleanupContainerCandidate({ Names: name }, options), false);
  }
  const row = { Name: '/' + executor, Config: { Labels: { 'io.appwritework.portable': project,
    'com.docker.compose.project': project, 'com.docker.compose.service': 'executor' } } };
  assert.equal(ownsComposeCleanupContainer(row, options), true);
  for (const [key, value] of [['io.appwritework.portable', 'foreign'], ['com.docker.compose.project', 'foreign'], ['com.docker.compose.service', 'execution-worker']]) {
    const altered = structuredClone(row); altered.Config.Labels[key] = value;
    assert.equal(ownsComposeCleanupContainer(altered, options), false);
  }
});
test('validated child auto-removal needs successful exact-ID absence and does not count as a removal', async () => {
  const calls = [], ownedIds = [worker, postgres];
  const receipt = await removeValidatedContainers({ ownedIds, sentinelId: 'c'.repeat(64), docker: async args => {
    calls.push(args);
    if (args[0] === 'rm' && args.at(-1) === postgres) throw new Error('Docker child disappeared after executor removal');
    if (args[0] === 'ps') { assert.deepEqual(args, ['ps', '-aq', '--no-trunc', '--filter', 'id=' + postgres]); return ''; }
    return '';
  } });
  assert.equal(receipt.status, 'PASS'); assert.deepEqual(receipt.removedIds, [worker]); assert.deepEqual(receipt.alreadyAbsentIds, [postgres]);
  assert.equal(calls.length, 3);
});
test('failed removal and unconfirmed absence preserve first cause while other validated targets are attempted', async () => {
  for (const proof of [worker, 'd'.repeat(64), 'throw']) {
    const attempted = [], first = new Error('Docker initial failure synthetic-sensitive-detail');
    const receipt = await removeValidatedContainers({ ownedIds: [worker, postgres], sentinelId: 'c'.repeat(64), docker: async args => {
      if (args[0] === 'rm') { attempted.push(args.at(-1)); if (args.at(-1) === worker) throw first; return ''; }
      if (proof === 'throw') throw new Error('inventory failed'); return proof;
    } });
    assert.equal(receipt.status, 'FAIL'); assert.deepEqual(attempted, [worker, postgres]); assert.deepEqual(receipt.removedIds, [postgres]);
    assert.deepEqual(receipt.alreadyAbsentIds, []); assert.equal(receipt.firstError, first);
    assert.equal(JSON.stringify(receipt).includes('synthetic-sensitive-detail'), false);
    assert.equal(receipt.failures[0].absence, proof === worker ? 'PRESENT' : 'UNCONFIRMED');
  }
  let mutations = 0;
  await assert.rejects(removeValidatedContainers({ ownedIds: [worker, 'c'.repeat(64)], sentinelId: 'c'.repeat(64), docker: async () => { mutations++; } }));
  assert.equal(mutations, 0);
});
test('final cleanup inventory rejects late children and ownerless task conflicts without widening removal authority', () => {
  const executor = buildCompose({ project, runId: project }).services.executor.container_name;
  const context = { project, executor, projectId: 'owned-project' };
  assertNoCleanupCandidates([{ Names: executor + 'similar' }, { Names: 'unrelated-project-worker' }], context);
  for (const name of [executor + '-late-child', project + '-ownerless-conflict', 'job-owned-project-late-build']) {
    assert.throws(() => assertNoCleanupCandidates([{ Names: name }], context), /CONTAINER_RESIDUE/);
  }
});
function history() { return { events: [
  { eventId: '1', workflowExecutionStartedEventAttributes: { workflowType: { name: 'SalmoraDagWorkflowV1' }, input: { payloads: [payload({ tenant_id: binding.tenantId, run_id: binding.runId, workflow_id: binding.workflowId, engine_id: 'temporal', engine_attempt_ref: binding.engineAttemptRef })] } } },
  { eventId: '2' }, { eventId: '3', workflowExecutionCompletedEventAttributes: { result: { payloads: [payload({ run_id: binding.runId, state: 'succeeded', result_digest: binding.terminalResultDigest })] } } },
] }; }

test('public failure evidence never quotes untrusted JSON payloads or secret-bearing transport errors', () => {
  const secret = 'synthetic-private-runtime-password';
  let parserError; try { JSON.parse(secret); } catch (error) { parserError = error; }
  assert.equal(publicFailureCode(parserError), 'INDEPENDENT_PRODUCT_OPERATOR_FAILED');
  assert.equal(publicFailureCode(new Error('PORTABLE_DOCKER_EXEC: ' + secret)), 'INDEPENDENT_PRODUCT_OPERATOR_FAILED');
  assert.equal(publicFailureCode(new Error('INDEPENDENT_TEMPORAL_RESULT_BINDING')), 'INDEPENDENT_TEMPORAL_RESULT_BINDING');
});

test('lost Docker create acknowledgement cannot certify cleanup or scrub recovery intent', () => {
  assert.equal(uninitializedCleanupVerdict({ sentinelAttempted: false }).status, 'PASS');
  assert.equal(uninitializedCleanupVerdict({ sentinelAttempted: true, sentinel: { id: 'owned immutable record' } }).status, 'PASS');
  const ambiguous = uninitializedCleanupVerdict({ sentinelAttempted: true });
  assert.equal(ambiguous.status, 'FAIL'); assert.equal(ambiguous.reason, 'SENTINEL_CREATE_UNCONFIRMED');
});

test('failed operators retain a protected redacted first cause without putting details in public receipts', async t => {
  const base = path.resolve('.local/portable-controller-fixtures'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(path.join(base, 'private-diagnostic-')); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const secret = 'synthetic-generated-operator-password';
  const receipt = await retainPrivateDiagnostic({ error: new Error('Docker pool exhausted ' + secret), stage: 'start-core', output: directory,
    redactor: message => message.replaceAll(secret, '[REDACTED]') });
  assert.equal(JSON.stringify(receipt).includes(secret), false); assert.equal(JSON.stringify(receipt).includes('pool exhausted'), false);
  const details = readFileSync(path.join(directory, receipt.path), 'utf8'); assert.match(details, /pool exhausted/); assert.equal(details.includes(secret), false);
  const unavailable = path.join(directory, 'fallback'); mkdirSync(unavailable);
  const fallback = await retainPrivateDiagnostic({ error: new Error(secret), stage: 'start-core', output: unavailable, redactor: () => { throw new Error(secret); } });
  assert.equal(readFileSync(path.join(unavailable, fallback.path), 'utf8').includes(secret), false);
});
test('projected tool failures retain bounded redacted output and exit evidence outside scrubbed private state', async t => {
  const base = path.resolve('.local/portable-controller-fixtures'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(path.join(base, 'tool-diagnostic-')); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const secret = 'synthetic-sql-projected-password';
  const observed = { stdout: 'migration first cause ' + secret, stderr: 'stderr ' + secret, exitCode: 1, signal: 'SIGTERM', timedOut: false };
  const receipt = await retainProjectedToolObservation({ output: directory, script: 'migrate.py', observed,
    container: { State: { ExitCode: 1 } }, redactor: message => message.replaceAll(secret, '[REDACTED]') });
  assert.equal(JSON.stringify(receipt).includes('first cause'), false); assert.equal(JSON.stringify(receipt).includes(secret), false);
  const detail = JSON.parse(readFileSync(path.join(directory, receipt.path), 'utf8'));
  assert.equal(detail.exitCode, 1); assert.equal(detail.containerExitCode, 1); assert.equal(detail.signal, 'SIGTERM');
  assert.match(detail.details, /migration first cause/); assert.equal(detail.details.includes(secret), false);
  const fallback = path.join(directory, 'fallback'); mkdirSync(fallback);
  await retainProjectedToolObservation({ output: fallback, script: 'migrate.py', observed, container: {}, redactor: () => { throw new Error(secret); } });
  assert.equal(readFileSync(path.join(fallback, receipt.path), 'utf8').includes(secret), false);
  const long = path.join(directory, 'long'); mkdirSync(long);
  await retainProjectedToolObservation({ output: long, script: 'migrate.py', observed: { stdout: 'a'.repeat(70 * 1024) + secret, exitCode: 1 },
    container: {}, redactor: message => message.replaceAll(secret, '[REDACTED]') });
  const truncated = JSON.parse(readFileSync(path.join(long, receipt.path), 'utf8'));
  assert.equal(truncated.outputTruncated, true); assert.ok(Buffer.byteLength(truncated.details) <= 64 * 1024);
  const oversized = path.join(directory, 'oversized'); mkdirSync(oversized);
  let oversizedRedactorCalled = false;
  await retainProjectedToolObservation({ output: oversized, script: 'migrate.py', observed: { stdout: secret + 'a'.repeat(1024 * 1024), exitCode: 1 },
    container: {}, redactor: () => { oversizedRedactorCalled = true; return secret; } });
  assert.equal(oversizedRedactorCalled, false);
  assert.equal(readFileSync(path.join(oversized, receipt.path), 'utf8').includes(secret), false);
  const unicode = path.join(directory, 'unicode'); mkdirSync(unicode);
  await retainProjectedToolObservation({ output: unicode, script: 'migrate.py', observed: { stdout: '€'.repeat(30000), exitCode: 1 },
    container: {}, redactor: message => message });
  assert.ok(Buffer.byteLength(JSON.parse(readFileSync(path.join(unicode, receipt.path), 'utf8')).details) <= 64 * 1024);
});
test('diagnostic traceback invokes only the same fixed migration main without bypassing tool scope', () => {
  assert.deepEqual(projectedToolArguments('migrate.py', []), ['-B', '/source/infra/portable/migrate.py']);
  assert.deepEqual(projectedToolArguments('clean_bootstrap.py', ['bootstrap']), ['-B', '/source/infra/portable/clean_bootstrap.py', 'bootstrap']);
  assert.deepEqual(projectedToolArguments('migrate.py', [], { diagnosticTraceback: true }),
    ['-B', '-c', "import runpy; runpy.run_path('/source/infra/portable/migrate.py', run_name='trusted_migration_diagnostic')['main']()"]);
  assert.throws(() => projectedToolArguments('../candidate.py', [], { diagnosticTraceback: true }));
  assert.throws(() => projectedToolArguments('clean_bootstrap.py', [], { diagnosticTraceback: true }));
  assert.throws(() => projectedToolArguments('migrate.py', ['arbitrary-argument'], { diagnosticTraceback: true }));
});

test('tool state materializes only bounded required inputs behind its private parent', async t => {
  const base = path.resolve('.local/portable-controller-fixtures'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(path.join(base, 'projected-state-'));
  t.after(async () => { await restoreProjectedDirectoryModes(directory); rmSync(directory, { recursive: true, force: true }); });
  const state = { dir: path.join(directory, 'state'), deploymentBinding: 'binding' };
  mkdirSync(path.join(state.dir, 'private'), { recursive: true }); mkdirSync(path.join(state.dir, 'secrets'));
  writeFileSync(path.join(state.dir, 'private/appwrite.private.json'), JSON.stringify({ cleanBinding: 'clean', tenantId: 'tenant', ownerId: 'owner', apiKey: 'must-not-project' }));
  for (const file of ['ca.crt', 'app-postgres.password', 'app-migrator.password', 'app-runtime.password']) writeFileSync(path.join(state.dir, 'secrets', file), 'fixture-' + file, { mode: 0o600 });
  writeFileSync(path.join(state.dir, 'secrets/ca.key'), 'must-not-project');
  const sourceDirectoryMode = lstatSync(path.join(state.dir, 'secrets')).mode & 0o777;
  const projection = await createProjectedToolState(state, directory);
  assert.deepEqual(readdirSync(projection).sort(), ['private', 'profile.json', 'secrets']);
  assert.deepEqual(readdirSync(path.join(projection, 'secrets')).sort(), ['app-migrator.password', 'app-postgres.password', 'app-runtime.password', 'ca.crt']);
  assert.deepEqual(JSON.parse(readFileSync(path.join(projection, 'private/appwrite.private.json'), 'utf8')), { cleanBinding: 'clean', ownerId: 'owner', tenantId: 'tenant' });
  assert.equal(readFileSync(path.join(projection, 'secrets/ca.crt'), 'utf8'), 'fixture-ca.crt');
  if (process.platform !== 'win32') {
    assert.equal(lstatSync(directory).mode & 0o777, 0o700);
    for (const name of ['', 'secrets', 'private']) assert.equal(lstatSync(path.join(projection, name)).mode & 0o777, 0o555);
    assert.equal(lstatSync(path.join(projection, 'secrets/ca.crt')).mode & 0o777, 0o444);
    assert.equal(lstatSync(path.join(state.dir, 'secrets/ca.crt')).mode & 0o777, 0o600);
  }
  writeFileSync(path.join(state.dir, 'secrets/ca.crt'), 'x'.repeat(32 * 1024 + 1));
  await assert.rejects(createProjectedToolState(state, directory), /TOOL_INPUT_INVALID/);
  rmSync(path.join(state.dir, 'secrets/ca.crt')); mkdirSync(path.join(state.dir, 'secrets/ca.crt'));
  await assert.rejects(createProjectedToolState(state, directory), /TOOL_INPUT_INVALID/);
  await assert.rejects(createProjectedToolState({ ...state, dir: base }, directory), /TOOL_PRIVATE_PARENT_REQUIRED/);
  await restoreProjectedDirectoryModes(directory);
  if (process.platform !== 'win32') {
    for (const name of ['', 'secrets', 'private']) assert.equal(lstatSync(path.join(projection, name)).mode & 0o777, 0o700);
    assert.equal(lstatSync(path.join(state.dir, 'secrets')).mode & 0o777, sourceDirectoryMode);
  }
});

test('freezing candidate inputs bounds reads before allocation and rejects changed identity/traversal', t => {
  const base = path.resolve('.local/portable-controller-fixtures'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(path.join(base, 'bounded-freeze-')); t.after(() => rmSync(directory, { recursive: true, force: true }));
  writeFileSync(path.join(directory, 'input.txt'), '12345678'); const entry = { path: 'input.txt', digest: digest('12345678') };
  assert.equal(readCandidateFile(directory, entry, 8).toString(), '12345678');
  assert.throws(() => readCandidateFile(directory, entry, 7), /SOURCE_SIZE_LIMIT/);
  assert.throws(() => readCandidateFile(directory, { ...entry, digest: digest('changed') }), /SOURCE_CHANGED/);
  assert.throws(() => readCandidateFile(directory, { ...entry, path: '../input.txt' }), /SOURCE_PATH_INVALID/);
});

test('owned source snapshots support deep Windows paths and use an explicit codex branch', async t => {
  const base = path.resolve('.local/portable-controller-fixtures'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(path.join(base, 'longpath-freeze-')); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = path.join(directory, 'source'), destination = path.join(directory, 'owned-frozen'); mkdirSync(source);
  const filename = path.join(source, 'a'.repeat(90), 'b'.repeat(90), 'input.txt'); mkdirSync(path.dirname(filename), { recursive: true }); writeFileSync(filename, 'bounded long-path fixture');
  writeFileSync(path.join(source, 'removed.txt'), 'retired source must not reappear');
  const git = args => execFileSync('git', ['-c', 'core.longpaths=true', '-c', 'core.hooksPath=/dev/null', '-C', source, ...args], { env: portableGitEnvironment(), windowsHide: true, stdio: 'pipe' });
  git(['init', '--quiet', '--initial-branch=codex/source-fixture']); git(['config', '--local', 'core.longpaths', 'true']); git(['add', '--force', '--all']);
  git(['-c', 'commit.gpgsign=false', '-c', 'user.name=Source fixture', '-c', 'user.email=fixture@portable.invalid', 'commit', '--quiet', '-m', 'owned fixture']);
  rmSync(path.join(source, 'removed.txt'));
  const result = await freezeProductSource(source, destination); assert.match(result.snapshotCommit, /^[a-f0-9]{40}$/u);
  assert.deepEqual(snapshotSource(destination).files, snapshotSource(source).files.filter(entry => entry.kind === 'file'));
  assert.equal(result.files, 1); assert.equal(result.trackedEntries, 2); assert.equal(result.omittedDeletedEntries, 1);
  assert.equal(execFileSync('git', ['-C', destination, 'symbolic-ref', '--short', 'HEAD'], { encoding: 'utf8', env: portableGitEnvironment(), windowsHide: true }).trim(), 'codex/verifier-input-snapshot');
});

test('trusted observer actual stop/ps/SQL argv is permitted only for the owned capability', () => {
  validateObserverAction(['stop', '-t', '20', worker], rows); validateObserverAction(['start', worker], rows);
  validateObserverAction(['ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + project, '--filter', 'label=com.docker.compose.service=app-postgres'], rows);
  validateObserverAction(['exec', postgres, 'psql', '-U', 'salmora_operator', '-d', 'salmora', '-XAt', '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT 1'], rows);
  for (const args of [['stop', '-t', '20', postgres], ['start', 'c'.repeat(64)], ['ps', '-aq'], ['exec', postgres, 'sh', '-c', 'true'], ['inspect', worker, postgres], ['stop', '--all']]) assert.throws(() => validateObserverAction(args, rows));
  assert.throws(() => validateObserverAction(['exec', postgres, 'psql', '-U', 'salmora_operator', '-d', 'salmora', '-XAt', '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT 1; DELETE FROM users'], rows));
});
test('real Temporal completion binds immutable input and SQL terminal digest', () => {
  assert.equal(assertTemporalHistory(history(), binding).runId, binding.runId);
  for (const change of [h => { h.events[0].workflowExecutionStartedEventAttributes.input.payloads[0] = payload({ tenant_id: 'other', run_id: binding.runId }); },
    h => { h.events[2].workflowExecutionCompletedEventAttributes.result.payloads[0] = payload({ run_id: 'other-run', state: 'succeeded', result_digest: binding.terminalResultDigest }); },
    h => { h.events[2].workflowExecutionCompletedEventAttributes.result.payloads[0] = payload({ run_id: binding.runId, state: 'succeeded', result_digest: 'sha256:' + '2'.repeat(64) }); },
    h => { delete h.events[2].workflowExecutionCompletedEventAttributes; }, h => { h.events[1].eventId = '8'; }]) {
    const h = history(); change(h); assert.throws(() => assertTemporalHistory(h, binding));
  }
});
test('Temporal description rejects unrelated execution/status even if SQL refs are present', () => {
  const value = { workflowExecutionInfo: { execution: { workflowId: binding.workflowId, runId: binding.firstExecutionRef }, type: { name: 'SalmoraDagWorkflowV1' }, status: 'WORKFLOW_EXECUTION_STATUS_COMPLETED', historyLength: '9' } };
  assert.equal(assertTemporalDescription(value, binding).historyEvents, 9);
  value.workflowExecutionInfo.status = 'RUNNING'; assert.throws(() => assertTemporalDescription(value, binding));
});
test('native wheel preparation rejects options, URLs, unpinned inputs and missing hashes', () => {
  assert.equal(validateHashedLock('# header\npkg==1.2.3 \\\n --hash=sha256:' + 'a'.repeat(64) + '\n'), 1);
  for (const value of ['--index-url https://evil.invalid', 'pkg @ https://evil.invalid/x.whl', 'pkg>=1', 'pkg==1', '../pkg==1 --hash=sha256:' + 'a'.repeat(64)]) assert.throws(() => validateHashedLock(value));
});
test('projected trusted tools reject writable mounts and Docker socket', () => {
  const row = { Config: { User: '1000:1000', Labels: { 'io.appwritework.portable': project } }, HostConfig: { ReadonlyRootfs: true, CapDrop: ['ALL'] }, Mounts: [{ Type: 'bind', Source: '/bundle', Destination: '/source', RW: false }, { Type: 'bind', Source: '/projected', Destination: '/run/portable', RW: false }] };
  validateToolMounts(row, { project, bundleRoot: '/bundle', projectedState: '/projected' });
  row.Mounts[0].RW = true; assert.throws(() => validateToolMounts(row, { project, bundleRoot: '/bundle', projectedState: '/projected' }));
  row.Mounts[0].RW = false; row.Mounts.push({ Type: 'bind', Source: '/var/run/docker.sock', Destination: '/var/run/docker.sock', RW: false });
  assert.throws(() => validateToolMounts(row, { project, bundleRoot: '/bundle', projectedState: '/projected' }));
});

test('projected tools accept equivalent Docker Desktop drive aliases and reject foreign paths', () => {
  const options = { project, bundleRoot: 'C:\\owned\\bundle', projectedState: 'C:/owned/projected' };
  const row = { Config: { User: '1000:1000', Labels: { 'io.appwritework.portable': project } }, HostConfig: { ReadonlyRootfs: true, CapDrop: ['ALL'] },
    Mounts: [{ Type: 'bind', Source: '/run/desktop/mnt/host/c/owned/bundle', Destination: '/source', RW: false },
      { Type: 'bind', Source: '/host_mnt/c/owned/projected', Destination: '/run/portable', RW: false }] };
  validateToolMounts(row, options);
  row.Mounts[0].Source = 'c:/owned/bundle'; validateToolMounts(row, options);
  for (const source of ['/host_mnt/d/owned/bundle', '/run/desktop/mnt/host/c/owned/bundle-other', 'C:\\foreign\\bundle']) {
    row.Mounts[0].Source = source; assert.throws(() => validateToolMounts(row, options), /TOOL_MOUNT_INVALID/);
  }
});
