import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const MAX_LOG = 128 * 1024;
const INHERITED_ENVIRONMENT = new Set([
  'path', 'systemroot', 'windir', 'comspec', 'pathext', 'temp', 'tmp',
  'userprofile', 'home', 'homedrive', 'homepath', 'appdata', 'localappdata',
  'programdata', 'lang', 'language', 'lc_all', 'lc_ctype', 'tz', 'ci',
  'number_of_processors', 'processor_architecture', 'os', 'no_color', 'term',
]);

export function buildCommandEnvironment(env = process.env, declared = {}, context) {
  const childEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (INHERITED_ENVIRONMENT.has(key.toLowerCase()) && typeof value === 'string') childEnv[key] = value;
  }
  for (const [key, value] of Object.entries(declared)) childEnv[key] = substitute(value, context);
  return childEnv;
}

export function redact(text, env = process.env) {
  let safe = String(text);
  for (const [name, value] of Object.entries(env)) {
    if (/secret|password|token|api.?key|credential/iu.test(name) && value && value.length >= 4) safe = safe.split(value).join('[REDACTED]');
  }
  return safe.replace(/((?:password|token|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+/giu, '$1[REDACTED]').replace(/https?:\/\/[^\s/@]+:[^\s/@]+@/giu, 'https://[REDACTED]@');
}

function substitute(value, { root, output }) {
  return String(value).replaceAll('{root}', root).replaceAll('{output}', output).replaceAll('{pathsep}', path.delimiter);
}

export function prepareCommand(suite, { root, output, env = process.env }) {
  const command = suite.command;
  if (!command || typeof command.executable !== 'string' || !Array.isArray(command.args)) throw new Error('INVALID_SUITE_COMMAND');
  if (suite.capabilities?.includes('windows-native') && process.platform !== 'win32') throw new Error('WINDOWS_NATIVE_REQUIRED');
  const childEnv = buildCommandEnvironment(env, command.env ?? {}, { root, output });
  let executable = command.executable;
  const args = command.args.map((arg) => substitute(arg, { root, output }));
  // Node 24 defaults to the human reporter even with piped stdout. Pin TAP
  // explicitly so collection cannot accidentally depend on terminal detection.
  if (suite.collection?.format === 'node-tap' && args.includes('--test') && !args.some((arg) => arg.startsWith('--test-reporter'))) args.splice(args.indexOf('--test') + 1, 0, '--test-reporter=tap');
  if (executable === '{node}') executable = process.execPath;
  if (suite.capabilities?.includes('node-24') && Number(process.versions.node.split('.')[0]) !== 24) throw new Error('NODE_24_REQUIRED');
  if (executable === '{python}') {
    const candidates = childEnv.PYTHON ? [{ executable: childEnv.PYTHON, prefix: [] }] : process.platform === 'win32'
      ? [{ executable: 'py', prefix: ['-3.12'] }, { executable: 'python', prefix: [] }]
      : [{ executable: 'python3.12', prefix: [] }, { executable: 'python3', prefix: [] }, { executable: 'python', prefix: [] }];
    const python312 = suite.capabilities?.includes('python-3.12');
    const selected = candidates.find((candidate) => {
      const probe = spawnSync(candidate.executable, [...candidate.prefix, '-I', '-c', 'import platform; print(platform.python_version())'], { encoding: 'utf8', env: childEnv, windowsHide: true, timeout: 5000 });
      return probe.status === 0 && (!python312 || /^3\.12\.\d+\s*$/u.test(probe.stdout));
    });
    if (!selected) throw new Error(python312 ? 'PYTHON_312_UNAVAILABLE' : 'PYTHON_UNAVAILABLE');
    executable = selected.executable; args.unshift(...selected.prefix);
  }
  // npm.cmd needs a shell on Windows. Invoke npm's JS CLI directly instead.
  if (executable === 'npm' && process.platform === 'win32') {
    const npmCli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
    if (!existsSync(npmCli)) throw new Error('NPM_CLI_UNAVAILABLE');
    executable = process.execPath; args.unshift(npmCli);
  }
  const cwd = path.resolve(root, command.cwd ?? '.');
  if (cwd !== path.resolve(root) && !cwd.startsWith(`${path.resolve(root)}${path.sep}`)) throw new Error('SUITE_CWD_OUTSIDE_CANDIDATE');
  return { executable, args, cwd, env: childEnv };
}

export function executeCommand(command, { timeoutMs = 600_000, signal, stopGraceMs = 2000, processOps = {} } = {}) {
  return new Promise((resolve) => {
    let stdout = ''; let stderr = ''; let timedOut = false; let interrupted = false; let spawnError = null;
    let settled = false; let exitCode = null; let exited = false; let stopping = false;
    let deadline; let stopTimer; let drainTimer;
    const terminationErrors = [];
    let processCleanup = { status: 'PASS' };
    const started = Date.now();
    const platform = processOps.platform ?? process.platform;
    const child = (processOps.spawn ?? spawn)(command.executable, command.args, { cwd: command.cwd, env: command.env, shell: false, windowsHide: true, detached: platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline); clearTimeout(stopTimer); clearTimeout(drainTimer);
      signal?.removeEventListener('abort', abort);
      child.stdout?.destroy(); child.stderr?.destroy();
      if (!exited && child.pid) child.unref();
      resolve({ exitCode, timedOut, interrupted, spawnError, processCleanup, terminationErrors, stdout: redact(stdout, command.env), stderr: redact(stderr, command.env), durationMs: Date.now() - started });
    };
    const stop = () => {
      if (stopping || settled) return;
      stopping = true;
      if (child.pid && !exited) {
        if (platform === 'win32') {
          const killed = (processOps.spawnSync ?? spawnSync)('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, encoding: 'utf8', timeout: Math.min(1500, stopGraceMs), stdio: ['ignore', 'pipe', 'pipe'] });
          if (killed.status !== 0 || killed.error) {
            terminationErrors.push({ code: killed.error?.code ?? 'TREE_TERMINATION_FAILED', exitCode: killed.status ?? null, detail: redact(String(killed.stderr ?? '').slice(0, 512), command.env) });
            processCleanup = { status: 'BLOCKED', reason: 'PROCESS_TREE_TERMINATION_UNCONFIRMED', pid: child.pid };
          }
        } else {
          try { (processOps.killGroup ?? process.kill)(-child.pid, 'SIGKILL'); }
          catch (error) { if (error.code !== 'ESRCH') { terminationErrors.push({ code: error.code ?? 'GROUP_TERMINATION_FAILED' }); processCleanup = { status: 'BLOCKED', reason: 'PROCESS_TREE_TERMINATION_UNCONFIRMED', pid: child.pid }; } }
        }
        // This targets only the process created above. It remains necessary
        // when taskkill/group termination is denied by the host sandbox.
        try { child.kill('SIGKILL'); } catch (error) { terminationErrors.push({ code: error.code ?? 'CHILD_TERMINATION_FAILED' }); }
      }
      stopTimer = setTimeout(() => {
        if (!exited && child.pid) processCleanup = { status: 'BLOCKED', reason: 'OWNED_PROCESS_STILL_UNCONFIRMED', pid: child.pid };
        else if (!settled) processCleanup = { status: 'BLOCKED', reason: 'OWNED_PROCESS_STREAMS_NOT_CLOSED', pid: child.pid ?? null };
        finish();
      }, stopGraceMs);
    };
    const abort = () => { interrupted = true; stop(); };
    deadline = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    child.stdout?.on('data', (chunk) => { stdout = (stdout + chunk.toString()).slice(-MAX_LOG); });
    child.stderr?.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-MAX_LOG); });
    child.once('error', (error) => { spawnError = error.code ?? 'SPAWN_ERROR'; if (!child.pid) finish(); else stop(); });
    child.once('exit', (code) => {
      exited = true; exitCode = code;
      clearTimeout(deadline);
      drainTimer = setTimeout(() => { processCleanup = { status: 'BLOCKED', reason: 'OWNED_PROCESS_STREAMS_NOT_CLOSED', pid: child.pid ?? null }; finish(); }, stopGraceMs);
    });
    child.once('close', (code) => { exited = true; exitCode = code; finish(); });
  });
}

export function collectTests(suite, observation, output, { allowFailedOperatorReport = false } = {}) {
  const format = suite.collection?.format ?? 'exit-code';
  const log = `${observation.stdout ?? ''}\n${observation.stderr ?? ''}`;
  if (format === 'exit-code') return { collected: null, executed: null, skipped: [], evidence: 'exit-code' };
  if (format === 'operator-json') {
    const reportPath = path.join(output, 'result.json');
    if (!existsSync(reportPath)) return { error: 'OPERATOR_RESULT_MISSING' };
    try {
      const report = JSON.parse(readFileSync(reportPath, 'utf8'));
      const acceptedStatus = report.status === 'PASS' || (allowFailedOperatorReport && report.status === 'FAIL');
      if (!acceptedStatus || report.cleanup?.status !== 'PASS' || report.tests?.countsKnown === false || !Number.isInteger(report.tests?.executed) || !Number.isInteger(report.tests?.collected) || !Array.isArray(report.tests?.skipped)) return { error: 'OPERATOR_RESULT_INCOMPLETE' };
      const counts = report.tests;
      const integer = (value) => Number.isSafeInteger(value) && value >= 0;
      if (![counts.collected, counts.executed, counts.failed ?? 0, counts.todo ?? 0, counts.cancelled ?? 0].every(integer)
        || counts.skipped.some((skip) => !skip || typeof skip.reason !== 'string' || !skip.reason.trim())
        || counts.executed + counts.skipped.length + (counts.todo ?? 0) + (counts.cancelled ?? 0) !== counts.collected
        || (counts.failed ?? 0) > counts.executed
        || (counts.passed !== undefined && (!integer(counts.passed) || counts.passed + (counts.failed ?? 0) !== counts.executed))) return { error: 'OPERATOR_COUNTERS_INCONSISTENT' };
      return { ...report.tests, evidence: 'operator-json' };
    } catch { return { error: 'OPERATOR_RESULT_INVALID' }; }
  }
  if (format === 'node-tap') {
    const counts = {};
    for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
      const entries = [...log.matchAll(new RegExp(`^# ${name} ([^\\r\\n]*)\\r?$`, 'gmu'))];
      if (entries.length !== 1 || !/^\d+$/u.test(entries[0][1])) return { error: 'TAP_COUNTER_MISSING_OR_AMBIGUOUS' };
      const value = Number(entries[0][1]);
      if (!Number.isSafeInteger(value)) return { error: 'TAP_COUNTER_INVALID' };
      counts[name] = value;
    }
    if (counts.tests !== counts.pass + counts.fail + counts.cancelled + counts.skipped + counts.todo) return { error: 'TAP_COUNTERS_INCONSISTENT' };
    if (/^\s*not ok\b/mu.test(log) && counts.fail === 0 && counts.cancelled === 0 && counts.todo === 0) return { error: 'TAP_CASES_INCONSISTENT' };
    const skips = [...log.matchAll(/^\s*(?:ok|not ok)\b([^\r\n]*?)# SKIP\b[^\S\r\n]*([^\r\n]*)\r?$/gmu)].map((match) => {
      const title = match[1].replace(/^\s*\d+(?:\s*-\s*|\s*$)/u, '').trim();
      const observedReason = match[2].trim();
      return { title, reason: observedReason || 'unspecified', observedReason };
    });
    const skipCount = counts.skipped;
    if (skips.length > skipCount) return { error: 'TAP_SKIP_COUNT_INCONSISTENT' };
    while (skips.length < skipCount) skips.push({ reason: 'unspecified' });
    return { collected: counts.tests, executed: counts.pass + counts.fail, passed: counts.pass, failed: counts.fail, cancelled: counts.cancelled, todo: counts.todo, skipped: skips, evidence: 'node-tap' };
  }
  if (format === 'pytest-junit') {
    const junitArg = suite.command.args.find((arg) => typeof arg === 'string' && arg.startsWith('--junitxml='));
    const junitFile = suite.collection?.reportPath ?? junitArg?.slice('--junitxml='.length);
    if (junitFile) {
      const filename = path.resolve(substitute(junitFile, { root: '', output }));
      if (!path.isAbsolute(filename) || !filename.startsWith(`${path.resolve(output)}${path.sep}`) || !existsSync(filename)) return { error: 'JUNIT_RESULT_MISSING' };
      const xml = readFileSync(filename, 'utf8');
      const cases = [...xml.matchAll(/<testcase\b[^>]*?\/>|<testcase\b[^>]*?>[\s\S]*?<\/testcase>/gu)].map((match) => match[0]);
      const validated = validateJunitCounters(xml, cases);
      if (validated.error) return validated;
      const skipped = cases.filter((entry) => /<skipped\b/u.test(entry)).map((entry) => ({ reason: entry.match(/<skipped\b[^>]*message="([^"]*)"/u)?.[1] ?? 'unspecified' }));
      const failed = cases.filter((entry) => /<(?:failure|error)\b/u.test(entry)).length;
      return { collected: cases.length, executed: cases.length - skipped.length, failed, skipped, evidence: 'pytest-junit' };
    }
    const passed = Number(log.match(/\b(\d+) passed\b/u)?.[1] ?? 0);
    const failed = Number(log.match(/\b(\d+) failed\b/u)?.[1] ?? 0);
    const skips = Number(log.match(/\b(\d+) skipped\b/u)?.[1] ?? 0);
    if (!passed && !failed && !skips) return { error: 'TEST_COLLECTION_MISSING' };
    return { collected: passed + failed + skips, executed: passed + failed, failed, skipped: Array.from({ length: skips }, () => ({ reason: 'unspecified; junit not emitted' })), evidence: 'pytest-summary' };
  }
  return { error: 'UNKNOWN_COLLECTION_FORMAT' };
}

function validateJunitCounters(xml, cases) {
  const stack = [];
  let observedCases = 0;
  const tokens = xml.matchAll(/<testcase\b[^>]*?\/>|<testcase\b[^>]*?>[\s\S]*?<\/testcase>|<\/?testsuites?\b[^>]*>/gu);
  for (const match of tokens) {
    const token = match[0];
    if (token.startsWith('<testcase')) {
      if (!stack.length) return { error: 'JUNIT_STRUCTURE_INVALID' };
      observedCases += 1;
      const count = { tests: 1, failures: /<failure\b/u.test(token) ? 1 : 0, errors: /<error\b/u.test(token) ? 1 : 0, skipped: /<skipped\b/u.test(token) ? 1 : 0 };
      if (count.failures + count.errors + count.skipped > 1) return { error: 'JUNIT_COUNTERS_INCONSISTENT' };
      for (const frame of stack) for (const [name, value] of Object.entries(count)) frame.observed[name] += value;
    } else if (token.startsWith('</')) {
      const name = token.match(/^<\/(testsuites?)\b/u)?.[1];
      const frame = stack.pop();
      if (!frame || frame.name !== name) return { error: 'JUNIT_STRUCTURE_INVALID' };
      for (const [key, value] of Object.entries(frame.declared)) if (frame.observed[key] !== value) return { error: 'JUNIT_COUNTERS_INCONSISTENT' };
    } else {
      const name = token.match(/^<(testsuites?)\b/u)?.[1];
      const declared = {};
      for (const key of ['tests', 'failures', 'errors', 'skipped']) {
        const entries = [...token.matchAll(new RegExp(`\\b${key}\\s*=\\s*(["'])(.*?)\\1`, 'gu'))];
        if (entries.length > 1 || (entries.length === 1 && (!/^\d+$/u.test(entries[0][2]) || !Number.isSafeInteger(Number(entries[0][2]))))) return { error: 'JUNIT_COUNTERS_INVALID' };
        if (entries.length) declared[key] = Number(entries[0][2]);
      }
      if (/\/>$/u.test(token)) {
        if (Object.values(declared).some((value) => value !== 0)) return { error: 'JUNIT_COUNTERS_INCONSISTENT' };
      } else stack.push({ name, declared, observed: { tests: 0, failures: 0, errors: 0, skipped: 0 } });
    }
  }
  if (stack.length || observedCases !== cases.length || [...xml.matchAll(/<testcase\b/gu)].length !== observedCases) return { error: 'JUNIT_STRUCTURE_INVALID' };
  return {};
}
