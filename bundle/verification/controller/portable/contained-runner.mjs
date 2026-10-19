import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { executeCommand } from '../../portable/process.mjs';
import { snapshotSource } from '../../portable/source.mjs';
import { digest } from './bundle.mjs';
import { linkCacheScript, validateNodeCache } from './dependency-cache.mjs';

const IMAGE = /^(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64})$/u;
const OWNER = 'appwritework.portable-verifier.owner';
const COPY_AND_EXEC = 'cp -R /candidate/. /work/ && cd "$1" && shift && exec "$@"';
const CACHE_COPY_AND_EXEC = 'cp -R /candidate/. /work/ && node -e "$1" "$2" && shift 2 && cd "$1" && shift && exec "$@"';
const ENV_KEYS = new Set(['CI', 'NO_COLOR', 'FORCE_COLOR', 'TZ', 'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED', 'NODE_ENV']);

function fail(code) { throw new Error(code); }
function docker(args, options = {}) {
  if (process.env.DOCKER_HOST || process.env.DOCKER_TLS_VERIFY || process.env.DOCKER_CERT_PATH) fail('INDEPENDENT_DOCKER_ENV_OVERRIDE_FORBIDDEN');
  return execFileSync('docker', args, { encoding: 'utf8', windowsHide: true, timeout: 30_000, maxBuffer: 8 * 1024 * 1024, ...options });
}
function beneath(root, filename) {
  const relative = path.relative(root, filename);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
export function validateContainedRuntime(executable, version) {
  const actual = String(version).trim();
  if (executable === 'python' ? !/^Python 3\.12\.\d+$/u.test(actual) : actual !== 'v24.11.1') fail('INDEPENDENT_CONTAINER_RUNTIME_MISMATCH');
  return actual;
}
export function containmentPlan(command, { candidateRoot, output, images, suite }) {
  const candidate = path.resolve(candidateRoot);
  const evidence = path.resolve(output);
  if (beneath(candidate, evidence) || beneath(evidence, candidate)) fail('CONTAINMENT_OUTPUT_OVERLAP');
  if (!beneath(candidate, command.cwd)) fail('CONTAINMENT_CWD_ESCAPE');
  if ([...(suite?.capabilities ?? []), ...(suite?.prerequisites ?? [])].some((entry) => /docker|windows|postgres|temporal|browser|tls/iu.test(typeof entry === 'string' ? entry : JSON.stringify(entry)))) fail('INDEPENDENT_PRIVILEGED_CAPABILITY_UNAVAILABLE');
  const isPython = /(?:^|[/\\])python(?:3(?:\.\d+)?)?(?:\.exe)?$/u.test(command.executable);
  const isNode = /(?:^|[/\\])node(?:\.exe)?$/u.test(command.executable);
  const isNpm = command.executable === 'npm';
  if (!isPython && !isNode && !isNpm) fail('INDEPENDENT_EXECUTABLE_UNSUPPORTED');
  const image = images[isPython ? 'python' : 'node'];
  if (!IMAGE.test(image ?? '')) fail('INDEPENDENT_IMAGE_DIGEST_REQUIRED');
  const replace = (value) => String(value).replaceAll(candidate, '/work').replaceAll(evidence, '/observations').replaceAll('\\', '/');
  const args = command.args.map(replace);
  if (args.some((value) => value.includes('docker.sock') || value.includes('//./pipe/docker') || value.includes('npipe:'))) fail('INDEPENDENT_DOCKER_SOCKET_FORBIDDEN');
  const env = Object.fromEntries(Object.entries(command.env ?? {}).filter(([key]) => ENV_KEYS.has(key)).map(([key, value]) => [key, replace(value)]));
  return { candidate, evidence, image, env, executable: isPython ? 'python' : isNpm ? 'npm' : 'node', args, cwd: `/work/${path.relative(candidate, command.cwd).replaceAll('\\', '/')}` };
}

// Read a small flat result archive as data. Never extract candidate-controlled tar
// paths, symlinks or hardlinks to the host filesystem.
export function readObservationTar(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8 * 1024 * 1024) fail('OBSERVATION_ARCHIVE_LIMIT');
  if (bytes.length < 1024 || bytes.length % 512 !== 0) fail('OBSERVATION_ARCHIVE_TRUNCATED');
  const files = new Map(); let total = 0; let terminated = false; let directorySeen = false;
  for (let offset = 0; offset < bytes.length;) {
    if (offset + 512 > bytes.length) fail('OBSERVATION_ARCHIVE_TRUNCATED');
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) {
      if (offset + 1024 > bytes.length || !bytes.subarray(offset + 512, offset + 1024).every((value) => value === 0)) fail('OBSERVATION_ARCHIVE_TERMINATOR_REQUIRED');
      if (!bytes.subarray(offset).every((value) => value === 0)) fail('OBSERVATION_ARCHIVE_TRAILING_DATA');
      terminated = true;
      break;
    }
    const field = (start, length) => {
      const bytesField = header.subarray(start, start + length);
      const nul = bytesField.indexOf(0);
      if (nul >= 0 && !bytesField.subarray(nul).every((value) => value === 0)) fail('OBSERVATION_ARCHIVE_FIELD_INVALID');
      return bytesField.subarray(0, nul < 0 ? length : nul).toString('utf8');
    };
    const name = field(0, 100); const prefix = field(345, 155);
    if (header.subarray(124, 136).some((value) => value > 127) || header.subarray(148, 156).some((value) => value > 127)) fail('OBSERVATION_ARCHIVE_INVALID');
    const sizeText = header.subarray(124, 136).toString('ascii').replace(/[\0 ]+$/u, '').trim();
    const checksumText = header.subarray(148, 156).toString('ascii').replace(/[\0 ]+$/u, '').trim();
    if (!/^[0-7]+$/u.test(sizeText) || !/^[0-7]+$/u.test(checksumText)) fail('OBSERVATION_ARCHIVE_INVALID');
    const size = Number.parseInt(sizeText, 8);
    const checksum = [...header].reduce((sum, value, index) => sum + (index >= 148 && index < 156 ? 32 : value), 0);
    if (checksum !== Number.parseInt(checksumText, 8)) fail('OBSERVATION_ARCHIVE_CHECKSUM');
    const type = String.fromCharCode(header[156]);
    offset += 512;
    if (prefix || field(157, 100) || !Number.isSafeInteger(size) || size < 0 || size > 4 * 1024 * 1024) fail('OBSERVATION_ARCHIVE_INVALID');
    const paddedSize = Math.ceil(size / 512) * 512;
    if (offset + paddedSize > bytes.length) fail('OBSERVATION_ARCHIVE_TRUNCATED');
    if (!bytes.subarray(offset + size, offset + paddedSize).every((value) => value === 0)) fail('OBSERVATION_ARCHIVE_PADDING_INVALID');
    if (type === '5' && ['observations/', 'observations'].includes(name) && size === 0) {
      if (directorySeen) fail('OBSERVATION_ARCHIVE_UNSAFE_ENTRY');
      directorySeen = true;
      continue;
    }
    const relative = name.replace(/^observations\//u, '');
    if (!['result.json', 'junit.xml', 'report.xml', 'results.xml'].includes(relative) || !['0', '\0'].includes(type) || files.has(relative)) fail('OBSERVATION_ARCHIVE_UNSAFE_ENTRY');
    total += size;
    if (total > 4 * 1024 * 1024) fail('OBSERVATION_ARCHIVE_LIMIT');
    files.set(relative, bytes.subarray(offset, offset + size));
    offset += paddedSize;
  }
  if (!terminated) fail('OBSERVATION_ARCHIVE_TERMINATOR_REQUIRED');
  return files;
}

export function createContainedRunner({ candidateRoot, images, nodeCache, nodeCacheReview, verifierManifestDigest }) {
  const candidate = realpathSync(candidateRoot);
  const receipts = [];
  let frozenRoot = null;
  let sourceDigest = null;
  const freeze = () => {
    if (frozenRoot) return;
    const snapshot = snapshotSource(candidate);
    frozenRoot = mkdtempSync(path.join(os.tmpdir(), 'aww-verifier-source-'));
    sourceDigest = snapshot.digest;
    let total = 0;
    for (const entry of snapshot.files) {
      if (entry.kind === 'deleted') continue;
      if (entry.kind !== 'file') fail('INDEPENDENT_SOURCE_SYMLINK_UNSUPPORTED');
      const original = path.join(candidate, entry.path);
      let ancestor = candidate;
      for (const segment of entry.path.split('/')) {
        ancestor = path.join(ancestor, segment);
        if (lstatSync(ancestor).isSymbolicLink() || !beneath(candidate, realpathSync(ancestor))) fail('INDEPENDENT_SOURCE_PATH_ESCAPE');
      }
      const info = lstatSync(original);
      const bytes = readFileSync(original);
      total += bytes.length;
      if (!info.isFile() || info.isSymbolicLink() || digest(bytes) !== entry.digest || total > 512 * 1024 * 1024) fail('INDEPENDENT_SOURCE_CHANGED_OR_LIMIT');
      const target = path.join(frozenRoot, entry.path);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, bytes, { flag: 'wx', mode: info.mode & 0o777 });
    }
    if (snapshotSource(candidate).digest !== sourceDigest) fail('INDEPENDENT_SOURCE_CHANGED');
  };
  const runner = async (command, options = {}) => {
    const started = Date.now(); const owner = randomUUID(); const name = `aww-verifier-${owner}`;
    let created = false; let result; let cleanup = 'NOT_CREATED';
    try {
      const cache = nodeCache ? validateNodeCache({ descriptor: nodeCache, review: nodeCacheReview, candidateRoot: candidate, verifierManifestDigest }) : null;
      const plan = containmentPlan(command, { candidateRoot: candidate, images: cache ? { ...images, node: cache.imageId } : images, output: options.output, suite: options.suite });
      if (plan.executable !== 'python' && command.args.some((arg) => /(?:^|[/\\])node_modules(?:[/\\]|$)/u.test(arg)) && !cache) fail('TRUSTED_NODE_DEPENDENCY_CACHE_REQUIRED');
      freeze();
      // A nondefault/remote Docker context could cross the local execution boundary.
      const endpoint = JSON.parse(docker(['context', 'inspect']))[0]?.Endpoints?.docker?.Host;
      if (typeof endpoint !== 'string' || !/^(?:unix:\/\/\/|npipe:\/\/\/\/\.\/pipe\/)/u.test(endpoint)) fail('INDEPENDENT_LOCAL_DOCKER_REQUIRED');
      if (docker(['info', '--format', '{{.OSType}}']).trim() !== 'linux') fail('INDEPENDENT_LINUX_DOCKER_REQUIRED');
      const create = ['create', '--name', name, '--label', `${OWNER}=${owner}`, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--memory', '2g', '--cpus', '2', '--user', '1000:1000',
        '--tmpfs', '/work:rw,nosuid,nodev,exec,uid=1000,gid=1000,size=2147483648', '--tmpfs', '/tmp:rw,nosuid,nodev,uid=1000,gid=1000,size=268435456', '--tmpfs', '/observations:rw,nosuid,nodev,noexec,uid=1000,gid=1000,size=8388608',
        '--mount', `type=bind,source=${frozenRoot},target=/candidate,readonly`, '--entrypoint', 'sh'];
      for (const [key, value] of Object.entries(plan.env)) create.push('--env', `${key}=${value}`);
      create.push(plan.image, '-c', 'while true; do sleep 3600; done');
      docker(create); created = true;
      const inspected = JSON.parse(docker(['inspect', name]))[0];
      if (inspected.Config?.Labels?.[OWNER] !== owner || inspected.HostConfig?.NetworkMode !== 'none'
        || inspected.HostConfig?.ReadonlyRootfs !== true || inspected.HostConfig?.Privileged === true
        || inspected.Config?.User !== '1000:1000' || inspected.Mounts?.filter((mount) => mount.Type === 'bind').length !== 1
        || !inspected.Mounts?.some((mount) => mount.Type === 'bind' && mount.Destination === '/candidate' && mount.RW === false)
        || inspected.Mounts?.some((mount) => !['bind', 'tmpfs'].includes(mount.Type))
        || !inspected.HostConfig?.CapDrop?.includes('ALL')) fail('INDEPENDENT_CONTAINER_BOUNDARY_INVALID');
      docker(['start', name]);
      const runtime = validateContainedRuntime(plan.executable, docker(['exec', name, plan.executable === 'python' ? 'python' : 'node', '--version']));
      const invocation = cache && plan.executable !== 'python'
        ? [CACHE_COPY_AND_EXEC, '--', linkCacheScript, JSON.stringify(cache.roots), plan.cwd, plan.executable, ...plan.args]
        : [COPY_AND_EXEC, '--', plan.cwd, plan.executable, ...plan.args];
      const observation = await executeCommand({ executable: 'docker', args: ['exec', name, 'sh', '-c', ...invocation], cwd: candidate, env: process.env }, options);
      const state = JSON.parse(docker(['inspect', name]))[0].State;
      result = { ...observation, exitCode: observation.timedOut || observation.interrupted || !state.Running || state.OOMKilled ? null : observation.exitCode };
      if (!cache && result.exitCode !== 0 && /ERR_MODULE_NOT_FOUND|Cannot find (?:module|package)/u.test(result.stderr)) result.spawnError = 'TRUSTED_NODE_DEPENDENCY_CACHE_REQUIRED';
      // These files remain untrusted suite observations; only trusted executor
      // collection/assertions may use them. They never overwrite the final report.
      if (options.suite?.collection?.format === 'pytest-junit' || options.suite?.collection?.format === 'operator-json') {
        // Read from inside the running mount namespace. Docker's archive API
        // does not consistently expose tmpfs contents, even while running.
        const archive = docker(['exec', name, 'tar', '-cf', '-', '-C', '/', 'observations'], { encoding: null });
        const files = readObservationTar(archive);
        mkdirSync(plan.evidence, { recursive: true });
        for (const [filename, bytes] of files) writeFileSync(path.join(plan.evidence, filename), bytes, { flag: 'wx' });
      }
      receipts.push({ suiteId: options.suite?.id ?? null, containerId: inspected.Id, imageId: inspected.Image, runtime, policy: 'linux-readonly-no-network-no-socket.v1', owner, status: result.exitCode === 0 ? 'PASS' : 'FAIL' });
    } catch (error) {
      result = { exitCode: null, timedOut: false, interrupted: false, spawnError: String(error.message), stdout: '', stderr: '', durationMs: Date.now() - started };
    } finally {
      if (created) {
        try {
          const inspected = JSON.parse(docker(['inspect', name]))[0];
          if (inspected.Config?.Labels?.[OWNER] !== owner) fail('INDEPENDENT_CLEANUP_OWNER_MISMATCH');
          docker(['rm', '--force', name]);
          const all = docker(['ps', '-a', '--filter', `label=${OWNER}=${owner}`, '--format', '{{.ID}}']).trim();
          if (all) fail('INDEPENDENT_CLEANUP_RESIDUE');
          cleanup = 'PASS';
        } catch { cleanup = 'FAIL'; }
      }
    }
    if (cleanup === 'FAIL') result = { ...result, exitCode: null, spawnError: 'INDEPENDENT_CLEANUP_FAILED' };
    return { ...result, containment: { policy: 'linux-readonly-no-network-no-socket.v1', cleanup }, durationMs: Date.now() - started };
  };
  const cleanup = () => {
    if (frozenRoot) {
      if (path.dirname(frozenRoot) !== realpathSync(os.tmpdir()) || !path.basename(frozenRoot).startsWith('aww-verifier-source-')) fail('INDEPENDENT_SNAPSHOT_CLEANUP_SCOPE');
      rmSync(frozenRoot, { recursive: true }); frozenRoot = null;
    }
    return { status: 'PASS' };
  };
  return { runner, receipts, cleanup, get sourceDigest() { return sourceDigest; } };
}
