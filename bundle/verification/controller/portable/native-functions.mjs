// Local self-hosted packaging with the unchanged native Appwrite build recipe.
// Cloud/Test publication remains governed separately.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
const execute=promisify(execFile);
const COMPONENTS=['salmora-access-py','salmora-authoring-py','salmora-content-py','project-snapshots-py'];
const FUNCTION_SCOPES=['buckets.read','files.read','files.write'];
const offlineContexts = new Map();
export function configureOfflinePackaging({ sourceRoot, context, project, cacheRoot }) {
  requireThat(/^sm[89]-[a-z0-9-]{6,36}$/u.test(project), 'INDEPENDENT_FUNCTION_PROJECT_INVALID');
  offlineContexts.set(path.resolve(sourceRoot), { context, project, cacheRoot, prepared: new Map() });
}
export function validateHashedLock(text) {
  requireThat(typeof text === 'string' && Buffer.byteLength(text) <= 1024 * 1024, 'INDEPENDENT_FUNCTION_LOCK_LIMIT');
  const lines = text.replace(/\\\r?\n/gu, ' ').split(/\r?\n/u).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  requireThat(lines.length > 0 && lines.every(line => /^[A-Za-z0-9][A-Za-z0-9_.-]*==[0-9][A-Za-z0-9.+-]*(?:\s+--hash=sha256:[a-f0-9]{64})+$/u.test(line)), 'INDEPENDENT_FUNCTION_LOCK_UNSAFE');
  return lines.length;
}
async function prepareWheels(sourceRoot, relativeLock, component, pythonBase) {
  const settings = offlineContexts.get(path.resolve(sourceRoot));
  requireThat(settings, 'INDEPENDENT_FUNCTION_OFFLINE_CONFIGURATION_REQUIRED');
  const lock = await fs.readFile(path.join(sourceRoot, relativeLock), 'utf8'); validateHashedLock(lock);
  const lockDigest = sha(lock);
  if (settings.prepared.has(lockDigest)) return settings.prepared.get(lockDigest);
  const directory = path.join(settings.cacheRoot, component);
  const input = path.join(directory, 'input'), wheels = path.join(directory, 'wheels');
  await fs.mkdir(input, { recursive: true, mode: 0o700 }); await fs.mkdir(wheels, { mode: 0o700 });
  await fs.writeFile(path.join(input, 'requirements.lock'), lock, { flag: 'wx' });
  // This online stage sees only the reviewed lock, never candidate source,
  // credentials, Docker socket or verifier reports. Wheels prohibit setup hooks.
  await execute('docker', ['--context', settings.context, 'run', '--rm', '--name', settings.project + '-wheels-' + component, '--label', 'io.appwritework.portable=' + settings.project,
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '512m', '--pids-limit', '128', '--tmpfs', '/tmp:rw,nosuid,nodev,size=134217728',
    '--mount', `type=bind,source=${input},target=/inputs,readonly`, '--mount', `type=bind,source=${wheels},target=/wheels`,
    '--entrypoint', 'python', pythonBase, '-I', '-m', 'pip', '--isolated', 'download', '--no-cache-dir', '--no-deps', '--only-binary=:all:', '--require-hashes',
    '--index-url', 'https://pypi.org/simple', '-r', '/inputs/requirements.lock', '--dest', '/wheels'],
    { windowsHide: true, timeout: 300_000, maxBuffer: 2 * 1024 * 1024 });
  const files = []; let total = 0;
  for (const name of await fs.readdir(wheels)) {
    const info = await fs.lstat(path.join(wheels, name));
    requireThat(/^[A-Za-z0-9_.+-]+\.whl$/u.test(name) && info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.size <= 64 * 1024 * 1024, 'INDEPENDENT_FUNCTION_WHEEL_INVALID');
    total += info.size; requireThat(total <= 256 * 1024 * 1024 && files.length < 200, 'INDEPENDENT_FUNCTION_WHEEL_LIMIT');
    files.push({ name, digest: sha(await fs.readFile(path.join(wheels, name))) });
  }
  requireThat(files.length > 0, 'INDEPENDENT_FUNCTION_WHEELS_MISSING');
  const result = { directory: wheels, lockDigest, files, onlineSourceVisible: false };
  settings.prepared.set(lockDigest, result); return result;
}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function requireThat(value,code){if(!value)throw new Error(code);}
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']'
  :value!==null&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}':JSON.stringify(value);
export async function prepareArchive({ sourceRoot, output, component, python, publicCa, allowedComponents = COMPONENTS }) {
  requireThat(allowedComponents.includes(component), 'M1_COMPONENT_INVALID');
  const trustedRecipe = path.resolve(import.meta.dirname, '../../../tools/build/native_function.py');
  const isolatedIdentity = "import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('trusted_native_recipe',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps(m.identity(sys.argv[2],Path(sys.argv[3]))))";
  const { stdout } = await execute(python, ['-I', '-S', '-B', '-c', isolatedIdentity, trustedRecipe, component, sourceRoot],
    { cwd: import.meta.dirname, shell: false, windowsHide: true, timeout: 30_000, maxBuffer: 8 * 1024 * 1024 });
  const identity = JSON.parse(stdout);
  requireThat(identity.logicalId === component && identity.schemaVersion === 'native-function-build.v1', 'M1_NATIVE_IDENTITY_INVALID');
  const locks = Object.keys(identity.files).filter(name => name.endsWith('/requirements.lock') && !name.startsWith('packages/'));
  requireThat(locks.length === 1, 'INDEPENDENT_FUNCTION_LOCK_AMBIGUOUS');
  const pins = JSON.parse(await fs.readFile(path.resolve(import.meta.dirname, '../../../infra/portable/images.lock.json'), 'utf8'));
  const wheels = await prepareWheels(sourceRoot, locks[0], component, pins['worker-base'].reference);
  const directory = path.join(output, `${component}-source`);
  await fs.mkdir(directory, { recursive: false });
  for (const [relative, expected] of Object.entries(identity.files)) {
    requireThat(!path.isAbsolute(relative) && !relative.split(/[\\/]/).includes('..'), 'M1_NATIVE_SOURCE_PATH_INVALID');
    const bytes = Buffer.from((await fs.readFile(path.join(sourceRoot, relative), 'utf8')).replace(/\r\n/g, '\n'));
    requireThat(sha(bytes) === expected, 'M1_NATIVE_SOURCE_DRIFT');
    const target = path.join(directory, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, bytes, { flag: 'wx' });
  }
  // Native staging/identity is trusted code. Candidate installer recipes are
  // preserved in original identity but never executed in this fixture.
  const recipeTarget = path.join(directory, 'tools/build/native_function.py');
  let recipe = (await fs.readFile(trustedRecipe, 'utf8')).replaceAll('\r\n', '\n');
  recipe = recipe.replace('"install", "--require-hashes",', '"install", "--no-index", "--find-links", str(ROOT / "verifier-wheels"), "--require-hashes",');
  requireThat(recipe.includes('"--no-index"'), 'INDEPENDENT_FUNCTION_OFFLINE_RECIPE_MISSING');
  await fs.writeFile(recipeTarget, recipe);
  const effectiveFiles = { ...identity.files, 'tools/build/native_function.py': sha(recipe) };
  const effectiveIdentity = { ...identity, files: effectiveFiles, inputsSha256: sha(canonical(effectiveFiles)) };
  const wheelTarget = path.join(directory, 'verifier-wheels'); await fs.mkdir(wheelTarget);
  for (const file of wheels.files) await fs.copyFile(path.join(wheels.directory, file.name), path.join(wheelTarget, file.name));
  const ca = await fs.readFile(publicCa);
  requireThat(ca.toString().includes('-----BEGIN CERTIFICATE-----') && !ca.toString().includes('PRIVATE KEY'), 'M1_PUBLIC_CA_REQUIRED');
  await fs.writeFile(path.join(directory, 'm1-ca.crt'), ca, { flag: 'wx' });
  const archivePath = path.join(output, `${component}.tar.gz`);
  await execute('tar', ['-czf', archivePath, '-C', directory, '.'],
    { shell: false, windowsHide: true, timeout: 60_000, maxBuffer: 1024 * 1024 });
  const result = { component, identity, archivePath, archiveSha256: sha(await fs.readFile(archivePath)),
    publicCaSha256: sha(ca), caRuntimePath: '/usr/local/server/src/function/m1-ca.crt',
    command: `python tools/build/native_function.py build ${component}`,
    effectiveIdentity, dependencyPreparation: { lockDigest: wheels.lockDigest, wheels: wheels.files, onlineSourceVisible: false },
    effectiveRecipeSha256: sha(recipe), candidateInstallerRecipeQualified: false,
    delivery: 'Independent fixture uses pinned staging and hash-locked offline wheels; candidate native installer is outside this assertion scope' };
  await fs.writeFile(path.join(output, `${component}-inputs.json`), JSON.stringify(result, null, 2) + '\n');
  return result;
}

export async function poll({ read, ready, failed = () => false, timeout = 600_000, label, save }) {
  const deadline = Date.now() + timeout;
  do {
    const result = await read();
    if (ready(result)) return result;
    if (failed(result)) { await save(`${label}-failed`, result); throw new Error(`M1_${label.toUpperCase()}_FAILED`); }
    await pause(1000);
  } while (Date.now() < deadline);
  throw new Error(`M1_${label.toUpperCase()}_TIMEOUT`);
}

export async function verifyFunctionConfiguration({request,functionId,environment,executeRoles=['users'],scopes=FUNCTION_SCOPES}) {
  const route=`/functions/${functionId}`;
    const current = (await request('GET', route)).value;
    requireThat(current.runtime === 'python-3.12' && current.enabled && current.timeout === 60
      && canonical(current.execute) === canonical(executeRoles) && !current.schedule && !current.events.length
      && canonical([...current.scopes].sort()) === canonical([...scopes].sort()), 'M5_FUNCTION_CONFIG_DRIFT');
    const vars = (await request('GET', `${route}/variables`)).value.variables;
    // Appwrite deliberately omits write-only secret values on readback. Their
    // metadata is checked here; the initial create ACK remains their evidence.
    requireThat(vars.length === Object.keys(environment).length && vars.every(v => Object.hasOwn(environment,v.key)
      && v.secret === /KEY|PASSWORD|SECRET|CONFIG_JSON|DSN|URL/.test(v.key)
      && (v.secret ? v.value === '' : String(environment[v.key]) === v.value)),
      'M5_FUNCTION_ENVIRONMENT_DRIFT');
}

export async function deploy({ request, component, functionId, archive, environment, save, register, executeRoles = ['users'], existing = false, scopes = FUNCTION_SCOPES }) {
  requireThat(component === archive.component && sha(await fs.readFile(archive.archivePath)) === archive.archiveSha256,
    'M1_DEPLOYMENT_ARCHIVE_DRIFT');
  const route = `/functions/${functionId}`;
  if (!existing) await request('POST', '/functions', { functionId, name: `M1 local ${component}`, runtime: 'python-3.12',
    execute: executeRoles, events: [], schedule: '', timeout: 60, enabled: true, logging: true,
    scopes,
    entrypoint: 'appwrite_function/main.py', commands: archive.command });
  const configured = [];
  if(existing)await verifyFunctionConfiguration({request,functionId,environment,executeRoles,scopes});
  for (const [key, value] of Object.entries(environment)) {
    const secret = /KEY|PASSWORD|SECRET|CONFIG_JSON|DSN|URL/.test(key);
    const response = existing ? { value: {} } : await request('POST', `${route}/variables`, { variableId: 'unique()', key, value: String(value), secret });
    configured.push({ key, secret, id: response.value.$id, valueSha256: secret ? null : sha(String(value)) });
  }
  await save(`${component}-configuration`, { functionId, variables: configured, metadataBackend: environment.SALMORA_METADATA_BACKEND });
  const form = new FormData();
  form.set('entrypoint', 'appwrite_function/main.py'); form.set('commands', archive.command); form.set('activate', 'true');
  form.set('code', new Blob([await fs.readFile(archive.archivePath)], { type: 'application/gzip' }), `${component}.tar.gz`);
  const response = await request('POST', `${route}/deployments`, form);
  await save(`${component}-deployment-primary`, response); // First ACK before any secondary read.
  const deploymentId = response.value?.$id;
  requireThat(deploymentId, 'M1_DEPLOYMENT_ID_MISSING');
  await register({ deploymentId });
  const deployment = await poll({ label: component, save, read: async () => (await request('GET', `${route}/deployments/${deploymentId}`)).value,
    ready: value => value.status === 'ready', failed: value => ['failed', 'canceled'].includes(value.status) });
  await save(`${component}-deployment-ready`, deployment);
  const active = (await request('GET', route)).value;
  requireThat((active.deploymentId ?? active.deployment) === deploymentId, 'M1_ACTIVE_DEPLOYMENT_MISMATCH');
  return { functionId, deploymentId, component, nativeInputsSha256: archive.identity.inputsSha256,
    archiveSha256: archive.archiveSha256, publicCaSha256: archive.publicCaSha256 };
}
