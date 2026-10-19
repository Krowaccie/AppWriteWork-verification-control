import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonical, hash, requireThat } from './product-client.mjs';

const OWNER = 'io.appwritework.portable', BROWSER_OWNER = 'io.appwritework.portable-browser';
const ID = /^[a-f0-9]{64}$/u, IMAGE = /^sha256:[a-f0-9]{64}$/u;
const PROJECT = /^sm[89]-[a-z0-9-]{6,36}$/u;
const CHECKS = ['login', 'open-editor', 'edit', 'save-draft', 'publish', 'execute', 'inspect-result'];
const sourceDirectory = path.resolve(import.meta.dirname, '../../..');
function hostPath(value) {
  const slash = String(value).replaceAll('\\', '/');
  const desktop = slash.match(/^\/(?:run\/desktop\/mnt\/host|host_mnt)\/([A-Za-z])(?:\/|$)(.*)$/u);
  if (desktop) return (desktop[1] + ':/' + desktop[2]).replace(/\/$/u, '').toLowerCase();
  if (/^[A-Za-z]:\//u.test(slash)) return slash.replace(/\/$/u, '').toLowerCase();
  return path.resolve(value);
}
const samePath = (a, b) => hostPath(a) === hostPath(b);
const beneath = (root, value) => { const relative = path.relative(path.resolve(root), path.resolve(value)); return relative !== '' && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative); };

export function validateBrowserGateway(row, project) {
  requireThat(PROJECT.test(project) && row && ID.test(row.Id ?? '') && row.State?.Running === true
    && row.Config?.Labels?.[OWNER] === project && row.Config?.Labels?.['com.docker.compose.project'] === project
    && row.Config?.Labels?.['com.docker.compose.service'] === 'gateway', 'BROWSER_GATEWAY_NOT_OWNED');
  return row.Id;
}

function ipv4(value) {
  requireThat(typeof value === 'string' && /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/u.test(value), 'BROWSER_GATEWAY_ADDRESS_INVALID');
  const octets = value.split('.').map(Number);
  requireThat(octets.every(part => part <= 255) && (octets[0] === 10
    || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 192 && octets[1] === 168), 'BROWSER_GATEWAY_ADDRESS_INVALID');
  return octets.reduce((result, part) => (result * 256 + part) >>> 0, 0);
}

// The browser gets a separate namespace on this internal bridge. Gateway's
// unrelated ingress attachment never becomes a browser egress path.
export function validateBrowserNetwork(network, gateway, project) {
  const gatewayId = validateBrowserGateway(gateway, project), networkName = project + '-network';
  requireThat(ID.test(network?.Id ?? '') && network.Name === networkName && network.Driver === 'bridge'
    && network.Internal === true && network.Ingress !== true && network.EnableIPv6 !== true
    && network.Labels?.[OWNER] === project && network.Labels?.['com.docker.compose.project'] === project
    && network.Labels?.['com.docker.compose.network'] === 'lab', 'BROWSER_INTERNAL_NETWORK_REQUIRED');
  const attached = gateway.NetworkSettings?.Networks?.[networkName], member = network.Containers?.[gatewayId];
  requireThat(attached?.NetworkID === network.Id && typeof member?.IPv4Address === 'string', 'BROWSER_GATEWAY_NETWORK_BINDING');
  const gatewayAddress = attached.IPAddress, address = ipv4(gatewayAddress);
  requireThat(network.IPAM?.Config?.length === 1 && typeof network.IPAM.Config[0].Subnet === 'string', 'BROWSER_NETWORK_SUBNET_REQUIRED');
  const [subnetAddress, prefixText, extra] = network.IPAM.Config[0].Subnet.split('/');
  requireThat(extra === undefined && /^(?:[8-9]|[12][0-9]|30)$/u.test(prefixText ?? ''), 'BROWSER_NETWORK_SUBNET_REQUIRED');
  const prefix = Number(prefixText), base = ipv4(subnetAddress), mask = (0xffffffff << (32 - prefix)) >>> 0;
  requireThat((base & mask) >>> 0 === base && (address & mask) >>> 0 === base
    && address !== base && address !== ((base | (~mask >>> 0)) >>> 0)
    && member.IPv4Address === gatewayAddress + '/' + prefix, 'BROWSER_GATEWAY_NETWORK_BINDING');
  return { networkName, networkId: network.Id, gatewayId, gatewayAddress, internal: true };
}

export function browserContainerArguments({ name, project, nonce, networkId, imageId, bundleRoot, inputRoot, observations }) {
  requireThat(PROJECT.test(project) && name.startsWith(project + '-trusted-browser-') && /^[a-z0-9-]+$/.test(name)
    && /^[a-f0-9]{32}$/.test(nonce) && ID.test(networkId) && IMAGE.test(imageId), 'BROWSER_CONTAINER_IDENTITY_INVALID');
  const paths = [bundleRoot, inputRoot, observations].map(value => path.resolve(value));
  requireThat(paths.every(value => !/[,\r\n\0]/.test(value))
    && !samePath(paths[0], paths[1]) && !samePath(paths[0], paths[2]) && !samePath(paths[1], paths[2])
    && !beneath(paths[0], paths[1]) && !beneath(paths[0], paths[2]) && !beneath(paths[1], paths[0]) && !beneath(paths[2], paths[0])
    && !beneath(paths[1], paths[2]) && !beneath(paths[2], paths[1]), 'BROWSER_MOUNT_OVERLAP');
  return ['create', '--name', name, '--label', OWNER + '=' + project, '--label', BROWSER_OWNER + '=' + nonce,
    '--network', networkId, '--dns', '127.0.0.1', '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--pids-limit', '512', '--memory', '1g', '--shm-size', '256m',
    ...['HTTP_PROXY=', 'HTTPS_PROXY=', 'ALL_PROXY=', 'http_proxy=', 'https_proxy=', 'all_proxy=', 'NO_PROXY=localhost', 'no_proxy=localhost'].flatMap(value => ['--env', value]),
    '--tmpfs', '/tmp:rw,nosuid,nodev,uid=1000,gid=1000,size=536870912',
    '--tmpfs', '/home/node:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=33554432',
    '--mount', 'type=bind,source=' + paths[0] + ',target=/verifier,readonly',
    '--mount', 'type=bind,source=' + paths[1] + ',target=/run/browser,readonly',
    '--mount', 'type=bind,source=' + paths[2] + ',target=/observations', imageId];
}

export function validateBrowserContainer(row, expected) {
  requireThat(ID.test(row?.Id ?? '') && row.Image === expected.imageId && row.Name === '/' + expected.name
    && row.Config?.Labels?.[OWNER] === expected.project && row.Config?.Labels?.[BROWSER_OWNER] === expected.nonce
    && row.Config?.User === '1000:1000' && row.HostConfig?.ReadonlyRootfs === true && row.HostConfig?.Privileged !== true
    && row.HostConfig?.CapDrop?.includes('ALL') && !row.HostConfig?.CapAdd?.length
    && row.HostConfig?.SecurityOpt?.some(value => value === 'no-new-privileges' || value === 'no-new-privileges:true')
    && row.HostConfig?.NetworkMode === expected.networkId && canonical(row.HostConfig?.Dns) === canonical(['127.0.0.1'])
    && !row.HostConfig?.ExtraHosts?.length, 'BROWSER_CONTAINER_BOUNDARY_INVALID');
  const networks = row.NetworkSettings?.Networks;
  requireThat(networks && canonical(Object.keys(networks)) === canonical([expected.networkName])
    && (networks[expected.networkName].NetworkID === expected.networkId
      || expected.beforeStart === true && networks[expected.networkName].NetworkID === ''), 'BROWSER_CONTAINER_NETWORK_INVALID');
  const expectedMounts = new Map([['/verifier', [expected.bundleRoot, false]], ['/run/browser', [expected.inputRoot, false]], ['/observations', [expected.observations, true]]]);
  const binds = row.Mounts?.filter(value => value.Type === 'bind');
  requireThat(binds?.length === expectedMounts.size && binds.every(mount => {
    const expectedMount = expectedMounts.get(mount.Destination);
    return expectedMount && samePath(mount.Source, expectedMount[0]) && mount.RW === expectedMount[1];
  }) && row.Mounts.every(mount => ['bind', 'tmpfs'].includes(mount.Type)), 'BROWSER_CONTAINER_MOUNT_INVALID');
  return row.Id;
}

export function validateBrowserReceipt(value, { projectId, expectedValue, networkId, gatewayAddress }) {
  requireThat(value?.schemaVersion === 'portable-product-browser.v1' && value.status === 'PASS' && value.tlsVerification === true
    && value.projectId === projectId && /^[A-Za-z0-9_-]{1,128}$/.test(value.runId ?? '') && value.expectedValue === expectedValue
    && canonical(value.checks) === canonical(CHECKS) && value.externalRequests === 0 && value.unhandledErrors === 0 && value.httpFailures === 0
    && value.network?.networkId === networkId && value.network?.gatewayAddress === gatewayAddress && value.network?.dnsUpstream === '127.0.0.1'
    && value.network?.defaultRouteAbsent === true && value.network?.defaultIpv6RouteAbsent === true
    && Array.isArray(value.operationKinds) && ['artifacts.save-draft.v1', 'artifacts.publish.v1'].every(kind => value.operationKinds.includes(kind)), 'BROWSER_OBSERVATION_BINDING_INVALID');
  return { schemaVersion: value.schemaVersion, status: value.status, tlsVerification: true, projectId, runId: value.runId,
    expectedValue, checks: [...CHECKS], network: { networkId, gatewayAddress, dnsUpstream: '127.0.0.1', defaultRouteAbsent: true, defaultIpv6RouteAbsent: true },
    externalRequests: 0, unhandledErrors: 0, httpFailures: 0 };
}

async function regularBytes(file, limit) {
  const metadata = await fs.lstat(file);
  requireThat(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= limit, 'BROWSER_FILE_NOT_REGULAR_OR_BOUNDED');
  return fs.readFile(file);
}

export async function observeProductBrowser({ state: s, credentials, bindings, bundleRoot, privateRoot, output, docker }) {
  requireThat(PROJECT.test(s?.project) && typeof docker === 'function' && /^[A-Za-z0-9_-]{1,128}$/.test(bindings?.projectId ?? ''), 'BROWSER_FIXTURE_SCOPE_REQUIRED');
  requireThat(credentials?.owner?.email?.endsWith('@portable.invalid') && typeof credentials.owner.password === 'string'
    && credentials.owner.password.length >= 12, 'BROWSER_SYNTHETIC_OWNER_REQUIRED');
  requireThat(samePath(await fs.realpath(bundleRoot), sourceDirectory), 'BROWSER_TRUSTED_BUNDLE_REQUIRED');
  for (const directory of [privateRoot, output]) requireThat(samePath(await fs.realpath(directory), directory), 'BROWSER_PARENT_LINK_REJECTED');
  requireThat(beneath(output, privateRoot) && !beneath(bundleRoot, output) && !samePath(bundleRoot, output), 'BROWSER_OUTPUT_BOUNDARY');
  const nonce = randomBytes(16).toString('hex'), name = s.project + '-trusted-browser-' + nonce.slice(0, 10);
  const tag = 'appwritework-trusted-browser:' + nonce;
  const work = await fs.mkdtemp(path.join(privateRoot, 'browser-'));
  const inputRoot = path.join(work, 'input'), observations = path.join(work, 'observations'), buildRoot = path.join(work, 'build');
  await fs.mkdir(inputRoot, { mode: 0o755 }); await fs.chmod(inputRoot, 0o755);
  await fs.mkdir(observations, { mode: 0o777 }); await fs.chmod(observations, 0o777);
  await fs.mkdir(buildRoot, { mode: 0o700 });
  const expectedValue = 'Independent_browser_' + nonce;
  const fixture = { projectName: 'Independent portable verifier', projectId: bindings.projectId, expectedValue,
    launchNonce: nonce,
    functions: { authoring: s.product?.functions?.['salmora-authoring-py']?.functionId,
      createRun: s.product?.functions?.['runs-create-py']?.functionId, statusRun: s.product?.functions?.['runs-status-py']?.functionId } };
  requireThat(Object.values(fixture.functions).every(value => /^[A-Za-z0-9_-]{1,128}$/.test(value ?? '')), 'BROWSER_FUNCTION_BINDINGS_REQUIRED');
  await fs.writeFile(path.join(inputRoot, 'owner.json'), JSON.stringify({ email: credentials.owner.email, password: credentials.owner.password }), { flag: 'wx', mode: 0o444 });
  const ca = await regularBytes(path.join(s.dir, 'secrets/ca.crt'), 32768);
  requireThat(ca.toString().includes('BEGIN CERTIFICATE') && !ca.toString().includes('PRIVATE KEY'), 'BROWSER_PUBLIC_CA_REQUIRED');
  await fs.writeFile(path.join(inputRoot, 'ca.crt'), ca, { flag: 'wx', mode: 0o444 });
  for (const filename of ['owner.json', 'ca.crt']) await fs.chmod(path.join(inputRoot, filename), 0o444);
  const dockerfile = await regularBytes(path.join(bundleRoot, 'verification/controller/portable/product-browser.Dockerfile'), 8192);
  const script = await regularBytes(path.join(bundleRoot, 'verification/controller/portable/product-browser.cjs'), 32768);
  await fs.writeFile(path.join(buildRoot, 'Dockerfile'), dockerfile, { flag: 'wx' });
  const result = { schemaVersion: 'trusted-product-browser-run.v1', status: 'IN_PROGRESS', cleanup: { status: 'NOT_RUN' },
    project: s.project, scriptDigest: hash(script), dockerfileDigest: hash(dockerfile), expectedValue };
  let imageId, containerId;
  try {
    const gatewayIds = String(await docker(['ps', '-q', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + s.project,
      '--filter', 'label=com.docker.compose.service=gateway'])).trim().split(/\s+/).filter(Boolean);
    requireThat(gatewayIds.length === 1 && ID.test(gatewayIds[0]), 'BROWSER_GATEWAY_REQUIRED');
    const gateway = JSON.parse(await docker(['inspect', gatewayIds[0]]))[0];
    const network = validateBrowserNetwork(JSON.parse(await docker(['network', 'inspect', s.project + '-network']))[0], gateway, s.project);
    result.network = network;
    fixture.gatewayAddress = network.gatewayAddress;
    fixture.networkId = network.networkId;
    await fs.writeFile(path.join(inputRoot, 'fixture.json'), JSON.stringify(fixture), { flag: 'wx', mode: 0o444 });
    await fs.chmod(path.join(inputRoot, 'fixture.json'), 0o444);
    await docker(['build', '--label', OWNER + '=' + s.project, '--label', BROWSER_OWNER + '=' + nonce, '--tag', tag, buildRoot], { timeout: 300_000 });
    const image = JSON.parse(await docker(['image', 'inspect', tag]))[0]; imageId = image.Id;
    requireThat(IMAGE.test(imageId) && image.Config?.Labels?.[OWNER] === s.project && image.Config?.Labels?.[BROWSER_OWNER] === nonce, 'BROWSER_IMAGE_IDENTITY_INVALID');
    result.imageId = imageId;
    const expected = { name, project: s.project, nonce, ...network, imageId, bundleRoot, inputRoot, observations };
    containerId = String(await docker(browserContainerArguments(expected))).trim();
    requireThat(ID.test(containerId), 'BROWSER_CREATED_ID_INVALID');
    validateBrowserContainer(JSON.parse(await docker(['inspect', containerId]))[0], { ...expected, beforeStart: true });
    await docker(['start', containerId]);
    // Trusted script waits for this host-owned gate before launching Chromium.
    // Inspect actual attachment after Docker has installed the namespace.
    validateBrowserContainer(JSON.parse(await docker(['inspect', containerId]))[0], expected);
    await fs.writeFile(path.join(inputRoot, 'launch.json'), JSON.stringify({ nonce }), { flag: 'wx', mode: 0o444 });
    await fs.chmod(path.join(inputRoot, 'launch.json'), 0o444);
    const exit = String(await docker(['wait', containerId], { timeout: 360_000 })).trim();
    requireThat(exit === '0', 'BROWSER_EXECUTION_FAILED');
    const stdout = String(await docker(['logs', containerId], { timeout: 30_000 }));
    requireThat(Buffer.byteLength(stdout) <= 65536, 'BROWSER_STDOUT_LIMIT');
    const stopped = JSON.parse(await docker(['inspect', containerId]))[0]; validateBrowserContainer(stopped, expected);
    requireThat(stopped.State?.Running === false && stopped.State?.ExitCode === 0 && stopped.State?.OOMKilled !== true, 'BROWSER_EXECUTION_FAILED');
    const receipt = JSON.parse(await regularBytes(path.join(observations, 'browser-observed.json'), 65536));
    const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
    requireThat(lines.length === 1 && canonical(JSON.parse(lines[0])) === canonical(receipt), 'BROWSER_RECEIPT_STDOUT_DRIFT');
    result.observation = validateBrowserReceipt(receipt, { projectId: bindings.projectId, expectedValue, ...network });
    const screenshot = await regularBytes(path.join(observations, 'browser.png'), 8 * 1024 * 1024);
    requireThat(screenshot.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')), 'BROWSER_SCREENSHOT_REQUIRED');
    result.screenshotDigest = hash(screenshot);
    const networkAfter = validateBrowserNetwork(JSON.parse(await docker(['network', 'inspect', network.networkId]))[0],
      JSON.parse(await docker(['inspect', network.gatewayId]))[0], s.project);
    requireThat(canonical(networkAfter) === canonical(network), 'BROWSER_NETWORK_DRIFT');
    requireThat(hash(await regularBytes(path.join(bundleRoot, 'verification/controller/portable/product-browser.cjs'), 32768)) === result.scriptDigest
      && hash(await regularBytes(path.join(bundleRoot, 'verification/controller/portable/product-browser.Dockerfile'), 8192)) === result.dockerfileDigest, 'BROWSER_TRUSTED_SOURCE_DRIFT');
    result.status = 'PASS';
  } catch (error) {
    result.status = 'FAIL'; result.reason = /^BROWSER_[A-Z0-9_]+$/.test(error.message) ? error.message : 'BROWSER_OWNED_EXECUTION_FAILED';
  } finally {
    const failures = [];
    if (containerId && ID.test(containerId)) try {
      const row = JSON.parse(await docker(['inspect', containerId]))[0];
      requireThat(row.Id === containerId && row.Name === '/' + name && row.Config?.Labels?.[OWNER] === s.project
        && row.Config?.Labels?.[BROWSER_OWNER] === nonce, 'BROWSER_CLEANUP_CONTAINER_OWNER');
      await docker(['rm', '--force', containerId]);
      requireThat(!String(await docker(['ps', '-aq', '--no-trunc', '--filter', 'label=' + BROWSER_OWNER + '=' + nonce])).trim(), 'BROWSER_CONTAINER_RESIDUE');
    } catch { failures.push('container'); }
    if (imageId) try {
      const row = JSON.parse(await docker(['image', 'inspect', tag]))[0];
      requireThat(row.Id === imageId && row.Config?.Labels?.[OWNER] === s.project && row.Config?.Labels?.[BROWSER_OWNER] === nonce, 'BROWSER_CLEANUP_IMAGE_OWNER');
      await docker(['image', 'rm', tag]);
      requireThat(!String(await docker(['image', 'ls', '-q', '--filter', 'reference=' + tag])).trim(), 'BROWSER_IMAGE_RESIDUE');
    } catch { failures.push('image'); }
    result.cleanup = { status: failures.length ? 'FAIL' : 'PASS', failures };
    if (failures.length) result.status = 'FAIL';
    await fs.writeFile(path.join(output, 'product-browser.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  }
  return result;
}
