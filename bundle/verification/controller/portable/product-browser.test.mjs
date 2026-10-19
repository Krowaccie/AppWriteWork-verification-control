import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import { browserContainerArguments, validateBrowserContainer, validateBrowserGateway, validateBrowserNetwork, validateBrowserReceipt } from './product-browser.mjs';
const { assertNoDefaultRoutes, browserResolutionArguments } = createRequire(import.meta.url)('./product-browser.cjs');

const project = 'sm9-owned-browser', gatewayId = 'a'.repeat(64), containerId = 'b'.repeat(64), networkId = 'e'.repeat(64), imageId = 'sha256:' + 'c'.repeat(64), nonce = 'd'.repeat(32);
const networkName = project + '-network';
const expected = { project, gatewayId, networkId, networkName, imageId, nonce, name: project + '-trusted-browser-0123456789',
  bundleRoot: path.resolve('trusted-verifier'), inputRoot: path.resolve('private/attempt/input'), observations: path.resolve('private/attempt/observations') };
const labels = { 'io.appwritework.portable': project, 'io.appwritework.portable-browser': nonce };
const makeRow = () => ({ Id: containerId, Image: imageId, Name: '/' + expected.name,
  Config: { User: '1000:1000', Labels: { ...labels } },
  HostConfig: { ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], CapAdd: [], SecurityOpt: ['no-new-privileges'], NetworkMode: networkId, Dns: ['127.0.0.1'] },
  NetworkSettings: { Networks: { [networkName]: { NetworkID: networkId, IPAddress: '172.28.8.20' } } },
  Mounts: [{ Type: 'bind', Source: expected.bundleRoot, Destination: '/verifier', RW: false },
    { Type: 'bind', Source: expected.inputRoot, Destination: '/run/browser', RW: false },
    { Type: 'bind', Source: expected.observations, Destination: '/observations', RW: true },
    { Type: 'tmpfs', Source: '', Destination: '/tmp', RW: true }], State: { Running: false, ExitCode: 0 } });
const gateway = () => ({ Id: gatewayId, State: { Running: true }, Config: { Labels: {
  'io.appwritework.portable': project, 'com.docker.compose.project': project, 'com.docker.compose.service': 'gateway' } },
  NetworkSettings: { Networks: { [networkName]: { NetworkID: networkId, IPAddress: '172.28.8.10' },
    [project + '_ingress']: { NetworkID: 'f'.repeat(64), IPAddress: '172.29.9.5' } } } });
const internalNetwork = () => ({ Id: networkId, Name: networkName, Driver: 'bridge', Internal: true, Ingress: false, EnableIPv6: false,
  Labels: { 'io.appwritework.portable': project, 'com.docker.compose.project': project, 'com.docker.compose.network': 'lab' },
  IPAM: { Config: [{ Subnet: '172.28.8.0/24', Gateway: '172.28.8.1' }] }, Containers: { [gatewayId]: { IPv4Address: '172.28.8.10/24' } } });
const fixture = { projectId: 'owned-project', expectedValue: 'Independent_browser_' + nonce, networkId, gatewayAddress: '172.28.8.10' };
const receipt = () => ({ schemaVersion: 'portable-product-browser.v1', status: 'PASS', tlsVerification: true, projectId: fixture.projectId, expectedValue: fixture.expectedValue,
  runId: 'real-browser-run', checks: ['login', 'open-editor', 'edit', 'save-draft', 'publish', 'execute', 'inspect-result'],
  network: { networkId, gatewayAddress: fixture.gatewayAddress, dnsUpstream: '127.0.0.1', defaultRouteAbsent: true, defaultIpv6RouteAbsent: true },
  operationKinds: ['artifacts.publish.v1', 'artifacts.save-draft.v1'], externalRequests: 0, unhandledErrors: 0, httpFailures: 0 });

test('only an actual running gateway with the exact project ownership is eligible', () => {
  assert.equal(validateBrowserGateway(gateway(), project), gatewayId);
  for (const mutated of [
    { ...gateway(), Id: 'alias' },
    { ...gateway(), State: { Running: false } },
    { ...gateway(), Config: { Labels: { ...gateway().Config.Labels, 'io.appwritework.portable': 'foreign' } } },
    { ...gateway(), Config: { Labels: { ...gateway().Config.Labels, 'com.docker.compose.project': 'foreign' } } },
    { ...gateway(), Config: { Labels: { ...gateway().Config.Labels, 'com.docker.compose.service': 'appwrite' } } },
  ]) assert.throws(() => validateBrowserGateway(mutated, project), /BROWSER_GATEWAY_NOT_OWNED/);
});

test('internal bridge binding rejects ingress and pins actual gateway address/membership', () => {
  assert.deepEqual(validateBrowserNetwork(internalNetwork(), gateway(), project), { networkName, networkId, gatewayId, gatewayAddress: '172.28.8.10', internal: true });
  for (const modify of [
    row => { row.Internal = false; }, row => { row.Ingress = true; }, row => { row.EnableIPv6 = true; },
    row => { row.Name = project + '_ingress'; }, row => { row.Driver = 'host'; }, row => { row.Id = 'alias'; },
    row => { row.Labels['io.appwritework.portable'] = 'foreign'; }, row => { row.Labels['com.docker.compose.project'] = 'foreign'; },
    row => { row.Labels['com.docker.compose.network'] = 'ingress'; }, row => { delete row.Containers[gatewayId]; },
    row => { row.Containers[gatewayId].IPv4Address = '172.28.8.11/24'; }, row => { row.IPAM.Config[0].Subnet = '172.28.9.0/24'; },
  ]) { const row = internalNetwork(); modify(row); assert.throws(() => validateBrowserNetwork(row, gateway(), project), /BROWSER_INTERNAL_NETWORK_REQUIRED|BROWSER_GATEWAY_NETWORK_BINDING/); }
});

test('gateway address must be an exact private IPv4 member of the owned subnet', () => {
  for (const address of ['127.0.0.1', '1.1.1.1', 'localhost', '172.028.8.10', '172.28.8.256', '172.28.9.10', '172.28.8.0', '172.28.8.255', '172.28.8.10,MAP * proxy.invalid']) {
    const row = gateway(), network = internalNetwork();
    row.NetworkSettings.Networks[networkName].IPAddress = address;
    network.Containers[gatewayId].IPv4Address = address + '/24';
    assert.throws(() => validateBrowserNetwork(network, row, project), /BROWSER_GATEWAY_ADDRESS_INVALID|BROWSER_GATEWAY_NETWORK_BINDING/);
  }
  const row = gateway(); row.NetworkSettings.Networks[networkName].NetworkID = 'f'.repeat(64);
  assert.throws(() => validateBrowserNetwork(internalNetwork(), row, project), /BROWSER_GATEWAY_NETWORK_BINDING/);
});

test('container plan uses exact internal network ID, no DNS forwarding or proxy and three minimal mounts', () => {
  const argv = browserContainerArguments(expected);
  assert.equal(argv[0], 'create'); assert.equal(argv.at(-1), imageId);
  assert.equal(argv[argv.indexOf('--network') + 1], networkId);
  assert.equal(argv[argv.indexOf('--dns') + 1], '127.0.0.1');
  assert.ok(argv.includes('HTTP_PROXY=')); assert.ok(argv.includes('HTTPS_PROXY=')); assert.ok(argv.includes('ALL_PROXY='));
  assert.ok(argv.every(value => !value.startsWith('container:')));
  assert.equal(argv[argv.indexOf('--user') + 1], '1000:1000');
  assert.ok(argv.includes('--read-only')); assert.ok(argv.includes('ALL')); assert.ok(argv.includes('no-new-privileges'));
  const mounts = argv.filter((value, index) => argv[index - 1] === '--mount');
  assert.equal(mounts.length, 3);
  assert.equal(mounts.filter(value => value.endsWith('readonly')).length, 2);
  assert.ok(mounts.some(value => value.endsWith('target=/observations')));
  assert.ok(argv.every(value => !value.includes('docker.sock') && !value.includes('npipe:') && !value.includes('apiKey')));
});

test('plan rejects network aliases, unpinned images and mount overlap/injection', () => {
  for (const changed of [
    { networkId: 'foreign-network' }, { imageId: 'playwright:latest' }, { name: 'foreign-browser' }, { nonce: 'not-a-nonce' },
    { inputRoot: expected.bundleRoot }, { observations: expected.bundleRoot }, { observations: expected.inputRoot },
    { inputRoot: path.join(expected.bundleRoot, 'private') }, { bundleRoot: path.join(expected.inputRoot, 'source') },
    { observations: path.join(expected.inputRoot, 'observations') }, { inputRoot: 'root,target=/etc' },
  ]) assert.throws(() => browserContainerArguments({ ...expected, ...changed }), /BROWSER_CONTAINER_IDENTITY_INVALID|BROWSER_MOUNT_OVERLAP/);
});

test('actual inspected container must preserve nonprivileged user, read-only root and network identity', () => {
  assert.equal(validateBrowserContainer(makeRow(), expected), containerId);
  for (const modify of [
    row => { row.Config.User = '0'; }, row => { row.HostConfig.Privileged = true; },
    row => { row.HostConfig.ReadonlyRootfs = false; }, row => { row.HostConfig.CapDrop = []; },
    row => { row.HostConfig.CapAdd = ['SYS_ADMIN']; }, row => { row.HostConfig.SecurityOpt = []; },
    row => { row.HostConfig.NetworkMode = 'host'; }, row => { row.HostConfig.NetworkMode = 'container:' + gatewayId; },
    row => { row.HostConfig.Dns = ['8.8.8.8']; }, row => { row.HostConfig.Dns = []; }, row => { row.HostConfig.ExtraHosts = ['foreign:1.1.1.1']; },
    row => { row.Image = 'sha256:' + 'f'.repeat(64); }, row => { row.Config.Labels['io.appwritework.portable'] = 'foreign'; },
    row => { row.Config.Labels['io.appwritework.portable-browser'] = 'foreign'; }, row => { row.Name = '/foreign'; },
  ]) { const row = makeRow(); modify(row); assert.throws(() => validateBrowserContainer(row, expected), /BROWSER_CONTAINER_BOUNDARY_INVALID/); }
});

test('actual attached network must be the sole immutable owned internal network', () => {
  for (const modify of [
    row => { row.NetworkSettings.Networks[networkName].NetworkID = 'f'.repeat(64); },
    row => { row.NetworkSettings.Networks[networkName].NetworkID = ''; },
    row => { row.NetworkSettings.Networks[project + '_ingress'] = { NetworkID: 'f'.repeat(64) }; },
    row => { delete row.NetworkSettings.Networks[networkName]; },
  ]) { const row = makeRow(); modify(row); assert.throws(() => validateBrowserContainer(row, expected), /BROWSER_CONTAINER_NETWORK_INVALID/); }
  const created = makeRow(); created.NetworkSettings.Networks[networkName].NetworkID = '';
  assert.equal(validateBrowserContainer(created, { ...expected, beforeStart: true }), containerId);
});

test('actual mounts reject writable verifier, whole-state credentials, Docker socket and unexpected volume', () => {
  for (const modify of [
    row => { row.Mounts[0].RW = true; }, row => { row.Mounts[1].RW = true; }, row => { row.Mounts[2].RW = false; },
    row => { row.Mounts[1].Source = path.dirname(expected.inputRoot); },
    row => { row.Mounts.push({ Type: 'bind', Source: '/var/run/docker.sock', Destination: '/var/run/docker.sock', RW: true }); },
    row => { row.Mounts.push({ Type: 'volume', Source: 'extra', Destination: '/extra', RW: true }); },
    row => { row.Mounts[0].Destination = '/another-verifier'; },
  ]) { const row = makeRow(); modify(row); assert.throws(() => validateBrowserContainer(row, expected), /BROWSER_CONTAINER_MOUNT_INVALID/); }
});

test('Docker Desktop source aliases still map to the exact Windows host paths', () => {
  const windows = { ...expected, bundleRoot: 'C:\\Users\\Task\\verifier', inputRoot: 'C:\\Users\\Task\\private\\input', observations: 'C:\\Users\\Task\\private\\observations' };
  const row = makeRow();
  row.Mounts[0].Source = '/run/desktop/mnt/host/c/Users/Task/verifier';
  row.Mounts[1].Source = '/host_mnt/c/Users/Task/private/input';
  row.Mounts[2].Source = 'c:/Users/Task/private/observations';
  assert.equal(validateBrowserContainer(row, windows), containerId);
  row.Mounts[1].Source = '/host_mnt/c/Users/Task/private';
  assert.throws(() => validateBrowserContainer(row, windows), /BROWSER_CONTAINER_MOUNT_INVALID/);
});

test('receipt binds the trusted browser checks to this project, unpredictable output and actual run', () => {
  assert.equal(validateBrowserReceipt(receipt(), fixture).runId, 'real-browser-run');
  for (const changed of [
    { status: 'FAIL' }, { projectId: 'foreign' }, { expectedValue: 'copied old result' }, { runId: '../file' },
    { tlsVerification: false }, { externalRequests: 1 }, { unhandledErrors: 1 }, { httpFailures: 1 },
    { checks: ['login'] }, { operationKinds: ['artifacts.save-draft.v1'] },
    { network: undefined }, { network: { ...receipt().network, defaultRouteAbsent: false } },
    { network: { ...receipt().network, defaultIpv6RouteAbsent: false } }, { network: { ...receipt().network, dnsUpstream: '8.8.8.8' } },
    { network: { ...receipt().network, networkId: 'f'.repeat(64) } }, { network: { ...receipt().network, gatewayAddress: '1.1.1.1' } },
  ]) assert.throws(() => validateBrowserReceipt({ ...receipt(), ...changed }, fixture), /BROWSER_OBSERVATION_BINDING_INVALID/);
});

test('browser script blocks foreign HTTP/WebSockets and relies on real Function responses', async () => {
  const script = await fs.readFile(new URL('product-browser.cjs', import.meta.url), 'utf8');
  assert.ok(script.includes("serviceWorkers: 'block'")); assert.ok(script.includes("context.routeWebSocket('**/*'"));
  assert.ok(script.includes("url.hostname === 'localhost' && url.port === ''"));
  assert.ok(script.includes("'--host-resolver-rules=MAP localhost ' + address + ',MAP * ~NOTFOUND'"));
  assert.ok(script.includes("'--dns-prefetch-disable'")); assert.ok(script.includes("'--no-proxy-server'"));
  assert.ok(script.includes('DnsOverHttps')); assert.ok(script.includes("fs.existsSync('/run/browser/launch.json')"));
  assert.ok(script.includes("fs.readFileSync('/proc/net/route', 'utf8')"));
  assert.ok(script.includes('requested.payload.projectId !== fixture.projectId'));
  assert.ok(script.includes('value.operationId !== requested.operationId'));
  assert.ok(script.includes("fs.writeFileSync('/observations/browser-observed.json'"));
  assert.equal(/ignoreHTTPSErrors|ignore-certificate-errors|NODE_TLS_REJECT_UNAUTHORIZED|dev\/labs|apiKey|docker\.sock/.test(script), false);
});

test('actual route guard rejects IPv4/IPv6 default routes before launching the browser', () => {
  const header = 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n';
  const internal = header + 'eth0\t00081CAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n';
  assert.deepEqual(assertNoDefaultRoutes(internal), { defaultRouteAbsent: true, defaultIpv6RouteAbsent: true });
  const external = 'eth0\t00000000\t01081CAC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n';
  assert.throws(() => assertNoDefaultRoutes(internal + external), /BROWSER_DEFAULT_ROUTE_FORBIDDEN/);
  assert.throws(() => assertNoDefaultRoutes(''), /BROWSER_ROUTE_TABLE_INVALID/);
  assert.throws(() => assertNoDefaultRoutes(header), /BROWSER_ROUTE_TABLE_INVALID/);
  assert.throws(() => assertNoDefaultRoutes(internal + 'malformed route'), /BROWSER_ROUTE_TABLE_INVALID/);
  const v6default = '0'.repeat(32) + ' 00 ' + '0'.repeat(32) + ' 00 ' + '0'.repeat(32) + ' 00000000 00000000 00000000 00000003 eth0\n';
  assert.throws(() => assertNoDefaultRoutes(internal, v6default), /BROWSER_IPV6_DEFAULT_ROUTE_FORBIDDEN/);
  assert.throws(() => assertNoDefaultRoutes(internal, 'malformed ipv6'), /BROWSER_IPV6_ROUTE_TABLE_INVALID/);
  const v6rejected = v6default.replace('00000003 eth0', '00200200 lo');
  assert.equal(assertNoDefaultRoutes(internal, v6rejected).defaultIpv6RouteAbsent, true);
});

test('actual Chromium resolver arguments map only localhost and suppress DNS/proxy egress', () => {
  const args = browserResolutionArguments('172.28.8.10');
  assert.deepEqual(args, ['--no-proxy-server', '--dns-prefetch-disable', '--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn,PreconnectToSearch,AsyncDns',
    '--host-resolver-rules=MAP localhost 172.28.8.10,MAP * ~NOTFOUND']);
  for (const address of ['127.0.0.1', '1.1.1.1', 'localhost', '172.028.8.10', '172.28.8.10,MAP * evil.invalid']) {
    assert.throws(() => browserResolutionArguments(address), /BROWSER_GATEWAY_ADDRESS_INVALID/);
  }
});

test('browser Dockerfile uses pinned base and trusted script with non-root runtime', async () => {
  const dockerfile = await fs.readFile(new URL('product-browser.Dockerfile', import.meta.url), 'utf8');
  assert.match(dockerfile, /^FROM mcr\.microsoft\.com\/playwright\/mcp@sha256:[a-f0-9]{64}/);
  assert.ok(dockerfile.includes('USER 1000:1000'));
  assert.ok(dockerfile.includes('ENV NODE_PATH=/app/node_modules'));
  assert.ok(dockerfile.includes('/verifier/verification/controller/portable/product-browser.cjs'));
  assert.equal(/COPY|ADD|dev\/labs|candidate/.test(dockerfile), false);
});
