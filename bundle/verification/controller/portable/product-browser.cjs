// Trusted browser observer. Product JavaScript runs only in this disposable container.
const fs = require('node:fs');
const cp = require('node:child_process');

function assertNoDefaultRoutes(ipv4Text, ipv6Text = '') {
  const lines = String(ipv4Text).trim().split(/\r?\n/);
  if (!/^Iface\s+Destination\s+Gateway\s+Flags\s/.test(lines[0]) || lines.length < 2) throw new Error('BROWSER_ROUTE_TABLE_INVALID');
  for (const line of lines.slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 11 || !/^[a-f0-9]{8}$/i.test(fields[1]) || !/^[a-f0-9]{8}$/i.test(fields[7])) throw new Error('BROWSER_ROUTE_TABLE_INVALID');
    if (fields[1] === '00000000' && fields[7] === '00000000') throw new Error('BROWSER_DEFAULT_ROUTE_FORBIDDEN');
  }
  for (const line of String(ipv6Text).trim().split(/\r?\n/).filter(Boolean)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length !== 10 || !/^[a-f0-9]{32}$/i.test(fields[0]) || !/^[a-f0-9]{2}$/i.test(fields[1])
        || !/^[a-f0-9]{8}$/i.test(fields[8])) throw new Error('BROWSER_IPV6_ROUTE_TABLE_INVALID');
    const flags = Number.parseInt(fields[8], 16);
    if (fields[0] === '0'.repeat(32) && fields[1] === '00' && (flags & 1) && !(flags & 0x200)) throw new Error('BROWSER_IPV6_DEFAULT_ROUTE_FORBIDDEN');
  }
  return { defaultRouteAbsent: true, defaultIpv6RouteAbsent: true };
}

function browserResolutionArguments(address) {
  const octets = String(address).split('.').map(Number);
  if (require('node:net').isIP(address) !== 4 || !(octets[0] === 10 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31
      || octets[0] === 192 && octets[1] === 168)) throw new Error('BROWSER_GATEWAY_ADDRESS_INVALID');
  return ['--no-proxy-server', '--dns-prefetch-disable', '--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn,PreconnectToSearch,AsyncDns',
    '--host-resolver-rules=MAP localhost ' + address + ',MAP * ~NOTFOUND'];
}

function routingControls() {
  let ipv6 = '';
  try { ipv6 = fs.readFileSync('/proc/net/ipv6_route', 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return assertNoDefaultRoutes(fs.readFileSync('/proc/net/route', 'utf8'), ipv6);
}

async function main() {
  const owner = JSON.parse(fs.readFileSync('/run/browser/owner.json', 'utf8'));
  const fixture = JSON.parse(fs.readFileSync('/run/browser/fixture.json', 'utf8'));
  if (!owner.email || !owner.password || fixture.projectName !== 'Independent portable verifier'
      || !/^[A-Za-z0-9_-]{1,128}$/.test(fixture.projectId)
      || !/^Independent_browser_[a-f0-9]{32}$/.test(fixture.expectedValue)
      || !/^[a-f0-9]{32}$/.test(fixture.launchNonce)
      || !/^[a-f0-9]{64}$/.test(fixture.networkId)
      || require('node:net').isIP(fixture.gatewayAddress) !== 4) throw new Error('BROWSER_FIXTURE_INVALID');
  const gateDeadline = Date.now() + 60000;
  while (!fs.existsSync('/run/browser/launch.json')) {
    if (Date.now() >= gateDeadline) throw new Error('BROWSER_LAUNCH_GATE_TIMEOUT');
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  if (JSON.parse(fs.readFileSync('/run/browser/launch.json', 'utf8')).nonce !== fixture.launchNonce) throw new Error('BROWSER_LAUNCH_GATE_INVALID');
  routingControls();
  const nss = process.env.HOME + '/.pki/nssdb';
  fs.mkdirSync(nss, { recursive: true });
  cp.execFileSync('certutil', ['-N', '-d', 'sql:' + nss, '--empty-password']);
  cp.execFileSync('certutil', ['-A', '-d', 'sql:' + nss, '-n', 'Owned independent CA', '-t', 'C,,', '-i', '/run/browser/ca.crt']);
  const { chromium } = require('playwright');
  const browser = await chromium.launch({ headless: true, executablePath: chromium.executablePath(),
    args: ['--no-sandbox', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run',
      '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', ...browserResolutionArguments(fixture.gatewayAddress)] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });
  await context.addInitScript(() => {
    for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'WebTransport'])
      Object.defineProperty(window, name, { value: undefined, writable: false, configurable: false });
  });
  const external = [], pageErrors = [], httpFailures = [], operations = [];
  const allowed = url => url.protocol === 'https:' && url.hostname === 'localhost' && url.port === '';
  await context.route('**/*', route => {
    if (!allowed(new URL(route.request().url()))) { external.push('blocked'); return route.abort(); }
    return route.continue();
  });
  await context.routeWebSocket('**/*', socket => {
    const url = new URL(socket.url());
    if (url.protocol === 'wss:' && url.hostname === 'localhost' && url.port === '') socket.connectToServer();
    else { external.push('blocked-websocket'); socket.close(); }
  });
  const page = await context.newPage();
  page.on('pageerror', () => pageErrors.push('unhandled-page-error'));
  page.on('response', response => {
    const url = new URL(response.url());
    if (response.status() >= 400 && !(response.status() === 401 && url.pathname === '/v1/account'))
      httpFailures.push({ path: url.pathname, status: response.status() });
    try { const body = JSON.parse(response.request().postDataJSON()?.body ?? '{}'); if (body.operationKind) operations.push(body.operationKind); }
    catch { /* Non-Function response. */ }
  });
  const functionRoute = id => '/v1/functions/' + id + '/executions';
  const waitOperation = kind => page.waitForResponse(response => {
    try { return new URL(response.url()).pathname === functionRoute(fixture.functions.authoring)
      && JSON.parse(response.request().postDataJSON().body).operationKind === kind; }
    catch { return false; }
  }, { timeout: 60000 });
  const assertOperation = async response => {
    const requested = JSON.parse(response.request().postDataJSON().body);
    const execution = await response.json(), value = JSON.parse(execution.responseBody);
    if (!response.ok() || execution.status !== 'completed' || execution.responseStatusCode !== 200
      || value.contract !== 'salmora.operation-result.v1' || value.status !== 'succeeded'
      || value.operationId !== requested.operationId || requested.payload.projectId !== fixture.projectId) throw new Error('BROWSER_OPERATION_BINDING');
  };
  try {
    await page.goto('https://localhost/app', { waitUntil: 'networkidle' });
    await page.getByRole('textbox', { name: 'Email', exact: true }).fill(owner.email);
    await page.getByRole('textbox', { name: 'Password', exact: true }).fill(owner.password);
    await page.getByRole('button', { name: 'Login', exact: true }).last().click();
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor({ state: 'hidden', timeout: 30000 });
    await page.getByRole('status', { name: 'Loading', exact: true }).waitFor({ state: 'hidden', timeout: 30000 });
    const welcome = page.getByRole('button', { name: 'Close Welcome to DAG Editor', exact: true });
    if (await welcome.isVisible()) await welcome.click();
    const home = page.getByRole('heading', { name: fixture.projectName, exact: true });
    if (!await home.isVisible()) await page.getByRole('button', { name: 'Open project ' + fixture.projectName, exact: true }).click();
    await home.waitFor();
    await page.getByRole('button', { name: 'Refreshing...', exact: true }).waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: 'Open Entrypoint', exact: true }).click();
    await page.getByRole('tab', { name: /Entrypoint/ }).waitFor();
    const node = page.locator('.react-flow__node[data-id="start"]'); await node.waitFor();
    const expand = node.getByRole('region', { name: 'Manual Values', exact: true }).locator('button[aria-expanded]').first();
    await expand.waitFor(); if (await expand.getAttribute('aria-expanded') === 'false') await expand.click();
    const text = page.getByPlaceholder('Enter text', { exact: true }); await text.waitFor({ timeout: 30000 });
    await text.fill(fixture.expectedValue);
    const saved = waitOperation('artifacts.save-draft.v1');
    await page.getByRole('button', { name: 'Save draft', exact: true }).click(); await assertOperation(await saved);
    const published = waitOperation('artifacts.publish.v1');
    await page.getByRole('button', { name: 'Publish stable version', exact: true }).click(); await assertOperation(await published);
    await page.getByRole('button', { name: 'Run', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Run Pipeline' }); await dialog.waitFor();
    const created = page.waitForResponse(response => new URL(response.url()).pathname === functionRoute(fixture.functions.createRun)
      && response.request().method() === 'POST');
    let runId;
    const succeeded = page.waitForResponse(async response => {
      if (new URL(response.url()).pathname !== functionRoute(fixture.functions.statusRun)) return false;
      try { return JSON.parse(response.request().postDataJSON().body).runId === runId
        && JSON.parse((await response.json()).responseBody).status === 'success'; } catch { return false; }
    }, { timeout: 90000 });
    succeeded.catch(() => {});
    await dialog.getByRole('button', { name: 'Run', exact: true }).click();
    const admission = await created, execution = await admission.json();
    const runRequest = JSON.parse(admission.request().postDataJSON().body);
    runId = JSON.parse(execution.responseBody).runId;
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(runId) || execution.status !== 'completed'
      || execution.responseStatusCode !== 200 || runRequest.projectId !== fixture.projectId) throw new Error('BROWSER_RUN_BINDING');
    await succeeded; await dialog.waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: 'Runs History', exact: true }).click();
    await page.getByRole('button', { name: /^success workflow:/ }).first().click();
    await page.getByRole('button', { name: 'Show steps (1)', exact: true }).click();
    await page.getByText(runId, { exact: true }).waitFor();
    await page.getByRole('application').getByRole('group').first().click();
    await page.getByRole('button', { name: 'Inspector', exact: true }).first().click();
    await page.locator('pre').filter({ hasText: new RegExp('^' + fixture.expectedValue + '$') }).waitFor();
    if (external.length || pageErrors.length || httpFailures.length) throw new Error('BROWSER_BOUNDARY_OR_PAGE_ERROR');
    const report = { schemaVersion: 'portable-product-browser.v1', status: 'PASS', tlsVerification: true,
      projectId: fixture.projectId, runId, expectedValue: fixture.expectedValue,
      network: { ...routingControls(), networkId: fixture.networkId, gatewayAddress: fixture.gatewayAddress, dnsUpstream: '127.0.0.1' },
      checks: ['login', 'open-editor', 'edit', 'save-draft', 'publish', 'execute', 'inspect-result'],
      operationKinds: [...new Set(operations)].sort(), externalRequests: 0, unhandledErrors: 0, httpFailures: 0 };
    await page.screenshot({ path: '/observations/browser.png', fullPage: true });
    fs.writeFileSync('/observations/browser-observed.json', JSON.stringify(report));
    console.log(JSON.stringify(report));
  } catch {
    fs.writeFileSync('/observations/browser-failure.json', JSON.stringify({ status: 'FAIL', externalRequests: external.length,
      unhandledErrors: pageErrors.length, httpFailures: httpFailures.length }));
    await page.screenshot({ path: '/observations/browser-failure.png', fullPage: true }).catch(() => {});
    throw new Error('BROWSER_ACCEPTANCE_FAILED');
  } finally { await browser.close(); }
}
module.exports = { assertNoDefaultRoutes, browserResolutionArguments };
if (require.main === module) main().catch(() => { console.error('TRUSTED_BROWSER_ACCEPTANCE_FAILED'); process.exitCode = 1; });
