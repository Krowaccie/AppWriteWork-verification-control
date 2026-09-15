import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';

import { createProductionReadonlyBrowser } from '../src/production-readonly-browser.mjs';

test('@production-readonly public production smoke', async ({ browser }) => {
  const policyPath = process.env.PRODUCTION_BROWSER_POLICY_PATH;
  const expectedDigest = process.env.PRODUCTION_BROWSER_POLICY_DIGEST;
  expect(policyPath).toBeTruthy();
  expect(expectedDigest).toMatch(/^sha256:[0-9a-f]{64}$/);

  const policyBytes = await readFile(policyPath);
  const actualDigest = `sha256:${createHash('sha256').update(policyBytes).digest('hex')}`;
  expect(actualDigest).toBe(expectedDigest);
  const policy = JSON.parse(policyBytes.toString('utf8'));

  const runner = createProductionReadonlyBrowser({ browserFactory: browser, policy });
  const result = await runner.run();
  expect(result.status).toBe('PASS');
});
